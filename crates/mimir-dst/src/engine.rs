use std::collections::HashSet;
use std::time::Duration;

use chrono::Utc;
use serde_json::Value;
use tracing::{debug, info, warn};

use mimir_entropy::shannon::json_entropy;
use mimir_gen::generator::{generate_mutation_suite, generate_query, GenConfig};
use mimir_graph::analysis::analyze_schema;
use mimir_mdp::explorer::compute_reward;
use mimir_mdp::state::{Action, ApiState};
use mimir_mdp::strategy::{EpsilonGreedy, ExplorationStrategy, ThompsonSampling, Ucb1};
use mimir_oracle::{AuthState, PropertyContext, PropertyRegistry};
use mimir_oracle::Finding;
use mimir_report::report::{SchemaStats, SweepReport};
use mimir_schema::types::Schema;
use mimir_schema::parse_introspection_response;
use mimir_transport::GraphqlClient;

use crate::config::{StrategyKind, SweepConfig};
use crate::error::DstError;

/// The main sweep engine that orchestrates the full security audit.
pub struct SweepEngine {
    config: SweepConfig,
    client: GraphqlClient,
    schema: Option<Schema>,
    oracle: PropertyRegistry,
}

impl SweepEngine {
    /// Create a new sweep engine from the given configuration.
    pub fn new(config: SweepConfig) -> Self {
        let mut client = GraphqlClient::new(&config.target_url)
            .with_timeout(Duration::from_secs(config.timeout_secs));

        for (name, value) in &config.auth_headers {
            client = client.with_header(name.clone(), value.clone());
        }

        Self {
            config,
            client,
            schema: None,
            oracle: PropertyRegistry::default_registry(),
        }
    }

    /// Run the full sweep: introspect, analyze, explore, report.
    pub async fn run(&mut self) -> Result<SweepReport, DstError> {
        let started_at = Utc::now();
        let mut all_findings: Vec<Finding> = Vec::new();

        // --- Step 1: Introspect ---
        info!(url = %self.config.target_url, "starting introspection");
        let introspection_json = self.client.introspect().await.map_err(|e| {
            DstError::IntrospectionFailed(format!("introspection request failed: {e}"))
        })?;

        let schema = parse_introspection_response(&introspection_json)?;
        info!(
            types = schema.types.len(),
            queries = schema.queries().len(),
            mutations = schema.mutations().len(),
            "schema parsed successfully"
        );
        self.schema = Some(schema.clone());

        // --- Step 2: Analyze schema graph ---
        let analysis = analyze_schema(&schema);
        info!(
            nodes = analysis.node_count,
            edges = analysis.edge_count,
            sccs = analysis.scc_count,
            has_cycles = analysis.has_cycles,
            "schema graph analysis complete"
        );

        // --- Step 3: Check introspection property ---
        {
            let intro_ctx = PropertyContext {
                request_query: "{ __schema { types { name } } }".to_string(),
                request_variables: serde_json::json!({}),
                response: introspection_json.clone(),
                response_errors: vec![],
                status_code: 200,
                auth_state: if self.config.auth_headers.is_empty() {
                    AuthState::None
                } else {
                    AuthState::ValidUser
                },
                entropy: json_entropy(&introspection_json),
                latency_ms: 0,
            };
            let intro_findings = self.oracle.check_all(&intro_ctx);
            all_findings.extend(intro_findings);
        }

        // --- Step 4: Generate actions ---
        let gen_config = GenConfig {
            max_depth: self.config.max_depth,
            include_args: true,
            include_fragments: false,
            seed: self.config.seed,
        };

        let mut actions: Vec<Action> = Vec::new();

        // Generate query actions
        for (i, field) in schema.queries().iter().enumerate() {
            let query_str = generate_query(&schema, field, &gen_config);
            actions.push(Action {
                id: format!("query-{i}"),
                operation_name: field.name.clone(),
                query: query_str,
                variables: serde_json::json!({}),
            });
        }

        // Generate mutation actions (only included if execute_mutations is set)
        let mutation_suite = generate_mutation_suite(&schema, &gen_config);
        if self.config.execute_mutations {
            for (i, (op_name, query_str, variables)) in mutation_suite.iter().enumerate() {
                actions.push(Action {
                    id: format!("mutation-{i}"),
                    operation_name: op_name.clone(),
                    query: query_str.clone(),
                    variables: variables.clone(),
                });
            }
        } else if !mutation_suite.is_empty() {
            info!(
                count = mutation_suite.len(),
                "mutations generated but NOT executed (use --execute-mutations to enable)"
            );
        }

        if actions.is_empty() {
            warn!("no actions to explore — schema may have no query fields");
            let completed_at = Utc::now();
            return Ok(SweepReport {
                target: self.config.target_url.clone(),
                started_at,
                completed_at,
                schema_stats: build_schema_stats(&schema, &self.config),
                findings: all_findings,
                operations_executed: 0,
                states_discovered: 0,
                seed: self.config.seed,
            });
        }

        // --- Step 5: Initialize MDP state ---
        let mut current_state = ApiState::new();

        // --- Step 6: Create exploration strategy ---
        let mut strategy: Box<dyn ExplorationStrategy> = match &self.config.strategy {
            StrategyKind::Ucb1 => Box::new(Ucb1::default_c()),
            StrategyKind::EpsilonGreedy(eps) => {
                Box::new(EpsilonGreedy::new(*eps, self.config.seed))
            }
            StrategyKind::Thompson => Box::new(ThompsonSampling::new(self.config.seed)),
        };

        // --- Step 7: Exploration loop ---
        let mut operations_executed: usize = 0;
        let mut discovered_states: HashSet<String> = HashSet::new();
        discovered_states.insert(current_state.fingerprint.clone());

        let action_count = actions.len();
        info!(
            action_count,
            max_ops = self.config.max_operations,
            "starting exploration loop"
        );

        for step in 0..self.config.max_operations {
            // (a) Select action via strategy
            let action_idx = strategy.select(action_count);
            let action = &actions[action_idx];

            debug!(
                step,
                action_id = %action.id,
                operation = %action.operation_name,
                "executing action"
            );

            // (b) Execute via client
            let variables = if action.variables.is_null() {
                None
            } else {
                Some(action.variables.clone())
            };
            let response = match self
                .client
                .execute(&action.query, variables, Some(&action.operation_name))
                .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    debug!(error = %e, "action execution failed, skipping");
                    // Give a small negative reward for failed requests
                    strategy.update(action_idx, -0.1);
                    operations_executed += 1;
                    continue;
                }
            };
            operations_executed += 1;

            // (c) Compute entropy of response
            let resp_entropy = json_entropy(&response.body);

            // (d) Build PropertyContext from response
            let error_messages: Vec<String> =
                response.errors.iter().map(|e| e.message.clone()).collect();

            let auth_state = if self.config.auth_headers.is_empty() {
                AuthState::None
            } else {
                AuthState::ValidUser
            };

            let prop_ctx = PropertyContext {
                request_query: action.query.clone(),
                request_variables: action.variables.clone(),
                response: response.body.clone(),
                response_errors: error_messages.clone(),
                status_code: response.status_code,
                auth_state,
                entropy: resp_entropy,
                latency_ms: response.latency_ms,
            };

            // (e) Run oracle.check_all() — collect findings
            let step_findings = self.oracle.check_all(&prop_ctx);
            all_findings.extend(step_findings);

            // (f) Build new state and compute reward
            let mut new_state = current_state.clone();
            new_state.step_count = step + 1;
            if !new_state.status_codes.contains(&response.status_code) {
                new_state.status_codes.push(response.status_code);
            }
            for msg in &error_messages {
                if !new_state.error_messages.contains(msg) {
                    new_state.error_messages.push(msg.clone());
                }
            }
            // Compute a fingerprint from the response shape
            let shape = compute_response_shape(&response.body);
            if !new_state.response_shapes.contains(&shape) {
                new_state.response_shapes.push(shape.clone());
            }
            new_state.fingerprint = compute_state_fingerprint(&new_state);

            let reward = compute_reward(
                &current_state,
                &new_state,
                response.status_code,
                &error_messages,
                resp_entropy,
            );

            // (g) Update strategy
            strategy.update(action_idx, reward);

            // (h) Track discovered states
            discovered_states.insert(new_state.fingerprint.clone());
            current_state = new_state;

            // (i) Log progress every 100 operations
            if (step + 1) % 100 == 0 {
                info!(
                    step = step + 1,
                    findings = all_findings.len(),
                    states = discovered_states.len(),
                    "exploration progress"
                );
            }
        }

        // --- Step 8: Build SweepReport ---
        let completed_at = Utc::now();

        // Deduplicate findings by id
        let findings = deduplicate_findings(all_findings);

        info!(
            operations = operations_executed,
            states = discovered_states.len(),
            findings = findings.len(),
            "sweep complete"
        );

        Ok(SweepReport {
            target: self.config.target_url.clone(),
            started_at,
            completed_at,
            schema_stats: build_schema_stats(&schema, &self.config),
            findings,
            operations_executed,
            states_discovered: discovered_states.len(),
            seed: self.config.seed,
        })
    }
}

/// Build schema statistics from the parsed schema.
fn build_schema_stats(schema: &Schema, config: &SweepConfig) -> SchemaStats {
    SchemaStats {
        type_count: schema.type_names().len(),
        query_count: schema.queries().len(),
        mutation_count: schema.mutations().len(),
        input_type_count: schema.input_types().len(),
        max_depth: Some(config.max_depth),
    }
}

/// Compute a simple shape signature from a JSON response for state tracking.
fn compute_response_shape(body: &Value) -> String {
    match body {
        Value::Object(map) => {
            let keys: Vec<&str> = map.keys().map(|k| k.as_str()).collect();
            format!("object({})", keys.join(","))
        }
        Value::Array(arr) => format!("array({})", arr.len()),
        Value::String(_) => "string".to_string(),
        Value::Number(_) => "number".to_string(),
        Value::Bool(_) => "bool".to_string(),
        Value::Null => "null".to_string(),
    }
}

/// Compute a fingerprint for an ApiState based on its observable features.
fn compute_state_fingerprint(state: &ApiState) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    state.status_codes.hash(&mut hasher);
    state.error_messages.hash(&mut hasher);
    state.response_shapes.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Deduplicate findings by their id, keeping the first occurrence.
fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for finding in findings {
        if seen.insert(finding.id.clone()) {
            unique.push(finding);
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{OutputFormat, StrategyKind, SweepConfig};

    #[test]
    fn engine_construction() {
        let config = SweepConfig {
            target_url: "http://localhost:4000/graphql".to_string(),
            seed: 42,
            max_operations: 500,
            max_depth: 4,
            strategy: StrategyKind::Ucb1,
            auth_headers: vec![("Authorization".to_string(), "Bearer test".to_string())],
            timeout_secs: 15,
            output_format: OutputFormat::Pretty,
            execute_mutations: false,
        };

        let engine = SweepEngine::new(config);
        assert!(engine.schema.is_none());
        assert_eq!(engine.config.max_operations, 500);
        assert_eq!(engine.config.seed, 42);
    }

    #[test]
    fn engine_default_config() {
        let config = SweepConfig::default();
        let engine = SweepEngine::new(config);
        assert!(engine.schema.is_none());
    }

    #[test]
    fn response_shape_computation() {
        let body = serde_json::json!({"data": {"users": []}});
        let shape = compute_response_shape(&body);
        assert!(shape.starts_with("object("));

        let arr = serde_json::json!([1, 2, 3]);
        let shape = compute_response_shape(&arr);
        assert!(shape.starts_with("array("));

        let null = serde_json::json!(null);
        assert_eq!(compute_response_shape(&null), "null");
    }

    #[test]
    fn state_fingerprint_deterministic() {
        let state = ApiState {
            fingerprint: String::new(),
            status_codes: vec![200],
            error_messages: vec!["test".to_string()],
            response_shapes: vec!["object(data)".to_string()],
            tokens: vec![],
            step_count: 1,
        };
        let fp1 = compute_state_fingerprint(&state);
        let fp2 = compute_state_fingerprint(&state);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn deduplication() {
        let f1 = Finding {
            id: "GQL-001".to_string(),
            category: mimir_oracle::FindingCategory::IntrospectionEnabled,
            severity: mimir_oracle::Severity::Medium,
            title: "first".to_string(),
            description: "desc".to_string(),
            evidence: vec![],
            reproduction: mimir_oracle::ReproductionInfo {
                seed: None,
                operation: "{ test }".to_string(),
                variables: serde_json::json!({}),
                response_snippet: None,
            },
        };
        let f2 = Finding {
            id: "GQL-001".to_string(),
            category: mimir_oracle::FindingCategory::IntrospectionEnabled,
            severity: mimir_oracle::Severity::Medium,
            title: "duplicate".to_string(),
            description: "desc2".to_string(),
            evidence: vec![],
            reproduction: mimir_oracle::ReproductionInfo {
                seed: None,
                operation: "{ test2 }".to_string(),
                variables: serde_json::json!({}),
                response_snippet: None,
            },
        };
        let f3 = Finding {
            id: "GQL-002".to_string(),
            category: mimir_oracle::FindingCategory::MutationWithoutAuth,
            severity: mimir_oracle::Severity::High,
            title: "different".to_string(),
            description: "desc3".to_string(),
            evidence: vec![],
            reproduction: mimir_oracle::ReproductionInfo {
                seed: None,
                operation: "mutation { test }".to_string(),
                variables: serde_json::json!({}),
                response_snippet: None,
            },
        };

        let deduped = deduplicate_findings(vec![f1, f2, f3]);
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].id, "GQL-001");
        assert_eq!(deduped[0].title, "first");
        assert_eq!(deduped[1].id, "GQL-002");
    }

    #[test]
    fn build_schema_stats_works() {
        use mimir_schema::types::*;
        use indexmap::IndexMap;

        let mut types = IndexMap::new();
        types.insert(
            "Query".to_string(),
            FullType {
                name: "Query".to_string(),
                kind: TypeKind::Object,
                description: None,
                fields: vec![Field {
                    name: "hello".to_string(),
                    description: None,
                    args: vec![],
                    field_type: TypeRef {
                        name: Some("String".to_string()),
                        kind: TypeKind::Scalar,
                        of_type: None,
                    },
                    is_deprecated: false,
                }],
                input_fields: vec![],
                interfaces: vec![],
                enum_values: vec![],
                possible_types: vec![],
            },
        );
        types.insert(
            "String".to_string(),
            FullType {
                name: "String".to_string(),
                kind: TypeKind::Scalar,
                description: None,
                fields: vec![],
                input_fields: vec![],
                interfaces: vec![],
                enum_values: vec![],
                possible_types: vec![],
            },
        );

        let schema = Schema {
            query_type: Some("Query".to_string()),
            mutation_type: None,
            subscription_type: None,
            types,
            directives: vec![],
        };

        let config = SweepConfig::default();
        let stats = build_schema_stats(&schema, &config);
        assert_eq!(stats.query_count, 1);
        assert_eq!(stats.mutation_count, 0);
        assert_eq!(stats.max_depth, Some(3));
    }
}
