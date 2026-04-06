use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::finding::{
    Finding, FindingCategory, ReproductionInfo, Severity,
};

/// The type signature for a property check function.
pub type PropertyCheck = fn(&PropertyContext) -> PropertyResult;

/// Authentication state for the request context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthState {
    /// No authentication provided.
    None,
    /// Authentication token is expired.
    Expired,
    /// Valid regular user authentication.
    ValidUser,
    /// Valid admin authentication.
    Admin,
}

/// Context provided to each property check.
#[derive(Debug, Clone)]
pub struct PropertyContext {
    /// The GraphQL query string that was sent.
    pub request_query: String,
    /// The variables used in the request.
    pub request_variables: Value,
    /// The full JSON response body.
    pub response: Value,
    /// Error messages extracted from the response.
    pub response_errors: Vec<String>,
    /// HTTP status code of the response.
    pub status_code: u16,
    /// The authentication state when the request was made.
    pub auth_state: AuthState,
    /// Shannon entropy of the response body.
    pub entropy: f64,
    /// Response latency in milliseconds.
    pub latency_ms: u64,
}

/// Result of evaluating a property.
#[derive(Debug, Clone)]
pub enum PropertyResult {
    /// The property holds; no issue found.
    Pass,
    /// The property is violated; a finding was produced.
    Fail(Finding),
    /// The property is not applicable to this operation.
    Skip,
}

/// Check: introspection should be disabled in production.
///
/// Detects if an introspection query returns a successful `__schema` response.
pub fn introspection_should_be_disabled(ctx: &PropertyContext) -> PropertyResult {
    let is_introspection_query = ctx.request_query.contains("__schema")
        || ctx.request_query.contains("__type");

    if !is_introspection_query {
        return PropertyResult::Skip;
    }

    // Check if the response contains introspection data (successful introspection).
    let has_schema_data = ctx
        .response
        .pointer("/data/__schema")
        .is_some_and(|v| !v.is_null());
    let has_type_data = ctx
        .response
        .pointer("/data/__type")
        .is_some_and(|v| !v.is_null());

    if has_schema_data || has_type_data {
        PropertyResult::Fail(Finding {
            id: "GQL-001".to_string(),
            category: FindingCategory::IntrospectionEnabled,
            severity: Severity::Medium,
            title: "GraphQL introspection is enabled".to_string(),
            description: "Introspection queries return schema information. \
                          This exposes the entire API surface to attackers and should \
                          be disabled in production environments."
                .to_string(),
            evidence: vec![
                "Introspection query returned __schema or __type data".to_string(),
            ],
            reproduction: ReproductionInfo {
                seed: None,
                operation: ctx.request_query.clone(),
                variables: ctx.request_variables.clone(),
                response_snippet: truncate_json(&ctx.response, 500),
            },
        })
    } else {
        PropertyResult::Pass
    }
}

/// Check: mutations should require authentication.
///
/// Detects if a mutation succeeds without any authentication.
pub fn mutations_require_auth(ctx: &PropertyContext) -> PropertyResult {
    // Only check mutation operations.
    let query_trimmed = ctx.request_query.trim();
    if !query_trimmed.starts_with("mutation") {
        return PropertyResult::Skip;
    }

    // Only relevant when no auth is provided.
    if ctx.auth_state != AuthState::None {
        return PropertyResult::Skip;
    }

    // Check if the mutation succeeded (has data and no errors, or 200 status).
    let has_data = ctx
        .response
        .get("data")
        .is_some_and(|d| !d.is_null());
    let has_errors = ctx
        .response
        .get("errors")
        .is_some_and(|e| e.is_array() && !e.as_array().unwrap().is_empty());

    if has_data && !has_errors && ctx.status_code == 200 {
        PropertyResult::Fail(Finding {
            id: "GQL-002".to_string(),
            category: FindingCategory::MutationWithoutAuth,
            severity: Severity::High,
            title: "Mutation succeeded without authentication".to_string(),
            description: "A mutation operation returned successful data without any \
                          authentication token. This may indicate a missing \
                          authorization check."
                .to_string(),
            evidence: vec![format!(
                "Mutation returned data with status {} and no auth",
                ctx.status_code
            )],
            reproduction: ReproductionInfo {
                seed: None,
                operation: ctx.request_query.clone(),
                variables: ctx.request_variables.clone(),
                response_snippet: truncate_json(&ctx.response, 500),
            },
        })
    } else {
        PropertyResult::Pass
    }
}

/// Check: error messages should not leak internal information.
///
/// Uses entropy as a heuristic: high-entropy error messages may contain stack
/// traces, file paths, or internal details.
pub fn errors_should_not_leak_info(ctx: &PropertyContext) -> PropertyResult {
    if ctx.response_errors.is_empty() {
        return PropertyResult::Skip;
    }

    let mut leaked_evidence = Vec::new();

    // Patterns that indicate information leakage.
    let leak_patterns = [
        "stack trace",
        "stacktrace",
        "at /",
        "at \\",
        ".js:",
        ".ts:",
        ".py:",
        ".rb:",
        ".java:",
        "node_modules",
        "ECONNREFUSED",
        "ENOTFOUND",
        "password",
        "secret",
        "token",
        "internal server error",
        "traceback",
        "exception",
        "postgres",
        "mysql",
        "mongodb",
        "redis",
        "connection refused",
        "syntax error",
        "column",
        "table",
        "relation",
    ];

    for error in &ctx.response_errors {
        let lower = error.to_lowercase();
        for pattern in &leak_patterns {
            if lower.contains(pattern) {
                leaked_evidence.push(format!(
                    "Error contains '{}': {}",
                    pattern,
                    truncate_str(error, 200)
                ));
            }
        }
    }

    // Also flag high-entropy errors (may contain encoded data or stack traces).
    if ctx.entropy > 5.0 && !ctx.response_errors.is_empty() {
        leaked_evidence.push(format!(
            "Response entropy is unusually high ({:.2} bits), may contain internal data",
            ctx.entropy
        ));
    }

    if leaked_evidence.is_empty() {
        PropertyResult::Pass
    } else {
        PropertyResult::Fail(Finding {
            id: "GQL-003".to_string(),
            category: FindingCategory::InformationLeakage,
            severity: Severity::Medium,
            title: "Error messages may leak internal information".to_string(),
            description: "GraphQL error messages contain patterns that suggest internal \
                          implementation details are being exposed. This information \
                          can help attackers understand the system architecture."
                .to_string(),
            evidence: leaked_evidence,
            reproduction: ReproductionInfo {
                seed: None,
                operation: ctx.request_query.clone(),
                variables: ctx.request_variables.clone(),
                response_snippet: truncate_json(&ctx.response, 500),
            },
        })
    }
}

/// Check: error responses should not contain field suggestions.
///
/// GraphQL servers often include "Did you mean ..." suggestions in error
/// messages, which leaks the schema to unauthenticated users.
pub fn no_field_suggestions(ctx: &PropertyContext) -> PropertyResult {
    if ctx.response_errors.is_empty() {
        return PropertyResult::Skip;
    }

    let mut evidence = Vec::new();

    for error in &ctx.response_errors {
        let lower = error.to_lowercase();
        if lower.contains("did you mean") {
            evidence.push(format!(
                "Error contains field suggestion: {}",
                truncate_str(error, 300)
            ));
        }
    }

    if evidence.is_empty() {
        PropertyResult::Pass
    } else {
        PropertyResult::Fail(Finding {
            id: "GQL-004".to_string(),
            category: FindingCategory::FieldSuggestionLeak,
            severity: Severity::Low,
            title: "Field suggestions leak schema information".to_string(),
            description: "Error messages contain 'Did you mean ...' suggestions that \
                          reveal valid field names. This allows attackers to enumerate \
                          the schema even when introspection is disabled."
                .to_string(),
            evidence,
            reproduction: ReproductionInfo {
                seed: None,
                operation: ctx.request_query.clone(),
                variables: ctx.request_variables.clone(),
                response_snippet: truncate_json(&ctx.response, 500),
            },
        })
    }
}

/// Check: batch queries should be limited.
///
/// Detects if a batch query (array of operations) succeeds without limits.
pub fn batch_queries_should_be_limited(ctx: &PropertyContext) -> PropertyResult {
    // Check if this looks like a batch query (array at top level of request).
    // We approximate this by checking if the query starts with '['.
    let trimmed = ctx.request_query.trim();
    if !trimmed.starts_with('[') {
        return PropertyResult::Skip;
    }

    // If the batch query succeeded, it may indicate missing limits.
    if ctx.status_code == 200 {
        let response_data = ctx.response.get("data");
        let has_data = response_data.is_some_and(|d| !d.is_null());

        // Also check if the response itself is an array (batch response).
        let is_batch_response = ctx.response.is_array();

        if has_data || is_batch_response {
            return PropertyResult::Fail(Finding {
                id: "GQL-005".to_string(),
                category: FindingCategory::BatchingAbuse,
                severity: Severity::Medium,
                title: "Batch queries are not limited".to_string(),
                description: "The server processes batch GraphQL queries without \
                              apparent limits. Attackers can abuse this to bypass \
                              rate limiting or perform denial-of-service attacks."
                    .to_string(),
                evidence: vec!["Batch query returned successful response".to_string()],
                reproduction: ReproductionInfo {
                    seed: None,
                    operation: ctx.request_query.clone(),
                    variables: ctx.request_variables.clone(),
                    response_snippet: truncate_json(&ctx.response, 500),
                },
            });
        }
    }

    PropertyResult::Pass
}

/// Check: deeply nested queries should be rejected.
///
/// Detects if a deeply nested query succeeds, suggesting missing depth limits.
pub fn depth_should_be_limited(ctx: &PropertyContext) -> PropertyResult {
    // Count the nesting depth of the query by counting '{' characters.
    let depth = count_query_depth(&ctx.request_query);

    // Only flag if the query is deeply nested (>= 10 levels).
    if depth < 10 {
        return PropertyResult::Skip;
    }

    // If a deep query succeeded, the server may not enforce depth limits.
    let has_data = ctx
        .response
        .get("data")
        .is_some_and(|d| !d.is_null());
    let has_errors = ctx
        .response
        .get("errors")
        .is_some_and(|e| e.is_array() && !e.as_array().unwrap().is_empty());

    if has_data && !has_errors && ctx.status_code == 200 {
        PropertyResult::Fail(Finding {
            id: "GQL-006".to_string(),
            category: FindingCategory::ExcessiveDepth,
            severity: Severity::Medium,
            title: "Deeply nested query was not rejected".to_string(),
            description: format!(
                "A query with nesting depth {} was accepted and returned data. \
                 The server should enforce a maximum query depth to prevent \
                 denial-of-service attacks via deeply nested queries.",
                depth
            ),
            evidence: vec![format!("Query depth: {} levels", depth)],
            reproduction: ReproductionInfo {
                seed: None,
                operation: ctx.request_query.clone(),
                variables: ctx.request_variables.clone(),
                response_snippet: truncate_json(&ctx.response, 500),
            },
        })
    } else {
        PropertyResult::Pass
    }
}

/// Count the maximum nesting depth of '{' in a query string.
fn count_query_depth(query: &str) -> usize {
    let mut max_depth = 0usize;
    let mut current_depth = 0usize;
    let mut in_string = false;
    let mut escape_next = false;

    for ch in query.chars() {
        if escape_next {
            escape_next = false;
            continue;
        }
        match ch {
            '\\' if in_string => escape_next = true,
            '"' => in_string = !in_string,
            '{' if !in_string => {
                current_depth += 1;
                max_depth = max_depth.max(current_depth);
            }
            '}' if !in_string => {
                current_depth = current_depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    max_depth
}

/// Truncate a JSON value to a string snippet of at most `max_len` characters.
fn truncate_json(value: &Value, max_len: usize) -> Option<String> {
    let s = serde_json::to_string(value).ok()?;
    Some(truncate_str(&s, max_len).to_string())
}

/// Truncate a string to at most `max_len` characters, appending "..." if truncated.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let end = s
            .char_indices()
            .nth(max_len.saturating_sub(3))
            .map(|(i, _)| i)
            .unwrap_or(s.len());
        format!("{}...", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_context(overrides: impl FnOnce(&mut PropertyContext)) -> PropertyContext {
        let mut ctx = PropertyContext {
            request_query: "{ users { id name } }".to_string(),
            request_variables: json!({}),
            response: json!({"data": {"users": [{"id": "1", "name": "Alice"}]}}),
            response_errors: vec![],
            status_code: 200,
            auth_state: AuthState::ValidUser,
            entropy: 3.0,
            latency_ms: 50,
        };
        overrides(&mut ctx);
        ctx
    }

    // --- introspection_should_be_disabled ---

    #[test]
    fn introspection_skip_for_non_introspection_query() {
        let ctx = make_context(|_| {});
        assert!(matches!(
            introspection_should_be_disabled(&ctx),
            PropertyResult::Skip
        ));
    }

    #[test]
    fn introspection_fail_when_schema_returned() {
        let ctx = make_context(|ctx| {
            ctx.request_query = "{ __schema { types { name } } }".to_string();
            ctx.response = json!({"data": {"__schema": {"types": [{"name": "Query"}]}}});
        });
        assert!(matches!(
            introspection_should_be_disabled(&ctx),
            PropertyResult::Fail(_)
        ));
    }

    #[test]
    fn introspection_pass_when_blocked() {
        let ctx = make_context(|ctx| {
            ctx.request_query = "{ __schema { types { name } } }".to_string();
            ctx.response = json!({"errors": [{"message": "Introspection is disabled"}]});
        });
        assert!(matches!(
            introspection_should_be_disabled(&ctx),
            PropertyResult::Pass
        ));
    }

    // --- mutations_require_auth ---

    #[test]
    fn mutations_skip_for_queries() {
        let ctx = make_context(|_| {});
        assert!(matches!(
            mutations_require_auth(&ctx),
            PropertyResult::Skip
        ));
    }

    #[test]
    fn mutations_skip_when_authed() {
        let ctx = make_context(|ctx| {
            ctx.request_query = "mutation { createUser(name: \"x\") { id } }".to_string();
            ctx.auth_state = AuthState::ValidUser;
        });
        assert!(matches!(
            mutations_require_auth(&ctx),
            PropertyResult::Skip
        ));
    }

    #[test]
    fn mutations_fail_when_unauthed_and_succeeds() {
        let ctx = make_context(|ctx| {
            ctx.request_query = "mutation { createUser(name: \"x\") { id } }".to_string();
            ctx.auth_state = AuthState::None;
            ctx.response = json!({"data": {"createUser": {"id": "1"}}});
            ctx.status_code = 200;
        });
        assert!(matches!(
            mutations_require_auth(&ctx),
            PropertyResult::Fail(_)
        ));
    }

    #[test]
    fn mutations_pass_when_unauthed_and_rejected() {
        let ctx = make_context(|ctx| {
            ctx.request_query = "mutation { createUser(name: \"x\") { id } }".to_string();
            ctx.auth_state = AuthState::None;
            ctx.response = json!({"data": null, "errors": [{"message": "Unauthorized"}]});
            ctx.status_code = 200;
        });
        assert!(matches!(
            mutations_require_auth(&ctx),
            PropertyResult::Pass
        ));
    }

    // --- errors_should_not_leak_info ---

    #[test]
    fn errors_skip_when_no_errors() {
        let ctx = make_context(|_| {});
        assert!(matches!(
            errors_should_not_leak_info(&ctx),
            PropertyResult::Skip
        ));
    }

    #[test]
    fn errors_fail_with_stack_trace() {
        let ctx = make_context(|ctx| {
            ctx.response_errors = vec![
                "Error: at /app/node_modules/graphql/execution.js:123".to_string(),
            ];
        });
        assert!(matches!(
            errors_should_not_leak_info(&ctx),
            PropertyResult::Fail(_)
        ));
    }

    #[test]
    fn errors_fail_with_high_entropy() {
        let ctx = make_context(|ctx| {
            ctx.response_errors = vec!["Something went wrong".to_string()];
            ctx.entropy = 6.5;
        });
        assert!(matches!(
            errors_should_not_leak_info(&ctx),
            PropertyResult::Fail(_)
        ));
    }

    #[test]
    fn errors_pass_with_generic_message() {
        let ctx = make_context(|ctx| {
            ctx.response_errors = vec!["Something went wrong".to_string()];
            ctx.entropy = 2.0;
        });
        assert!(matches!(
            errors_should_not_leak_info(&ctx),
            PropertyResult::Pass
        ));
    }

    // --- no_field_suggestions ---

    #[test]
    fn suggestions_skip_when_no_errors() {
        let ctx = make_context(|_| {});
        assert!(matches!(
            no_field_suggestions(&ctx),
            PropertyResult::Skip
        ));
    }

    #[test]
    fn suggestions_fail_with_did_you_mean() {
        let ctx = make_context(|ctx| {
            ctx.response_errors = vec![
                "Cannot query field \"naem\" on type \"User\". Did you mean \"name\"?".to_string(),
            ];
        });
        assert!(matches!(
            no_field_suggestions(&ctx),
            PropertyResult::Fail(_)
        ));
    }

    #[test]
    fn suggestions_pass_without_did_you_mean() {
        let ctx = make_context(|ctx| {
            ctx.response_errors = vec!["Cannot query field \"naem\" on type \"User\"".to_string()];
        });
        assert!(matches!(
            no_field_suggestions(&ctx),
            PropertyResult::Pass
        ));
    }

    // --- batch_queries_should_be_limited ---

    #[test]
    fn batch_skip_for_single_query() {
        let ctx = make_context(|_| {});
        assert!(matches!(
            batch_queries_should_be_limited(&ctx),
            PropertyResult::Skip
        ));
    }

    #[test]
    fn batch_fail_when_batch_succeeds() {
        let ctx = make_context(|ctx| {
            ctx.request_query =
                "[{\"query\": \"{ a }\"}, {\"query\": \"{ b }\"}]".to_string();
            ctx.response = json!([{"data": {"a": 1}}, {"data": {"b": 2}}]);
            ctx.status_code = 200;
        });
        assert!(matches!(
            batch_queries_should_be_limited(&ctx),
            PropertyResult::Fail(_)
        ));
    }

    #[test]
    fn batch_pass_when_batch_rejected() {
        let ctx = make_context(|ctx| {
            ctx.request_query =
                "[{\"query\": \"{ a }\"}, {\"query\": \"{ b }\"}]".to_string();
            ctx.response = json!({"errors": [{"message": "Batching is not allowed"}]});
            ctx.status_code = 400;
        });
        assert!(matches!(
            batch_queries_should_be_limited(&ctx),
            PropertyResult::Pass
        ));
    }

    // --- depth_should_be_limited ---

    #[test]
    fn depth_skip_for_shallow_query() {
        let ctx = make_context(|_| {});
        assert!(matches!(
            depth_should_be_limited(&ctx),
            PropertyResult::Skip
        ));
    }

    #[test]
    fn depth_fail_for_deep_successful_query() {
        // Build a deeply nested query (12 levels).
        let mut query = String::from("query Deep { a ");
        for _ in 0..12 {
            query.push_str("{ b ");
        }
        for _ in 0..12 {
            query.push_str(" }");
        }
        query.push_str(" }");

        let ctx = make_context(|ctx| {
            ctx.request_query = query.clone();
            ctx.response = json!({"data": {"a": {"b": {"b": null}}}});
            ctx.status_code = 200;
        });
        assert!(matches!(
            depth_should_be_limited(&ctx),
            PropertyResult::Fail(_)
        ));
    }

    #[test]
    fn depth_pass_for_deep_rejected_query() {
        let mut query = String::from("query Deep { a ");
        for _ in 0..12 {
            query.push_str("{ b ");
        }
        for _ in 0..12 {
            query.push_str(" }");
        }
        query.push_str(" }");

        let ctx = make_context(|ctx| {
            ctx.request_query = query.clone();
            ctx.response =
                json!({"data": null, "errors": [{"message": "Query depth limit exceeded"}]});
            ctx.status_code = 200;
        });
        assert!(matches!(
            depth_should_be_limited(&ctx),
            PropertyResult::Pass
        ));
    }

    // --- count_query_depth ---

    #[test]
    fn count_depth_simple() {
        assert_eq!(count_query_depth("{ a }"), 1);
        assert_eq!(count_query_depth("{ a { b } }"), 2);
        assert_eq!(count_query_depth("{ a { b { c } } }"), 3);
    }

    #[test]
    fn count_depth_ignores_strings() {
        assert_eq!(count_query_depth(r#"{ a(x: "{ not { real }") }"#), 1);
    }
}
