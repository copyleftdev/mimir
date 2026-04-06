use crate::finding::Finding;
use crate::properties::{
    PropertyCheck, PropertyContext, PropertyResult, batch_queries_should_be_limited,
    depth_should_be_limited, errors_should_not_leak_info, introspection_should_be_disabled,
    mutations_require_auth, no_field_suggestions,
};

/// Registry of security properties to evaluate against GraphQL responses.
pub struct PropertyRegistry {
    properties: Vec<(&'static str, PropertyCheck)>,
}

impl PropertyRegistry {
    /// Create a registry with all built-in security properties.
    pub fn default_registry() -> Self {
        let mut registry = Self {
            properties: Vec::new(),
        };
        registry.register(
            "introspection_should_be_disabled",
            introspection_should_be_disabled,
        );
        registry.register("mutations_require_auth", mutations_require_auth);
        registry.register("errors_should_not_leak_info", errors_should_not_leak_info);
        registry.register("no_field_suggestions", no_field_suggestions);
        registry.register(
            "batch_queries_should_be_limited",
            batch_queries_should_be_limited,
        );
        registry.register("depth_should_be_limited", depth_should_be_limited);
        registry
    }

    /// Register a new property check.
    pub fn register(&mut self, name: &'static str, check: PropertyCheck) {
        self.properties.push((name, check));
    }

    /// Evaluate all registered properties against the given context.
    ///
    /// Returns a list of findings for any properties that failed.
    pub fn check_all(&self, ctx: &PropertyContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for &(_name, check) in &self.properties {
            if let PropertyResult::Fail(finding) = check(ctx) {
                findings.push(finding);
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{FindingCategory, Severity};
    use crate::properties::AuthState;
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

    #[test]
    fn default_registry_has_all_properties() {
        let registry = PropertyRegistry::default_registry();
        assert_eq!(registry.properties.len(), 6);
    }

    #[test]
    fn check_all_returns_empty_for_normal_query() {
        let registry = PropertyRegistry::default_registry();
        let ctx = make_context(|_| {});
        let findings = registry.check_all(&ctx);
        assert!(
            findings.is_empty(),
            "Expected no findings for normal query, got {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn check_all_detects_introspection() {
        let registry = PropertyRegistry::default_registry();
        let ctx = make_context(|ctx| {
            ctx.request_query = "{ __schema { types { name } } }".to_string();
            ctx.response = json!({"data": {"__schema": {"types": [{"name": "Query"}]}}});
        });
        let findings = registry.check_all(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.category == FindingCategory::IntrospectionEnabled),
            "Expected introspection finding"
        );
    }

    #[test]
    fn check_all_detects_unauthed_mutation() {
        let registry = PropertyRegistry::default_registry();
        let ctx = make_context(|ctx| {
            ctx.request_query = "mutation { deleteUser(id: \"1\") { id } }".to_string();
            ctx.auth_state = AuthState::None;
            ctx.response = json!({"data": {"deleteUser": {"id": "1"}}});
        });
        let findings = registry.check_all(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.category == FindingCategory::MutationWithoutAuth),
            "Expected mutation-without-auth finding"
        );
    }

    #[test]
    fn check_all_detects_info_leakage() {
        let registry = PropertyRegistry::default_registry();
        let ctx = make_context(|ctx| {
            ctx.response_errors = vec![
                "TypeError: Cannot read property 'id' of undefined at /app/node_modules/graphql/execution.js:42".to_string(),
            ];
        });
        let findings = registry.check_all(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.category == FindingCategory::InformationLeakage),
            "Expected information leakage finding"
        );
    }

    #[test]
    fn check_all_detects_field_suggestions() {
        let registry = PropertyRegistry::default_registry();
        let ctx = make_context(|ctx| {
            ctx.response_errors = vec![
                "Cannot query field \"naem\" on type \"User\". Did you mean \"name\"?".to_string(),
            ];
        });
        let findings = registry.check_all(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.category == FindingCategory::FieldSuggestionLeak),
            "Expected field suggestion leak finding"
        );
    }

    #[test]
    fn custom_property_can_be_registered() {
        let mut registry = PropertyRegistry::default_registry();

        fn always_fail(ctx: &PropertyContext) -> PropertyResult {
            PropertyResult::Fail(crate::finding::Finding {
                id: "CUSTOM-001".to_string(),
                category: FindingCategory::TypeConfusion,
                severity: Severity::Info,
                title: "Custom check".to_string(),
                description: "Always fails for testing".to_string(),
                evidence: vec![],
                reproduction: crate::finding::ReproductionInfo {
                    seed: None,
                    operation: ctx.request_query.clone(),
                    variables: ctx.request_variables.clone(),
                    response_snippet: None,
                },
            })
        }

        registry.register("always_fail", always_fail);
        assert_eq!(registry.properties.len(), 7);

        let ctx = make_context(|_| {});
        let findings = registry.check_all(&ctx);
        assert!(
            findings.iter().any(|f| f.id == "CUSTOM-001"),
            "Expected custom finding"
        );
    }

    #[test]
    fn finding_severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }
}
