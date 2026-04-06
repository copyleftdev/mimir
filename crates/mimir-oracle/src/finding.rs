use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Severity level of a security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Category of a security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingCategory {
    IntrospectionEnabled,
    MissingRateLimit,
    InformationLeakage,
    AuthorizationBypass,
    ExcessiveDepth,
    BatchingAbuse,
    CostLimitBypass,
    FieldSuggestionLeak,
    TypeConfusion,
    MutationWithoutAuth,
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingCategory::IntrospectionEnabled => write!(f, "INTROSPECTION_ENABLED"),
            FindingCategory::MissingRateLimit => write!(f, "MISSING_RATE_LIMIT"),
            FindingCategory::InformationLeakage => write!(f, "INFORMATION_LEAKAGE"),
            FindingCategory::AuthorizationBypass => write!(f, "AUTHORIZATION_BYPASS"),
            FindingCategory::ExcessiveDepth => write!(f, "EXCESSIVE_DEPTH"),
            FindingCategory::BatchingAbuse => write!(f, "BATCHING_ABUSE"),
            FindingCategory::CostLimitBypass => write!(f, "COST_LIMIT_BYPASS"),
            FindingCategory::FieldSuggestionLeak => write!(f, "FIELD_SUGGESTION_LEAK"),
            FindingCategory::TypeConfusion => write!(f, "TYPE_CONFUSION"),
            FindingCategory::MutationWithoutAuth => write!(f, "MUTATION_WITHOUT_AUTH"),
        }
    }
}

/// A security finding produced by a property check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding (e.g., "GQL-001").
    pub id: String,
    /// The category of security issue.
    pub category: FindingCategory,
    /// How severe the finding is.
    pub severity: Severity,
    /// Short human-readable title.
    pub title: String,
    /// Detailed description of the issue and its impact.
    pub description: String,
    /// Evidence strings (e.g., response excerpts, matched patterns).
    pub evidence: Vec<String>,
    /// Information needed to reproduce the finding.
    pub reproduction: ReproductionInfo,
}

/// Information needed to reproduce a security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproductionInfo {
    /// The seed used for test generation, if applicable.
    pub seed: Option<u64>,
    /// The GraphQL operation that triggered the finding.
    pub operation: String,
    /// The variables used in the operation.
    pub variables: Value,
    /// A snippet from the response that demonstrates the issue.
    pub response_snippet: Option<String>,
}
