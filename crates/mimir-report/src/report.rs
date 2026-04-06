use chrono::{DateTime, Utc};
use mimir_oracle::Finding;
use serde::{Deserialize, Serialize};

/// Statistics about the GraphQL schema that was scanned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaStats {
    /// Total number of types in the schema.
    pub type_count: usize,
    /// Number of query fields on the root query type.
    pub query_count: usize,
    /// Number of mutation fields on the root mutation type.
    pub mutation_count: usize,
    /// Number of input object types.
    pub input_type_count: usize,
    /// Maximum nesting depth observed in query generation.
    pub max_depth: Option<usize>,
}

/// A complete sweep report summarizing the security scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepReport {
    /// Target URL or endpoint.
    pub target: String,
    /// When the scan started.
    pub started_at: DateTime<Utc>,
    /// When the scan completed.
    pub completed_at: DateTime<Utc>,
    /// Schema statistics.
    pub schema_stats: SchemaStats,
    /// All security findings.
    pub findings: Vec<Finding>,
    /// Total number of GraphQL operations executed.
    pub operations_executed: usize,
    /// Total number of distinct MDP states discovered.
    pub states_discovered: usize,
    /// RNG seed used for reproducibility.
    pub seed: u64,
}

impl SweepReport {
    /// Duration of the scan.
    pub fn duration(&self) -> chrono::Duration {
        self.completed_at - self.started_at
    }

    /// Count findings by severity.
    pub fn count_by_severity(&self) -> SeverityCounts {
        let mut counts = SeverityCounts::default();
        for finding in &self.findings {
            match finding.severity {
                mimir_oracle::Severity::Critical => counts.critical += 1,
                mimir_oracle::Severity::High => counts.high += 1,
                mimir_oracle::Severity::Medium => counts.medium += 1,
                mimir_oracle::Severity::Low => counts.low += 1,
                mimir_oracle::Severity::Info => counts.info += 1,
            }
        }
        counts
    }
}

/// Summary of finding counts by severity level.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use mimir_oracle::finding::{FindingCategory, ReproductionInfo, Severity};

    fn make_finding(severity: Severity, category: FindingCategory) -> Finding {
        Finding {
            id: "test-1".to_string(),
            title: "Test Finding".to_string(),
            description: "A test finding".to_string(),
            severity,
            category,
            evidence: vec!["evidence item".to_string()],
            reproduction: ReproductionInfo {
                seed: Some(42),
                operation: "{ test }".to_string(),
                variables: serde_json::json!({}),
                response_snippet: Some("{}".to_string()),
            },
        }
    }

    fn make_report(findings: Vec<Finding>) -> SweepReport {
        SweepReport {
            target: "https://example.com/graphql".to_string(),
            started_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            completed_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 5, 0).unwrap(),
            schema_stats: SchemaStats {
                type_count: 10,
                query_count: 5,
                mutation_count: 3,
                input_type_count: 2,
                max_depth: Some(4),
            },
            findings,
            operations_executed: 100,
            states_discovered: 15,
            seed: 42,
        }
    }

    #[test]
    fn test_duration() {
        let report = make_report(vec![]);
        let duration = report.duration();
        assert_eq!(duration.num_minutes(), 5);
    }

    #[test]
    fn test_count_by_severity() {
        let findings = vec![
            make_finding(Severity::Critical, FindingCategory::AuthorizationBypass),
            make_finding(Severity::High, FindingCategory::MutationWithoutAuth),
            make_finding(Severity::High, FindingCategory::BatchingAbuse),
            make_finding(Severity::Medium, FindingCategory::InformationLeakage),
            make_finding(Severity::Low, FindingCategory::FieldSuggestionLeak),
            make_finding(Severity::Info, FindingCategory::TypeConfusion),
        ];
        let report = make_report(findings);
        let counts = report.count_by_severity();
        assert_eq!(counts.critical, 1);
        assert_eq!(counts.high, 2);
        assert_eq!(counts.medium, 1);
        assert_eq!(counts.low, 1);
        assert_eq!(counts.info, 1);
    }

    #[test]
    fn test_report_serialization() {
        let report = make_report(vec![make_finding(
            Severity::High,
            FindingCategory::IntrospectionEnabled,
        )]);
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: SweepReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.target, "https://example.com/graphql");
        assert_eq!(deserialized.findings.len(), 1);
    }
}
