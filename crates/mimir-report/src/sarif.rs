use crate::report::SweepReport;
use mimir_oracle::finding::{FindingCategory, Severity};

/// Map severity to SARIF level string.
fn sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Map severity to a numeric SARIF security-severity score (0-10).
fn security_severity(severity: &Severity) -> f64 {
    match severity {
        Severity::Critical => 9.5,
        Severity::High => 7.5,
        Severity::Medium => 5.0,
        Severity::Low => 2.5,
        Severity::Info => 1.0,
    }
}

/// Generate a SARIF rule ID from the finding category.
fn rule_id(category: &FindingCategory) -> String {
    format!("mimir/{category}")
}

/// Generate a SARIF v2.1.0 document from a sweep report.
///
/// Conforms to the OASIS SARIF specification:
/// <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>
pub fn to_sarif(report: &SweepReport) -> serde_json::Value {
    // Collect unique rules from findings.
    let mut seen_rules = std::collections::HashSet::new();
    let mut rules = Vec::new();

    for finding in &report.findings {
        let rid = rule_id(&finding.category);
        if seen_rules.insert(rid.clone()) {
            rules.push(serde_json::json!({
                "id": rid,
                "name": format!("{}", finding.category),
                "shortDescription": {
                    "text": format!("{} detection", finding.category)
                },
                "fullDescription": {
                    "text": format!(
                        "Detects {} vulnerabilities in GraphQL APIs.",
                        finding.category
                    )
                },
                "properties": {
                    "security-severity": format!("{:.1}", security_severity(&finding.severity))
                },
                "helpUri": "https://github.com/copyleftdev/mimir"
            }));
        }
    }

    // Build results.
    let results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "ruleId": rule_id(&finding.category),
                "level": sarif_level(&finding.severity),
                "message": {
                    "text": finding.description.clone()
                },
                "properties": {
                    "finding-id": finding.id,
                    "evidence": finding.evidence,
                    "operation": finding.reproduction.operation,
                }
            })
        })
        .collect();

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mimir",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/copyleftdev/mimir",
                        "rules": rules
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": true,
                        "startTimeUtc": report.started_at.to_rfc3339(),
                        "endTimeUtc": report.completed_at.to_rfc3339(),
                        "properties": {
                            "target": report.target,
                            "operations_executed": report.operations_executed,
                            "states_discovered": report.states_discovered,
                            "seed": report.seed,
                        }
                    }
                ]
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{SchemaStats, SweepReport};
    use chrono::{TimeZone, Utc};
    use mimir_oracle::finding::{Finding, FindingCategory, ReproductionInfo, Severity};

    fn make_finding(id: &str, severity: Severity, category: FindingCategory) -> Finding {
        Finding {
            id: id.to_string(),
            category,
            severity,
            title: format!("Finding {id}"),
            description: format!("Description for finding {id}"),
            evidence: vec!["Some evidence".to_string()],
            reproduction: ReproductionInfo {
                seed: Some(42),
                operation: "mutation { test }".to_string(),
                variables: serde_json::json!({}),
                response_snippet: Some(r#"{"errors": [{"message": "access denied"}]}"#.to_string()),
            },
        }
    }

    fn make_report() -> SweepReport {
        SweepReport {
            target: "https://example.com/graphql".to_string(),
            started_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            completed_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 5, 0).unwrap(),
            schema_stats: SchemaStats {
                type_count: 20,
                query_count: 8,
                mutation_count: 5,
                input_type_count: 4,
                max_depth: Some(6),
            },
            findings: vec![
                make_finding("F-001", Severity::Critical, FindingCategory::IntrospectionEnabled),
                make_finding("F-002", Severity::High, FindingCategory::MutationWithoutAuth),
                make_finding("F-003", Severity::Medium, FindingCategory::InformationLeakage),
            ],
            operations_executed: 250,
            states_discovered: 30,
            seed: 12345,
        }
    }

    #[test]
    fn sarif_has_correct_version() {
        let report = make_report();
        let sarif = to_sarif(&report);
        assert_eq!(sarif["version"], "2.1.0");
    }

    #[test]
    fn sarif_has_schema_reference() {
        let report = make_report();
        let sarif = to_sarif(&report);
        assert!(sarif["$schema"].as_str().unwrap().contains("sarif-schema-2.1.0"));
    }

    #[test]
    fn sarif_contains_all_results() {
        let report = make_report();
        let sarif = to_sarif(&report);
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn sarif_has_tool_info() {
        let report = make_report();
        let sarif = to_sarif(&report);
        let tool = &sarif["runs"][0]["tool"]["driver"];
        assert_eq!(tool["name"], "mimir");
    }

    #[test]
    fn sarif_maps_severity_to_level() {
        assert_eq!(sarif_level(&Severity::Critical), "error");
        assert_eq!(sarif_level(&Severity::High), "error");
        assert_eq!(sarif_level(&Severity::Medium), "warning");
        assert_eq!(sarif_level(&Severity::Low), "note");
        assert_eq!(sarif_level(&Severity::Info), "note");
    }

    #[test]
    fn sarif_has_rules() {
        let report = make_report();
        let sarif = to_sarif(&report);
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        // 3 findings with 3 different categories = 3 rules
        assert_eq!(rules.len(), 3);
    }

    #[test]
    fn sarif_has_invocation() {
        let report = make_report();
        let sarif = to_sarif(&report);
        let invocations = sarif["runs"][0]["invocations"].as_array().unwrap();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0]["executionSuccessful"], true);
    }

    #[test]
    fn sarif_empty_findings() {
        let mut report = make_report();
        report.findings.clear();
        let sarif = to_sarif(&report);
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
    }
}
