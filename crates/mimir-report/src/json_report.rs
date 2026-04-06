use crate::report::SweepReport;

/// Generate a simple JSON report from a sweep report.
///
/// The output includes all findings, schema statistics, scan metadata,
/// and reproduction information (seed, target).
pub fn to_json(report: &SweepReport) -> serde_json::Value {
    let counts = report.count_by_severity();
    let duration_secs = report.duration().num_seconds();

    let findings_json: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "severity": format!("{}", f.severity),
                "category": format!("{}", f.category),
                "evidence": f.evidence,
                "reproduction": {
                    "seed": f.reproduction.seed,
                    "operation": f.reproduction.operation,
                    "variables": f.reproduction.variables,
                    "response_snippet": f.reproduction.response_snippet,
                },
            })
        })
        .collect();

    serde_json::json!({
        "target": report.target,
        "scan": {
            "started_at": report.started_at.to_rfc3339(),
            "completed_at": report.completed_at.to_rfc3339(),
            "duration_seconds": duration_secs,
            "operations_executed": report.operations_executed,
            "states_discovered": report.states_discovered,
            "seed": report.seed,
        },
        "schema": {
            "type_count": report.schema_stats.type_count,
            "query_count": report.schema_stats.query_count,
            "mutation_count": report.schema_stats.mutation_count,
            "input_type_count": report.schema_stats.input_type_count,
            "max_depth": report.schema_stats.max_depth,
        },
        "summary": {
            "total_findings": report.findings.len(),
            "critical": counts.critical,
            "high": counts.high,
            "medium": counts.medium,
            "low": counts.low,
            "info": counts.info,
        },
        "findings": findings_json,
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
            description: format!("Description for {id}"),
            evidence: vec!["evidence".to_string()],
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
            target: "https://api.example.com/graphql".to_string(),
            started_at: Utc.with_ymd_and_hms(2026, 3, 15, 10, 0, 0).unwrap(),
            completed_at: Utc.with_ymd_and_hms(2026, 3, 15, 10, 3, 30).unwrap(),
            schema_stats: SchemaStats {
                type_count: 15,
                query_count: 6,
                mutation_count: 4,
                input_type_count: 3,
                max_depth: Some(5),
            },
            findings,
            operations_executed: 200,
            states_discovered: 20,
            seed: 9999,
        }
    }

    #[test]
    fn json_contains_target() {
        let report = make_report(vec![]);
        let json = to_json(&report);
        assert_eq!(json["target"], "https://api.example.com/graphql");
    }

    #[test]
    fn json_contains_scan_metadata() {
        let report = make_report(vec![]);
        let json = to_json(&report);
        assert_eq!(json["scan"]["operations_executed"], 200);
        assert_eq!(json["scan"]["states_discovered"], 20);
        assert_eq!(json["scan"]["seed"], 9999);
        assert_eq!(json["scan"]["duration_seconds"], 210); // 3 min 30 sec
    }

    #[test]
    fn json_contains_schema_stats() {
        let report = make_report(vec![]);
        let json = to_json(&report);
        assert_eq!(json["schema"]["type_count"], 15);
        assert_eq!(json["schema"]["query_count"], 6);
        assert_eq!(json["schema"]["mutation_count"], 4);
    }

    #[test]
    fn json_contains_findings() {
        let findings = vec![
            make_finding("F-001", Severity::High, FindingCategory::IntrospectionEnabled),
            make_finding("F-002", Severity::Low, FindingCategory::FieldSuggestionLeak),
        ];
        let report = make_report(findings);
        let json = to_json(&report);

        let findings_arr = json["findings"].as_array().unwrap();
        assert_eq!(findings_arr.len(), 2);
        assert_eq!(findings_arr[0]["id"], "F-001");
        assert_eq!(findings_arr[1]["id"], "F-002");
    }

    #[test]
    fn json_has_severity_summary() {
        let findings = vec![
            make_finding("F-001", Severity::Critical, FindingCategory::IntrospectionEnabled),
            make_finding("F-002", Severity::High, FindingCategory::MutationWithoutAuth),
            make_finding("F-003", Severity::High, FindingCategory::BatchingAbuse),
        ];
        let report = make_report(findings);
        let json = to_json(&report);
        assert_eq!(json["summary"]["total_findings"], 3);
        assert_eq!(json["summary"]["critical"], 1);
        assert_eq!(json["summary"]["high"], 2);
    }

    #[test]
    fn json_empty_findings() {
        let report = make_report(vec![]);
        let json = to_json(&report);
        let findings_arr = json["findings"].as_array().unwrap();
        assert!(findings_arr.is_empty());
        assert_eq!(json["summary"]["total_findings"], 0);
    }
}
