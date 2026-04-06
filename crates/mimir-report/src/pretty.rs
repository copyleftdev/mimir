use crate::report::SweepReport;
use mimir_oracle::finding::Severity;

// ANSI color codes
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const CYAN: &str = "\x1b[36m";
const WHITE: &str = "\x1b[37m";
const BG_RED: &str = "\x1b[41m";
const MAGENTA: &str = "\x1b[35m";
const DIM: &str = "\x1b[2m";

const SEPARATOR_EQ: &str =
    "========================================================================";
const SEPARATOR_DASH: &str =
    "------------------------------------------------------------------------";

/// Get the ANSI color code for a severity level.
fn severity_color(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => BG_RED,
        Severity::High => RED,
        Severity::Medium => YELLOW,
        Severity::Low => BLUE,
        Severity::Info => CYAN,
    }
}

/// Format a severity label with ANSI colors.
fn colored_severity(severity: &Severity) -> String {
    let color = severity_color(severity);
    let label = match severity {
        Severity::Critical => " CRITICAL ",
        Severity::High => " HIGH ",
        Severity::Medium => " MEDIUM ",
        Severity::Low => " LOW ",
        Severity::Info => " INFO ",
    };
    format!("{BOLD}{color}{WHITE}{label}{RESET}")
}

/// Generate a human-readable, ANSI-colored terminal report.
pub fn to_pretty(report: &SweepReport) -> String {
    let mut out = String::new();

    // Header
    out.push_str(&format!("\n{BOLD}{MAGENTA}{SEPARATOR_EQ}{RESET}\n"));
    out.push_str(&format!("{BOLD}{MAGENTA}  mimir Security Report{RESET}\n"));
    out.push_str(&format!("{BOLD}{MAGENTA}{SEPARATOR_EQ}{RESET}\n\n"));

    // Target and timing
    out.push_str(&format!("{BOLD}Target:{RESET}    {}\n", report.target));
    out.push_str(&format!(
        "{BOLD}Started:{RESET}   {}\n",
        report.started_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    out.push_str(&format!(
        "{BOLD}Completed:{RESET} {}\n",
        report.completed_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    let duration = report.duration();
    out.push_str(&format!(
        "{BOLD}Duration:{RESET}  {}m {}s\n",
        duration.num_minutes(),
        duration.num_seconds() % 60
    ));
    out.push_str(&format!("{BOLD}Seed:{RESET}      {}\n", report.seed));

    // Schema stats
    out.push_str(&format!("\n{BOLD}{CYAN}{SEPARATOR_DASH}{RESET}\n"));
    out.push_str(&format!("{BOLD}{CYAN}  Schema Statistics{RESET}\n"));
    out.push_str(&format!("{BOLD}{CYAN}{SEPARATOR_DASH}{RESET}\n\n"));
    out.push_str(&format!(
        "  Types: {}  |  Queries: {}  |  Mutations: {}  |  Inputs: {}\n",
        report.schema_stats.type_count,
        report.schema_stats.query_count,
        report.schema_stats.mutation_count,
        report.schema_stats.input_type_count,
    ));
    if let Some(depth) = report.schema_stats.max_depth {
        out.push_str(&format!("  Max depth: {depth}\n"));
    }

    // Scan stats
    out.push_str(&format!("\n{BOLD}{CYAN}{SEPARATOR_DASH}{RESET}\n"));
    out.push_str(&format!("{BOLD}{CYAN}  Exploration Statistics{RESET}\n"));
    out.push_str(&format!("{BOLD}{CYAN}{SEPARATOR_DASH}{RESET}\n\n"));
    out.push_str(&format!(
        "  Operations executed: {}\n",
        report.operations_executed
    ));
    out.push_str(&format!(
        "  States discovered:   {}\n",
        report.states_discovered
    ));

    // Severity summary
    let counts = report.count_by_severity();
    out.push_str(&format!("\n{BOLD}{CYAN}{SEPARATOR_DASH}{RESET}\n"));
    out.push_str(&format!("{BOLD}{CYAN}  Finding Summary{RESET}\n"));
    out.push_str(&format!("{BOLD}{CYAN}{SEPARATOR_DASH}{RESET}\n\n"));
    out.push_str(&format!(
        "  {} Critical: {}  {} High: {}  {} Medium: {}  {} Low: {}  {} Info: {}\n",
        colored_severity(&Severity::Critical),
        counts.critical,
        colored_severity(&Severity::High),
        counts.high,
        colored_severity(&Severity::Medium),
        counts.medium,
        colored_severity(&Severity::Low),
        counts.low,
        colored_severity(&Severity::Info),
        counts.info,
    ));
    out.push_str(&format!(
        "  {BOLD}Total: {}{RESET}\n",
        report.findings.len()
    ));

    if report.findings.is_empty() {
        out.push_str(&format!("\n  {DIM}No security findings detected.{RESET}\n"));
    } else {
        // Group findings by category
        let mut by_category: std::collections::BTreeMap<String, Vec<&mimir_oracle::Finding>> =
            std::collections::BTreeMap::new();
        for finding in &report.findings {
            by_category
                .entry(format!("{}", finding.category))
                .or_default()
                .push(finding);
        }

        out.push_str(&format!("\n{BOLD}{CYAN}{SEPARATOR_DASH}{RESET}\n"));
        out.push_str(&format!("{BOLD}{CYAN}  Findings by Category{RESET}\n"));
        out.push_str(&format!("{BOLD}{CYAN}{SEPARATOR_DASH}{RESET}\n"));

        for (category, findings) in &by_category {
            out.push_str(&format!(
                "\n  {BOLD}{category}{RESET} ({} finding{})\n",
                findings.len(),
                if findings.len() == 1 { "" } else { "s" }
            ));

            for finding in findings {
                out.push_str(&format!(
                    "\n    {} {BOLD}{}{RESET}\n",
                    colored_severity(&finding.severity),
                    finding.title,
                ));
                out.push_str(&format!("    {DIM}ID: {}{RESET}\n", finding.id));
                out.push_str(&format!("    {}\n", finding.description));
                out.push_str(&format!(
                    "    {DIM}Operation: {}{RESET}\n",
                    finding.reproduction.operation,
                ));

                if !finding.evidence.is_empty() {
                    out.push_str(&format!("    {DIM}Evidence:{RESET}\n"));
                    for item in &finding.evidence {
                        out.push_str(&format!("      {DIM}- {item}{RESET}\n"));
                    }
                }

                if let Some(seed) = finding.reproduction.seed {
                    out.push_str(&format!("    {DIM}Seed: {seed}{RESET}\n"));
                }
            }
        }
    }

    // Footer
    out.push_str(&format!("\n{BOLD}{MAGENTA}{SEPARATOR_EQ}{RESET}\n"));
    out.push_str(&format!(
        "{DIM}  Report generated by mimir | seed={} | {}{RESET}\n",
        report.seed,
        report.completed_at.format("%Y-%m-%d %H:%M:%S UTC"),
    ));
    out.push_str(&format!("{BOLD}{MAGENTA}{SEPARATOR_EQ}{RESET}\n"));

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{SchemaStats, SweepReport};
    use chrono::{TimeZone, Utc};
    use mimir_oracle::finding::{Finding, FindingCategory, ReproductionInfo, Severity};

    fn make_finding(
        id: &str,
        title: &str,
        severity: Severity,
        category: FindingCategory,
    ) -> Finding {
        Finding {
            id: id.to_string(),
            category,
            severity,
            title: title.to_string(),
            description: format!("Description for {id}"),
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
            completed_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 2, 30).unwrap(),
            schema_stats: SchemaStats {
                type_count: 10,
                query_count: 5,
                mutation_count: 3,
                input_type_count: 2,
                max_depth: Some(4),
            },
            findings,
            operations_executed: 150,
            states_discovered: 12,
            seed: 42,
        }
    }

    #[test]
    fn pretty_contains_target() {
        let report = make_report(vec![]);
        let output = to_pretty(&report);
        assert!(output.contains("https://example.com/graphql"));
    }

    #[test]
    fn pretty_contains_header() {
        let report = make_report(vec![]);
        let output = to_pretty(&report);
        assert!(output.contains("mimir Security Report"));
    }

    #[test]
    fn pretty_contains_schema_stats() {
        let report = make_report(vec![]);
        let output = to_pretty(&report);
        assert!(output.contains("Types: 10"));
        assert!(output.contains("Queries: 5"));
        assert!(output.contains("Mutations: 3"));
    }

    #[test]
    fn pretty_contains_findings() {
        let findings = vec![
            make_finding(
                "F-001",
                "Auth Bypass in createUser",
                Severity::Critical,
                FindingCategory::IntrospectionEnabled,
            ),
            make_finding(
                "F-002",
                "Mutation without auth",
                Severity::High,
                FindingCategory::MutationWithoutAuth,
            ),
        ];
        let report = make_report(findings);
        let output = to_pretty(&report);
        assert!(output.contains("Auth Bypass in createUser"));
        assert!(output.contains("Mutation without auth"));
    }

    #[test]
    fn pretty_shows_no_findings_message() {
        let report = make_report(vec![]);
        let output = to_pretty(&report);
        assert!(output.contains("No security findings detected"));
    }

    #[test]
    fn pretty_groups_by_category() {
        let findings = vec![
            make_finding(
                "F-001",
                "Finding 1",
                Severity::High,
                FindingCategory::IntrospectionEnabled,
            ),
            make_finding(
                "F-002",
                "Finding 2",
                Severity::Medium,
                FindingCategory::IntrospectionEnabled,
            ),
            make_finding(
                "F-003",
                "Finding 3",
                Severity::High,
                FindingCategory::MutationWithoutAuth,
            ),
        ];
        let report = make_report(findings);
        let output = to_pretty(&report);
        // Both categories should appear
        assert!(output.contains("INTROSPECTION_ENABLED"));
        assert!(output.contains("2 findings"));
        assert!(output.contains("MUTATION_WITHOUT_AUTH"));
        assert!(output.contains("1 finding)"));
    }

    #[test]
    fn pretty_contains_evidence() {
        let findings = vec![make_finding(
            "F-001",
            "Test",
            Severity::High,
            FindingCategory::IntrospectionEnabled,
        )];
        let report = make_report(findings);
        let output = to_pretty(&report);
        assert!(output.contains("evidence item"));
    }

    #[test]
    fn pretty_contains_ansi_codes() {
        let findings = vec![make_finding(
            "F-001",
            "Test",
            Severity::Critical,
            FindingCategory::IntrospectionEnabled,
        )];
        let report = make_report(findings);
        let output = to_pretty(&report);
        // Should contain ANSI escape codes
        assert!(output.contains("\x1b["));
    }
}
