use crate::shrinker::ShrinkResult;

/// Extension trait for formatting shrink results.
pub trait ShrinkResultExt {
    /// Format as a human-readable reproduction guide.
    fn reproduction_guide(&self) -> String;
}

impl ShrinkResultExt for ShrinkResult {
    fn reproduction_guide(&self) -> String {
        let mut guide = String::new();

        guide.push_str("=== Minimal Reproduction Guide ===\n\n");

        guide.push_str(&format!(
            "Finding: {}\n",
            self.shrunk_sequence.finding_id
        ));
        guide.push_str(&format!(
            "Original sequence length: {}\n",
            self.original_length
        ));
        guide.push_str(&format!(
            "Minimized sequence length: {}\n",
            self.shrunk_length
        ));
        guide.push_str(&format!(
            "Reduction: {:.1}% ({} steps)\n\n",
            self.reduction_ratio * 100.0,
            self.shrink_steps
        ));

        guide.push_str("Steps to reproduce:\n");
        guide.push_str(&"-".repeat(40));
        guide.push('\n');

        for (i, action) in self.shrunk_sequence.actions.iter().enumerate() {
            guide.push_str(&format!(
                "\nStep {} — {} (HTTP {})\n",
                i + 1,
                action.operation_name,
                action.response_status
            ));
            guide.push_str(&format!("  Query:\n    {}\n", action.query));

            if action.variables != serde_json::Value::Null {
                guide.push_str(&format!(
                    "  Variables:\n    {}\n",
                    serde_json::to_string_pretty(&action.variables)
                        .unwrap_or_else(|_| "{}".to_string())
                ));
            }

            if action.triggered_finding {
                guide.push_str("  >>> THIS STEP TRIGGERED THE FINDING <<<\n");
            }
        }

        guide.push('\n');
        guide.push_str(&"-".repeat(40));
        guide.push('\n');
        guide.push_str(&format!(
            "Seed: {} (use this to replay deterministically)\n",
            self.shrunk_sequence.seed
        ));

        guide
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sequence::{ActionSequence, RecordedAction};

    #[test]
    fn test_reproduction_guide_format() {
        let result = ShrinkResult {
            original_length: 10,
            shrunk_length: 2,
            shrunk_sequence: ActionSequence {
                actions: vec![
                    RecordedAction {
                        index: 0,
                        operation_name: "SetFormValue".to_string(),
                        query: "mutation SetFormValue($input: FormInput!) { setFormValue(input: $input) { id } }".to_string(),
                        variables: serde_json::json!({"input": {"field": "email", "value": "test@evil.com"}}),
                        response_status: 200,
                        response_body: serde_json::json!({"data": {"setFormValue": {"id": "1"}}}),
                        triggered_finding: false,
                    },
                    RecordedAction {
                        index: 1,
                        operation_name: "SubmitForm".to_string(),
                        query: "mutation SubmitForm($id: ID!) { submitForm(id: $id) { status } }".to_string(),
                        variables: serde_json::json!({"id": "1"}),
                        response_status: 200,
                        response_body: serde_json::json!({"data": {"submitForm": {"status": "submitted"}}}),
                        triggered_finding: true,
                    },
                ],
                finding_id: "IDOR-001".to_string(),
                seed: 42,
            },
            shrink_steps: 15,
            reduction_ratio: 0.8,
        };

        let guide = result.reproduction_guide();

        assert!(guide.contains("Minimal Reproduction Guide"));
        assert!(guide.contains("IDOR-001"));
        assert!(guide.contains("Original sequence length: 10"));
        assert!(guide.contains("Minimized sequence length: 2"));
        assert!(guide.contains("80.0%"));
        assert!(guide.contains("SetFormValue"));
        assert!(guide.contains("SubmitForm"));
        assert!(guide.contains("THIS STEP TRIGGERED THE FINDING"));
        assert!(guide.contains("Seed: 42"));
    }

    #[test]
    fn test_reproduction_guide_empty() {
        let result = ShrinkResult {
            original_length: 0,
            shrunk_length: 0,
            shrunk_sequence: ActionSequence {
                actions: vec![],
                finding_id: "EMPTY-001".to_string(),
                seed: 0,
            },
            shrink_steps: 0,
            reduction_ratio: 0.0,
        };

        let guide = result.reproduction_guide();
        assert!(guide.contains("EMPTY-001"));
        assert!(guide.contains("Minimized sequence length: 0"));
    }
}
