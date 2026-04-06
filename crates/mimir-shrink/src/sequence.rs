use serde::{Deserialize, Serialize};

/// A recorded action in an attack sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedAction {
    pub index: usize,
    pub operation_name: String,
    pub query: String,
    pub variables: serde_json::Value,
    pub response_status: u16,
    pub response_body: serde_json::Value,
    pub triggered_finding: bool,
}

/// A sequence of operations that led to a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSequence {
    pub actions: Vec<RecordedAction>,
    pub finding_id: String,
    pub seed: u64,
}

impl ActionSequence {
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Create a subsequence by removing the action at the given index.
    pub fn without(&self, index: usize) -> Self {
        let actions = self
            .actions
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != index)
            .map(|(_, a)| a)
            .enumerate()
            .map(|(new_idx, a)| {
                let mut cloned = a.clone();
                cloned.index = new_idx;
                cloned
            })
            .collect();

        Self {
            actions,
            finding_id: self.finding_id.clone(),
            seed: self.seed,
        }
    }

    /// Create a subsequence keeping only the given indices.
    pub fn keep_only(&self, indices: &[usize]) -> Self {
        let actions = indices
            .iter()
            .enumerate()
            .filter_map(|(new_idx, &orig_idx)| {
                self.actions.get(orig_idx).map(|a| {
                    let mut cloned = a.clone();
                    cloned.index = new_idx;
                    cloned
                })
            })
            .collect();

        Self {
            actions,
            finding_id: self.finding_id.clone(),
            seed: self.seed,
        }
    }

    /// Create a subsequence from a contiguous range.
    pub fn slice(&self, start: usize, end: usize) -> Self {
        let end = end.min(self.actions.len());
        let start = start.min(end);

        let actions = self.actions[start..end]
            .iter()
            .enumerate()
            .map(|(new_idx, a)| {
                let mut cloned = a.clone();
                cloned.index = new_idx;
                cloned
            })
            .collect();

        Self {
            actions,
            finding_id: self.finding_id.clone(),
            seed: self.seed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_action(index: usize, triggered: bool) -> RecordedAction {
        RecordedAction {
            index,
            operation_name: format!("op_{index}"),
            query: format!("query Op{index} {{ field }}"),
            variables: serde_json::Value::Null,
            response_status: 200,
            response_body: serde_json::Value::Null,
            triggered_finding: triggered,
        }
    }

    fn make_sequence(n: usize) -> ActionSequence {
        ActionSequence {
            actions: (0..n).map(|i| make_action(i, i == n - 1)).collect(),
            finding_id: "test-finding".to_string(),
            seed: 42,
        }
    }

    #[test]
    fn test_len_and_is_empty() {
        let empty = make_sequence(0);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let seq = make_sequence(5);
        assert!(!seq.is_empty());
        assert_eq!(seq.len(), 5);
    }

    #[test]
    fn test_without() {
        let seq = make_sequence(5);
        let shorter = seq.without(2);
        assert_eq!(shorter.len(), 4);
        // Indices should be re-numbered 0..4
        for (i, action) in shorter.actions.iter().enumerate() {
            assert_eq!(action.index, i);
        }
        // Original op_2 should be gone
        let names: Vec<&str> = shorter
            .actions
            .iter()
            .map(|a| a.operation_name.as_str())
            .collect();
        assert!(!names.contains(&"op_2"));
    }

    #[test]
    fn test_keep_only() {
        let seq = make_sequence(5);
        let kept = seq.keep_only(&[0, 4]);
        assert_eq!(kept.len(), 2);
        assert_eq!(kept.actions[0].operation_name, "op_0");
        assert_eq!(kept.actions[1].operation_name, "op_4");
        assert_eq!(kept.actions[0].index, 0);
        assert_eq!(kept.actions[1].index, 1);
    }

    #[test]
    fn test_slice() {
        let seq = make_sequence(5);
        let sliced = seq.slice(1, 3);
        assert_eq!(sliced.len(), 2);
        assert_eq!(sliced.actions[0].operation_name, "op_1");
        assert_eq!(sliced.actions[1].operation_name, "op_2");
        assert_eq!(sliced.actions[0].index, 0);
        assert_eq!(sliced.actions[1].index, 1);
    }

    #[test]
    fn test_slice_clamps() {
        let seq = make_sequence(3);
        let sliced = seq.slice(0, 100);
        assert_eq!(sliced.len(), 3);

        let sliced2 = seq.slice(50, 100);
        assert_eq!(sliced2.len(), 0);
    }
}
