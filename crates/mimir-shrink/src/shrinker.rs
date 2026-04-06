use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::sequence::ActionSequence;

/// A function that replays a sequence and returns whether the finding still reproduces.
pub type ReplayFn = Box<dyn Fn(&ActionSequence) -> bool>;

/// Result of shrinking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShrinkResult {
    pub original_length: usize,
    pub shrunk_length: usize,
    pub shrunk_sequence: ActionSequence,
    pub shrink_steps: usize,
    pub reduction_ratio: f64,
}

/// Shrink an action sequence to the minimal reproduction.
///
/// Uses three strategies in order:
/// 1. Binary search for minimal prefix (ddmin-inspired)
/// 2. One-at-a-time removal
/// 3. Contiguous subsequence search
pub struct Shrinker {
    max_attempts: usize,
}

impl Default for Shrinker {
    fn default() -> Self {
        Self { max_attempts: 1000 }
    }
}

impl Shrinker {
    /// Create a new shrinker with the given maximum number of replay attempts.
    pub fn new(max_attempts: usize) -> Self {
        Self { max_attempts }
    }

    /// Shrink the sequence using the replay function to verify each candidate.
    pub fn shrink(&self, sequence: &ActionSequence, replay: &ReplayFn) -> ShrinkResult {
        let original_length = sequence.len();

        if original_length == 0 {
            return ShrinkResult {
                original_length: 0,
                shrunk_length: 0,
                shrunk_sequence: sequence.clone(),
                shrink_steps: 0,
                reduction_ratio: 0.0,
            };
        }

        let mut current = sequence.clone();
        let mut steps = 0;

        // Strategy 1: Binary prefix search
        info!(
            original_length,
            "Starting binary prefix shrink"
        );
        current = self.binary_prefix_shrink(&current, replay, &mut steps);
        debug!(length = current.len(), steps, "After binary prefix");

        // Strategy 2: One-at-a-time removal
        if steps < self.max_attempts {
            info!(
                current_length = current.len(),
                "Starting individual removal shrink"
            );
            current = self.individual_removal_shrink(&current, replay, &mut steps);
            debug!(length = current.len(), steps, "After individual removal");
        }

        // Strategy 3: Contiguous window search
        if steps < self.max_attempts && current.len() > 1 {
            info!(
                current_length = current.len(),
                "Starting contiguous window shrink"
            );
            current = self.contiguous_window_shrink(&current, replay, &mut steps);
            debug!(length = current.len(), steps, "After contiguous windows");
        }

        let shrunk_length = current.len();
        let reduction_ratio = if original_length == 0 {
            0.0
        } else {
            1.0 - (shrunk_length as f64 / original_length as f64)
        };

        info!(
            original_length,
            shrunk_length,
            steps,
            reduction_ratio,
            "Shrinking complete"
        );

        ShrinkResult {
            original_length,
            shrunk_length,
            shrunk_sequence: current,
            shrink_steps: steps,
            reduction_ratio,
        }
    }

    /// Strategy 1: Binary prefix search.
    /// Try first half; if it reproduces, recurse on that. Otherwise try second half.
    fn binary_prefix_shrink(
        &self,
        sequence: &ActionSequence,
        replay: &ReplayFn,
        steps: &mut usize,
    ) -> ActionSequence {
        if sequence.len() <= 1 || *steps >= self.max_attempts {
            return sequence.clone();
        }

        let mid = sequence.len() / 2;

        // Try first half
        let first_half = sequence.slice(0, mid);
        *steps += 1;
        if replay(&first_half) {
            debug!(len = first_half.len(), "First half reproduces, recursing");
            return self.binary_prefix_shrink(&first_half, replay, steps);
        }

        // Try second half
        let second_half = sequence.slice(mid, sequence.len());
        *steps += 1;
        if replay(&second_half) {
            debug!(
                len = second_half.len(),
                "Second half reproduces, recursing"
            );
            return self.binary_prefix_shrink(&second_half, replay, steps);
        }

        sequence.clone()
    }

    /// Strategy 2: One-at-a-time removal.
    /// For each action, try removing it. If still reproduces, keep the shorter sequence.
    /// Repeat until a full pass makes no progress.
    fn individual_removal_shrink(
        &self,
        sequence: &ActionSequence,
        replay: &ReplayFn,
        steps: &mut usize,
    ) -> ActionSequence {
        let mut current = sequence.clone();

        loop {
            let mut made_progress = false;
            let mut i = 0;

            while i < current.len() && *steps < self.max_attempts {
                let candidate = current.without(i);
                *steps += 1;

                if replay(&candidate) {
                    debug!(
                        removed_index = i,
                        new_len = candidate.len(),
                        "Removed action, still reproduces"
                    );
                    current = candidate;
                    made_progress = true;
                    // Don't increment i -- the next action shifted into position i
                } else {
                    i += 1;
                }
            }

            if !made_progress || *steps >= self.max_attempts {
                break;
            }
        }

        current
    }

    /// Strategy 3: Contiguous window search.
    /// Try all windows of decreasing size. First reproducing window wins.
    fn contiguous_window_shrink(
        &self,
        sequence: &ActionSequence,
        replay: &ReplayFn,
        steps: &mut usize,
    ) -> ActionSequence {
        let len = sequence.len();

        // Try windows from size len-1 down to 1
        for window_size in (1..len).rev() {
            if *steps >= self.max_attempts {
                break;
            }

            let num_windows = len - window_size + 1;
            for start in 0..num_windows {
                if *steps >= self.max_attempts {
                    break;
                }

                let candidate = sequence.slice(start, start + window_size);
                *steps += 1;

                if replay(&candidate) {
                    debug!(
                        start,
                        window_size,
                        "Contiguous window reproduces"
                    );
                    // Recurse — maybe we can shrink the window further
                    return self.contiguous_window_shrink(&candidate, replay, steps);
                }
            }
        }

        sequence.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sequence::RecordedAction;

    fn make_action(index: usize, name: &str) -> RecordedAction {
        RecordedAction {
            index,
            operation_name: name.to_string(),
            query: format!("query {name} {{ field }}"),
            variables: serde_json::Value::Null,
            response_status: 200,
            response_body: serde_json::Value::Null,
            triggered_finding: false,
        }
    }

    fn make_sequence(names: &[&str]) -> ActionSequence {
        ActionSequence {
            actions: names
                .iter()
                .enumerate()
                .map(|(i, name)| make_action(i, name))
                .collect(),
            finding_id: "test-finding".to_string(),
            seed: 42,
        }
    }

    #[test]
    fn test_only_last_action_matters() {
        let seq = make_sequence(&["a", "b", "c", "d", "critical"]);

        let replay: ReplayFn = Box::new(|candidate| {
            candidate
                .actions
                .iter()
                .any(|a| a.operation_name == "critical")
        });

        let shrinker = Shrinker::new(1000);
        let result = shrinker.shrink(&seq, &replay);

        assert_eq!(result.shrunk_length, 1);
        assert_eq!(
            result.shrunk_sequence.actions[0].operation_name,
            "critical"
        );
    }

    #[test]
    fn test_first_and_last_matter() {
        let seq = make_sequence(&["setup", "noise1", "noise2", "noise3", "trigger"]);

        let replay: ReplayFn = Box::new(|candidate| {
            let has_setup = candidate
                .actions
                .iter()
                .any(|a| a.operation_name == "setup");
            let has_trigger = candidate
                .actions
                .iter()
                .any(|a| a.operation_name == "trigger");
            has_setup && has_trigger
        });

        let shrinker = Shrinker::new(1000);
        let result = shrinker.shrink(&seq, &replay);

        assert_eq!(result.shrunk_length, 2);
        let names: Vec<&str> = result
            .shrunk_sequence
            .actions
            .iter()
            .map(|a| a.operation_name.as_str())
            .collect();
        assert!(names.contains(&"setup"));
        assert!(names.contains(&"trigger"));
    }

    #[test]
    fn test_everything_matters() {
        let seq = make_sequence(&["a", "b", "c"]);

        // All three actions are required
        let replay: ReplayFn = Box::new(|candidate| {
            let has_a = candidate.actions.iter().any(|a| a.operation_name == "a");
            let has_b = candidate.actions.iter().any(|a| a.operation_name == "b");
            let has_c = candidate.actions.iter().any(|a| a.operation_name == "c");
            has_a && has_b && has_c
        });

        let shrinker = Shrinker::new(1000);
        let result = shrinker.shrink(&seq, &replay);

        assert_eq!(result.shrunk_length, 3);
    }

    #[test]
    fn test_empty_sequence() {
        let seq = make_sequence(&[]);

        let replay: ReplayFn = Box::new(|_| false);

        let shrinker = Shrinker::new(1000);
        let result = shrinker.shrink(&seq, &replay);

        assert_eq!(result.original_length, 0);
        assert_eq!(result.shrunk_length, 0);
        assert_eq!(result.shrink_steps, 0);
    }

    #[test]
    fn test_shrunk_length_leq_original() {
        let seq = make_sequence(&["a", "b", "c", "d", "e", "f", "g", "h"]);

        // Only "d" and "g" are required
        let replay: ReplayFn = Box::new(|candidate| {
            let has_d = candidate.actions.iter().any(|a| a.operation_name == "d");
            let has_g = candidate.actions.iter().any(|a| a.operation_name == "g");
            has_d && has_g
        });

        let shrinker = Shrinker::new(1000);
        let result = shrinker.shrink(&seq, &replay);

        assert!(result.shrunk_length <= result.original_length);
    }

    #[test]
    fn test_reduction_ratio_in_range() {
        let seq = make_sequence(&["a", "b", "c", "d", "e"]);

        let replay: ReplayFn = Box::new(|candidate| {
            candidate
                .actions
                .iter()
                .any(|a| a.operation_name == "c")
        });

        let shrinker = Shrinker::new(1000);
        let result = shrinker.shrink(&seq, &replay);

        assert!(result.reduction_ratio >= 0.0);
        assert!(result.reduction_ratio <= 1.0);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::sequence::RecordedAction;
    use proptest::prelude::*;

    fn arb_action(index: usize) -> RecordedAction {
        RecordedAction {
            index,
            operation_name: format!("op_{index}"),
            query: format!("query Op{index} {{ field }}"),
            variables: serde_json::Value::Null,
            response_status: 200,
            response_body: serde_json::Value::Null,
            triggered_finding: false,
        }
    }

    proptest! {
        #[test]
        fn prop_shrunk_leq_original(len in 0usize..20) {
            let seq = ActionSequence {
                actions: (0..len).map(|i| arb_action(i)).collect(),
                finding_id: "prop-test".to_string(),
                seed: 123,
            };

            // The last action is "required"
            let replay: ReplayFn = Box::new(move |candidate| {
                if len == 0 { return false; }
                let target = format!("op_{}", len - 1);
                candidate.actions.iter().any(|a| a.operation_name == target)
            });

            let shrinker = Shrinker::new(500);
            let result = shrinker.shrink(&seq, &replay);

            prop_assert!(result.shrunk_length <= result.original_length);
        }

        #[test]
        fn prop_reduction_ratio_bounds(len in 1usize..15) {
            let seq = ActionSequence {
                actions: (0..len).map(|i| arb_action(i)).collect(),
                finding_id: "prop-test".to_string(),
                seed: 456,
            };

            let replay: ReplayFn = Box::new(move |candidate| {
                // Always reproduces if non-empty
                !candidate.actions.is_empty()
            });

            let shrinker = Shrinker::new(500);
            let result = shrinker.shrink(&seq, &replay);

            prop_assert!(result.reduction_ratio >= 0.0);
            prop_assert!(result.reduction_ratio <= 1.0);
        }
    }
}
