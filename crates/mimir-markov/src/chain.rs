#![allow(
    clippy::redundant_closure,
    clippy::needless_range_loop,
    clippy::excessive_precision,
    clippy::manual_saturating_arithmetic,
    clippy::let_and_return
)]
use serde::{Deserialize, Serialize};

/// A discrete Markov chain built from observed state transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkovChain {
    /// State names
    pub states: Vec<String>,
    /// Transition count matrix: counts[i][j] = number of observed transitions from i to j
    pub transition_counts: Vec<Vec<u64>>,
    /// Total transitions observed
    pub total_transitions: u64,
}

impl MarkovChain {
    pub fn new() -> Self {
        Self {
            states: Vec::new(),
            transition_counts: Vec::new(),
            total_transitions: 0,
        }
    }

    /// Add a state if it doesn't exist, return its index.
    pub fn add_state(&mut self, name: &str) -> usize {
        if let Some(idx) = self.state_index(name) {
            return idx;
        }
        let idx = self.states.len();
        self.states.push(name.to_string());

        // Expand the transition matrix: add a new column to every existing row,
        // then add a new row of the correct width.
        for row in &mut self.transition_counts {
            row.push(0);
        }
        self.transition_counts.push(vec![0; idx + 1]);

        idx
    }

    /// Record a transition from state `from` to state `to`.
    pub fn record_transition(&mut self, from: &str, to: &str) {
        let i = self.add_state(from);
        let j = self.add_state(to);
        self.transition_counts[i][j] += 1;
        self.total_transitions += 1;
    }

    /// Get the transition probability matrix P where P[i][j] = P(j|i).
    ///
    /// For rows with zero total transitions, returns a uniform distribution
    /// (absorbing states are handled separately in analysis).
    pub fn transition_matrix(&self) -> Vec<Vec<f64>> {
        let n = self.states.len();
        let mut matrix = vec![vec![0.0; n]; n];

        for i in 0..n {
            let row_sum: u64 = self.transition_counts[i].iter().sum();
            if row_sum == 0 {
                // Absorbing state: self-loop with probability 1
                matrix[i][i] = 1.0;
            } else {
                for j in 0..n {
                    matrix[i][j] = self.transition_counts[i][j] as f64 / row_sum as f64;
                }
            }
        }

        matrix
    }

    /// Number of states.
    pub fn state_count(&self) -> usize {
        self.states.len()
    }

    /// Get state index by name.
    pub fn state_index(&self, name: &str) -> Option<usize> {
        self.states.iter().position(|s| s == name)
    }

    /// Get state name by index.
    pub fn state_name(&self, index: usize) -> Option<&str> {
        self.states.get(index).map(|s| s.as_str())
    }
}

impl Default for MarkovChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_state_is_idempotent() {
        let mut chain = MarkovChain::new();
        let i1 = chain.add_state("A");
        let i2 = chain.add_state("A");
        assert_eq!(i1, i2);
        assert_eq!(chain.state_count(), 1);
    }

    #[test]
    fn record_transition_creates_states() {
        let mut chain = MarkovChain::new();
        chain.record_transition("A", "B");
        assert_eq!(chain.state_count(), 2);
        assert_eq!(chain.total_transitions, 1);
        assert_eq!(chain.transition_counts[0][1], 1);
    }

    #[test]
    fn transition_matrix_rows_sum_to_one() {
        let mut chain = MarkovChain::new();
        chain.record_transition("A", "B");
        chain.record_transition("A", "A");
        chain.record_transition("B", "A");
        let matrix = chain.transition_matrix();
        for row in &matrix {
            let sum: f64 = row.iter().sum();
            assert!((sum - 1.0).abs() < 1e-12, "Row sums to {sum}, expected 1.0");
        }
    }

    #[test]
    fn absorbing_state_has_self_loop() {
        let mut chain = MarkovChain::new();
        chain.record_transition("A", "B");
        // B has no outgoing transitions
        let matrix = chain.transition_matrix();
        assert_eq!(matrix[1][1], 1.0); // B -> B self-loop
    }
}
