use serde::{Deserialize, Serialize};

/// Configuration for the SPRT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SprtConfig {
    /// Type I error rate (false positive): probability of declaring "vulnerable" when secure.
    /// Default: 0.05 (5%)
    pub alpha: f64,
    /// Type II error rate (false negative): probability of declaring "secure" when vulnerable.
    /// Default: 0.10 (10%)
    pub beta: f64,
    /// Minimum observations before a decision can be made.
    pub min_observations: usize,
    /// Maximum observations (hard stop).
    pub max_observations: usize,
}

impl Default for SprtConfig {
    fn default() -> Self {
        Self {
            alpha: 0.05,
            beta: 0.10,
            min_observations: 10,
            max_observations: 10_000,
        }
    }
}
