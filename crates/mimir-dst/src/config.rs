use serde::{Deserialize, Serialize};

/// Configuration for a security sweep run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepConfig {
    /// The target GraphQL endpoint URL.
    pub target_url: String,
    /// Seed for deterministic exploration.
    pub seed: u64,
    /// Maximum number of operations to execute.
    pub max_operations: usize,
    /// Maximum query depth for generation.
    pub max_depth: usize,
    /// Exploration strategy to use.
    pub strategy: StrategyKind,
    /// Headers to include for authenticated requests.
    pub auth_headers: Vec<(String, String)>,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
    /// Output format for the report.
    pub output_format: OutputFormat,
    /// Whether to actually execute mutations (dangerous: modifies server state).
    pub execute_mutations: bool,
}

/// Which multi-armed bandit strategy to use for exploration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StrategyKind {
    Ucb1,
    EpsilonGreedy(f64),
    Thompson,
}

/// Output format for the sweep report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    Pretty,
    Json,
    Sarif,
}

impl Default for SweepConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            seed: 0,
            max_operations: 1000,
            max_depth: 3,
            strategy: StrategyKind::Ucb1,
            auth_headers: Vec::new(),
            timeout_secs: 10,
            output_format: OutputFormat::Pretty,
            execute_mutations: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let config = SweepConfig::default();
        assert_eq!(config.target_url, "");
        assert_eq!(config.seed, 0);
        assert_eq!(config.max_operations, 1000);
        assert_eq!(config.max_depth, 3);
        assert!(matches!(config.strategy, StrategyKind::Ucb1));
        assert!(config.auth_headers.is_empty());
        assert_eq!(config.timeout_secs, 10);
        assert_eq!(config.output_format, OutputFormat::Pretty);
        assert!(!config.execute_mutations);
    }

    #[test]
    fn config_serialization_roundtrip() {
        let config = SweepConfig {
            target_url: "http://localhost:4000/graphql".to_string(),
            seed: 42,
            max_operations: 500,
            max_depth: 5,
            strategy: StrategyKind::EpsilonGreedy(0.1),
            auth_headers: vec![("Authorization".to_string(), "Bearer tok".to_string())],
            timeout_secs: 30,
            output_format: OutputFormat::Json,
            execute_mutations: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: SweepConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.target_url, config.target_url);
        assert_eq!(deserialized.seed, config.seed);
        assert_eq!(deserialized.max_operations, config.max_operations);
    }
}
