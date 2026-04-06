use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::node::{Dependency, VulnNode};

/// A Bayesian network of vulnerability dependencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BayesNetwork {
    pub nodes: IndexMap<String, VulnNode>,
    pub dependencies: Vec<Dependency>,
}

impl BayesNetwork {
    pub fn new() -> Self {
        Self {
            nodes: IndexMap::new(),
            dependencies: Vec::new(),
        }
    }

    /// Add a vulnerability node with a prior probability.
    pub fn add_vulnerability(&mut self, id: &str, name: &str, prior: f64) {
        let node = VulnNode::new(id, name, prior);
        self.nodes.insert(id.to_string(), node);
    }

    /// Add a conditional dependency.
    ///
    /// "If `parent` is true, `child` has probability `conditional_prob` of being true."
    /// "If `parent` is false, `child` has probability `base_prob` of being true."
    pub fn add_dependency(
        &mut self,
        parent: &str,
        child: &str,
        conditional_prob: f64,
        base_prob: f64,
    ) {
        self.dependencies
            .push(Dependency::new(parent, child, conditional_prob, base_prob));
    }

    /// Record an observation (evidence).
    pub fn observe(&mut self, id: &str, present: bool) {
        if let Some(node) = self.nodes.get_mut(id) {
            node.observed = true;
            node.observation = Some(present);
            node.posterior = if present { 1.0 } else { 0.0 };
        }
    }

    /// Get the current posterior for a node.
    pub fn posterior(&self, id: &str) -> Option<f64> {
        self.nodes.get(id).map(|n| n.posterior)
    }

    /// Get all nodes sorted by posterior (highest risk first).
    pub fn ranked_risks(&self) -> Vec<(&str, f64)> {
        let mut risks: Vec<(&str, f64)> = self
            .nodes
            .values()
            .map(|n| (n.id.as_str(), n.posterior))
            .collect();
        risks.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        risks
    }

    /// Build the default GraphQL vulnerability network.
    pub fn default_graphql_network() -> Self {
        let mut net = Self::new();

        // Nodes with priors
        net.add_vulnerability("introspection", "Introspection enabled", 0.70);
        net.add_vulnerability("no_rate_limit", "No rate limiting", 0.40);
        net.add_vulnerability("weak_auth", "Weak authorization", 0.30);
        net.add_vulnerability("field_suggestions", "Field suggestions in errors", 0.50);
        net.add_vulnerability("info_leakage", "Information leakage in errors", 0.35);
        net.add_vulnerability("batch_abuse", "Batch queries not limited", 0.25);
        net.add_vulnerability("depth_unlimited", "No depth limiting", 0.20);
        net.add_vulnerability("data_extraction", "Ability to extract sensitive data", 0.10);
        net.add_vulnerability("account_takeover", "Ability to take over accounts", 0.05);
        net.add_vulnerability("denial_of_service", "Ability to DoS the service", 0.15);

        // Dependencies: parent -> child (conditional_prob, base_prob)
        net.add_dependency("introspection", "data_extraction", 0.40, 0.05);
        net.add_dependency("no_rate_limit", "data_extraction", 0.35, 0.10);
        net.add_dependency("no_rate_limit", "denial_of_service", 0.60, 0.05);
        net.add_dependency("weak_auth", "account_takeover", 0.50, 0.02);
        net.add_dependency("weak_auth", "data_extraction", 0.45, 0.08);
        net.add_dependency("field_suggestions", "info_leakage", 0.70, 0.20);
        net.add_dependency("info_leakage", "data_extraction", 0.30, 0.10);
        net.add_dependency("batch_abuse", "denial_of_service", 0.45, 0.10);
        net.add_dependency("depth_unlimited", "denial_of_service", 0.50, 0.08);

        net
    }
}

impl Default for BayesNetwork {
    fn default() -> Self {
        Self::new()
    }
}
