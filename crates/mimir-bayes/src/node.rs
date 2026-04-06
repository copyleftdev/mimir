use serde::{Deserialize, Serialize};

/// A node in the Bayesian vulnerability network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnNode {
    /// Unique identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Prior probability of this vulnerability existing (before any evidence)
    pub prior: f64,
    /// Current posterior probability (updated with evidence)
    pub posterior: f64,
    /// Whether this has been directly observed
    pub observed: bool,
    /// The observation (if observed)
    pub observation: Option<bool>,
}

impl VulnNode {
    /// Create a new vulnerability node with the given prior.
    pub fn new(id: &str, name: &str, prior: f64) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            prior,
            posterior: prior,
            observed: false,
            observation: None,
        }
    }
}

/// A conditional dependency between vulnerabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    /// Parent node ID (the condition)
    pub parent: String,
    /// Child node ID (the dependent)
    pub child: String,
    /// P(child=true | parent=true) -- how much parent being true increases child's probability
    pub conditional_prob: f64,
    /// P(child=true | parent=false)
    pub base_prob: f64,
}

impl Dependency {
    /// Create a new dependency.
    pub fn new(parent: &str, child: &str, conditional_prob: f64, base_prob: f64) -> Self {
        Self {
            parent: parent.to_string(),
            child: child.to_string(),
            conditional_prob,
            base_prob,
        }
    }
}
