pub mod inference;
pub mod network;
pub mod node;

pub use inference::{compound_risk, propagate, what_if};
pub use network::BayesNetwork;
pub use node::{Dependency, VulnNode};
