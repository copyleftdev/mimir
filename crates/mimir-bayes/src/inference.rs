use crate::network::BayesNetwork;

/// Update all posteriors given current observations.
///
/// Uses a simplified form of belief propagation suitable for a DAG.
/// For each unobserved node with parents, we compute:
///
///   P(child | evidence) = sum over parent configs of P(child | parent_config) * P(parent_config | evidence)
///
/// For a node with multiple parents, we treat parents as independent (noisy-OR model):
///   P(child=false | parents) = product over parents of P(child=false | parent_i)
///   P(child=true | parents) = 1 - P(child=false | parents)
///
/// We iterate until convergence since child posteriors may feed into grandchildren.
pub fn propagate(network: &mut BayesNetwork) {
    // Run multiple passes to propagate through chains of dependencies.
    // In a DAG we'd need at most depth(DAG) passes, but we iterate to convergence.
    let max_passes = 100;
    let tolerance = 1e-12;

    for _ in 0..max_passes {
        let mut max_change: f64 = 0.0;

        // Collect the node IDs so we can iterate without holding a borrow on the network.
        let node_ids: Vec<String> = network.nodes.keys().cloned().collect();

        for node_id in &node_ids {
            let node = &network.nodes[node_id];

            // Skip observed nodes -- their posterior is fixed.
            if node.observed {
                continue;
            }

            // Find all dependencies where this node is the child.
            let parent_deps: Vec<(String, f64, f64)> = network
                .dependencies
                .iter()
                .filter(|d| d.child == *node_id)
                .map(|d| (d.parent.clone(), d.conditional_prob, d.base_prob))
                .collect();

            if parent_deps.is_empty() {
                // No parents: posterior stays at prior
                continue;
            }

            // Noisy-OR combination:
            // P(child=false) = product_i P(child=false | parent_i's state)
            //
            // For each parent i:
            //   P(child=false | parent_i) = P(parent_i=true) * (1 - conditional_prob_i)
            //                              + P(parent_i=false) * (1 - base_prob_i)
            let mut prob_false: f64 = 1.0;

            for (parent_id, cond_prob, base_prob) in &parent_deps {
                let parent_posterior = network
                    .nodes
                    .get(parent_id)
                    .map(|n| n.posterior)
                    .unwrap_or(0.0);

                // P(child=false given this parent's current belief)
                let p_false_given_parent = parent_posterior * (1.0 - cond_prob)
                    + (1.0 - parent_posterior) * (1.0 - base_prob);

                prob_false *= p_false_given_parent;
            }

            let new_posterior = 1.0 - prob_false;

            // Clamp to [0, 1] for safety
            let new_posterior = new_posterior.clamp(0.0, 1.0);

            let old_posterior = network.nodes[node_id].posterior;
            let change = (new_posterior - old_posterior).abs();
            if change > max_change {
                max_change = change;
            }

            network.nodes.get_mut(node_id).unwrap().posterior = new_posterior;
        }

        if max_change < tolerance {
            break;
        }
    }
}

/// Compute compound risk: probability that ALL of the given vulnerabilities
/// exist simultaneously.
///
/// Under the assumption that node posteriors (after propagation) represent
/// marginal probabilities and, lacking full joint distribution information,
/// we use the upper bound: P(A and B) <= min(P(A), P(B)).
///
/// For a more precise (but still approximate) estimate under conditional
/// independence given parents, we multiply the marginals. This gives a lower
/// bound when nodes are positively correlated.
///
/// We return the product of posteriors, which is a conservative estimate
/// (the true compound risk is between the product and the minimum).
pub fn compound_risk(network: &BayesNetwork, vuln_ids: &[&str]) -> f64 {
    let mut risk = 1.0;
    for id in vuln_ids {
        let posterior = network.nodes.get(*id).map(|n| n.posterior).unwrap_or(0.0);
        risk *= posterior;
    }
    risk
}

/// What-if analysis: if we observed this vulnerability, what would change?
///
/// Returns a clone of the network with the observation applied and beliefs
/// propagated. The original network is not modified.
pub fn what_if(network: &BayesNetwork, vuln_id: &str, present: bool) -> BayesNetwork {
    let mut cloned = network.clone();
    cloned.observe(vuln_id, present);
    propagate(&mut cloned);
    cloned
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::BayesNetwork;

    #[test]
    fn observing_introspection_increases_data_extraction() {
        let mut net = BayesNetwork::default_graphql_network();
        let before = net.posterior("data_extraction").unwrap();

        net.observe("introspection", true);
        propagate(&mut net);

        let after = net.posterior("data_extraction").unwrap();
        assert!(
            after > before,
            "data_extraction should increase: before={before}, after={after}"
        );
    }

    #[test]
    fn observing_no_rate_limit_and_depth_unlimited_increases_dos() {
        let mut net = BayesNetwork::default_graphql_network();
        let before = net.posterior("denial_of_service").unwrap();

        net.observe("no_rate_limit", true);
        net.observe("depth_unlimited", true);
        propagate(&mut net);

        let after = net.posterior("denial_of_service").unwrap();
        assert!(
            after > before,
            "denial_of_service should increase significantly: before={before}, after={after}"
        );
        // With both parents observed true, should be quite high
        assert!(
            after > 0.5,
            "denial_of_service should be > 0.5 with both parents true, got {after}"
        );
    }

    #[test]
    fn unobserved_nodes_posterior_equals_prior_before_propagation() {
        let net = BayesNetwork::default_graphql_network();
        for node in net.nodes.values() {
            assert!(
                (node.posterior - node.prior).abs() < 1e-12,
                "Node {} posterior ({}) should equal prior ({}) before propagation",
                node.id,
                node.posterior,
                node.prior
            );
        }
    }

    #[test]
    fn what_if_does_not_modify_original() {
        let net = BayesNetwork::default_graphql_network();
        let original_posterior = net.posterior("data_extraction").unwrap();

        let _modified = what_if(&net, "introspection", true);

        let still_original = net.posterior("data_extraction").unwrap();
        assert!(
            (still_original - original_posterior).abs() < 1e-12,
            "Original network should not be modified"
        );
    }

    #[test]
    fn all_posteriors_in_valid_range() {
        let mut net = BayesNetwork::default_graphql_network();
        net.observe("introspection", true);
        net.observe("no_rate_limit", true);
        net.observe("weak_auth", true);
        propagate(&mut net);

        for node in net.nodes.values() {
            assert!(
                (0.0..=1.0).contains(&node.posterior),
                "Node {} has invalid posterior: {}",
                node.id,
                node.posterior
            );
        }
    }

    #[test]
    fn compound_risk_leq_min_individual() {
        let mut net = BayesNetwork::default_graphql_network();
        net.observe("introspection", true);
        propagate(&mut net);

        let ids = &["data_extraction", "denial_of_service"];
        let compound = compound_risk(&net, ids);

        let min_individual = ids
            .iter()
            .map(|id| net.posterior(id).unwrap())
            .fold(f64::INFINITY, f64::min);

        assert!(
            compound <= min_individual + 1e-12,
            "Compound risk ({compound}) should be <= min individual ({min_individual})"
        );
    }

    #[test]
    fn ranked_risks_sorted_descending() {
        let mut net = BayesNetwork::default_graphql_network();
        net.observe("introspection", true);
        propagate(&mut net);

        let ranked = net.ranked_risks();
        for window in ranked.windows(2) {
            assert!(
                window[0].1 >= window[1].1,
                "Not sorted: {} ({}) before {} ({})",
                window[0].0,
                window[0].1,
                window[1].0,
                window[1].1
            );
        }
    }

    #[test]
    fn observing_false_decreases_dependent() {
        let mut net = BayesNetwork::default_graphql_network();
        // First propagate with defaults
        propagate(&mut net);
        let before = net.posterior("data_extraction").unwrap();

        // Now observe that introspection is NOT present
        let net2 = what_if(&net, "introspection", false);
        let after = net2.posterior("data_extraction").unwrap();

        assert!(
            after < before,
            "data_extraction should decrease when introspection=false: before={before}, after={after}"
        );
    }

    #[test]
    fn propagation_through_chain() {
        // field_suggestions -> info_leakage -> data_extraction
        // Observing field_suggestions=true should increase data_extraction
        let mut net = BayesNetwork::default_graphql_network();
        propagate(&mut net);
        let before = net.posterior("data_extraction").unwrap();

        let net2 = what_if(&net, "field_suggestions", true);
        let after = net2.posterior("data_extraction").unwrap();

        assert!(
            after > before,
            "data_extraction should increase via chain: before={before}, after={after}"
        );
    }

    #[test]
    fn default_network_has_correct_node_count() {
        let net = BayesNetwork::default_graphql_network();
        assert_eq!(net.nodes.len(), 10);
        assert_eq!(net.dependencies.len(), 9);
    }

    #[test]
    fn compound_risk_of_single_node_equals_posterior() {
        let mut net = BayesNetwork::default_graphql_network();
        net.observe("introspection", true);
        propagate(&mut net);

        let single = compound_risk(&net, &["data_extraction"]);
        let posterior = net.posterior("data_extraction").unwrap();
        assert!(
            (single - posterior).abs() < 1e-12,
            "Single-node compound risk should equal posterior"
        );
    }
}
