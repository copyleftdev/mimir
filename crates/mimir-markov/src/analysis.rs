#![allow(
    clippy::redundant_closure,
    clippy::needless_range_loop,
    clippy::excessive_precision,
    clippy::manual_saturating_arithmetic,
    clippy::let_and_return
)]
use serde::{Deserialize, Serialize};

use crate::chain::MarkovChain;
use crate::steady_state;

/// Analysis results from the Markov chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkovAnalysis {
    /// States ordered by steady-state probability (highest first)
    pub ranked_states: Vec<(String, f64)>,
    /// Whether the chain is ergodic
    pub is_ergodic: bool,
    /// Mixing time estimate (how many steps to reach ~stationary)
    pub mixing_time_estimate: usize,
    /// Absorbing states (states with no outgoing transitions to other states)
    pub absorbing_states: Vec<String>,
    /// Transient states (states not in any SCC that includes a cycle)
    pub transient_states: Vec<String>,
}

/// Analyze a Markov chain built from exploration data.
pub fn analyze_chain(chain: &MarkovChain) -> MarkovAnalysis {
    let n = chain.state_count();
    let ergodic = steady_state::is_ergodic(chain);

    // Compute stationary distribution
    let pi =
        steady_state::stationary_distribution(chain, 10_000, 1e-10).unwrap_or_else(|| vec![0.0; n]);

    // Rank states by steady-state probability (descending)
    let mut ranked_states: Vec<(String, f64)> = chain
        .states
        .iter()
        .zip(pi.iter())
        .map(|(name, &prob)| (name.clone(), prob))
        .collect();
    ranked_states.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Find absorbing states: states whose only outgoing transition is to themselves.
    // In the transition count matrix, row i has no positive entries for j != i.
    let absorbing_states = find_absorbing_states(chain);

    // Find transient states: states that are not part of any bottom SCC.
    let transient_states = find_transient_states(chain);

    // Estimate mixing time
    let mixing_time = estimate_mixing_time(chain, 0.01);

    MarkovAnalysis {
        ranked_states,
        is_ergodic: ergodic,
        mixing_time_estimate: mixing_time,
        absorbing_states,
        transient_states,
    }
}

/// Find absorbing states: states with no outgoing transitions to other states.
fn find_absorbing_states(chain: &MarkovChain) -> Vec<String> {
    let n = chain.state_count();
    let mut absorbing = Vec::new();

    for i in 0..n {
        let has_exit = (0..n).any(|j| j != i && chain.transition_counts[i][j] > 0);
        if !has_exit {
            absorbing.push(chain.states[i].clone());
        }
    }

    absorbing
}

/// Find transient states using Tarjan's SCC algorithm.
///
/// A state is transient if it is not in a "bottom" SCC (an SCC with no edges leaving it).
/// Absorbing states form their own bottom SCCs with self-loops.
fn find_transient_states(chain: &MarkovChain) -> Vec<String> {
    let n = chain.state_count();
    if n == 0 {
        return Vec::new();
    }

    let p = chain.transition_matrix();

    // Build adjacency list
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
    for i in 0..n {
        for j in 0..n {
            if p[i][j] > 0.0 {
                adj[i].push(j);
            }
        }
    }

    // Tarjan's SCC
    let sccs = tarjan_scc(&adj, n);

    // A bottom SCC is one where no node in it has an edge to a node outside it.
    let mut node_to_scc = vec![0usize; n];
    for (scc_idx, scc) in sccs.iter().enumerate() {
        for &node in scc {
            node_to_scc[node] = scc_idx;
        }
    }

    let mut is_bottom_scc = vec![true; sccs.len()];
    for (scc_idx, scc) in sccs.iter().enumerate() {
        for &node in scc {
            for &neighbor in &adj[node] {
                if node_to_scc[neighbor] != scc_idx {
                    is_bottom_scc[scc_idx] = false;
                    break;
                }
            }
            if !is_bottom_scc[scc_idx] {
                break;
            }
        }
    }

    // Transient states are those NOT in a bottom SCC
    let mut transient = Vec::new();
    for i in 0..n {
        if !is_bottom_scc[node_to_scc[i]] {
            transient.push(chain.states[i].clone());
        }
    }

    transient
}

/// Tarjan's algorithm for strongly connected components.
/// Returns SCCs in reverse topological order.
fn tarjan_scc(adj: &[Vec<usize>], n: usize) -> Vec<Vec<usize>> {
    struct TarjanState {
        index_counter: usize,
        stack: Vec<usize>,
        on_stack: Vec<bool>,
        index: Vec<Option<usize>>,
        lowlink: Vec<usize>,
        sccs: Vec<Vec<usize>>,
    }

    let mut state = TarjanState {
        index_counter: 0,
        stack: Vec::new(),
        on_stack: vec![false; n],
        index: vec![None; n],
        lowlink: vec![0; n],
        sccs: Vec::new(),
    };

    fn strongconnect(v: usize, adj: &[Vec<usize>], state: &mut TarjanState) {
        state.index[v] = Some(state.index_counter);
        state.lowlink[v] = state.index_counter;
        state.index_counter += 1;
        state.stack.push(v);
        state.on_stack[v] = true;

        for &w in &adj[v] {
            if state.index[w].is_none() {
                strongconnect(w, adj, state);
                state.lowlink[v] = state.lowlink[v].min(state.lowlink[w]);
            } else if state.on_stack[w] {
                state.lowlink[v] = state.lowlink[v].min(state.index[w].unwrap());
            }
        }

        if state.lowlink[v] == state.index[v].unwrap() {
            let mut scc = Vec::new();
            loop {
                let w = state.stack.pop().unwrap();
                state.on_stack[w] = false;
                scc.push(w);
                if w == v {
                    break;
                }
            }
            state.sccs.push(scc);
        }
    }

    for v in 0..n {
        if state.index[v].is_none() {
            strongconnect(v, adj, &mut state);
        }
    }

    state.sccs
}

/// Estimate mixing time: number of steps for total variation distance < threshold.
///
/// Simulates the power iteration from the worst initial state (each pure state)
/// and finds the maximum number of steps needed.
fn estimate_mixing_time(chain: &MarkovChain, threshold: f64) -> usize {
    let n = chain.state_count();
    if n == 0 {
        return 0;
    }

    let p = chain.transition_matrix();

    // Get stationary distribution
    let pi = match steady_state::stationary_distribution(chain, 10_000, 1e-12) {
        Some(pi) => pi,
        None => return 0,
    };

    let mut max_steps = 0;

    // For each starting state, simulate forward
    for start in 0..n {
        let mut dist = vec![0.0; n];
        dist[start] = 1.0;

        for step in 1..=10_000 {
            // dist = dist * P
            let mut new_dist = vec![0.0; n];
            for j in 0..n {
                for i in 0..n {
                    new_dist[j] += dist[i] * p[i][j];
                }
            }
            dist = new_dist;

            // Total variation distance = 0.5 * sum |dist[i] - pi[i]|
            let tv: f64 = 0.5
                * dist
                    .iter()
                    .zip(pi.iter())
                    .map(|(a, b)| (a - b).abs())
                    .sum::<f64>();

            if tv < threshold {
                if step > max_steps {
                    max_steps = step;
                }
                break;
            }

            if step == 10_000 {
                max_steps = 10_000;
            }
        }
    }

    max_steps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::MarkovChain;

    #[test]
    fn analyze_simple_ergodic_chain() {
        let mut chain = MarkovChain::new();
        chain.record_transition("A", "B");
        chain.record_transition("B", "A");
        chain.record_transition("A", "A");
        chain.record_transition("B", "B");

        let analysis = analyze_chain(&chain);
        assert!(analysis.is_ergodic);
        assert!(analysis.absorbing_states.is_empty());
        assert!(analysis.transient_states.is_empty());
        assert_eq!(analysis.ranked_states.len(), 2);
    }

    #[test]
    fn analyze_absorbing_chain() {
        let mut chain = MarkovChain::new();
        chain.record_transition("A", "B");
        // B is absorbing

        let analysis = analyze_chain(&chain);
        assert!(!analysis.is_ergodic);
        assert!(analysis.absorbing_states.contains(&"B".to_string()));
        assert!(analysis.transient_states.contains(&"A".to_string()));

        // B should be ranked first (highest probability)
        assert_eq!(analysis.ranked_states[0].0, "B");
    }

    #[test]
    fn analyze_three_state_cycle() {
        let mut chain = MarkovChain::new();
        chain.record_transition("A", "B");
        chain.record_transition("B", "C");
        chain.record_transition("C", "A");

        let analysis = analyze_chain(&chain);
        // Pure cycle is not ergodic (periodic)
        assert!(!analysis.is_ergodic);
        assert!(analysis.absorbing_states.is_empty());
        assert!(analysis.transient_states.is_empty());

        // All states should have roughly equal probability
        for (_, prob) in &analysis.ranked_states {
            assert!(
                (prob - 1.0 / 3.0).abs() < 1e-3,
                "Expected ~0.333, got {prob}"
            );
        }
    }

    #[test]
    fn mixing_time_is_reasonable() {
        let mut chain = MarkovChain::new();
        // Strongly connected with self-loops: should mix fast
        chain.record_transition("A", "B");
        chain.record_transition("B", "A");
        chain.record_transition("A", "A");
        chain.record_transition("B", "B");

        let analysis = analyze_chain(&chain);
        assert!(
            analysis.mixing_time_estimate < 1000,
            "Mixing time too high: {}",
            analysis.mixing_time_estimate
        );
    }

    #[test]
    fn ranked_states_sorted_descending() {
        let mut chain = MarkovChain::new();
        chain.record_transition("A", "B");
        chain.record_transition("B", "A");
        chain.record_transition("B", "B");
        chain.record_transition("B", "B");

        let analysis = analyze_chain(&chain);
        for window in analysis.ranked_states.windows(2) {
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
}
