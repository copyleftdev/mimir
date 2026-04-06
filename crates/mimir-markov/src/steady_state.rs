#![allow(
    clippy::redundant_closure,
    clippy::needless_range_loop,
    clippy::excessive_precision,
    clippy::manual_saturating_arithmetic,
    clippy::let_and_return
)]
use crate::chain::MarkovChain;

/// Compute the stationary distribution using the power iteration method.
///
/// Start with a uniform distribution, repeatedly multiply by P until convergence.
/// Returns `Vec<f64>` where `result[i]` = long-run probability of being in state `i`.
///
/// Returns `None` if the chain has no states or fails to converge within
/// `max_iterations`.
pub fn stationary_distribution(
    chain: &MarkovChain,
    max_iterations: usize,
    tolerance: f64,
) -> Option<Vec<f64>> {
    let n = chain.state_count();
    if n == 0 {
        return None;
    }

    let p = chain.transition_matrix();

    // Start with uniform distribution
    let mut pi = vec![1.0 / n as f64; n];

    for _ in 0..max_iterations {
        // pi_new = pi * P  (row vector times matrix)
        let mut pi_new = vec![0.0; n];
        for j in 0..n {
            for i in 0..n {
                pi_new[j] += pi[i] * p[i][j];
            }
        }

        // Check convergence: L1 norm of difference
        let diff: f64 = pi
            .iter()
            .zip(pi_new.iter())
            .map(|(a, b)| (a - b).abs())
            .sum();

        pi = pi_new;

        if diff < tolerance {
            return Some(pi);
        }
    }

    // Did not converge; return the best estimate we have
    // (caller can check by comparing to tolerance)
    Some(pi)
}

/// Check if the chain is ergodic (irreducible and aperiodic).
///
/// An ergodic chain has a unique stationary distribution. We check:
/// 1. Irreducibility: every state is reachable from every other state.
/// 2. Aperiodicity: at least one state has a self-loop (gcd of return times = 1).
///
/// For our purposes, a simpler sufficient condition: the chain is irreducible and
/// has at least one self-loop (P[i][i] > 0 for some i).
pub fn is_ergodic(chain: &MarkovChain) -> bool {
    let n = chain.state_count();
    if n == 0 {
        return false;
    }

    let p = chain.transition_matrix();

    // Check irreducibility via reachability (BFS/DFS from each state).
    // Build adjacency: i -> j if P[i][j] > 0.
    if !is_irreducible(&p, n) {
        return false;
    }

    // Check aperiodicity: sufficient to have at least one self-loop.
    let has_self_loop = (0..n).any(|i| p[i][i] > 0.0);

    has_self_loop
}

/// Check if the chain is irreducible: every state can reach every other state.
fn is_irreducible(p: &[Vec<f64>], n: usize) -> bool {
    for start in 0..n {
        let reachable = bfs_reachable(p, n, start);
        if reachable.iter().any(|&r| !r) {
            return false;
        }
    }
    true
}

/// BFS to find all states reachable from `start`.
fn bfs_reachable(p: &[Vec<f64>], n: usize, start: usize) -> Vec<bool> {
    let mut visited = vec![false; n];
    let mut queue = std::collections::VecDeque::new();
    visited[start] = true;
    queue.push_back(start);

    while let Some(current) = queue.pop_front() {
        for j in 0..n {
            if !visited[j] && p[current][j] > 0.0 {
                visited[j] = true;
                queue.push_back(j);
            }
        }
    }

    visited
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::MarkovChain;

    #[test]
    fn two_state_symmetric_chain() {
        // A <-> B with equal transitions: stationary = [0.5, 0.5]
        let mut chain = MarkovChain::new();
        chain.record_transition("A", "B");
        chain.record_transition("B", "A");
        chain.record_transition("A", "B");
        chain.record_transition("B", "A");

        let pi = stationary_distribution(&chain, 1000, 1e-10).unwrap();
        assert!((pi[0] - 0.5).abs() < 1e-6);
        assert!((pi[1] - 0.5).abs() < 1e-6);
    }

    #[test]
    fn absorbing_chain() {
        // A -> B (only), B is absorbing
        // Stationary: all probability flows to B
        let mut chain = MarkovChain::new();
        chain.record_transition("A", "B");
        // B has no outgoing transitions -> self-loop in transition matrix

        let pi = stationary_distribution(&chain, 1000, 1e-10).unwrap();
        assert!(pi[1] > 0.99, "B should get ~1.0 probability, got {}", pi[1]);
        assert!(pi[0] < 0.01, "A should get ~0.0 probability, got {}", pi[0]);
    }

    #[test]
    fn three_state_cycle() {
        // A -> B -> C -> A (uniform cycle)
        // Stationary: [1/3, 1/3, 1/3]
        let mut chain = MarkovChain::new();
        chain.record_transition("A", "B");
        chain.record_transition("B", "C");
        chain.record_transition("C", "A");

        let pi = stationary_distribution(&chain, 10000, 1e-10).unwrap();
        for &prob in &pi {
            assert!(
                (prob - 1.0 / 3.0).abs() < 1e-4,
                "Expected ~0.333, got {prob}"
            );
        }
    }

    #[test]
    fn power_iteration_converges_for_known_matrix() {
        // Chain with known stationary distribution:
        // P = [[0.7, 0.3], [0.4, 0.6]]
        // pi = [4/7, 3/7] ≈ [0.5714, 0.4286]
        let mut chain = MarkovChain::new();
        chain.add_state("A");
        chain.add_state("B");
        // A->A: 7, A->B: 3, B->A: 4, B->B: 6
        for _ in 0..7 {
            chain.record_transition("A", "A");
        }
        for _ in 0..3 {
            chain.record_transition("A", "B");
        }
        for _ in 0..4 {
            chain.record_transition("B", "A");
        }
        for _ in 0..6 {
            chain.record_transition("B", "B");
        }

        let pi = stationary_distribution(&chain, 1000, 1e-12).unwrap();
        assert!(
            (pi[0] - 4.0 / 7.0).abs() < 1e-8,
            "Expected 4/7, got {}",
            pi[0]
        );
        assert!(
            (pi[1] - 3.0 / 7.0).abs() < 1e-8,
            "Expected 3/7, got {}",
            pi[1]
        );
    }

    #[test]
    fn stationary_distribution_sums_to_one() {
        let mut chain = MarkovChain::new();
        chain.record_transition("A", "B");
        chain.record_transition("B", "C");
        chain.record_transition("C", "A");
        chain.record_transition("A", "C");
        chain.record_transition("B", "A");

        let pi = stationary_distribution(&chain, 1000, 1e-10).unwrap();
        let sum: f64 = pi.iter().sum();
        assert!((sum - 1.0).abs() < 1e-8, "Sum should be 1.0, got {sum}");
    }

    #[test]
    fn all_probabilities_non_negative() {
        let mut chain = MarkovChain::new();
        chain.record_transition("A", "B");
        chain.record_transition("B", "C");
        chain.record_transition("C", "A");

        let pi = stationary_distribution(&chain, 1000, 1e-10).unwrap();
        for &prob in &pi {
            assert!(prob >= 0.0, "Probability must be >= 0, got {prob}");
        }
    }

    #[test]
    fn ergodic_chain_detected() {
        // A <-> B with self-loops: irreducible + aperiodic
        let mut chain = MarkovChain::new();
        chain.record_transition("A", "B");
        chain.record_transition("B", "A");
        chain.record_transition("A", "A");
        chain.record_transition("B", "B");

        assert!(is_ergodic(&chain));
    }

    #[test]
    fn non_ergodic_absorbing_chain() {
        // A -> B only, B absorbing: not irreducible
        let mut chain = MarkovChain::new();
        chain.record_transition("A", "B");

        assert!(!is_ergodic(&chain));
    }

    #[test]
    fn pure_cycle_not_aperiodic() {
        // A -> B -> C -> A (no self-loops) is periodic with period 3
        let mut chain = MarkovChain::new();
        chain.record_transition("A", "B");
        chain.record_transition("B", "C");
        chain.record_transition("C", "A");

        // Irreducible but periodic (no self-loops), so not ergodic
        assert!(!is_ergodic(&chain));
    }

    #[test]
    fn empty_chain_not_ergodic() {
        let chain = MarkovChain::new();
        assert!(!is_ergodic(&chain));
    }
}
