use crate::type_graph::TypeGraph;
use indexmap::IndexMap;
use std::collections::VecDeque;

/// Compute betweenness centrality for all nodes using Brandes' algorithm.
///
/// For unweighted directed graphs this runs in O(VE) time.
/// The result is normalized by dividing by (n-1)(n-2) for directed graphs,
/// yielding scores in the range [0.0, 1.0].
pub fn betweenness_centrality(graph: &TypeGraph) -> IndexMap<String, f64> {
    let n = graph.node_count;
    let mut cb = vec![0.0_f64; n];

    if n < 2 {
        let mut result = IndexMap::new();
        for (name, &_idx) in &graph.nodes {
            result.insert(name.clone(), 0.0);
        }
        return result;
    }

    // Brandes' algorithm
    for s in 0..n {
        // Stack of nodes in order of non-increasing distance from s
        let mut stack: Vec<usize> = Vec::new();
        // Predecessors on shortest paths from s
        let mut pred: Vec<Vec<usize>> = vec![Vec::new(); n];
        // Number of shortest paths from s to each node
        let mut sigma: Vec<f64> = vec![0.0; n];
        sigma[s] = 1.0;
        // Distance from s (-1 means unvisited)
        let mut dist: Vec<i64> = vec![-1; n];
        dist[s] = 0;

        // BFS
        let mut queue: VecDeque<usize> = VecDeque::new();
        queue.push_back(s);

        while let Some(v) = queue.pop_front() {
            stack.push(v);
            for &(w, _) in graph.neighbors(v) {
                // w found for the first time?
                if dist[w] < 0 {
                    dist[w] = dist[v] + 1;
                    queue.push_back(w);
                }
                // shortest path to w via v?
                if dist[w] == dist[v] + 1 {
                    sigma[w] += sigma[v];
                    pred[w].push(v);
                }
            }
        }

        // Accumulation: back-propagate dependencies
        let mut delta = vec![0.0_f64; n];
        while let Some(w) = stack.pop() {
            for &v in &pred[w] {
                delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w]);
            }
            if w != s {
                cb[w] += delta[w];
            }
        }
    }

    // Normalize: for directed graphs, divide by (n-1)(n-2)
    let norm = (n as f64 - 1.0) * (n as f64 - 2.0);
    if norm > 0.0 {
        for val in &mut cb {
            *val /= norm;
        }
    }

    let mut result = IndexMap::new();
    for (name, &idx) in &graph.nodes {
        result.insert(name.clone(), cb[idx]);
    }
    result
}

/// Return the top-k types by betweenness centrality, sorted descending.
pub fn top_central_types(graph: &TypeGraph, k: usize) -> Vec<(String, f64)> {
    let centrality = betweenness_centrality(graph);
    let mut entries: Vec<(String, f64)> = centrality.into_iter().collect();
    entries.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    entries.truncate(k);
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_graph::TypeGraph;
    use crate::type_graph::test_helpers::make_test_schema;

    #[test]
    fn test_betweenness_centrality_hub_is_highest() {
        // In our test schema, User and Post form a hub connecting Query, Comment,
        // Category. They should have high centrality.
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);
        let centrality = betweenness_centrality(&graph);

        let user_score = centrality.get("User").copied().unwrap_or(0.0);
        let post_score = centrality.get("Post").copied().unwrap_or(0.0);
        let category_score = centrality.get("Category").copied().unwrap_or(0.0);
        let isolated_score = centrality.get("Isolated").copied().unwrap_or(0.0);

        // Post should have higher centrality than Category (leaf) and Isolated (disconnected)
        assert!(
            post_score > category_score,
            "Post ({post_score}) should have higher centrality than Category ({category_score})"
        );
        assert!(
            post_score > isolated_score,
            "Post ({post_score}) should have higher centrality than Isolated ({isolated_score})"
        );
        // User should also rank high
        assert!(
            user_score > isolated_score,
            "User ({user_score}) should have higher centrality than Isolated ({isolated_score})"
        );
    }

    #[test]
    fn test_top_central_types() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);
        let top = top_central_types(&graph, 3);

        assert_eq!(top.len(), 3);
        // Scores should be in descending order
        for window in top.windows(2) {
            assert!(window[0].1 >= window[1].1);
        }
    }

    #[test]
    fn test_centrality_scores_normalized() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);
        let centrality = betweenness_centrality(&graph);

        for (_name, &score) in &centrality {
            assert!(score >= 0.0, "Centrality should be non-negative");
            assert!(score <= 1.0, "Centrality should be <= 1.0 (normalized)");
        }
    }
}
