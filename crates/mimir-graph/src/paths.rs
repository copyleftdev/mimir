use crate::type_graph::TypeGraph;
use std::collections::VecDeque;

/// Find all simple paths from source type to target type.
///
/// Returns a Vec of paths. Each path is a Vec of `(type_name, field_name)` pairs
/// representing the sequence of edges from `from` to `to`.
/// The first entry's type_name is the source, with the field_name being the edge
/// traversed from it.
///
/// Limited to `max_depth` edges to prevent combinatorial explosion.
/// Returns an empty Vec if either type is not in the graph or no paths exist.
pub fn all_paths(
    graph: &TypeGraph,
    from: &str,
    to: &str,
    max_depth: usize,
) -> Vec<Vec<(String, String)>> {
    let Some(start) = graph.node_index(from) else {
        return vec![];
    };
    let Some(end) = graph.node_index(to) else {
        return vec![];
    };

    let mut results: Vec<Vec<(String, String)>> = Vec::new();
    let mut visited = vec![false; graph.node_count];
    let mut current_path: Vec<(String, String)> = Vec::new();

    visited[start] = true;
    dfs_all_paths(
        graph,
        start,
        end,
        max_depth,
        &mut visited,
        &mut current_path,
        &mut results,
    );
    results
}

fn dfs_all_paths(
    graph: &TypeGraph,
    current: usize,
    target: usize,
    max_depth: usize,
    visited: &mut Vec<bool>,
    current_path: &mut Vec<(String, String)>,
    results: &mut Vec<Vec<(String, String)>>,
) {
    if current_path.len() > max_depth {
        return;
    }

    if current == target && !current_path.is_empty() {
        results.push(current_path.clone());
        return;
    }

    if current_path.len() == max_depth {
        return;
    }

    for (neighbor, field_name) in graph.neighbors(current) {
        let neighbor = *neighbor;
        let field_name = field_name.clone();

        if !visited[neighbor] || neighbor == target {
            let type_name = graph
                .node_name(current)
                .unwrap_or("?")
                .to_string();

            current_path.push((type_name, field_name));

            if neighbor != target {
                visited[neighbor] = true;
            }

            dfs_all_paths(graph, neighbor, target, max_depth, visited, current_path, results);

            if neighbor != target {
                visited[neighbor] = false;
            }
            current_path.pop();
        }
    }
}

/// Find the shortest path from source to target using BFS.
///
/// Returns a path as a Vec of `(type_name, field_name)` pairs, or `None` if
/// the target is unreachable. The path represents edges: each entry is the
/// source type and the field name used to reach the next type.
pub fn shortest_path(
    graph: &TypeGraph,
    from: &str,
    to: &str,
) -> Option<Vec<(String, String)>> {
    let start = graph.node_index(from)?;
    let end = graph.node_index(to)?;

    if start == end {
        return Some(vec![]);
    }

    let n = graph.node_count;
    // predecessor[w] = Some((v, field_name)) meaning we reached w from v via field_name
    let mut predecessor: Vec<Option<(usize, String)>> = vec![None; n];
    let mut visited = vec![false; n];
    let mut queue: VecDeque<usize> = VecDeque::new();

    visited[start] = true;
    queue.push_back(start);

    while let Some(v) = queue.pop_front() {
        for (w, field_name) in graph.neighbors(v) {
            let w = *w;
            if !visited[w] {
                visited[w] = true;
                predecessor[w] = Some((v, field_name.clone()));
                if w == end {
                    // Reconstruct path
                    let mut path = Vec::new();
                    let mut current = end;
                    while let Some((prev, fname)) = &predecessor[current] {
                        let type_name = graph.node_name(*prev).unwrap_or("?").to_string();
                        path.push((type_name, fname.clone()));
                        current = *prev;
                    }
                    path.reverse();
                    return Some(path);
                }
                queue.push_back(w);
            }
        }
    }

    None
}

/// Compute the all-pairs shortest path distance matrix using BFS from each node.
///
/// Returns a 2D vec where `distances[i][j] = Some(d)` is the shortest distance
/// from node i to node j, or `None` if j is unreachable from i.
/// `distances[i][i] = Some(0)` for all i.
pub fn distance_matrix(graph: &TypeGraph) -> Vec<Vec<Option<usize>>> {
    let n = graph.node_count;
    let mut distances = vec![vec![None; n]; n];

    for s in 0..n {
        // BFS from s
        distances[s][s] = Some(0);
        let mut queue: VecDeque<usize> = VecDeque::new();
        queue.push_back(s);

        while let Some(v) = queue.pop_front() {
            let d = distances[s][v].unwrap();
            for &(w, _) in graph.neighbors(v) {
                if distances[s][w].is_none() {
                    distances[s][w] = Some(d + 1);
                    queue.push_back(w);
                }
            }
        }
    }

    distances
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_graph::test_helpers::make_test_schema;
    use crate::type_graph::TypeGraph;

    #[test]
    fn test_all_paths_basic() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);

        // Query -> User (direct)
        // Query -> Post -> User (via author)
        // etc.
        let paths = all_paths(&graph, "Query", "User", 5);
        assert!(
            !paths.is_empty(),
            "Should find at least one path from Query to User"
        );

        // The direct path Query->User should be among them
        let has_direct = paths.iter().any(|p| {
            p.len() == 1 && p[0].0 == "Query" && p[0].1 == "user"
        });
        assert!(has_direct, "Should find direct Query->User path via 'user' field");
    }

    #[test]
    fn test_all_paths_unreachable() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);

        // Isolated has no incoming edges from non-Isolated types, so Query can't reach it
        let paths = all_paths(&graph, "Query", "Isolated", 10);
        assert!(paths.is_empty(), "No path should exist to Isolated");
    }

    #[test]
    fn test_all_paths_nonexistent_type() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);

        let paths = all_paths(&graph, "Query", "DoesNotExist", 10);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_shortest_path_direct() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);

        let path = shortest_path(&graph, "Query", "User");
        assert!(path.is_some(), "Should find path from Query to User");
        let path = path.unwrap();
        assert_eq!(path.len(), 1, "Shortest path Query->User is 1 edge");
        assert_eq!(path[0].0, "Query");
        assert_eq!(path[0].1, "user");
    }

    #[test]
    fn test_shortest_path_multi_hop() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);

        // Shortest path from Query to Comment:
        //   Query -> Post -> Comment (length 2)
        let path = shortest_path(&graph, "Query", "Comment");
        assert!(path.is_some(), "Should find path from Query to Comment");
        let path = path.unwrap();
        assert_eq!(path.len(), 2, "Shortest path Query->Comment should be 2 edges");
    }

    #[test]
    fn test_shortest_path_self() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);

        let path = shortest_path(&graph, "User", "User");
        assert!(path.is_some());
        assert_eq!(path.unwrap().len(), 0, "Path from self to self is empty");
    }

    #[test]
    fn test_shortest_path_unreachable() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);

        let path = shortest_path(&graph, "Query", "Isolated");
        assert!(path.is_none(), "No path should exist to Isolated");
    }

    #[test]
    fn test_distance_matrix_basic() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);
        let dm = distance_matrix(&graph);

        let n = graph.node_count;
        assert_eq!(dm.len(), n);
        for row in &dm {
            assert_eq!(row.len(), n);
        }

        // Diagonal should be 0
        for i in 0..n {
            assert_eq!(dm[i][i], Some(0));
        }

        // Query -> User = 1
        let qi = graph.node_index("Query").unwrap();
        let ui = graph.node_index("User").unwrap();
        assert_eq!(dm[qi][ui], Some(1));

        // Isolated should be unreachable from Query
        let ii = graph.node_index("Isolated").unwrap();
        assert_eq!(dm[qi][ii], None);
    }

    #[test]
    fn test_distance_matrix_symmetry_check() {
        // In a directed graph, distances are NOT necessarily symmetric.
        // Category has no outgoing edges to other non-builtins, so
        // distance from Category to Query should be None, but Query to Category
        // should be Some.
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);
        let dm = distance_matrix(&graph);

        let qi = graph.node_index("Query").unwrap();
        let ci = graph.node_index("Category").unwrap();

        assert!(dm[qi][ci].is_some(), "Query should reach Category");
        assert!(dm[ci][qi].is_none(), "Category should NOT reach Query (no outgoing edges)");
    }
}
