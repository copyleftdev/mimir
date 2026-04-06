use crate::type_graph::TypeGraph;

/// Internal state for Tarjan's algorithm.
struct TarjanState {
    index_counter: usize,
    stack: Vec<usize>,
    on_stack: Vec<bool>,
    index: Vec<Option<usize>>,
    lowlink: Vec<usize>,
    components: Vec<Vec<usize>>,
}

impl TarjanState {
    fn new(n: usize) -> Self {
        Self {
            index_counter: 0,
            stack: Vec::new(),
            on_stack: vec![false; n],
            index: vec![None; n],
            lowlink: vec![0; n],
            components: Vec::new(),
        }
    }
}

/// Find all strongly connected components using Tarjan's algorithm.
///
/// Returns a Vec of components, where each component is a Vec of type names.
/// Components are in reverse topological order of the condensation DAG.
pub fn strongly_connected_components(graph: &TypeGraph) -> Vec<Vec<String>> {
    let n = graph.node_count;
    let mut state = TarjanState::new(n);

    for v in 0..n {
        if state.index[v].is_none() {
            strongconnect(graph, v, &mut state);
        }
    }

    // Convert node indices to type names
    state
        .components
        .iter()
        .map(|component| {
            component
                .iter()
                .filter_map(|&idx| graph.node_name(idx).map(|s| s.to_string()))
                .collect()
        })
        .collect()
}

/// The recursive strongconnect procedure from Tarjan's algorithm.
///
/// This uses an explicit work stack to avoid Rust stack overflow on deep graphs.
fn strongconnect(graph: &TypeGraph, root: usize, state: &mut TarjanState) {
    // We use an iterative approach with an explicit call stack to handle
    // arbitrarily deep graphs without risking stack overflow.
    //
    // Each frame on the call stack represents a call to strongconnect(v),
    // tracking which neighbor we're currently processing.
    struct Frame {
        v: usize,
        neighbor_idx: usize,
    }

    let mut call_stack: Vec<Frame> = Vec::new();

    // Initialize root
    state.index[root] = Some(state.index_counter);
    state.lowlink[root] = state.index_counter;
    state.index_counter += 1;
    state.stack.push(root);
    state.on_stack[root] = true;
    call_stack.push(Frame {
        v: root,
        neighbor_idx: 0,
    });

    while let Some(frame) = call_stack.last_mut() {
        let v = frame.v;
        let neighbors = graph.neighbors(v);

        if frame.neighbor_idx < neighbors.len() {
            let (w, _) = &neighbors[frame.neighbor_idx];
            let w = *w;
            frame.neighbor_idx += 1;

            if state.index[w].is_none() {
                // w has not been visited; recurse
                state.index[w] = Some(state.index_counter);
                state.lowlink[w] = state.index_counter;
                state.index_counter += 1;
                state.stack.push(w);
                state.on_stack[w] = true;
                call_stack.push(Frame {
                    v: w,
                    neighbor_idx: 0,
                });
            } else if state.on_stack[w] {
                // w is on the stack, so it's in the current SCC
                state.lowlink[v] =
                    state.lowlink[v].min(state.index[w].unwrap());
            }
        } else {
            // All neighbors processed; check if v is a root of an SCC
            if state.lowlink[v] == state.index[v].unwrap() {
                let mut component = Vec::new();
                loop {
                    let w = state.stack.pop().unwrap();
                    state.on_stack[w] = false;
                    component.push(w);
                    if w == v {
                        break;
                    }
                }
                state.components.push(component);
            }

            // Pop this frame and propagate lowlink to caller
            let finished_v = v;
            let finished_lowlink = state.lowlink[finished_v];
            call_stack.pop();
            if let Some(parent_frame) = call_stack.last() {
                let parent_v = parent_frame.v;
                state.lowlink[parent_v] =
                    state.lowlink[parent_v].min(finished_lowlink);
            }
        }
    }
}

/// Find the largest strongly connected component (the "core" of the type graph).
///
/// Returns the type names in the largest SCC. If there are ties, the first
/// one found (in reverse topological order) is returned.
pub fn largest_scc(graph: &TypeGraph) -> Vec<String> {
    let components = strongly_connected_components(graph);
    components
        .into_iter()
        .max_by_key(|c| c.len())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_graph::test_helpers::make_test_schema;
    use crate::type_graph::TypeGraph;

    #[test]
    fn test_scc_finds_cycles() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);
        let components = strongly_connected_components(&graph);

        // User <-> Post and Post <-> Comment form cycles.
        // User, Post, Comment should all be in the same SCC.
        let mut found_cycle_scc = false;
        for comp in &components {
            if comp.contains(&"User".to_string())
                && comp.contains(&"Post".to_string())
                && comp.contains(&"Comment".to_string())
            {
                found_cycle_scc = true;
            }
        }
        assert!(
            found_cycle_scc,
            "User, Post, Comment should be in the same SCC due to mutual cycles"
        );
    }

    #[test]
    fn test_scc_singleton_components() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);
        let components = strongly_connected_components(&graph);

        // Category and Isolated should be in singleton SCCs (no outgoing edges to cycle partners)
        let category_comp = components
            .iter()
            .find(|c| c.contains(&"Category".to_string()))
            .expect("Category should be in some SCC");
        assert_eq!(
            category_comp.len(),
            1,
            "Category should be in a singleton SCC"
        );

        let isolated_comp = components
            .iter()
            .find(|c| c.contains(&"Isolated".to_string()))
            .expect("Isolated should be in some SCC");
        assert_eq!(
            isolated_comp.len(),
            1,
            "Isolated should be in a singleton SCC"
        );
    }

    #[test]
    fn test_largest_scc() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);
        let largest = largest_scc(&graph);

        // The largest SCC should contain User, Post, Comment (the cycle)
        assert!(
            largest.contains(&"User".to_string()),
            "Largest SCC should contain User"
        );
        assert!(
            largest.contains(&"Post".to_string()),
            "Largest SCC should contain Post"
        );
        assert!(
            largest.contains(&"Comment".to_string()),
            "Largest SCC should contain Comment"
        );
    }

    #[test]
    fn test_all_nodes_covered() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);
        let components = strongly_connected_components(&graph);

        // Every node should appear in exactly one component
        let total_nodes: usize = components.iter().map(|c| c.len()).sum();
        assert_eq!(
            total_nodes, graph.node_count,
            "Total nodes in all SCCs should equal node_count"
        );
    }
}
