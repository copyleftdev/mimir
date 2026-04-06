use crate::centrality::top_central_types;
use crate::paths::distance_matrix;
use crate::scc::strongly_connected_components;
use crate::type_graph::TypeGraph;
use mimir_schema::types::Schema;
use serde::{Deserialize, Serialize};

/// High-level analysis summary of a GraphQL schema's type graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaAnalysis {
    pub node_count: usize,
    pub edge_count: usize,
    pub scc_count: usize,
    pub largest_scc_size: usize,
    pub largest_scc_types: Vec<String>,
    pub top_central_types: Vec<(String, f64)>,
    pub has_cycles: bool,
    pub max_depth_from_query: Option<usize>,
    pub max_depth_from_mutation: Option<usize>,
    pub mutation_count: usize,
    pub query_count: usize,
}

/// Analyze a GraphQL schema and produce a comprehensive summary.
///
/// Combines graph construction, SCC detection, centrality analysis,
/// and distance computation into a single report.
pub fn analyze_schema(schema: &Schema) -> SchemaAnalysis {
    let graph = TypeGraph::from_schema(schema);

    // SCCs
    let sccs = strongly_connected_components(&graph);
    let scc_count = sccs.len();
    let largest = sccs
        .iter()
        .max_by_key(|c| c.len())
        .cloned()
        .unwrap_or_default();
    let largest_scc_size = largest.len();

    // Cycles exist if any SCC has more than one node
    let has_cycles = sccs.iter().any(|c| c.len() > 1);

    // Centrality: top 10
    let top_central = top_central_types(&graph, 10);

    // Distance matrix for max-depth calculations
    let dm = distance_matrix(&graph);

    // Max depth from query root
    let max_depth_from_query = schema
        .query_type
        .as_deref()
        .and_then(|q| graph.node_index(q))
        .map(|qi| {
            dm[qi]
                .iter()
                .filter_map(|d| *d)
                .max()
                .unwrap_or(0)
        });

    // Max depth from mutation root
    let max_depth_from_mutation = schema
        .mutation_type
        .as_deref()
        .and_then(|m| graph.node_index(m))
        .map(|mi| {
            dm[mi]
                .iter()
                .filter_map(|d| *d)
                .max()
                .unwrap_or(0)
        });

    // Counts of query and mutation fields
    let query_count = schema.queries().len();
    let mutation_count = schema.mutations().len();

    SchemaAnalysis {
        node_count: graph.node_count,
        edge_count: graph.edge_count(),
        scc_count,
        largest_scc_size,
        largest_scc_types: largest,
        top_central_types: top_central,
        has_cycles,
        max_depth_from_query,
        max_depth_from_mutation,
        mutation_count,
        query_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_graph::test_helpers::make_test_schema;

    #[test]
    fn test_analyze_schema_basic() {
        let schema = make_test_schema();
        let analysis = analyze_schema(&schema);

        assert!(analysis.node_count > 0);
        assert!(analysis.edge_count > 0);
        assert!(analysis.scc_count > 0);
        assert!(analysis.has_cycles, "Schema has cycles (User <-> Post <-> Comment)");
        assert!(analysis.largest_scc_size >= 3, "Largest SCC should have at least User, Post, Comment");
        assert!(!analysis.top_central_types.is_empty());
    }

    #[test]
    fn test_analyze_schema_counts() {
        let schema = make_test_schema();
        let analysis = analyze_schema(&schema);

        assert_eq!(analysis.query_count, 2, "Query has 'user' and 'posts' fields");
        assert_eq!(analysis.mutation_count, 1, "Mutation has 'createUser' field");
    }

    #[test]
    fn test_analyze_schema_depths() {
        let schema = make_test_schema();
        let analysis = analyze_schema(&schema);

        assert!(
            analysis.max_depth_from_query.is_some(),
            "Should have max depth from Query"
        );
        let max_depth = analysis.max_depth_from_query.unwrap();
        assert!(
            max_depth >= 2,
            "Max depth from Query should be at least 2 (Query->Post->Category)"
        );

        assert!(
            analysis.max_depth_from_mutation.is_some(),
            "Should have max depth from Mutation"
        );
    }

    #[test]
    fn test_analyze_schema_serialization() {
        let schema = make_test_schema();
        let analysis = analyze_schema(&schema);

        // Should be serializable to JSON
        let json = serde_json::to_string_pretty(&analysis).expect("Should serialize to JSON");
        assert!(!json.is_empty());

        // Should be deserializable
        let deserialized: SchemaAnalysis =
            serde_json::from_str(&json).expect("Should deserialize from JSON");
        assert_eq!(deserialized.node_count, analysis.node_count);
        assert_eq!(deserialized.edge_count, analysis.edge_count);
    }
}
