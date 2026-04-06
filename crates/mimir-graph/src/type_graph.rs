use indexmap::IndexMap;
use mimir_schema::types::{Schema, TypeKind, TypeRef};

/// A directed graph representation of a GraphQL schema's type relationships.
#[derive(Debug, Clone)]
pub struct TypeGraph {
    /// Node indices by type name
    pub nodes: IndexMap<String, usize>,
    /// Adjacency list: node index -> Vec<(target index, field name)>
    pub adjacency: Vec<Vec<(usize, String)>>,
    /// Reverse adjacency for incoming edge lookups
    pub reverse_adjacency: Vec<Vec<(usize, String)>>,
    /// Node count
    pub node_count: usize,
}

/// Built-in scalar and introspection type names to skip when building edges.
fn is_builtin(name: &str) -> bool {
    matches!(
        name,
        "String"
            | "Int"
            | "Float"
            | "Boolean"
            | "ID"
            | "__Schema"
            | "__Type"
            | "__Field"
            | "__InputValue"
            | "__EnumValue"
            | "__Directive"
            | "__DirectiveLocation"
    )
}

/// Resolve a TypeRef to its innermost concrete type name.
fn resolve_inner_name(type_ref: &TypeRef) -> Option<&str> {
    type_ref.inner_name()
}

impl TypeGraph {
    /// Build the directed type graph from a GraphQL schema.
    ///
    /// For each Object or Interface type, edges are added from that type to every
    /// type referenced by its fields (both the field return type and any argument
    /// input types). Built-in scalar and introspection types are skipped.
    pub fn from_schema(schema: &Schema) -> Self {
        let mut nodes: IndexMap<String, usize> = IndexMap::new();

        // First pass: register all non-builtin types as nodes.
        for (name, _full_type) in &schema.types {
            if !is_builtin(name) {
                let idx = nodes.len();
                nodes.insert(name.clone(), idx);
            }
        }

        let node_count = nodes.len();
        let mut adjacency: Vec<Vec<(usize, String)>> = vec![Vec::new(); node_count];
        let mut reverse_adjacency: Vec<Vec<(usize, String)>> = vec![Vec::new(); node_count];

        // Second pass: build edges.
        for (name, full_type) in &schema.types {
            if is_builtin(name) {
                continue;
            }
            // Only Object and Interface types have fields that produce edges.
            if full_type.kind != TypeKind::Object && full_type.kind != TypeKind::Interface {
                continue;
            }
            let Some(&src_idx) = nodes.get(name) else {
                continue;
            };

            for field in &full_type.fields {
                // Edge from this type to the field's return type.
                if let Some(target_name) = resolve_inner_name(&field.field_type) {
                    if !is_builtin(target_name) {
                        if let Some(&tgt_idx) = nodes.get(target_name) {
                            adjacency[src_idx].push((tgt_idx, field.name.clone()));
                            reverse_adjacency[tgt_idx].push((src_idx, field.name.clone()));
                        }
                    }
                }

                // Edges from this type to each argument's input type.
                for arg in &field.args {
                    if let Some(arg_type_name) = resolve_inner_name(&arg.input_type) {
                        if !is_builtin(arg_type_name) {
                            if let Some(&tgt_idx) = nodes.get(arg_type_name) {
                                let edge_label = format!("{}.{}", field.name, arg.name);
                                adjacency[src_idx].push((tgt_idx, edge_label.clone()));
                                reverse_adjacency[tgt_idx].push((src_idx, edge_label));
                            }
                        }
                    }
                }
            }
        }

        Self {
            nodes,
            adjacency,
            reverse_adjacency,
            node_count,
        }
    }

    /// Return outgoing neighbors for a node.
    pub fn neighbors(&self, node: usize) -> &[(usize, String)] {
        &self.adjacency[node]
    }

    /// Return incoming neighbors for a node.
    pub fn in_neighbors(&self, node: usize) -> &[(usize, String)] {
        &self.reverse_adjacency[node]
    }

    /// Return the type name for a node index.
    pub fn node_name(&self, index: usize) -> Option<&str> {
        self.nodes.get_index(index).map(|(name, _)| name.as_str())
    }

    /// Return the node index for a type name.
    pub fn node_index(&self, name: &str) -> Option<usize> {
        self.nodes.get(name).copied()
    }

    /// Total number of directed edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.adjacency.iter().map(|adj| adj.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_graph::test_helpers::make_test_schema;

    #[test]
    fn test_basic_graph_construction() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);

        // Should have nodes for Query, User, Post, Comment, Category (non-builtin types)
        assert!(graph.node_index("Query").is_some());
        assert!(graph.node_index("User").is_some());
        assert!(graph.node_index("Post").is_some());
        assert!(graph.node_index("Comment").is_some());
        assert!(graph.node_index("Category").is_some());

        // Should NOT have nodes for builtins
        assert!(graph.node_index("String").is_none());
        assert!(graph.node_index("Int").is_none());
    }

    #[test]
    fn test_edge_count() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);
        assert!(graph.edge_count() > 0);
    }

    #[test]
    fn test_neighbors_and_reverse() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);

        let query_idx = graph.node_index("Query").unwrap();
        let user_idx = graph.node_index("User").unwrap();

        // Query should have an edge to User (via "user" field)
        let query_neighbors = graph.neighbors(query_idx);
        assert!(query_neighbors.iter().any(|(idx, _)| *idx == user_idx));

        // User should have Query as an in-neighbor
        let user_in = graph.in_neighbors(user_idx);
        assert!(user_in.iter().any(|(idx, _)| *idx == query_idx));
    }

    #[test]
    fn test_node_name_roundtrip() {
        let schema = make_test_schema();
        let graph = TypeGraph::from_schema(&schema);

        for (name, &idx) in &graph.nodes {
            assert_eq!(graph.node_name(idx), Some(name.as_str()));
            assert_eq!(graph.node_index(name), Some(idx));
        }
    }
}

/// Test helpers for building hand-crafted schemas.
#[cfg(test)]
pub(crate) mod test_helpers {
    use indexmap::IndexMap;
    use mimir_schema::types::*;

    pub fn make_type_ref(name: &str) -> TypeRef {
        TypeRef {
            name: Some(name.to_string()),
            kind: TypeKind::Scalar,
            of_type: None,
        }
    }

    pub fn make_object_type_ref(name: &str) -> TypeRef {
        TypeRef {
            name: Some(name.to_string()),
            kind: TypeKind::Object,
            of_type: None,
        }
    }

    #[allow(dead_code)]
    pub fn make_non_null(inner: TypeRef) -> TypeRef {
        TypeRef {
            name: None,
            kind: TypeKind::NonNull,
            of_type: Some(Box::new(inner)),
        }
    }

    pub fn make_list(inner: TypeRef) -> TypeRef {
        TypeRef {
            name: None,
            kind: TypeKind::List,
            of_type: Some(Box::new(inner)),
        }
    }

    pub fn make_field(name: &str, type_ref: TypeRef) -> Field {
        Field {
            name: name.to_string(),
            description: None,
            args: vec![],
            field_type: type_ref,
            is_deprecated: false,
        }
    }

    pub fn make_field_with_args(name: &str, type_ref: TypeRef, args: Vec<InputValue>) -> Field {
        Field {
            name: name.to_string(),
            description: None,
            args,
            field_type: type_ref,
            is_deprecated: false,
        }
    }

    pub fn make_input_value(name: &str, type_ref: TypeRef) -> InputValue {
        InputValue {
            name: name.to_string(),
            description: None,
            input_type: type_ref,
            default_value: None,
        }
    }

    pub fn make_full_type(name: &str, kind: TypeKind, fields: Vec<Field>) -> FullType {
        FullType {
            name: name.to_string(),
            kind,
            description: None,
            fields,
            input_fields: vec![],
            interfaces: vec![],
            enum_values: vec![],
            possible_types: vec![],
        }
    }

    /// Build a test schema with the following structure:
    ///
    /// ```text
    /// Query -> User (via "user" field)
    /// Query -> Post (via "posts" field)
    /// User -> Post (via "posts" field)
    /// Post -> User (via "author" field)   <-- creates cycle User <-> Post
    /// Post -> Comment (via "comments" field)
    /// Post -> Category (via "category" field)
    /// Comment -> User (via "author" field)
    /// Comment -> Post (via "post" field)  <-- creates cycle Post <-> Comment
    /// ```
    ///
    /// Mutation -> User (via "createUser" field)
    ///
    /// Isolated is a disconnected node (no edges to/from it).
    pub fn make_test_schema() -> Schema {
        let mut types: IndexMap<String, FullType> = IndexMap::new();

        // Query root
        types.insert(
            "Query".to_string(),
            make_full_type(
                "Query",
                TypeKind::Object,
                vec![
                    make_field("user", make_object_type_ref("User")),
                    make_field("posts", make_list(make_object_type_ref("Post"))),
                ],
            ),
        );

        // Mutation root
        types.insert(
            "Mutation".to_string(),
            make_full_type(
                "Mutation",
                TypeKind::Object,
                vec![make_field_with_args(
                    "createUser",
                    make_object_type_ref("User"),
                    vec![make_input_value(
                        "input",
                        make_object_type_ref("CreateUserInput"),
                    )],
                )],
            ),
        );

        // User
        types.insert(
            "User".to_string(),
            make_full_type(
                "User",
                TypeKind::Object,
                vec![
                    make_field("id", make_type_ref("ID")),
                    make_field("name", make_type_ref("String")),
                    make_field("posts", make_list(make_object_type_ref("Post"))),
                ],
            ),
        );

        // Post
        types.insert(
            "Post".to_string(),
            make_full_type(
                "Post",
                TypeKind::Object,
                vec![
                    make_field("id", make_type_ref("ID")),
                    make_field("title", make_type_ref("String")),
                    make_field("author", make_object_type_ref("User")),
                    make_field("comments", make_list(make_object_type_ref("Comment"))),
                    make_field("category", make_object_type_ref("Category")),
                ],
            ),
        );

        // Comment
        types.insert(
            "Comment".to_string(),
            make_full_type(
                "Comment",
                TypeKind::Object,
                vec![
                    make_field("id", make_type_ref("ID")),
                    make_field("body", make_type_ref("String")),
                    make_field("author", make_object_type_ref("User")),
                    make_field("post", make_object_type_ref("Post")),
                ],
            ),
        );

        // Category (leaf — no outgoing edges to other non-builtins)
        types.insert(
            "Category".to_string(),
            make_full_type(
                "Category",
                TypeKind::Object,
                vec![
                    make_field("id", make_type_ref("ID")),
                    make_field("name", make_type_ref("String")),
                ],
            ),
        );

        // CreateUserInput (InputObject — no edges from it in Object-only traversal)
        types.insert(
            "CreateUserInput".to_string(),
            FullType {
                name: "CreateUserInput".to_string(),
                kind: TypeKind::InputObject,
                description: None,
                fields: vec![],
                input_fields: vec![make_input_value("name", make_type_ref("String"))],
                interfaces: vec![],
                enum_values: vec![],
                possible_types: vec![],
            },
        );

        // Isolated (disconnected node)
        types.insert(
            "Isolated".to_string(),
            make_full_type(
                "Isolated",
                TypeKind::Object,
                vec![make_field("value", make_type_ref("Int"))],
            ),
        );

        // Add builtin scalars so Schema::is_builtin works and inner_name resolves
        for scalar in &["String", "Int", "Float", "Boolean", "ID"] {
            types.insert(
                scalar.to_string(),
                FullType {
                    name: scalar.to_string(),
                    kind: TypeKind::Scalar,
                    description: None,
                    fields: vec![],
                    input_fields: vec![],
                    interfaces: vec![],
                    enum_values: vec![],
                    possible_types: vec![],
                },
            );
        }

        Schema {
            query_type: Some("Query".to_string()),
            mutation_type: Some("Mutation".to_string()),
            subscription_type: None,
            types,
            directives: vec![],
        }
    }
}
