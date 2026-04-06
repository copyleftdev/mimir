use mimir_schema::types::{Field, Schema, TypeKind, TypeRef};
use serde_json::{json, Value};

use crate::covering::{mutation_to_factors, pairwise_covering_array};

/// Configuration for query generation.
#[derive(Debug, Clone)]
pub struct GenConfig {
    /// Maximum selection set depth.
    pub max_depth: usize,
    /// Whether to include arguments in generated queries.
    pub include_args: bool,
    /// Whether to include inline fragments for union/interface types.
    pub include_fragments: bool,
    /// Deterministic seed for reproducible generation.
    pub seed: u64,
}

impl Default for GenConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            include_args: true,
            include_fragments: false,
            seed: 0,
        }
    }
}

/// Generate a GraphQL query string for a specific field (query or mutation).
///
/// The generated query includes a selection set that recurses into object types
/// up to `config.max_depth` levels deep.
pub fn generate_query(schema: &Schema, field: &Field, config: &GenConfig) -> String {
    let selection = generate_selection_set(schema, &field.field_type, 0, config.max_depth);

    let args_str = if config.include_args && !field.args.is_empty() {
        let params: Vec<String> = field
            .args
            .iter()
            .map(|arg| format!("${}: {}", arg.name, arg.input_type.display_type()))
            .collect();
        let args: Vec<String> = field
            .args
            .iter()
            .map(|arg| format!("{}: ${}", arg.name, arg.name))
            .collect();
        format!(
            "({}) {{ {}({}) {} }}",
            params.join(", "),
            field.name,
            args.join(", "),
            selection
        )
    } else if selection.is_empty() {
        format!("{{ {} }}", field.name)
    } else {
        format!("{{ {} {} }}", field.name, selection)
    };

    // Determine operation type based on whether this field appears in the
    // mutation root or defaults to query.
    let op_type = if is_mutation_field(schema, field) {
        "mutation"
    } else {
        "query"
    };

    let op_name = capitalize(&field.name);
    format!("{op_type} {op_name}{args_str}")
}

/// Generate a selection set for a type, recursing up to max_depth.
fn generate_selection_set(
    schema: &Schema,
    type_ref: &TypeRef,
    depth: usize,
    max_depth: usize,
) -> String {
    if depth >= max_depth {
        return String::new();
    }

    let resolved = match schema.resolve_type_ref(type_ref) {
        Some(t) => t,
        None => return String::new(),
    };

    match resolved.kind {
        TypeKind::Object | TypeKind::Interface => {
            if resolved.fields.is_empty() {
                return String::new();
            }

            let mut field_strs: Vec<String> = Vec::new();
            for f in &resolved.fields {
                // Skip introspection fields.
                if f.name.starts_with("__") {
                    continue;
                }

                let inner = generate_selection_set(schema, &f.field_type, depth + 1, max_depth);
                if inner.is_empty() {
                    // Leaf field (scalar or max depth reached).
                    field_strs.push(f.name.clone());
                } else {
                    field_strs.push(format!("{} {}", f.name, inner));
                }
            }

            if field_strs.is_empty() {
                // If all fields were skipped (e.g., all introspection), try __typename.
                return "{ __typename }".to_string();
            }

            format!("{{ {} }}", field_strs.join(" "))
        }
        TypeKind::Union => {
            // For unions, select __typename and inline fragments for each possible type.
            let mut parts = vec!["__typename".to_string()];
            for possible in &resolved.possible_types {
                if let Some(type_name) = possible.inner_name() {
                    let inner = generate_selection_set(
                        schema,
                        possible,
                        depth + 1,
                        max_depth,
                    );
                    if !inner.is_empty() {
                        parts.push(format!("... on {type_name} {inner}"));
                    }
                }
            }
            format!("{{ {} }}", parts.join(" "))
        }
        TypeKind::Enum | TypeKind::Scalar => {
            // Leaf types have no selection set.
            String::new()
        }
        _ => String::new(),
    }
}

/// Generate all mutations with pairwise-covered arguments.
///
/// Returns a Vec of `(operation_name, query_string, variables)`.
/// Each mutation gets a suite of test cases generated via pairwise covering
/// arrays over its arguments.
pub fn generate_mutation_suite(
    schema: &Schema,
    config: &GenConfig,
) -> Vec<(String, String, Value)> {
    let mutations = schema.mutations();
    let mut suite = Vec::new();

    for mutation in mutations {
        let factors = mutation_to_factors(schema, mutation);

        if factors.is_empty() {
            // Mutation with no arguments: single test case.
            let query = generate_query(schema, mutation, config);
            suite.push((mutation.name.clone(), query, json!({})));
            continue;
        }

        let test_cases = pairwise_covering_array(&factors);

        for (i, tc) in test_cases.iter().enumerate() {
            let query = generate_query(schema, mutation, config);

            let mut variables = serde_json::Map::new();
            for (name, value) in tc {
                variables.insert(name.clone(), value.clone());
            }

            let op_name = format!("{}_{}", mutation.name, i);
            suite.push((op_name, query, Value::Object(variables)));
        }
    }

    suite
}

/// Check if a field belongs to the mutation root type.
fn is_mutation_field(schema: &Schema, field: &Field) -> bool {
    let mutations = schema.mutations();
    mutations.iter().any(|m| m.name == field.name)
}

/// Capitalize the first letter of a string.
fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mimir_schema::types::*;
    use indexmap::IndexMap;

    fn make_test_schema() -> Schema {
        let mut types = IndexMap::new();

        // Scalar types.
        for name in &["String", "Int", "Float", "Boolean", "ID"] {
            types.insert(
                name.to_string(),
                FullType {
                    name: name.to_string(),
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

        // User object type.
        types.insert(
            "User".to_string(),
            FullType {
                name: "User".to_string(),
                kind: TypeKind::Object,
                description: None,
                fields: vec![
                    Field {
                        name: "id".to_string(),
                        description: None,
                        args: vec![],
                        field_type: TypeRef {
                            name: Some("ID".to_string()),
                            kind: TypeKind::Scalar,
                            of_type: None,
                        },
                        is_deprecated: false,
                    },
                    Field {
                        name: "name".to_string(),
                        description: None,
                        args: vec![],
                        field_type: TypeRef {
                            name: Some("String".to_string()),
                            kind: TypeKind::Scalar,
                            of_type: None,
                        },
                        is_deprecated: false,
                    },
                    Field {
                        name: "email".to_string(),
                        description: None,
                        args: vec![],
                        field_type: TypeRef {
                            name: Some("String".to_string()),
                            kind: TypeKind::Scalar,
                            of_type: None,
                        },
                        is_deprecated: false,
                    },
                ],
                input_fields: vec![],
                interfaces: vec![],
                enum_values: vec![],
                possible_types: vec![],
            },
        );

        // Query root type.
        types.insert(
            "Query".to_string(),
            FullType {
                name: "Query".to_string(),
                kind: TypeKind::Object,
                description: None,
                fields: vec![
                    Field {
                        name: "user".to_string(),
                        description: None,
                        args: vec![InputValue {
                            name: "id".to_string(),
                            description: None,
                            input_type: TypeRef {
                                name: None,
                                kind: TypeKind::NonNull,
                                of_type: Some(Box::new(TypeRef {
                                    name: Some("ID".to_string()),
                                    kind: TypeKind::Scalar,
                                    of_type: None,
                                })),
                            },
                            default_value: None,
                        }],
                        field_type: TypeRef {
                            name: Some("User".to_string()),
                            kind: TypeKind::Object,
                            of_type: None,
                        },
                        is_deprecated: false,
                    },
                    Field {
                        name: "users".to_string(),
                        description: None,
                        args: vec![],
                        field_type: TypeRef {
                            name: None,
                            kind: TypeKind::List,
                            of_type: Some(Box::new(TypeRef {
                                name: Some("User".to_string()),
                                kind: TypeKind::Object,
                                of_type: None,
                            })),
                        },
                        is_deprecated: false,
                    },
                ],
                input_fields: vec![],
                interfaces: vec![],
                enum_values: vec![],
                possible_types: vec![],
            },
        );

        // Mutation root type.
        types.insert(
            "Mutation".to_string(),
            FullType {
                name: "Mutation".to_string(),
                kind: TypeKind::Object,
                description: None,
                fields: vec![Field {
                    name: "createUser".to_string(),
                    description: None,
                    args: vec![
                        InputValue {
                            name: "name".to_string(),
                            description: None,
                            input_type: TypeRef {
                                name: None,
                                kind: TypeKind::NonNull,
                                of_type: Some(Box::new(TypeRef {
                                    name: Some("String".to_string()),
                                    kind: TypeKind::Scalar,
                                    of_type: None,
                                })),
                            },
                            default_value: None,
                        },
                        InputValue {
                            name: "email".to_string(),
                            description: None,
                            input_type: TypeRef {
                                name: Some("String".to_string()),
                                kind: TypeKind::Scalar,
                                of_type: None,
                            },
                            default_value: None,
                        },
                    ],
                    field_type: TypeRef {
                        name: Some("User".to_string()),
                        kind: TypeKind::Object,
                        of_type: None,
                    },
                    is_deprecated: false,
                }],
                input_fields: vec![],
                interfaces: vec![],
                enum_values: vec![],
                possible_types: vec![],
            },
        );

        Schema {
            query_type: Some("Query".to_string()),
            mutation_type: Some("Mutation".to_string()),
            subscription_type: None,
            types,
            directives: vec![],
        }
    }

    #[test]
    fn generate_simple_query() {
        let schema = make_test_schema();
        let config = GenConfig {
            include_args: false,
            ..GenConfig::default()
        };
        let field = &schema.queries()[1]; // users
        let query = generate_query(&schema, field, &config);

        assert!(query.starts_with("query"));
        assert!(query.contains("users"));
        assert!(query.contains("id"));
        assert!(query.contains("name"));
        assert!(query.contains("email"));
    }

    #[test]
    fn generate_query_with_args() {
        let schema = make_test_schema();
        let config = GenConfig::default();
        let field = &schema.queries()[0]; // user(id: ID!)
        let query = generate_query(&schema, field, &config);

        assert!(query.starts_with("query"));
        assert!(query.contains("$id"));
        assert!(query.contains("id: $id"));
        assert!(query.contains("ID!"));
    }

    #[test]
    fn generate_mutation_query() {
        let schema = make_test_schema();
        let config = GenConfig::default();
        let field = &schema.mutations()[0]; // createUser
        let query = generate_query(&schema, field, &config);

        assert!(query.starts_with("mutation"));
        assert!(query.contains("createUser"));
        assert!(query.contains("$name"));
    }

    #[test]
    fn generate_mutation_suite_produces_test_cases() {
        let schema = make_test_schema();
        let config = GenConfig::default();
        let suite = generate_mutation_suite(&schema, &config);

        assert!(
            !suite.is_empty(),
            "Suite should contain at least one test case"
        );

        for (op_name, query, variables) in &suite {
            assert!(!op_name.is_empty());
            assert!(query.starts_with("mutation"));
            assert!(variables.is_object());
        }
    }

    #[test]
    fn selection_set_respects_max_depth() {
        let schema = make_test_schema();
        let user_type_ref = TypeRef {
            name: Some("User".to_string()),
            kind: TypeKind::Object,
            of_type: None,
        };

        // depth=0, max_depth=0 should produce empty selection.
        let s0 = generate_selection_set(&schema, &user_type_ref, 0, 0);
        assert!(s0.is_empty());

        // depth=0, max_depth=1 should produce fields.
        let s1 = generate_selection_set(&schema, &user_type_ref, 0, 1);
        assert!(s1.contains("id"));
        assert!(s1.contains("name"));
    }

    #[test]
    fn scalar_field_has_no_selection_set() {
        let schema = make_test_schema();
        let string_ref = TypeRef {
            name: Some("String".to_string()),
            kind: TypeKind::Scalar,
            of_type: None,
        };
        let s = generate_selection_set(&schema, &string_ref, 0, 3);
        assert!(s.is_empty());
    }

    #[test]
    fn default_config_values() {
        let config = GenConfig::default();
        assert_eq!(config.max_depth, 3);
        assert!(config.include_args);
        assert!(!config.include_fragments);
        assert_eq!(config.seed, 0);
    }
}
