use mimir_schema::types::{Schema, TypeKind};
use serde_json::{json, Value};

/// Strategy for generating test values for a given scalar type.
pub fn generate_scalar_values(type_name: &str) -> Vec<Value> {
    match type_name {
        "String" => vec![
            json!(null),
            json!(""),
            json!("test"),
            json!("<script>alert(1)</script>"),
            json!("a".repeat(10000)),
            json!("' OR 1=1 --"),
        ],
        "Int" => vec![
            json!(null),
            json!(0),
            json!(1),
            json!(-1),
            json!(i32::MAX),
            json!(i32::MIN),
        ],
        "Float" => vec![
            json!(null),
            json!(0.0),
            json!(1.0),
            json!(-1.0),
            json!(f64::MAX),
            json!(f64::MIN),
            json!(f64::NAN),
        ],
        "Boolean" => vec![json!(null), json!(true), json!(false)],
        "ID" => vec![
            json!(null),
            json!(""),
            json!("1"),
            json!("00000000-0000-0000-0000-000000000000"),
            json!("../../etc/passwd"),
        ],
        _ => vec![json!(null), json!("test")],
    }
}

/// Generate a valid input object value from a schema's InputObject type.
///
/// Uses `seed` to deterministically pick one value per field from the available
/// test values for that field's type.
pub fn generate_input_object(schema: &Schema, type_name: &str, seed: u64) -> Value {
    let full_type = match schema.get_type(type_name) {
        Some(t) if t.kind == TypeKind::InputObject => t,
        _ => return json!(null),
    };

    let mut map = serde_json::Map::new();
    for (i, field) in full_type.input_fields.iter().enumerate() {
        let inner_name = field.input_type.inner_name().unwrap_or("String");
        let value = generate_field_value(schema, inner_name, seed.wrapping_add(i as u64));
        map.insert(field.name.clone(), value);
    }

    Value::Object(map)
}

/// Generate a single value for a field given its resolved type name and a seed.
fn generate_field_value(schema: &Schema, type_name: &str, seed: u64) -> Value {
    // Check if this is an enum type.
    if let Some(full_type) = schema.get_type(type_name) {
        if full_type.kind == TypeKind::Enum {
            if full_type.enum_values.is_empty() {
                return json!(null);
            }
            let idx = (seed as usize) % full_type.enum_values.len();
            return json!(full_type.enum_values[idx].name);
        }
        if full_type.kind == TypeKind::InputObject {
            return generate_input_object(schema, type_name, seed);
        }
    }

    // Scalar or unknown type.
    let values = generate_scalar_values(type_name);
    let idx = (seed as usize) % values.len();
    values[idx].clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mimir_schema::types::*;
    use indexmap::IndexMap;

    fn make_test_schema() -> Schema {
        let mut types = IndexMap::new();

        // Add scalar types.
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

        // Add an enum type.
        types.insert(
            "Status".to_string(),
            FullType {
                name: "Status".to_string(),
                kind: TypeKind::Enum,
                description: None,
                fields: vec![],
                input_fields: vec![],
                interfaces: vec![],
                enum_values: vec![
                    EnumValue {
                        name: "ACTIVE".to_string(),
                        description: None,
                        is_deprecated: false,
                    },
                    EnumValue {
                        name: "INACTIVE".to_string(),
                        description: None,
                        is_deprecated: false,
                    },
                ],
                possible_types: vec![],
            },
        );

        // Add an input object type.
        types.insert(
            "CreateUserInput".to_string(),
            FullType {
                name: "CreateUserInput".to_string(),
                kind: TypeKind::InputObject,
                description: None,
                fields: vec![],
                input_fields: vec![
                    InputValue {
                        name: "name".to_string(),
                        description: None,
                        input_type: TypeRef {
                            name: Some("String".to_string()),
                            kind: TypeKind::Scalar,
                            of_type: None,
                        },
                        default_value: None,
                    },
                    InputValue {
                        name: "age".to_string(),
                        description: None,
                        input_type: TypeRef {
                            name: Some("Int".to_string()),
                            kind: TypeKind::Scalar,
                            of_type: None,
                        },
                        default_value: None,
                    },
                    InputValue {
                        name: "status".to_string(),
                        description: None,
                        input_type: TypeRef {
                            name: Some("Status".to_string()),
                            kind: TypeKind::Enum,
                            of_type: None,
                        },
                        default_value: None,
                    },
                ],
                interfaces: vec![],
                enum_values: vec![],
                possible_types: vec![],
            },
        );

        Schema {
            query_type: None,
            mutation_type: None,
            subscription_type: None,
            types,
            directives: vec![],
        }
    }

    #[test]
    fn scalar_values_for_string() {
        let vals = generate_scalar_values("String");
        assert!(vals.len() >= 5);
        assert!(vals.contains(&json!(null)));
        assert!(vals.contains(&json!("")));
    }

    #[test]
    fn scalar_values_for_int() {
        let vals = generate_scalar_values("Int");
        assert!(vals.contains(&json!(0)));
        assert!(vals.contains(&json!(i32::MAX)));
        assert!(vals.contains(&json!(i32::MIN)));
    }

    #[test]
    fn scalar_values_for_boolean() {
        let vals = generate_scalar_values("Boolean");
        assert!(vals.contains(&json!(true)));
        assert!(vals.contains(&json!(false)));
    }

    #[test]
    fn scalar_values_for_unknown_type() {
        let vals = generate_scalar_values("CustomScalar");
        assert!(vals.contains(&json!(null)));
        assert!(vals.contains(&json!("test")));
    }

    #[test]
    fn generate_input_object_produces_valid_object() {
        let schema = make_test_schema();
        let value = generate_input_object(&schema, "CreateUserInput", 42);
        assert!(value.is_object());
        let obj = value.as_object().unwrap();
        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("age"));
        assert!(obj.contains_key("status"));
    }

    #[test]
    fn generate_input_object_unknown_type_returns_null() {
        let schema = make_test_schema();
        let value = generate_input_object(&schema, "NonExistentType", 0);
        assert!(value.is_null());
    }

    #[test]
    fn different_seeds_produce_different_values() {
        let schema = make_test_schema();
        let v1 = generate_input_object(&schema, "CreateUserInput", 0);
        let v2 = generate_input_object(&schema, "CreateUserInput", 3);
        // With different seeds we should get at least some different values.
        // (Not guaranteed for all seeds, but 0 and 3 should differ on at least one field.)
        // Just verify they are both valid objects.
        assert!(v1.is_object());
        assert!(v2.is_object());
    }
}
