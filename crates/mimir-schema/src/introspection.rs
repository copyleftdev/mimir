//! Standard GraphQL introspection query and response parsing.

use indexmap::IndexMap;
use serde_json::Value;

use crate::error::SchemaError;
use crate::types::*;

/// The standard full introspection query. Compatible with most GraphQL servers.
pub const INTROSPECTION_QUERY: &str = r#"
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"#;

/// Parse a JSON introspection response into a [`Schema`].
///
/// Expects the standard `{ "data": { "__schema": { ... } } }` envelope.
/// Also accepts a bare `{ "__schema": { ... } }` object (no `data` wrapper).
pub fn parse_introspection_response(json: &Value) -> Result<Schema, SchemaError> {
    // Navigate to __schema, supporting both `data.__schema` and bare `__schema`.
    let schema_val = json
        .get("data")
        .and_then(|d| d.get("__schema"))
        .or_else(|| json.get("__schema"))
        .ok_or_else(|| {
            SchemaError::IntrospectionFailed(
                "response missing `data.__schema` or `__schema`".into(),
            )
        })?;

    let query_type = schema_val
        .get("queryType")
        .and_then(|v| v.get("name"))
        .and_then(Value::as_str)
        .map(String::from);

    let mutation_type = schema_val
        .get("mutationType")
        .and_then(|v| v.get("name"))
        .and_then(Value::as_str)
        .map(String::from);

    let subscription_type = schema_val
        .get("subscriptionType")
        .and_then(|v| v.get("name"))
        .and_then(Value::as_str)
        .map(String::from);

    // Parse types
    let types_array = schema_val
        .get("types")
        .and_then(Value::as_array)
        .ok_or_else(|| SchemaError::IntrospectionFailed("missing `types` array".into()))?;

    let mut types = IndexMap::new();
    for type_val in types_array {
        let full_type = parse_full_type(type_val)?;
        types.insert(full_type.name.clone(), full_type);
    }

    // Parse directives
    let directives = schema_val
        .get("directives")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_directive).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();

    Ok(Schema {
        query_type,
        mutation_type,
        subscription_type,
        types,
        directives,
    })
}

// ---------------------------------------------------------------------------
// Internal parsers
// ---------------------------------------------------------------------------

fn parse_type_kind(s: &str) -> Result<TypeKind, SchemaError> {
    match s {
        "SCALAR" => Ok(TypeKind::Scalar),
        "OBJECT" => Ok(TypeKind::Object),
        "INTERFACE" => Ok(TypeKind::Interface),
        "UNION" => Ok(TypeKind::Union),
        "ENUM" => Ok(TypeKind::Enum),
        "INPUT_OBJECT" => Ok(TypeKind::InputObject),
        "LIST" => Ok(TypeKind::List),
        "NON_NULL" => Ok(TypeKind::NonNull),
        other => Err(SchemaError::ParseError(format!(
            "unknown type kind: {other}"
        ))),
    }
}

fn parse_type_ref(val: &Value) -> Result<TypeRef, SchemaError> {
    let kind_str = val
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| SchemaError::ParseError("type ref missing `kind`".into()))?;
    let kind = parse_type_kind(kind_str)?;
    let name = val.get("name").and_then(Value::as_str).map(String::from);
    let of_type = val
        .get("ofType")
        .filter(|v| !v.is_null())
        .map(|v| parse_type_ref(v))
        .transpose()?
        .map(Box::new);

    Ok(TypeRef {
        name,
        kind,
        of_type,
    })
}

fn parse_input_value(val: &Value) -> Result<InputValue, SchemaError> {
    let name = val
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| SchemaError::ParseError("input value missing `name`".into()))?
        .to_string();

    let description = val
        .get("description")
        .and_then(Value::as_str)
        .map(String::from);

    let input_type = val
        .get("type")
        .ok_or_else(|| SchemaError::ParseError("input value missing `type`".into()))
        .and_then(parse_type_ref)?;

    let default_value = val
        .get("defaultValue")
        .and_then(Value::as_str)
        .map(String::from);

    Ok(InputValue {
        name,
        description,
        input_type,
        default_value,
    })
}

fn parse_field(val: &Value) -> Result<Field, SchemaError> {
    let name = val
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| SchemaError::ParseError("field missing `name`".into()))?
        .to_string();

    let description = val
        .get("description")
        .and_then(Value::as_str)
        .map(String::from);

    let args = val
        .get("args")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_input_value).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();

    let field_type = val
        .get("type")
        .ok_or_else(|| SchemaError::ParseError("field missing `type`".into()))
        .and_then(parse_type_ref)?;

    let is_deprecated = val
        .get("isDeprecated")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    Ok(Field {
        name,
        description,
        args,
        field_type,
        is_deprecated,
    })
}

fn parse_enum_value(val: &Value) -> Result<EnumValue, SchemaError> {
    let name = val
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| SchemaError::ParseError("enum value missing `name`".into()))?
        .to_string();

    let description = val
        .get("description")
        .and_then(Value::as_str)
        .map(String::from);

    let is_deprecated = val
        .get("isDeprecated")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    Ok(EnumValue {
        name,
        description,
        is_deprecated,
    })
}

fn parse_full_type(val: &Value) -> Result<FullType, SchemaError> {
    let name = val
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| SchemaError::ParseError("type missing `name`".into()))?
        .to_string();

    let kind_str = val
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| SchemaError::ParseError(format!("type `{name}` missing `kind`")))?;
    let kind = parse_type_kind(kind_str)?;

    let description = val
        .get("description")
        .and_then(Value::as_str)
        .map(String::from);

    let fields = val
        .get("fields")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_field).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();

    let input_fields = val
        .get("inputFields")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_input_value).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();

    let interfaces = val
        .get("interfaces")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_type_ref).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();

    let enum_values = val
        .get("enumValues")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_enum_value).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();

    let possible_types = val
        .get("possibleTypes")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_type_ref).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();

    Ok(FullType {
        name,
        kind,
        description,
        fields,
        input_fields,
        interfaces,
        enum_values,
        possible_types,
    })
}

fn parse_directive(val: &Value) -> Result<Directive, SchemaError> {
    let name = val
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| SchemaError::ParseError("directive missing `name`".into()))?
        .to_string();

    let description = val
        .get("description")
        .and_then(Value::as_str)
        .map(String::from);

    let locations = val
        .get("locations")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();

    let args = val
        .get("args")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_input_value).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();

    Ok(Directive {
        name,
        description,
        locations,
        args,
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build a realistic introspection response JSON for testing.
    fn sample_introspection_response() -> Value {
        json!({
            "data": {
                "__schema": {
                    "queryType": { "name": "Query" },
                    "mutationType": { "name": "Mutation" },
                    "subscriptionType": null,
                    "types": [
                        {
                            "kind": "SCALAR",
                            "name": "String",
                            "description": "Built-in String scalar",
                            "fields": null,
                            "inputFields": null,
                            "interfaces": null,
                            "enumValues": null,
                            "possibleTypes": null
                        },
                        {
                            "kind": "SCALAR",
                            "name": "Int",
                            "description": "Built-in Int scalar",
                            "fields": null,
                            "inputFields": null,
                            "interfaces": null,
                            "enumValues": null,
                            "possibleTypes": null
                        },
                        {
                            "kind": "SCALAR",
                            "name": "Boolean",
                            "description": "Built-in Boolean scalar",
                            "fields": null,
                            "inputFields": null,
                            "interfaces": null,
                            "enumValues": null,
                            "possibleTypes": null
                        },
                        {
                            "kind": "SCALAR",
                            "name": "ID",
                            "description": "Built-in ID scalar",
                            "fields": null,
                            "inputFields": null,
                            "interfaces": null,
                            "enumValues": null,
                            "possibleTypes": null
                        },
                        {
                            "kind": "OBJECT",
                            "name": "Query",
                            "description": "Root query type",
                            "fields": [
                                {
                                    "name": "user",
                                    "description": "Fetch a user by ID",
                                    "args": [
                                        {
                                            "name": "id",
                                            "description": null,
                                            "type": {
                                                "kind": "NON_NULL",
                                                "name": null,
                                                "ofType": {
                                                    "kind": "SCALAR",
                                                    "name": "ID",
                                                    "ofType": null
                                                }
                                            },
                                            "defaultValue": null
                                        }
                                    ],
                                    "type": {
                                        "kind": "OBJECT",
                                        "name": "User",
                                        "ofType": null
                                    },
                                    "isDeprecated": false
                                },
                                {
                                    "name": "users",
                                    "description": "List all users",
                                    "args": [
                                        {
                                            "name": "filter",
                                            "description": "Optional filter",
                                            "type": {
                                                "kind": "INPUT_OBJECT",
                                                "name": "UserFilter",
                                                "ofType": null
                                            },
                                            "defaultValue": null
                                        }
                                    ],
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "LIST",
                                            "name": null,
                                            "ofType": {
                                                "kind": "NON_NULL",
                                                "name": null,
                                                "ofType": {
                                                    "kind": "OBJECT",
                                                    "name": "User",
                                                    "ofType": null
                                                }
                                            }
                                        }
                                    },
                                    "isDeprecated": false
                                },
                                {
                                    "name": "status",
                                    "description": "Deprecated status check",
                                    "args": [],
                                    "type": {
                                        "kind": "SCALAR",
                                        "name": "String",
                                        "ofType": null
                                    },
                                    "isDeprecated": true
                                }
                            ],
                            "inputFields": null,
                            "interfaces": [],
                            "enumValues": null,
                            "possibleTypes": null
                        },
                        {
                            "kind": "OBJECT",
                            "name": "Mutation",
                            "description": "Root mutation type",
                            "fields": [
                                {
                                    "name": "createUser",
                                    "description": "Create a new user",
                                    "args": [
                                        {
                                            "name": "input",
                                            "description": null,
                                            "type": {
                                                "kind": "NON_NULL",
                                                "name": null,
                                                "ofType": {
                                                    "kind": "INPUT_OBJECT",
                                                    "name": "CreateUserInput",
                                                    "ofType": null
                                                }
                                            },
                                            "defaultValue": null
                                        }
                                    ],
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "OBJECT",
                                            "name": "User",
                                            "ofType": null
                                        }
                                    },
                                    "isDeprecated": false
                                },
                                {
                                    "name": "deleteUser",
                                    "description": "Delete a user",
                                    "args": [
                                        {
                                            "name": "id",
                                            "description": null,
                                            "type": {
                                                "kind": "NON_NULL",
                                                "name": null,
                                                "ofType": {
                                                    "kind": "SCALAR",
                                                    "name": "ID",
                                                    "ofType": null
                                                }
                                            },
                                            "defaultValue": null
                                        }
                                    ],
                                    "type": {
                                        "kind": "SCALAR",
                                        "name": "Boolean",
                                        "ofType": null
                                    },
                                    "isDeprecated": false
                                }
                            ],
                            "inputFields": null,
                            "interfaces": [],
                            "enumValues": null,
                            "possibleTypes": null
                        },
                        {
                            "kind": "OBJECT",
                            "name": "User",
                            "description": "A user in the system",
                            "fields": [
                                {
                                    "name": "id",
                                    "description": null,
                                    "args": [],
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "SCALAR",
                                            "name": "ID",
                                            "ofType": null
                                        }
                                    },
                                    "isDeprecated": false
                                },
                                {
                                    "name": "name",
                                    "description": null,
                                    "args": [],
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "SCALAR",
                                            "name": "String",
                                            "ofType": null
                                        }
                                    },
                                    "isDeprecated": false
                                },
                                {
                                    "name": "email",
                                    "description": "The user's email address",
                                    "args": [],
                                    "type": {
                                        "kind": "SCALAR",
                                        "name": "String",
                                        "ofType": null
                                    },
                                    "isDeprecated": false
                                },
                                {
                                    "name": "role",
                                    "description": null,
                                    "args": [],
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "ENUM",
                                            "name": "Role",
                                            "ofType": null
                                        }
                                    },
                                    "isDeprecated": false
                                },
                                {
                                    "name": "posts",
                                    "description": null,
                                    "args": [],
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "LIST",
                                            "name": null,
                                            "ofType": {
                                                "kind": "NON_NULL",
                                                "name": null,
                                                "ofType": {
                                                    "kind": "OBJECT",
                                                    "name": "Post",
                                                    "ofType": null
                                                }
                                            }
                                        }
                                    },
                                    "isDeprecated": false
                                }
                            ],
                            "inputFields": null,
                            "interfaces": [
                                {
                                    "kind": "INTERFACE",
                                    "name": "Node",
                                    "ofType": null
                                }
                            ],
                            "enumValues": null,
                            "possibleTypes": null
                        },
                        {
                            "kind": "OBJECT",
                            "name": "Post",
                            "description": "A blog post",
                            "fields": [
                                {
                                    "name": "id",
                                    "description": null,
                                    "args": [],
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "SCALAR",
                                            "name": "ID",
                                            "ofType": null
                                        }
                                    },
                                    "isDeprecated": false
                                },
                                {
                                    "name": "title",
                                    "description": null,
                                    "args": [],
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "SCALAR",
                                            "name": "String",
                                            "ofType": null
                                        }
                                    },
                                    "isDeprecated": false
                                },
                                {
                                    "name": "body",
                                    "description": null,
                                    "args": [],
                                    "type": {
                                        "kind": "SCALAR",
                                        "name": "String",
                                        "ofType": null
                                    },
                                    "isDeprecated": false
                                }
                            ],
                            "inputFields": null,
                            "interfaces": [
                                {
                                    "kind": "INTERFACE",
                                    "name": "Node",
                                    "ofType": null
                                }
                            ],
                            "enumValues": null,
                            "possibleTypes": null
                        },
                        {
                            "kind": "INTERFACE",
                            "name": "Node",
                            "description": "An object with a globally unique ID",
                            "fields": [
                                {
                                    "name": "id",
                                    "description": null,
                                    "args": [],
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "SCALAR",
                                            "name": "ID",
                                            "ofType": null
                                        }
                                    },
                                    "isDeprecated": false
                                }
                            ],
                            "inputFields": null,
                            "interfaces": null,
                            "enumValues": null,
                            "possibleTypes": [
                                {
                                    "kind": "OBJECT",
                                    "name": "User",
                                    "ofType": null
                                },
                                {
                                    "kind": "OBJECT",
                                    "name": "Post",
                                    "ofType": null
                                }
                            ]
                        },
                        {
                            "kind": "ENUM",
                            "name": "Role",
                            "description": "User role in the system",
                            "fields": null,
                            "inputFields": null,
                            "interfaces": null,
                            "enumValues": [
                                {
                                    "name": "ADMIN",
                                    "description": "Full access",
                                    "isDeprecated": false
                                },
                                {
                                    "name": "USER",
                                    "description": "Standard user",
                                    "isDeprecated": false
                                },
                                {
                                    "name": "GUEST",
                                    "description": "Read-only access",
                                    "isDeprecated": true
                                }
                            ],
                            "possibleTypes": null
                        },
                        {
                            "kind": "INPUT_OBJECT",
                            "name": "CreateUserInput",
                            "description": "Input for creating a user",
                            "fields": null,
                            "inputFields": [
                                {
                                    "name": "name",
                                    "description": null,
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "SCALAR",
                                            "name": "String",
                                            "ofType": null
                                        }
                                    },
                                    "defaultValue": null
                                },
                                {
                                    "name": "email",
                                    "description": null,
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "SCALAR",
                                            "name": "String",
                                            "ofType": null
                                        }
                                    },
                                    "defaultValue": null
                                },
                                {
                                    "name": "role",
                                    "description": null,
                                    "type": {
                                        "kind": "ENUM",
                                        "name": "Role",
                                        "ofType": null
                                    },
                                    "defaultValue": "\"USER\""
                                }
                            ],
                            "interfaces": null,
                            "enumValues": null,
                            "possibleTypes": null
                        },
                        {
                            "kind": "INPUT_OBJECT",
                            "name": "UserFilter",
                            "description": "Filter options for user listing",
                            "fields": null,
                            "inputFields": [
                                {
                                    "name": "role",
                                    "description": "Filter by role",
                                    "type": {
                                        "kind": "ENUM",
                                        "name": "Role",
                                        "ofType": null
                                    },
                                    "defaultValue": null
                                },
                                {
                                    "name": "nameContains",
                                    "description": "Substring match on name",
                                    "type": {
                                        "kind": "SCALAR",
                                        "name": "String",
                                        "ofType": null
                                    },
                                    "defaultValue": null
                                }
                            ],
                            "interfaces": null,
                            "enumValues": null,
                            "possibleTypes": null
                        },
                        {
                            "kind": "UNION",
                            "name": "SearchResult",
                            "description": "A union of searchable types",
                            "fields": null,
                            "inputFields": null,
                            "interfaces": null,
                            "enumValues": null,
                            "possibleTypes": [
                                {
                                    "kind": "OBJECT",
                                    "name": "User",
                                    "ofType": null
                                },
                                {
                                    "kind": "OBJECT",
                                    "name": "Post",
                                    "ofType": null
                                }
                            ]
                        },
                        {
                            "kind": "OBJECT",
                            "name": "__Schema",
                            "description": "Introspection schema object",
                            "fields": [],
                            "inputFields": null,
                            "interfaces": [],
                            "enumValues": null,
                            "possibleTypes": null
                        },
                        {
                            "kind": "OBJECT",
                            "name": "__Type",
                            "description": "Introspection type object",
                            "fields": [],
                            "inputFields": null,
                            "interfaces": [],
                            "enumValues": null,
                            "possibleTypes": null
                        }
                    ],
                    "directives": [
                        {
                            "name": "include",
                            "description": "Conditionally include a field",
                            "locations": ["FIELD", "FRAGMENT_SPREAD", "INLINE_FRAGMENT"],
                            "args": [
                                {
                                    "name": "if",
                                    "description": "Boolean condition",
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "SCALAR",
                                            "name": "Boolean",
                                            "ofType": null
                                        }
                                    },
                                    "defaultValue": null
                                }
                            ]
                        },
                        {
                            "name": "skip",
                            "description": "Conditionally skip a field",
                            "locations": ["FIELD", "FRAGMENT_SPREAD", "INLINE_FRAGMENT"],
                            "args": [
                                {
                                    "name": "if",
                                    "description": "Boolean condition",
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": null,
                                        "ofType": {
                                            "kind": "SCALAR",
                                            "name": "Boolean",
                                            "ofType": null
                                        }
                                    },
                                    "defaultValue": null
                                }
                            ]
                        },
                        {
                            "name": "deprecated",
                            "description": "Marks a field as deprecated",
                            "locations": ["FIELD_DEFINITION", "ENUM_VALUE"],
                            "args": [
                                {
                                    "name": "reason",
                                    "description": "Deprecation reason",
                                    "type": {
                                        "kind": "SCALAR",
                                        "name": "String",
                                        "ofType": null
                                    },
                                    "defaultValue": "\"No longer supported\""
                                }
                            ]
                        }
                    ]
                }
            }
        })
    }

    fn parse_sample() -> Schema {
        let json = sample_introspection_response();
        parse_introspection_response(&json).expect("failed to parse sample introspection response")
    }

    #[test]
    fn parse_introspection_response_root_types() {
        let schema = parse_sample();
        assert_eq!(schema.query_type.as_deref(), Some("Query"));
        assert_eq!(schema.mutation_type.as_deref(), Some("Mutation"));
        assert_eq!(schema.subscription_type, None);
    }

    #[test]
    fn parse_introspection_response_type_count() {
        let schema = parse_sample();
        // String, Int, Boolean, ID, Query, Mutation, User, Post, Node, Role,
        // CreateUserInput, UserFilter, SearchResult, __Schema, __Type = 15
        assert_eq!(schema.types.len(), 15);
    }

    #[test]
    fn queries_returns_query_fields() {
        let schema = parse_sample();
        let queries = schema.queries();
        let names: Vec<&str> = queries.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["user", "users", "status"]);
    }

    #[test]
    fn mutations_returns_mutation_fields() {
        let schema = parse_sample();
        let mutations = schema.mutations();
        let names: Vec<&str> = mutations.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["createUser", "deleteUser"]);
    }

    #[test]
    fn input_types_returns_input_objects() {
        let schema = parse_sample();
        let inputs = schema.input_types();
        let mut names: Vec<&str> = inputs.iter().map(|t| t.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["CreateUserInput", "UserFilter"]);
    }

    #[test]
    fn object_types_excludes_builtins() {
        let schema = parse_sample();
        let objects = schema.object_types();
        let names: Vec<&str> = objects.iter().map(|t| t.name.as_str()).collect();
        // Should include Query, Mutation, User, Post but NOT __Schema, __Type
        assert!(names.contains(&"Query"));
        assert!(names.contains(&"User"));
        assert!(names.contains(&"Post"));
        assert!(!names.contains(&"__Schema"));
        assert!(!names.contains(&"__Type"));
    }

    #[test]
    fn is_builtin_works() {
        assert!(Schema::is_builtin("__Schema"));
        assert!(Schema::is_builtin("__Type"));
        assert!(Schema::is_builtin("String"));
        assert!(Schema::is_builtin("Int"));
        assert!(Schema::is_builtin("Float"));
        assert!(Schema::is_builtin("Boolean"));
        assert!(Schema::is_builtin("ID"));
        assert!(!Schema::is_builtin("User"));
        assert!(!Schema::is_builtin("Post"));
        assert!(!Schema::is_builtin("Role"));
    }

    #[test]
    fn type_names_excludes_builtins() {
        let schema = parse_sample();
        let names = schema.type_names();
        assert!(names.contains(&"User"));
        assert!(names.contains(&"Query"));
        assert!(names.contains(&"Role"));
        assert!(names.contains(&"SearchResult"));
        assert!(!names.contains(&"String"));
        assert!(!names.contains(&"__Schema"));
        assert!(!names.contains(&"__Type"));
    }

    #[test]
    fn resolve_type_ref_simple() {
        let schema = parse_sample();
        let type_ref = TypeRef {
            kind: TypeKind::Object,
            name: Some("User".into()),
            of_type: None,
        };
        let resolved = schema.resolve_type_ref(&type_ref).unwrap();
        assert_eq!(resolved.name, "User");
        assert_eq!(resolved.kind, TypeKind::Object);
    }

    #[test]
    fn resolve_type_ref_non_null_list_non_null() {
        // NonNull<List<NonNull<User>>>
        let schema = parse_sample();
        let type_ref = TypeRef {
            kind: TypeKind::NonNull,
            name: None,
            of_type: Some(Box::new(TypeRef {
                kind: TypeKind::List,
                name: None,
                of_type: Some(Box::new(TypeRef {
                    kind: TypeKind::NonNull,
                    name: None,
                    of_type: Some(Box::new(TypeRef {
                        kind: TypeKind::Object,
                        name: Some("User".into()),
                        of_type: None,
                    })),
                })),
            })),
        };
        let resolved = schema.resolve_type_ref(&type_ref).unwrap();
        assert_eq!(resolved.name, "User");
    }

    #[test]
    fn type_ref_inner_name() {
        // NonNull<List<NonNull<User>>>
        let type_ref = TypeRef {
            kind: TypeKind::NonNull,
            name: None,
            of_type: Some(Box::new(TypeRef {
                kind: TypeKind::List,
                name: None,
                of_type: Some(Box::new(TypeRef {
                    kind: TypeKind::NonNull,
                    name: None,
                    of_type: Some(Box::new(TypeRef {
                        kind: TypeKind::Object,
                        name: Some("User".into()),
                        of_type: None,
                    })),
                })),
            })),
        };
        assert_eq!(type_ref.inner_name(), Some("User"));
    }

    #[test]
    fn type_ref_display() {
        // [User!]!
        let type_ref = TypeRef {
            kind: TypeKind::NonNull,
            name: None,
            of_type: Some(Box::new(TypeRef {
                kind: TypeKind::List,
                name: None,
                of_type: Some(Box::new(TypeRef {
                    kind: TypeKind::NonNull,
                    name: None,
                    of_type: Some(Box::new(TypeRef {
                        kind: TypeKind::Object,
                        name: Some("User".into()),
                        of_type: None,
                    })),
                })),
            })),
        };
        assert_eq!(type_ref.display_type(), "[User!]!");
    }

    #[test]
    fn type_ref_is_non_null() {
        let non_null = TypeRef {
            kind: TypeKind::NonNull,
            name: None,
            of_type: Some(Box::new(TypeRef {
                kind: TypeKind::Scalar,
                name: Some("String".into()),
                of_type: None,
            })),
        };
        assert!(non_null.is_non_null());

        let nullable = TypeRef {
            kind: TypeKind::Scalar,
            name: Some("String".into()),
            of_type: None,
        };
        assert!(!nullable.is_non_null());
    }

    #[test]
    fn type_ref_is_list() {
        // NonNull<List<String>>
        let list = TypeRef {
            kind: TypeKind::NonNull,
            name: None,
            of_type: Some(Box::new(TypeRef {
                kind: TypeKind::List,
                name: None,
                of_type: Some(Box::new(TypeRef {
                    kind: TypeKind::Scalar,
                    name: Some("String".into()),
                    of_type: None,
                })),
            })),
        };
        assert!(list.is_list());

        let scalar = TypeRef {
            kind: TypeKind::Scalar,
            name: Some("String".into()),
            of_type: None,
        };
        assert!(!scalar.is_list());
    }

    #[test]
    fn parse_directives() {
        let schema = parse_sample();
        assert_eq!(schema.directives.len(), 3);
        let names: Vec<&str> = schema.directives.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"include"));
        assert!(names.contains(&"skip"));
        assert!(names.contains(&"deprecated"));

        let deprecated = schema
            .directives
            .iter()
            .find(|d| d.name == "deprecated")
            .unwrap();
        assert_eq!(deprecated.locations, vec!["FIELD_DEFINITION", "ENUM_VALUE"]);
        assert_eq!(deprecated.args.len(), 1);
        assert_eq!(deprecated.args[0].name, "reason");
        assert_eq!(
            deprecated.args[0].default_value.as_deref(),
            Some("\"No longer supported\"")
        );
    }

    #[test]
    fn parse_enum_values() {
        let schema = parse_sample();
        let role = schema.get_type("Role").unwrap();
        assert_eq!(role.kind, TypeKind::Enum);
        assert_eq!(role.enum_values.len(), 3);

        let admin = role
            .enum_values
            .iter()
            .find(|v| v.name == "ADMIN")
            .unwrap();
        assert!(!admin.is_deprecated);

        let guest = role
            .enum_values
            .iter()
            .find(|v| v.name == "GUEST")
            .unwrap();
        assert!(guest.is_deprecated);
    }

    #[test]
    fn parse_interfaces_and_possible_types() {
        let schema = parse_sample();

        let user = schema.get_type("User").unwrap();
        assert_eq!(user.interfaces.len(), 1);
        assert_eq!(user.interfaces[0].name.as_deref(), Some("Node"));

        let node = schema.get_type("Node").unwrap();
        assert_eq!(node.kind, TypeKind::Interface);
        assert_eq!(node.possible_types.len(), 2);
        let possible_names: Vec<Option<&str>> = node
            .possible_types
            .iter()
            .map(|t| t.name.as_deref())
            .collect();
        assert!(possible_names.contains(&Some("User")));
        assert!(possible_names.contains(&Some("Post")));
    }

    #[test]
    fn parse_union() {
        let schema = parse_sample();
        let search = schema.get_type("SearchResult").unwrap();
        assert_eq!(search.kind, TypeKind::Union);
        assert_eq!(search.possible_types.len(), 2);
    }

    #[test]
    fn parse_input_object_fields_and_defaults() {
        let schema = parse_sample();
        let create_user = schema.get_type("CreateUserInput").unwrap();
        assert_eq!(create_user.kind, TypeKind::InputObject);
        assert_eq!(create_user.input_fields.len(), 3);

        let role_field = create_user
            .input_fields
            .iter()
            .find(|f| f.name == "role")
            .unwrap();
        assert_eq!(role_field.default_value.as_deref(), Some("\"USER\""));
        assert_eq!(role_field.input_type.kind, TypeKind::Enum);
    }

    #[test]
    fn field_args_parsed() {
        let schema = parse_sample();
        let query = schema.get_type("Query").unwrap();
        let user_field = query.fields.iter().find(|f| f.name == "user").unwrap();
        assert_eq!(user_field.args.len(), 1);
        assert_eq!(user_field.args[0].name, "id");
        assert!(user_field.args[0].input_type.is_non_null());
        assert_eq!(user_field.args[0].input_type.inner_name(), Some("ID"));
    }

    #[test]
    fn get_type_returns_none_for_missing() {
        let schema = parse_sample();
        assert!(schema.get_type("NonExistent").is_none());
    }

    #[test]
    fn resolve_type_ref_returns_none_for_missing() {
        let schema = parse_sample();
        let type_ref = TypeRef {
            kind: TypeKind::Object,
            name: Some("NonExistent".into()),
            of_type: None,
        };
        assert!(schema.resolve_type_ref(&type_ref).is_none());
    }

    #[test]
    fn bare_schema_envelope_accepted() {
        // Test that __schema without the data wrapper is accepted
        let json = json!({
            "__schema": {
                "queryType": { "name": "Query" },
                "mutationType": null,
                "subscriptionType": null,
                "types": [
                    {
                        "kind": "OBJECT",
                        "name": "Query",
                        "description": null,
                        "fields": [],
                        "inputFields": null,
                        "interfaces": [],
                        "enumValues": null,
                        "possibleTypes": null
                    }
                ],
                "directives": []
            }
        });
        let schema = parse_introspection_response(&json).unwrap();
        assert_eq!(schema.query_type.as_deref(), Some("Query"));
        assert_eq!(schema.types.len(), 1);
    }

    #[test]
    fn deprecated_field_detected() {
        let schema = parse_sample();
        let query = schema.get_type("Query").unwrap();
        let status = query.fields.iter().find(|f| f.name == "status").unwrap();
        assert!(status.is_deprecated);

        let user = query.fields.iter().find(|f| f.name == "user").unwrap();
        assert!(!user.is_deprecated);
    }

    #[test]
    fn error_on_missing_schema() {
        let json = json!({ "data": {} });
        let result = parse_introspection_response(&json);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SchemaError::IntrospectionFailed(_)));
    }

    #[test]
    fn error_on_missing_types_array() {
        let json = json!({
            "data": {
                "__schema": {
                    "queryType": null,
                    "mutationType": null,
                    "subscriptionType": null
                }
            }
        });
        let result = parse_introspection_response(&json);
        assert!(result.is_err());
    }

    #[test]
    fn serde_roundtrip_type_kind() {
        for kind in [
            TypeKind::Scalar,
            TypeKind::Object,
            TypeKind::Interface,
            TypeKind::Union,
            TypeKind::Enum,
            TypeKind::InputObject,
            TypeKind::List,
            TypeKind::NonNull,
        ] {
            let serialized = serde_json::to_string(&kind).unwrap();
            let deserialized: TypeKind = serde_json::from_str(&serialized).unwrap();
            assert_eq!(kind, deserialized);
        }
    }

    #[test]
    fn serde_roundtrip_schema() {
        let schema = parse_sample();
        let json = serde_json::to_value(&schema).unwrap();
        let _: Schema = serde_json::from_value(json).unwrap();
    }

    #[test]
    fn mutations_empty_when_no_mutation_type() {
        let json = json!({
            "data": {
                "__schema": {
                    "queryType": { "name": "Query" },
                    "mutationType": null,
                    "subscriptionType": null,
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "Query",
                            "description": null,
                            "fields": [],
                            "inputFields": null,
                            "interfaces": [],
                            "enumValues": null,
                            "possibleTypes": null
                        }
                    ],
                    "directives": []
                }
            }
        });
        let schema = parse_introspection_response(&json).unwrap();
        assert!(schema.mutations().is_empty());
    }
}
