use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// The fundamental kind of a GraphQL type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TypeKind {
    Scalar,
    Object,
    Interface,
    Union,
    Enum,
    InputObject,
    List,
    NonNull,
}

impl std::fmt::Display for TypeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeKind::Scalar => write!(f, "SCALAR"),
            TypeKind::Object => write!(f, "OBJECT"),
            TypeKind::Interface => write!(f, "INTERFACE"),
            TypeKind::Union => write!(f, "UNION"),
            TypeKind::Enum => write!(f, "ENUM"),
            TypeKind::InputObject => write!(f, "INPUT_OBJECT"),
            TypeKind::List => write!(f, "LIST"),
            TypeKind::NonNull => write!(f, "NON_NULL"),
        }
    }
}

/// A reference to a GraphQL type, potentially wrapped in `NonNull` or `List` modifiers.
///
/// Leaf types carry a `name`; wrapper types (`List`, `NonNull`) carry an `of_type`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeRef {
    pub name: Option<String>,
    pub kind: TypeKind,
    pub of_type: Option<Box<TypeRef>>,
}

impl TypeRef {
    /// Unwrap all `NonNull` and `List` wrappers and return the innermost concrete type name.
    pub fn inner_name(&self) -> Option<&str> {
        match self.kind {
            TypeKind::NonNull | TypeKind::List => {
                self.of_type.as_ref().and_then(|t| t.inner_name())
            }
            _ => self.name.as_deref(),
        }
    }

    /// Returns `true` if the outermost wrapper is `NonNull`.
    pub fn is_non_null(&self) -> bool {
        self.kind == TypeKind::NonNull
    }

    /// Returns `true` if this type (possibly under a `NonNull` wrapper) is a `List`.
    pub fn is_list(&self) -> bool {
        match self.kind {
            TypeKind::List => true,
            TypeKind::NonNull => self.of_type.as_ref().is_some_and(|t| t.is_list()),
            _ => false,
        }
    }

    /// Build a compact display string such as `[User!]!`.
    pub fn display_type(&self) -> String {
        match self.kind {
            TypeKind::NonNull => {
                let inner = self
                    .of_type
                    .as_ref()
                    .map(|t| t.display_type())
                    .unwrap_or_default();
                format!("{inner}!")
            }
            TypeKind::List => {
                let inner = self
                    .of_type
                    .as_ref()
                    .map(|t| t.display_type())
                    .unwrap_or_default();
                format!("[{inner}]")
            }
            _ => self.name.clone().unwrap_or_default(),
        }
    }
}

/// A field on an Object or Interface type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub description: Option<String>,
    pub args: Vec<InputValue>,
    pub field_type: TypeRef,
    pub is_deprecated: bool,
}

/// An input value: either a field argument or an input-object field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputValue {
    pub name: String,
    pub description: Option<String>,
    pub input_type: TypeRef,
    pub default_value: Option<String>,
}

/// A single value in an Enum type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumValue {
    pub name: String,
    pub description: Option<String>,
    pub is_deprecated: bool,
}

/// Full representation of a named GraphQL type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullType {
    pub name: String,
    pub kind: TypeKind,
    pub description: Option<String>,
    /// Fields on this type. Non-empty for Object and Interface kinds.
    pub fields: Vec<Field>,
    /// Input fields. Non-empty for InputObject kind.
    pub input_fields: Vec<InputValue>,
    /// Interfaces this type implements (Object kind).
    pub interfaces: Vec<TypeRef>,
    /// Possible enum values (Enum kind).
    pub enum_values: Vec<EnumValue>,
    /// Possible concrete types (Interface and Union kinds).
    pub possible_types: Vec<TypeRef>,
}

/// The complete GraphQL schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    pub query_type: Option<String>,
    pub mutation_type: Option<String>,
    pub subscription_type: Option<String>,
    /// All named types keyed by their name. Insertion order is preserved.
    pub types: IndexMap<String, FullType>,
    pub directives: Vec<Directive>,
}

/// A GraphQL directive definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Directive {
    pub name: String,
    pub description: Option<String>,
    pub locations: Vec<String>,
    pub args: Vec<InputValue>,
}

/// Built-in introspection and scalar type names that should generally be excluded from
/// user-facing listings.
const BUILTIN_NAMES: &[&str] = &[
    "__Schema",
    "__Type",
    "__Field",
    "__InputValue",
    "__EnumValue",
    "__Directive",
    "__DirectiveLocation",
    "String",
    "Int",
    "Float",
    "Boolean",
    "ID",
];

impl Schema {
    /// Look up a type by name.
    pub fn get_type(&self, name: &str) -> Option<&FullType> {
        self.types.get(name)
    }

    /// Return all fields on the mutation root type, or an empty vec if there is none.
    pub fn mutations(&self) -> Vec<&Field> {
        self.root_fields(&self.mutation_type)
    }

    /// Return all fields on the query root type, or an empty vec if there is none.
    pub fn queries(&self) -> Vec<&Field> {
        self.root_fields(&self.query_type)
    }

    /// Return all `InputObject` types in the schema.
    pub fn input_types(&self) -> Vec<&FullType> {
        self.types
            .values()
            .filter(|t| t.kind == TypeKind::InputObject)
            .collect()
    }

    /// Return all `Object` types, excluding introspection built-ins (names starting with `__`).
    pub fn object_types(&self) -> Vec<&FullType> {
        self.types
            .values()
            .filter(|t| t.kind == TypeKind::Object && !t.name.starts_with("__"))
            .collect()
    }

    /// Returns `true` if `name` is a GraphQL built-in introspection or scalar type.
    pub fn is_builtin(name: &str) -> bool {
        BUILTIN_NAMES.contains(&name)
    }

    /// Unwrap `NonNull` and `List` wrappers on a [`TypeRef`] and resolve to the concrete
    /// [`FullType`] in this schema.
    pub fn resolve_type_ref(&self, type_ref: &TypeRef) -> Option<&FullType> {
        match type_ref.kind {
            TypeKind::NonNull | TypeKind::List => type_ref
                .of_type
                .as_ref()
                .and_then(|inner| self.resolve_type_ref(inner)),
            _ => type_ref.name.as_deref().and_then(|n| self.get_type(n)),
        }
    }

    /// Return all non-builtin type names.
    pub fn type_names(&self) -> Vec<&str> {
        self.types
            .keys()
            .filter(|name| !Self::is_builtin(name))
            .map(|s| s.as_str())
            .collect()
    }

    // ---- private helpers ----

    fn root_fields(&self, root: &Option<String>) -> Vec<&Field> {
        root.as_deref()
            .and_then(|name| self.get_type(name))
            .map(|t| t.fields.iter().collect())
            .unwrap_or_default()
    }
}
