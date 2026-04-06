/// Errors that can occur when working with a GraphQL schema.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SchemaError {
    /// The introspection query failed or returned an unexpected response shape.
    #[error("introspection failed: {0}")]
    IntrospectionFailed(String),

    /// A schema definition could not be parsed.
    #[error("parse error: {0}")]
    ParseError(String),

    /// The schema is structurally invalid (e.g. missing required root types).
    #[error("invalid schema: {0}")]
    InvalidSchema(String),
}
