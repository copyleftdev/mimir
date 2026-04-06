use thiserror::Error;

/// Errors that can occur during a deterministic simulation sweep.
#[derive(Debug, Error)]
pub enum DstError {
    /// The introspection query failed or was blocked.
    #[error("introspection failed: {0}")]
    IntrospectionFailed(String),

    /// A transport-level error occurred during HTTP communication.
    #[error("transport error: {0}")]
    TransportError(#[from] mimir_transport::TransportError),

    /// The exploration loop encountered an unrecoverable error.
    #[error("exploration failed: {0}")]
    ExplorationFailed(String),

    /// The schema could not be parsed or is invalid.
    #[error("schema error: {0}")]
    SchemaError(#[from] mimir_schema::SchemaError),
}
