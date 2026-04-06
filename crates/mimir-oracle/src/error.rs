use thiserror::Error;

/// Errors that can occur during oracle evaluation.
#[derive(Debug, Error)]
pub enum OracleError {
    /// The property definition is invalid or cannot be parsed.
    #[error("invalid property: {0}")]
    InvalidProperty(String),

    /// A property check failed to execute (not the same as the property failing).
    #[error("check failed: {0}")]
    CheckFailed(String),
}
