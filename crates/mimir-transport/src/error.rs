use thiserror::Error;

/// Errors that can occur during GraphQL HTTP transport.
#[derive(Debug, Error)]
pub enum TransportError {
    /// An HTTP-level error from reqwest.
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    /// The request timed out.
    #[error("request timed out after {0}ms")]
    Timeout(u64),

    /// The server returned a response that could not be parsed as valid JSON.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// The GraphQL response contained one or more errors.
    #[error("GraphQL errors: {}", .0.join("; "))]
    GraphqlError(Vec<String>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_timeout() {
        let err = TransportError::Timeout(5000);
        assert_eq!(err.to_string(), "request timed out after 5000ms");
    }

    #[test]
    fn display_invalid_response() {
        let err = TransportError::InvalidResponse("expected JSON object".into());
        assert_eq!(err.to_string(), "invalid response: expected JSON object");
    }

    #[test]
    fn display_graphql_error_single() {
        let err = TransportError::GraphqlError(vec!["field not found".into()]);
        assert_eq!(err.to_string(), "GraphQL errors: field not found");
    }

    #[test]
    fn display_graphql_error_multiple() {
        let err =
            TransportError::GraphqlError(vec!["field not found".into(), "unauthorized".into()]);
        assert_eq!(
            err.to_string(),
            "GraphQL errors: field not found; unauthorized"
        );
    }
}
