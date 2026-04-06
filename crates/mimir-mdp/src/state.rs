use serde::{Deserialize, Serialize};

/// Observable state of the API at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiState {
    /// Unique state fingerprint (hash of observable features).
    pub fingerprint: String,
    /// HTTP status codes seen.
    pub status_codes: Vec<u16>,
    /// Error messages seen (deduplicated).
    pub error_messages: Vec<String>,
    /// Response shapes seen (type structure, not values).
    pub response_shapes: Vec<String>,
    /// Auth tokens/cookies received.
    pub tokens: Vec<String>,
    /// Number of operations executed so far.
    pub step_count: usize,
}

impl ApiState {
    /// Create a new empty API state.
    pub fn new() -> Self {
        Self {
            fingerprint: String::new(),
            status_codes: Vec::new(),
            error_messages: Vec::new(),
            response_shapes: Vec::new(),
            tokens: Vec::new(),
            step_count: 0,
        }
    }
}

impl Default for ApiState {
    fn default() -> Self {
        Self::new()
    }
}

/// An action in the MDP (a GraphQL operation to perform).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub id: String,
    pub operation_name: String,
    pub query: String,
    pub variables: serde_json::Value,
}

/// Outcome of taking an action.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub action_id: String,
    pub new_state: ApiState,
    pub reward: f64,
    pub is_new_state: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_state_default() {
        let state = ApiState::default();
        assert!(state.fingerprint.is_empty());
        assert!(state.status_codes.is_empty());
        assert_eq!(state.step_count, 0);
    }

    #[test]
    fn test_action_serialization() {
        let action = Action {
            id: "a1".to_string(),
            operation_name: "createUser".to_string(),
            query: "mutation { createUser(input: {}) { id } }".to_string(),
            variables: serde_json::json!({"name": "test"}),
        };
        let json = serde_json::to_string(&action).unwrap();
        let deserialized: Action = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "a1");
        assert_eq!(deserialized.operation_name, "createUser");
    }
}
