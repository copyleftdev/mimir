use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A captured outbound GraphQL request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedRequest {
    /// SHA-256 hash of operation + variables, used as a correlation id.
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub operation_name: Option<String>,
    pub query: String,
    pub variables: serde_json::Value,
    pub headers: Vec<(String, String)>,
}

/// A captured inbound GraphQL response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedResponse {
    /// Matches the corresponding `CapturedRequest::id`.
    pub request_id: String,
    pub timestamp: DateTime<Utc>,
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: serde_json::Value,
    pub latency_ms: u64,
    pub data: Option<serde_json::Value>,
    pub errors: Vec<GraphqlError>,
}

/// A single error entry from a GraphQL response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphqlError {
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<ErrorLocation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Location within a GraphQL document where an error occurred.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorLocation {
    pub line: u32,
    pub column: u32,
}

/// An append-only log of captured request/response exchanges.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CaptureLog {
    exchanges: Vec<(CapturedRequest, CapturedResponse)>,
}

impl CaptureLog {
    /// Create an empty capture log.
    pub fn new() -> Self {
        Self {
            exchanges: Vec::new(),
        }
    }

    /// Append a request/response pair.
    pub fn push(&mut self, request: CapturedRequest, response: CapturedResponse) {
        self.exchanges.push((request, response));
    }

    /// Number of captured exchanges.
    pub fn len(&self) -> usize {
        self.exchanges.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.exchanges.is_empty()
    }

    /// Iterate over all exchanges.
    pub fn iter(&self) -> impl Iterator<Item = &(CapturedRequest, CapturedResponse)> {
        self.exchanges.iter()
    }

    /// Iterate over captured requests only.
    pub fn requests(&self) -> impl Iterator<Item = &CapturedRequest> {
        self.exchanges.iter().map(|(req, _)| req)
    }

    /// Iterate over captured responses only.
    pub fn responses(&self) -> impl Iterator<Item = &CapturedResponse> {
        self.exchanges.iter().map(|(_, resp)| resp)
    }

    /// Find exchanges whose operation name matches `name`.
    pub fn find_by_operation(&self, name: &str) -> Vec<&(CapturedRequest, CapturedResponse)> {
        self.exchanges
            .iter()
            .filter(|(req, _)| req.operation_name.as_deref() == Some(name))
            .collect()
    }

    /// Return only exchanges whose response contains GraphQL errors.
    pub fn errors_only(&self) -> Vec<&(CapturedRequest, CapturedResponse)> {
        self.exchanges
            .iter()
            .filter(|(_, resp)| !resp.errors.is_empty())
            .collect()
    }

    /// Serialize the full log to a JSON value.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(&self.exchanges)
            .unwrap_or_else(|_| serde_json::Value::Array(Vec::new()))
    }
}

/// Compute a deterministic request id from the query text and variables.
pub fn compute_request_id(query: &str, variables: &serde_json::Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(query.as_bytes());
    hasher.update(variables.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request(op: Option<&str>) -> CapturedRequest {
        CapturedRequest {
            id: compute_request_id("{ hero { name } }", &serde_json::json!({})),
            timestamp: Utc::now(),
            operation_name: op.map(String::from),
            query: "{ hero { name } }".into(),
            variables: serde_json::json!({}),
            headers: vec![("content-type".into(), "application/json".into())],
        }
    }

    fn sample_response(request_id: &str, has_errors: bool) -> CapturedResponse {
        let errors = if has_errors {
            vec![GraphqlError {
                message: "not found".into(),
                locations: Some(vec![ErrorLocation { line: 1, column: 3 }]),
                path: Some(vec![serde_json::json!("hero")]),
                extensions: None,
            }]
        } else {
            vec![]
        };

        CapturedResponse {
            request_id: request_id.into(),
            timestamp: Utc::now(),
            status_code: 200,
            headers: vec![],
            body: serde_json::json!({"data": {"hero": {"name": "Luke"}}}),
            latency_ms: 42,
            data: Some(serde_json::json!({"hero": {"name": "Luke"}})),
            errors,
        }
    }

    #[test]
    fn request_id_is_deterministic() {
        let a = compute_request_id("{ hero }", &serde_json::json!({"id": 1}));
        let b = compute_request_id("{ hero }", &serde_json::json!({"id": 1}));
        assert_eq!(a, b);
    }

    #[test]
    fn request_id_differs_for_different_input() {
        let a = compute_request_id("{ hero }", &serde_json::json!({"id": 1}));
        let b = compute_request_id("{ villain }", &serde_json::json!({"id": 1}));
        assert_ne!(a, b);
    }

    #[test]
    fn capture_log_push_and_len() {
        let mut log = CaptureLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);

        let req = sample_request(Some("GetHero"));
        let req_id = req.id.clone();
        let resp = sample_response(&req_id, false);
        log.push(req, resp);

        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
    }

    #[test]
    fn capture_log_iter_requests_responses() {
        let mut log = CaptureLog::new();

        let req1 = sample_request(Some("GetHero"));
        let resp1 = sample_response(&req1.id, false);
        let req2 = sample_request(Some("GetVillain"));
        let resp2 = sample_response(&req2.id, true);

        log.push(req1, resp1);
        log.push(req2, resp2);

        assert_eq!(log.iter().count(), 2);
        assert_eq!(log.requests().count(), 2);
        assert_eq!(log.responses().count(), 2);
    }

    #[test]
    fn find_by_operation() {
        let mut log = CaptureLog::new();

        let req1 = sample_request(Some("GetHero"));
        let resp1 = sample_response(&req1.id, false);
        let req2 = sample_request(Some("GetVillain"));
        let resp2 = sample_response(&req2.id, false);
        let req3 = sample_request(None);
        let resp3 = sample_response(&req3.id, false);

        log.push(req1, resp1);
        log.push(req2, resp2);
        log.push(req3, resp3);

        assert_eq!(log.find_by_operation("GetHero").len(), 1);
        assert_eq!(log.find_by_operation("GetVillain").len(), 1);
        assert_eq!(log.find_by_operation("Nonexistent").len(), 0);
    }

    #[test]
    fn errors_only() {
        let mut log = CaptureLog::new();

        let req1 = sample_request(Some("Ok"));
        let resp1 = sample_response(&req1.id, false);
        let req2 = sample_request(Some("Err"));
        let resp2 = sample_response(&req2.id, true);

        log.push(req1, resp1);
        log.push(req2, resp2);

        let errs = log.errors_only();
        assert_eq!(errs.len(), 1);
        assert_eq!(
            errs[0].0.operation_name.as_deref(),
            Some("Err")
        );
    }

    #[test]
    fn to_json_returns_array() {
        let mut log = CaptureLog::new();
        let req = sample_request(Some("GetHero"));
        let resp = sample_response(&req.id, false);
        log.push(req, resp);

        let json = log.to_json();
        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 1);
    }

    #[test]
    fn graphql_error_serde_roundtrip() {
        let err = GraphqlError {
            message: "Syntax error".into(),
            locations: Some(vec![ErrorLocation { line: 1, column: 5 }]),
            path: None,
            extensions: Some(serde_json::json!({"code": "GRAPHQL_PARSE_FAILED"})),
        };

        let json = serde_json::to_string(&err).unwrap();
        let deserialized: GraphqlError = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.message, "Syntax error");
        assert!(deserialized.path.is_none());
        assert!(deserialized.locations.is_some());
        assert!(deserialized.extensions.is_some());
    }
}
