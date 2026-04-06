use std::time::{Duration, Instant};

use chrono::Utc;
use serde_json::Value;
use tracing::{debug, error, info, warn};

use crate::capture::{
    CaptureLog, CapturedRequest, CapturedResponse, GraphqlError, compute_request_id,
};
use crate::error::TransportError;

/// Standard introspection query used by `introspect()`.
const INTROSPECTION_QUERY: &str = r#"
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
      args { ...InputValue }
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
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
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
            }
          }
        }
      }
    }
  }
}
"#;

/// A GraphQL HTTP client that sends operations and captures request/response pairs.
pub struct GraphqlClient {
    endpoint: String,
    http: reqwest::Client,
    default_headers: Vec<(String, String)>,
    capture: CaptureLog,
    timeout: Duration,
}

impl GraphqlClient {
    /// Create a new client pointing at the given GraphQL endpoint.
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            http: reqwest::Client::new(),
            default_headers: Vec::new(),
            capture: CaptureLog::new(),
            timeout: Duration::from_secs(30),
        }
    }

    /// Add a default header sent with every request (builder pattern).
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.default_headers.push((name.into(), value.into()));
        self
    }

    /// Set the request timeout (builder pattern).
    pub fn with_timeout(mut self, duration: Duration) -> Self {
        self.timeout = duration;
        self
    }

    /// Execute a GraphQL operation.
    ///
    /// Sends the query as a POST request with JSON body, measures latency,
    /// captures the full request/response exchange, and returns the parsed response.
    pub async fn execute(
        &mut self,
        query: &str,
        variables: Option<Value>,
        operation_name: Option<&str>,
    ) -> Result<CapturedResponse, TransportError> {
        let variables = variables.unwrap_or(Value::Null);
        let request_id = compute_request_id(query, &variables);

        // Build JSON payload
        let mut payload = serde_json::json!({
            "query": query,
            "variables": variables,
        });
        if let Some(op) = operation_name {
            payload["operationName"] = Value::String(op.to_string());
        }

        debug!(
            endpoint = %self.endpoint,
            operation = ?operation_name,
            request_id = %request_id,
            "sending GraphQL request"
        );

        // Build HTTP request
        let mut req_builder = self
            .http
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .timeout(self.timeout);

        // Collect headers for capture
        let mut captured_headers = vec![("content-type".into(), "application/json".into())];
        for (name, value) in &self.default_headers {
            req_builder = req_builder.header(name.as_str(), value.as_str());
            captured_headers.push((name.clone(), value.clone()));
        }

        let captured_request = CapturedRequest {
            id: request_id.clone(),
            timestamp: Utc::now(),
            operation_name: operation_name.map(String::from),
            query: query.to_string(),
            variables: variables.clone(),
            headers: captured_headers,
        };

        // Send and measure latency
        let start = Instant::now();
        let http_response = req_builder.json(&payload).send().await.map_err(|e| {
            if e.is_timeout() {
                warn!(request_id = %request_id, "request timed out");
                TransportError::Timeout(self.timeout.as_millis() as u64)
            } else {
                error!(request_id = %request_id, error = %e, "HTTP error");
                TransportError::HttpError(e)
            }
        })?;
        let latency_ms = start.elapsed().as_millis() as u64;

        let status_code = http_response.status().as_u16();

        // Capture response headers
        let response_headers: Vec<(String, String)> = http_response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_string()))
            .collect();

        // Read body
        let body_text = http_response.text().await.map_err(|e| {
            error!(request_id = %request_id, error = %e, "failed to read response body");
            TransportError::HttpError(e)
        })?;

        let body: Value = serde_json::from_str(&body_text).map_err(|e| {
            error!(
                request_id = %request_id,
                body = %body_text,
                error = %e,
                "response is not valid JSON"
            );
            TransportError::InvalidResponse(format!(
                "expected JSON body, got parse error: {e}"
            ))
        })?;

        // Extract data and errors
        let data = body.get("data").cloned();
        let errors = parse_graphql_errors(&body);

        info!(
            request_id = %request_id,
            status = status_code,
            latency_ms = latency_ms,
            errors = errors.len(),
            "GraphQL response received"
        );

        let captured_response = CapturedResponse {
            request_id: request_id.clone(),
            timestamp: Utc::now(),
            status_code,
            headers: response_headers,
            body,
            latency_ms,
            data,
            errors,
        };

        self.capture
            .push(captured_request, captured_response.clone());

        Ok(captured_response)
    }

    /// Send the standard introspection query and return the schema JSON.
    pub async fn introspect(&mut self) -> Result<Value, TransportError> {
        let response = self
            .execute(INTROSPECTION_QUERY, None, Some("IntrospectionQuery"))
            .await?;

        if !response.errors.is_empty() {
            let messages: Vec<String> =
                response.errors.iter().map(|e| e.message.clone()).collect();
            return Err(TransportError::GraphqlError(messages));
        }

        response.data.ok_or_else(|| {
            TransportError::InvalidResponse("introspection response missing 'data' field".into())
        })
    }

    /// Get a reference to the capture log.
    pub fn capture_log(&self) -> &CaptureLog {
        &self.capture
    }

    /// Drain and return the capture log, replacing it with an empty one.
    pub fn take_capture_log(&mut self) -> CaptureLog {
        std::mem::take(&mut self.capture)
    }
}

/// Parse the `"errors"` array out of a GraphQL response body.
fn parse_graphql_errors(body: &Value) -> Vec<GraphqlError> {
    let Some(errors_value) = body.get("errors") else {
        return Vec::new();
    };
    let Some(errors_array) = errors_value.as_array() else {
        return Vec::new();
    };

    errors_array
        .iter()
        .filter_map(|entry| serde_json::from_value::<GraphqlError>(entry.clone()).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_pattern() {
        let client = GraphqlClient::new("http://localhost:4000/graphql")
            .with_header("Authorization", "Bearer tok123")
            .with_timeout(Duration::from_secs(10));

        assert_eq!(client.endpoint, "http://localhost:4000/graphql");
        assert_eq!(client.default_headers.len(), 1);
        assert_eq!(client.default_headers[0].0, "Authorization");
        assert_eq!(client.default_headers[0].1, "Bearer tok123");
        assert_eq!(client.timeout, Duration::from_secs(10));
    }

    #[test]
    fn default_timeout_is_30s() {
        let client = GraphqlClient::new("http://localhost/graphql");
        assert_eq!(client.timeout, Duration::from_secs(30));
    }

    #[test]
    fn capture_log_starts_empty() {
        let client = GraphqlClient::new("http://localhost/graphql");
        assert!(client.capture_log().is_empty());
    }

    #[test]
    fn take_capture_log_drains() {
        let mut client = GraphqlClient::new("http://localhost/graphql");
        // Manually push a fake exchange to validate drain behavior
        let req = CapturedRequest {
            id: "abc".into(),
            timestamp: Utc::now(),
            operation_name: None,
            query: "{ __typename }".into(),
            variables: Value::Null,
            headers: vec![],
        };
        let resp = CapturedResponse {
            request_id: "abc".into(),
            timestamp: Utc::now(),
            status_code: 200,
            headers: vec![],
            body: serde_json::json!({"data": {"__typename": "Query"}}),
            latency_ms: 1,
            data: Some(serde_json::json!({"__typename": "Query"})),
            errors: vec![],
        };
        client.capture.push(req, resp);
        assert_eq!(client.capture_log().len(), 1);

        let taken = client.take_capture_log();
        assert_eq!(taken.len(), 1);
        assert!(client.capture_log().is_empty());
    }

    #[test]
    fn parse_graphql_errors_none() {
        let body = serde_json::json!({"data": {"hero": null}});
        assert!(parse_graphql_errors(&body).is_empty());
    }

    #[test]
    fn parse_graphql_errors_present() {
        let body = serde_json::json!({
            "data": null,
            "errors": [
                {
                    "message": "Cannot query field \"foo\"",
                    "locations": [{"line": 1, "column": 3}],
                    "path": ["hero", "foo"]
                },
                {
                    "message": "Unauthorized"
                }
            ]
        });
        let errors = parse_graphql_errors(&body);
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].message, "Cannot query field \"foo\"");
        assert!(errors[0].locations.is_some());
        assert_eq!(errors[0].locations.as_ref().unwrap()[0].line, 1);
        assert_eq!(errors[1].message, "Unauthorized");
        assert!(errors[1].locations.is_none());
    }

    #[test]
    fn parse_graphql_errors_not_array() {
        let body = serde_json::json!({"errors": "not an array"});
        assert!(parse_graphql_errors(&body).is_empty());
    }

    #[test]
    fn introspection_query_contains_schema() {
        assert!(INTROSPECTION_QUERY.contains("__schema"));
        assert!(INTROSPECTION_QUERY.contains("IntrospectionQuery"));
    }

    #[test]
    fn with_header_accumulates() {
        let client = GraphqlClient::new("http://localhost/graphql")
            .with_header("X-First", "1")
            .with_header("X-Second", "2")
            .with_header("X-Third", "3");

        assert_eq!(client.default_headers.len(), 3);
        assert_eq!(client.default_headers[2].0, "X-Third");
    }

    /// Test that execute works end-to-end against a nonexistent server,
    /// verifying we get an appropriate error rather than panicking.
    #[tokio::test]
    async fn execute_connection_refused() {
        let mut client = GraphqlClient::new("http://127.0.0.1:1/graphql")
            .with_timeout(Duration::from_secs(2));

        let result = client.execute("{ __typename }", None, None).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportError::HttpError(_) => {} // expected
            other => panic!("expected HttpError, got: {other}"),
        }
    }
}
