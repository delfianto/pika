use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
    /// Null or missing for notifications (no response expected).
    pub id: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 error object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// Standard JSON-RPC 2.0 error codes
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

impl JsonRpcResponse {
    /// Create a successful response.
    pub fn ok(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Create an error response.
    pub fn err(id: Option<serde_json::Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }

    /// Create a notification (server-initiated, no id).
    pub fn notification(method: &str, params: serde_json::Value) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: None,
        }
    }
}

impl JsonRpcRequest {
    /// Validate that this is a valid JSON-RPC 2.0 request.
    pub fn validate(&self) -> Result<(), String> {
        if self.jsonrpc != "2.0" {
            return Err(format!("expected jsonrpc \"2.0\", got \"{}\"", self.jsonrpc));
        }
        if self.method.is_empty() {
            return Err("method must not be empty".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_request() {
        let json = r#"{"jsonrpc":"2.0","method":"pid.list","params":{},"id":1}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "pid.list");
        assert_eq!(req.id, Some(serde_json::json!(1)));
    }

    #[test]
    fn deserialize_request_without_params() {
        let json = r#"{"jsonrpc":"2.0","method":"pid.list","id":1}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.params, serde_json::Value::Null);
    }

    #[test]
    fn deserialize_notification() {
        let json = r#"{"jsonrpc":"2.0","method":"scan.progress","params":{"progress":50}}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert!(req.id.is_none());
    }

    #[test]
    fn serialize_ok_response() {
        let resp = JsonRpcResponse::ok(Some(serde_json::json!(1)), serde_json::json!({"status": "ok"}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"result\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn serialize_error_response() {
        let resp = JsonRpcResponse::err(Some(serde_json::json!(1)), METHOD_NOT_FOUND, "not found");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"error\""));
        assert!(!json.contains("\"result\""));
        assert!(json.contains("-32601"));
    }

    #[test]
    fn validate_valid_request() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "test".to_string(),
            params: serde_json::Value::Null,
            id: Some(serde_json::json!(1)),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_wrong_version() {
        let req = JsonRpcRequest {
            jsonrpc: "1.0".to_string(),
            method: "test".to_string(),
            params: serde_json::Value::Null,
            id: Some(serde_json::json!(1)),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn validate_empty_method() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: String::new(),
            params: serde_json::Value::Null,
            id: Some(serde_json::json!(1)),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn response_roundtrip() {
        let resp = JsonRpcResponse::ok(Some(serde_json::json!(42)), serde_json::json!({"candidates": 100}));
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: JsonRpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, Some(serde_json::json!(42)));
        assert!(parsed.result.is_some());
        assert!(parsed.error.is_none());
    }
}
