//! Minimal JSON-RPC 2.0 framing for MCP.

use serde_json::{Value, json};

/// MCP protocol revisions this server can speak, newest first.
pub const SUPPORTED_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// Invalid JSON.
pub const PARSE_ERROR: i64 = -32700;
/// Not a valid request object.
pub const INVALID_REQUEST: i64 = -32600;
/// Unknown method.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// Bad parameters (including unknown tool names).
pub const INVALID_PARAMS: i64 = -32602;

/// Chooses the protocol version to answer `initialize` with: the client's if
/// we support it, otherwise our newest.
pub fn negotiate(requested: Option<&str>) -> &'static str {
    requested
        .and_then(|r| SUPPORTED_VERSIONS.iter().find(|v| **v == r).copied())
        .unwrap_or(SUPPORTED_VERSIONS[0])
}

/// A successful response.
pub fn result(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// An error response.
pub fn error(id: &Value, code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message.into() } })
}
