//! Minimal JSON-RPC 2.0 framing for MCP, plus the per-revision differences
//! this server has to respect.
//!
//! Supported revisions were checked against the published specification
//! (<https://modelcontextprotocol.io/specification>) and its schemas. The
//! newest published revision, `2026-07-28`, is deliberately **not** listed: it
//! removes the `initialize` handshake and `ping` and requires
//! `server/discover`, none of which this server implements. Per that
//! revision's stdio backward-compatibility rules, a modern client probing with
//! `server/discover` receives `-32601` here and falls back to `initialize`.

use serde_json::{Value, json};

/// MCP protocol revisions this server implements, newest first.
pub const SUPPORTED_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// Invalid JSON.
pub const PARSE_ERROR: i64 = -32700;
/// Not a valid request object.
pub const INVALID_REQUEST: i64 = -32600;
/// Unknown method.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// Bad parameters (including unknown tool names).
pub const INVALID_PARAMS: i64 = -32602;

/// What differs between the supported revisions, as far as this server's
/// messages are concerned. Derived from each revision's `schema.ts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Features {
    /// `Tool.annotations` exists (2025-03-26+).
    pub tool_annotations: bool,
    /// `title` on tools/implementations and `CallToolResult.structuredContent`
    /// exist (2025-06-18+).
    pub titles_and_structured_content: bool,
    /// Servers MUST accept JSON-RPC batches (2025-03-26 only; removed in
    /// 2025-06-18). Also accepted for 2024-11-05, which inherits JSON-RPC 2.0.
    pub batches: bool,
    /// Tool *input validation* failures are reported as tool results with
    /// `isError: true` (2025-11-25+). Earlier revisions list "invalid
    /// arguments" under JSON-RPC protocol errors (`-32602`).
    pub validation_as_tool_error: bool,
}

/// Returns the feature set of a supported revision.
pub fn features(version: &str) -> Features {
    let at_least = |v: &str| version >= v; // ISO dates compare lexicographically
    Features {
        tool_annotations: at_least("2025-03-26"),
        titles_and_structured_content: at_least("2025-06-18"),
        batches: !at_least("2025-06-18"),
        validation_as_tool_error: at_least("2025-11-25"),
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_matrix_matches_the_schemas() {
        let f = features("2024-11-05");
        assert!(
            !f.tool_annotations
                && !f.titles_and_structured_content
                && f.batches
                && !f.validation_as_tool_error
        );
        let f = features("2025-03-26");
        assert!(
            f.tool_annotations
                && !f.titles_and_structured_content
                && f.batches
                && !f.validation_as_tool_error
        );
        let f = features("2025-06-18");
        assert!(
            f.tool_annotations
                && f.titles_and_structured_content
                && !f.batches
                && !f.validation_as_tool_error
        );
        let f = features("2025-11-25");
        assert!(
            f.tool_annotations
                && f.titles_and_structured_content
                && !f.batches
                && f.validation_as_tool_error
        );
    }

    #[test]
    fn negotiation() {
        assert_eq!(negotiate(Some("2025-03-26")), "2025-03-26");
        // Published but not implemented here: fall back to our newest.
        assert_eq!(negotiate(Some("2026-07-28")), "2025-11-25");
        assert_eq!(negotiate(None), "2025-11-25");
    }
}
