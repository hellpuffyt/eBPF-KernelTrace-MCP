//! MCP request dispatch.

use kerneltrace_core::{Config, Engine};
use serde_json::{Map, Value, json};

use crate::protocol::{
    self, Features, INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND, PARSE_ERROR,
};
use crate::tools::{self, CallError};

const INSTRUCTIONS: &str = "Read-only kernel telemetry. Call `capabilities` first to learn whether events are \
live or synthetic and which fields are collected. Use `summarize_events` for an overview and `query_events` \
with filters for detail. Paths are omitted or redacted unless the operator enabled them.";

/// Maximum messages in one JSON-RPC batch (only accepted on revisions that allow batches).
pub const MAX_BATCH: usize = 64;

/// Protocol state for one client connection.
pub struct Server<'a> {
    engine: &'a Engine,
    collection: Value,
    /// Revision agreed in `initialize`; `None` until then.
    version: Option<&'static str>,
}

impl<'a> Server<'a> {
    /// Creates a server over a running engine.
    pub fn new(engine: &'a Engine, cfg: &Config) -> Self {
        let collection = json!({
            "mode": format!("{:?}", cfg.mode).to_lowercase(),
            "kinds": { "exec": cfg.sources.exec, "exit": cfg.sources.exit, "open": cfg.sources.open },
            "include_paths": cfg.sources.include_paths,
            "sample_every": cfg.limits.sample_every,
            "max_events": cfg.limits.max_events,
            "max_age_secs": cfg.limits.max_age_secs,
            "max_query_limit": cfg.limits.max_query_limit,
        });
        Self {
            engine,
            collection,
            version: None,
        }
    }

    /// The negotiated protocol revision, once `initialize` has been answered.
    #[cfg(test)]
    pub fn version(&self) -> Option<&'static str> {
        self.version
    }

    /// Handles one line (a JSON-RPC message or, where allowed, a batch).
    /// Returns the response, or `None` when nothing must be sent.
    pub fn handle_line(&mut self, line: &str) -> Option<Value> {
        match serde_json::from_str::<Value>(line) {
            Ok(Value::Array(items)) => self.handle_batch(items),
            Ok(msg) => self.handle_message(&msg, false),
            Err(e) => Some(protocol::error(
                &Value::Null,
                PARSE_ERROR,
                format!("parse error: {e}"),
            )),
        }
    }

    fn handle_batch(&mut self, items: Vec<Value>) -> Option<Value> {
        let batches = self
            .version
            .map(protocol::features)
            .is_some_and(|f| f.batches);
        if !batches {
            let why = match self.version {
                Some(v) => format!("JSON-RPC batches are not supported in protocol version {v}"),
                None => "JSON-RPC batches are not accepted before initialize".to_string(),
            };
            return Some(protocol::error(&Value::Null, INVALID_REQUEST, why));
        }
        if items.is_empty() {
            return Some(protocol::error(
                &Value::Null,
                INVALID_REQUEST,
                "empty batch",
            ));
        }
        if items.len() > MAX_BATCH {
            return Some(protocol::error(
                &Value::Null,
                INVALID_REQUEST,
                format!(
                    "batch of {} messages exceeds the limit of {MAX_BATCH}",
                    items.len()
                ),
            ));
        }
        let responses: Vec<Value> = items
            .iter()
            .filter_map(|m| self.handle_message(m, true))
            .collect();
        (!responses.is_empty()).then_some(Value::Array(responses))
    }

    fn handle_message(&mut self, msg: &Value, in_batch: bool) -> Option<Value> {
        let Some(obj) = msg.as_object() else {
            return Some(protocol::error(
                &Value::Null,
                INVALID_REQUEST,
                "expected a JSON-RPC object",
            ));
        };
        let id = obj.get("id").cloned();
        if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(protocol::error(
                &id.unwrap_or(Value::Null),
                INVALID_REQUEST,
                "jsonrpc must be \"2.0\"",
            ));
        }
        let Some(method) = obj.get("method").and_then(Value::as_str) else {
            // A response from the client (we never send requests): ignore.
            return None;
        };
        // Notifications (e.g. notifications/initialized) need no response.
        let id = id?;
        if !(id.is_string() || id.is_i64() || id.is_u64()) {
            return Some(protocol::error(
                &Value::Null,
                INVALID_REQUEST,
                "id must be a string or an integer",
            ));
        }
        if in_batch && method == "initialize" {
            return Some(protocol::error(
                &id,
                INVALID_REQUEST,
                "initialize must not be part of a batch",
            ));
        }
        Some(self.dispatch(&id, method, obj.get("params")))
    }

    fn dispatch(&mut self, id: &Value, method: &str, params: Option<&Value>) -> Value {
        match method {
            "initialize" => self.initialize(id, params),
            "ping" => protocol::result(id, json!({})),
            "tools/list" | "tools/call" => {
                let Some(version) = self.version else {
                    return protocol::error(
                        id,
                        INVALID_REQUEST,
                        format!("server not initialized: send initialize before {method}"),
                    );
                };
                let f = protocol::features(version);
                if method == "tools/list" {
                    protocol::result(id, tools::list(self.engine.max_query_limit(), f))
                } else {
                    self.call_tool(id, params, f)
                }
            }
            other => protocol::error(id, METHOD_NOT_FOUND, format!("method not found: {other}")),
        }
    }

    fn initialize(&mut self, id: &Value, params: Option<&Value>) -> Value {
        let requested = params
            .and_then(|p| p.get("protocolVersion"))
            .and_then(Value::as_str);
        let version = protocol::negotiate(requested);
        self.version = Some(version);
        let mut info = json!({ "name": "kerneltrace-mcp", "version": env!("CARGO_PKG_VERSION") });
        if protocol::features(version).titles_and_structured_content {
            info["title"] = json!("eBPF KernelTrace MCP");
        }
        protocol::result(
            id,
            json!({
                "protocolVersion": version,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": info,
                "instructions": INSTRUCTIONS,
            }),
        )
    }

    fn call_tool(&self, id: &Value, params: Option<&Value>, f: Features) -> Value {
        let Some(params) = params.and_then(Value::as_object) else {
            return protocol::error(id, INVALID_PARAMS, "tools/call requires a params object");
        };
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return protocol::error(
                id,
                INVALID_PARAMS,
                "tools/call requires params.name (a string)",
            );
        };
        let tool_error = |msg: String| {
            protocol::result(
                id,
                json!({ "content": [{ "type": "text", "text": msg }], "isError": true }),
            )
        };
        match tools::call(self.engine, &self.collection, name, params.get("arguments")) {
            Ok(structured) => {
                let mut r = Map::new();
                r.insert(
                    "content".into(),
                    json!([{ "type": "text", "text": structured.to_string() }]),
                );
                if f.titles_and_structured_content {
                    r.insert("structuredContent".into(), structured);
                }
                r.insert("isError".into(), json!(false));
                protocol::result(id, Value::Object(r))
            }
            Err(CallError::UnknownTool(name)) => protocol::error(
                id,
                INVALID_PARAMS,
                format!(
                    "unknown tool: {name} (available: {})",
                    tools::TOOL_NAMES.join(", ")
                ),
            ),
            Err(CallError::InvalidArgs(msg)) if f.validation_as_tool_error => tool_error(msg),
            Err(CallError::InvalidArgs(msg)) => protocol::error(id, INVALID_PARAMS, msg),
            Err(CallError::Failed(msg)) => tool_error(msg),
        }
    }
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
