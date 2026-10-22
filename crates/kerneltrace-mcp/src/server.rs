//! MCP request dispatch.

use kerneltrace_core::{Config, Engine};
use serde_json::{Value, json};

use crate::protocol::{self, INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND, PARSE_ERROR};
use crate::tools::{self, CallError};

const INSTRUCTIONS: &str = "Read-only kernel telemetry. Call `capabilities` first to learn whether events are \
live or synthetic and which fields are collected. Use `summarize_events` for an overview and `query_events` \
with filters for detail. Paths are omitted or redacted unless the operator enabled them.";

/// Protocol state for one client connection.
pub struct Server<'a> {
    engine: &'a Engine,
    collection: Value,
    initialized: bool,
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
            initialized: false,
        }
    }

    /// Whether `initialize` has been answered.
    #[cfg(test)]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Handles one JSON-RPC message. Returns the response line, or `None` for notifications.
    pub fn handle_line(&mut self, line: &str) -> Option<Value> {
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return Some(protocol::error(
                    &Value::Null,
                    PARSE_ERROR,
                    format!("parse error: {e}"),
                ));
            }
        };
        let Some(obj) = msg.as_object() else {
            // JSON-RPC batches were removed from MCP in 2025-06-18.
            return Some(protocol::error(
                &Value::Null,
                INVALID_REQUEST,
                "expected a single JSON-RPC object",
            ));
        };
        let id = obj.get("id").cloned();
        let method = obj.get("method").and_then(Value::as_str);
        if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return id.map(|id| protocol::error(&id, INVALID_REQUEST, "jsonrpc must be \"2.0\""));
        }
        let Some(method) = method else {
            // A response from the client (we never send requests) or garbage.
            return None;
        };
        let Some(id) = id else {
            // Notification (e.g. notifications/initialized, notifications/cancelled).
            return None;
        };
        let params = obj.get("params");
        Some(self.dispatch(&id, method, params))
    }

    fn dispatch(&mut self, id: &Value, method: &str, params: Option<&Value>) -> Value {
        match method {
            "initialize" => {
                let requested = params
                    .and_then(|p| p.get("protocolVersion"))
                    .and_then(Value::as_str);
                self.initialized = true;
                protocol::result(
                    id,
                    json!({
                        "protocolVersion": protocol::negotiate(requested),
                        "capabilities": { "tools": { "listChanged": false } },
                        "serverInfo": { "name": "kerneltrace-mcp", "title": "eBPF KernelTrace MCP", "version": env!("CARGO_PKG_VERSION") },
                        "instructions": INSTRUCTIONS,
                    }),
                )
            }
            "ping" => protocol::result(id, json!({})),
            "tools/list" => protocol::result(id, tools::list(self.engine.max_query_limit())),
            "tools/call" => {
                let Some(name) = params.and_then(|p| p.get("name")).and_then(Value::as_str) else {
                    return protocol::error(id, INVALID_PARAMS, "tools/call requires params.name");
                };
                let args = params.and_then(|p| p.get("arguments"));
                match tools::call(self.engine, &self.collection, name, args) {
                    Ok(structured) => protocol::result(
                        id,
                        json!({
                            "content": [{ "type": "text", "text": structured.to_string() }],
                            "structuredContent": structured,
                            "isError": false,
                        }),
                    ),
                    Err(CallError::Tool(msg)) => protocol::result(
                        id,
                        json!({ "content": [{ "type": "text", "text": msg }], "isError": true }),
                    ),
                    Err(CallError::UnknownTool(name)) => {
                        protocol::error(id, INVALID_PARAMS, format!("unknown tool: {name}"))
                    }
                }
            }
            other => protocol::error(id, METHOD_NOT_FOUND, format!("method not found: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerneltrace_core::{Pacing, SyntheticSource};

    fn with_server(f: impl FnOnce(&mut Server<'_>)) {
        let mut cfg = Config::default();
        cfg.sources.open = true;
        let mut engine = Engine::start(
            &cfg,
            Box::new(SyntheticSource::new(1, 1000, 0)),
            Pacing::Unpaced,
        )
        .expect("engine");
        while engine.stats().stored < 200 {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let mut srv = Server::new(&engine, &cfg);
        f(&mut srv);
        engine.shutdown();
    }

    fn call(srv: &mut Server<'_>, line: &str) -> Value {
        srv.handle_line(line).expect("response")
    }

    #[test]
    fn negotiates_versions() {
        with_server(|s| {
            let r = call(
                s,
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
            );
            assert_eq!(r["result"]["protocolVersion"], "2025-06-18");
            assert!(s.is_initialized());
            let r = call(
                s,
                r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#,
            );
            assert_eq!(
                r["result"]["protocolVersion"],
                protocol::SUPPORTED_VERSIONS[0]
            );
        });
    }

    #[test]
    fn protocol_errors() {
        with_server(|s| {
            assert_eq!(call(s, "{not json")["error"]["code"], PARSE_ERROR);
            assert_eq!(call(s, "[1,2]")["error"]["code"], INVALID_REQUEST);
            assert_eq!(
                call(s, r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#)["error"]["code"],
                INVALID_REQUEST
            );
            assert_eq!(
                call(s, r#"{"jsonrpc":"2.0","id":1,"method":"nope"}"#)["error"]["code"],
                METHOD_NOT_FOUND
            );
            assert_eq!(
                call(
                    s,
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rm_rf"}}"#
                )["error"]["code"],
                INVALID_PARAMS
            );
            assert!(
                s.handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                    .is_none()
            );
        });
    }

    #[test]
    fn tool_argument_errors_are_tool_errors() {
        with_server(|s| {
            let bad_limit = call(
                s,
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_events","arguments":{"limit":100000}}}"#,
            );
            assert_eq!(bad_limit["result"]["isError"], true);
            let unknown_field = call(
                s,
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_events","arguments":{"pid":1}}}"#,
            );
            assert_eq!(unknown_field["result"]["isError"], true);
            let bad_kind = call(
                s,
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_events","arguments":{"kinds":["fork"]}}}"#,
            );
            assert_eq!(bad_kind["result"]["isError"], true);
        });
    }

    #[test]
    fn query_and_summarize() {
        with_server(|s| {
            let q = call(
                s,
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_events","arguments":{"kinds":["open"],"limit":5}}}"#,
            );
            let sc = &q["result"]["structuredContent"];
            assert_eq!(sc["returned"], 5);
            assert!(
                sc["events"]
                    .as_array()
                    .expect("array")
                    .iter()
                    .all(|e| e["kind"] == "open")
            );
            let sm = call(
                s,
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"summarize_events","arguments":{"top_n":3}}}"#,
            );
            assert!(
                sm["result"]["structuredContent"]["total"]
                    .as_u64()
                    .expect("total")
                    >= 200
            );
            let st = call(
                s,
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"stats"}}"#,
            );
            assert_eq!(st["result"]["structuredContent"]["source"], "synthetic");
        });
    }
}
