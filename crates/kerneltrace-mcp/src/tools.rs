//! MCP tool definitions and implementations. All tools are read-only.

use kerneltrace_core::{Engine, EventKind, Filter, capability};
use serde::Deserialize;
use serde_json::{Value, json};

const DEFAULT_LIMIT: usize = 50;
const DEFAULT_TOP_N: usize = 5;
const MAX_TOP_N: usize = 50;

fn filter_schema(extra: Value) -> Value {
    let mut props = json!({
        "pids": { "type": "array", "items": { "type": "integer", "minimum": 0 }, "description": "Only these process ids." },
        "comms": { "type": "array", "items": { "type": "string" }, "description": "Only these command names (exact)." },
        "kinds": { "type": "array", "items": { "type": "string", "enum": ["exec", "exit", "open"] } },
        "path_prefix": { "type": "string", "description": "Only events whose (possibly redacted) path starts with this." },
        "after_seq": { "type": "integer", "minimum": 0, "description": "Page forward: only events with seq greater than this." },
        "last_secs": { "type": "number", "exclusiveMinimum": 0, "description": "Only events received in the last N seconds." }
    });
    if let (Some(p), Some(e)) = (props.as_object_mut(), extra.as_object()) {
        p.extend(e.clone());
    }
    json!({ "type": "object", "properties": props, "additionalProperties": false })
}

/// The `tools/list` payload.
pub fn list(max_query_limit: usize) -> Value {
    let ro = json!({ "readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false });
    json!({ "tools": [
        {
            "name": "capabilities",
            "title": "Host capabilities",
            "description": "Report whether live eBPF telemetry is possible on this host and why not, plus which event kinds and sensitive fields are enabled.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
            "annotations": ro
        },
        {
            "name": "query_events",
            "title": "Query events",
            "description": format!("Return stored kernel events (exec/exit/open) matching filters. Without after_seq returns the most recent matches; with after_seq pages forward. limit defaults to {DEFAULT_LIMIT}, hard maximum {max_query_limit}."),
            "inputSchema": filter_schema(json!({ "limit": { "type": "integer", "minimum": 1, "maximum": max_query_limit } })),
            "annotations": ro
        },
        {
            "name": "summarize_events",
            "title": "Summarize events",
            "description": "Aggregate stored events matching filters: counts by kind, top command names and pids, and event rate.",
            "inputSchema": filter_schema(json!({ "top_n": { "type": "integer", "minimum": 1, "maximum": MAX_TOP_N } })),
            "annotations": ro
        },
        {
            "name": "stats",
            "title": "Pipeline statistics",
            "description": "Pipeline counters: records read, decode errors, sampled out, redacted, queue drops (backpressure), retention evictions, queue latency percentiles.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
            "annotations": ro
        }
    ]})
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FilterArgs {
    pids: Vec<u32>,
    comms: Vec<String>,
    kinds: Vec<EventKind>,
    path_prefix: Option<String>,
    after_seq: Option<u64>,
    last_secs: Option<f64>,
    limit: Option<usize>,
    top_n: Option<usize>,
}

impl FilterArgs {
    fn filter(&self, engine: &Engine) -> Result<Filter, String> {
        let min_received_ns = match self.last_secs {
            None => None,
            Some(s) if s.is_finite() && s > 0.0 => {
                Some(engine.now_ns().saturating_sub((s * 1e9) as u64))
            }
            Some(_) => return Err("last_secs must be a positive number".into()),
        };
        Ok(Filter {
            pids: self.pids.clone(),
            comms: self.comms.clone(),
            kinds: self.kinds.clone(),
            path_prefix: self.path_prefix.clone(),
            after_seq: self.after_seq,
            min_received_ns,
        })
    }
}

/// Error from a tool call.
pub enum CallError {
    /// No such tool (a protocol error).
    UnknownTool(String),
    /// Bad arguments or execution failure (reported as `isError: true`).
    Tool(String),
}

fn parse<T: for<'de> Deserialize<'de> + Default>(args: Option<&Value>) -> Result<T, CallError> {
    match args {
        None | Some(Value::Null) => Ok(T::default()),
        Some(v) => serde_json::from_value(v.clone())
            .map_err(|e| CallError::Tool(format!("invalid arguments: {e}"))),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoArgs {}

/// Runs one tool and returns its structured result.
pub fn call(
    engine: &Engine,
    ctx: &Value,
    name: &str,
    args: Option<&Value>,
) -> Result<Value, CallError> {
    match name {
        "capabilities" => {
            parse::<NoArgs>(args)?;
            Ok(json!({ "host": capability::detect(), "collection": ctx }))
        }
        "stats" => {
            parse::<NoArgs>(args)?;
            serde_json::to_value(engine.stats()).map_err(|e| CallError::Tool(e.to_string()))
        }
        "query_events" => {
            let a: FilterArgs = parse(args)?;
            if a.top_n.is_some() {
                return Err(CallError::Tool(
                    "top_n is not valid for query_events".into(),
                ));
            }
            let limit = a.limit.unwrap_or(DEFAULT_LIMIT);
            if limit == 0 || limit > engine.max_query_limit() {
                return Err(CallError::Tool(format!(
                    "limit must be between 1 and {}",
                    engine.max_query_limit()
                )));
            }
            let filter = a.filter(engine).map_err(CallError::Tool)?;
            let r = engine.query(&filter, limit);
            Ok(json!({
                "events": r.events,
                "returned": r.events.len(),
                "matched": r.matched,
                "truncated": r.truncated,
                "next_after_seq": r.events.last().map(|e| e.seq),
            }))
        }
        "summarize_events" => {
            let a: FilterArgs = parse(args)?;
            if a.limit.is_some() {
                return Err(CallError::Tool(
                    "limit is not valid for summarize_events; use top_n".into(),
                ));
            }
            let top_n = a.top_n.unwrap_or(DEFAULT_TOP_N);
            if top_n == 0 || top_n > MAX_TOP_N {
                return Err(CallError::Tool(format!(
                    "top_n must be between 1 and {MAX_TOP_N}"
                )));
            }
            let filter = a.filter(engine).map_err(CallError::Tool)?;
            serde_json::to_value(engine.summarize(&filter, top_n))
                .map_err(|e| CallError::Tool(e.to_string()))
        }
        other => Err(CallError::UnknownTool(other.to_string())),
    }
}
