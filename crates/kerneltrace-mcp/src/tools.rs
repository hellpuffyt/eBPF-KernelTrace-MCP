//! MCP tool definitions and implementations. All tools are read-only.

use kerneltrace_core::{Engine, EventKind, Filter, capability};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::protocol::Features;

const DEFAULT_LIMIT: usize = 50;
const DEFAULT_TOP_N: usize = 5;
const MAX_TOP_N: usize = 50;
/// Maximum entries in each of `pids` / `comms` / `kinds`. Filtering is
/// O(entries × stored events), so this bounds the cost of one query.
pub const MAX_LIST_ENTRIES: usize = 64;
/// Maximum byte length of `path_prefix` and of each `comms` entry.
pub const MAX_STRING_BYTES: usize = 4096;
/// Largest accepted `last_secs` (about 31.7 years; keeps the ns conversion exact enough).
pub const MAX_LAST_SECS: f64 = 1.0e9;

/// Tool names, in `tools/list` order.
pub const TOOL_NAMES: [&str; 4] = ["capabilities", "query_events", "summarize_events", "stats"];

fn filter_schema(extra: Value) -> Value {
    let mut props = json!({
        "pids": { "type": "array", "maxItems": MAX_LIST_ENTRIES, "items": { "type": "integer", "minimum": 0, "maximum": u32::MAX }, "description": "Only these process ids." },
        "comms": { "type": "array", "maxItems": MAX_LIST_ENTRIES, "items": { "type": "string", "maxLength": MAX_STRING_BYTES }, "description": "Only these command names (exact)." },
        "kinds": { "type": "array", "maxItems": MAX_LIST_ENTRIES, "items": { "type": "string", "enum": ["exec", "exit", "open"] } },
        "path_prefix": { "type": "string", "maxLength": MAX_STRING_BYTES, "description": "Only events whose (possibly redacted) path starts with this." },
        "after_seq": { "type": "integer", "minimum": 0, "description": "Page forward: only events with seq greater than this." },
        "last_secs": { "type": "number", "exclusiveMinimum": 0, "maximum": MAX_LAST_SECS, "description": "Only events received in the last N seconds." }
    });
    if let (Some(p), Some(e)) = (props.as_object_mut(), extra.as_object()) {
        p.extend(e.clone());
    }
    json!({ "type": "object", "properties": props, "additionalProperties": false })
}

/// The `tools/list` payload, shaped for the negotiated protocol revision.
pub fn list(max_query_limit: usize, features: Features) -> Value {
    let ro = json!({ "readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false });
    let empty = json!({ "type": "object", "properties": {}, "additionalProperties": false });
    let defs = [
        (
            "Host capabilities",
            "Report whether live eBPF telemetry is possible on this host and why not, plus which event kinds and sensitive fields are enabled.".to_string(),
            empty.clone(),
        ),
        (
            "Query events",
            format!("Return stored kernel events (exec/exit/open) matching filters. Without after_seq returns the most recent matches; with after_seq pages forward. limit defaults to {DEFAULT_LIMIT}, hard maximum {max_query_limit}."),
            filter_schema(json!({ "limit": { "type": "integer", "minimum": 1, "maximum": max_query_limit } })),
        ),
        (
            "Summarize events",
            "Aggregate stored events matching filters: counts by kind, top command names and pids, and event rate.".to_string(),
            filter_schema(json!({ "top_n": { "type": "integer", "minimum": 1, "maximum": MAX_TOP_N } })),
        ),
        (
            "Pipeline statistics",
            "Pipeline counters: records read, decode errors, sampled out, redacted, queue drops (backpressure), retention evictions, queue latency percentiles.".to_string(),
            empty,
        ),
    ];
    let tools: Vec<Value> = TOOL_NAMES
        .iter()
        .zip(defs)
        .map(|(name, (title, description, schema))| {
            let mut t = Map::new();
            t.insert("name".into(), json!(name));
            if features.titles_and_structured_content {
                t.insert("title".into(), json!(title));
            }
            t.insert("description".into(), json!(description));
            t.insert("inputSchema".into(), schema);
            if features.tool_annotations {
                t.insert("annotations".into(), ro.clone());
            }
            Value::Object(t)
        })
        .collect();
    json!({ "tools": tools })
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
    limit: Option<u64>,
    top_n: Option<u64>,
}

impl FilterArgs {
    fn filter(&self, engine: &Engine) -> Result<Filter, CallError> {
        let invalid = |m: String| Err(CallError::InvalidArgs(m));
        if self.pids.len() > MAX_LIST_ENTRIES
            || self.comms.len() > MAX_LIST_ENTRIES
            || self.kinds.len() > MAX_LIST_ENTRIES
        {
            return invalid(format!(
                "pids, comms and kinds may each have at most {MAX_LIST_ENTRIES} entries"
            ));
        }
        if self.comms.iter().any(|c| c.len() > MAX_STRING_BYTES) {
            return invalid(format!(
                "each comms entry must be at most {MAX_STRING_BYTES} bytes"
            ));
        }
        if self
            .path_prefix
            .as_ref()
            .is_some_and(|p| p.len() > MAX_STRING_BYTES)
        {
            return invalid(format!(
                "path_prefix must be at most {MAX_STRING_BYTES} bytes"
            ));
        }
        let min_received_ns = match self.last_secs {
            None => None,
            Some(s) if s.is_finite() && s > 0.0 && s <= MAX_LAST_SECS => {
                Some(engine.now_ns().saturating_sub((s * 1e9) as u64))
            }
            Some(s) => {
                return invalid(format!(
                    "last_secs must be > 0 and <= {MAX_LAST_SECS}, got {s}"
                ));
            }
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
#[derive(Debug)]
pub enum CallError {
    /// No such tool: always a JSON-RPC protocol error.
    UnknownTool(String),
    /// Arguments failed validation. Reported as a protocol error or as a tool
    /// result with `isError`, depending on the negotiated revision.
    InvalidArgs(String),
    /// The tool itself failed: always a tool result with `isError`.
    Failed(String),
}

fn parse<T: for<'de> Deserialize<'de> + Default>(
    tool: &str,
    args: Option<&Value>,
) -> Result<T, CallError> {
    match args {
        None | Some(Value::Null) => Ok(T::default()),
        Some(Value::Object(_)) => {
            let v = args.cloned().unwrap_or(Value::Null);
            serde_path_to_error::deserialize(v).map_err(|e| {
                let path = e.path().to_string();
                let inner = e.into_inner();
                if path == "." {
                    CallError::InvalidArgs(format!("invalid arguments for {tool}: {inner}"))
                } else {
                    CallError::InvalidArgs(format!(
                        "invalid arguments for {tool}: `{path}`: {inner}"
                    ))
                }
            })
        }
        Some(other) => Err(CallError::InvalidArgs(format!(
            "arguments for {tool} must be a JSON object, got {}",
            type_name(other)
        ))),
    }
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoArgs {}

fn in_range(
    name: &str,
    value: Option<u64>,
    default: usize,
    max: usize,
) -> Result<usize, CallError> {
    match value {
        None => Ok(default),
        Some(v) if v >= 1 && v <= max as u64 => Ok(v as usize),
        Some(v) => Err(CallError::InvalidArgs(format!(
            "{name} must be between 1 and {max}, got {v}"
        ))),
    }
}

/// Runs one tool and returns its structured result.
pub fn call(
    engine: &Engine,
    ctx: &Value,
    name: &str,
    args: Option<&Value>,
) -> Result<Value, CallError> {
    let to_value =
        |v: Result<Value, serde_json::Error>| v.map_err(|e| CallError::Failed(e.to_string()));
    match name {
        "capabilities" => {
            parse::<NoArgs>(name, args)?;
            Ok(json!({ "host": capability::detect(), "collection": ctx }))
        }
        "stats" => {
            parse::<NoArgs>(name, args)?;
            to_value(serde_json::to_value(engine.stats()))
        }
        "query_events" => {
            let a: FilterArgs = parse(name, args)?;
            if a.top_n.is_some() {
                return Err(CallError::InvalidArgs(
                    "top_n is not valid for query_events; use limit".into(),
                ));
            }
            let limit = in_range("limit", a.limit, DEFAULT_LIMIT, engine.max_query_limit())?;
            let filter = a.filter(engine)?;
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
            let a: FilterArgs = parse(name, args)?;
            if a.limit.is_some() {
                return Err(CallError::InvalidArgs(
                    "limit is not valid for summarize_events; use top_n".into(),
                ));
            }
            let top_n = in_range("top_n", a.top_n, DEFAULT_TOP_N, MAX_TOP_N)?;
            let filter = a.filter(engine)?;
            to_value(serde_json::to_value(engine.summarize(&filter, top_n)))
        }
        other => Err(CallError::UnknownTool(other.to_string())),
    }
}
