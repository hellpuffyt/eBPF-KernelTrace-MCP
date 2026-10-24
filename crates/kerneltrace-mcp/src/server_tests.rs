//! Unit tests for request dispatch, run against a real engine.

use super::*;
use crate::protocol::SUPPORTED_VERSIONS;
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

fn send(srv: &mut Server<'_>, v: Value) -> Value {
    srv.handle_line(&v.to_string()).expect("response")
}

fn init(srv: &mut Server<'_>, version: &str) -> Value {
    send(
        srv,
        json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":version,"capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
    )
}

fn call(srv: &mut Server<'_>, name: &str, args: Value) -> Value {
    send(
        srv,
        json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":name,"arguments":args}}),
    )
}

/// Asserts a validation failure is reported the way `version` requires and
/// returns its message.
fn invalid(srv: &mut Server<'_>, version: &str, name: &str, args: Value) -> String {
    let r = call(srv, name, args.clone());
    if protocol::features(version).validation_as_tool_error {
        assert_eq!(r["result"]["isError"], true, "{version} {args}: {r}");
        r["result"]["content"][0]["text"]
            .as_str()
            .expect("text")
            .to_string()
    } else {
        assert_eq!(r["error"]["code"], INVALID_PARAMS, "{version} {args}: {r}");
        r["error"]["message"].as_str().expect("message").to_string()
    }
}

#[test]
fn negotiates_versions() {
    with_server(|s| {
        assert_eq!(
            init(s, "2025-06-18")["result"]["protocolVersion"],
            "2025-06-18"
        );
        assert_eq!(s.version(), Some("2025-06-18"));
        assert_eq!(
            init(s, "1999-01-01")["result"]["protocolVersion"],
            SUPPORTED_VERSIONS[0]
        );
        // The newest published revision is stateless and not implemented here.
        assert_eq!(
            init(s, "2026-07-28")["result"]["protocolVersion"],
            "2025-11-25"
        );
    });
}

#[test]
fn modern_discover_probe_gets_method_not_found() {
    // 2026-07-28 stdio clients probe with server/discover and fall back to
    // initialize on any non-modern error.
    with_server(|s| {
        let r = send(
            s,
            json!({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}),
        );
        assert_eq!(r["error"]["code"], METHOD_NOT_FOUND);
    });
}

#[test]
fn tools_require_initialize() {
    with_server(|s| {
        for m in ["tools/list", "tools/call"] {
            let r = send(
                s,
                json!({"jsonrpc":"2.0","id":1,"method":m,"params":{"name":"stats"}}),
            );
            assert_eq!(r["error"]["code"], INVALID_REQUEST);
            assert!(
                r["error"]["message"]
                    .as_str()
                    .expect("msg")
                    .contains("send initialize")
            );
        }
        // ping is allowed before initialize.
        assert_eq!(
            send(s, json!({"jsonrpc":"2.0","id":2,"method":"ping"}))["result"],
            json!({})
        );
    });
}

#[test]
fn protocol_errors() {
    with_server(|s| {
        init(s, "2025-11-25");
        assert_eq!(
            s.handle_line("{not json").expect("r")["error"]["code"],
            PARSE_ERROR
        );
        assert_eq!(send(s, json!([1, 2]))["error"]["code"], INVALID_REQUEST);
        assert_eq!(send(s, json!(42))["error"]["code"], INVALID_REQUEST);
        assert_eq!(
            send(s, json!({"jsonrpc":"1.0","id":1,"method":"ping"}))["error"]["code"],
            INVALID_REQUEST
        );
        assert_eq!(
            send(s, json!({"jsonrpc":"2.0","id":null,"method":"ping"}))["error"]["code"],
            INVALID_REQUEST
        );
        assert_eq!(
            send(s, json!({"jsonrpc":"2.0","id":1.5,"method":"ping"}))["error"]["code"],
            INVALID_REQUEST
        );
        assert_eq!(
            send(s, json!({"jsonrpc":"2.0","id":1,"method":"nope"}))["error"]["code"],
            METHOD_NOT_FOUND
        );
        assert!(
            s.handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .is_none()
        );
        // Malformed tools/call requests are protocol errors in every revision.
        for params in [json!(null), json!([]), json!({}), json!({"name": 5})] {
            let r = send(
                s,
                json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":params}),
            );
            assert_eq!(r["error"]["code"], INVALID_PARAMS, "{params}");
        }
    });
}

#[test]
fn unknown_tool_is_a_protocol_error_in_every_version() {
    with_server(|s| {
        for v in SUPPORTED_VERSIONS {
            init(s, v);
            let r = call(s, "write_kernel_memory", json!({}));
            assert_eq!(r["error"]["code"], INVALID_PARAMS, "{v}");
            let msg = r["error"]["message"].as_str().expect("msg");
            assert!(
                msg.contains("unknown tool: write_kernel_memory") && msg.contains("query_events"),
                "{msg}"
            );
        }
    });
}

#[test]
fn invalid_arguments_have_useful_messages_in_every_version() {
    with_server(|s| {
        for v in SUPPORTED_VERSIONS {
            init(s, v);
            let q = "query_events";
            let cases: Vec<(&str, Value, &str)> = vec![
                (
                    q,
                    json!({"limit": 100000}),
                    "limit must be between 1 and 500, got 100000",
                ),
                (
                    q,
                    json!({"limit": 0}),
                    "limit must be between 1 and 500, got 0",
                ),
                (
                    q,
                    json!({"limit": -1}),
                    "`limit`: invalid value: integer `-1`",
                ),
                (
                    q,
                    json!({"limit": "5"}),
                    "`limit`: invalid type: string \"5\"",
                ),
                (
                    q,
                    json!({"limit": 1e30}),
                    "`limit`: invalid type: floating point",
                ),
                (
                    q,
                    json!({"after_seq": -3}),
                    "`after_seq`: invalid value: integer `-3`",
                ),
                (
                    q,
                    json!({"pids": [1, 4294967296u64]}),
                    "`pids[1]`: invalid value: integer `4294967296`",
                ),
                (q, json!({"pids": "1"}), "`pids`: invalid type: string"),
                (
                    q,
                    json!({"kinds": ["fork"]}),
                    "`kinds[0]`: unknown variant `fork`",
                ),
                (q, json!({"pid": 1}), "unknown field `pid`"),
                (q, json!({"last_secs": -1.0}), "last_secs must be > 0"),
                (
                    q,
                    json!({"last_secs": 1e300}),
                    "last_secs must be > 0 and <= 1000000000",
                ),
                (
                    q,
                    json!({"pids": (0..65).collect::<Vec<u32>>()}),
                    "at most 64 entries",
                ),
                (
                    q,
                    json!({"path_prefix": "x".repeat(5000)}),
                    "path_prefix must be at most 4096 bytes",
                ),
                (
                    q,
                    json!({"top_n": 3}),
                    "top_n is not valid for query_events",
                ),
                (
                    q,
                    json!([1, 2]),
                    "arguments for query_events must be a JSON object, got an array",
                ),
                (
                    "summarize_events",
                    json!({"top_n": 51}),
                    "top_n must be between 1 and 50, got 51",
                ),
                (
                    "summarize_events",
                    json!({"limit": 5}),
                    "limit is not valid for summarize_events",
                ),
                ("stats", json!({"verbose": true}), "unknown field `verbose`"),
            ];
            for (tool, args, want) in cases {
                let msg = invalid(s, v, tool, args.clone());
                assert!(
                    msg.contains(want),
                    "{v} {tool} {args}: got {msg:?}, want {want:?}"
                );
            }
        }
    });
}

#[test]
fn results_are_shaped_per_version() {
    with_server(|s| {
        for v in SUPPORTED_VERSIONS {
            let f = protocol::features(v);
            let i = init(s, v);
            assert_eq!(
                i["result"]["serverInfo"].get("title").is_some(),
                f.titles_and_structured_content,
                "{v}"
            );
            let list = send(s, json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}));
            let tools = list["result"]["tools"].as_array().expect("tools");
            assert_eq!(tools.len(), 4);
            for t in tools {
                assert_eq!(t.get("annotations").is_some(), f.tool_annotations, "{v}");
                assert_eq!(
                    t.get("title").is_some(),
                    f.titles_and_structured_content,
                    "{v}"
                );
            }
            let r = call(s, "query_events", json!({"kinds": ["open"], "limit": 5}));
            assert_eq!(r["result"]["isError"], false);
            assert_eq!(
                r["result"].get("structuredContent").is_some(),
                f.titles_and_structured_content,
                "{v}"
            );
            // The text content always carries the full JSON.
            let text: Value =
                serde_json::from_str(r["result"]["content"][0]["text"].as_str().expect("t"))
                    .expect("json");
            assert_eq!(text["returned"], 5);
        }
    });
}

#[test]
fn batches_follow_the_negotiated_version() {
    with_server(|s| {
        let batch = json!([
            {"jsonrpc":"2.0","id":1,"method":"ping"},
            {"jsonrpc":"2.0","method":"notifications/initialized"},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"stats"}},
            {"jsonrpc":"2.0","id":3,"method":"initialize","params":{}}
        ]);
        assert_eq!(
            send(s, batch.clone())["error"]["code"],
            INVALID_REQUEST,
            "before initialize"
        );
        for v in SUPPORTED_VERSIONS {
            init(s, v);
            let r = send(s, batch.clone());
            if protocol::features(v).batches {
                let arr = r.as_array().expect("batch response");
                assert_eq!(arr.len(), 3, "{v}: notification gets no response");
                assert_eq!(arr[0]["id"], 1);
                assert_eq!(arr[1]["result"]["isError"], false);
                assert_eq!(
                    arr[2]["error"]["code"], INVALID_REQUEST,
                    "initialize inside a batch"
                );
                assert_eq!(send(s, json!([]))["error"]["code"], INVALID_REQUEST);
                let too_many: Vec<Value> = (0..65)
                    .map(|i| json!({"jsonrpc":"2.0","id":i,"method":"ping"}))
                    .collect();
                assert_eq!(
                    send(s, Value::Array(too_many))["error"]["code"],
                    INVALID_REQUEST
                );
                assert!(
                    s.handle_line(r#"[{"jsonrpc":"2.0","method":"notifications/x"}]"#)
                        .is_none()
                );
            } else {
                assert_eq!(r["error"]["code"], INVALID_REQUEST, "{v}");
                assert!(r["error"]["message"].as_str().expect("m").contains(v));
            }
        }
    });
}

#[test]
fn query_and_summarize() {
    with_server(|s| {
        init(s, "2025-11-25");
        let q = call(s, "query_events", json!({"kinds":["open"],"limit":5}));
        let sc = &q["result"]["structuredContent"];
        assert_eq!(sc["returned"], 5);
        assert!(
            sc["events"]
                .as_array()
                .expect("array")
                .iter()
                .all(|e| e["kind"] == "open")
        );
        let sm = call(s, "summarize_events", json!({"top_n":3}));
        assert!(
            sm["result"]["structuredContent"]["total"]
                .as_u64()
                .expect("total")
                >= 200
        );
        let st = call(s, "stats", Value::Null);
        assert_eq!(st["result"]["structuredContent"]["source"], "synthetic");
        // Huge after_seq within u64 is valid and simply matches nothing.
        let none = call(s, "query_events", json!({"after_seq": u64::MAX}));
        assert_eq!(none["result"]["structuredContent"]["returned"], 0);
    });
}
