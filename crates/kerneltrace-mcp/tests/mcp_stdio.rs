//! End-to-end: spawn the real binary in synthetic mode and speak MCP over stdio.

#![allow(clippy::expect_used, clippy::unwrap_used)] // test harness: panics are the failure signal

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_kerneltrace-mcp");

struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Session {
    fn start(args: &[&str]) -> Self {
        let mut child = Command::new(BIN)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn kerneltrace-mcp");
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        }
    }

    fn send(&mut self, v: &Value) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        writeln!(stdin, "{v}").expect("write");
        stdin.flush().expect("flush");
    }

    fn read(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad response {line:?}: {e}"))
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        let r = self.read();
        assert_eq!(r["id"], id, "response id matches request");
        r
    }

    fn tool(&mut self, name: &str, args: Value) -> Value {
        let r = self.request("tools/call", json!({ "name": name, "arguments": args }));
        assert_eq!(r["result"]["isError"], false, "{r}");
        r["result"]["structuredContent"].clone()
    }

    fn wait_exit(mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("server did not exit");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn initialize(s: &mut Session) -> Value {
    let r = s.request(
        "initialize",
        json!({ "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": { "name": "it", "version": "0" } }),
    );
    s.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
    r
}

fn wait_for_events(s: &mut Session, n: u64) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while s.tool("stats", json!({}))["stored"].as_u64().unwrap_or(0) < n {
        assert!(Instant::now() < deadline, "events never arrived");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn full_session_over_stdio() {
    let mut s = Session::start(&["--seed", "7", "--rate", "5000", "--open", "--include-paths"]);
    let init = initialize(&mut s);
    assert_eq!(init["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(init["result"]["serverInfo"]["name"], "kerneltrace-mcp");
    assert!(init["result"]["capabilities"]["tools"].is_object());

    assert_eq!(s.request("ping", json!({}))["result"], json!({}));

    let tools = s.request("tools/list", json!({}));
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|t| t["name"].as_str().expect("name"))
        .collect();
    assert_eq!(
        names,
        ["capabilities", "query_events", "summarize_events", "stats"]
    );
    assert!(
        tools["result"]["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .all(|t| t["annotations"]["readOnlyHint"] == true)
    );

    let caps = s.tool("capabilities", json!({}));
    assert_eq!(caps["collection"]["mode"], "synthetic");
    assert_eq!(caps["host"]["synthetic_supported"], true);
    if cfg!(not(target_os = "linux")) {
        assert_eq!(caps["host"]["live_supported"], false);
    }

    wait_for_events(&mut s, 500);

    let q = s.tool("query_events", json!({ "kinds": ["open"], "limit": 20 }));
    let events = q["events"].as_array().expect("events");
    assert_eq!(events.len(), 20);
    for e in events {
        assert_eq!(e["kind"], "open");
        let p = e["path"].as_str().expect("paths enabled");
        assert!(
            !p.contains("alice") && !p.contains(".ssh") && !p.contains(".env"),
            "unredacted path {p}"
        );
    }

    // Paging forward from the first returned seq yields strictly increasing seqs.
    let first = events[0]["seq"].as_u64().expect("seq");
    let page = s.tool("query_events", json!({ "after_seq": first, "limit": 5 }));
    let seqs: Vec<u64> = page["events"]
        .as_array()
        .expect("e")
        .iter()
        .map(|e| e["seq"].as_u64().expect("seq"))
        .collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]) && seqs[0] > first);

    let sum = s.tool(
        "summarize_events",
        json!({ "kinds": ["exec", "open"], "top_n": 3 }),
    );
    assert!(sum["total"].as_u64().expect("total") > 0);
    assert!(sum["by_kind"].get("exit").is_none());
    assert!(sum["top_comms"].as_array().expect("top").len() <= 3);

    let stats = s.tool("stats", json!({}));
    assert!(stats["redacted"].as_u64().expect("redacted") > 0);

    // Bad arguments are tool errors, unknown tools are protocol errors.
    let bad = s.request(
        "tools/call",
        json!({ "name": "query_events", "arguments": { "limit": 0 } }),
    );
    assert_eq!(bad["result"]["isError"], true);
    let unknown = s.request(
        "tools/call",
        json!({ "name": "write_kernel_memory", "arguments": {} }),
    );
    assert_eq!(unknown["error"]["code"], -32602);

    // A malformed line gets a parse error and the session continues.
    s.stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"{oops\n")
        .expect("write");
    assert_eq!(s.read()["error"]["code"], -32700);
    assert_eq!(s.request("ping", json!({}))["result"], json!({}));

    // EOF on stdin is a graceful shutdown.
    drop(s.stdin.take());
    assert!(s.wait_exit().success());
}

#[test]
fn paths_absent_by_default() {
    let mut s = Session::start(&["--seed", "7", "--rate", "5000", "--open"]);
    initialize(&mut s);
    wait_for_events(&mut s, 200);
    let q = s.tool("query_events", json!({ "limit": 200 }));
    assert!(
        q["events"]
            .as_array()
            .expect("events")
            .iter()
            .all(|e| e.get("path").is_none())
    );
    drop(s.stdin.take());
    assert!(s.wait_exit().success());
}

#[test]
fn oversized_message_is_rejected_without_killing_the_session() {
    let mut s = Session::start(&["--rate", "100"]);
    initialize(&mut s);
    let huge = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\",\"pad\":\"{}\"}}\n",
        "x".repeat(2 << 20)
    );
    s.stdin
        .as_mut()
        .expect("stdin")
        .write_all(huge.as_bytes())
        .expect("write");
    assert_eq!(s.read()["error"]["code"], -32600);
    assert_eq!(s.request("ping", json!({}))["result"], json!({}));
    drop(s.stdin.take());
    assert!(s.wait_exit().success());
}

#[cfg(unix)]
#[test]
fn signals_shut_down_gracefully() {
    for signal in ["-INT", "-TERM"] {
        let mut s = Session::start(&["--rate", "100"]);
        initialize(&mut s);
        let pid = s.child.id().to_string();
        let killed = Command::new("kill")
            .args([signal, &pid])
            .status()
            .expect("kill");
        assert!(killed.success());
        // stdin is still open: exit must come from the signal path, with status 0.
        assert!(s.wait_exit().success(), "{signal}");
    }
}

#[test]
fn dump_is_deterministic_for_a_seed() {
    let run = || {
        let out = Command::new(BIN)
            .args(["--seed", "99", "--rate", "20000", "--open", "--dump", "100"])
            .output()
            .expect("run");
        assert!(out.status.success());
        String::from_utf8(out.stdout)
            .expect("utf8")
            .lines()
            .map(|l| {
                let v: Value = serde_json::from_str(l).expect("json");
                (
                    v["seq"].clone(),
                    v["ts_ns"].clone(),
                    v["kind"].clone(),
                    v["pid"].clone(),
                    v["comm"].clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    let a = run();
    assert_eq!(a.len(), 100);
    assert_eq!(a, run());
}

#[test]
fn capabilities_flag_prints_json() {
    let out = Command::new(BIN)
        .arg("--capabilities")
        .output()
        .expect("run");
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["os"], std::env::consts::OS);
}

#[test]
fn live_mode_fails_clearly_off_linux() {
    if cfg!(target_os = "linux") {
        return;
    }
    let out = Command::new(BIN)
        .args(["--mode", "live"])
        .stdin(Stdio::null())
        .output()
        .expect("run");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not Linux"), "{err}");
}

#[test]
fn invalid_config_is_reported() {
    let dir = std::env::temp_dir().join(format!("kt-cfg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("bad.toml");
    std::fs::write(&path, "[limits]\nqueue_capacity = 0\n").expect("write");
    let out = Command::new(BIN)
        .arg("--config")
        .arg(&path)
        .stdin(Stdio::null())
        .output()
        .expect("run");
    std::fs::remove_dir_all(&dir).ok();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("queue_capacity"));
}
