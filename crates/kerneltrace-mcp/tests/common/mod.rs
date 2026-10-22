//! MCP stdio client used by the end-to-end tests.

#![allow(dead_code, clippy::expect_used, clippy::unwrap_used)] // each test crate uses a subset

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// The server binary under test.
pub const BIN: &str = env!("CARGO_BIN_EXE_kerneltrace-mcp");

pub struct Session {
    pub child: Child,
    pub stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Session {
    /// Starts the server with stderr discarded.
    pub fn start(args: &[&str]) -> Self {
        Self::start_with(args, Stdio::null())
    }

    /// Starts the server with the given stderr handling.
    pub fn start_with(args: &[&str], stderr: Stdio) -> Self {
        let mut child = Command::new(BIN)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
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

    pub fn send(&mut self, v: &Value) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        writeln!(stdin, "{v}").expect("write");
        stdin.flush().expect("flush");
    }

    pub fn read(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad response {line:?}: {e}"))
    }

    pub fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        let r = self.read();
        assert_eq!(r["id"], id, "response id matches request");
        r
    }

    pub fn tool(&mut self, name: &str, args: Value) -> Value {
        let r = self.request("tools/call", json!({ "name": name, "arguments": args }));
        assert_eq!(r["result"]["isError"], false, "{r}");
        r["result"]["structuredContent"].clone()
    }

    pub fn wait_exit(mut self) -> std::process::ExitStatus {
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
