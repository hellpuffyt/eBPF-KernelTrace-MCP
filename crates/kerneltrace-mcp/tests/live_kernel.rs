//! Live-kernel integration test: loads the real eBPF probe, generates known
//! kernel activity and checks it arrives, correctly attributed, over MCP.
//!
//! Requirements (a missing one is a FAILURE when this test is run):
//! - Linux with the BPF ring buffer (≥ 5.8), tracefs, running as root;
//! - `KERNELTRACE_EBPF_OBJECT` = path to the compiled probe;
//! - built with `--features live`.
//!
//! It is ignored by default and run explicitly by CI's `live-kernel` job:
//! `sudo -E <test binary> --ignored --nocapture --test-threads=1`.
//!
//! Two server runs:
//! - **A, default sources** (exec+exit, no open, no paths): a uniquely named
//!   copy of `true` must produce exec and exit events with the right pid and
//!   comm and no path; `kt_open` must not even be loaded.
//! - **B, `open` + `include_paths`**: a uniquely named copy of `cat` reads a
//!   unique file (path must be reported verbatim) and a file whose name
//!   contains `token` (path must be `<redacted>`); exec carries the binary path.
//!
//! - **C, flood with a one-page ring buffer**: a bounded pool of threads runs
//!   2000 short-lived processes (no fork bomb: at most 8 at a time). The
//!   probe must count its ring-full losses (`stats.kernel.ring_full_drops`),
//!   retention and the queue must stay within their limits, and the server's
//!   resident memory must stay bounded.
//!
//! Every run ends with SIGTERM: exit status 0, and the kernel's program list
//! (read with aya's `loaded_programs()`) must show no `kt_*` programs left.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use common::Session;
use serde_json::{Value, json};

const PROGS: [&str; 3] = ["kt_exec", "kt_exit", "kt_open"];

fn require(cond: bool, what: &str) {
    assert!(cond, "live-kernel prerequisite missing: {what}");
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .map(|l| l.split_whitespace().nth(2) == Some("0"))
        })
        .unwrap_or(false)
}

/// Names of loaded BPF programs that belong to this probe, read through the
/// kernel's program-id iterator (`BPF_PROG_GET_NEXT_ID`) via aya, so no
/// external tool is needed. The kernel keeps at most 15 name bytes;
/// `kt_exec`/`kt_exit`/`kt_open` fit.
fn loaded_probe_programs() -> Vec<String> {
    let mut names = Vec::new();
    let mut listed = 0usize;
    let mut errors = Vec::new();
    for info in aya::programs::loaded_programs() {
        listed += 1;
        match info {
            Ok(info) => {
                if let Some(name) = info.name_as_str().filter(|n| PROGS.contains(n)) {
                    names.push(name.to_string());
                }
            }
            // A program can be unloaded between id enumeration and the fd
            // lookup; that race is expected while detaching.
            Err(e) => errors.push(e.to_string()),
        }
    }
    assert!(
        listed == 0 || errors.len() < listed,
        "could not inspect any loaded BPF program: {errors:?}"
    );
    names.sort();
    names
}

fn wait_until_detached() {
    // Program memory is freed asynchronously after the last fd closes.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let left = loaded_probe_programs();
        if left.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "programs still loaded after shutdown: {left:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn unique() -> String {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .subsec_nanos();
    format!("{:06x}", (n ^ std::process::id()) & 0xff_ffff)
}

/// Copies a system binary to `dir/name` so its exec has a unique comm and path.
fn copy_bin(src: &str, dir: &Path, name: &str) -> PathBuf {
    let dst = dir.join(name);
    std::fs::copy(src, &dst).unwrap_or_else(|e| panic!("copy {src}: {e}"));
    dst
}

fn start_server(config: &Path) -> Session {
    let mut s = Session::start_with(
        &["--config", config.to_str().expect("utf8")],
        Stdio::piped(),
    );
    let init = s.request(
        "initialize",
        json!({ "protocolVersion": "2025-11-25", "capabilities": {} }),
    );
    if init.get("result").is_none() {
        panic!("initialize failed: {init}");
    }
    let caps = s.tool("capabilities", json!({}));
    eprintln!("capabilities: {caps}");
    assert_eq!(caps["collection"]["mode"], "live");
    assert_eq!(caps["host"]["live_supported"], true, "{caps}");
    s
}

/// Polls until events for `pid` include every kind in `kinds`. On timeout the
/// panic message carries the pipeline and kernel-side counters, so a missing
/// event can be attributed (never fired, lost to a full ring, or dropped in
/// userspace).
fn events_for(s: &mut Session, pid: u32, kinds: &[&str]) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let r = s.tool("query_events", json!({ "pids": [pid], "limit": 500 }));
        let events = r["events"].as_array().expect("events").clone();
        if kinds.iter().all(|k| events.iter().any(|e| e["kind"] == *k)) {
            return events;
        }
        if Instant::now() >= deadline {
            let stats = s.tool("stats", json!({}));
            panic!("pid {pid}: wanted kinds {kinds:?}, got {events:#?}\nstats: {stats}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn one<'a>(events: &'a [Value], kind: &str) -> &'a Value {
    let v: Vec<&Value> = events.iter().filter(|e| e["kind"] == kind).collect();
    assert_eq!(v.len(), 1, "expected exactly one {kind} event: {events:#?}");
    v[0]
}

fn ts(e: &Value) -> u64 {
    e["ts_ns"].as_u64().expect("ts_ns")
}

/// Polls `stats` until `kernel.<field>` (refreshed every 100 ms) reaches `n`.
fn kernel_counter_at_least(s: &mut Session, field: &str, n: u64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let stats = s.tool("stats", json!({}));
        if stats["kernel"][field].as_u64().unwrap_or(0) >= n {
            return stats;
        }
        assert!(
            Instant::now() < deadline,
            "kernel.{field} stayed below {n}: {stats}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Sends SIGTERM and checks a clean exit, clean stats and full detach.
fn stop(mut s: Session) {
    let stats = s.tool("stats", json!({}));
    eprintln!("stats before shutdown: {stats}");
    assert_eq!(stats["source"], "live");
    assert!(stats["records"].as_u64().expect("records") > 0);
    assert_eq!(
        stats["decode_errors"], 0,
        "kernel and userspace disagree on the record layout"
    );
    assert_eq!(stats["source_errors"], 0);
    assert!(stats["last_source_error"].is_null());
    // Drops are allowed under load but must be accounted, never negative/missing.
    assert!(stats["queue_dropped_newest"].is_u64() && stats["queue_dropped_oldest"].is_u64());
    let k = &stats["kernel"];
    for field in [
        "ring_full_drops",
        "path_unreadable",
        "fired_exec",
        "fired_exit",
        "fired_open",
    ] {
        assert!(k[field].is_u64(), "kernel counter {field} missing: {stats}");
    }

    let pid = s.child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .expect("kill")
            .success()
    );
    let mut stderr = s.child.stderr.take().expect("stderr");
    let status = s.wait_exit();
    let mut log = String::new();
    stderr.read_to_string(&mut log).expect("stderr");
    eprintln!("server stderr:\n{log}");
    assert!(status.success(), "exit status {status}");
    assert!(log.contains("shutting down (signal)"), "{log}");
    wait_until_detached();
}

#[test]
#[ignore = "needs Linux + root + BTF; run by CI's live-kernel job"]
fn live_probe_reports_known_activity() {
    require(is_root(), "must run as root (sudo -E)");
    let object = std::env::var("KERNELTRACE_EBPF_OBJECT").unwrap_or_default();
    require(
        Path::new(&object).is_file(),
        "KERNELTRACE_EBPF_OBJECT must point to the compiled probe",
    );
    eprintln!(
        "kernel: {}",
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
    );
    // A previous (crashed) run's programs are freed asynchronously.
    wait_until_detached();

    let id = unique();
    let dir = std::env::temp_dir().join(format!("kt-live-{id}"));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let _cleanup = Scratch(dir.clone());

    // ---- Run A: default sources (exec + exit), no paths ----
    let cfg_a = dir.join("a.toml");
    std::fs::write(
        &cfg_a,
        format!("mode = \"live\"\n[live]\nebpf_object = {object:?}\n"),
    )
    .expect("write");
    let mut s = start_server(&cfg_a);
    assert_eq!(
        loaded_probe_programs(),
        ["kt_exec", "kt_exit"],
        "kt_open must not load when open is off"
    );

    let true_name = format!("kttrue{id}");
    let true_bin = copy_bin("/bin/true", &dir, &true_name);
    let child = Command::new(&true_bin).spawn().expect("spawn true copy");
    let pid = child.id();
    let out = child.wait_with_output().expect("wait");
    assert!(out.status.success());

    let ev = events_for(&mut s, pid, &["exec", "exit"]);
    let (exec, exit) = (one(&ev, "exec"), one(&ev, "exit"));
    for e in [exec, exit] {
        assert_eq!(e["pid"], pid);
        assert_eq!(e["tid"], pid);
        assert_eq!(e["uid"], 0, "spawned by root");
        assert_eq!(e["comm"], true_name.as_str());
        assert!(
            e.get("path").is_none(),
            "paths must be absent by default: {e}"
        );
        assert!(ts(e) > 0);
    }
    assert!(ts(exec) < ts(exit), "exec before exit");
    assert!(exec["seq"].as_u64() < exit["seq"].as_u64());
    assert!(
        !ev.iter().any(|e| e["kind"] == "open"),
        "open events must be off by default"
    );
    let all = s.tool("query_events", json!({ "limit": 500 }));
    assert!(
        all["events"]
            .as_array()
            .expect("e")
            .iter()
            .all(|e| e.get("path").is_none()),
        "no event may carry a path"
    );
    let summary = s.tool("summarize_events", json!({}));
    assert!(summary["by_kind"].get("open").is_none(), "{summary}");
    let stats = kernel_counter_at_least(&mut s, "fired_exec", 1);
    assert_eq!(
        stats["kernel"]["fired_open"], 0,
        "kt_open not loaded: {stats}"
    );
    assert!(summary["by_kind"]["exec"].as_u64().expect("exec") >= 1);
    stop(s);

    // ---- Run B: open + include_paths, with redaction ----
    let cfg_b = dir.join("b.toml");
    std::fs::write(
        &cfg_b,
        format!(
            "mode = \"live\"\n[limits]\nmax_events = 200000\n[sources]\nopen = true\ninclude_paths = true\n[live]\nebpf_object = {object:?}\n"
        ),
    )
    .expect("write");
    let mut s = start_server(&cfg_b);
    assert_eq!(loaded_probe_programs(), PROGS);
    // kt_open must actually run, not just be attached: open a file ourselves
    // and wait for the probe's own invocation counter to move.
    let probe_file = dir.join(format!("probe-{id}.txt"));
    std::fs::write(&probe_file, "x").expect("write");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let _ = std::fs::read(&probe_file).expect("read");
        let stats = s.tool("stats", json!({}));
        if stats["kernel"]["fired_open"].as_u64().unwrap_or(0) > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "kt_open is attached but the kernel never ran it: {stats}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let cat_name = format!("ktcat{id}");
    let cat_bin = copy_bin("/bin/cat", &dir, &cat_name);
    let plain = dir.join(format!("plain-{id}.txt"));
    let secret = dir.join(format!("api-token-{id}.txt"));
    std::fs::write(&plain, "x").expect("write");
    std::fs::write(&secret, "x").expect("write");

    let run_cat = |file: &Path| {
        let child = Command::new(&cat_bin)
            .arg(file)
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn cat copy");
        let pid = child.id();
        assert!(child.wait_with_output().expect("wait").status.success());
        pid
    };
    let plain_pid = run_cat(&plain);
    let secret_pid = run_cat(&secret);

    let ev = events_for(&mut s, plain_pid, &["exec", "open", "exit"]);
    let exec = one(&ev, "exec");
    assert_eq!(exec["comm"], cat_name.as_str());
    assert_eq!(
        exec["path"],
        cat_bin.to_str().expect("utf8"),
        "exec carries the executed path"
    );
    let plain_s = plain.to_str().expect("utf8");
    let opens: Vec<&Value> = ev
        .iter()
        .filter(|e| e["kind"] == "open" && e["path"] == plain_s)
        .collect();
    assert_eq!(
        opens.len(),
        1,
        "exactly one openat of the unique file by pid {plain_pid}: {ev:#?}"
    );
    let open = opens[0];
    assert_eq!(open["comm"], cat_name.as_str());
    let exit = one(&ev, "exit");
    assert!(
        ts(exec) < ts(open) && ts(open) < ts(exit),
        "exec < open < exit: {ev:#?}"
    );

    let ev = events_for(&mut s, secret_pid, &["exec", "open", "exit"]);
    assert!(
        ev.iter()
            .any(|e| e["kind"] == "open" && e["path"] == "<redacted>"),
        "the token file's path must be redacted: {ev:#?}"
    );
    let leaked = s.tool(
        "query_events",
        json!({ "limit": 500, "path_prefix": dir.to_str().expect("utf8") }),
    );
    for e in leaked["events"].as_array().expect("e") {
        assert!(
            !e["path"].as_str().unwrap_or("").contains("token"),
            "unredacted secret path: {e}"
        );
    }
    let summary = s.tool(
        "summarize_events",
        json!({ "pids": [plain_pid, secret_pid] }),
    );
    assert!(
        summary["by_kind"]["open"].as_u64().expect("open") >= 2,
        "{summary}"
    );
    assert_eq!(summary["by_kind"]["exec"], 2, "{summary}");
    assert_eq!(summary["by_kind"]["exit"], 2, "{summary}");
    stop(s);

    // ---- Run C: flood with a one-page ring buffer ----
    let page = page_size();
    let cfg_c = dir.join("c.toml");
    std::fs::write(
        &cfg_c,
        format!(
            "mode = \"live\"\n[limits]\nmax_events = 1000\nqueue_capacity = 64\n[sources]\nopen = true\n[live]\nebpf_object = {object:?}\nring_buffer_bytes = {page}\n"
        ),
    )
    .expect("write");
    let mut s = start_server(&cfg_c);
    let rss_before = rss_kib(s.child.id());
    const PROCS: usize = 2000;
    const WORKERS: usize = 8;
    let flood_start = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..WORKERS {
            scope.spawn(|| {
                for _ in 0..PROCS / WORKERS {
                    let st = Command::new("/bin/true").status().expect("spawn true");
                    assert!(st.success());
                }
            });
        }
    });
    let flood_secs = flood_start.elapsed().as_secs_f64();
    // Let the reader drain and the kernel counters refresh (every 100 ms).
    let deadline = Instant::now() + Duration::from_secs(10);
    let stats = loop {
        let stats = s.tool("stats", json!({}));
        let fired_exec = stats["kernel"]["fired_exec"].as_u64().unwrap_or(0);
        if fired_exec >= PROCS as u64 && stats["queue_len"] == 0 {
            break stats;
        }
        assert!(
            Instant::now() < deadline,
            "flood: kernel saw fewer than {PROCS} execs: {stats}"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    let rss_after = rss_kib(s.child.id());
    eprintln!(
        "flood: {PROCS} processes in {flood_secs:.2}s, ring {page} B, rss {rss_before} -> {rss_after} KiB, stats {stats}"
    );
    let k = &stats["kernel"];
    let drops = k["ring_full_drops"].as_u64().expect("drops");
    assert!(
        drops > 0,
        "a one-page ring must overflow under this flood: {stats}"
    );
    assert!(stats["stored"].as_u64().expect("stored") <= 1000, "{stats}");
    assert!(stats["queue_capacity"] == 64, "{stats}");
    let fired = k["fired_exec"].as_u64().unwrap()
        + k["fired_exit"].as_u64().unwrap()
        + k["fired_open"].as_u64().unwrap();
    // Each attempted event was either delivered or counted as a kernel drop.
    // (Other processes keep producing events, so on a busy host this is only
    // approximately equal between two counter refreshes; on a quiet VM it is
    // exact.)
    assert!(drops < fired, "{stats}");
    // Everything read from the ring is accounted for downstream.
    let records = stats["records"].as_u64().expect("records");
    let accounted = stats["decode_errors"].as_u64().unwrap()
        + stats["disabled_kind"].as_u64().unwrap()
        + stats["sampled_out"].as_u64().unwrap()
        + stats["queue_dropped_newest"].as_u64().unwrap()
        + stats["queue_dropped_oldest"].as_u64().unwrap()
        + stats["last_seq"].as_u64().unwrap();
    assert_eq!(
        records, accounted,
        "every record is stored or counted: {stats}"
    );
    assert!(
        rss_after < rss_before + 32 * 1024,
        "server memory grew from {rss_before} to {rss_after} KiB"
    );
    stop(s);
}

fn page_size() -> u64 {
    let out = Command::new("getconf")
        .arg("PAGESIZE")
        .output()
        .expect("getconf");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("page size")
}

fn rss_kib(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .expect("status")
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
        .expect("VmRSS")
}

/// DIAGNOSTIC (diag/live-intermittent branch only): measures, without
/// asserting, which `cat` runs get their open events delivered, as a function
/// of time since the probe attached. Prints one `DIAG` JSON line.
#[test]
#[ignore = "diagnostic"]
fn diag_open_delivery() {
    let object = std::env::var("KERNELTRACE_EBPF_OBJECT").unwrap_or_default();
    let id = unique();
    let dir = std::env::temp_dir().join(format!("kt-diag-{id}"));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let _cleanup = Scratch(dir.clone());
    let cat_bin = copy_bin("/bin/cat", &dir, &format!("ktdcat{id}"));
    let files: Vec<PathBuf> = (0..30)
        .map(|i| {
            let p = dir.join(format!("f{i}-{id}.txt"));
            std::fs::write(&p, "x").expect("write");
            p
        })
        .collect();
    let cfg = dir.join("d.toml");
    std::fs::write(
        &cfg,
        format!(
            "mode = \"live\"\n[limits]\nmax_events = 200000\n[sources]\nopen = true\ninclude_paths = true\n[live]\nebpf_object = {object:?}\n"
        ),
    )
    .expect("write");
    let mut s = start_server(&cfg);
    let t0 = Instant::now();
    let stats0 = s.tool("stats", json!({}));
    let mut runs = Vec::new();
    let pin = std::env::var("DIAG_PIN").is_ok();
    let ncpu = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    for (i, f) in files.iter().enumerate() {
        let t = t0.elapsed().as_millis() as u64;
        let cpu = i % ncpu;
        let child = if pin {
            // taskset execs the cat copy on the given CPU (same pid).
            Command::new("taskset")
                .arg("-c")
                .arg(cpu.to_string())
                .arg(&cat_bin)
                .arg(f)
                .stdout(Stdio::null())
                .spawn()
                .expect("spawn")
        } else {
            Command::new(&cat_bin)
                .arg(f)
                .stdout(Stdio::null())
                .spawn()
                .expect("spawn")
        };
        let pid = child.id();
        child.wait_with_output().expect("wait");
        runs.push((t, pid, f.clone(), cpu));
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(1500));
    let stats = s.tool("stats", json!({}));
    let mut rows = Vec::new();
    let mut missing = 0;
    let mut missing_by_cpu = vec![0u32; ncpu];
    let mut runs_by_cpu = vec![0u32; ncpu];
    for (t, pid, f, cpu) in &runs {
        runs_by_cpu[*cpu] += 1;
        let r = s.tool("query_events", json!({ "pids": [pid], "limit": 500 }));
        let ev = r["events"].as_array().expect("events");
        let has = |k: &str| ev.iter().any(|e| e["kind"] == k);
        let opens = ev.iter().filter(|e| e["kind"] == "open").count();
        let target = ev
            .iter()
            .any(|e| e["kind"] == "open" && e["path"] == f.to_str().unwrap());
        if !target {
            missing += 1;
            missing_by_cpu[*cpu] += 1;
        }
        rows.push(json!({"cpu": if pin { json!(cpu) } else { Value::Null }, "t_ms": t, "exec": has("exec"), "opens": opens, "target": target, "exit": has("exit")}));
    }
    let all = s.tool("query_events", json!({ "limit": 500, "kinds": ["open"] }));
    let n_open_all = all["events"].as_array().map(|a| a.len()).unwrap_or(0);
    eprintln!(
        "DIAG {}",
        json!({"kernel": std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim(),
               "ftrace": std::env::var("DIAG_FTRACE").unwrap_or_default(),
               "missing_target": missing, "runs": runs.len(), "open_events_stored": n_open_all,
               "stats0": stats0["kernel"], "stats": stats, "rows": rows})
    );
    eprintln!("DIAG_SUMMARY missing_target={missing}/{}", runs.len());
    if pin {
        eprintln!("DIAG_PIN missing_by_cpu={missing_by_cpu:?} runs_by_cpu={runs_by_cpu:?}");
    }
    let pid = s.child.id().to_string();
    let _ = Command::new("kill").args(["-TERM", &pid]).status();
    let _ = s.wait_exit();
    wait_until_detached();
}
