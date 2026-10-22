//! A deterministic, unprivileged event source.
//!
//! Emits a plausible mix of exec/open/exit records encoded exactly as the
//! probe would write them, so the full decode → sample → redact → store path
//! runs without a Linux kernel. The same seed always produces the same stream.

use crate::decode::{encode, raw_event};
use crate::error::SourceError;
use crate::event::EventKind;
use crate::rng::SplitMix64;
use crate::source::Source;

const COMMS: [&str; 8] = [
    "bash", "sshd", "nginx", "postgres", "cargo", "python3", "systemd", "cron",
];
const PATHS: [&str; 10] = [
    "/etc/hosts",
    "/etc/passwd",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/var/log/syslog",
    "/tmp/build.lock",
    "/proc/self/status",
    "/home/alice/project/src/main.rs",
    "/home/alice/.ssh/id_ed25519",
    "/srv/app/.env",
    "/var/lib/postgresql/16/main/base/1/1259",
];

/// `openat` flags as on Linux x86_64/aarch64: O_RDONLY, O_RDONLY|O_CLOEXEC,
/// O_WRONLY|O_CREAT|O_TRUNC.
const OPEN_FLAGS: [i64; 3] = [0, 0o2_000_000, 0o1101];

#[derive(Debug, Clone)]
struct Proc {
    pid: u32,
    uid: u32,
    comm: &'static str,
}

/// Seeded synthetic source.
#[derive(Debug, Clone)]
pub struct SyntheticSource {
    rng: SplitMix64,
    procs: Vec<Proc>,
    next_pid: u32,
    ts_ns: u64,
    step_ns: u64,
    emitted: u64,
    malformed_every: u64,
}

impl SyntheticSource {
    /// Creates a source. `step_ns` is the virtual time between events
    /// (minimum 1). `malformed_every > 0` makes every Nth record truncated,
    /// to exercise decode-error handling.
    pub fn new(seed: u64, step_ns: u64, malformed_every: u64) -> Self {
        let mut s = Self {
            rng: SplitMix64::new(seed),
            procs: Vec::new(),
            next_pid: 1000,
            ts_ns: 0,
            step_ns: step_ns.max(1),
            emitted: 0,
            malformed_every,
        };
        for _ in 0..4 {
            s.spawn();
        }
        s
    }

    fn spawn(&mut self) -> Proc {
        let comm = COMMS[self.rng.below(COMMS.len() as u64) as usize];
        let uid = if self.rng.below(4) == 0 { 0 } else { 1000 };
        let p = Proc {
            pid: self.next_pid,
            uid,
            comm,
        };
        self.next_pid += 1;
        self.procs.push(p.clone());
        p
    }

    /// Produces the next record's bytes.
    pub fn next_record(&mut self) -> Vec<u8> {
        self.emitted += 1;
        self.ts_ns += self.step_ns;
        let roll = self.rng.below(100);
        let raw = if roll < 15 || self.procs.is_empty() {
            let p = self.spawn();
            let path = format!("/usr/bin/{}", p.comm);
            raw_event(
                EventKind::Exec,
                self.ts_ns,
                p.pid,
                p.pid,
                p.uid,
                p.comm,
                Some(&path),
            )
        } else if roll < 28 && self.procs.len() > 1 {
            let i = self.rng.below(self.procs.len() as u64) as usize;
            let p = self.procs.swap_remove(i);
            raw_event(
                EventKind::Exit,
                self.ts_ns,
                p.pid,
                p.pid,
                p.uid,
                p.comm,
                None,
            )
        } else {
            let path = PATHS[self.rng.below(PATHS.len() as u64) as usize];
            let flags = OPEN_FLAGS[self.rng.below(OPEN_FLAGS.len() as u64) as usize];
            let p = &self.procs[self.rng.below(self.procs.len() as u64) as usize];
            let mut raw = raw_event(
                EventKind::Open,
                self.ts_ns,
                p.pid,
                p.pid,
                p.uid,
                p.comm,
                Some(path),
            );
            raw.ret = flags;
            raw
        };
        let mut bytes = encode(&raw).to_vec();
        if self.malformed_every > 0 && self.emitted.is_multiple_of(self.malformed_every) {
            bytes.truncate(bytes.len() / 2);
        }
        bytes
    }
}

impl Source for SyntheticSource {
    fn name(&self) -> &'static str {
        "synthetic"
    }

    fn poll(&mut self, max: usize, sink: &mut dyn FnMut(&[u8])) -> Result<usize, SourceError> {
        for _ in 0..max {
            let rec = self.next_record();
            sink(&rec);
        }
        Ok(max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::decode;

    fn collect(seed: u64, n: usize) -> Vec<Vec<u8>> {
        let mut s = SyntheticSource::new(seed, 1000, 0);
        let mut out = Vec::new();
        s.poll(n, &mut |b| out.push(b.to_vec())).expect("poll");
        out
    }

    #[test]
    fn same_seed_same_stream() {
        assert_eq!(collect(7, 500), collect(7, 500));
        assert_ne!(collect(7, 500), collect(8, 500));
    }

    #[test]
    fn records_decode_and_cover_all_kinds() {
        let mut kinds = std::collections::BTreeSet::new();
        let mut last_ts = 0;
        for rec in collect(1, 2000) {
            let e = decode(&rec).expect("valid");
            assert!(e.ts_ns > last_ts, "timestamps strictly increase");
            last_ts = e.ts_ns;
            kinds.insert(e.kind);
        }
        assert_eq!(kinds.len(), 3);
    }

    #[test]
    fn malformed_records_are_injected() {
        let mut s = SyntheticSource::new(1, 1, 10);
        let mut bad = 0;
        s.poll(100, &mut |b| bad += usize::from(decode(b).is_err()))
            .expect("poll");
        assert_eq!(bad, 10);
    }
}
