//! Owned, decoded events.

use std::fmt;
use std::str::FromStr;

use kerneltrace_common::{KIND_EXEC, KIND_EXIT, KIND_OPEN};
use serde::{Deserialize, Serialize};

/// The kinds of kernel events kerneltrace understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    /// Successful `execve`/`execveat` (`sched:sched_process_exec`).
    Exec,
    /// Task exit (`sched:sched_process_exit`).
    Exit,
    /// Entry to `openat(2)` (`syscalls:sys_enter_openat`).
    Open,
}

impl EventKind {
    /// All kinds, in wire order.
    pub const ALL: [EventKind; 3] = [EventKind::Exec, EventKind::Exit, EventKind::Open];

    /// Maps a wire value to a kind.
    pub fn from_wire(value: u32) -> Option<Self> {
        match value {
            KIND_EXEC => Some(Self::Exec),
            KIND_EXIT => Some(Self::Exit),
            KIND_OPEN => Some(Self::Open),
            _ => None,
        }
    }

    /// The wire value for this kind.
    pub fn to_wire(self) -> u32 {
        match self {
            Self::Exec => KIND_EXEC,
            Self::Exit => KIND_EXIT,
            Self::Open => KIND_OPEN,
        }
    }

    /// Lower-case name used in JSON and on the command line.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::Exit => "exit",
            Self::Open => "open",
        }
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EventKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "exec" => Ok(Self::Exec),
            "exit" => Ok(Self::Exit),
            "open" => Ok(Self::Open),
            other => Err(format!(
                "unknown event kind {other:?} (expected exec, exit or open)"
            )),
        }
    }
}

/// A decoded event owned by userspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Event {
    /// Monotonic sequence number assigned when the event is stored (starts at 1).
    pub seq: u64,
    /// Source timestamp in nanoseconds (CLOCK_MONOTONIC for live events,
    /// a deterministic virtual clock for synthetic events).
    pub ts_ns: u64,
    /// Nanoseconds since the engine started when userspace received the event.
    pub received_ns: u64,
    /// Event kind.
    pub kind: EventKind,
    /// Process id.
    pub pid: u32,
    /// Thread id.
    pub tid: u32,
    /// Real user id.
    pub uid: u32,
    /// Task command name (sanitised, at most 15 characters).
    pub comm: String,
    /// Path, if the kind carries one and path collection is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Kind-specific value: `openat` flags for `open` events, 0 otherwise.
    pub ret: i64,
}
