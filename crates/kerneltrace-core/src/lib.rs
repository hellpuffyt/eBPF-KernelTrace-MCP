//! Userspace core of kerneltrace: decoding, buffering, filtering, sampling,
//! retention, redaction and capability detection for kernel events.
//!
//! Everything here is portable and testable without privileges. Kernel access
//! lives behind the Linux-only `live` feature (see [`live`]).

#![forbid(unsafe_code)]

pub mod capability;
pub mod config;
pub mod decode;
pub mod engine;
pub mod error;
pub mod event;
pub mod filter;
pub mod live;
pub mod queue;
pub mod redact;
pub mod rng;
pub mod sample;
pub mod source;
pub mod store;
pub mod summary;
pub mod synthetic;

pub use config::{Config, Mode};
pub use engine::{Engine, Pacing, StatsSnapshot};
pub use error::{ConfigError, DecodeError, SourceError};
pub use event::{Event, EventKind};
pub use filter::Filter;
pub use source::Source;
pub use synthetic::SyntheticSource;
