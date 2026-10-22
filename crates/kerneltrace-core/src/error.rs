//! Error types.

use kerneltrace_common::PATH_LEN;

/// A raw ring-buffer record could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The record does not have the exact size of a `RawEvent`.
    #[error("record is {actual} bytes, expected exactly {expected}")]
    Length {
        /// Bytes received.
        actual: usize,
        /// Bytes required.
        expected: usize,
    },
    /// The `kind` field holds an unknown value.
    #[error("unknown event kind {0}")]
    UnknownKind(u32),
    /// `path_len` points past the end of the path field.
    #[error("path_len {0} exceeds the {PATH_LEN}-byte path field")]
    PathLen(u32),
}

/// The configuration file could not be loaded or is invalid.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Reading the file failed.
    #[error("cannot read config file {path}: {source}")]
    Io {
        /// Path that was read.
        path: String,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The file is not valid TOML for this schema.
    #[error("invalid config: {0}")]
    Parse(#[from] toml::de::Error),
    /// A value is out of its allowed range.
    #[error("invalid config value: {0}")]
    Invalid(String),
}

/// An event source failed.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// The source cannot run on this host. The message says why.
    #[error("event source unsupported: {0}")]
    Unsupported(String),
    /// Loading or attaching the source failed.
    #[error("event source failed to start: {0}")]
    Start(String),
    /// Reading from the source failed.
    #[error("event source read failed: {0}")]
    Read(String),
}
