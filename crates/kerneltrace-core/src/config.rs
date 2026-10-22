//! Configuration (TOML).

use std::path::Path;

use serde::Deserialize;

use crate::error::ConfigError;
use crate::event::EventKind;
use crate::queue::OverflowPolicy;
use crate::redact::RedactionConfig;

/// Where events come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Deterministic generated events; no privileges required.
    #[default]
    Synthetic,
    /// Kernel events via the eBPF probe (Linux, `live` feature, privileges).
    Live,
}

/// `[limits]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Capacity of the queue between the source reader and the store.
    pub queue_capacity: usize,
    /// What to drop when that queue is full.
    pub overflow: OverflowPolicy,
    /// Keep 1 in N events (1 = keep all).
    pub sample_every: u64,
    /// Maximum events retained.
    pub max_events: usize,
    /// Maximum age of retained events in seconds (0 = no age limit).
    pub max_age_secs: u64,
    /// Hard cap on events returned by one query.
    pub max_query_limit: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            queue_capacity: 4096,
            overflow: OverflowPolicy::DropOldest,
            sample_every: 1,
            max_events: 10_000,
            max_age_secs: 600,
            max_query_limit: 500,
        }
    }
}

/// `[sources]` table: which event kinds are collected.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Sources {
    /// Collect exec events.
    pub exec: bool,
    /// Collect exit events.
    pub exit: bool,
    /// Collect `openat` events. Off by default: high volume and reveals file activity.
    pub open: bool,
    /// Keep file paths (exec filenames, opened paths). **Sensitive**; off by
    /// default. Redaction rules still apply when enabled.
    pub include_paths: bool,
}

impl Default for Sources {
    fn default() -> Self {
        Self {
            exec: true,
            exit: true,
            open: false,
            include_paths: false,
        }
    }
}

impl Sources {
    /// Whether `kind` is collected.
    pub fn enabled(&self, kind: EventKind) -> bool {
        match kind {
            EventKind::Exec => self.exec,
            EventKind::Exit => self.exit,
            EventKind::Open => self.open,
        }
    }
}

/// `[synthetic]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SyntheticConfig {
    /// PRNG seed.
    pub seed: u64,
    /// Events generated per second of wall time (0 = as fast as possible).
    pub rate_per_sec: u64,
    /// Make every Nth record malformed (0 = never).
    pub malformed_every: u64,
}

impl Default for SyntheticConfig {
    fn default() -> Self {
        Self {
            seed: 42,
            rate_per_sec: 200,
            malformed_every: 0,
        }
    }
}

/// `[live]` table.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LiveConfig {
    /// Path to the compiled eBPF object (`kerneltrace-ebpf`).
    pub ebpf_object: Option<String>,
}

/// Top-level configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Event source.
    pub mode: Mode,
    /// Resource limits.
    pub limits: Limits,
    /// Enabled event kinds and sensitive fields.
    pub sources: Sources,
    /// Redaction rules.
    pub redaction: RedactionConfig,
    /// Synthetic source settings.
    pub synthetic: SyntheticConfig,
    /// Live source settings.
    pub live: LiveConfig,
}

impl Config {
    /// Parses and validates TOML text.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Reads, parses and validates a file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_toml(&text)
    }

    /// Checks value ranges.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let l = &self.limits;
        let check = |ok: bool, msg: &str| {
            if ok {
                Ok(())
            } else {
                Err(ConfigError::Invalid(msg.to_string()))
            }
        };
        check(
            (1..=1_000_000).contains(&l.queue_capacity),
            "limits.queue_capacity must be 1..=1000000",
        )?;
        check(
            (1..=10_000_000).contains(&l.max_events),
            "limits.max_events must be 1..=10000000",
        )?;
        check(
            (1..=1_000_000).contains(&l.sample_every),
            "limits.sample_every must be 1..=1000000",
        )?;
        check(
            (1..=10_000).contains(&l.max_query_limit),
            "limits.max_query_limit must be 1..=10000",
        )?;
        check(
            self.synthetic.rate_per_sec <= 10_000_000,
            "synthetic.rate_per_sec must be <= 10000000",
        )?;
        check(
            self.sources.exec || self.sources.exit || self.sources.open,
            "at least one of sources.exec, sources.exit, sources.open must be enabled",
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let c = Config::from_toml("").expect("empty config is valid");
        assert_eq!(c.mode, Mode::Synthetic);
        assert!(!c.sources.open);
        assert!(!c.sources.include_paths);
        assert_eq!(c.limits.overflow, OverflowPolicy::DropOldest);
    }

    #[test]
    fn parses_full_example() {
        let text = include_str!("../../../examples/kerneltrace.toml");
        let c = Config::from_toml(text).expect("example config parses");
        assert_eq!(c.synthetic.seed, 42);
    }

    #[test]
    fn rejects_unknown_keys_and_bad_ranges() {
        assert!(matches!(
            Config::from_toml("bogus = 1"),
            Err(ConfigError::Parse(_))
        ));
        assert!(matches!(
            Config::from_toml("[limits]\nqueue_capacity = 0"),
            Err(ConfigError::Invalid(_))
        ));
        assert!(matches!(
            Config::from_toml("[sources]\nexec = false\nexit = false"),
            Err(ConfigError::Invalid(_))
        ));
        assert!(matches!(
            Config::from_toml("[limits]\noverflow = \"block\""),
            Err(ConfigError::Parse(_))
        ));
    }
}
