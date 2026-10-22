//! Redaction of sensitive event fields.
//!
//! Paths can reveal user names, project names and secrets, so they are
//! dropped entirely unless `include_paths` is enabled. When paths are
//! enabled, two kinds of rules apply, in this order:
//!
//! 1. **Substring rules** (case-insensitive): any path containing one of these
//!    strings is replaced entirely by `<redacted>`.
//! 2. **Prefix rules**: a path under one of these directories keeps the
//!    prefix and the rest becomes `<redacted>` — e.g. with prefix `/home`,
//!    `/home/alice/notes.txt` becomes `/home/<redacted>`. Prefixes only match
//!    whole path components (`/home` does not match `/homework`).

use serde::Deserialize;

use crate::event::Event;

/// Marker that replaces redacted content.
pub const REDACTED: &str = "<redacted>";

/// Redaction settings (the `[redaction]` config table).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RedactionConfig {
    /// Directory prefixes whose contents are hidden.
    pub path_prefixes: Vec<String>,
    /// Case-insensitive substrings that hide the whole path.
    pub substrings: Vec<String>,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            path_prefixes: vec!["/home".into(), "/root".into(), "/Users".into()],
            substrings: [
                ".ssh",
                ".gnupg",
                ".aws",
                ".env",
                "secret",
                "token",
                "password",
                "credential",
                "id_rsa",
                "id_ed25519",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        }
    }
}

/// Applies redaction rules to events.
#[derive(Debug, Clone)]
pub struct Redactor {
    include_paths: bool,
    prefixes: Vec<String>,
    substrings: Vec<String>,
}

impl Redactor {
    /// Builds a redactor. With `include_paths == false` every path is removed.
    pub fn new(include_paths: bool, config: &RedactionConfig) -> Self {
        Self {
            include_paths,
            prefixes: config
                .path_prefixes
                .iter()
                .map(|p| p.trim_end_matches('/').to_string())
                .filter(|p| !p.is_empty())
                .collect(),
            substrings: config
                .substrings
                .iter()
                .map(|s| s.to_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }

    /// Redacts `event` in place. Returns true if anything was changed.
    pub fn apply(&self, event: &mut Event) -> bool {
        let Some(path) = event.path.as_deref() else {
            return false;
        };
        if !self.include_paths {
            event.path = None;
            return true;
        }
        let lower = path.to_lowercase();
        if self.substrings.iter().any(|s| lower.contains(s.as_str())) {
            event.path = Some(REDACTED.to_string());
            return true;
        }
        for prefix in &self.prefixes {
            if let Some(rest) = path.strip_prefix(prefix.as_str())
                && rest.starts_with('/')
                && rest.len() > 1
            {
                event.path = Some(format!("{prefix}/{REDACTED}"));
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventKind;

    fn with_path(p: &str) -> Event {
        Event {
            seq: 0,
            ts_ns: 0,
            received_ns: 0,
            kind: EventKind::Open,
            pid: 1,
            tid: 1,
            uid: 0,
            comm: "cat".into(),
            path: Some(p.into()),
            ret: 0,
        }
    }

    fn redact(include: bool, p: &str) -> Option<String> {
        let mut e = with_path(p);
        Redactor::new(include, &RedactionConfig::default()).apply(&mut e);
        e.path
    }

    #[test]
    fn paths_are_dropped_unless_enabled() {
        assert_eq!(redact(false, "/etc/hosts"), None);
        assert_eq!(redact(true, "/etc/hosts").as_deref(), Some("/etc/hosts"));
    }

    #[test]
    fn substring_rules_hide_whole_path() {
        assert_eq!(
            redact(true, "/srv/app/.env.production").as_deref(),
            Some(REDACTED)
        );
        assert_eq!(redact(true, "/opt/Secrets/db").as_deref(), Some(REDACTED));
        assert_eq!(
            redact(true, "/home/alice/.ssh/id_ed25519").as_deref(),
            Some(REDACTED)
        );
    }

    #[test]
    fn prefix_rules_keep_only_the_prefix() {
        assert_eq!(
            redact(true, "/home/alice/notes.txt").as_deref(),
            Some("/home/<redacted>")
        );
        assert_eq!(redact(true, "/home").as_deref(), Some("/home"));
        assert_eq!(redact(true, "/homework/a").as_deref(), Some("/homework/a"));
    }

    #[test]
    fn events_without_paths_are_untouched() {
        let mut e = with_path("x");
        e.path = None;
        assert!(!Redactor::new(false, &RedactionConfig::default()).apply(&mut e));
    }
}
