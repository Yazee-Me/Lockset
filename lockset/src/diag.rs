//! Diagnostics levels: notes, warnings, and debug lines go to stderr; data
//! stays on stdout. `--quiet` and `--verbose` select the level and win over
//! `RUST_LOG`; with neither flag `RUST_LOG` decides, and the default is
//! `info`, which shows notes and warnings.
//!
//! The level is resolved from the flags and the injected environment, so a
//! library caller gets the same behaviour without touching the process.

use std::fmt::Display;

/// The stderr level, lowest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Off,
    Error,
    Warn,
    Info,
    Debug,
}

impl Level {
    /// `--quiet`/`--verbose` win over `RUST_LOG`, which defaults to `info`.
    pub fn resolve(quiet: bool, verbose: bool, rust_log: Option<&str>) -> Self {
        if quiet {
            return Level::Error;
        }
        if verbose {
            return Level::Debug;
        }
        rust_log.and_then(parse).unwrap_or(Level::Info)
    }

    /// The stderr prefix a message at this level gets.
    fn prefix(self) -> &'static str {
        match self {
            Level::Warn | Level::Error => "warning: ",
            _ => "",
        }
    }

    pub fn allows(self, required: Level) -> bool {
        self != Level::Off && self >= required
    }

    pub fn format(self, message: impl Display) -> String {
        format!("{}{message}", self.prefix())
    }
}

/// Parse a `RUST_LOG` value. Plain levels are accepted (`off`, `error`, `warn`,
/// `info`, `debug`, `trace`); a directive list keeps the last entry that names
/// `lockset` or gives a plain level, so `RUST_LOG=lockset=debug` works. An
/// unrecognised value leaves the default alone.
pub fn parse(text: &str) -> Option<Level> {
    let mut level = None;
    for directive in text.split(',').map(str::trim).filter(|d| !d.is_empty()) {
        let (target, name) = match directive.split_once('=') {
            Some((target, name)) => (Some(target.trim()), name.trim()),
            None => (None, directive),
        };
        if let Some(target) = target {
            if !(target.is_empty() || target == "lockset" || target.starts_with("lockset::")) {
                continue;
            }
        }
        if let Some(parsed) = named(name) {
            level = Some(parsed);
        }
    }
    level
}

fn named(name: &str) -> Option<Level> {
    Some(match name.trim().to_ascii_lowercase().as_str() {
        "off" => Level::Off,
        "error" => Level::Error,
        "warn" | "warning" => Level::Warn,
        "info" => Level::Info,
        "debug" | "trace" => Level::Debug,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_win_over_rust_log() {
        assert_eq!(Level::resolve(true, false, Some("debug")), Level::Error);
        assert_eq!(Level::resolve(false, true, Some("off")), Level::Debug);
    }

    #[test]
    fn rust_log_selects_without_flags() {
        assert_eq!(Level::resolve(false, false, Some("debug")), Level::Debug);
        assert_eq!(Level::resolve(false, false, Some("off")), Level::Off);
        assert_eq!(Level::resolve(false, false, Some("warn")), Level::Warn);
        assert_eq!(Level::resolve(false, false, None), Level::Info);
        assert_eq!(Level::resolve(false, false, Some("")), Level::Info);
    }

    #[test]
    fn directives_name_lockset_or_a_plain_level() {
        assert_eq!(parse("lockset=debug"), Some(Level::Debug));
        assert_eq!(parse("lockset::wiring=trace"), Some(Level::Debug));
        assert_eq!(parse("other=off"), None);
        assert_eq!(parse("other=off,info"), Some(Level::Info));
        assert_eq!(parse("nonsense"), None);
        assert_eq!(parse("INFO"), Some(Level::Info));
    }

    #[test]
    fn a_message_is_prefixed_by_level() {
        assert_eq!(Level::Warn.format("disk full"), "warning: disk full");
        assert_eq!(Level::Info.format("note"), "note");
        assert_eq!(Level::Debug.format("debug"), "debug");
    }
}
