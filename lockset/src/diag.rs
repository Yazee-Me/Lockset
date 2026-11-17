//! Diagnostics: notes, warnings, and debug lines go to stderr; data stays on
//! stdout. `--quiet` and `--verbose` select the level and win over `RUST_LOG`;
//! with neither flag `RUST_LOG` decides, and the default is `info`, which shows
//! notes and warnings.

use std::io::Write;

use log::{Level, LevelFilter};

/// The stderr prefix a level gets, so a warning is unmistakable in a log and a
/// note reads as a note.
fn prefix(level: Level) -> &'static str {
    match level {
        Level::Warn | Level::Error => "warning: ",
        _ => "",
    }
}

fn format(buf: &mut env_logger::fmt::Formatter, record: &log::Record<'_>) -> std::io::Result<()> {
    writeln!(buf, "{}{}", prefix(record.level()), record.args())
}

/// Build the logger. Flags win over `RUST_LOG`; the default level is `info`, so
/// notes and warnings show and a pipeline can silence them with `--quiet`.
pub fn init(quiet: bool, verbose: bool) {
    let mut builder = env_logger::Builder::new();
    if quiet {
        builder.filter_level(LevelFilter::Error);
    } else if verbose {
        builder.filter_level(LevelFilter::Debug);
    } else {
        builder.filter_level(LevelFilter::Info);
        builder.parse_default_env();
    }
    builder.format(format);
    // The logger is process-wide; a second init in one process is not an error.
    let _ = builder.try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warnings_carry_a_prefix_and_notes_do_not() {
        assert_eq!(prefix(Level::Warn), "warning: ");
        assert_eq!(prefix(Level::Error), "warning: ");
        assert_eq!(prefix(Level::Info), "");
        assert_eq!(prefix(Level::Debug), "");
    }
}
