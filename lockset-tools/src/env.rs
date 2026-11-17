//! Child-process environment hygiene.
//!
//! The identity this process holds is the master key for every payload, and
//! sops reads several variables that decide where it looks for one. Neither
//! belongs in a child: a build script started by `run`, or a sops plugin, would
//! otherwise be able to read them. Children therefore start from a scrubbed
//! copy of the parent environment, not from an inherited one.

use std::ffi::OsString;

/// Variables this process reads the identity from. A future custody variable
/// belongs in this list, so no child inherits it by accident.
const IDENTITY_VARS: &[&str] = &["LOCKSET_AGE_KEY"];

/// Every sops control variable shares this prefix: `SOPS_AGE_KEY`,
/// `SOPS_AGE_KEY_FILE`, `SOPS_AGE_KEY_CMD`, and the rest of sops's options.
const SOPS_PREFIX: &str = "SOPS_";

/// What `run --clean-env` keeps: enough to start a program, and nothing that
/// could carry an unrelated CI secret.
const CLEAN_ENV: &[&str] = &["PATH", "HOME", "TMPDIR", "LANG"];

/// Whether `--clean-env` keeps this variable.
pub fn is_kept(name: &str) -> bool {
    CLEAN_ENV.contains(&name)
}

/// The parent environment reduced to the `--clean-env` allowlist.
pub fn clean(env: impl IntoIterator<Item = (OsString, OsString)>) -> Vec<(OsString, OsString)> {
    env.into_iter()
        .filter(|(name, _)| is_kept(&name.to_string_lossy()))
        .collect()
}

/// Whether a child must not inherit this variable.
pub fn is_reserved(name: &str) -> bool {
    IDENTITY_VARS.contains(&name) || name.starts_with(SOPS_PREFIX)
}

/// The parent environment without the identity and without any variable that
/// would change how sops resolves a key.
///
/// Copying what remains, rather than inheriting and removing, keeps the child's
/// environment explicit: a variable set after this call cannot reach it.
pub fn without_identity(
    env: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    env.into_iter()
        .filter(|(name, _)| !is_reserved(&name.to_string_lossy()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect()
    }

    fn names(env: &[(OsString, OsString)]) -> Vec<String> {
        let mut names: Vec<String> = env
            .iter()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn drops_the_identity_and_every_sops_variable() {
        let scrubbed = without_identity(env(&[
            ("PATH", "/usr/bin"),
            ("LOCKSET_AGE_KEY", "AGE-SECRET-KEY-1EXAMPLE"),
            ("SOPS_AGE_KEY", "AGE-SECRET-KEY-1EXAMPLE"),
            ("SOPS_AGE_KEY_FILE", "/tmp/key.txt"),
            ("SOPS_AGE_KEY_CMD", "op read op://vault/key"),
            ("SOPS_AGE_RECIPIENTS", "age1example"),
            ("SOPS_UNRELATED", "value"),
        ]));

        assert_eq!(names(&scrubbed), vec!["PATH".to_owned()]);
    }

    #[test]
    fn clean_keeps_only_the_allowlist() {
        let kept = clean(env(&[
            ("PATH", "/usr/bin"),
            ("HOME", "/home/dev"),
            ("TMPDIR", "/tmp"),
            ("LANG", "C.UTF-8"),
            ("CI_JOB_TOKEN", "secret"),
            ("LOCKSET_AGE_KEY", "AGE-SECRET-KEY-1EXAMPLE"),
            ("SOME_APP_KEY", "value"),
        ]));

        assert_eq!(
            names(&kept),
            vec![
                "HOME".to_owned(),
                "LANG".to_owned(),
                "PATH".to_owned(),
                "TMPDIR".to_owned(),
            ]
        );
    }

    #[test]
    fn keeps_everything_else() {
        let scrubbed = without_identity(env(&[
            ("HOME", "/home/dev"),
            ("PATH", "/usr/bin"),
            ("LOCKSET_SOPS", "/usr/local/bin/sops"),
            ("SOME_APP_KEY", "not an identity"),
        ]));

        assert_eq!(
            names(&scrubbed),
            vec![
                "HOME".to_owned(),
                "LOCKSET_SOPS".to_owned(),
                "PATH".to_owned(),
                "SOME_APP_KEY".to_owned(),
            ]
        );
    }
}
