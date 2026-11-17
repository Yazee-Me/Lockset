use std::io::{IsTerminal, Read};
use std::path::Path;

use anyhow::{Context, Result};
use lockset_core::SecretKey;
use zeroize::Zeroizing;

use crate::usage;

/// Where `set` takes the value from. Exactly one source is chosen by the
/// caller; a non-terminal run without one is refused instead of reading stdin
/// implicitly, because a pipeline with a closed stdin would otherwise blank the
/// secret.
pub struct ValueSource<'a> {
    pub stdin: bool,
    pub from_env: Option<&'a str>,
    pub file: Option<&'a Path>,
    pub allow_empty: bool,
}

/// A dotenv value from the chosen source. Trailing newlines are dropped;
/// embedded lines are refused, and an empty value needs `allow_empty`.
pub fn read_value(source: &ValueSource<'_>) -> Result<Zeroizing<String>> {
    let raw = if let Some(name) = source.from_env {
        std::env::var(name).map_err(|_| usage::error(format!("{name} is not set")))?
    } else if let Some(path) = source.file {
        std::fs::read_to_string(path)
            .map_err(|error| usage::error(format!("cannot read {}: {error}", path.display())))?
    } else if source.stdin {
        read_stdin()?
    } else if std::io::stdin().is_terminal() {
        rpassword::prompt_password("value (input hidden): ").context("cannot read the value")?
    } else {
        return Err(usage::error(
            "stdin is not a terminal and no value source was given; \
             pass --stdin, --from-env NAME, or --value-file PATH",
        ));
    };
    let value = raw.trim_end_matches(['\r', '\n']).to_owned();
    if value.contains(['\r', '\n']) {
        return Err(usage::error("a dotenv value must be a single line"));
    }
    if value.is_empty() && !source.allow_empty {
        return Err(usage::error(
            "the value is empty; pass --allow-empty to store an empty value",
        ));
    }
    Ok(Zeroizing::new(value))
}

fn read_stdin() -> Result<String> {
    let mut buffer = String::new();
    std::io::stdin()
        .read_to_string(&mut buffer)
        .context("cannot read stdin")?;
    Ok(buffer)
}

/// Read a private key without it ever reaching argv or shell history.
pub fn read_key(
    file: Option<&Path>,
    stdin_flag: bool,
    from_env: Option<&str>,
) -> Result<SecretKey> {
    let text = if let Some(path) = file {
        std::fs::read_to_string(path)
            .map_err(|error| usage::error(format!("cannot read {}: {error}", path.display())))?
    } else if let Some(name) = from_env {
        std::env::var(name).map_err(|_| usage::error(format!("{name} is not set")))?
    } else if stdin_flag || !std::io::stdin().is_terminal() {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .context("cannot read stdin")?;
        buffer
    } else {
        rpassword::prompt_password("paste the age private key (input hidden): ")
            .context("cannot read the pasted key")?
    };

    SecretKey::from_text(&text).map_err(Into::into)
}

pub fn confirm(question: &str) -> Result<bool> {
    use std::io::Write;
    print!("{question} [y/N] ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    /// A value file outside the repository, removed with the value.
    struct ValueFile(PathBuf);

    impl ValueFile {
        fn new(name: &str, contents: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("lockset-value-{name}-{}", std::process::id()));
            std::fs::write(&path, contents).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ValueFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn from_file(path: &Path, allow_empty: bool) -> Result<Zeroizing<String>> {
        read_value(&ValueSource {
            stdin: false,
            from_env: None,
            file: Some(path),
            allow_empty,
        })
    }

    #[test]
    fn a_value_file_loses_only_its_trailing_newlines() {
        let file = ValueFile::new("newline", "s3cret\n");
        assert_eq!(from_file(file.path(), false).unwrap().as_str(), "s3cret");
    }

    #[test]
    fn an_empty_value_needs_allow_empty() {
        let file = ValueFile::new("empty", "");

        let error = from_file(file.path(), false).unwrap_err();
        assert!(error.to_string().contains("--allow-empty"), "{error}");
        assert_eq!(from_file(file.path(), true).unwrap().as_str(), "");
    }

    #[test]
    fn a_multiline_value_is_refused() {
        let file = ValueFile::new("multiline", "first\nsecond\n");

        let error = from_file(file.path(), false).unwrap_err();
        assert!(error.to_string().contains("single line"), "{error}");
    }

    #[test]
    fn an_environment_variable_is_a_source() {
        std::env::set_var("LOCKSET_TEST_VALUE", "from-env\n");
        let source = ValueSource {
            stdin: false,
            from_env: Some("LOCKSET_TEST_VALUE"),
            file: None,
            allow_empty: false,
        };
        let value = read_value(&source).unwrap();
        std::env::remove_var("LOCKSET_TEST_VALUE");

        assert_eq!(value.as_str(), "from-env");
    }

    #[test]
    fn a_missing_environment_variable_is_an_error() {
        let source = ValueSource {
            stdin: false,
            from_env: Some("LOCKSET_TEST_VALUE_ABSENT"),
            file: None,
            allow_empty: false,
        };

        let error = read_value(&source).unwrap_err();
        assert!(error.to_string().contains("is not set"), "{error}");
    }
}
