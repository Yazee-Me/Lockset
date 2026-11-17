use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::OnceLock;

use lockset_core::{Codec, Error, PathId, Result, SecretKey};

use crate::env;

/// The oldest sops this crate is written against.
pub const MIN_VERSION: Version = Version {
    major: 3,
    minor: 13,
    patch: 0,
};

/// A parsed `sops --version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The first `major.minor[.patch]` token in `sops --version` output.
pub fn parse_version(text: &str) -> Option<Version> {
    for word in text.split_whitespace() {
        let word = word.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
        let mut parts = word.split('.');
        let (Some(major), Some(minor)) = (parts.next(), parts.next()) else {
            continue;
        };
        let (Ok(major), Ok(minor)) = (major.parse(), minor.parse()) else {
            continue;
        };
        let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        return Some(Version {
            major,
            minor,
            patch,
        });
    }
    None
}

/// The sops CLI, wrapped. The key is handed over through the child
/// environment only; it never reaches argv or a file.
pub struct SopsCodec {
    root: PathBuf,
    bin: String,
    /// The preflight result, so a command checks the tool once.
    checked: OnceLock<std::result::Result<Version, String>>,
}

impl SopsCodec {
    pub fn new(root: impl Into<PathBuf>, bin: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            bin: bin.into(),
            checked: OnceLock::new(),
        }
    }

    /// The binary this codec runs (`--sops`, then `LOCKSET_SOPS`, then `sops`).
    pub fn bin(&self) -> &str {
        &self.bin
    }

    /// `<bin> --version`, run once per codec.
    fn version(&self) -> Result<Version> {
        let output = std::process::Command::new(&self.bin)
            .arg("--version")
            // Same policy as every other sops child: no identity, no SOPS_*
            // overrides. `--version` needs neither.
            .env_clear()
            .envs(env::without_identity(std::env::vars_os()))
            .output()
            .map_err(|error| {
                Error::tool(format!(
                    "cannot run sops (`{}`): {error}; install sops >= {MIN_VERSION} \
                     or pass --sops <path>",
                    self.bin
                ))
            })?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if let Some(version) = parse_version(&text) {
            return Ok(version);
        }
        if !output.status.success() {
            let detail = text.lines().next().unwrap_or("no output").trim();
            return Err(Error::tool(format!(
                "sops (`{}`) --version failed: {detail}; install sops >= {MIN_VERSION} \
                 or pass --sops <path>",
                self.bin
            )));
        }
        Err(Error::tool(format!(
            "cannot read the sops version from `{}`; expected output like `sops {MIN_VERSION}`",
            self.bin
        )))
    }

    /// The mutation preflight: sops is present and at least [`MIN_VERSION`].
    /// The answer is cached, so a command pays for it once per process.
    pub fn preflight(&self) -> Result<Version> {
        let checked = self.checked.get_or_init(|| {
            self.version()
                .and_then(|version| {
                    if version < MIN_VERSION {
                        return Err(Error::tool(format!(
                            "sops {version} is older than the required {MIN_VERSION};                              upgrade sops or pass --sops <path>"
                        )));
                    }
                    Ok(version)
                })
                .map_err(|error| error.to_string())
        });
        match checked {
            Ok(version) => Ok(*version),
            Err(message) => Err(Error::tool(message.clone())),
        }
    }

    /// The sops child. Its environment is its own rather than inherited: the
    /// parent's identity and every `SOPS_*` variable are dropped, so
    /// `SOPS_AGE_KEY` is the only key source and no inherited override can
    /// point sops at another one.
    fn command(
        &self,
        args: &[&str],
        key: &SecretKey,
        parent_env: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> Command {
        let mut command = Command::new(&self.bin);
        command
            .args(args)
            .current_dir(&self.root)
            .env_clear()
            .envs(env::without_identity(parent_env))
            .env("SOPS_AGE_KEY", key.expose());
        command
    }

    fn run(&self, args: &[&str], key: &SecretKey) -> Result<Output> {
        self.command(args, key, std::env::vars_os())
            .output()
            .map_err(|e| Error::tool(format!("cannot run {}: {e}", self.bin)))
    }

    fn ok(&self, output: &Output, what: &str) -> Result<()> {
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Error::tool(format!(
            "sops {what} failed: {}",
            stderr.trim().lines().next().unwrap_or("no output")
        )))
    }

    /// A rewrite that leaves a structurally valid file with lost values only
    /// shows up on decryption, so every write is followed by a read.
    fn verify(&self, id: &PathId, key: &SecretKey) -> Result<()> {
        self.decrypt(id, key).map(|_| ())
    }
}

impl Codec for SopsCodec {
    fn decrypt(&self, id: &PathId, key: &SecretKey) -> Result<Vec<u8>> {
        let output = self.run(&["-d", id.as_str()], key)?;
        self.ok(&output, &format!("decrypt {id}"))?;
        Ok(output.stdout)
    }

    fn rewrap(&self, id: &PathId, key: &SecretKey) -> Result<()> {
        let output = self.run(&["updatekeys", "-y", id.as_str()], key)?;
        self.ok(&output, &format!("updatekeys {id}"))?;
        self.verify(id, key)
    }

    fn rekey(&self, id: &PathId, key: &SecretKey) -> Result<()> {
        let output = self.run(&["rotate", "-i", id.as_str()], key)?;
        self.ok(&output, &format!("rotate {id}"))?;
        self.verify(id, key)
    }

    fn set_value(&self, id: &PathId, name: &str, value: &str, key: &SecretKey) -> Result<()> {
        use std::io::Write;
        use std::process::Stdio;

        let json = serde_json::to_string(value)
            .map_err(|e| Error::tool(format!("cannot encode the value: {e}")))?;
        let selector = format!("[\"{name}\"]");

        let mut child = self
            .command(
                &["set", "--value-stdin", id.as_str(), &selector],
                key,
                std::env::vars_os(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::tool(format!("cannot run {}: {e}", self.bin)))?;

        child
            .stdin
            .take()
            .ok_or_else(|| Error::tool("sops set: no stdin"))?
            .write_all(json.as_bytes())
            .map_err(|e| Error::tool(format!("cannot feed the value to sops: {e}")))?;

        let output = child
            .wait_with_output()
            .map_err(|e| Error::tool(format!("sops set failed: {e}")))?;
        self.ok(&output, &format!("set {name} in {id}"))?;

        // Prove the value landed and that the rest of the file still opens.
        let plain = self.decrypt(id, key)?;
        let text = String::from_utf8_lossy(&plain);
        let landed = lockset_core::dotenv::parse(&text)
            .iter()
            .any(|(n, v)| n == name && v == value);
        if !landed {
            return Err(Error::tool(format!(
                "sops set reported success, but {name} reads back differently"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::process::Command;

    use super::*;

    /// A parent environment that looks like a machine holding the identity
    /// plus every override sops might honour.
    fn parent() -> Vec<(OsString, OsString)> {
        vec![
            ("PATH".into(), "/usr/bin".into()),
            ("HOME".into(), "/home/dev".into()),
            ("LOCKSET_AGE_KEY".into(), "AGE-SECRET-KEY-1PARENT".into()),
            ("SOPS_AGE_KEY".into(), "AGE-SECRET-KEY-1PARENT".into()),
            ("SOPS_AGE_KEY_FILE".into(), "/tmp/key.txt".into()),
            ("SOPS_AGE_KEY_CMD".into(), "op read op://vault/key".into()),
            ("SOPS_AGE_RECIPIENTS".into(), "age1example".into()),
        ]
    }

    fn command(codec: &SopsCodec, key: &SecretKey) -> Command {
        codec.command(&["-d", "secrets/dev.env"], key, parent())
    }

    fn child_env(command: &Command) -> BTreeMap<String, String> {
        command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.unwrap_or_default().to_string_lossy().into_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn the_sops_child_holds_only_its_own_key() {
        let codec = SopsCodec::new("/repo", "sops");
        let key = SecretKey::generate();
        let env = child_env(&command(&codec, &key));

        assert_eq!(
            env.get("SOPS_AGE_KEY").map(String::as_str),
            Some(key.expose())
        );
        assert_eq!(env.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert!(!env.contains_key("LOCKSET_AGE_KEY"));
        assert!(!env.contains_key("SOPS_AGE_KEY_FILE"));
        assert!(!env.contains_key("SOPS_AGE_KEY_CMD"));
        assert!(!env.contains_key("SOPS_AGE_RECIPIENTS"));
    }

    #[test]
    fn the_key_never_reaches_argv() {
        let codec = SopsCodec::new("/repo", "sops");
        let key = SecretKey::generate();
        let argv: Vec<String> = command(&codec, &key)
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert!(argv.iter().all(|arg| !arg.contains(key.expose())));
    }
}

#[cfg(test)]
mod preflight_tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn parses_a_sops_version_line() {
        assert_eq!(
            parse_version("sops 3.13.3 (latest)"),
            Some(Version {
                major: 3,
                minor: 13,
                patch: 3
            })
        );
        assert_eq!(
            parse_version("sops 4.0"),
            Some(Version {
                major: 4,
                minor: 0,
                patch: 0
            })
        );
        assert_eq!(parse_version("no version here"), None);
    }

    #[cfg(unix)]
    struct FakeSops(PathBuf);

    #[cfg(unix)]
    impl FakeSops {
        fn new(name: &str, body: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let path = std::env::temp_dir()
                .join(format!("lockset-fake-sops-{name}-{}", std::process::id()));
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            Self(path)
        }

        fn as_str(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }

    #[cfg(unix)]
    impl Drop for FakeSops {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn preflight_accepts_the_minimum_version() {
        let sops = FakeSops::new("good", "#!/bin/sh\necho 'sops 3.13.3 (latest)'\n");
        let codec = SopsCodec::new("/repo", sops.as_str());

        assert_eq!(
            codec.preflight().unwrap(),
            Version {
                major: 3,
                minor: 13,
                patch: 3
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn preflight_rejects_an_old_sops() {
        let sops = FakeSops::new("old", "#!/bin/sh\necho 'sops 3.12.0'\n");
        let codec = SopsCodec::new("/repo", sops.as_str());

        let error = codec.preflight().unwrap_err();

        assert!(
            error.to_string().contains("older than the required 3.13"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn preflight_rejects_output_without_a_version() {
        let sops = FakeSops::new("garbage", "#!/bin/sh\necho 'what is sops'\n");
        let codec = SopsCodec::new("/repo", sops.as_str());

        let error = codec.preflight().unwrap_err();

        assert!(
            error.to_string().contains("cannot read the sops version"),
            "{error}"
        );
    }

    #[test]
    fn preflight_names_a_missing_binary_and_the_flag() {
        let codec = SopsCodec::new("/repo", "/nonexistent/lockset-sops");

        let error = codec.preflight().unwrap_err();
        let message = error.to_string();

        assert!(message.contains("cannot run sops"), "{message}");
        assert!(message.contains("--sops"), "{message}");
    }
}
