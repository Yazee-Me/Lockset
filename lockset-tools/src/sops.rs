use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::OnceLock;

use lockset_core::{Codec, Error, PathId, Result, SecretKey};

use crate::env;

/// The version type and the default minimum live in core, so `lockset.toml`
/// can carry one; re-exported here because this is where sops is wrapped.
pub use lockset_core::version::{parse_version, Version, MIN_VERSION};

/// The prefix every age identity starts with.
const SECRET_PREFIX: &str = "AGE-SECRET-KEY-";

/// Indent each line under the error, or say the tool was silent.
fn indent(text: &str) -> String {
    if text.trim().is_empty() {
        return " no output".to_owned();
    }
    text.lines().map(|line| format!("\n  {line}")).collect()
}

/// Replace the identity this codec holds and any `AGE-SECRET-KEY-…` token with
/// `[redacted]`: a tool that echoes its environment must not print the key into
/// a CI log.
fn redact(text: &str, key: Option<&SecretKey>) -> String {
    let text = match key {
        Some(key) => text.replace(key.expose(), "[redacted]"),
        None => text.to_owned(),
    };
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(start) = rest.find(SECRET_PREFIX) {
        out.push_str(&rest[..start]);
        out.push_str("[redacted]");
        let tail = &rest[start + SECRET_PREFIX.len()..];
        let end = tail
            .find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit()))
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// The sops CLI, wrapped. The key is handed over through the child
/// environment only; it never reaches argv or a file.
pub struct SopsCodec {
    root: PathBuf,
    bin: String,
    /// The oldest version this repository accepts, from `codec.min_version`.
    min: Version,
    /// The sops config file, from `repo.sops_config`.
    config: PathId,
    /// The parent environment the child inherits (minus identity and `SOPS_*`),
    /// injected instead of read from the process.
    environment: Vec<(OsString, OsString)>,
    /// The preflight result, so a command checks the tool once.
    checked: OnceLock<std::result::Result<Version, String>>,
}

impl SopsCodec {
    pub fn new(root: impl Into<PathBuf>, bin: impl Into<String>, min: Version) -> Self {
        Self {
            root: root.into(),
            bin: bin.into(),
            min,
            config: PathId::parse(lockset_core::config::DEFAULT_SOPS_CONFIG)
                .expect("the default sops config path is valid"),
            environment: Vec::new(),
            checked: OnceLock::new(),
        }
    }

    /// Read and rewrite the sops config at `path` instead of `.sops.yaml`.
    pub fn with_config(mut self, path: PathId) -> Self {
        self.config = path;
        self
    }

    /// Give the sops children this environment instead of the process's own.
    /// The identity and every `SOPS_*` variable are removed from it.
    pub fn with_environment(mut self, environment: Vec<(OsString, OsString)>) -> Self {
        self.environment = environment;
        self
    }

    /// The config file this codec passes to sops.
    pub fn config(&self) -> &PathId {
        &self.config
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
            .envs(env::without_identity(self.environment.clone()))
            .output()
            .map_err(|error| {
                Error::tool(format!(
                    "cannot run sops (`{}`): {error}; install sops >= {} \
                     or pass --sops <path>",
                    self.bin, self.min
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
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::tool(format!(
                "sops (`{}`) --version failed:{}; install sops >= {} \
                 or pass --sops <path>",
                self.bin,
                indent(&redact(stderr.trim_end(), None)),
                self.min
            )));
        }
        Err(Error::tool(format!(
            "cannot read the sops version from `{}`; expected output like `sops {}`",
            self.bin, self.min
        )))
    }

    /// The mutation preflight: sops is present and at least [`MIN_VERSION`].
    /// The answer is cached, so a command pays for it once per process.
    pub fn preflight(&self) -> Result<Version> {
        let checked = self.checked.get_or_init(|| {
            self.version()
                .and_then(|version| {
                    if version < self.min {
                        return Err(Error::tool(format!(
                            "sops {version} is older than the required {};                              upgrade sops or pass --sops <path>",
                            self.min
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
    fn command(&self, args: &[&str], key: &SecretKey) -> Command {
        let mut command = Command::new(&self.bin);
        // sops looks for `.sops.yaml` in the working directory we set, so the
        // flag is only needed when the repository keeps its config elsewhere.
        if self.config.as_str() != lockset_core::config::DEFAULT_SOPS_CONFIG {
            command.args(["--config", self.config.as_str()]);
        }
        command
            .args(args)
            .current_dir(&self.root)
            .env_clear()
            .envs(env::without_identity(self.environment.clone()))
            .env("SOPS_AGE_KEY", key.expose());
        command
    }

    fn run(&self, args: &[&str], key: &SecretKey) -> Result<Output> {
        self.command(args, key)
            .output()
            .map_err(|e| Error::tool(format!("cannot run {}: {e}", self.bin)))
    }

    fn ok(&self, output: &Output, what: &str, key: &SecretKey) -> Result<()> {
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Error::tool(format!(
            "sops {what} failed:{}",
            indent(&redact(stderr.trim_end(), Some(key)))
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
        self.ok(&output, &format!("decrypt {id}"), key)?;
        Ok(output.stdout)
    }

    fn rewrap(&self, id: &PathId, key: &SecretKey) -> Result<()> {
        let output = self.run(&["updatekeys", "-y", id.as_str()], key)?;
        self.ok(&output, &format!("updatekeys {id}"), key)?;
        self.verify(id, key)
    }

    fn rekey(&self, id: &PathId, key: &SecretKey) -> Result<()> {
        let output = self.run(&["rotate", "-i", id.as_str()], key)?;
        self.ok(&output, &format!("rotate {id}"), key)?;
        self.verify(id, key)
    }

    fn set_value(&self, id: &PathId, name: &str, value: &str, key: &SecretKey) -> Result<()> {
        use std::io::Write;
        use std::process::Stdio;

        let json = serde_json::to_string(value)
            .map_err(|e| Error::tool(format!("cannot encode the value: {e}")))?;
        let selector = format!("[\"{name}\"]");

        let mut child = self
            .command(&["set", "--value-stdin", id.as_str(), &selector], key)
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
        self.ok(&output, &format!("set {name} in {id}"), key)?;

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

    #[test]
    fn an_identity_in_the_output_is_redacted() {
        let key = SecretKey::generate();
        let text = format!(
            "decrypting with {} failed\nretry with AGE-SECRET-KEY-1ABCDEFGHIJ, or rotate\n",
            key.expose()
        );

        let redacted = redact(&text, Some(&key));

        assert!(!redacted.contains(key.expose()), "{redacted}");
        assert!(!redacted.contains("1ABCDEFGHIJ"), "{redacted}");
        assert_eq!(redacted.matches("[redacted]").count(), 2, "{redacted}");
        assert!(
            redacted.contains("decrypting with [redacted] failed"),
            "{redacted}"
        );
    }

    #[test]
    fn an_error_keeps_every_stderr_line() {
        let detail = indent("failed to decrypt data key\nage: no identity matched");

        assert!(detail.contains("  failed to decrypt data key"), "{detail}");
        assert!(detail.contains("  age: no identity matched"), "{detail}");
        assert_eq!(indent("  \n"), " no output");
    }

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

    fn codec(name: &str) -> SopsCodec {
        SopsCodec::new("/repo", name, MIN_VERSION).with_environment(parent())
    }

    fn command(codec: &SopsCodec, key: &SecretKey) -> Command {
        codec.command(&["-d", "secrets/dev.env"], key)
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
        let codec = codec("sops");
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
    fn a_non_default_config_is_passed_to_sops() {
        let codec = codec("sops").with_config(PathId::parse("sops/settings.yaml").unwrap());
        let key = SecretKey::generate();
        let argv: Vec<String> = command(&codec, &key)
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert_eq!(&argv[..2], ["--config", "sops/settings.yaml"], "{argv:?}");
        assert!(argv.iter().any(|arg| arg == "-d"), "{argv:?}");
    }

    #[test]
    fn the_default_config_is_left_to_sops_discovery() {
        let codec = codec("sops");
        let key = SecretKey::generate();
        let argv: Vec<String> = command(&codec, &key)
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert!(!argv.iter().any(|arg| arg == "--config"), "{argv:?}");
    }

    #[test]
    fn the_key_never_reaches_argv() {
        let codec = codec("sops");
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
        let codec = SopsCodec::new("/repo", sops.as_str(), MIN_VERSION);

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
        let codec = SopsCodec::new("/repo", sops.as_str(), MIN_VERSION);

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
        let codec = SopsCodec::new("/repo", sops.as_str(), MIN_VERSION);

        let error = codec.preflight().unwrap_err();

        assert!(
            error.to_string().contains("cannot read the sops version"),
            "{error}"
        );
    }

    #[test]
    fn preflight_names_a_missing_binary_and_the_flag() {
        let codec = SopsCodec::new("/repo", "/nonexistent/lockset-sops", MIN_VERSION);

        let error = codec.preflight().unwrap_err();
        let message = error.to_string();

        assert!(message.contains("cannot run sops"), "{message}");
        assert!(message.contains("--sops"), "{message}");
    }
}
