use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};

use lockset_core::{Codec, Error, PathId, Result, SecretKey};

use crate::env;

/// The sops CLI, wrapped. The key is handed over through the child
/// environment only; it never reaches argv or a file.
pub struct SopsCodec {
    root: PathBuf,
    bin: String,
}

impl SopsCodec {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            bin: std::env::var("LOCKSET_SOPS").unwrap_or_else(|_| "sops".to_owned()),
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
        let codec = SopsCodec::new("/repo");
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
        let codec = SopsCodec::new("/repo");
        let key = SecretKey::generate();
        let argv: Vec<String> = command(&codec, &key)
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert!(argv.iter().all(|arg| !arg.contains(key.expose())));
    }
}
