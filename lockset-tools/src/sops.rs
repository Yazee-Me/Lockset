use std::path::PathBuf;
use std::process::{Command, Output};

use lockset_core::{Codec, Error, PathId, Result, SecretKey};

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

    fn run(&self, args: &[&str], key: &SecretKey) -> Result<Output> {
        Command::new(&self.bin)
            .args(args)
            .current_dir(&self.root)
            .env("SOPS_AGE_KEY", key.expose())
            .env_remove("SOPS_AGE_KEY_FILE")
            .output()
            .map_err(|e| Error::failed(format!("cannot run {}: {e}", self.bin)))
    }

    fn ok(&self, output: &Output, what: &str) -> Result<()> {
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Error::failed(format!(
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
            .map_err(|e| Error::failed(format!("cannot encode the value: {e}")))?;
        let selector = format!("[\"{name}\"]");

        let mut child = Command::new(&self.bin)
            .args(["set", "--value-stdin", id.as_str(), &selector])
            .current_dir(&self.root)
            .env("SOPS_AGE_KEY", key.expose())
            .env_remove("SOPS_AGE_KEY_FILE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::failed(format!("cannot run {}: {e}", self.bin)))?;

        child
            .stdin
            .take()
            .ok_or_else(|| Error::failed("sops set: no stdin"))?
            .write_all(json.as_bytes())
            .map_err(|e| Error::failed(format!("cannot feed the value to sops: {e}")))?;

        let output = child
            .wait_with_output()
            .map_err(|e| Error::failed(format!("sops set failed: {e}")))?;
        self.ok(&output, &format!("set {name} in {id}"))?;

        // Prove the value landed and that the rest of the file still opens.
        let plain = self.decrypt(id, key)?;
        let text = String::from_utf8_lossy(&plain);
        let landed = lockset_core::dotenv::parse(&text)
            .iter()
            .any(|(n, v)| n == name && v == value);
        if !landed {
            return Err(Error::failed(format!(
                "sops set reported success, but {name} reads back differently"
            )));
        }
        Ok(())
    }
}
