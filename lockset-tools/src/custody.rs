use std::path::PathBuf;
use std::sync::Mutex;

use lockset_core::{Custody, CustodyKind, Error, Result, SecretKey};

/// CI and one-shot restores: the key comes from the environment, nothing is
/// persisted by this process.
pub struct EnvCustody {
    var: String,
}

impl EnvCustody {
    pub fn new(var: impl Into<String>) -> Self {
        Self { var: var.into() }
    }
}

impl Custody for EnvCustody {
    fn get(&self) -> Result<Option<SecretKey>> {
        match std::env::var(&self.var) {
            Ok(value) if !value.trim().is_empty() => Ok(Some(SecretKey::from_text(&value)?)),
            _ => Ok(None),
        }
    }

    fn set(&self, _key: &SecretKey) -> Result<()> {
        Err(Error::refused(format!(
            "{} is read-only here; set it in the parent environment",
            self.var
        )))
    }

    fn forget(&self) -> Result<()> {
        Err(Error::refused(format!(
            "{} is not owned by lockset; unset it yourself",
            self.var
        )))
    }

    fn kind(&self) -> CustodyKind {
        CustodyKind::Env
    }
}

/// Explicit file custody for headless machines: mode 0600, never inside the
/// repository.
pub struct FileCustody {
    path: PathBuf,
}

impl FileCustody {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl Custody for FileCustody {
    fn get(&self) -> Result<Option<SecretKey>> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Ok(Some(SecretKey::from_text(&text)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::failed(format!(
                "cannot read {}: {e}",
                self.path.display()
            ))),
        }
    }

    fn set(&self, key: &SecretKey) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::failed(format!("cannot create {}: {e}", parent.display())))?;
        }
        std::fs::write(&self.path, format!("{}\n", key.expose()))
            .map_err(|e| Error::failed(format!("cannot write {}: {e}", self.path.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| Error::failed(format!("cannot chmod 600 the key file: {e}")))?;
        }
        Ok(())
    }

    fn forget(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::failed(format!(
                "cannot remove {}: {e}",
                self.path.display()
            ))),
        }
    }

    fn kind(&self) -> CustodyKind {
        CustodyKind::File
    }
}

/// The OS credential store: Keychain, Credential Manager, Secret Service.
pub struct KeyringCustody {
    service: String,
    account: String,
}

impl KeyringCustody {
    pub fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
        }
    }

    /// The item this repository created belongs to `security(1)`. macOS binds a
    /// keychain item's ACL to the binary that created it, so reading it from an
    /// unsigned CLI through the Security framework raises a prompt that a
    /// non-interactive run cancels. Using the same tool that created the item
    /// keeps the existing custody working; the secret never appears in output.
    #[cfg(target_os = "macos")]
    fn security(&self, args: &[&str]) -> Result<std::process::Output> {
        std::process::Command::new("security")
            .args(args)
            .output()
            .map_err(|e| Error::failed(format!("cannot run security(1): {e}")))
    }

    #[cfg(not(target_os = "macos"))]
    fn entry(&self) -> Result<keyring::v1::Entry> {
        keyring::v1::Entry::new(&self.service, &self.account)
            .map_err(|e| Error::failed(format!("keyring unavailable: {e}")))
    }
}

impl Custody for KeyringCustody {
    fn get(&self) -> Result<Option<SecretKey>> {
        #[cfg(target_os = "macos")]
        {
            let output = self.security(&["find-generic-password", "-s", &self.service, "-w"])?;
            if !output.status.success() {
                return Ok(None);
            }
            let value = String::from_utf8_lossy(&output.stdout);
            let value = value.lines().next().unwrap_or("").trim();
            if value.is_empty() {
                Ok(None)
            } else {
                Ok(Some(SecretKey::from_text(value)?))
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            match self.entry()?.get_password() {
                Ok(value) if !value.trim().is_empty() => Ok(Some(SecretKey::from_text(&value)?)),
                Ok(_) => Ok(None),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(Error::failed(format!(
                    "cannot read the keyring item {}: {e}",
                    self.service
                ))),
            }
        }
    }

    fn set(&self, key: &SecretKey) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let output = self.security(&[
                "add-generic-password",
                "-U",
                "-s",
                &self.service,
                "-a",
                &self.account,
                "-w",
                key.expose(),
            ])?;
            if !output.status.success() {
                return Err(Error::failed(format!(
                    "security add-generic-password failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.entry()?
                .set_password(key.expose())
                .map_err(|e| Error::failed(format!("cannot write the keyring item: {e}")))
        }
    }

    fn forget(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let _ = self.security(&["delete-generic-password", "-s", &self.service])?;
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            match self.entry()?.delete_credential() {
                Ok(()) => Ok(()),
                Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(Error::failed(format!(
                    "cannot delete the keyring item: {e}"
                ))),
            }
        }
    }

    fn kind(&self) -> CustodyKind {
        CustodyKind::Keyring
    }
}

/// In-memory custody for tests and `--dry-run` wiring.
#[derive(Default)]
pub struct MemoryCustody {
    inner: Mutex<Option<SecretKey>>,
}

impl MemoryCustody {
    pub fn new(key: Option<SecretKey>) -> Self {
        Self {
            inner: Mutex::new(key),
        }
    }
}

impl Custody for MemoryCustody {
    fn get(&self) -> Result<Option<SecretKey>> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| Error::failed("memory custody poisoned"))?;
        guard
            .as_ref()
            .map(|k| SecretKey::from_value(k.expose()))
            .transpose()
    }

    fn set(&self, key: &SecretKey) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| Error::failed("memory custody poisoned"))?;
        *guard = Some(SecretKey::from_value(key.expose())?);
        Ok(())
    }

    fn forget(&self) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| Error::failed("memory custody poisoned"))?;
        *guard = None;
        Ok(())
    }

    fn kind(&self) -> CustodyKind {
        CustodyKind::Memory
    }
}
