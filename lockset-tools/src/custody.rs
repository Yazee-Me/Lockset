use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Mutex;

use lockset_core::{Custody, CustodyKind, Error, Result, SecretKey};

/// CI and one-shot restores: the key comes from the environment, nothing is
/// persisted by this process.
pub struct EnvCustody {
    var: String,
    /// The variables the caller injected; `None` reads the process, which is
    /// only what a CLI run does.
    environment: Option<Vec<(OsString, OsString)>>,
}

impl EnvCustody {
    pub fn new(var: impl Into<String>) -> Self {
        Self {
            var: var.into(),
            environment: None,
        }
    }

    /// Read from these variables instead of the process environment.
    pub fn with_environment(mut self, environment: Vec<(OsString, OsString)>) -> Self {
        self.environment = Some(environment);
        self
    }

    fn value(&self) -> Option<String> {
        match &self.environment {
            Some(vars) => vars
                .iter()
                .find(|(name, _)| name == &OsString::from(&self.var))
                .map(|(_, value)| value.to_string_lossy().into_owned()),
            None => std::env::var(&self.var).ok(),
        }
    }
}

impl Custody for EnvCustody {
    fn get(&self) -> Result<Option<SecretKey>> {
        match self.value() {
            Some(value) if !value.trim().is_empty() => Ok(Some(SecretKey::from_text(&value)?)),
            _ => Ok(None),
        }
    }

    fn set(&self, _key: &SecretKey) -> Result<()> {
        Err(Error::custody(format!(
            "{} is read-only here; set it in the parent environment",
            self.var
        )))
    }

    fn forget(&self) -> Result<()> {
        Err(Error::custody(format!(
            "{} is not owned by lockset; unset it yourself",
            self.var
        )))
    }

    fn kind(&self) -> CustodyKind {
        CustodyKind::Env
    }
}

/// No identity source is configured and the run is not interactive. Reports see
/// no identity instead of probing the OS keychain; storing or forgetting a key
/// asks for an explicit source rather than guessing one.
pub struct UnconfiguredCustody;

impl Custody for UnconfiguredCustody {
    fn get(&self) -> Result<Option<SecretKey>> {
        Ok(None)
    }

    fn set(&self, _key: &SecretKey) -> Result<()> {
        Err(Error::custody(
            "no identity source is configured for a non-interactive run; \
             set LOCKSET_AGE_KEY or pass --custody file:<path>",
        ))
    }

    fn forget(&self) -> Result<()> {
        Err(Error::custody(
            "there is nothing to forget: no identity source is configured for a \
             non-interactive run; pass --custody keyring or --custody file:<path>",
        ))
    }

    fn kind(&self) -> CustodyKind {
        CustodyKind::None
    }
}

/// Explicit file custody for headless machines: mode 0600, never inside the
/// repository.
#[derive(Debug)]
pub struct FileCustody {
    path: PathBuf,
}

impl FileCustody {
    /// `repo_root` is the repository the key must stay outside of. The path is
    /// resolved through any symlinks before that check, and an existing target
    /// must be a regular file that is not a symlink. The key file itself may be
    /// missing: `key import` creates it.
    pub fn new(path: impl Into<PathBuf>, repo_root: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(Error::invalid("file: custody needs a path to the key"));
        }
        let root = repo_root.into();
        let root = root.canonicalize().map_err(|e| {
            Error::custody(format!(
                "cannot resolve the repository {}: {e}",
                root.display()
            ))
        })?;
        if resolve(&path)?.starts_with(&root) {
            return Err(Error::custody(format!(
                "refusing to keep the key at {}: it is inside the repository; \
                 mount it outside (an absolute path) or use --custody env",
                path.display()
            )));
        }
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => regular_file(&path, &meta)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Error::custody(format!(
                    "cannot inspect {}: {e}",
                    path.display()
                )))
            }
        }
        Ok(Self { path })
    }
}

impl Custody for FileCustody {
    fn get(&self) -> Result<Option<SecretKey>> {
        let meta = match std::fs::symlink_metadata(&self.path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(Error::custody(format!(
                    "cannot inspect {}: {e}",
                    self.path.display()
                )))
            }
        };
        regular_file(&self.path, &meta)?;
        owner_only(&self.path, &meta)?;
        let text = std::fs::read_to_string(&self.path)
            .map_err(|e| Error::custody(format!("cannot read {}: {e}", self.path.display())))?;
        Ok(Some(SecretKey::from_text(&text)?))
    }

    fn set(&self, key: &SecretKey) -> Result<()> {
        use std::io::Write;

        // Opening an existing file keeps its mode, so it must already be
        // private before the key is written through it.
        match std::fs::symlink_metadata(&self.path) {
            Ok(meta) => {
                regular_file(&self.path, &meta)?;
                owner_only(&self.path, &meta)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Error::custody(format!(
                    "cannot inspect {}: {e}",
                    self.path.display()
                )))
            }
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::custody(format!("cannot create {}: {e}", parent.display())))?;
        }

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // The file is created private instead of being chmodded afterwards,
            // so the key is never briefly world-readable.
            options.mode(0o600);
        }
        let mut file = options
            .open(&self.path)
            .map_err(|e| Error::custody(format!("cannot open {}: {e}", self.path.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = file
                .metadata()
                .map_err(|e| {
                    Error::custody(format!("cannot inspect {}: {e}", self.path.display()))
                })?
                .permissions()
                .mode()
                & 0o777;
            // A file swapped in between the check above and this open keeps its
            // own mode; tighten the handle before any secret reaches it.
            if mode & 0o077 != 0 {
                file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| Error::custody(format!("cannot chmod 600 the key file: {e}")))?;
            }
        }
        file.write_all(format!("{}\n", key.expose()).as_bytes())
            .map_err(|e| Error::custody(format!("cannot write {}: {e}", self.path.display())))?;
        Ok(())
    }

    fn forget(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::custody(format!(
                "cannot remove {}: {e}",
                self.path.display()
            ))),
        }
    }

    fn kind(&self) -> CustodyKind {
        CustodyKind::File
    }
}

/// `security add-generic-password` for this item. `-w` is last and bare, so
/// `security(1)` prompts for the password instead of taking it from argv, where
/// `ps` would show it to every same-user process.
#[cfg(any(target_os = "macos", test))]
fn add_arguments(service: &str, account: &str) -> Vec<String> {
    [
        "add-generic-password",
        "-U",
        "-s",
        service,
        "-a",
        account,
        "-w",
    ]
    .map(str::to_owned)
    .to_vec()
}

/// `security find-generic-password` for this item: the service and the account
/// together name it, so another account's item cannot be read by mistake.
#[cfg(any(target_os = "macos", test))]
fn find_arguments(service: &str, account: &str) -> Vec<String> {
    ["find-generic-password", "-s", service, "-a", account, "-w"]
        .map(str::to_owned)
        .to_vec()
}

/// `security delete-generic-password`, with the same service plus account match
/// as the lookup, so `key forget` removes only this machine's item.
#[cfg(any(target_os = "macos", test))]
fn delete_arguments(service: &str, account: &str) -> Vec<String> {
    ["delete-generic-password", "-s", service, "-a", account]
        .map(str::to_owned)
        .to_vec()
}

/// Canonicalize a path that may not exist yet: the deepest existing ancestor is
/// resolved through symlinks and the missing tail is appended unchanged.
fn resolve(path: &std::path::Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| Error::custody(format!("cannot resolve the current directory: {e}")))?
            .join(path)
    };
    let mut existing = absolute;
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if existing.exists() {
            let mut resolved = existing.canonicalize().map_err(|e| {
                Error::custody(format!("cannot resolve {}: {e}", existing.display()))
            })?;
            for part in tail.iter().rev() {
                resolved.push(part);
            }
            return Ok(resolved);
        }
        let Some(name) = existing.file_name() else {
            return Err(Error::invalid(format!(
                "cannot resolve the key path {}",
                path.display()
            )));
        };
        tail.push(name.to_os_string());
        if !existing.pop() {
            return Err(Error::invalid(format!(
                "cannot resolve the key path {}",
                path.display()
            )));
        }
    }
}

/// A key file must be a regular file: a symlink would let the path and the data
/// diverge, and a directory or FIFO is not an identity.
fn regular_file(path: &std::path::Path, meta: &std::fs::Metadata) -> Result<()> {
    if meta.file_type().is_symlink() {
        return Err(Error::custody(format!(
            "refusing the key at {}: it is a symlink; point --custody file: at the file itself",
            path.display()
        )));
    }
    if !meta.file_type().is_file() {
        return Err(Error::custody(format!(
            "refusing the key at {}: it is not a regular file",
            path.display()
        )));
    }
    Ok(())
}

/// 0600 or stricter: any group or other permission exposes the identity.
fn owner_only(path: &std::path::Path, meta: &std::fs::Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(Error::custody(format!(
                "{} is readable by other users (mode {mode:03o}); run `chmod 600 {}` and retry",
                path.display(),
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = (path, meta);
    Ok(())
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

    /// The keychain service this custody reads (`lockset.toml` may set it).
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The keychain account this custody reads.
    pub fn account(&self) -> &str {
        &self.account
    }

    /// The item this repository created belongs to `security(1)`. macOS binds a
    /// keychain item's ACL to the binary that created it, so reading it from an
    /// unsigned CLI through the Security framework raises a prompt that a
    /// non-interactive run cancels. Using the same tool that created the item
    /// keeps the existing custody working; the secret never appears in output.
    #[cfg(target_os = "macos")]
    fn security(&self, args: &[String]) -> Result<std::process::Output> {
        std::process::Command::new("security")
            .args(args)
            // `security add-generic-password -w` reads the password from the
            // terminal; capturing stdin would hand it an empty stream instead.
            .stdin(std::process::Stdio::inherit())
            .output()
            .map_err(|e| Error::custody(format!("cannot run security(1): {e}")))
    }

    #[cfg(all(not(target_os = "macos"), feature = "keyring"))]
    fn entry(&self) -> Result<keyring::v1::Entry> {
        keyring::v1::Entry::new(&self.service, &self.account).map_err(|e| {
            Error::custody(format!(
                "keyring unavailable: {e}; use --custody env or --custody file:<path> \
                     on a machine without a session keyring"
            ))
        })
    }
}

/// The message a build without the `keyring` feature gives: the CLI still
/// accepts `--custody keyring` so a pipeline gets an explanation, not a parse
/// failure about a platform it may be able to use after a rebuild.
#[cfg(all(not(target_os = "macos"), not(feature = "keyring")))]
const KEYRING_UNAVAILABLE: &str = "the OS keychain backend is not compiled into this build \
     (no `keyring` feature); use --custody env[:NAME] or --custody file:<absolute path>, or \
     rebuild with --features keyring";

impl Custody for KeyringCustody {
    fn get(&self) -> Result<Option<SecretKey>> {
        #[cfg(target_os = "macos")]
        {
            let output = self.security(&find_arguments(&self.service, &self.account))?;
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
        #[cfg(all(not(target_os = "macos"), not(feature = "keyring")))]
        {
            Err(Error::custody(KEYRING_UNAVAILABLE))
        }
        #[cfg(all(not(target_os = "macos"), feature = "keyring"))]
        {
            match self.entry()?.get_password() {
                Ok(value) if !value.trim().is_empty() => Ok(Some(SecretKey::from_text(&value)?)),
                Ok(_) => Ok(None),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(Error::custody(format!(
                    "cannot read the keyring item {}: {e}; use --custody env or \
                     --custody file:<path> on a machine without a session keyring",
                    self.service
                ))),
            }
        }
    }

    fn set(&self, key: &SecretKey) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            use std::io::IsTerminal;

            if !std::io::stdin().is_terminal() {
                return Err(Error::custody(
                    "the macOS keychain asks for the identity on the terminal, so a \
                     non-interactive run cannot store it; use --custody env or \
                     --custody file:<path>",
                ));
            }
            let output = self.security(&add_arguments(&self.service, &self.account))?;
            if !output.status.success() {
                return Err(Error::custody(format!(
                    "security add-generic-password failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            // `security` exits 0 even when the two entries it prompted for
            // differ, so read back rather than report a missing item as stored.
            match self.get()? {
                Some(stored) if stored.expose() == key.expose() => Ok(()),
                _ => Err(Error::custody(
                    "security(1) reported success, but the keychain item does not \
                     hold the key; if it asked twice, the two entries differed",
                )),
            }
        }
        #[cfg(all(not(target_os = "macos"), not(feature = "keyring")))]
        {
            let _ = key;
            Err(Error::custody(KEYRING_UNAVAILABLE))
        }
        #[cfg(all(not(target_os = "macos"), feature = "keyring"))]
        {
            self.entry()?.set_password(key.expose()).map_err(|e| {
                Error::custody(format!(
                    "cannot write the keyring item: {e}; use --custody env or \
                         --custody file:<path> on a machine without a session keyring"
                ))
            })
        }
    }

    fn forget(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let _ = self.security(&delete_arguments(&self.service, &self.account))?;
            Ok(())
        }
        #[cfg(all(not(target_os = "macos"), not(feature = "keyring")))]
        {
            Err(Error::custody(KEYRING_UNAVAILABLE))
        }
        #[cfg(all(not(target_os = "macos"), feature = "keyring"))]
        {
            match self.entry()?.delete_credential() {
                Ok(()) => Ok(()),
                Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(Error::custody(format!(
                    "cannot delete the keyring item: {e}; use --custody env or \
                     --custody file:<path> on a machine without a session keyring"
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
            .map_err(|_| Error::custody("memory custody poisoned"))?;
        guard
            .as_ref()
            .map(|k| SecretKey::from_value(k.expose()))
            .transpose()
    }

    fn set(&self, key: &SecretKey) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| Error::custody("memory custody poisoned"))?;
        *guard = Some(SecretKey::from_value(key.expose())?);
        Ok(())
    }

    fn forget(&self) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| Error::custody("memory custody poisoned"))?;
        *guard = None;
        Ok(())
    }

    fn kind(&self) -> CustodyKind {
        CustodyKind::Memory
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_keychain_write_never_takes_the_secret_as_an_argument() {
        let arguments = add_arguments("lockset-age-key", "alice");

        assert_eq!(
            arguments.iter().map(String::as_str).collect::<Vec<_>>(),
            [
                "add-generic-password",
                "-U",
                "-s",
                "lockset-age-key",
                "-a",
                "alice",
                "-w",
            ]
        );
        assert_eq!(arguments.last().map(String::as_str), Some("-w"));
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "lockset-file-custody-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(all(not(target_os = "macos"), not(feature = "keyring")))]
    #[test]
    fn a_build_without_the_keyring_feature_explains_itself() {
        let custody = KeyringCustody::new("lockset-age-key", "alice");

        for error in [
            custody.get().unwrap_err(),
            custody.set(&SecretKey::generate()).unwrap_err(),
            custody.forget().unwrap_err(),
        ] {
            assert!(
                error.to_string().contains("not compiled into this build"),
                "{error}"
            );
            assert!(error.to_string().contains("--custody env"), "{error}");
            assert!(error.to_string().contains("keyring"), "{error}");
        }
        assert_eq!(custody.kind(), CustodyKind::Keyring);
    }

    #[test]
    fn an_unconfigured_custody_holds_nothing_and_asks_for_a_source() {
        let custody = UnconfiguredCustody;

        assert!(custody.get().unwrap().is_none());
        assert_eq!(custody.kind(), CustodyKind::None);
        let error = custody.set(&SecretKey::generate()).unwrap_err();
        assert!(error.to_string().contains("LOCKSET_AGE_KEY"), "{error}");
        assert!(custody.forget().is_err());
    }

    #[test]
    fn a_key_inside_the_repository_is_refused() {
        let repo = TempDir::new("repo");
        let inside = repo.path().join("key.txt");

        let error = FileCustody::new(&inside, repo.path()).unwrap_err();

        assert!(
            error.to_string().contains("inside the repository"),
            "{error}"
        );
        assert!(!inside.exists(), "the refused path must not be created");
    }

    #[test]
    fn a_key_under_a_missing_repository_directory_is_refused() {
        let repo = TempDir::new("repo-nested");
        let inside = repo.path().join("missing/dir/key.txt");

        let error = FileCustody::new(&inside, repo.path()).unwrap_err();

        assert!(
            error.to_string().contains("inside the repository"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_key_file_is_refused() {
        let repo = TempDir::new("symlink-repo");
        let outside = TempDir::new("symlink-outside");
        let target = outside.path().join("real-key.txt");
        std::fs::write(&target, "AGE-SECRET-KEY-1EXAMPLE\n").unwrap();
        let link = outside.path().join("key.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let error = FileCustody::new(&link, repo.path()).unwrap_err();

        assert!(error.to_string().contains("symlink"), "{error}");
    }

    #[test]
    fn a_directory_is_not_a_key_file() {
        let repo = TempDir::new("dir-repo");
        let outside = TempDir::new("dir-outside");

        let error = FileCustody::new(outside.path(), repo.path()).unwrap_err();

        assert!(error.to_string().contains("not a regular file"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_group_or_world_readable_key_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let repo = TempDir::new("mode-repo");
        let outside = TempDir::new("mode-outside");
        let path = outside.path().join("key.txt");
        let key = SecretKey::generate();
        std::fs::write(&path, format!("{}\n", key.expose())).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let custody = FileCustody::new(&path, repo.path()).unwrap();
        let error = custody.get().unwrap_err();

        assert!(error.to_string().contains("chmod 600"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_new_key_file_is_created_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let repo = TempDir::new("create-repo");
        let outside = TempDir::new("create-outside");
        let path = outside.path().join("nested/key.txt");
        let key = SecretKey::generate();

        let custody = FileCustody::new(&path, repo.path()).unwrap();
        custody.set(&key).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the key file must be private from creation");
        assert_eq!(
            custody.get().unwrap().unwrap().public().unwrap(),
            key.public().unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn writing_over_a_broad_file_is_refused_before_truncation() {
        use std::os::unix::fs::PermissionsExt;

        let repo = TempDir::new("broad-repo");
        let outside = TempDir::new("broad-outside");
        let path = outside.path().join("key.txt");
        std::fs::write(&path, "leave me\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        let custody = FileCustody::new(&path, repo.path()).unwrap();
        let error = custody.set(&SecretKey::generate()).unwrap_err();

        assert!(error.to_string().contains("chmod 600"), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "leave me\n");
    }

    #[test]
    fn a_missing_key_file_reads_as_no_identity() {
        let repo = TempDir::new("missing-repo");
        let outside = TempDir::new("missing-outside");
        let custody = FileCustody::new(outside.path().join("key.txt"), repo.path()).unwrap();

        assert!(custody.get().unwrap().is_none());
    }

    #[test]
    fn lookup_and_delete_match_the_account_as_well_as_the_service() {
        for arguments in [
            find_arguments("lockset-age-key", "alice"),
            delete_arguments("lockset-age-key", "alice"),
        ] {
            let service = arguments.iter().position(|arg| arg == "-s").unwrap();
            assert_eq!(
                arguments.get(service + 1).map(String::as_str),
                Some("lockset-age-key")
            );
            let account = arguments.iter().position(|arg| arg == "-a").unwrap();
            assert_eq!(
                arguments.get(account + 1).map(String::as_str),
                Some("alice")
            );
        }
    }
}
