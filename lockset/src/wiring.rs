use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as AnyhowContext, Result};
use lockset_core::sopsfile::SopsFile;
use lockset_core::{meta, Custody, IdentityView, PathId, PayloadError, Repo, SecretKey, Snapshot};
use lockset_tools::custody::{EnvCustody, FileCustody, KeyringCustody, UnconfiguredCustody};
use lockset_tools::fs_repo::FsRepo;
use lockset_tools::lock::Lock;
use lockset_tools::sops::SopsCodec;

use crate::cli::{Cli, Command};
use crate::usage;

pub const DEFAULT_KEYCHAIN_ITEM: &str = "lockset-age-key";
pub const KEY_ENV: &str = "LOCKSET_AGE_KEY";

pub struct Context {
    pub root: PathBuf,
    pub repo: FsRepo,
    pub codec: SopsCodec,
    pub custody: Box<dyn Custody>,
}

impl Context {
    pub fn detect(cli: &Cli) -> Result<Self> {
        let root = find_root(cli.repo.as_deref())?;
        let interactive = std::io::stdin().is_terminal();
        let custody = make_custody(cli.custody.as_deref(), &root, interactive)?;
        let codec = SopsCodec::new(&root, sops_bin(cli));
        log::debug!("repository root {}", root.display());
        log::debug!("custody {}", custody.kind());
        log::debug!("sops {}", codec.bin());
        Ok(Self {
            repo: FsRepo::new(&root),
            codec,
            root,
            custody,
        })
    }

    pub fn require_key(&self) -> Result<SecretKey> {
        let kind = self.custody.kind();
        self.custody.get()?.ok_or_else(|| match kind {
            lockset_core::CustodyKind::None => anyhow::Error::new(lockset_core::Error::custody(
                "no identity source is configured; set LOCKSET_AGE_KEY or pass --custody file:<path>",
            )),
            kind => anyhow::Error::new(lockset_core::Error::custody(format!(
                "no identity in custody ({kind})"
            ))),
        })
    }
}

/// `--sops`, then `LOCKSET_SOPS`, then the `sops` on PATH.
fn sops_bin(cli: &Cli) -> String {
    cli.sops
        .as_ref()
        .map(|path| path.display().to_string())
        .or_else(|| std::env::var("LOCKSET_SOPS").ok())
        .unwrap_or_else(|| "sops".to_owned())
}

fn find_root(start: Option<&Path>) -> Result<PathBuf> {
    let start = match start {
        Some(dir) => dir.to_path_buf(),
        None => std::env::current_dir().context("cannot resolve the current directory")?,
    };
    let mut dir = start
        .canonicalize()
        .with_context(|| format!("cannot resolve {}", start.display()))?;
    loop {
        if dir.join(".sops.yaml").is_file() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err(usage::error(
                "no .sops.yaml found above the start directory; pass --repo",
            ));
        }
    }
}

fn make_custody(spec: Option<&str>, root: &Path, interactive: bool) -> Result<Box<dyn Custody>> {
    Ok(match spec {
        Some("env") => env_custody(),
        Some("keyring") => keyring_custody(),
        Some(other) if other.starts_with("file:") => {
            Box::new(FileCustody::new(&other["file:".len()..], root)?)
        }
        Some("keyring:") => keyring_custody(),
        Some(other) if other.starts_with("keyring:") => Box::new(KeyringCustody::new(
            &other["keyring:".len()..],
            current_user(),
        )),
        Some(other) => {
            return Err(usage::error(format!(
                "unknown custody '{other}'; use env, keyring, file:<path>, or keyring:<service>"
            )))
        }
        None => default_custody(interactive),
    })
}

/// The implicit choice: `LOCKSET_AGE_KEY` when set, the keychain on a terminal,
/// and otherwise nothing — a container must not be handed whichever key a
/// keychain happens to hold, nor be made to fail when it holds none.
fn default_custody(interactive: bool) -> Box<dyn Custody> {
    if env_is_set(KEY_ENV) {
        env_custody()
    } else if interactive {
        keyring_custody()
    } else {
        Box::new(UnconfiguredCustody)
    }
}

fn env_is_set(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| !value.trim().is_empty())
}

fn env_custody() -> Box<dyn Custody> {
    Box::new(EnvCustody::new(KEY_ENV))
}

fn keyring_custody() -> Box<dyn Custody> {
    Box::new(KeyringCustody::new(DEFAULT_KEYCHAIN_ITEM, current_user()))
}

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "lockset".to_owned())
}

/// Hold the repository lock while a command that writes runs. A dry run or a
/// read-only command takes nothing.
pub fn mutation_lock(cli: &Cli, context: &Context) -> Result<Option<Lock>> {
    if cli.dry_run || !writes(&cli.command) {
        return Ok(None);
    }
    Ok(Some(Lock::acquire(
        &context.root,
        Duration::from_secs(cli.lock_timeout),
    )?))
}

/// Commands that change repository files; custody and child processes do not.
fn writes(command: &Command) -> bool {
    matches!(
        command,
        Command::Set { .. }
            | Command::Rotate { .. }
            | Command::Grant { .. }
            | Command::Revoke { .. }
            | Command::Person { .. }
    )
}

pub fn snapshot(context: &Context) -> Result<Snapshot> {
    let mut digests = std::collections::BTreeMap::new();

    let sops_path = PathId::parse(".sops.yaml")?;
    let sops_bytes = context.repo.read(&sops_path)?;
    digests.insert(sops_path, lockset_core::digest(&sops_bytes));
    let sops_text = String::from_utf8(sops_bytes).context(".sops.yaml is not UTF-8")?;
    let sops = SopsFile::parse(&sops_text)?;

    let mut payloads = Vec::new();
    let mut payload_errors = Vec::new();
    for id in context.repo.list(&PathId::parse("secrets")?)? {
        // A payload that cannot be read or parsed is a finding, not a reason to
        // abandon the report: the rest of the repository stays usable.
        let bytes = match context.repo.read(&id) {
            Ok(bytes) => bytes,
            Err(error) => {
                payload_errors.push(PayloadError {
                    id,
                    error: error.to_string(),
                });
                continue;
            }
        };
        digests.insert(id.clone(), lockset_core::digest(&bytes));
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => {
                payload_errors.push(PayloadError {
                    id,
                    error: "not UTF-8".to_owned(),
                });
                continue;
            }
        };
        match meta::parse(id.clone(), &text) {
            Ok(payload) => payloads.push(payload),
            Err(error) => payload_errors.push(PayloadError {
                id,
                error: error.to_string(),
            }),
        }
    }

    let (identity, identity_error) = match context.custody.get() {
        Ok(Some(key)) => {
            let public = key.public()?;
            let label = sops.rules().iter().find_map(|rule| rule.label_of(&public));
            (
                Some(IdentityView {
                    public,
                    custody: context.custody.kind(),
                    label,
                }),
                None,
            )
        }
        Ok(None) => (None, None),
        // Read-only reports stay up; `check` records the reason as a finding.
        Err(error) => (None, Some(error.to_string())),
    };

    let mut snapshot = Snapshot::new(context.root.display().to_string(), sops, payloads, identity)
        .with_digests(digests)
        .with_payload_errors(payload_errors);
    if let Some(error) = identity_error {
        snapshot = snapshot.identity_unavailable(error);
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use lockset_core::CustodyKind;

    use super::*;

    /// Sets one variable for the test and puts the previous value back on drop.
    struct SetVar {
        name: &'static str,
        previous: Option<OsString>,
    }

    impl SetVar {
        fn new(name: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(name);
            std::env::set_var(name, value);
            Self { name, previous }
        }
    }

    impl Drop for SetVar {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(self.name, value),
                None => std::env::remove_var(self.name),
            }
        }
    }

    fn default_kind(interactive: bool) -> CustodyKind {
        default_custody(interactive).kind()
    }

    #[test]
    fn default_custody_selects_on_the_current_variable_and_the_terminal() {
        let key = SecretKey::generate();
        let guard = SetVar::new(KEY_ENV, key.expose());
        assert_eq!(default_kind(false), CustodyKind::Env);
        drop(guard);

        let guard = SetVar::new(KEY_ENV, "   ");
        assert_eq!(default_kind(true), CustodyKind::Keyring);
        assert_eq!(default_kind(false), CustodyKind::None);
        drop(guard);
    }

    #[test]
    fn an_unknown_custody_spec_is_a_usage_error() {
        let error = make_custody(Some("bogus"), Path::new("/tmp"), true)
            .err()
            .expect("an unknown custody must be refused");

        assert_eq!(usage::exit_code(&error), 2, "{error}");
        let message = error.to_string();
        assert!(message.contains("unknown custody 'bogus'"), "{message}");
        for form in ["env", "keyring", "file:<path>", "keyring:<service>"] {
            assert!(message.contains(form), "{message} does not list {form}");
        }
    }

    /// Custody that cannot answer, as a container without a session keyring.
    struct FailingCustody;

    impl Custody for FailingCustody {
        fn get(&self) -> lockset_core::Result<Option<SecretKey>> {
            Err(lockset_core::Error::failed(
                "no session keyring in this container",
            ))
        }

        fn set(&self, _key: &SecretKey) -> lockset_core::Result<()> {
            Err(lockset_core::Error::refused("read-only test custody"))
        }

        fn forget(&self) -> lockset_core::Result<()> {
            Err(lockset_core::Error::refused("read-only test custody"))
        }

        fn kind(&self) -> CustodyKind {
            CustodyKind::Keyring
        }
    }

    /// A repository with the `.sops.yaml` that `snapshot` insists on.
    struct TempRepo(PathBuf);

    impl TempRepo {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("lockset-wiring-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("secrets")).unwrap();
            std::fs::write(
                dir.join(".sops.yaml"),
                "creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x # dev-alice\n",
            )
            .unwrap();
            Self(dir)
        }
    }

    impl Drop for TempRepo {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn failing_custody_degrades_the_report_instead_of_aborting() {
        let repo = TempRepo::new("headless");
        let context = Context {
            root: repo.0.clone(),
            repo: FsRepo::new(&repo.0),
            codec: SopsCodec::new(&repo.0, "sops"),
            custody: Box::new(FailingCustody),
        };

        let snapshot = snapshot(&context).expect("a custody failure must not abort a report");

        assert!(snapshot.identity.is_none());
        assert_eq!(
            snapshot.identity_error.as_deref(),
            Some("no session keyring in this container")
        );
        let checks = lockset_core::ops::checks(&snapshot);
        let identity = checks
            .iter()
            .find(|check| check.name == "identity")
            .unwrap();
        assert!(!identity.ok);
        assert!(
            identity.detail.contains("no session keyring"),
            "{identity:?}"
        );
    }
}
