use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as AnyhowContext, Result};
use lockset_core::config::Config;
use lockset_core::sopsfile::SopsFile;
use lockset_core::{meta, Custody, IdentityView, PayloadError, Repo, SecretKey, Snapshot};
use lockset_tools::custody::{EnvCustody, FileCustody, KeyringCustody, UnconfiguredCustody};
use lockset_tools::fs_repo::FsRepo;
use lockset_tools::lock::Lock;
use lockset_tools::sops::SopsCodec;

use crate::cli::{Cli, Command};
use crate::usage;

/// The identity variable the tests drive the default custody through.
#[cfg(test)]
const KEY_ENV: &str = lockset_core::config::DEFAULT_KEY_ENV;

/// The file name `lockset` reads at the repository root when no flag or
/// environment names one.
pub const CONFIG_FILE: &str = "lockset.toml";

pub struct Context {
    pub root: PathBuf,
    pub repo: FsRepo,
    pub codec: SopsCodec,
    pub custody: Box<dyn Custody>,
    pub config: Config,
}

impl Context {
    pub fn detect(cli: &Cli) -> Result<Self> {
        let root = find_root(repo_start(cli))?;
        let config = load_config(cli.config.as_deref(), &root)?;
        let interactive = std::io::stdin().is_terminal();
        let custody = make_custody(cli.custody.as_deref(), &root, interactive, &config)?;
        let codec = SopsCodec::new(&root, sops_bin(cli, &config), config.codec.min_version)
            .with_config(config.sops_config.clone());
        log::debug!("repository root {}", root.display());
        log::debug!("custody {}", custody.kind());
        log::debug!("sops {}", codec.bin());
        log::debug!("sops config {}", config.sops_config);
        Ok(Self {
            repo: FsRepo::new(&root),
            codec,
            root,
            custody,
            config,
        })
    }

    pub fn require_key(&self) -> Result<SecretKey> {
        let kind = self.custody.kind();
        self.custody.get()?.ok_or_else(|| match kind {
            lockset_core::CustodyKind::None => {
                anyhow::Error::new(lockset_core::Error::custody(format!(
                    "no identity source is configured; set {} or pass --custody file:<path>",
                    self.config.custody.env
                )))
            }
            kind => anyhow::Error::new(lockset_core::Error::custody(format!(
                "no identity in custody ({kind})"
            ))),
        })
    }
}

/// `--repo`, then `LOCKSET_REPO`, then the current directory.
fn repo_start(cli: &Cli) -> Option<PathBuf> {
    cli.repo
        .clone()
        .or_else(|| std::env::var_os("LOCKSET_REPO").map(PathBuf::from))
}

/// `--sops`, then `LOCKSET_SOPS`, then `codec.sops`, then the sops on PATH.
fn sops_bin(cli: &Cli, config: &Config) -> String {
    cli.sops
        .as_ref()
        .map(|path| path.display().to_string())
        .or_else(|| std::env::var("LOCKSET_SOPS").ok())
        .unwrap_or_else(|| config.codec.sops.clone())
}

/// `--config`, then `LOCKSET_CONFIG`, then `<root>/lockset.toml`. An explicit
/// file must exist; the implicit one is optional.
fn load_config(explicit: Option<&Path>, root: &Path) -> Result<Config> {
    let (path, required) = match explicit {
        Some(path) => (path.to_path_buf(), true),
        None => match std::env::var_os("LOCKSET_CONFIG") {
            Some(value) => (PathBuf::from(value), true),
            None => (root.join(CONFIG_FILE), false),
        },
    };
    if !path.is_file() {
        if !required {
            return Ok(Config::default());
        }
        return Err(usage::error(format!(
            "no such config file: {} (--config or LOCKSET_CONFIG)",
            path.display()
        )));
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|error| usage::error(format!("cannot read {}: {error}", path.display())))?;
    Config::parse(&text).map_err(|error| usage::error(format!("{}: {error}", path.display())))
}

fn find_root(start: Option<PathBuf>) -> Result<PathBuf> {
    let start = match start {
        Some(dir) => dir,
        None => std::env::current_dir().context("cannot resolve the current directory")?,
    };
    let mut dir = start
        .canonicalize()
        .with_context(|| format!("cannot resolve {}", start.display()))?;
    loop {
        if dir.join(".sops.yaml").is_file() || dir.join(CONFIG_FILE).is_file() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err(usage::error(
                "no .sops.yaml or lockset.toml found above the start directory; pass --repo",
            ));
        }
    }
}

/// `--custody`, then the identity environment variable, then `custody.kind`,
/// then the default: the keychain on a terminal and nothing otherwise — a
/// container must not be handed whichever key a keychain happens to hold, nor
/// be made to fail when it holds none.
fn make_custody(
    spec: Option<&str>,
    root: &Path,
    interactive: bool,
    config: &Config,
) -> Result<Box<dyn Custody>> {
    let kind = match spec {
        Some(kind) => kind.to_owned(),
        None if env_is_set(&config.custody.env) => return Ok(env_custody(&config.custody.env)),
        None => config.custody.kind.clone(),
    };
    if spec.is_none() && kind == "auto" {
        return Ok(if interactive {
            keyring_custody(config)
        } else {
            Box::new(UnconfiguredCustody)
        });
    }
    from_kind(&kind, root, config)
}

fn from_kind(kind: &str, root: &Path, config: &Config) -> Result<Box<dyn Custody>> {
    Ok(match kind {
        "env" => env_custody(&config.custody.env),
        "keyring" | "keyring:" => keyring_custody(config),
        "none" => Box::new(UnconfiguredCustody),
        other if other.starts_with("file:") => {
            Box::new(FileCustody::new(&other["file:".len()..], root)?)
        }
        other if other.starts_with("keyring:") => Box::new(KeyringCustody::new(
            &other["keyring:".len()..],
            current_user(),
        )),
        other => {
            return Err(usage::error(format!(
                "unknown custody '{other}'; use env, keyring, file:<path>, or keyring:<service>"
            )))
        }
    })
}

fn env_is_set(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| !value.trim().is_empty())
}

fn env_custody(var: &str) -> Box<dyn Custody> {
    Box::new(EnvCustody::new(var))
}

fn keyring_custody(config: &Config) -> Box<dyn Custody> {
    Box::new(KeyringCustody::new(
        &config.custody.keychain_item,
        current_user(),
    ))
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

    let sops_path = context.config.sops_config.clone();
    let sops_bytes = context.repo.read(&sops_path)?;
    digests.insert(sops_path.clone(), lockset_core::digest(&sops_bytes));
    let sops_text =
        String::from_utf8(sops_bytes).with_context(|| format!("{} is not UTF-8", sops_path))?;
    let sops = SopsFile::parse(&sops_text)?;

    let mut payloads = Vec::new();
    let mut payload_errors = Vec::new();
    for id in context.repo.walk()? {
        if !context.config.payload_globs.matches(id.as_str()) {
            continue;
        }
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
        .with_registry(context.config.registry.clone())
        .with_sops_path(sops_path)
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
        make_custody(None, Path::new("/tmp"), interactive, &Config::default())
            .expect("the default custody resolves")
            .kind()
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
        let error = make_custody(Some("bogus"), Path::new("/tmp"), true, &Config::default())
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
            codec: SopsCodec::new(&repo.0, "sops", lockset_core::MIN_VERSION),
            custody: Box::new(FailingCustody),
            config: Config::default(),
        };

        let snapshot = snapshot(&context).expect("a custody failure must not abort a report");

        assert!(snapshot.identity.is_none());
        assert_eq!(
            snapshot.identity_error.as_deref(),
            Some("no session keyring in this container")
        );
        let checks = lockset_core::ops::checks(&snapshot, &Config::default().labels);
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
