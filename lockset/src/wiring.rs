use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as AnyhowContext, Result};
use lockset_core::config::{Config, CustodySpec};
use lockset_core::sopsfile::SopsFile;
use lockset_core::{meta, Custody, IdentityView, PathId, PayloadError, Repo, SecretKey, Snapshot};
use lockset_tools::custody::{EnvCustody, FileCustody, KeyringCustody, UnconfiguredCustody};
use lockset_tools::fs_repo::FsRepo;
use lockset_tools::lock::Lock;
use lockset_tools::sops::SopsCodec;

use crate::cli::{Cli, Command};
use crate::inputs::Inputs;
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
    /// The config file, when one was read; `None` for the implicit default.
    pub config_path: Option<PathBuf>,
    /// The config file's bytes, kept so a registry edit can plan a rewrite
    /// without reading the file again.
    pub config_text: Option<String>,
}

/// The variable that selects custody when no flag does.
pub const CUSTODY_ENV: &str = "LOCKSET_CUSTODY";

impl Context {
    /// Build the context from the parsed arguments and the injected inputs;
    /// nothing here reads the process environment.
    pub fn detect(cli: &Cli, inputs: &Inputs) -> Result<Self> {
        let root = find_root(repo_start(cli, inputs), inputs.cwd())?;
        let LoadedConfig {
            config,
            path: config_path,
            text: config_text,
        } = load_config(cli.config.as_deref(), &root, inputs)?;
        let spec = custody_spec(cli, inputs);
        let custody = make_custody(
            spec.as_deref(),
            &root,
            inputs.is_interactive(),
            &config,
            inputs,
        )?;
        let codec = SopsCodec::new(
            &root,
            sops_bin(cli, &config, inputs),
            config.codec.min_version,
        )
        .with_config(config.sops_config.clone())
        .with_environment(inputs.vars_os())
        .with_editor(
            inputs
                .var("SOPS_EDITOR")
                .unwrap_or(lockset_tools::sops::DEFAULT_EDITOR),
        );
        Ok(Self {
            repo: FsRepo::new(&root),
            codec,
            root,
            custody,
            config,
            config_path,
            config_text,
        })
    }

    pub fn require_key(&self) -> Result<SecretKey> {
        let kind = self.custody.kind();
        self.custody.get()?.ok_or_else(|| match kind {
            lockset_core::CustodyKind::None => {
                anyhow::Error::new(lockset_core::Error::custody(format!(
                    "no identity source is configured; set {}, set LOCKSET_CUSTODY, or pass \
                     --custody file:<path>",
                    self.config.custody.env
                )))
            }
            kind => anyhow::Error::new(lockset_core::Error::custody(format!(
                "no identity in custody ({kind})"
            ))),
        })
    }
}

/// `--repo`, then `LOCKSET_REPO`, then the working directory.
fn repo_start(cli: &Cli, inputs: &Inputs) -> Option<PathBuf> {
    cli.repo
        .clone()
        .or_else(|| inputs.var("LOCKSET_REPO").map(PathBuf::from))
}

/// `--sops`, then `LOCKSET_SOPS`, then `codec.sops`, then the sops on PATH.
fn sops_bin(cli: &Cli, config: &Config, inputs: &Inputs) -> String {
    cli.sops
        .as_ref()
        .map(|path| path.display().to_string())
        .or_else(|| inputs.var("LOCKSET_SOPS").map(str::to_owned))
        .unwrap_or_else(|| config.codec.sops.clone())
}

/// A config file that was read, plus its bytes so a registry edit can plan a
/// rewrite from the same snapshot.
struct LoadedConfig {
    config: Config,
    path: Option<PathBuf>,
    text: Option<String>,
}

/// `--config`, then `LOCKSET_CONFIG`, then `<root>/lockset.toml`. An explicit
/// file must exist; the implicit one is optional.
fn load_config(explicit: Option<&Path>, root: &Path, inputs: &Inputs) -> Result<LoadedConfig> {
    let (path, required) = match explicit {
        Some(path) => (path.to_path_buf(), true),
        None => match inputs.var("LOCKSET_CONFIG") {
            Some(value) => (PathBuf::from(value), true),
            None => (root.join(CONFIG_FILE), false),
        },
    };
    if !path.is_file() {
        if !required {
            return Ok(LoadedConfig {
                config: Config::default(),
                path: None,
                text: None,
            });
        }
        return Err(usage::error(format!(
            "no such config file: {} (--config or LOCKSET_CONFIG)",
            path.display()
        )));
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|error| usage::error(format!("cannot read {}: {error}", path.display())))?;
    let config = Config::parse(&text)
        .map_err(|error| usage::error(format!("{}: {error}", path.display())))?;
    Ok(LoadedConfig {
        config,
        path: Some(path),
        text: Some(text),
    })
}

fn find_root(start: Option<PathBuf>, cwd: &Path) -> Result<PathBuf> {
    let start = start.unwrap_or_else(|| cwd.to_path_buf());
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

/// `--custody`, then `LOCKSET_CUSTODY`, then the identity environment variable,
/// then `custody.kind`, then the default: the keychain on a terminal and
/// nothing otherwise — a container must not be handed whichever key a keychain
/// happens to hold, nor be made to fail when it holds none.
fn custody_spec(cli: &Cli, inputs: &Inputs) -> Option<String> {
    cli.custody
        .clone()
        .or_else(|| inputs.var(CUSTODY_ENV).map(str::to_owned))
        .filter(|value| !value.trim().is_empty())
}

fn make_custody(
    spec: Option<&str>,
    root: &Path,
    interactive: bool,
    config: &Config,
    inputs: &Inputs,
) -> Result<Box<dyn Custody>> {
    if let Some(spec) = spec {
        return build_custody(&CustodySpec::parse(spec)?, root, config, inputs);
    }
    if inputs.var_is_set(&config.custody.env) {
        return Ok(env_custody(&config.custody.env, inputs));
    }
    if config.custody.kind == "auto" {
        return Ok(if interactive {
            keyring_custody(config, &config.custody.keychain_item, inputs)
        } else {
            Box::new(UnconfiguredCustody)
        });
    }
    // Validated at load time; parsing again keeps one code path for every form.
    let spec = CustodySpec::parse(&config.custody.kind)
        .map_err(|error| usage::error(format!("custody.kind: {error}")))?;
    build_custody(&spec, root, config, inputs)
}

fn build_custody(
    spec: &CustodySpec,
    root: &Path,
    config: &Config,
    inputs: &Inputs,
) -> Result<Box<dyn Custody>> {
    Ok(match spec {
        CustodySpec::Env(None) => env_custody(&config.custody.env, inputs),
        CustodySpec::Env(Some(name)) => env_custody(name, inputs),
        CustodySpec::Keyring(None) => {
            keyring_custody(config, &config.custody.keychain_item, inputs)
        }
        CustodySpec::Keyring(Some(service)) => keyring_custody(config, service, inputs),
        CustodySpec::File(path) => Box::new(FileCustody::new(path, root)?),
        CustodySpec::None => Box::new(UnconfiguredCustody),
    })
}

fn env_custody(var: &str, inputs: &Inputs) -> Box<dyn Custody> {
    Box::new(EnvCustody::new(var).with_environment(inputs.vars_os()))
}

fn keyring_custody(config: &Config, service: &str, inputs: &Inputs) -> Box<dyn Custody> {
    Box::new(keyring_entry(config, service, inputs))
}

fn keyring_entry(config: &Config, service: &str, inputs: &Inputs) -> KeyringCustody {
    KeyringCustody::new(service, keychain_account(config, inputs))
}

/// The account a per-repo keychain item lives under: `custody.keychain_account`
/// when set, else the current user, as the injected environment names them.
fn keychain_account(config: &Config, inputs: &Inputs) -> String {
    config
        .custody
        .keychain_account
        .clone()
        .unwrap_or_else(|| current_user(inputs))
}

fn current_user(inputs: &Inputs) -> String {
    inputs
        .var("USER")
        .or_else(|| inputs.var("LOGNAME"))
        .or_else(|| inputs.var("USERNAME"))
        .unwrap_or("lockset")
        .to_owned()
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

/// `path` as a repo-relative `PathId`, when it names a file inside `root`.
/// A config outside the repository has no `PathId`; read-only commands still
/// run, and only a registry edit refuses.
fn repo_relative(path: &Path, root: &Path) -> Option<PathId> {
    let absolute = path.canonicalize().ok()?;
    let relative = absolute.strip_prefix(root).ok()?;
    PathId::parse(&relative.to_string_lossy().replace('\\', "/")).ok()
}

pub fn snapshot(context: &Context) -> Result<Snapshot> {
    let mut digests = std::collections::BTreeMap::new();

    let config_document = match (&context.config_path, &context.config_text) {
        (Some(path), Some(text)) => repo_relative(path, &context.root).map(|id| {
            digests.insert(id.clone(), lockset_core::digest(text.as_bytes()));
            (id, text.clone())
        }),
        _ => None,
    };

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
    if let Some((path, text)) = config_document {
        snapshot = snapshot.with_config_document(path, text);
    }
    if let Some(error) = identity_error {
        snapshot = snapshot.identity_unavailable(error);
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use lockset_core::CustodyKind;

    use super::*;

    fn headless() -> Inputs {
        Inputs::default()
    }

    fn default_kind(inputs: &Inputs) -> CustodyKind {
        make_custody(
            None,
            Path::new("/tmp"),
            inputs.is_interactive(),
            &Config::default(),
            inputs,
        )
        .expect("the default custody resolves")
        .kind()
    }

    #[test]
    fn default_custody_selects_on_the_injected_variable_and_the_terminal() {
        let key = SecretKey::generate();

        let with_key = headless().with_var(KEY_ENV, key.expose());
        assert_eq!(default_kind(&with_key), CustodyKind::Env);

        let blank_on_a_terminal = headless().with_var(KEY_ENV, "   ").interactive(true);
        assert_eq!(default_kind(&blank_on_a_terminal), CustodyKind::Keyring);

        let blank_headless = headless().with_var(KEY_ENV, "   ");
        assert_eq!(default_kind(&blank_headless), CustodyKind::None);
    }

    #[test]
    fn an_unknown_custody_spec_is_a_usage_error() {
        let error = make_custody(
            Some("bogus"),
            Path::new("/tmp"),
            true,
            &Config::default(),
            &headless(),
        )
        .err()
        .expect("an unknown custody must be refused");

        assert_eq!(usage::exit_code(&error), 2, "{error}");
        let message = error.to_string();
        assert!(message.contains("unknown custody 'bogus'"), "{message}");
        for form in [
            "env:<NAME>",
            "keyring",
            "file:<absolute path>",
            "keyring:<service>",
        ] {
            assert!(message.contains(form), "{message} does not list {form}");
        }
    }

    #[test]
    fn an_env_name_reads_that_injected_variable() {
        let first = SecretKey::generate();
        let second = SecretKey::generate();
        let inputs = headless()
            .with_var("LOCKSET_TEST_KEY_A", first.expose())
            .with_var("LOCKSET_TEST_KEY_B", second.expose())
            .with_var(KEY_ENV, second.expose());

        let custody = make_custody(
            Some("env:LOCKSET_TEST_KEY_A"),
            Path::new("/tmp"),
            false,
            &Config::default(),
            &inputs,
        )
        .unwrap();
        let key = custody
            .get()
            .unwrap()
            .expect("the named variable holds a key");

        assert_eq!(key.public().unwrap(), first.public().unwrap());
        assert_ne!(key.public().unwrap(), second.public().unwrap());
    }

    #[test]
    fn the_flag_wins_over_lockset_custody() {
        let inputs = headless().with_var(CUSTODY_ENV, "env:FROM_ENV");

        let plain = Cli::parse_from(["lockset", "status"]);
        assert_eq!(
            custody_spec(&plain, &inputs).as_deref(),
            Some("env:FROM_ENV")
        );

        let flagged = Cli::parse_from(["lockset", "--custody", "env:FROM_FLAG", "status"]);
        assert_eq!(
            custody_spec(&flagged, &inputs).as_deref(),
            Some("env:FROM_FLAG")
        );
    }

    #[test]
    fn an_empty_lockset_custody_is_unset() {
        let inputs = headless().with_var(CUSTODY_ENV, "   ");
        let cli = Cli::parse_from(["lockset", "status"]);

        assert_eq!(custody_spec(&cli, &inputs), None);
    }

    #[test]
    fn a_config_kind_applies_off_a_terminal() {
        let inputs = headless();
        let config = Config::parse("[custody]\nkind = \"none\"\n").unwrap();
        assert_eq!(
            make_custody(None, Path::new("/tmp"), false, &config, &inputs)
                .unwrap()
                .kind(),
            CustodyKind::None
        );

        let config = Config::parse("[custody]\nkind = \"keyring\"\n").unwrap();
        assert_eq!(
            make_custody(None, Path::new("/tmp"), false, &config, &inputs)
                .unwrap()
                .kind(),
            CustodyKind::Keyring,
            "an explicit config kind applies to non-interactive runs"
        );
    }

    #[test]
    fn the_identity_variable_wins_over_the_config_kind() {
        let key = SecretKey::generate();
        let inputs = headless().with_var(KEY_ENV, key.expose());
        let config = Config::parse("[custody]\nkind = \"none\"\n").unwrap();

        assert_eq!(
            make_custody(None, Path::new("/tmp"), false, &config, &inputs)
                .unwrap()
                .kind(),
            CustodyKind::Env
        );
    }

    #[test]
    fn a_config_env_name_selects_that_variable() {
        let key = SecretKey::generate();
        let inputs = headless().with_var("LOCKSET_TEST_CONFIG_KEY", key.expose());
        let config = Config::parse("[custody]\nkind = \"env:LOCKSET_TEST_CONFIG_KEY\"\n").unwrap();

        let custody = make_custody(None, Path::new("/tmp"), false, &config, &inputs).unwrap();

        assert_eq!(custody.kind(), CustodyKind::Env);
        assert_eq!(
            custody
                .get()
                .unwrap()
                .expect("the configured variable")
                .public()
                .unwrap(),
            key.public().unwrap()
        );
    }

    #[test]
    fn a_per_repo_keychain_item_and_account_are_used() {
        let inputs = headless().with_var("USER", "dev");
        let config = Config::parse(
            "[custody]\nkind = \"keyring\"\nkeychain_item = \"lockset-age-key-app\"\nkeychain_account = \"ci\"\n",
        )
        .unwrap();

        let entry = keyring_entry(&config, &config.custody.keychain_item, &inputs);
        assert_eq!(entry.service(), "lockset-age-key-app");
        assert_eq!(entry.account(), "ci");

        // An explicit `keyring:<service>` keeps the configured account.
        let entry = keyring_entry(&config, "shared-item", &inputs);
        assert_eq!(entry.service(), "shared-item");
        assert_eq!(entry.account(), "ci");

        // Without an account the injected user names it.
        let default_account = Config::default();
        let entry = keyring_entry(&default_account, "item", &inputs);
        assert_eq!(entry.account(), "dev");
    }

    #[test]
    fn a_repository_root_can_come_from_a_sops_config_or_a_config_file() {
        let repo = TempRepo::new("root");
        let cli = Cli::parse_from(["lockset", "status"]);
        let root = find_root(None, &repo.0).expect("the root is found");

        assert_eq!(root, repo.0.canonicalize().unwrap());
        assert_eq!(repo_start(&cli, &headless()), None);
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
            config_path: None,
            config_text: None,
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
