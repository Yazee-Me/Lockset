use std::path::{Path, PathBuf};

use anyhow::{bail, Context as AnyhowContext, Result};
use yzs_core::sopsfile::SopsFile;
use yzs_core::{meta, Custody, IdentityView, PathId, Repo, SecretKey, Snapshot};
use yzs_tools::custody::{EnvCustody, FileCustody, KeyringCustody};
use yzs_tools::fs_repo::FsRepo;
use yzs_tools::sops::SopsCodec;

use crate::cli::Cli;

pub const DEFAULT_KEYCHAIN_ITEM: &str = "yazee-age-key";
pub const KEY_ENV: &str = "YAZEE_AGE_KEY";

pub struct Context {
    pub root: PathBuf,
    pub repo: FsRepo,
    pub codec: SopsCodec,
    pub custody: Box<dyn Custody>,
}

impl Context {
    pub fn detect(cli: &Cli) -> Result<Self> {
        let root = find_root(cli.repo.as_deref())?;
        let custody = make_custody(cli.custody.as_deref());
        Ok(Self {
            repo: FsRepo::new(&root),
            codec: SopsCodec::new(&root),
            root,
            custody,
        })
    }

    pub fn require_key(&self) -> Result<SecretKey> {
        self.custody
            .get()?
            .ok_or_else(|| anyhow::anyhow!("no identity in custody ({})", self.custody.kind()))
    }
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
            bail!("no .sops.yaml found above the start directory; pass --repo");
        }
    }
}

fn make_custody(spec: Option<&str>) -> Box<dyn Custody> {
    match spec {
        Some("env") => Box::new(EnvCustody::new(KEY_ENV)),
        Some("keyring") => Box::new(keyring_custody()),
        Some(other) if other.starts_with("file:") => {
            Box::new(FileCustody::new(&other["file:".len()..]))
        }
        Some("keyring:") => Box::new(keyring_custody()),
        Some(other) if other.starts_with("keyring:") => Box::new(KeyringCustody::new(
            &other["keyring:".len()..],
            current_user(),
        )),
        Some(other) => {
            eprintln!("unknown custody '{other}'; using the default");
            default_custody()
        }
        None => default_custody(),
    }
}

fn default_custody() -> Box<dyn Custody> {
    match std::env::var(KEY_ENV) {
        Ok(value) if !value.trim().is_empty() => Box::new(EnvCustody::new(KEY_ENV)),
        _ => Box::new(keyring_custody()),
    }
}

fn keyring_custody() -> KeyringCustody {
    KeyringCustody::new(DEFAULT_KEYCHAIN_ITEM, current_user())
}

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "yzs".to_owned())
}

pub fn snapshot(context: &Context) -> Result<Snapshot> {
    let sops_text = String::from_utf8(context.repo.read(&PathId::new(".sops.yaml"))?)
        .context(".sops.yaml is not UTF-8")?;
    let sops = SopsFile::parse(&sops_text)?;

    let mut payloads = Vec::new();
    for id in context.repo.list("secrets")? {
        let text = String::from_utf8(context.repo.read(&id)?)
            .with_context(|| format!("{id} is not UTF-8"))?;
        payloads.push(meta::parse(id, &text)?);
    }

    let identity = match context.custody.get()? {
        Some(key) => {
            let public = key.public()?;
            let label = sops.rules().iter().find_map(|rule| rule.label_of(&public));
            Some(IdentityView {
                public,
                custody: context.custody.kind(),
                label,
            })
        }
        None => None,
    };

    Ok(Snapshot::new(
        context.root.display().to_string(),
        sops,
        payloads,
        identity,
    ))
}
