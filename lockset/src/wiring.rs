use std::path::{Path, PathBuf};

use anyhow::{bail, Context as AnyhowContext, Result};
use lockset_core::sopsfile::SopsFile;
use lockset_core::{meta, Custody, IdentityView, PathId, Repo, SecretKey, Snapshot};
use lockset_tools::custody::{EnvCustody, FileCustody, KeyringCustody};
use lockset_tools::fs_repo::FsRepo;
use lockset_tools::sops::SopsCodec;

use crate::cli::Cli;

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
        Some("env") => env_custody(),
        Some("keyring") => keyring_custody(),
        Some(other) if other.starts_with("file:") => {
            Box::new(FileCustody::new(&other["file:".len()..]))
        }
        Some("keyring:") => keyring_custody(),
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
    if env_is_set(KEY_ENV) {
        env_custody()
    } else {
        keyring_custody()
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

    fn default_kind() -> CustodyKind {
        default_custody().kind()
    }

    #[test]
    fn default_custody_selects_on_the_current_variable_only() {
        let key = SecretKey::generate();
        let guard = SetVar::new(KEY_ENV, key.expose());
        assert_eq!(default_kind(), CustodyKind::Env);
        drop(guard);

        let guard = SetVar::new(KEY_ENV, "   ");
        assert_eq!(default_kind(), CustodyKind::Keyring);
        drop(guard);
    }
}
