//! Shared harness for the CLI integration tests: a throwaway repository and a
//! runner that keeps the codec out of reach.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A repository root with the `.sops.yaml` the CLI insists on finding.
pub struct Repo(PathBuf);

impl Repo {
    pub fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("lockset-usage-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(".sops.yaml"),
            "creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n",
        )
        .unwrap();
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn sops_path(&self) -> PathBuf {
        self.0.join(".sops.yaml")
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn lockset(repo: &Repo, args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lockset"))
        .arg("--repo")
        .arg(repo.0.as_os_str())
        .args(args)
        // Reaching the codec would surface this path instead of the expected error.
        .env("LOCKSET_SOPS", "/nonexistent/lockset-test-sops")
        .env_remove("LOCKSET_AGE_KEY")
        .output()
        .unwrap()
}

pub fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}
