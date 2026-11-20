//! Shared harness for the CLI integration tests: a throwaway repository and a
//! runner that keeps the codec out of reach.
#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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

    /// Write a repository file, creating its directories.
    pub fn write(&self, relative: &str, contents: &str) {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    /// Read a repository file back.
    pub fn read(&self, relative: &str) -> String {
        fs::read_to_string(self.0.join(relative)).unwrap()
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn lockset(repo: &Repo, args: &[String]) -> Output {
    lockset_with(repo, args, &[], None)
}

/// Run the binary with extra environment and, when given, text on stdin. A
/// missing stdin is closed, as a pipeline with nothing to say would be.
pub fn lockset_with(
    repo: &Repo,
    args: &[String],
    env: &[(&str, &str)],
    stdin: Option<&str>,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lockset"));
    command
        .arg("--repo")
        .arg(repo.0.as_os_str())
        .args(args)
        // Reaching the codec would surface this path instead of the expected error.
        .env("LOCKSET_SOPS", "/nonexistent/lockset-test-sops")
        .env_remove("LOCKSET_AGE_KEY")
        .envs(env.iter().copied());

    match stdin {
        None => command.output().unwrap(),
        Some(text) => {
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command.spawn().unwrap();
            let mut stdin = child.stdin.take().unwrap();
            if let Err(error) = stdin.write_all(text.as_bytes()) {
                // The command may reject its arguments and exit before it
                // reads stdin, which closes the pipe. The caller asserts the
                // exit status and output, so only a real write error fails.
                match error.kind() {
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset => {}
                    _ => panic!("writing stdin: {error}"),
                }
            }
            drop(stdin);
            child.wait_with_output().unwrap()
        }
    }
}

pub fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}
