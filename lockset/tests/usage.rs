//! A payload path that could leave the repository, or that an external tool
//! would read as an option, is a usage error: exit 2 before any codec call.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A repository root with the `.sops.yaml` the CLI insists on finding.
struct Repo(PathBuf);

impl Repo {
    fn new(name: &str) -> Self {
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
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn lockset(repo: &Repo, args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lockset"))
        .arg("--repo")
        .arg(repo.0.as_os_str())
        .args(args)
        // Reaching the codec would surface this path instead of the usage error.
        .env("LOCKSET_SOPS", nonexistent_sops())
        .env_remove("LOCKSET_AGE_KEY")
        .output()
        .unwrap()
}

fn nonexistent_sops() -> &'static Path {
    Path::new("/nonexistent/lockset-test-sops")
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

#[test]
fn run_refuses_bad_payloads_before_the_codec() {
    let repo = Repo::new("run");
    for payload in [
        "../key.txt",
        "secrets/../../key.txt",
        "secrets/../dev.env",
        "/etc/passwd",
        "secrets//dev.env",
        "secrets\\dev.env",
        "-x",
    ] {
        let payload_option = format!("--payload={payload}");
        let output = lockset(&repo, &strings(&["run", &payload_option, "--", "true"]));
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(
            output.status.code(),
            Some(2),
            "payload {payload} exited with {stderr}"
        );
        assert!(
            stderr.contains("invalid path") && stderr.contains(payload),
            "payload {payload} was not named: {stderr}"
        );
    }
}

#[test]
fn set_refuses_a_traversing_payload_before_the_codec() {
    let repo = Repo::new("set");
    let output = lockset(
        &repo,
        &strings(&["set", "TOKEN", "--payload", "../dev.env"]),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("invalid path"), "{stderr}");
}
