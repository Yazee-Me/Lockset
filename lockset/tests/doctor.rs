//! `doctor` preflights a repository and mutations fail early when sops is
//! missing or too old. The sops "binaries" are scripts, so the versions are
//! deterministic without a real install.

#![cfg(unix)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Output;

use common::{lockset, lockset_with, strings, Repo};

const B: &str = "age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q";

/// A script that answers `sops --version`.
struct FakeSops(PathBuf);

impl FakeSops {
    fn new(repo: &Repo, name: &str, version_line: &str) -> Self {
        let path = repo.path().join(format!("sops-{name}"));
        std::fs::write(&path, format!("#!/bin/sh\necho '{version_line}'\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self(path)
    }

    fn as_str(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for FakeSops {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A ready repository: a valid map, the default payload, and the identity that
/// is its only recipient.
fn ready(name: &str) -> (Repo, String, String) {
    let repo = Repo::new(name);
    let key = lockset_core::SecretKey::generate();
    let secret = key.expose().to_owned();
    let public = key.public().unwrap().as_str().to_owned();
    repo.write(
        ".sops.yaml",
        &format!("creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: {public} # admin\n"),
    );
    repo.write("secrets/prod/infra.env", &payload(&public));
    (repo, secret, public)
}

fn payload(recipient: &str) -> String {
    format!(
        "TOKEN=ENC[a,type:str]\nsops_age__list_0__map_enc=x\nsops_age__list_0__map_recipient={recipient}\nsops_version=3.13.3\nsops_mac=ENC[a,type:str]\n"
    )
}

fn doctor(repo: &Repo, args: &[&str], secret: Option<&str>) -> Output {
    let mut all = strings(args);
    all.extend(strings(&["doctor"]));
    match secret {
        Some(secret) => lockset_with(repo, &all, &[("LOCKSET_AGE_KEY", secret)], None),
        None => lockset(repo, &all),
    }
}

#[test]
fn doctor_passes_on_a_ready_repository() {
    let (repo, secret, _) = ready("ready");
    let sops = FakeSops::new(&repo, "good", "sops 3.13.3 (latest)");

    let output = doctor(&repo, &["--sops", sops.as_str()], Some(&secret));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{stdout}");
    for check in [
        "repo",
        "sops",
        "custody",
        "legacy identity sources",
        "CI custody policy",
        "identity",
        "coverage",
        "payloads",
        "default payload",
    ] {
        assert!(
            stdout.lines().any(|line| line.starts_with(check)),
            "missing check {check}: {stdout}"
        );
    }
    assert!(!stdout.contains("FAIL"), "{stdout}");
}

#[test]
fn doctor_names_a_missing_sops() {
    let (repo, secret, _) = ready("missing-sops");

    let output = doctor(
        &repo,
        &["--sops", "/nonexistent/lockset-sops"],
        Some(&secret),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(1), "{stdout}");
    let sops = stdout
        .lines()
        .find(|line| line.starts_with("sops"))
        .unwrap_or_else(|| panic!("no sops check: {stdout}"));
    assert!(sops.contains("FAIL"), "{sops}");
    assert!(sops.contains("install sops"), "{sops}");
}

#[test]
fn doctor_names_an_old_sops() {
    let (repo, secret, _) = ready("old-sops");
    let sops = FakeSops::new(&repo, "old", "sops 3.12.0");

    let output = doctor(&repo, &["--sops", sops.as_str()], Some(&secret));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("older than the required 3.13"), "{stdout}");
}

#[test]
fn doctor_json_is_pipeline_parseable() {
    let (repo, secret, _) = ready("json");

    let output = doctor(
        &repo,
        &["--sops", "/nonexistent/lockset-sops", "--json"],
        Some(&secret),
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(output.status.code(), Some(1), "{json}");
    assert_eq!(json["schema_version"], 1);
    let checks = json["checks"].as_array().unwrap();
    let sops = checks.iter().find(|check| check["name"] == "sops").unwrap();
    assert_eq!(sops["ok"], false);
    assert!(sops["detail"].as_str().unwrap().contains("install sops"));
}

#[test]
fn doctor_names_a_broken_config() {
    let (repo, secret, _) = ready("broken");
    repo.write(".sops.yaml", "this: is: not: yaml\n");
    let sops = FakeSops::new(&repo, "good", "sops 3.13.3");

    let output = doctor(&repo, &["--sops", sops.as_str()], Some(&secret));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(1), "{stdout}");
    let repo_line = stdout
        .lines()
        .find(|line| line.starts_with("repo"))
        .unwrap_or_else(|| panic!("no repo check: {stdout}"));
    assert!(repo_line.contains("FAIL"), "{repo_line}");
    assert!(stdout.contains("not checked"), "{stdout}");
}

#[test]
fn doctor_reports_the_ci_custody_policy() {
    let (repo, _, _) = ready("ci-policy");
    let sops = FakeSops::new(&repo, "good", "sops 3.13.3");

    // No identity source and no terminal: the default custody is "none".
    let output = doctor(&repo, &["--sops", sops.as_str()], None);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(1), "{stdout}");
    let policy = stdout
        .lines()
        .find(|line| line.starts_with("CI custody policy"))
        .unwrap();
    assert!(policy.contains("FAIL"), "{policy}");
    assert!(policy.contains("non-interactive"), "{policy}");
    let identity = stdout
        .lines()
        .find(|line| line.starts_with("identity"))
        .unwrap();
    assert!(identity.contains("FAIL"), "{identity}");
}

#[test]
fn mutations_preflight_sops_and_the_flag_wins_over_the_environment() {
    let (repo, secret, _) = ready("mutations");
    let mut before = repo.read(".sops.yaml");
    let good = FakeSops::new(&repo, "good", "sops 3.13.3");
    let old = FakeSops::new(&repo, "old", "sops 3.12.0");

    // Missing: exit 4, the actionable preflight message, and no write.
    let missing = lockset_with(
        &repo,
        &strings(&[
            "--sops",
            "/nonexistent/lockset-sops",
            "grant",
            B,
            "--label",
            "dev-b",
        ]),
        &[("LOCKSET_AGE_KEY", &secret)],
        None,
    );
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert_eq!(missing.status.code(), Some(4), "{stderr}");
    assert!(stderr.contains("install sops"), "{stderr}");
    assert_eq!(repo.read(".sops.yaml"), before);

    // Too old: exit 4 and the same guarantee.
    let old_run = lockset_with(
        &repo,
        &strings(&["--sops", old.as_str(), "grant", B, "--label", "dev-b"]),
        &[("LOCKSET_AGE_KEY", &secret)],
        None,
    );
    let stderr = String::from_utf8_lossy(&old_run.stderr);
    assert_eq!(old_run.status.code(), Some(4), "{stderr}");
    assert!(stderr.contains("older than the required 3.13"), "{stderr}");
    assert_eq!(repo.read(".sops.yaml"), before);

    // A dry run does not preflight at all.
    let dry = lockset_with(
        &repo,
        &strings(&[
            "--sops",
            "/nonexistent/lockset-sops",
            "--dry-run",
            "grant",
            B,
            "--label",
            "dev-b",
        ]),
        &[("LOCKSET_AGE_KEY", &secret)],
        None,
    );
    assert_eq!(
        dry.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&dry.stderr)
    );

    // `--sops` wins over the environment, so the mutation lands.
    let good_run = lockset_with(
        &repo,
        &strings(&["--sops", good.as_str(), "grant", B, "--label", "dev-b"]),
        &[("LOCKSET_AGE_KEY", &secret)],
        None,
    );
    let stderr = String::from_utf8_lossy(&good_run.stderr);
    assert_eq!(good_run.status.code(), Some(0), "{stderr}");
    before.push_str("");
    assert!(repo.read(".sops.yaml").contains(B));
}
