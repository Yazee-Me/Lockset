//! The exit-code contract: 0 ok, 1 findings, 2 usage/config, 3 custody/auth,
//! 4 external tool, 5 conflict/lock, 6 partial apply (covered by the unit test
//! that maps the error class; this file exercises the binary for the rest).

mod common;

use common::{lockset, lockset_with, strings, Repo};

/// No identity anywhere: custody is empty.
const KEYLESS: &str = "file:/nonexistent/lockset-exit-key";

fn keyless(rest: &[&str]) -> Vec<String> {
    let mut args = vec!["--custody".to_owned(), KEYLESS.to_owned()];
    args.extend(rest.iter().map(|arg| (*arg).to_owned()));
    args
}

/// A fresh identity: the private key for custody, the public key for the map.
fn identity() -> (String, String) {
    let key = lockset_core::SecretKey::generate();
    (
        key.expose().to_owned(),
        key.public().unwrap().as_str().to_owned(),
    )
}

fn payload(recipient: &str, extra: &str) -> String {
    format!(
        "{extra}TOKEN=ENC[a,type:str]\nsops_age__list_0__map_enc=x\nsops_age__list_0__map_recipient={recipient}\nsops_version=3.13.3\nsops_mac=ENC[a,type:str]\n"
    )
}

fn repo_with(name: &str, recipient: &str, payload: &str) -> Repo {
    let repo = Repo::new(name);
    repo.write(
        ".sops.yaml",
        &format!("creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: {recipient} # dev-alice\n"),
    );
    repo.write("secrets/dev.env", payload);
    repo
}

#[test]
fn a_clean_run_exits_zero() {
    let (_, public) = identity();
    let repo = repo_with("zero", &public, &payload(&public, ""));

    let status = lockset(&repo, &keyless(&["status"]));
    let stderr = String::from_utf8_lossy(&status.stderr);
    assert_eq!(status.status.code(), Some(0), "{stderr}");

    let plan = lockset(&repo, &keyless(&["--dry-run", "rotate", "--all"]));
    assert_eq!(
        plan.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&plan.stderr)
    );
}

#[test]
fn findings_exit_one() {
    let (secret, public) = identity();
    let repo = repo_with("one", &public, &payload(&public, "EMPTY=\n"));

    let check = lockset(&repo, &keyless(&["check"]));
    let stdout = String::from_utf8_lossy(&check.stdout);
    assert_eq!(check.status.code(), Some(1), "{stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("no empty values")),
        "{stdout}"
    );

    // `--strict` turns the same findings into the exit code.
    let strict = lockset_with(
        &repo,
        &strings(&["status", "--strict"]),
        &[("LOCKSET_AGE_KEY", &secret)],
        None,
    );
    let stderr = String::from_utf8_lossy(&strict.stderr);
    assert_eq!(strict.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("strict: 1 finding(s)"), "{stderr}");
    assert!(stderr.contains("empty values: 1"), "{stderr}");
}

#[test]
fn a_missing_identity_is_a_strict_finding() {
    let (_, public) = identity();
    let repo = repo_with("strict-identity", &public, &payload(&public, ""));

    let strict = lockset(&repo, &keyless(&["status", "--strict"]));
    let stderr = String::from_utf8_lossy(&strict.stderr);

    assert_eq!(strict.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("identity: none"), "{stderr}");
}

#[test]
fn usage_and_config_errors_exit_two() {
    let (_, public) = identity();
    let repo = repo_with("two", &public, &payload(&public, ""));

    let bad_label = lockset(
        &repo,
        &keyless(&["--dry-run", "grant", &public, "--label", "BAD"]),
    );
    assert_eq!(
        bad_label.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&bad_label.stderr)
    );

    // A directory without `.sops.yaml` is a config error, not a crash.
    let empty = std::env::temp_dir().join(format!("lockset-exit-empty-{}", std::process::id()));
    std::fs::create_dir_all(&empty).unwrap();
    let missing_repo = std::process::Command::new(env!("CARGO_BIN_EXE_lockset"))
        .args(["--repo", empty.to_str().unwrap(), "status"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&missing_repo.stderr);
    assert_eq!(missing_repo.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("no .sops.yaml"), "{stderr}");
    let _ = std::fs::remove_dir_all(empty);
}

#[test]
fn a_missing_identity_is_a_custody_error() {
    let (_, public) = identity();
    let repo = repo_with("three", &public, &payload(&public, ""));

    let output = lockset(
        &repo,
        &keyless(&["run", "--payload", "secrets/dev.env", "--", "true"]),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(stderr.contains("no identity"), "{stderr}");
}

#[test]
fn an_external_tool_failure_exits_four() {
    let (secret, public) = identity();
    let repo = repo_with("four", &public, &payload(&public, ""));

    // The helper points LOCKSET_SOPS at a path that does not exist.
    let output = lockset_with(
        &repo,
        &strings(&["run", "--payload", "secrets/dev.env", "--", "true"]),
        &[("LOCKSET_AGE_KEY", &secret)],
        None,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(4), "{stderr}");
    assert!(stderr.contains("cannot run"), "{stderr}");
}

#[test]
fn a_held_lock_exits_five() {
    let (_, public) = identity();
    let repo = repo_with("five", &public, &payload(&public, ""));
    std::fs::write(repo.path().join(".lockset.lock"), "pid 0\n").unwrap();

    let output = lockset(
        &repo,
        &keyless(&["grant", &public, "--label", "dev-b", "--lock-timeout", "1"]),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(5), "{stderr}");
    assert!(stderr.contains("another lockset"), "{stderr}");
    std::fs::remove_file(repo.path().join(".lockset.lock")).unwrap();
}

#[test]
fn check_decrypts_with_any_label_not_just_admin() {
    let (secret, public) = identity();
    // The label is "dev-alice", and the point is that the decrypt proof still
    // runs; without sops it fails as a finding rather than being skipped.
    let repo = repo_with("decrypt", &public, &payload(&public, ""));

    let output = lockset_with(
        &repo,
        &strings(&["check"]),
        &[("LOCKSET_AGE_KEY", &secret)],
        None,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("decrypts: secrets/dev.env")),
        "{stdout}"
    );
}
