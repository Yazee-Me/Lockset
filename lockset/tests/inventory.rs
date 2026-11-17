//! One malformed payload is a finding, not an abort, and symlinks cannot
//! duplicate or loop the payload inventory.

#![cfg(unix)]
mod common;

use common::{lockset, lockset_with, strings, Repo};

const A: &str = "age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x";

/// No identity: these reports must not need one.
const KEYLESS: &str = "file:/nonexistent/lockset-inventory-key";

fn keyless(rest: &[&str]) -> Vec<String> {
    let mut args = vec!["--custody".to_owned(), KEYLESS.to_owned()];
    args.extend(rest.iter().map(|arg| (*arg).to_owned()));
    args
}

fn encrypted(recipient: &str) -> String {
    format!(
        "TOKEN=ENC[a,type:str]\nsops_age__list_0__map_enc=x\nsops_age__list_0__map_recipient={recipient}\nsops_version=3.13.3\nsops_mac=ENC[a,type:str]\n"
    )
}

fn repo_with(name: &str) -> Repo {
    let repo = Repo::new(name);
    repo.write(
        ".sops.yaml",
        &format!("creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: {A} # admin\n"),
    );
    repo
}

#[test]
fn one_bad_payload_does_not_block_the_reports() {
    let repo = repo_with("bad-payload");
    repo.write("secrets/good.env", &encrypted(A));
    repo.write("secrets/bad.env", &encrypted("not-a-key"));

    let status = lockset(&repo, &strings(&["status"]));
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert_eq!(status.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("secrets/good.env"), "{stdout}");
    assert!(stdout.contains("unreadable payloads: 1"), "{stdout}");
    assert!(
        stdout.contains("secrets/bad.env: not an x25519 age public key"),
        "{stdout}"
    );

    let who = lockset(&repo, &strings(&["who"]));
    assert_eq!(
        who.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&who.stderr)
    );

    let check = lockset(&repo, &strings(&["check"]));
    let stdout = String::from_utf8_lossy(&check.stdout);
    assert_eq!(check.status.code(), Some(1), "{stdout}");
    let parse = stdout
        .lines()
        .find(|line| line.starts_with("payloads parse"))
        .unwrap_or_else(|| panic!("no parse check in: {stdout}"));
    assert!(parse.contains("FAIL"), "{parse}");
    assert!(parse.contains("secrets/bad.env"), "{parse}");
    assert!(parse.contains("not an x25519 age public key"), "{parse}");
}

#[test]
fn a_bad_payload_does_not_block_an_unrelated_operation() {
    let repo = repo_with("unrelated");
    repo.write("secrets/good.env", &encrypted(A));
    repo.write("secrets/bad.env", &encrypted("not-a-key"));

    let rotate = lockset(&repo, &keyless(&["--dry-run", "rotate", "--all"]));
    let stdout = String::from_utf8_lossy(&rotate.stdout);
    assert_eq!(rotate.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains("would rotate the data key of secrets/good.env"),
        "{stdout}"
    );
    assert!(!stdout.contains("bad.env"), "{stdout}");

    let set_good = lockset_with(
        &repo,
        &keyless(&[
            "--dry-run",
            "set",
            "TOKEN",
            "--payload",
            "secrets/good.env",
            "--stdin",
        ]),
        &[],
        Some("v"),
    );
    assert_eq!(
        set_good.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&set_good.stderr)
    );

    let set_bad = lockset_with(
        &repo,
        &keyless(&[
            "--dry-run",
            "set",
            "TOKEN",
            "--payload",
            "secrets/bad.env",
            "--stdin",
        ]),
        &[],
        Some("v"),
    );
    let stderr = String::from_utf8_lossy(&set_bad.stderr);
    // A payload that cannot be parsed is a config error for a targeted command.
    assert_eq!(set_bad.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("cannot use secrets/bad.env"), "{stderr}");
    assert!(stderr.contains("not an x25519 age public key"), "{stderr}");
}

#[cfg(unix)]
#[test]
fn symlinks_cannot_duplicate_or_loop_payloads() {
    use std::os::unix::fs::symlink;

    let repo = repo_with("symlinks");
    repo.write("secrets/dev.env", &encrypted(A));
    symlink("dev.env", repo.path().join("secrets/link.env")).unwrap();
    symlink(".", repo.path().join("secrets/self")).unwrap();

    let status = lockset(&repo, &strings(&["status"]));
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert_eq!(status.status.code(), Some(0), "{stdout}");
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.starts_with("secrets/dev.env"))
            .count(),
        1,
        "the payload must be listed once: {stdout}"
    );
    assert!(!stdout.contains("link.env"), "{stdout}");
    assert!(!stdout.contains("self"), "{stdout}");

    let rotate = lockset(&repo, &keyless(&["--dry-run", "rotate", "--all"]));
    let stdout = String::from_utf8_lossy(&rotate.stdout);
    assert_eq!(rotate.status.code(), Some(0), "{stdout}");
    assert_eq!(
        stdout
            .matches("would rotate the data key of secrets/dev.env")
            .count(),
        1,
        "{stdout}"
    );
}
