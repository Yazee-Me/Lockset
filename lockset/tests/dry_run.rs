//! `--dry-run` renders every mutating plan without an identity and changes
//! nothing; the key is required only to apply.

mod common;

use std::path::PathBuf;

use common::{lockset, lockset_with, Repo};

const A: &str = "age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x";
const B: &str = "age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q";

/// A custody path that cannot hold a key, so the run is identity-less.
const KEYLESS: &str = "file:/nonexistent/lockset-dry-run-key";

fn keyless(rest: &[&str]) -> Vec<String> {
    let mut args = vec!["--custody".to_owned(), KEYLESS.to_owned()];
    args.extend(rest.iter().map(|arg| (*arg).to_owned()));
    args
}

fn repo_with_recipients(name: &str) -> Repo {
    let repo = Repo::new(name);
    repo.write(
        ".sops.yaml",
        &format!(
            "creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: {A},{B} # admin,dev-b\n"
        ),
    );
    repo
}

fn repo_with_payload(name: &str) -> Repo {
    let repo = Repo::new(name);
    repo.write("secrets/dev.env", "TOKEN=old\n");
    repo
}

/// A throwaway identity file for `key import`.
fn identity_file() -> PathBuf {
    let path = std::env::temp_dir().join(format!("lockset-dry-run-id-{}", std::process::id()));
    std::fs::write(&path, lockset_core::SecretKey::generate().expose()).unwrap();
    path
}

#[test]
fn grant_plans_without_an_identity() {
    let repo = Repo::new("grant");
    let before = repo.read(".sops.yaml");

    let output = lockset(
        &repo,
        &keyless(&["--dry-run", "grant", A, "--label", "dev-a"]),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("would write .sops.yaml"), "{stdout}");
    assert_eq!(repo.read(".sops.yaml"), before);
}

#[test]
fn revoke_plans_without_an_identity() {
    let repo = repo_with_recipients("revoke");
    let before = repo.read(".sops.yaml");

    let output = lockset(&repo, &keyless(&["--dry-run", "revoke", B]));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("would write .sops.yaml"), "{stdout}");
    assert_eq!(repo.read(".sops.yaml"), before);
}

#[test]
fn rotate_plans_without_an_identity() {
    let repo = repo_with_payload("rotate");
    let before = repo.read("secrets/dev.env");

    let output = lockset(&repo, &keyless(&["--dry-run", "rotate", "--all"]));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains("would rotate the data key of secrets/dev.env"),
        "{stdout}"
    );
    assert_eq!(repo.read("secrets/dev.env"), before);
}

#[test]
fn person_add_plans_without_an_identity() {
    let repo = Repo::new("person-add");
    let before = repo.read(".sops.yaml");

    let output = lockset(
        &repo,
        &keyless(&["--dry-run", "person", "add", B, "--label", "dev-b"]),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("would write .sops.yaml"), "{stdout}");
    assert_eq!(repo.read(".sops.yaml"), before);
}

#[test]
fn set_plans_without_an_identity() {
    let repo = repo_with_payload("set");
    let before = repo.read("secrets/dev.env");

    let output = lockset_with(
        &repo,
        &keyless(&[
            "--dry-run",
            "set",
            "TOKEN",
            "--payload",
            "secrets/dev.env",
            "--stdin",
        ]),
        &[],
        Some("new-value"),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains("would set TOKEN in secrets/dev.env"),
        "{stdout}"
    );
    assert_eq!(repo.read("secrets/dev.env"), before);
}

#[test]
fn key_import_and_forget_plan_without_an_identity() {
    let repo = Repo::new("key");
    let identity = identity_file();

    let import = lockset(
        &repo,
        &keyless(&[
            "--dry-run",
            "key",
            "import",
            "--file",
            identity.to_str().unwrap(),
        ]),
    );
    let import_out = String::from_utf8_lossy(&import.stdout);
    assert_eq!(import.status.code(), Some(0), "{import_out}");
    assert!(
        import_out.contains("would store the key in file"),
        "{import_out}"
    );

    let forget = lockset(&repo, &keyless(&["--dry-run", "key", "forget"]));
    let forget_out = String::from_utf8_lossy(&forget.stdout);
    assert_eq!(forget.status.code(), Some(0), "{forget_out}");
    assert!(
        forget_out.contains("would remove the key from file"),
        "{forget_out}"
    );

    let _ = std::fs::remove_file(identity);
}

#[test]
fn a_json_dry_run_is_keyless_too() {
    let repo = Repo::new("json");

    let output = lockset(
        &repo,
        &keyless(&["--dry-run", "--json", "grant", A, "--label", "dev-a"]),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("\"type\": \"write_file\""), "{stdout}");
    assert!(stdout.contains("\"path\": \".sops.yaml\""), "{stdout}");
}

#[test]
fn an_invalid_plan_still_fails_without_an_identity() {
    let repo = Repo::new("invalid");

    let output = lockset(
        &repo,
        &keyless(&["--dry-run", "grant", A, "--label", "BAD"]),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    // An invalid label is a usage error, not a missing-identity finding.
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("invalid label"), "{stderr}");
}

#[test]
fn applying_still_requires_an_identity() {
    let repo = Repo::new("apply");

    let output = lockset(&repo, &keyless(&["grant", A, "--label", "dev-a"]));
    let stderr = String::from_utf8_lossy(&output.stderr);

    // No identity is a custody error.
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(stderr.contains("no identity in custody"), "{stderr}");
    assert!(
        !repo.read(".sops.yaml").contains(A),
        "a failed apply must not write"
    );
}
