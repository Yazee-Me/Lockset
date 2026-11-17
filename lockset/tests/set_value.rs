//! `set` never reads stdin implicitly, and never stores an empty value unless
//! the caller says so.

mod common;

use std::path::PathBuf;

use common::{lockset, lockset_with, strings, Repo};

fn repo_with_payload(name: &str) -> Repo {
    let repo = Repo::new(name);
    repo.write("secrets/dev.env", "TOKEN=old\n");
    repo
}

/// A throwaway identity, so the value checks are reached instead of custody.
fn identity() -> String {
    lockset_core::SecretKey::generate().expose().to_owned()
}

/// A mounted-secret style value file outside the repository.
struct ValueFile(PathBuf);

impl ValueFile {
    fn new(name: &str, contents: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("lockset-set-value-{name}-{}", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        Self(path)
    }
}

impl Drop for ValueFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn a_non_interactive_run_needs_an_explicit_source() {
    let repo = repo_with_payload("source");
    let key = identity();
    let before = repo.read("secrets/dev.env");

    let output = lockset_with(
        &repo,
        &strings(&["set", "TOKEN", "--payload", "secrets/dev.env"]),
        &[("LOCKSET_AGE_KEY", &key)],
        None,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "{stderr}");
    for flag in ["--stdin", "--from-env", "--value-file"] {
        assert!(stderr.contains(flag), "{stderr} does not name {flag}");
    }
    assert_eq!(repo.read("secrets/dev.env"), before);
}

#[test]
fn empty_stdin_is_refused_without_allow_empty() {
    let repo = repo_with_payload("empty-stdin");
    let key = identity();
    let before = repo.read("secrets/dev.env");

    let output = lockset_with(
        &repo,
        &strings(&["set", "TOKEN", "--payload", "secrets/dev.env", "--stdin"]),
        &[("LOCKSET_AGE_KEY", &key)],
        Some(""),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--allow-empty"), "{stderr}");
    assert_eq!(repo.read("secrets/dev.env"), before);
}

#[test]
fn an_empty_value_is_stored_only_with_allow_empty() {
    let repo = repo_with_payload("allow-empty");
    let key = identity();

    let output = lockset_with(
        &repo,
        &strings(&[
            "set",
            "TOKEN",
            "--payload",
            "secrets/dev.env",
            "--stdin",
            "--allow-empty",
            "--dry-run",
        ]),
        &[("LOCKSET_AGE_KEY", &key)],
        Some(""),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains("would set TOKEN in secrets/dev.env"),
        "{stdout}"
    );
    assert_eq!(repo.read("secrets/dev.env"), "TOKEN=old\n");
}

#[test]
fn stdin_from_env_and_value_file_all_reach_the_plan() {
    let repo = repo_with_payload("sources");
    let key = identity();
    let file = ValueFile::new("mounted", "from-file\n");

    let runs = [
        (
            strings(&[
                "set",
                "TOKEN",
                "--payload",
                "secrets/dev.env",
                "--stdin",
                "--dry-run",
            ]),
            Some("from-stdin\n"),
        ),
        (
            strings(&[
                "set",
                "TOKEN",
                "--payload",
                "secrets/dev.env",
                "--from-env",
                "LOCKSET_TEST_VALUE",
                "--dry-run",
            ]),
            None,
        ),
        (
            strings(&[
                "set",
                "TOKEN",
                "--payload",
                "secrets/dev.env",
                "--value-file",
                file.0.to_str().unwrap(),
                "--dry-run",
            ]),
            None,
        ),
    ];

    for (args, stdin) in runs {
        let output = lockset_with(
            &repo,
            &args,
            &[
                ("LOCKSET_AGE_KEY", &key),
                ("LOCKSET_TEST_VALUE", "from-env"),
            ],
            stdin,
        );
        let stdout = String::from_utf8_lossy(&output.stdout);

        assert_eq!(
            output.status.code(),
            Some(0),
            "{}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains("would set TOKEN in secrets/dev.env"),
            "{}: {stdout}",
            args.join(" ")
        );
    }
    assert_eq!(repo.read("secrets/dev.env"), "TOKEN=old\n");
}

#[test]
fn two_sources_are_refused() {
    let repo = repo_with_payload("conflict");
    let key = identity();

    let output = lockset_with(
        &repo,
        &strings(&[
            "set",
            "TOKEN",
            "--payload",
            "secrets/dev.env",
            "--stdin",
            "--from-env",
            "LOCKSET_TEST_VALUE",
        ]),
        &[("LOCKSET_AGE_KEY", &key), ("LOCKSET_TEST_VALUE", "x")],
        Some("y"),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("cannot be used with"), "{stderr}");
}

#[test]
fn a_value_file_that_cannot_be_read_is_an_error() {
    let repo = repo_with_payload("missing-file");

    let output = lockset(
        &repo,
        &strings(&[
            "set",
            "TOKEN",
            "--payload",
            "secrets/dev.env",
            "--value-file",
            "/nonexistent/lockset-value",
            "--dry-run",
        ]),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    // No identity is configured, so custody fails first; the point is that the
    // command changes nothing.
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert_eq!(repo.read("secrets/dev.env"), "TOKEN=old\n");
}

#[test]
fn a_json_dry_run_names_the_key_but_never_the_value() {
    let repo = repo_with_payload("json");
    let key = identity();

    let output = lockset_with(
        &repo,
        &strings(&[
            "--json",
            "--dry-run",
            "set",
            "TOKEN",
            "--payload",
            "secrets/dev.env",
            "--stdin",
        ]),
        &[("LOCKSET_AGE_KEY", &key)],
        Some("hunter2"),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("\"type\": \"set_value\""), "{stdout}");
    assert!(
        stdout.contains("\"payload\": \"secrets/dev.env\""),
        "{stdout}"
    );
    assert!(stdout.contains("\"name\": \"TOKEN\""), "{stdout}");
    assert!(stdout.contains("\"value\": null"), "{stdout}");
    assert!(!stdout.contains("hunter2"), "the value leaked: {stdout}");
    assert_eq!(repo.read("secrets/dev.env"), "TOKEN=old\n");
}

#[test]
fn json_without_a_dry_run_is_a_usage_error() {
    let repo = repo_with_payload("json-live");
    let key = identity();

    let output = lockset_with(
        &repo,
        &strings(&[
            "set",
            "TOKEN",
            "--payload",
            "secrets/dev.env",
            "--stdin",
            "--json",
        ]),
        &[("LOCKSET_AGE_KEY", &key)],
        Some("hunter2"),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--dry-run"), "{stderr}");
    assert_eq!(repo.read("secrets/dev.env"), "TOKEN=old\n");
}
