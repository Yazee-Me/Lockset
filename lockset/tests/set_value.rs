//! `set` never reads stdin implicitly, and never stores an empty value unless
//! the caller says so.

#![cfg(unix)]
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

    // An unreadable source is a usage error, and nothing is written.
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("cannot read"), "{stderr}");
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

/// A shim that reads and writes the payload file itself, so `--if-absent` can
/// be exercised end to end without sops.
struct SetHarness {
    repo: Repo,
    shim: PathBuf,
    secret: String,
}

impl SetHarness {
    fn new(name: &str, payload: &str) -> Self {
        let repo = Repo::new(name);
        repo.write("secrets/dev.env", payload);
        let shim = repo.path().join("sops-shim");
        std::fs::write(
            &shim,
            concat!(
                "#!/bin/sh\n",
                "case \"$1\" in\n",
                "  --version) echo 'sops 3.13.3' ;;\n",
                "  -d) cat \"$2\" ;;\n",
                "  set)\n",
                "    path=\"$3\"\n",
                "    value=$(cat)\n",
                "    value=${value#\\\"}\n",
                "    value=${value%\\\"}\n",
                "    printf 'TOKEN=%s\\n' \"$value\" > \"$path\" ;;\n",
                "  *) exit 1 ;;\n",
                "esac\n"
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        let secret = identity();
        Self { repo, shim, secret }
    }

    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
        let mut all = vec![
            ("LOCKSET_AGE_KEY", self.secret.as_str()),
            ("LOCKSET_SOPS", self.shim.to_str().unwrap()),
            ("VALUE", "new"),
        ];
        all.extend(env.iter().copied());
        lockset_with(&self.repo, &strings(args), &all, None)
    }

    fn payload(&self) -> String {
        self.repo.read("secrets/dev.env")
    }
}

impl Drop for SetHarness {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.shim);
    }
}

#[test]
fn if_absent_skips_a_key_that_already_has_a_value() {
    let harness = SetHarness::new("if-absent-skip", "TOKEN=old\n");

    let output = harness.run(
        &[
            "set",
            "TOKEN",
            "--payload",
            "secrets/dev.env",
            "--from-env",
            "VALUE",
            "--if-absent",
        ],
        &[],
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("already has a value"), "{stderr}");
    assert_eq!(harness.payload(), "TOKEN=old\n");
}

#[test]
fn if_absent_writes_a_key_the_payload_does_not_set() {
    let harness = SetHarness::new("if-absent-write", "OTHER=1\n");

    let output = harness.run(
        &[
            "set",
            "TOKEN",
            "--payload",
            "secrets/dev.env",
            "--from-env",
            "VALUE",
            "--if-absent",
        ],
        &[],
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert_eq!(harness.payload(), "TOKEN=new\n");
}

#[test]
fn if_absent_treats_an_empty_value_as_absent() {
    let harness = SetHarness::new("if-absent-empty", "TOKEN=\n");

    let output = harness.run(
        &[
            "set",
            "TOKEN",
            "--payload",
            "secrets/dev.env",
            "--from-env",
            "VALUE",
            "--if-absent",
        ],
        &[],
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert_eq!(harness.payload(), "TOKEN=new\n");
}

#[test]
fn without_if_absent_an_existing_value_is_replaced() {
    let harness = SetHarness::new("overwrite", "TOKEN=old\n");

    let output = harness.run(
        &[
            "set",
            "TOKEN",
            "--payload",
            "secrets/dev.env",
            "--from-env",
            "VALUE",
        ],
        &[],
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert_eq!(harness.payload(), "TOKEN=new\n");
}

#[test]
fn if_absent_needs_the_identity_even_for_a_dry_run() {
    let harness = SetHarness::new("if-absent-keyless", "TOKEN=old\n");

    let output = lockset_with(
        &harness.repo,
        &strings(&[
            "set",
            "TOKEN",
            "--payload",
            "secrets/dev.env",
            "--from-env",
            "VALUE",
            "--if-absent",
            "--dry-run",
        ]),
        &[
            ("LOCKSET_SOPS", harness.shim.to_str().unwrap()),
            ("VALUE", "new"),
        ],
        None,
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(stderr.contains("no identity"), "{stderr}");
    assert_eq!(harness.payload(), "TOKEN=old\n");
}
