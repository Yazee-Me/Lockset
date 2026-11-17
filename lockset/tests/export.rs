//! `export` writes the selected values in the requested format and nothing else.
//! The sops binary is a shim here, so the values are deterministic without a
//! keychain or a real decrypt.

#![cfg(unix)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Output;

use common::{lockset, lockset_with, strings, Repo};

/// A repository, a fake sops that prints canned payloads, and an identity.
struct Harness {
    repo: Repo,
    shim: PathBuf,
    secret: String,
}

impl Harness {
    fn new(name: &str) -> Self {
        let repo = Repo::new(name);
        let shim = repo.path().join("sops-shim");
        std::fs::write(
            &shim,
            "#!/bin/sh\ncase \"$2\" in\n  *a.env) printf 'TOKEN=a\\nONLY_A=1\\n' ;;\n  *b.env) printf 'TOKEN=b\\nONLY_B=2\\n' ;;\n  *c.env) printf 'LOCKSET_AGE_KEY=payload-value\\n' ;;\n  *d.env) printf 'TOKEN=hunter2\\n' ;;\n  *) echo \"unexpected payload: $2\" >&2; exit 1 ;;\nesac\n",
        )
        .unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        let secret = lockset_core::SecretKey::generate().expose().to_owned();
        Self { repo, shim, secret }
    }

    fn run(&self, args: &[&str]) -> Output {
        lockset_with(
            &self.repo,
            &strings(args),
            &[
                ("LOCKSET_AGE_KEY", &self.secret),
                ("LOCKSET_SOPS", self.shim.to_str().unwrap()),
            ],
            None,
        )
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.shim);
    }
}

#[test]
fn dotenv_exports_the_merged_values_and_nothing_else() {
    let harness = Harness::new("dotenv");

    let output = harness.run(&[
        "export",
        "--last-wins",
        "--payload",
        "secrets/a.env",
        "--payload",
        "secrets/b.env",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert_eq!(stdout, "TOKEN=b\nONLY_A=1\nONLY_B=2\n");
    assert!(stderr.contains("secret material"), "{stderr}");
}

#[test]
fn json_exports_one_object() {
    let harness = Harness::new("json");

    let output = harness.run(&[
        "export",
        "--last-wins",
        "--payload",
        "secrets/a.env",
        "--payload",
        "secrets/b.env",
        "--format",
        "json",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The whole of stdout is the document.
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["TOKEN"], "b");
    assert_eq!(parsed["ONLY_A"], "1");
    assert_eq!(parsed["ONLY_B"], "2");
}

#[test]
fn sh_exports_assignments() {
    let harness = Harness::new("sh");

    let output = harness.run(&["export", "--payload", "secrets/a.env", "--format", "sh"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert_eq!(stdout, "export TOKEN='a'\nexport ONLY_A='1'\n");
}

#[test]
fn payloads_merge_in_order_and_the_last_value_wins() {
    let harness = Harness::new("merge");

    let output = harness.run(&[
        "export",
        "--last-wins",
        "--payload",
        "secrets/b.env",
        "--payload",
        "secrets/a.env",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert_eq!(stdout, "TOKEN=a\nONLY_B=2\nONLY_A=1\n");
}

#[test]
fn the_identity_is_never_exported() {
    let harness = Harness::new("identity");

    let output = harness.run(&["export", "--payload", "secrets/c.env"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("identity or sops variable"), "{stderr}");
    assert!(output.stdout.is_empty(), "{stderr}");
}

#[test]
fn values_never_reach_an_error_message() {
    let harness = Harness::new("errors");

    // No identity: the failure happens before any value is printed or named.
    let output = lockset(
        &harness.repo,
        &strings(&[
            "--custody",
            "file:/nonexistent/export-key",
            "export",
            "--payload",
            "secrets/d.env",
        ]),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(!stderr.contains("hunter2"), "{stderr}");
    assert!(output.stdout.is_empty(), "{stderr}");
}

#[test]
fn json_and_unknown_formats_are_usage_errors() {
    let harness = Harness::new("usage");

    let global = harness.run(&["--json", "export", "--payload", "secrets/a.env"]);
    let stderr = String::from_utf8_lossy(&global.stderr);
    assert_eq!(global.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("own --format"), "{stderr}");

    let unknown = harness.run(&["export", "--payload", "secrets/a.env", "--format", "yaml"]);
    assert_eq!(
        unknown.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&unknown.stderr)
    );
}

#[test]
fn a_non_dotenv_payload_is_refused_before_custody() {
    let harness = Harness::new("format");

    let output = lockset(
        &harness.repo,
        &strings(&[
            "--custody",
            "file:/nonexistent/export-key",
            "export",
            "--payload",
            "secrets/a.yaml",
        ]),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("dotenv"), "{stderr}");
}
