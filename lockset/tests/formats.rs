//! One payload format is supported: dotenv (`.env`). Anything else under the
//! payload directory is reported, never silently ignored, and `run`/`set`
//! reject it with a message that names the format.

mod common;

use common::{lockset, lockset_with, strings, Repo};

const A: &str = "age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x";

/// No identity: the format checks must happen before custody.
const KEYLESS: &str = "file:/nonexistent/lockset-formats-key";

fn keyless(rest: &[&str]) -> Vec<String> {
    let mut args = vec!["--custody".to_owned(), KEYLESS.to_owned()];
    args.extend(rest.iter().map(|arg| (*arg).to_owned()));
    args
}

fn encrypted() -> String {
    format!(
        "TOKEN=ENC[a,type:str]\nsops_age__list_0__map_enc=x\nsops_age__list_0__map_recipient={A}\nsops_version=3.13.3\nsops_mac=ENC[a,type:str]\n"
    )
}

fn yaml_payload() -> String {
    format!(
        "TOKEN: ENC[a,type:str]\nsops:\n    age:\n        - recipient: {A}\n          enc: |\n            x\n    version: 3.13.3\n"
    )
}

fn repo_with_both_formats(name: &str) -> Repo {
    let repo = Repo::new(name);
    repo.write(
        ".sops.yaml",
        &format!("creation_rules:\n  - path_regex: secrets/.*\n    age: {A} # admin\n"),
    );
    repo.write("secrets/dev.env", &encrypted());
    repo.write("secrets/config.yaml", &yaml_payload());
    repo.write("secrets/.gitkeep", "");
    repo
}

#[test]
fn an_unsupported_payload_is_reported_not_ignored() {
    let repo = repo_with_both_formats("report");

    let status = lockset(&repo, &strings(&["status"]));
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert_eq!(status.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("secrets/dev.env"), "{stdout}");
    assert!(stdout.contains("unreadable payloads: 1"), "{stdout}");
    assert!(stdout.contains("secrets/config.yaml"), "{stdout}");
    assert!(stdout.contains("dotenv"), "{stdout}");
    assert!(!stdout.contains(".gitkeep"), "{stdout}");

    let check = lockset(&repo, &strings(&["check"]));
    let stdout = String::from_utf8_lossy(&check.stdout);
    assert_eq!(check.status.code(), Some(1), "{stdout}");
    let parse = stdout
        .lines()
        .find(|line| line.starts_with("payloads parse"))
        .unwrap_or_else(|| panic!("no parse check in: {stdout}"));
    assert!(parse.contains("secrets/config.yaml"), "{parse}");

    let rotate = lockset(&repo, &keyless(&["--dry-run", "rotate", "--all"]));
    let stdout = String::from_utf8_lossy(&rotate.stdout);
    assert_eq!(rotate.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains("would rotate the data key of secrets/dev.env"),
        "{stdout}"
    );
    assert!(!stdout.contains("config.yaml"), "{stdout}");
}

#[test]
fn run_rejects_an_unsupported_payload_before_custody() {
    let repo = repo_with_both_formats("run");

    let output = lockset(
        &repo,
        &keyless(&["run", "--payload", "secrets/config.yaml", "--", "true"]),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("secrets/config.yaml"), "{stderr}");
    assert!(stderr.contains("dotenv"), "{stderr}");
}

#[test]
fn set_rejects_an_unsupported_payload() {
    let repo = repo_with_both_formats("set");

    let bad = lockset_with(
        &repo,
        &keyless(&[
            "--dry-run",
            "set",
            "TOKEN",
            "--payload",
            "secrets/config.yaml",
            "--stdin",
        ]),
        &[],
        Some("v"),
    );
    let stderr = String::from_utf8_lossy(&bad.stderr);
    assert_eq!(bad.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("cannot use secrets/config.yaml"),
        "{stderr}"
    );
    assert!(stderr.contains("dotenv"), "{stderr}");

    let good = lockset_with(
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
        Some("v"),
    );
    let stdout = String::from_utf8_lossy(&good.stdout);
    assert_eq!(good.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains("would set TOKEN in secrets/dev.env"),
        "{stdout}"
    );
}
