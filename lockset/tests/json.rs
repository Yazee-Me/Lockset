//! `--json` documents: pinned schema, redaction, and the text views unchanged.

mod common;

use std::process::Output;

use serde_json::Value;

use common::{lockset, lockset_with, strings, Repo};

const A: &str = "age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x";
const B: &str = "age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q";

/// No identity: JSON output must not need one.
const KEYLESS: &str = "file:/nonexistent/lockset-json-key";

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

fn repo(name: &str) -> Repo {
    let repo = Repo::new(name);
    repo.write(
        ".sops.yaml",
        &format!("creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: {A} # admin\n"),
    );
    repo.write("secrets/dev.env", &encrypted());
    repo
}

fn json_of(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "not JSON ({error}): {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

#[test]
fn status_json_pins_the_schema() {
    let repo = repo("status");
    let output = lockset(&repo, &keyless(&["status", "--json"]));
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = json_of(&output);

    assert_eq!(
        keys(&json),
        [
            "coverage",
            "drift",
            "empty_values",
            "identities",
            "identity",
            "identity_error",
            "next",
            "payload_errors",
            "payloads",
            "root",
            "schema_version",
        ]
    );
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["identity"], Value::Null);
    assert_eq!(json["identity_error"], Value::Null);
    assert_eq!(json["coverage"], Value::Null);
    assert_eq!(json["payloads"][0]["path"], "secrets/dev.env");
    assert_eq!(json["payloads"][0]["keys"], 1);
    assert_eq!(json["payloads"][0]["recipients"], 1);
    assert_eq!(json["payloads"][0]["empty"], 0);
    assert_eq!(json["identities"][0]["label"], "admin");
    assert_eq!(json["identities"][0]["public"], A);
    assert_eq!(json["identities"][0]["payloads"], 1);
    assert_eq!(json["identities"][0]["local"], false);
    assert_eq!(json["drift"].as_array().unwrap().len(), 0);
    assert_eq!(json["empty_values"], 0);
    assert_eq!(json["next"], "next: lockset key import");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("ENC["),
        "ciphertext must not be serialized"
    );
}

#[test]
fn status_json_with_an_identity_has_coverage() {
    let repo = repo("coverage");
    let key = lockset_core::SecretKey::generate().expose().to_owned();

    let output = lockset_with(
        &repo,
        &strings(&["--json", "status"]),
        &[("LOCKSET_AGE_KEY", &key)],
        None,
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = json_of(&output);

    assert_eq!(keys(&json["identity"]), ["custody", "label", "public"]);
    assert_eq!(json["identity"]["custody"], "env");
    assert_eq!(json["identity"]["label"], Value::Null);
    assert_eq!(keys(&json["coverage"]), ["missing", "opens", "total"]);
    assert_eq!(json["coverage"]["opens"], 0);
    assert_eq!(json["coverage"]["total"], 1);
    assert_eq!(json["coverage"]["missing"][0], "secrets/dev.env");
}

#[test]
fn who_json_pins_the_identity_map() {
    let repo = repo("who");
    let output = lockset(&repo, &keyless(&["who", "--json"]));
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = json_of(&output);

    assert_eq!(keys(&json), ["identities", "schema_version"]);
    assert_eq!(json["schema_version"], 1);
    assert_eq!(
        keys(&json["identities"][0]),
        ["label", "local", "payloads", "public"]
    );
    assert_eq!(json["identities"][0]["label"], "admin");
    assert_eq!(json["identities"][0]["public"], A);
    assert_eq!(json["identities"][0]["local"], false);
}

#[test]
fn check_json_pins_the_checks() {
    let repo = repo("check");
    let output = lockset(&repo, &keyless(&["check", "--json"]));
    let json = json_of(&output);

    assert_eq!(output.status.code(), Some(1), "{json}");
    assert_eq!(keys(&json), ["checks", "schema_version"]);
    assert_eq!(json["schema_version"], 1);
    let checks = json["checks"].as_array().unwrap();
    assert!(checks.len() >= 4, "{json}");
    for check in checks {
        assert_eq!(keys(check), ["detail", "name", "ok"]);
    }
    let identity = checks
        .iter()
        .find(|check| check["name"] == "identity")
        .unwrap();
    assert_eq!(identity["ok"], false);
    assert!(checks.iter().any(|check| check["name"] == "payloads parse"));
}

#[test]
fn a_plan_json_is_versioned_and_redacted() {
    let repo = repo("plan");
    let output = lockset_with(
        &repo,
        &keyless(&[
            "--dry-run",
            "--json",
            "set",
            "TOKEN",
            "--payload",
            "secrets/dev.env",
            "--stdin",
        ]),
        &[],
        Some("hunter2"),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    let json = json_of(&output);

    assert_eq!(keys(&json), ["plan", "schema_version"]);
    assert_eq!(json["schema_version"], 1);
    assert_eq!(keys(&json["plan"]), ["changes", "notes", "warnings"]);
    assert_eq!(json["plan"]["changes"][0]["type"], "set_value");
    assert_eq!(json["plan"]["changes"][0]["payload"], "secrets/dev.env");
    assert_eq!(json["plan"]["changes"][0]["name"], "TOKEN");
    assert_eq!(json["plan"]["changes"][0]["value"], Value::Null);
    assert!(!stdout.contains("hunter2"), "the value leaked: {stdout}");
}

#[test]
fn human_output_is_unchanged_and_notes_go_to_stderr() {
    let repo = repo("text");

    let status = lockset(&repo, &keyless(&["status"]));
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert_eq!(status.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("identity: none"), "{stdout}");
    assert!(stdout.contains("payload"), "{stdout}");
    assert!(stdout.contains("drift: none"), "{stdout}");

    let grant = lockset(
        &repo,
        &keyless(&["--dry-run", "grant", B, "--label", "dev-b"]),
    );
    let stdout = String::from_utf8_lossy(&grant.stdout);
    let stderr = String::from_utf8_lossy(&grant.stderr);
    assert_eq!(grant.status.code(), Some(0), "{stderr}");
    assert!(stdout.contains("would write .sops.yaml"), "{stdout}");
    assert!(
        !stdout.contains(&format!("grant {B}")),
        "notes belong on stderr: {stdout}"
    );
    assert!(stderr.contains(&format!("grant {B} as dev-b")), "{stderr}");
}

#[test]
fn run_has_no_json_output() {
    let repo = repo("run");

    let output = lockset(&repo, &keyless(&["--json", "run", "--", "true"]));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("no JSON output"), "{stderr}");
}
