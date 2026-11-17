//! A payload path that could leave the repository, or that an external tool
//! would read as an option, is a usage error: exit 2 before any codec call.

mod common;

use common::{lockset, strings, Repo};

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

#[test]
fn an_unknown_custody_spec_is_a_usage_error_that_changes_nothing() {
    let repo = Repo::new("custody");
    let before = std::fs::read_to_string(repo.sops_path()).unwrap();

    let output = lockset(&repo, &strings(&["--custody", "bogus", "status"]));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("unknown custody 'bogus'"), "{stderr}");
    for form in [
        "env:<NAME>",
        "keyring",
        "file:<absolute path>",
        "keyring:<service>",
    ] {
        assert!(
            stderr.contains(form),
            "stderr does not list {form}: {stderr}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(repo.sops_path()).unwrap(),
        before,
        "a rejected custody spec must not touch the repository"
    );
    assert!(
        !repo.path().join("secrets").exists(),
        "a rejected custody spec must not create anything"
    );
}
