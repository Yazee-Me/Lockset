//! Mutations serialize on the repository lock, a held lock is a conflict, and a
//! CRLF map keeps its line endings through a rewrite.

mod common;

use std::process::{Command, Stdio};

use common::{strings, Repo};

const A: &str = "age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x";
const B: &str = "age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q";

fn identity() -> String {
    lockset_core::SecretKey::generate().expose().to_owned()
}

/// A mutation now preflights `sops --version`; answer it with a script.
fn fake_sops(repo: &Repo) -> String {
    use std::os::unix::fs::PermissionsExt;

    let path = repo.path().join("sops-fake");
    std::fs::write(&path, "#!/bin/sh\necho 'sops 3.13.3'\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path.to_str().unwrap().to_owned()
}

fn command(repo: &Repo, args: &[String], key: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lockset"));
    command
        .arg("--repo")
        .arg(repo.path())
        .args(args)
        .env("LOCKSET_SOPS", "/nonexistent/lockset-test-sops")
        .env("LOCKSET_AGE_KEY", key)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[test]
fn two_concurrent_grants_both_land() {
    let repo = Repo::new("concurrent");
    let key = identity();
    let sops = fake_sops(&repo);

    let first = command(
        &repo,
        &strings(&["--sops", &sops, "grant", A, "--label", "dev-a"]),
        &key,
    )
    .spawn()
    .unwrap();
    let second = command(
        &repo,
        &strings(&["--sops", &sops, "grant", B, "--label", "dev-b"]),
        &key,
    )
    .spawn()
    .unwrap();
    let first = first.wait_with_output().unwrap();
    let second = second.wait_with_output().unwrap();

    assert_eq!(
        first.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(
        second.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let map = repo.read(".sops.yaml");
    assert!(
        map.contains(A) && map.contains(B),
        "a concurrent grant was lost: {map}"
    );
    assert!(
        !repo.path().join(".lockset.lock").exists(),
        "the lock must be released"
    );
}

#[test]
fn a_held_lock_times_out_as_a_conflict() {
    let repo = Repo::new("locked");
    let key = identity();
    let before = repo.read(".sops.yaml");
    std::fs::write(repo.path().join(".lockset.lock"), "pid 0\n").unwrap();

    let output = command(
        &repo,
        &strings(&["grant", A, "--label", "dev-a", "--lock-timeout", "1"]),
        &key,
    )
    .output()
    .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(5), "{stderr}");
    assert!(stderr.contains("another lockset"), "{stderr}");
    assert_eq!(repo.read(".sops.yaml"), before, "nothing may be written");

    std::fs::remove_file(repo.path().join(".lockset.lock")).unwrap();
}

#[test]
fn a_crlf_map_stays_crlf() {
    let repo = Repo::new("crlf");
    let key = identity();
    repo.write(
        ".sops.yaml",
        &format!(
            "creation_rules:\r\n  - path_regex: secrets/.*\\.env$\r\n    age: {A} # admin\r\n"
        ),
    );

    let sops = fake_sops(&repo);
    let output = command(
        &repo,
        &strings(&["--sops", &sops, "grant", B, "--label", "dev-b"]),
        &key,
    )
    .output()
    .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let after = repo.read(".sops.yaml");
    assert!(after.contains(B), "{after}");
    assert!(after.contains("# admin,dev-b"), "{after}");
    assert!(
        !after.replace("\r\n", "").contains('\n'),
        "mixed line endings: {after:?}"
    );
}
