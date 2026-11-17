//! Revoke safety and rollback: a machine refuses to revoke its own identity
//! without `--force`, and an apply that fails part-way restores every file it
//! had already written.

#![cfg(unix)]

mod common;

use std::path::PathBuf;
use std::process::{Command, Output};

use common::{strings, Repo};

const ADMIN: &str = "age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x";
const READER: &str = "age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q";
const NEW: &str = "age1y4gs9hk93n3mpvhwydaq7uz4mn3a0esf0wfh3md2v2qz4hye9frsfpelwh";

fn identity() -> String {
    lockset_core::SecretKey::generate().expose().to_owned()
}

/// A sops shim that can be told to fail the second `updatekeys` call, so a
/// grant lands a map write and one re-wrap before failing.
fn fake_sops(repo: &Repo, fail_second_updatekeys: bool) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = repo.path().join("sops-fake");
    let counter = repo.path().join("updatekeys.count");
    let body = if fail_second_updatekeys {
        format!(
            concat!(
                "#!/bin/sh\n",
                "for argument in \"$@\"; do\n",
                "  case \"$argument\" in\n",
                "    --version) echo 'sops 3.13.3'; exit 0 ;;\n",
                "    -d) printf 'TOKEN=s3cret\\n'; exit 0 ;;\n",
                "    updatekeys)\n",
                "      count=0\n",
                "      [ -f '{counter}' ] && count=$(cat '{counter}')\n",
                "      count=$((count + 1))\n",
                "      printf '%s' \"$count\" > '{counter}'\n",
                "      if [ \"$count\" -ge 2 ]; then\n",
                "        echo 'sops: refused the second updatekeys' >&2\n",
                "        exit 1\n",
                "      fi\n",
                "      exit 0 ;;\n",
                "    rotate) exit 0 ;;\n",
                "  esac\n",
                "done\n",
                "exit 1\n"
            ),
            counter = counter.display()
        )
    } else {
        concat!(
            "#!/bin/sh\n",
            "for argument in \"$@\"; do\n",
            "  case \"$argument\" in\n",
            "    --version) echo 'sops 3.13.3'; exit 0 ;;\n",
            "    -d) printf 'TOKEN=s3cret\\n'; exit 0 ;;\n",
            "    updatekeys|rotate) exit 0 ;;\n",
            "  esac\n",
            "done\n",
            "exit 1\n"
        )
        .to_owned()
    };
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn run(repo: &Repo, args: &[&str], key: &str, sops: &PathBuf) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lockset"))
        .arg("--repo")
        .arg(repo.path())
        .args(strings(args))
        .env("LOCKSET_SOPS", sops)
        .env("LOCKSET_AGE_KEY", key)
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn two_recipient_map(name: &str) -> Repo {
    let repo = Repo::new(name);
    repo.write(
        ".sops.yaml",
        &format!(
            "creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: {ADMIN},{READER} # admin,dev-reader\n"
        ),
    );
    repo.write("secrets/dev.env", "TOKEN=ENC[a,type:str]\n");
    repo
}

#[test]
fn a_machine_refuses_to_revoke_its_own_identity() {
    let repo = two_recipient_map("self-revoke");
    let key = identity();
    let own = lockset_core::SecretKey::from_text(&key).unwrap();
    let own_public = own.public().unwrap().as_str().to_owned();
    let sops = fake_sops(&repo, false);
    let before = repo.read(".sops.yaml");

    let output = run(&repo, &["revoke", &own_public], &key, &sops);

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("this machine's identity"),
        "{}",
        stderr(&output)
    );
    assert!(stderr(&output).contains("--force"), "{}", stderr(&output));
    assert_eq!(repo.read(".sops.yaml"), before, "nothing may be written");
}

#[test]
fn force_revokes_the_machines_own_identity() {
    let repo = Repo::new("revoke-force");
    let key = identity();
    let own_public = lockset_core::SecretKey::from_text(&key)
        .unwrap()
        .public()
        .unwrap()
        .as_str()
        .to_owned();
    repo.write(
        ".sops.yaml",
        &format!(
            "creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: {READER},{own_public} # dev-reader,admin\n"
        ),
    );
    repo.write("secrets/dev.env", "TOKEN=ENC[a,type:str]\n");
    let sops = fake_sops(&repo, false);

    let output = run(&repo, &["revoke", &own_public, "--force"], &key, &sops);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let map = repo.read(".sops.yaml");
    assert!(!map.contains(&own_public), "{map}");
    assert!(map.contains(READER), "{map}");
}

#[test]
fn revoking_another_identity_rewrites_the_map() {
    let repo = two_recipient_map("revoke-other");
    let key = identity();
    let sops = fake_sops(&repo, false);

    let output = run(&repo, &["revoke", READER], &key, &sops);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let map = repo.read(".sops.yaml");
    assert!(!map.contains(READER), "{map}");
    assert!(map.contains(ADMIN), "{map}");
}

#[test]
fn a_failed_apply_restores_the_map_and_the_payloads() {
    let repo = Repo::new("revoke-rollback");
    repo.write(
        ".sops.yaml",
        &format!(
            "creation_rules:\n  - path_regex: secrets/a\\.env$\n    age: {ADMIN} # admin\n  - path_regex: secrets/b\\.env$\n    age: {ADMIN} # admin\n"
        ),
    );
    repo.write("secrets/a.env", "TOKEN=ENC[a,type:str]\n");
    repo.write("secrets/b.env", "TOKEN=ENC[a,type:str]\n");
    let before_map = repo.read(".sops.yaml");
    let before_a = repo.read("secrets/a.env");
    let before_b = repo.read("secrets/b.env");
    let key = identity();
    let sops = fake_sops(&repo, true);

    let output = run(
        &repo,
        &[
            "grant",
            NEW,
            "--label",
            "dev-new",
            "--only",
            "secrets/a.env,secrets/b.env",
        ],
        &key,
        &sops,
    );
    let err = stderr(&output);

    assert_eq!(output.status.code(), Some(4), "{err}");
    assert!(err.contains("nothing was changed"), "{err}");
    assert!(err.contains("refused the second updatekeys"), "{err}");
    assert_eq!(
        repo.read(".sops.yaml"),
        before_map,
        "the map must be restored"
    );
    assert_eq!(
        repo.read("secrets/a.env"),
        before_a,
        "a.env must be restored"
    );
    assert_eq!(
        repo.read("secrets/b.env"),
        before_b,
        "b.env must be restored"
    );
    assert!(
        !repo.read(".sops.yaml").contains(NEW),
        "no new recipient may remain"
    );
}
