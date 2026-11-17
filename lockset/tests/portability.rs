//! Portability: both path separators, refused ambiguous forms, and CRLF that
//! survives a real rewrite.

#![cfg(unix)]
mod common;

use std::path::PathBuf;

use common::{lockset, lockset_with, strings, Repo};

const ADMIN: &str = "age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x";
const ALICE: &str = "age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q";
const CAROL: &str = "age1y4gs9hk93n3mpvhwydaq7uz4mn3a0esf0wfh3md2v2qz4hye9frsfpelwh";

fn repo_with_payload(name: &str) -> Repo {
    let repo = Repo::new(name);
    repo.write("secrets/dev.env", "TOKEN=ENC[a,type:str]\n");
    repo
}

#[test]
fn a_payload_path_accepts_either_separator() {
    let repo = repo_with_payload("separators");
    let mut out = Vec::new();
    let mut err = Vec::new();
    for path in ["secrets/dev.env", "secrets\\dev.env"] {
        let output = lockset_with(
            &repo,
            &strings(&["set", "TOKEN", "--payload", path, "--stdin", "--dry-run"]),
            &[],
            Some("value\n"),
        );
        out.push(String::from_utf8_lossy(&output.stdout).into_owned());
        err.push(String::from_utf8_lossy(&output.stderr).into_owned());
        assert_eq!(
            output.status.code(),
            Some(0),
            "{path}: {}",
            err.last().unwrap()
        );
    }
    assert_eq!(out[0], out[1], "both spellings reach the same payload");
    assert!(
        out[0].contains("would set TOKEN in secrets/dev.env"),
        "{}",
        out[0]
    );
    assert!(!err[0].contains("invalid path"), "{}", err[0]);
}

#[test]
fn a_config_path_and_default_payload_accept_either_separator() {
    let repo = repo_with_payload("config-separators");
    // Single-quoted TOML strings keep the backslashes literal.
    repo.write(
        "lockset.toml",
        "[repo]\nsops_config = 'sops\\settings.yaml'\ndefault_payloads = ['secrets\\dev.env']\n",
    );
    let map = repo.read(".sops.yaml");
    repo.write("sops/settings.yaml", &map);
    std::fs::remove_file(repo.sops_path()).unwrap();

    let status = lockset(&repo, &strings(&["status"]));
    let out = String::from_utf8_lossy(&status.stdout);
    assert_eq!(status.status.code(), Some(0), "{out}");
    assert!(
        out.contains("secrets/dev.env"),
        "the payload is discovered: {out}"
    );

    // `set` without --payload uses the configured default.
    let output = lockset_with(
        &repo,
        &strings(&["set", "TOKEN", "--stdin", "--dry-run"]),
        &[],
        Some("value\n"),
    );
    let out = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(output.status.code(), Some(0), "{out}");
    assert!(out.contains("would set TOKEN in secrets/dev.env"), "{out}");
}

#[test]
fn ambiguous_paths_are_refused_with_the_reason() {
    let repo = repo_with_payload("ambiguous");

    for (path, reason) in [
        ("C:\\secrets\\dev.env", "drive path is absolute"),
        ("c:/secrets/dev.env", "drive path is absolute"),
        ("\\\\server\\share\\dev.env", "UNC path is absolute"),
        ("secrets\\..\\dev.env", "'..' leaves the repository"),
        ("secrets\\\\.env", "empty segment"),
        ("secrets/dev.env:stream", "stream form"),
    ] {
        let output = lockset_with(
            &repo,
            &strings(&["set", "TOKEN", "--payload", path, "--stdin", "--dry-run"]),
            &[],
            Some("value\n"),
        );
        let err = String::from_utf8_lossy(&output.stderr).into_owned();
        assert_eq!(output.status.code(), Some(2), "{path}: {err}");
        assert!(
            err.contains("invalid path") && err.contains(reason),
            "{path}: {err}"
        );
    }
}

struct CrlfHarness {
    repo: Repo,
    shim: PathBuf,
    secret: String,
}

impl CrlfHarness {
    fn new(name: &str) -> Self {
        let repo = Repo::new(name);
        repo.write("secrets/dev.env", "TOKEN=ENC[a,type:str]\n");
        let map = format!(
            "# owned by this repository\r\ncreation_rules:\r\n  - path_regex: secrets/.*\\.env$\r\n    age: {ADMIN},{ALICE} # admin,dev-alice\r\n"
        );
        repo.write(".sops.yaml", &map);
        let shim = repo.path().join("sops-shim");
        std::fs::write(
            &shim,
            concat!(
                "#!/bin/sh\n",
                "for arg in \"$@\"; do\n",
                "  case \"$arg\" in\n",
                "    --version) echo 'sops 3.13.3'; exit 0 ;;\n",
                "    -d) printf 'TOKEN=v\\n'; exit 0 ;;\n",
                "    updatekeys|rotate) exit 0 ;;\n",
                "  esac\n",
                "done\n",
                "exit 1\n"
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        let secret = lockset_core::SecretKey::generate().expose().to_owned();
        Self { repo, shim, secret }
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        lockset_with(
            &self.repo,
            &strings(args),
            &[
                ("LOCKSET_AGE_KEY", self.secret.as_str()),
                ("LOCKSET_SOPS", self.shim.to_str().unwrap()),
            ],
            None,
        )
    }
}

impl Drop for CrlfHarness {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.shim);
    }
}

#[test]
fn a_crlf_sops_config_stays_crlf_through_a_grant() {
    let harness = CrlfHarness::new("crlf-grant");
    let before = harness.repo.read(".sops.yaml");
    assert!(before.contains("\r\n"), "the fixture is CRLF");

    let output = harness.run(&[
        "grant",
        CAROL,
        "--label",
        "dev-carol",
        "--only",
        "secrets/dev.env",
    ]);
    let err = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(0), "{err}");

    let after = harness.repo.read(".sops.yaml");
    assert!(
        !after.replace("\r\n", "").contains('\n'),
        "a CRLF file must not gain a bare LF: {after:?}"
    );
    assert!(
        after.starts_with("# owned by this repository\r\ncreation_rules:\r\n"),
        "untouched lines keep their bytes: {after:?}"
    );
    assert!(after.contains(CAROL), "{after}");
    assert!(
        after.contains("# admin,dev-alice,dev-carol\r\n"),
        "{after:?}"
    );
}
