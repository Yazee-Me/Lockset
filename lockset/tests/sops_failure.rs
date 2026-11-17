//! A sops failure keeps every stderr line, names the payload, and never prints
//! the identity, even when sops itself echoes it.

mod common;

use std::path::PathBuf;

use common::{lockset_with, strings, Repo};

struct Harness {
    repo: Repo,
    shim: PathBuf,
    secret: String,
}

impl Harness {
    fn new(name: &str) -> Self {
        let repo = Repo::new(name);
        repo.write("secrets/dev.env", "TOKEN=ENC[a,type:str]\n");
        let shim = repo.path().join("sops-shim");
        std::fs::write(
            &shim,
            concat!(
                "#!/bin/sh\n",
                "case \"$1\" in\n",
                "  --version) echo 'sops 3.13.3' ;;\n",
                "  -d)\n",
                "    echo 'failed to decrypt data key' >&2\n",
                "    echo \"age: identity $SOPS_AGE_KEY did not match\" >&2\n",
                "    exit 1 ;;\n",
                "  set)\n",
                "    echo 'sops: cannot write the file' >&2\n",
                "    echo 'sops: the store is read-only' >&2\n",
                "    exit 1 ;;\n",
                "esac\n",
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

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.shim);
    }
}

#[test]
fn a_decrypt_failure_names_the_payload_and_keeps_every_line() {
    let harness = Harness::new("full");
    let secret = harness.secret.clone();

    let output = harness.run(&["export", "--payload", "secrets/dev.env"]);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert_eq!(output.status.code(), Some(4), "{stderr}");
    assert!(
        stderr.contains("sops decrypt secrets/dev.env failed"),
        "{stderr}"
    );
    assert!(stderr.contains("failed to decrypt data key"), "{stderr}");
    assert!(stderr.contains("did not match"), "{stderr}");
    assert!(
        !stderr.contains(&secret),
        "the identity must be redacted: {stderr}"
    );
    assert!(stderr.contains("[redacted]"), "{stderr}");
}

#[test]
fn a_write_failure_names_the_key_and_the_payload() {
    let harness = Harness::new("write");

    let output = lockset_with(
        &harness.repo,
        &strings(&[
            "set",
            "TOKEN",
            "--payload",
            "secrets/dev.env",
            "--from-env",
            "VALUE",
        ]),
        &[
            ("LOCKSET_AGE_KEY", harness.secret.as_str()),
            ("LOCKSET_SOPS", harness.shim.to_str().unwrap()),
            ("VALUE", "new"),
        ],
        None,
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert_eq!(output.status.code(), Some(4), "{stderr}");
    assert!(
        stderr.contains("sops set TOKEN in secrets/dev.env failed"),
        "{stderr}"
    );
    assert!(stderr.contains("cannot write the file"), "{stderr}");
    assert!(stderr.contains("the store is read-only"), "{stderr}");
}
