//! `unset` removes one key, keeps every other value and the recipient set, and
//! treats a missing key as a no-op success.

#![cfg(unix)]
mod common;

use std::path::PathBuf;
use std::process::{Command, Output};

use common::Repo;

const ADMIN: &str = "age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x";
const READER: &str = "age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q";

/// A dotenv payload as sops writes it: two encrypted values, then the flat
/// metadata, which carries the recipient set.
fn payload() -> String {
    format!(
        "ONE=ENC[AES256_GCM,data:aaa,type:str]\n\
         TWO=ENC[AES256_GCM,data:bbb,type:str]\n\
         sops_age__list_0__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\\nYWdl\n\
         sops_age__list_0__map_recipient={ADMIN}\n\
         sops_age__list_1__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\\nYWdl\n\
         sops_age__list_1__map_recipient={READER}\n\
         sops_lastmodified=2026-11-21T00:00:00Z\n\
         sops_mac=ENC[AES256_GCM,data:zzz,type:str]\n\
         sops_version=3.13.3\n"
    )
}

/// A fake `sops`: `--version` answers the floor, `-d` reads the plaintext
/// fixture, and `unset` removes the named line from the payload and the
/// plaintext while recording its argv. A `corrupt` shim also rewrites another
/// value, so the codec's read-back check is exercised.
struct Unset {
    repo: Repo,
    shim: PathBuf,
    plain: PathBuf,
    log: PathBuf,
    secret: String,
}

impl Unset {
    fn new(name: &str, corrupt: bool) -> Self {
        use std::os::unix::fs::PermissionsExt;

        let repo = Repo::new(name);
        repo.write("secrets/dev.env", &payload());
        let plain = repo.path().join("plain.env");
        std::fs::write(&plain, "ONE=first\nTWO=second\n").unwrap();
        let log = repo.path().join("sops.log");
        let shim = repo.path().join("sops-shim");
        let extra = if corrupt {
            "  printf 'OTHER=changed\\n' >> \"$path\"\n  printf 'OTHER=changed\\n' >> \"$UNSET_PLAIN\"\n"
        } else {
            ""
        };
        std::fs::write(
            &shim,
            format!(
                concat!(
                    "#!/bin/sh\n",
                    "case \"$1\" in\n",
                    "  --version) echo 'sops 3.13.3' ;;\n",
                    "  -d) cat \"$UNSET_PLAIN\" ;;\n",
                    "  unset)\n",
                    "    echo \"$*\" >> \"$UNSET_LOG\"\n",
                    "    name=$(printf '%s' \"$4\" | tr -d '[]\"')\n",
                    "    path=\"$3\"\n",
                    "    awk -v key=\"$name\" 'index($0, key \"=\") != 1' \"$path\" > \"$path.tmp\"\n",
                    "    mv \"$path.tmp\" \"$path\"\n",
                    "    awk -v key=\"$name\" 'index($0, key \"=\") != 1' \"$UNSET_PLAIN\" > \"$UNSET_PLAIN.tmp\"\n",
                    "    mv \"$UNSET_PLAIN.tmp\" \"$UNSET_PLAIN\"\n",
                    "{}",
                    "    ;;\n",
                    "  *) exit 1 ;;\n",
                    "esac\n"
                ),
                extra
            ),
        )
        .unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();

        Self {
            repo,
            shim,
            plain,
            log,
            secret: lockset_core::SecretKey::generate().expose().to_owned(),
        }
    }

    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lockset"));
        command
            .arg("--repo")
            .arg(self.repo.path())
            .args(args)
            .env("LOCKSET_SOPS", &self.shim)
            .env("UNSET_LOG", &self.log)
            .env("UNSET_PLAIN", &self.plain)
            .env_remove("LOCKSET_AGE_KEY")
            .envs(env.iter().copied());
        command.output().unwrap()
    }

    fn with_identity(&self, args: &[&str]) -> Output {
        self.run(args, &[("LOCKSET_AGE_KEY", self.secret.as_str())])
    }

    fn payload(&self) -> String {
        self.repo.read("secrets/dev.env")
    }

    /// The argv of every `unset` invocation, one line each.
    fn unset_argv(&self) -> Vec<String> {
        match std::fs::read_to_string(&self.log) {
            Ok(text) => text.lines().map(str::to_owned).collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("reading the sops log: {error}"),
        }
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn unset_removes_only_the_named_key() {
    let fake = Unset::new("unset-one", false);

    let output = fake.with_identity(&["unset", "ONE", "--payload", "secrets/dev.env"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("removed ONE from secrets/dev.env"),
        "{}",
        stdout(&output)
    );
    let after = fake.payload();
    assert!(!after.contains("ONE="), "{after}");
    assert!(
        after.contains("TWO=ENC[AES256_GCM,data:bbb,type:str]"),
        "{after}"
    );
    assert!(
        after.contains(&format!("sops_age__list_0__map_recipient={ADMIN}")),
        "{after}"
    );
    assert!(
        after.contains(&format!("sops_age__list_1__map_recipient={READER}")),
        "{after}"
    );
    assert!(after.contains("sops_version=3.13.3"), "{after}");
    assert_eq!(
        fake.unset_argv(),
        [r#"unset --idempotent secrets/dev.env ["ONE"]"#]
    );
    let plain = std::fs::read_to_string(&fake.plain).unwrap();
    assert!(!plain.contains("ONE="), "{plain}");
    assert!(plain.contains("TWO=second"), "{plain}");
}

#[test]
fn a_missing_key_is_a_no_op_success() {
    let fake = Unset::new("unset-missing", false);
    let before = fake.payload();

    let output = fake.with_identity(&["unset", "THREE", "--payload", "secrets/dev.env"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("THREE is not set in secrets/dev.env; nothing to do"),
        "{}",
        stderr(&output)
    );
    assert!(fake.unset_argv().is_empty(), "sops unset was invoked");
    assert_eq!(fake.payload(), before);
}

#[test]
fn a_dry_run_prints_the_plan_without_a_key() {
    let fake = Unset::new("unset-dry-run", false);
    let before = fake.payload();

    let output = fake.run(
        &[
            "--json",
            "--dry-run",
            "unset",
            "ONE",
            "--payload",
            "secrets/dev.env",
        ],
        &[],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let document = stdout(&output);
    assert!(document.contains("\"type\": \"unset_value\""), "{document}");
    assert!(
        document.contains("\"payload\": \"secrets/dev.env\""),
        "{document}"
    );
    assert!(document.contains("\"name\": \"ONE\""), "{document}");
    assert!(fake.unset_argv().is_empty(), "sops unset was invoked");
    assert_eq!(fake.payload(), before);
}

#[test]
fn an_invalid_key_name_is_a_usage_error() {
    let fake = Unset::new("unset-invalid", false);
    let before = fake.payload();

    for name in ["1BAD", "NOT-A-KEY", ""] {
        let output = fake.with_identity(&["unset", name, "--payload", "secrets/dev.env"]);

        assert_eq!(output.status.code(), Some(2), "{name}: {}", stderr(&output));
        assert!(
            stderr(&output).contains("invalid key name"),
            "{name}: {}",
            stderr(&output)
        );
        assert_eq!(fake.payload(), before);
    }
    assert!(fake.unset_argv().is_empty(), "sops unset was invoked");
}

#[test]
fn the_default_payload_is_used_when_it_names_exactly_one() {
    let fake = Unset::new("unset-default-one", false);
    fake.repo.write(
        "lockset.toml",
        "[repo]\ndefault_payloads = [\"secrets/dev.env\"]\n",
    );

    let output = fake.with_identity(&["unset", "ONE"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(!fake.payload().contains("ONE="), "{}", fake.payload());
}

#[test]
fn two_default_payloads_are_refused() {
    let fake = Unset::new("unset-default-two", false);
    fake.repo.write(
        "lockset.toml",
        "[repo]\ndefault_payloads = [\"secrets/dev.env\", \"secrets/other.env\"]\n",
    );
    let before = fake.payload();

    let output = fake.with_identity(&["unset", "ONE"]);

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("exactly one payload"),
        "{}",
        stderr(&output)
    );
    assert!(fake.unset_argv().is_empty(), "sops unset was invoked");
    assert_eq!(fake.payload(), before);
}

#[test]
fn no_default_payload_lists_what_is_available() {
    let fake = Unset::new("unset-default-none", false);
    let before = fake.payload();

    let output = fake.with_identity(&["unset", "ONE"]);

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no payload selected"),
        "{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("secrets/dev.env"),
        "{}",
        stderr(&output)
    );
    assert_eq!(fake.payload(), before);
}

#[test]
fn a_result_that_changed_another_value_is_rolled_back() {
    let fake = Unset::new("unset-corrupt", true);
    let before = fake.payload();

    let output = fake.with_identity(&["unset", "ONE", "--payload", "secrets/dev.env"]);

    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("changed beyond ONE"),
        "{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("the repository was restored"),
        "{}",
        stderr(&output)
    );
    assert_eq!(fake.payload(), before);
}
