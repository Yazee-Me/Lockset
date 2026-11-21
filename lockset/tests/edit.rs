//! `lockset edit`: sops decrypts the payload into `$SOPS_EDITOR` and
//! re-encrypts it with the same recipients. A failed editor, a payload that
//! comes back unencrypted or with other recipients, and every plaintext value
//! are refused with exit 4 while the payload stays byte-identical.

#![cfg(unix)]

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use common::Repo;

const ADMIN: &str = "age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x";
const READER: &str = "age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q";
const OTHER: &str = "age1y4gs9hk93n3mpvhwydaq7uz4mn3a0esf0wfh3md2v2qz4hye9frsfpelwh";

const ENC_TOKEN: &str = "ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]";
const ENC_OTHER: &str = "ENC[AES256_GCM,data:xyz,iv:def,tag:ghi,type:str]";

/// A dotenv payload as sops writes it: encrypted values, then the flat
/// `sops_*` metadata that carries the recipient set.
fn payload(values: &[(&str, &str)], recipients: &[&str]) -> String {
    let mut out = String::new();
    for (name, value) in values {
        out.push_str(&format!("{name}={value}\n"));
    }
    for (index, recipient) in recipients.iter().enumerate() {
        out.push_str(&format!(
            "sops_age__list_{index}__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\\nYWdl\n"
        ));
        out.push_str(&format!(
            "sops_age__list_{index}__map_recipient={recipient}\n"
        ));
    }
    out.push_str("sops_lastmodified=2026-11-21T00:00:00Z\n");
    out.push_str("sops_mac=ENC[AES256_GCM,data:zzz,iv:yyy,tag:xxx,type:str]\n");
    out.push_str("sops_version=3.13.3\n");
    out
}

/// The recipient lines, so a test can prove the set survived the edit.
fn recipients(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| line.starts_with("sops_age__list_") && line.contains("__map_recipient="))
        .map(str::to_owned)
        .collect()
}

/// A repository, a fake `sops`, and the file the fake `edit` copies over the
/// payload: the answer a real editor would have produced.
struct Fixture {
    repo: Repo,
    shim: PathBuf,
    log: PathBuf,
    plain: PathBuf,
    result: PathBuf,
    secret: String,
}

impl Fixture {
    fn new(name: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;

        let repo = Repo::new(&format!("edit-{name}"));
        let log = repo.path().join("sops.log");
        let plain = repo.path().join("plain.txt");
        let result = repo.path().join("edited.txt");
        fs::write(&plain, "TOKEN=s3cret\n").unwrap();
        let shim = repo.path().join("sops-shim");
        fs::write(
            &shim,
            concat!(
                "#!/bin/sh\n",
                "{\n",
                "  echo 'argv:'\n",
                "  for argument in \"$@\"; do echo \"  $argument\"; done\n",
                "  echo 'env:'\n",
                "  env\n",
                "  echo '---'\n",
                "} >> \"$EDIT_LOG\"\n",
                "case \"$1\" in\n",
                "  --version) echo 'sops 3.13.3'; exit 0 ;;\n",
                "  -d) cat \"$EDIT_PLAIN\"; exit 0 ;;\n",
                "  edit)\n",
                "    if [ -n \"$EDIT_FAIL\" ]; then\n",
                "      echo 'the editor exited non-zero' >&2\n",
                "      exit 1\n",
                "    fi\n",
                "    cp \"$EDIT_RESULT\" \"$2\"\n",
                "    exit 0 ;;\n",
                "esac\n",
                "exit 1\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();

        Self {
            repo,
            shim,
            log,
            plain,
            result,
            secret: lockset_core::SecretKey::generate().expose().to_owned(),
        }
    }

    /// The original payload and the ciphertext the fake editor leaves behind.
    fn start(&self, before: &str, after: &str) -> Vec<u8> {
        self.repo.write("secrets/dev.env", before);
        fs::write(&self.result, after).unwrap();
        self.bytes()
    }

    fn bytes(&self) -> Vec<u8> {
        fs::read(self.repo.path().join("secrets/dev.env")).unwrap()
    }

    fn write_config(&self, text: &str) {
        self.repo.write("lockset.toml", text);
    }

    fn run(&self, args: &[&str], editor: Option<&str>, fail: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lockset"));
        command
            .arg("--repo")
            .arg(self.repo.path())
            .args(args)
            .env("LOCKSET_SOPS", &self.shim)
            .env("LOCKSET_AGE_KEY", &self.secret)
            .env("EDIT_LOG", &self.log)
            .env("EDIT_PLAIN", &self.plain)
            .env("EDIT_RESULT", &self.result)
            .env_remove("LOCKSET_CONFIG")
            .env_remove("LOCKSET_CUSTODY")
            .env_remove("SOPS_EDITOR");
        if fail {
            command.env("EDIT_FAIL", "1");
        }
        if let Some(editor) = editor {
            command.env("SOPS_EDITOR", editor);
        }
        command.output().unwrap()
    }

    /// Each fake-sops invocation, split into argv lines and environment lines.
    fn invocations(&self) -> Vec<(Vec<String>, Vec<String>)> {
        let text = fs::read_to_string(&self.log).unwrap_or_default();
        let mut out = Vec::new();
        for block in text.split("---").filter(|block| block.contains("argv:")) {
            let (argv_part, env_part) = block.split_once("env:").unwrap();
            let argv = argv_part
                .lines()
                .skip_while(|line| !line.starts_with("argv:"))
                .skip(1)
                .map(|line| line.trim().to_owned())
                .collect();
            let env = env_part.lines().map(str::to_owned).collect();
            out.push((argv, env));
        }
        out
    }

    fn edit_invocation(&self) -> (Vec<String>, Vec<String>) {
        self.invocations()
            .into_iter()
            .find(|(argv, _)| argv.first().map(String::as_str) == Some("edit"))
            .unwrap_or_else(|| panic!("the fake sops never ran `edit`"))
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn an_edit_rewrites_the_payload_and_keeps_the_recipients() {
    let fixture = Fixture::new("success");
    let before = payload(
        &[("TOKEN", ENC_TOKEN), ("OTHER", ENC_OTHER)],
        &[ADMIN, READER],
    );
    let after = payload(
        &[
            ("TOKEN", ENC_TOKEN),
            ("OTHER", ENC_OTHER),
            ("ADDED", ENC_TOKEN),
        ],
        &[ADMIN, READER],
    );
    let original = fixture.start(&before, &after);

    let output = fixture.run(&["edit", "secrets/dev.env"], None, false);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("edited secrets/dev.env"),
        "{}",
        stdout(&output)
    );
    let edited = String::from_utf8(fixture.bytes()).unwrap();
    assert_eq!(edited, after);
    assert_ne!(fixture.bytes(), original);
    assert_eq!(recipients(&edited), recipients(&before));
    let (argv, _) = fixture.edit_invocation();
    assert_eq!(argv.join(" "), "edit secrets/dev.env");
}

#[test]
fn the_editor_defaults_to_vim_and_honours_sops_editor() {
    let fixture = Fixture::new("editor-default");
    let before = payload(&[("TOKEN", ENC_TOKEN)], &[ADMIN]);
    let after = payload(&[("TOKEN", ENC_TOKEN), ("ADDED", ENC_TOKEN)], &[ADMIN]);
    fixture.start(&before, &after);

    let output = fixture.run(&["edit", "--payload", "secrets/dev.env"], None, false);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let (_, env) = fixture.edit_invocation();
    let editors: Vec<String> = env
        .iter()
        .filter(|line| line.starts_with("SOPS_EDITOR="))
        .cloned()
        .collect();
    assert_eq!(editors, ["SOPS_EDITOR=vim -n"], "{env:?}");

    let fixture = Fixture::new("editor-set");
    fixture.start(&before, &after);
    let output = fixture.run(&["edit", "secrets/dev.env"], Some("nano -w"), false);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let (_, env) = fixture.edit_invocation();
    let editors: Vec<String> = env
        .iter()
        .filter(|line| line.starts_with("SOPS_EDITOR="))
        .cloned()
        .collect();
    assert_eq!(editors, ["SOPS_EDITOR=nano -w"], "{env:?}");
}

#[test]
fn the_identity_reaches_the_edit_child_only_through_sops_age_key() {
    let fixture = Fixture::new("identity");
    let before = payload(&[("TOKEN", ENC_TOKEN)], &[ADMIN]);
    let after = payload(&[("TOKEN", ENC_TOKEN), ("ADDED", ENC_TOKEN)], &[ADMIN]);
    fixture.start(&before, &after);

    let output = fixture.run(&["edit", "secrets/dev.env"], None, false);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    for (argv, env) in fixture.invocations() {
        let argv_text = argv.join(" ");
        assert!(!argv_text.contains("AGE-SECRET-KEY"), "{argv_text}");
        assert!(!argv_text.contains(&fixture.secret), "{argv_text}");
        for line in env {
            if let Some(value) = line.strip_prefix("SOPS_EDITOR=") {
                assert!(!value.contains(&fixture.secret), "{line}");
            }
        }
    }
    let (_, env) = fixture.edit_invocation();
    let keys: Vec<String> = env
        .iter()
        .filter(|line| line.starts_with("SOPS_AGE_KEY="))
        .cloned()
        .collect();
    assert_eq!(
        keys,
        [format!("SOPS_AGE_KEY={}", fixture.secret)],
        "{env:?}"
    );
}

#[test]
fn a_failing_editor_leaves_the_payload_byte_identical() {
    let fixture = Fixture::new("failed");
    let before = payload(&[("TOKEN", ENC_TOKEN)], &[ADMIN, READER]);
    let after = payload(&[("TOKEN", ENC_TOKEN), ("ADDED", ENC_TOKEN)], &[ADMIN]);
    let original = fixture.start(&before, &after);

    let output = fixture.run(&["edit", "secrets/dev.env"], None, true);

    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    assert!(stderr(&output).contains("sops edit"), "{}", stderr(&output));
    assert_eq!(fixture.bytes(), original);
}

#[test]
fn a_payload_that_comes_back_unencrypted_is_refused() {
    let fixture = Fixture::new("plaintext");
    let before = payload(&[("TOKEN", ENC_TOKEN)], &[ADMIN, READER]);
    let original = fixture.start(&before, "TOKEN=plain\n");

    let output = fixture.run(&["edit", "secrets/dev.env"], None, false);

    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("not encrypted after the editor closed"),
        "{}",
        stderr(&output)
    );
    assert_eq!(fixture.bytes(), original);
}

#[test]
fn a_payload_that_changes_recipients_is_refused() {
    let fixture = Fixture::new("recipients");
    let before = payload(&[("TOKEN", ENC_TOKEN)], &[ADMIN, READER]);
    let after = payload(&[("TOKEN", ENC_TOKEN)], &[ADMIN, OTHER]);
    let original = fixture.start(&before, &after);

    let output = fixture.run(&["edit", "secrets/dev.env"], None, false);

    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("must keep its recipient set"),
        "{}",
        stderr(&output)
    );
    assert_eq!(fixture.bytes(), original);
}

#[test]
fn a_dry_run_prints_the_plan_and_starts_no_sops() {
    let fixture = Fixture::new("dry-run");
    let before = payload(&[("TOKEN", ENC_TOKEN)], &[ADMIN]);
    let original = fixture.start(&before, &before);

    let output = fixture.run(&["--dry-run", "edit", "secrets/dev.env"], None, false);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("would edit secrets/dev.env"),
        "{}",
        stdout(&output)
    );
    assert_eq!(fixture.bytes(), original);
    assert!(
        !fixture.log.exists(),
        "a dry run must not start sops: {}",
        fs::read_to_string(&fixture.log).unwrap_or_default()
    );
}

#[test]
fn a_dry_run_as_json_names_the_payload_and_no_secret() {
    let fixture = Fixture::new("dry-run-json");
    let before = payload(&[("TOKEN", ENC_TOKEN)], &[ADMIN]);
    fixture.start(&before, &before);

    let output = fixture.run(
        &[
            "--dry-run",
            "--json",
            "edit",
            "--payload",
            "secrets/dev.env",
        ],
        None,
        false,
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(document["plan"]["changes"][0]["type"], "edit_payload");
    assert_eq!(document["plan"]["changes"][0]["payload"], "secrets/dev.env");
    assert!(!text.contains("s3cret"), "{text}");
}

#[test]
fn the_single_default_payload_is_used_without_a_selector() {
    let fixture = Fixture::new("default-one");
    let before = payload(&[("TOKEN", ENC_TOKEN)], &[ADMIN]);
    let after = payload(&[("TOKEN", ENC_TOKEN), ("ADDED", ENC_TOKEN)], &[ADMIN]);
    fixture.start(&before, &after);
    fixture.write_config("[repo]\ndefault_payloads = [\"secrets/dev.env\"]\n");

    let output = fixture.run(&["edit"], None, false);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(String::from_utf8(fixture.bytes()).unwrap(), after);
}

#[test]
fn two_default_payloads_are_a_usage_error() {
    let fixture = Fixture::new("default-two");
    let before = payload(&[("TOKEN", ENC_TOKEN)], &[ADMIN]);
    fixture.start(&before, &before);
    fixture.write_config("[repo]\ndefault_payloads = [\"secrets/a.env\", \"secrets/b.env\"]\n");

    let output = fixture.run(&["edit"], None, false);

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let message = stderr(&output);
    assert!(message.contains("secrets/a.env"), "{message}");
    assert!(message.contains("secrets/b.env"), "{message}");
    assert_eq!(fixture.bytes(), before.as_bytes());
}

#[test]
fn no_default_payload_lists_what_the_repository_has() {
    let fixture = Fixture::new("default-none");
    let before = payload(&[("TOKEN", ENC_TOKEN)], &[ADMIN]);
    fixture.start(&before, &before);

    let output = fixture.run(&["edit"], None, false);

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let message = stderr(&output);
    assert!(message.contains("no payload selected"), "{message}");
    assert!(message.contains("secrets/dev.env"), "{message}");
    assert_eq!(fixture.bytes(), before.as_bytes());
}

#[test]
fn a_path_and_a_payload_flag_conflict() {
    let fixture = Fixture::new("selector-conflict");

    let output = fixture.run(
        &["edit", "secrets/dev.env", "--payload", "secrets/dev.env"],
        None,
        false,
    );

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(!fixture.log.exists());
}
