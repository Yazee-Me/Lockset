//! The security boundary between lockset and sops, asserted against a fake
//! `sops` that records every argv and environment it is invoked with: the
//! identity never reaches argv, and the sops child never inherits it (or a
//! `SOPS_*` override) from the parent environment.

#![cfg(unix)]

mod common;

use std::path::PathBuf;
use std::process::{Command, Output};

use common::Repo;

const ADMIN: &str = "age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x";
const READER: &str = "age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q";
const NEW_VALUE: &str = "contract-value-never-in-argv";

struct Recorder {
    repo: Repo,
    shim: PathBuf,
    /// A real identity, so the CLI accepts it; the test inspects how it is
    /// handed to sops, not whether sops could decrypt.
    secret: String,
    /// Every invocation, as `argv:` / `env:` blocks.
    log: PathBuf,
    /// The plaintext the fake decrypts, and where it writes a set value.
    /// The recorder variables are deliberately not `SOPS_*`: those are stripped
    /// from the child environment (which the assertions below also check).
    plain: PathBuf,
}

impl Recorder {
    fn new(name: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;

        let repo = Repo::new(name);
        repo.write(
            ".sops.yaml",
            &format!(
                "creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: {ADMIN},{READER} # admin,dev-reader\n"
            ),
        );
        repo.write(
            "secrets/dev.env",
            &format!(
                "TOKEN=ENC[a,type:str]\n\
                 sops_age__list_0__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\\nYWdl\n\
                 sops_age__list_0__map_recipient={ADMIN}\n\
                 sops_lastmodified=2026-11-21T00:00:00Z\n\
                 sops_mac=ENC[a,type:str]\n\
                 sops_version=3.13.3\n"
            ),
        );
        let log = repo.path().join("sops.log");
        let plain = repo.path().join("plain.env");
        std::fs::write(&plain, "TOKEN=s3cret\n").unwrap();

        let shim = repo.path().join("sops-recorder");
        std::fs::write(
            &shim,
            concat!(
                "#!/bin/sh\n",
                "{\n",
                "  echo 'argv:'\n",
                "  for argument in \"$@\"; do echo \"  $argument\"; done\n",
                "  echo 'env:'\n",
                "  env\n",
                "  echo '---'\n",
                "} >> \"$RECORDER_LOG\"\n",
                "for argument in \"$@\"; do\n",
                "  case \"$argument\" in\n",
                "    --version) echo 'sops 3.13.3'; exit 0 ;;\n",
                "    -d) cat \"$RECORDER_PLAIN\"; exit 0 ;;\n",
                "    updatekeys|rotate) exit 0 ;;\n",
                "    set)\n",
                "      name=$(printf '%s' \"$4\" | tr -d '[]\"')\n",
                "      value=$(cat)\n",
                "      value=${value#\\\"}\n",
                "      value=${value%\\\"}\n",
                "      printf '%s=%s\\n' \"$name\" \"$value\" > \"$RECORDER_PLAIN\"\n",
                "      exit 0 ;;\n",
                "    edit) exit 0 ;;\n",
                "  esac\n",
                "done\n",
                "exit 1\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();

        Self {
            repo,
            shim,
            secret: lockset_core::SecretKey::generate().expose().to_owned(),
            log,
            plain,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_lockset"))
            .arg("--repo")
            .arg(self.repo.path())
            .args(args)
            .env("LOCKSET_SOPS", &self.shim)
            .env("LOCKSET_AGE_KEY", &self.secret)
            .env("RECORDER_LOG", &self.log)
            .env("RECORDER_PLAIN", &self.plain)
            .env("NEW_VALUE", NEW_VALUE)
            // Variables the sops child must not inherit, even if the parent has them.
            .env("SOPS_AGE_KEY_FILE", "/parent/key.txt")
            .env("SOPS_AGE_KEY_CMD", "parent-command")
            .env("SOPS_AGE_RECIPIENTS", "age1parentrecipient")
            .env_remove("SOPS_EDITOR")
            .output()
            .unwrap()
    }

    /// Each invocation split into its argv lines and its environment lines.
    fn invocations(&self) -> Vec<(Vec<String>, Vec<String>)> {
        let text = std::fs::read_to_string(&self.log).unwrap();
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
        assert!(!out.is_empty(), "the fake sops was never invoked");
        out
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn the_identity_never_reaches_sops_argv_or_an_inherited_variable() {
    let recorder = Recorder::new("contract");
    let operations: [&[&str]; 6] = [
        &["status"],
        &["export", "--payload", "secrets/dev.env"],
        &[
            "set",
            "TOKEN",
            "--payload",
            "secrets/dev.env",
            "--from-env",
            "NEW_VALUE",
        ],
        &[
            "grant",
            "age1y4gs9hk93n3mpvhwydaq7uz4mn3a0esf0wfh3md2v2qz4hye9frsfpelwh",
            "--label",
            "dev-new",
        ],
        &["rotate", "--all"],
        &["edit", "--payload", "secrets/dev.env"],
    ];

    for args in operations {
        let output = recorder.run(args);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{} failed: {}",
            args.join(" "),
            stderr(&output)
        );
    }

    let invocations = recorder.invocations();
    for (argv, env) in &invocations {
        let argv_text = argv.join(" ");
        assert!(
            !argv_text.contains("AGE-SECRET-KEY"),
            "an identity reached sops argv: {argv_text}"
        );
        assert!(
            !argv_text.contains(&recorder.secret),
            "the identity reached sops argv: {argv_text}"
        );
        assert!(
            !argv_text.contains(NEW_VALUE),
            "a set value reached sops argv: {argv_text}"
        );
        assert!(
            !env.iter().any(|line| line.starts_with("LOCKSET_AGE_KEY=")),
            "the sops child inherited LOCKSET_AGE_KEY: {env:?}"
        );
        for name in [
            "SOPS_AGE_KEY_FILE",
            "SOPS_AGE_KEY_CMD",
            "SOPS_AGE_RECIPIENTS",
        ] {
            assert!(
                !env.iter().any(|line| line.starts_with(&format!("{name}="))),
                "the sops child inherited {name}: {env:?}"
            );
        }
        // The version preflight needs no key; every other operation gets
        // exactly one key source, in the environment only.
        if argv.first().map(String::as_str) != Some("--version") {
            let expected = format!("SOPS_AGE_KEY={}", recorder.secret);
            assert_eq!(
                env.iter()
                    .filter(|line| line.starts_with("SOPS_AGE_KEY="))
                    .count(),
                1,
                "exactly the intended key source: {env:?}"
            );
            assert!(
                env.iter().any(|line| line == &expected),
                "the intended key source is missing: {env:?}"
            );
        }
    }

    // The argv shapes the codec relies on, once per operation.
    let argv_lines: Vec<String> = invocations.iter().map(|(argv, _)| argv.join(" ")).collect();
    assert!(
        argv_lines.contains(&"-d secrets/dev.env".to_owned()),
        "decrypt argv missing: {argv_lines:?}"
    );
    assert!(
        argv_lines.contains(&"set --value-stdin secrets/dev.env [\"TOKEN\"]".to_owned()),
        "set argv missing: {argv_lines:?}"
    );
    assert!(
        argv_lines.contains(&"updatekeys -y secrets/dev.env".to_owned()),
        "updatekeys argv missing: {argv_lines:?}"
    );
    assert!(
        argv_lines.contains(&"rotate -i secrets/dev.env".to_owned()),
        "rotate argv missing: {argv_lines:?}"
    );
    assert!(
        argv_lines.contains(&"edit secrets/dev.env".to_owned()),
        "edit argv missing: {argv_lines:?}"
    );

    // `edit` is the one child that starts the user's editor, so it carries
    // exactly the editor `SOPS_EDITOR` names (defaulted here).
    let (_, edit_env) = invocations
        .iter()
        .find(|(argv, _)| argv.join(" ") == "edit secrets/dev.env")
        .expect("the fake sops never ran edit");
    assert_eq!(
        edit_env
            .iter()
            .filter(|line| line.starts_with("SOPS_EDITOR="))
            .count(),
        1,
        "exactly one editor: {edit_env:?}"
    );
    assert!(
        edit_env.iter().any(|line| line == "SOPS_EDITOR=vim -n"),
        "the default editor is missing: {edit_env:?}"
    );
}
