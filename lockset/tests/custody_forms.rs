//! Custody forms: `env:<NAME>`, `LOCKSET_CUSTODY`, and the per-repo config
//! kind, with the documented precedence and fail-closed errors.

mod common;

use std::process::{Command, Output};

use common::{strings, Repo};

struct Harness {
    repo: Repo,
    first: String,
    second: String,
    first_public: String,
    second_public: String,
}

impl Harness {
    fn new(name: &str) -> Self {
        let repo = Repo::new(name);
        repo.write("secrets/dev.env", "TOKEN=ENC[a,type:str]\n");
        let first = lockset_core::SecretKey::generate();
        let second = lockset_core::SecretKey::generate();
        let first_public = first.public().unwrap().as_str().to_owned();
        let second_public = second.public().unwrap().as_str().to_owned();
        Self {
            repo,
            first: first.expose().to_owned(),
            second: second.expose().to_owned(),
            first_public,
            second_public,
        }
    }

    fn config(&self, text: &str) {
        self.repo.write("lockset.toml", text);
    }

    /// Run with exactly the custody environment the test names: the identity
    /// variables and `LOCKSET_CUSTODY` are cleared first.
    fn invoke(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lockset"));
        command
            .arg("--repo")
            .arg(self.repo.path())
            .args(strings(args))
            .env("LOCKSET_SOPS", "/nonexistent/lockset-test-sops")
            .env_remove("LOCKSET_AGE_KEY")
            .env_remove("LOCKSET_CUSTODY")
            .env_remove("LOCKSET_CONFIG")
            .envs(env.iter().copied());
        command.output().unwrap()
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn env_name_reads_only_the_named_variable() {
    let harness = Harness::new("env-name");

    let named = harness.invoke(
        &["--custody", "env:LOCKSET_TEST_KEY_A", "status"],
        &[("LOCKSET_TEST_KEY_A", &harness.first)],
    );
    let out = stdout(&named);
    assert_eq!(named.status.code(), Some(0), "{}", stderr(&named));
    assert!(out.contains(&harness.first_public), "{out}");

    // Without a flag or LOCKSET_CUSTODY the default policy applies: no
    // identity variable is set, so a non-interactive run has no source.
    let plain = harness.invoke(&["status"], &[("LOCKSET_TEST_KEY_A", &harness.first)]);
    let out = stdout(&plain);
    assert_eq!(plain.status.code(), Some(0), "{}", stderr(&plain));
    assert!(out.contains("identity: none"), "{out}");
}

#[test]
fn two_pipelines_use_different_variables() {
    let harness = Harness::new("two-pipelines");

    let first = harness.invoke(
        &["--custody", "env:LOCKSET_TEST_KEY_A", "status"],
        &[
            ("LOCKSET_TEST_KEY_A", &harness.first),
            ("LOCKSET_TEST_KEY_B", &harness.second),
        ],
    );
    let out = stdout(&first);
    assert!(out.contains(&harness.first_public), "{out}");
    assert!(!out.contains(&harness.second_public), "{out}");

    let second = harness.invoke(
        &["--custody", "env:LOCKSET_TEST_KEY_B", "status"],
        &[
            ("LOCKSET_TEST_KEY_A", &harness.first),
            ("LOCKSET_TEST_KEY_B", &harness.second),
        ],
    );
    let out = stdout(&second);
    assert!(out.contains(&harness.second_public), "{out}");
    assert!(!out.contains(&harness.first_public), "{out}");
}

#[test]
fn lockset_custody_selects_and_the_flag_wins() {
    let harness = Harness::new("lockset-custody");
    let env = [
        ("LOCKSET_TEST_KEY_A", harness.first.as_str()),
        ("LOCKSET_TEST_KEY_B", harness.second.as_str()),
    ];

    let from_env = harness.invoke(
        &["status"],
        &[
            env[0],
            env[1],
            ("LOCKSET_CUSTODY", "env:LOCKSET_TEST_KEY_B"),
        ],
    );
    assert!(
        stdout(&from_env).contains(&harness.second_public),
        "{}",
        stdout(&from_env)
    );

    let from_flag = harness.invoke(
        &["--custody", "env:LOCKSET_TEST_KEY_A", "status"],
        &[
            env[0],
            env[1],
            ("LOCKSET_CUSTODY", "env:LOCKSET_TEST_KEY_B"),
        ],
    );
    let out = stdout(&from_flag);
    assert!(out.contains(&harness.first_public), "{out}");
    assert!(!out.contains(&harness.second_public), "{out}");
}

#[test]
fn an_empty_lockset_custody_falls_through_to_the_policy() {
    let harness = Harness::new("empty-lockset-custody");

    let output = harness.invoke(
        &["status"],
        &[
            ("LOCKSET_CUSTODY", "   "),
            ("LOCKSET_AGE_KEY", &harness.first),
        ],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains(&harness.first_public));
}

#[test]
fn a_config_env_name_applies_without_a_flag() {
    let harness = Harness::new("config-env-name");
    harness.config("[custody]\nkind = \"env:DEPLOY_KEY\"\n");

    let output = harness.invoke(&["status"], &[("DEPLOY_KEY", &harness.first)]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains(&harness.first_public));
}

#[test]
fn a_config_kind_none_stays_none_off_a_terminal() {
    let harness = Harness::new("config-none");
    harness.config("[custody]\nkind = \"none\"\n");

    let output = harness.invoke(&["status"], &[]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains("identity: none"));
}

#[test]
fn invalid_specs_fail_closed() {
    let harness = Harness::new("invalid");
    let key = [("LOCKSET_AGE_KEY", harness.first.as_str())];

    for (args, env) in [
        (vec!["--custody", "magic", "status"], key.as_slice()),
        (
            vec!["status"],
            &[("LOCKSET_CUSTODY", "magic")] as &[(&str, &str)],
        ),
        (vec!["--custody", "file:", "status"], key.as_slice()),
    ] {
        let output = harness.invoke(&args, env);
        let err = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{}: {err}", args.join(" "));
        assert!(stdout(&output).is_empty(), "no report is printed: {err}");
    }

    let forms = harness.invoke(&["--custody", "magic", "status"], &[]);
    let err = stderr(&forms);
    assert!(err.contains("env:<NAME>"), "{err}");
    assert!(err.contains("file:<absolute path>"), "{err}");
    assert!(err.contains("keyring:<service>"), "{err}");
}
