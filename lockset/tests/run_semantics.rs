//! `run` hands over the child's status and signals, `--clean-env` narrows the
//! environment, and a duplicate key is never resolved without a flag.

#![cfg(unix)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Output;

use common::{lockset_with, strings, Repo};

/// A repository plus a fake sops that answers per payload, and an identity.
struct Harness {
    repo: Repo,
    shim: PathBuf,
    secret: String,
}

impl Harness {
    fn new(name: &str) -> Self {
        let repo = Repo::new(name);
        let shim = repo.path().join("sops-shim");
        std::fs::write(
            &shim,
            "#!/bin/sh\ncase \"$2\" in\n  *a.env) printf 'TOKEN=a\\nONLY_A=1\\n' ;;\n  *b.env) printf 'TOKEN=b\\nONLY_B=2\\n' ;;\n  *dev.env) printf 'TOKEN=from-payload\\n' ;;\n  *) exit 1 ;;\nesac\n",
        )
        .unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        let secret = lockset_core::SecretKey::generate().expose().to_owned();
        Self { repo, shim, secret }
    }

    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut all = vec![("LOCKSET_AGE_KEY", self.secret.as_str())];
        all.push(("LOCKSET_SOPS", self.shim.to_str().unwrap()));
        all.extend(env.iter().copied());
        lockset_with(&self.repo, &strings(args), &all, None)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.shim);
    }
}

#[test]
fn a_child_exit_code_is_preserved() {
    let harness = Harness::new("exit");

    let output = harness.run(
        &[
            "run",
            "--payload",
            "secrets/dev.env",
            "--",
            "sh",
            "-c",
            "exit 7",
        ],
        &[],
    );

    assert_eq!(output.status.code(), Some(7), "{output:?}");
}

#[test]
fn a_child_signal_is_preserved() {
    let harness = Harness::new("signal");

    let output = harness.run(
        &[
            "run",
            "--payload",
            "secrets/dev.env",
            "--",
            "sh",
            "-c",
            "kill -TERM $$",
        ],
        &[],
    );

    assert_eq!(output.status.signal(), Some(15), "{output:?}");
    assert_eq!(output.status.code(), None, "{output:?}");
}

#[test]
fn clean_env_keeps_only_the_allowlist_and_the_payload() {
    let harness = Harness::new("clean");

    let output = harness.run(
        &[
            "run",
            "--clean-env",
            "--payload",
            "secrets/dev.env",
            "--",
            "sh",
            "-c",
            concat!(
                "printf 'token=%s\\n' \"$TOKEN\"; ",
                "printf 'home=%s\\n' \"${HOME:-<unset>}\"; ",
                "printf 'leak=%s\\n' \"${LOCKSET_TEST_SECRET:-<unset>}\"; ",
                "printf 'ci=%s\\n' \"${CI_JOB_TOKEN:-<unset>}\"; ",
                "printf 'identity=%s\\n' \"${LOCKSET_AGE_KEY:-<unset>}\""
            ),
        ],
        &[("LOCKSET_TEST_SECRET", "leak"), ("CI_JOB_TOKEN", "leak")],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("token=from-payload"), "{stdout}");
    assert!(!stdout.contains("home=<unset>"), "{stdout}");
    assert!(stdout.contains("leak=<unset>"), "{stdout}");
    assert!(stdout.contains("ci=<unset>"), "{stdout}");
    assert!(stdout.contains("identity=<unset>"), "{stdout}");
}

#[test]
fn the_default_environment_is_the_parents_minus_the_identity() {
    let harness = Harness::new("scrubbed");

    let output = harness.run(
        &[
            "run",
            "--payload",
            "secrets/dev.env",
            "--",
            "sh",
            "-c",
            "printf '%s' \"${LOCKSET_TEST_SECRET:-<unset>}\"",
        ],
        &[("LOCKSET_TEST_SECRET", "visible")],
    );

    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "visible",
        "only --clean-env narrows the parent environment"
    );
}

#[test]
fn duplicate_keys_are_an_error_by_default() {
    let harness = Harness::new("duplicates");

    let run = harness.run(
        &[
            "run",
            "--payload",
            "secrets/a.env",
            "--payload",
            "secrets/b.env",
            "--",
            "sh",
            "-c",
            "echo the-child-ran",
        ],
        &[],
    );
    let stderr = String::from_utf8_lossy(&run.stderr);

    assert_eq!(run.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("duplicate key TOKEN in secrets/a.env and secrets/b.env"),
        "{stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&run.stdout).contains("the-child-ran"),
        "the child must not start"
    );

    let export = harness.run(
        &[
            "export",
            "--payload",
            "secrets/a.env",
            "--payload",
            "secrets/b.env",
        ],
        &[],
    );
    let stderr = String::from_utf8_lossy(&export.stderr);
    assert_eq!(export.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("duplicate key TOKEN"), "{stderr}");
}

#[test]
fn the_duplicate_flags_choose_a_side() {
    let harness = Harness::new("sides");

    let last = harness.run(
        &[
            "run",
            "--last-wins",
            "--payload",
            "secrets/a.env",
            "--payload",
            "secrets/b.env",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$TOKEN\"",
        ],
        &[],
    );
    assert_eq!(String::from_utf8_lossy(&last.stdout), "b", "{last:?}");

    let first = harness.run(
        &[
            "run",
            "--first-wins",
            "--payload",
            "secrets/a.env",
            "--payload",
            "secrets/b.env",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$TOKEN\"",
        ],
        &[],
    );
    assert_eq!(String::from_utf8_lossy(&first.stdout), "a", "{first:?}");

    let export = harness.run(
        &[
            "export",
            "--last-wins",
            "--payload",
            "secrets/a.env",
            "--payload",
            "secrets/b.env",
        ],
        &[],
    );
    assert!(
        String::from_utf8_lossy(&export.stdout).contains("TOKEN=b"),
        "{export:?}"
    );
}

#[test]
fn contradictory_flags_are_usage_errors() {
    let harness = Harness::new("flags");

    for args in [
        vec![
            "run",
            "--pass-custody",
            "--clean-env",
            "--payload",
            "secrets/dev.env",
            "--",
            "true",
        ],
        vec![
            "run",
            "--last-wins",
            "--first-wins",
            "--payload",
            "secrets/dev.env",
            "--",
            "true",
        ],
    ] {
        let output = harness.run(&args, &[]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
