//! Streams: stdout carries data, stderr carries notes, warnings, and debug
//! lines. `--quiet` and `--verbose` select the level and win over `RUST_LOG`.

mod common;

use std::path::PathBuf;

use common::{lockset, lockset_with, strings, Repo};

/// A repository whose payload decrypts through a shim, so reports succeed.
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
            "#!/bin/sh\ncase \"$1\" in\n  --version) echo 'sops 3.13.3' ;;\n  -d) printf 'TOKEN=1\\n' ;;\n  *) exit 1 ;;\nesac\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        let secret = lockset_core::SecretKey::generate().expose().to_owned();
        Self { repo, shim, secret }
    }

    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
        let mut all = vec![
            ("LOCKSET_AGE_KEY", self.secret.as_str()),
            ("LOCKSET_SOPS", self.shim.to_str().unwrap()),
        ];
        all.extend(env.iter().copied());
        lockset_with(&self.repo, &strings(args), &all, None)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.shim);
    }
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn a_plan_puts_its_notes_on_stderr_and_the_plan_on_stdout() {
    let harness = Harness::new("plan-streams");

    let output = harness.run(&["--dry-run", "rotate", "--all"], &[]);
    let err = stderr(&output);

    assert_eq!(output.status.code(), Some(0), "{err}");
    assert!(err.contains("values are unchanged"), "{err}");
    assert!(
        !stdout(&output).contains("values are unchanged"),
        "a note must not reach stdout: {}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("would rotate"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn quiet_keeps_the_plan_and_drops_the_note() {
    let harness = Harness::new("plan-quiet");

    let output = harness.run(&["--quiet", "--dry-run", "rotate", "--all"], &[]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stderr(&output).is_empty(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("would rotate"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn the_export_warning_goes_to_stderr_only() {
    let harness = Harness::new("export-streams");

    let output = harness.run(&["export", "--payload", "secrets/dev.env"], &[]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(stdout(&output), "TOKEN=1\n");
    assert!(
        stderr(&output).contains("mask them in CI logs"),
        "{}",
        stderr(&output)
    );

    let quiet = harness.run(&["--quiet", "export", "--payload", "secrets/dev.env"], &[]);
    assert!(stderr(&quiet).is_empty(), "{}", stderr(&quiet));
    assert_eq!(stdout(&quiet), "TOKEN=1\n");
}

#[test]
fn verbose_adds_debug_lines_without_touching_stdout() {
    let harness = Harness::new("verbose");

    let plain = harness.run(&["check"], &[]);
    let verbose = harness.run(&["--verbose", "check"], &[]);
    let err = stderr(&verbose);

    assert_eq!(verbose.status.code(), plain.status.code(), "{err}");
    assert_eq!(stdout(&verbose), stdout(&plain));
    assert!(err.contains("repository root"), "{err}");
    assert!(err.contains("custody"), "{err}");
    assert!(err.contains("sops "), "{err}");
    assert!(
        !stderr(&plain).contains("repository root"),
        "{}",
        stderr(&plain)
    );
}

#[test]
fn rust_log_decides_when_neither_flag_is_given() {
    let harness = Harness::new("rust-log");

    let debug = harness.run(&["check"], &[("RUST_LOG", "debug")]);
    assert!(
        stderr(&debug).contains("repository root"),
        "{}",
        stderr(&debug)
    );

    let off = harness.run(
        &["export", "--payload", "secrets/dev.env"],
        &[("RUST_LOG", "off")],
    );
    assert!(stderr(&off).is_empty(), "{}", stderr(&off));
    assert_eq!(stdout(&off), "TOKEN=1\n");
}

#[test]
fn the_flags_win_over_rust_log() {
    let harness = Harness::new("flags-win");

    let quiet = harness.run(&["--quiet", "check"], &[("RUST_LOG", "debug")]);
    assert!(stderr(&quiet).is_empty(), "{}", stderr(&quiet));

    let verbose = harness.run(&["--verbose", "check"], &[("RUST_LOG", "off")]);
    assert!(
        stderr(&verbose).contains("repository root"),
        "{}",
        stderr(&verbose)
    );
}

#[test]
fn quiet_and_verbose_conflict() {
    let harness = Harness::new("conflict");
    let repo = &harness.repo;

    let output = lockset(repo, &strings(&["--quiet", "--verbose", "check"]));

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}
