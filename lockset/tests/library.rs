//! The orchestration as a library: inputs injected, both streams captured, no
//! process spawned. This is the reuse path an action or another front end uses.

mod common;

use clap::Parser;
use lockset::{run, run_with_context, wiring, Cli, Inputs, Stdin};
use lockset_core::CustodyKind;
use lockset_tools::custody::MemoryCustody;
use lockset_tools::fs_repo::FsRepo;
use lockset_tools::sops::SopsCodec;

use common::{strings, Repo};

/// One in-process call: the exit code and both captured streams.
struct Called {
    code: u8,
    out: String,
    err: String,
}

fn call(repo: &Repo, args: &[&str], inputs: &Inputs) -> Called {
    let mut cli_args = vec![
        "lockset".to_owned(),
        "--repo".to_owned(),
        repo.path().display().to_string(),
    ];
    cli_args.extend(strings(args));
    let cli = Cli::parse_from(cli_args);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let code = run(cli, inputs, &mut out, &mut err);
    Called {
        code,
        out: String::from_utf8_lossy(&out).into_owned(),
        err: String::from_utf8_lossy(&err).into_owned(),
    }
}

fn repo_with_payload(name: &str) -> Repo {
    let repo = Repo::new(name);
    repo.write("secrets/dev.env", "TOKEN=ENC[a,type:str]\n");
    repo
}

#[test]
fn status_reports_through_the_captured_streams() {
    let repo = repo_with_payload("library-status");
    let key = lockset_core::SecretKey::generate();
    let inputs = Inputs::default().with_var("LOCKSET_AGE_KEY", key.expose());

    let called = call(&repo, &["status"], &inputs);

    assert_eq!(called.code, 0, "{}", called.err);
    assert!(
        called.out.contains(key.public().unwrap().as_str()),
        "{}",
        called.out
    );
    assert!(called.err.is_empty(), "{}", called.err);
}

#[test]
fn a_plan_note_goes_to_the_injected_stderr() {
    let repo = repo_with_payload("library-plan");
    let inputs = Inputs::default();

    let called = call(&repo, &["--dry-run", "rotate", "--all"], &inputs);

    assert_eq!(called.code, 0, "{}", called.err);
    assert!(called.out.contains("would rotate"), "{}", called.out);
    assert!(
        called.err.contains("values are unchanged"),
        "{}",
        called.err
    );
    assert!(
        !called.out.contains("values are unchanged"),
        "{}",
        called.out
    );
}

#[test]
fn quiet_suppresses_notes_but_keeps_data() {
    let repo = repo_with_payload("library-quiet");
    let inputs = Inputs::default();

    let called = call(&repo, &["--quiet", "--dry-run", "rotate", "--all"], &inputs);

    assert_eq!(called.code, 0, "{}", called.err);
    assert!(called.out.contains("would rotate"), "{}", called.out);
    assert!(called.err.is_empty(), "{}", called.err);
}

#[test]
fn supplied_stdin_feeds_set_without_a_process_pipe() {
    let repo = repo_with_payload("library-stdin");
    let inputs = Inputs::default().with_stdin(Stdin::Text("value\n".into()));

    let called = call(
        &repo,
        &[
            "set",
            "TOKEN",
            "--payload",
            "secrets/dev.env",
            "--stdin",
            "--dry-run",
        ],
        &inputs,
    );

    assert_eq!(called.code, 0, "{}", called.err);
    assert!(
        called.out.contains("would set TOKEN in secrets/dev.env"),
        "{}",
        called.out
    );
}

#[test]
fn custody_reads_the_injected_variables_not_the_process() {
    let repo = repo_with_payload("library-custody");
    let key = lockset_core::SecretKey::generate();
    // The process has no such variable: only the injected inputs carry it.
    let inputs = Inputs::default().with_var("LIBRARY_ONLY_KEY", key.expose());

    let named = call(
        &repo,
        &["--custody", "env:LIBRARY_ONLY_KEY", "status"],
        &inputs,
    );
    assert_eq!(named.code, 0, "{}", named.err);
    assert!(
        named.out.contains(key.public().unwrap().as_str()),
        "{}",
        named.out
    );

    let plain = Inputs::default();
    let none = call(&repo, &["status"], &plain);
    assert!(none.out.contains("identity: none"), "{}", none.out);
}

#[test]
fn rust_log_debug_from_the_inputs_reaches_stderr() {
    let repo = repo_with_payload("library-log");
    let inputs = Inputs::default().with_var("RUST_LOG", "debug");

    let called = call(&repo, &["status"], &inputs);

    assert_eq!(called.code, 0, "{}", called.err);
    assert!(called.err.contains("repository root"), "{}", called.err);
    assert!(called.err.contains("sops "), "{}", called.err);
}

#[test]
fn a_bad_argument_still_exits_two_with_the_message_on_stderr() {
    let repo = repo_with_payload("library-usage");
    let inputs = Inputs::default();

    let called = call(&repo, &["--custody", "magic", "status"], &inputs);

    assert_eq!(called.code, 2, "{}", called.err);
    assert!(called.out.is_empty(), "{}", called.out);
    assert!(called.err.contains("error: "), "{}", called.err);
    assert!(called.err.contains("env:<NAME>"), "{}", called.err);
}

#[test]
fn injected_ports_replace_custody_and_codec() {
    // A caller that wants its own ports: no environment, no keychain, no
    // sops-on-PATH — the same orchestration over an in-memory custody.
    let repo = repo_with_payload("library-ports");
    let key = lockset_core::SecretKey::generate();
    let public = key.public().unwrap().as_str().to_owned();
    let config = lockset_core::Config::default();
    let context = wiring::Context {
        root: repo.path().to_path_buf(),
        repo: FsRepo::new(repo.path()),
        codec: SopsCodec::new(repo.path(), "sops", lockset_core::MIN_VERSION),
        custody: Box::new(MemoryCustody::new(Some(key))),
        config,
        config_path: None,
        config_text: None,
    };
    let cli = Cli::parse_from(["lockset", "--repo", repo.path().to_str().unwrap(), "status"]);
    let inputs = Inputs::default();
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();

    let code = run_with_context(cli, context, &inputs, &mut out, &mut err);
    let out = String::from_utf8_lossy(&out).into_owned();

    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
    assert!(out.contains(&public), "{out}");
    assert!(
        out.contains(&format!("via {}", CustodyKind::Memory)),
        "{out}"
    );
}
