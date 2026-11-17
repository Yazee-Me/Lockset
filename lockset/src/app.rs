//! The orchestration the CLI runs. `main` parses, calls one function, and maps
//! the result to an exit code; everything else lives here and can be called by
//! a test or an action with its own inputs and ports.

use std::ffi::OsString;
use std::fmt::Display;
use std::io::Write;

use anyhow::Result;
use lockset_core::ops::{self, GrantRequest, RevokeRequest, RevokeTarget};
use lockset_core::{
    exec, Change, Check, CheckReport, Codec, DuplicateKeys, IdentityReport, Label, PathId, Plan,
    PubKey, SecretValue, StatusReport,
};

use crate::cli::{self, Cli, Command, KeyCommand, PersonCommand};
use crate::diag::Level;
use crate::inputs::Inputs;
use crate::{input, render, usage, wiring};

/// Data on stdout, diagnostics on stderr: the handlers below read like the
/// `println!`/`eprintln!`/`log` calls they replaced, but every byte goes
/// through the caller's writers.
macro_rules! sayln {
    ($ui:expr, $($arg:tt)*) => {
        $ui.writeln_fmt(format_args!($($arg)*))
    };
}
macro_rules! say {
    ($ui:expr, $($arg:tt)*) => {
        $ui.write_fmt(format_args!($($arg)*))
    };
}
macro_rules! sayln_err {
    ($ui:expr, $($arg:tt)*) => {
        $ui.strict(format_args!($($arg)*))
    };
}
macro_rules! warn {
    ($ui:expr, $($arg:tt)*) => {
        $ui.warn(format_args!($($arg)*))
    };
}
macro_rules! note {
    ($ui:expr, $($arg:tt)*) => {
        $ui.note(format_args!($($arg)*))
    };
}

/// The library entry point: exit code, all output through the two writers.
pub fn run(cli: Cli, inputs: &Inputs, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let mut ui = Ui::new(out, err, level(&cli, inputs));
    match execute(cli, inputs, &mut ui) {
        Ok(code) => code,
        Err(error) => {
            ui.error(format_args!("{error:#}"));
            usage::exit_code(&error)
        }
    }
}

/// The same orchestration over ports the caller built: an action or a test can
/// inject a different codec, custody, or repository.
pub fn run_with_context(
    cli: Cli,
    context: wiring::Context,
    inputs: &Inputs,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let mut ui = Ui::new(out, err, level(&cli, inputs));
    let result = json_requested(&cli).and_then(|_| dispatch(&cli, &context, inputs, &mut ui));
    match result {
        Ok(code) => code,
        Err(error) => {
            ui.error(format_args!("{error:#}"));
            usage::exit_code(&error)
        }
    }
}

fn level(cli: &Cli, inputs: &Inputs) -> Level {
    Level::resolve(cli.quiet, cli.verbose, inputs.var("RUST_LOG"))
}

/// Parse-time checks, the context, and the command.
fn execute(cli: Cli, inputs: &Inputs, ui: &mut Ui) -> Result<u8> {
    json_requested(&cli)?;
    let context = wiring::Context::detect(&cli, inputs)?;
    ui.debug(format_args!("repository root {}", context.root.display()));
    ui.debug(format_args!("custody {}", context.custody.kind()));
    ui.debug(format_args!("sops {}", context.codec.bin()));
    ui.debug(format_args!("sops config {}", context.config.sops_config));
    dispatch(&cli, &context, inputs, ui)
}

/// stdout and stderr with a level, so a library caller captures both instead
/// of inheriting the process's.
pub struct Ui<'a> {
    out: &'a mut dyn Write,
    err: &'a mut dyn Write,
    level: Level,
}

impl<'a> Ui<'a> {
    pub fn new(out: &'a mut dyn Write, err: &'a mut dyn Write, level: Level) -> Self {
        Self { out, err, level }
    }

    /// Data, no newline.
    pub fn write_fmt(&mut self, args: impl Display) {
        let _ = write!(self.out, "{args}");
    }

    /// Data, one line.
    pub fn writeln_fmt(&mut self, args: impl Display) {
        let _ = writeln!(self.out, "{args}");
    }

    pub fn blank_line(&mut self) {
        let _ = writeln!(self.out);
    }

    /// Diagnostics that belong to the outcome (strict findings): always on
    /// stderr, whatever the level.
    pub fn strict(&mut self, args: impl Display) {
        let _ = writeln!(self.err, "{args}");
    }

    pub fn note(&mut self, args: impl Display) {
        if self.level.allows(Level::Info) {
            let _ = writeln!(self.err, "{}", Level::Info.format(args));
        }
    }

    pub fn warn(&mut self, args: impl Display) {
        if self.level.allows(Level::Warn) {
            let _ = writeln!(self.err, "{}", Level::Warn.format(args));
        }
    }

    pub fn debug(&mut self, args: impl Display) {
        if self.level.allows(Level::Debug) {
            let _ = writeln!(self.err, "{}", Level::Debug.format(args));
        }
    }

    pub fn error(&mut self, args: impl Display) {
        let _ = writeln!(self.err, "error: {args}");
    }

    /// Ask a yes/no question on stdout, answered by the injected stdin.
    pub fn ask(&mut self, question: &str, inputs: &Inputs) -> Result<bool> {
        input::confirm(question, inputs, self.out)
    }
}

/// Write the plan's notes and warnings to stderr, then its body to stdout.
fn emit_plan(plan: &Plan, cli: &Cli, ui: &mut Ui) -> Result<()> {
    for note in &plan.notes {
        ui.note(note);
    }
    for warning in &plan.warnings {
        ui.warn(warning);
    }
    let body = render::plan(plan, cli.dry_run, cli.json)?;
    ui.write_fmt(body);
    Ok(())
}

/// A path from the command line. Parsing it first means an absolute path,
/// `..`, a backslash, an empty segment, or a leading `-` stops here, before any
/// sops invocation can be handed the value.
fn payload_id(value: &str) -> Result<PathId> {
    PathId::parse(value).map_err(|error| usage::error(error.to_string()))
}

fn payload_list(list: &str) -> Result<Vec<PathId>> {
    list.split(',')
        .map(|path| payload_id(path.trim()))
        .collect()
}

/// Whether `--json` applies here. Reports are JSON on their own; a plan is
/// JSON only with `--dry-run` (an apply's log is text); `run` has no document.
fn json_requested(cli: &Cli) -> Result<bool> {
    if !cli.json {
        return Ok(false);
    }
    match &cli.command {
        Command::Who { toml: true } if cli.json => Err(usage::error(
            "--json prints the identity map; --toml prints a lockset.toml fragment",
        )),
        Command::Status { .. } | Command::Who { .. } | Command::Check | Command::Doctor => Ok(true),
        Command::Run { .. } => Err(usage::error(
            "--json prints plans and reports; run has no JSON output",
        )),
        Command::Export { .. } => Err(usage::error(
            "--json prints plans and reports; export has its own --format",
        )),
        _ if !cli.dry_run => Err(usage::error("--json prints a plan; pass --dry-run with it")),
        _ => Ok(true),
    }
}

/// How the child's environment starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildEnv {
    /// The parent's, minus the identity and every `SOPS_*` variable.
    Scrubbed,
    /// Only `PATH`, `HOME`, `TMPDIR`, and `LANG` from the parent.
    Clean,
    /// The parent's, identity included (`--pass-custody`).
    Inherited,
}

fn dispatch(cli: &Cli, context: &wiring::Context, inputs: &Inputs, ui: &mut Ui) -> Result<u8> {
    let _lock = wiring::mutation_lock(cli, context)?;
    match &cli.command {
        Command::Status { strict } => {
            let report = StatusReport::new(&wiring::snapshot(context)?);
            if cli.json {
                sayln!(ui, "{}", render::json(&report)?);
            } else {
                sayln!(ui, "{}", render::status(&report));
            }
            if *strict {
                let findings = report.strict_findings();
                if !findings.is_empty() {
                    sayln_err!(ui, "strict: {} finding(s)", findings.len());
                    for finding in &findings {
                        sayln_err!(ui, "  {finding}");
                    }
                    return Ok(1);
                }
            }
            Ok(0)
        }
        Command::Who { toml } => {
            let snapshot = wiring::snapshot(context)?;
            if *toml {
                if !snapshot.registry.is_empty() {
                    warn!(
                        ui,
                        "lockset.toml already registers {} identities; this block is the comment \
                         view and may be stale",
                        snapshot.registry.identities().len()
                    );
                }
                let unlabelled = snapshot
                    .sops
                    .rules()
                    .iter()
                    .flat_map(|rule| rule.recipients.iter())
                    .filter(|recipient| recipient.label.is_none())
                    .count();
                if unlabelled > 0 {
                    warn!(
                    ui,
                        "{unlabelled} recipient(s) have no comment label; add them to lockset.toml by hand"
                    );
                }
                say!(ui, "{}", render::identities_toml(&snapshot));
                return Ok(0);
            }
            let report = IdentityReport::new(&snapshot);
            if cli.json {
                sayln!(ui, "{}", render::json(&report)?);
            } else {
                sayln!(ui, "{}", render::who(&report));
            }
            Ok(0)
        }
        Command::Check => check(context, cli, ui),
        Command::Doctor => doctor(context, cli, ui),
        Command::Set {
            key,
            payload,
            stdin,
            from_env,
            value_file,
            allow_empty,
            if_absent,
        } => set(
            context,
            cli,
            inputs,
            ui,
            &input::ValueSource {
                stdin: *stdin,
                from_env: from_env.as_deref(),
                file: value_file.as_deref(),
                allow_empty: *allow_empty,
            },
            SetRequest {
                name: key,
                payload: payload.as_deref(),
                if_absent: *if_absent,
            },
        ),
        Command::Rotate { all, payload } => rotate(context, cli, ui, *all, payload),
        Command::Person { command } => person(context, cli, ui, command),
        Command::Export {
            payload,
            format,
            last_wins,
            first_wins,
        } => export(
            context,
            payload,
            *format,
            duplicate_policy(*last_wins, *first_wins),
            ui,
        ),
        Command::Run {
            payload,
            pass_custody,
            clean_env,
            last_wins,
            first_wins,
            argv,
        } => run_command(
            context,
            payload,
            argv,
            child_env(*pass_custody, *clean_env),
            duplicate_policy(*last_wins, *first_wins),
            inputs,
        ),
        Command::Key { command } => key(context, cli, inputs, ui, command),
        Command::Grant {
            public,
            label,
            only,
        } => grant(context, cli, public, label, only.as_deref(), ui),
        Command::Revoke {
            public,
            label,
            keep_data_key,
            force,
        } => revoke(
            context,
            cli,
            public.as_deref(),
            label.as_deref(),
            *keep_data_key,
            *force,
            ui,
        ),
    }
}

/// The payloads a command falls back to when no `--payload` is given: the
/// config's `repo.default_payloads`. A repository that configures none gets an
/// error naming what it does have; no production path is invented.
fn selected_payloads(context: &wiring::Context) -> Result<Vec<PathId>> {
    if context.config.has_default_payloads() {
        return Ok(context.config.default_payloads.clone());
    }
    Err(no_default_payload(context))
}

fn one_default_payload(context: &wiring::Context) -> Result<PathId> {
    match context.config.default_payloads.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(no_default_payload(context)),
        many => Err(usage::error(format!(
            "set writes one payload, but repo.default_payloads lists {} ({}); pass --payload <PATH>",
            many.len(),
            many.iter()
                .map(|id| id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

fn no_default_payload(context: &wiring::Context) -> anyhow::Error {
    let discovered = wiring::snapshot(context)
        .map(|snapshot| {
            snapshot
                .payloads
                .iter()
                .map(|payload| payload.id.as_str().to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let list = if discovered.is_empty() {
        "the repository has no payloads".to_owned()
    } else {
        format!("discovered: {}", discovered.join(", "))
    };
    usage::error(format!(
        "no payload selected: pass --payload <PATH> or set repo.default_payloads in \
         lockset.toml ({list})"
    ))
}

/// Preflight for a pipeline: repo, sops, custody, identity, coverage, payloads,
/// and the CI custody policy. Every item is a finding, so the exit code is 1
/// when anything is off and the failing check is named.
fn doctor(context: &wiring::Context, cli: &Cli, ui: &mut Ui) -> Result<u8> {
    let mut checks: Vec<Check> = Vec::new();

    let snapshot = match wiring::snapshot(context) {
        Ok(snapshot) => {
            checks.push(Check {
                name: "repo".into(),
                ok: true,
                detail: format!(
                    "{} (sops config: {})",
                    context.root.display(),
                    context.config.sops_config
                ),
            });
            Some(snapshot)
        }
        Err(error) => {
            checks.push(Check {
                name: "repo".into(),
                ok: false,
                detail: format!("cannot read the repository: {error:#}"),
            });
            None
        }
    };

    checks.push(match context.codec.preflight() {
        Ok(version) => Check {
            name: "sops".into(),
            ok: true,
            detail: format!("{version} ({})", context.codec.bin()),
        },
        Err(error) => Check {
            name: "sops".into(),
            ok: false,
            detail: error.to_string(),
        },
    });

    checks.push(match context.custody.get() {
        Ok(Some(key)) => match key.public() {
            Ok(public) => Check {
                name: "custody".into(),
                ok: true,
                detail: format!("{} holds {public}", context.custody.kind()),
            },
            Err(error) => Check {
                name: "custody".into(),
                ok: false,
                detail: error.to_string(),
            },
        },
        Ok(None) => Check {
            name: "custody".into(),
            ok: true,
            detail: format!("{} (no identity)", context.custody.kind()),
        },
        Err(error) => Check {
            name: "custody".into(),
            ok: false,
            detail: error.to_string(),
        },
    });

    checks.push(Check {
        name: "legacy identity sources".into(),
        ok: true,
        detail: format!(
            "only {} and the {} item (account {}) are read",
            context.config.custody.env,
            context.config.custody.keychain_item,
            context
                .config
                .custody
                .keychain_account
                .clone()
                .unwrap_or_else(|| { "current user".to_owned() })
        ),
    });

    let kind = context.custody.kind();
    checks.push(Check {
        name: "CI custody policy".into(),
        ok: kind != lockset_core::CustodyKind::None,
        detail: if kind == lockset_core::CustodyKind::None {
            "no identity source for a non-interactive run; set LOCKSET_AGE_KEY or \
             pass --custody file:<path>"
                .into()
        } else {
            format!("{kind}")
        },
    });

    match &snapshot {
        Some(snapshot) => {
            let status = StatusReport::new(snapshot);

            checks.push(match (&status.identity, &status.identity_error) {
                (Some(identity), _) => Check {
                    name: "identity".into(),
                    ok: true,
                    detail: format!("{} via {}", identity.public, identity.custody),
                },
                (None, Some(error)) => Check {
                    name: "identity".into(),
                    ok: false,
                    detail: format!("unavailable: {error}"),
                },
                (None, None) => Check {
                    name: "identity".into(),
                    ok: false,
                    detail: "none — run `lockset key import`".into(),
                },
            });

            checks.push(match &status.coverage {
                Some(coverage) if coverage.missing.is_empty() => Check {
                    name: "coverage".into(),
                    ok: true,
                    detail: format!("opens all {} payloads", coverage.total),
                },
                Some(coverage) => Check {
                    name: "coverage".into(),
                    ok: false,
                    detail: format!(
                        "opens {}/{} payloads; missing: {}",
                        coverage.opens,
                        coverage.total,
                        coverage
                            .missing
                            .iter()
                            .map(|path| path.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                },
                None => Check {
                    name: "coverage".into(),
                    ok: false,
                    detail: "no identity to check coverage with".into(),
                },
            });

            checks.push(Check {
                name: "payloads".into(),
                ok: status.payload_errors.is_empty(),
                detail: if status.payload_errors.is_empty() {
                    format!("{} payloads", status.payloads.len())
                } else {
                    status
                        .payload_errors
                        .iter()
                        .map(|error| format!("{}: {}", error.id, error.error))
                        .collect::<Vec<_>>()
                        .join("; ")
                },
            });

            let defaults = &context.config.default_payloads;
            let missing: Vec<&PathId> = defaults
                .iter()
                .filter(|id| !status.payloads.iter().any(|payload| &payload.path == *id))
                .collect();
            checks.push(Check {
                name: "default payloads".into(),
                ok: missing.is_empty(),
                detail: if defaults.is_empty() {
                    "none configured; run and set need --payload".to_owned()
                } else if missing.is_empty() {
                    defaults
                        .iter()
                        .map(|id| id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                } else {
                    format!(
                        "missing: {}; discovered: {}",
                        missing
                            .iter()
                            .map(|id| id.as_str())
                            .collect::<Vec<_>>()
                            .join(", "),
                        status
                            .payloads
                            .iter()
                            .map(|payload| payload.path.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                },
            });
        }
        None => {
            for name in ["identity", "coverage", "payloads", "default payloads"] {
                checks.push(Check {
                    name: name.into(),
                    ok: false,
                    detail: "not checked: `.sops.yaml` could not be read".into(),
                });
            }
        }
    }

    let report = CheckReport::new(checks);
    if cli.json {
        sayln!(ui, "{}", render::json(&report)?);
    } else {
        sayln!(ui, "{}", render::check(&report));
    }
    Ok(if report.failed() == 0 { 0 } else { 1 })
}

fn check(context: &wiring::Context, cli: &Cli, ui: &mut Ui) -> Result<u8> {
    let snapshot = wiring::snapshot(context)?;
    let mut results = ops::checks(&snapshot, &context.config.labels);

    // A label is a name, not a permission: whatever identity this machine has
    // gets a decrypt proof for every payload it is a recipient of.
    if let Some(identity) = &snapshot.identity {
        let key = context.require_key()?;
        for payload in snapshot.payloads_with(&identity.public) {
            if let Err(error) = context.codec.decrypt(&payload.id, &key) {
                results.push(Check {
                    name: format!("decrypts: {}", payload.id),
                    ok: false,
                    detail: error.to_string(),
                });
            }
        }
    }

    let report = CheckReport::new(results);
    if cli.json {
        sayln!(ui, "{}", render::json(&report)?);
    } else {
        sayln!(ui, "{}", render::check(&report));
    }
    Ok(if report.failed() == 0 { 0 } else { 1 })
}

/// Values for a multi-step pipeline. Only the selected payload values reach
/// stdout; the identity never does, and the warning goes to stderr so a pipeline
/// can still consume stdout as data.
fn export(
    context: &wiring::Context,
    payload: &[String],
    format: cli::ExportFormat,
    duplicates: DuplicateKeys,
    ui: &mut Ui,
) -> Result<u8> {
    let ids: Vec<PathId> = payload
        .iter()
        .map(|path| payload_id(path))
        .collect::<Result<_>>()?;
    for id in &ids {
        lockset_core::meta::require_dotenv(id).map_err(|error| usage::error(error.to_string()))?;
    }
    let key = context.require_key()?;
    let values = exported_payload(ops::env_for(&context.codec, &ids, &key, duplicates)?, false)?;
    warn!(
        ui,
        "the exported values are secret material; mask them in CI logs"
    );
    say!(ui, "{}", render::export(format, &values)?);
    Ok(0)
}

fn run_command(
    context: &wiring::Context,
    payload: &[String],
    argv: &[String],
    mode: ChildEnv,
    duplicates: DuplicateKeys,
    inputs: &Inputs,
) -> Result<u8> {
    let ids: Vec<PathId> = if payload.is_empty() {
        selected_payloads(context)?
    } else {
        payload
            .iter()
            .map(|path| payload_id(path))
            .collect::<Result<_>>()?
    };
    for id in &ids {
        lockset_core::meta::require_dotenv(id).map_err(|error| usage::error(error.to_string()))?;
    }
    let key = context.require_key()?;
    let inherited = mode == ChildEnv::Inherited;
    let envs = exported_payload(
        ops::env_for(&context.codec, &ids, &key, duplicates)?,
        inherited,
    )?;

    let (program, rest) = argv
        .split_first()
        .ok_or_else(|| usage::error("run needs a command after --"))?;
    let mut command = child_command(program, rest, envs, mode, inputs.vars_os());

    // On Unix the child *is* this process after `exec`, so its exit code and
    // signals pass through untouched. Elsewhere the status is propagated.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = command.exec();
        Err(usage::error(format!("cannot run {program}: {error}")))
    }
    #[cfg(not(unix))]
    {
        let status = command
            .status()
            .map_err(|error| usage::error(format!("cannot run {program}: {error}")))?;
        Ok(exit_status_code(status))
    }
}

fn child_env(pass_custody: bool, clean_env: bool) -> ChildEnv {
    if clean_env {
        ChildEnv::Clean
    } else if pass_custody {
        ChildEnv::Inherited
    } else {
        ChildEnv::Scrubbed
    }
}

fn duplicate_policy(last_wins: bool, first_wins: bool) -> DuplicateKeys {
    if last_wins {
        DuplicateKeys::LastWins
    } else if first_wins {
        DuplicateKeys::FirstWins
    } else {
        DuplicateKeys::Error
    }
}

/// The child's own code; a process killed by a signal becomes `128 + signal`
/// where the platform reports one. (Unix uses `exec`, so this is the wait path.)
#[cfg(any(not(unix), test))]
fn exit_status_code(status: std::process::ExitStatus) -> u8 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128u8.saturating_add(u8::try_from(signal).unwrap_or(1));
        }
    }
    match status.code() {
        Some(code) => code as u8,
        None => 1,
    }
}

/// The payload values `run` hands over. A payload may not smuggle the identity
/// or a sops variable into the child: that would contradict the command's
/// promise to give the child no key source at all.
fn exported_payload(
    envs: Vec<(String, String)>,
    pass_custody: bool,
) -> Result<Vec<(String, String)>> {
    if !pass_custody {
        if let Some(name) = envs
            .iter()
            .map(|(name, _)| name)
            .find(|name| lockset_tools::env::is_reserved(name))
        {
            return Err(usage::error(format!(
                "payload variable {name} is an identity or sops variable; \
                 run keeps those out of the child (--pass-custody exports it deliberately)"
            )));
        }
    }
    Ok(envs)
}

/// The command `run` starts. Unless custody is passed deliberately, its
/// environment is explicit rather than inherited: the parent's, minus the
/// identity and every `SOPS_*` variable, plus the payload values. The identity
/// opens every payload, so a build script must not be able to read it.
fn child_command(
    program: &str,
    rest: &[String],
    payload_env: Vec<(String, String)>,
    mode: ChildEnv,
    parent_env: impl IntoIterator<Item = (OsString, OsString)>,
) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    command.args(rest);
    match mode {
        ChildEnv::Inherited => {}
        ChildEnv::Scrubbed => {
            command
                .env_clear()
                .envs(lockset_tools::env::without_identity(parent_env));
        }
        ChildEnv::Clean => {
            command
                .env_clear()
                .envs(lockset_tools::env::clean(parent_env));
        }
    }
    command.envs(payload_env);
    command
}

fn key(
    context: &wiring::Context,
    cli: &Cli,
    inputs: &Inputs,
    ui: &mut Ui,
    command: &KeyCommand,
) -> Result<u8> {
    match command {
        KeyCommand::Import {
            file,
            stdin,
            from_env,
            force,
        } => {
            let key = input::read_key(file.as_deref(), *stdin, from_env.as_deref(), inputs)?;
            let public = key.public()?;
            let snapshot = wiring::snapshot(context)?;
            let label = snapshot.label_for(&public);

            if let Some(label) = &label {
                if label.is_offmachine() {
                    return Err(usage::error(format!(
                        "{label} identities are never installed on a machine"
                    )));
                }
            }
            if let Some(existing) = context.custody.get()? {
                let existing_public = existing.public()?;
                if existing_public != public && !*force {
                    return Err(anyhow::Error::new(lockset_core::Error::custody(format!(
                        "custody already holds a different identity ({existing_public}); pass --force to replace it"
                    ))));
                }
            }

            let mut plan = Plan::default();
            plan.push(Change::StoreKey {
                custody: context.custody.kind(),
            });
            if cli.dry_run {
                emit_plan(&plan, cli, ui)?;
                return Ok(0);
            }
            exec::apply(
                &plan,
                &context.repo,
                &context.codec,
                context.custody.as_ref(),
                &key,
            )?;

            sayln!(ui, "public key: {public}");
            sayln!(
                ui,
                "label:      {}",
                label
                    .as_ref()
                    .map(|label| label.to_string())
                    .unwrap_or_else(|| "unlabelled".into())
            );
            sayln!(ui, "stored in:  {}", context.custody.kind());

            let covered = snapshot.payloads_with(&public);
            if covered.is_empty() {
                warn!(ui, "{public} is not a recipient of any payload yet");
                warn!(
                    ui,
                    "ask an operator: lockset grant {public} --label {}<name>",
                    context.config.labels.person_prefix
                );
                return Ok(1);
            }
            for payload in &covered {
                context.codec.decrypt(&payload.id, &key).map_err(|error| {
                    anyhow::Error::new(lockset_core::Error::tool(format!(
                        "the key was stored, but it cannot open {}: {error}",
                        payload.id
                    )))
                })?;
            }
            sayln!(
                ui,
                "opens:      {}",
                covered
                    .iter()
                    .map(|payload| payload.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            Ok(0)
        }
        KeyCommand::Status => {
            sayln!(ui, "custody:    {}", context.custody.kind());
            match context.custody.get()? {
                Some(key) => {
                    let public = key.public()?;
                    let snapshot = wiring::snapshot(context)?;
                    sayln!(ui, "public key: {public}");
                    sayln!(
                        ui,
                        "label:      {}",
                        snapshot
                            .label_for(&public)
                            .map(|label| label.to_string())
                            .unwrap_or_else(|| "unlabelled".into())
                    );
                    sayln!(
                        ui,
                        "opens:      {} payload(s)",
                        snapshot.payloads_with(&public).len()
                    );
                }
                None => sayln!(ui, "no key in custody"),
            }
            Ok(0)
        }
        KeyCommand::Forget { yes } => {
            if !*yes && !cli.dry_run {
                if !inputs.is_interactive() {
                    return Err(usage::error("refusing to remove the key without --yes"));
                }
                if !ui.ask("remove the key from custody?", inputs)? {
                    sayln!(ui, "kept");
                    return Ok(0);
                }
            }
            let mut plan = Plan::default();
            plan.push(Change::ForgetKey {
                custody: context.custody.kind(),
            });
            if cli.dry_run {
                emit_plan(&plan, cli, ui)?;
                return Ok(0);
            }
            let key = context.custody.get()?.ok_or_else(|| {
                anyhow::Error::new(lockset_core::Error::custody("no key in custody"))
            })?;
            exec::apply(
                &plan,
                &context.repo,
                &context.codec,
                context.custody.as_ref(),
                &key,
            )?;
            sayln!(ui, "removed the key from {}", context.custody.kind());
            Ok(0)
        }
    }
}

/// What `set` writes: one key, into the selected (or configured default)
/// payload, optionally only when absent.
struct SetRequest<'a> {
    name: &'a str,
    payload: Option<&'a str>,
    if_absent: bool,
}

fn set(
    context: &wiring::Context,
    cli: &Cli,
    inputs: &Inputs,
    ui: &mut Ui,
    source: &input::ValueSource<'_>,
    request: SetRequest<'_>,
) -> Result<u8> {
    let SetRequest {
        name,
        payload,
        if_absent,
    } = request;
    if !lockset_core::meta::is_name(name) {
        return Err(usage::error(format!("invalid key name: {name}")));
    }
    let id = match payload {
        Some(path) => payload_id(path)?,
        None => one_default_payload(context)?,
    };
    let snapshot = wiring::snapshot(context)?;
    if snapshot.payload(&id).is_none() {
        if let Some(error) = snapshot.payload_error(&id) {
            return Err(usage::error(format!(
                "cannot use {}: {}",
                error.id, error.error
            )));
        }
        return Err(usage::error(format!("no such payload: {id}")));
    }
    if if_absent && key_is_set(context, &id, name)? {
        note!(
            ui,
            "{name} already has a value in {id}; nothing to do (--if-absent)"
        );
        return Ok(0);
    }
    let value = input::read_value(source, inputs)?;

    let mut plan = Plan::default();
    plan.push(Change::SetValue {
        payload: id.clone(),
        name: name.to_owned(),
        value: SecretValue::new(value),
    });
    plan.expect(&snapshot.digests);
    if cli.dry_run {
        emit_plan(&plan, cli, ui)?;
        return Ok(0);
    }
    let key = context.require_key()?;
    context.codec.preflight()?;
    for line in exec::apply(
        &plan,
        &context.repo,
        &context.codec,
        context.custody.as_ref(),
        &key,
    )? {
        sayln!(ui, "{line}");
    }
    Ok(0)
}

/// Whether the payload already gives `name` a non-empty value. `--if-absent`
/// answers that with the payload itself, so it needs the identity even for
/// `--dry-run`; an empty value counts as absent.
fn key_is_set(context: &wiring::Context, id: &PathId, name: &str) -> Result<bool> {
    let key = context.require_key()?;
    let plain = context.codec.decrypt(id, &key)?;
    let text = String::from_utf8_lossy(&plain);
    Ok(lockset_core::dotenv::parse(&text)
        .iter()
        .any(|(key, value)| key == name && !value.is_empty()))
}

fn rotate(
    context: &wiring::Context,
    cli: &Cli,
    ui: &mut Ui,
    all: bool,
    payload: &[String],
) -> Result<u8> {
    if !all && payload.is_empty() {
        return Err(usage::error(
            "rotating a data key rewrites every value; pass --all or explicit --payload",
        ));
    }
    let ids: Option<Vec<PathId>> = if all {
        None
    } else {
        Some(
            payload
                .iter()
                .map(|path| payload_id(path))
                .collect::<Result<_>>()?,
        )
    };
    let snapshot = wiring::snapshot(context)?;
    let plan = ops::rotate(&snapshot, ids.as_deref())?;
    finish(context, cli, plan, ui)
}

fn person(
    context: &wiring::Context,
    cli: &Cli,
    ui: &mut Ui,
    command: &PersonCommand,
) -> Result<u8> {
    match command {
        PersonCommand::Add {
            public,
            label,
            only,
        } => {
            let label = Label::parse(label)?;
            if label.is_reserved() {
                return Err(usage::error(format!(
                    "{label} is a reserved label; use grant/revoke for estate identities"
                )));
            }
            let public = PubKey::parse(public)?;
            let only = match only.as_deref() {
                Some(list) => Some(payload_list(list)?),
                None => None,
            };
            let snapshot = wiring::snapshot(context)?;
            let plan = ops::grant(
                &snapshot,
                &GrantRequest {
                    key: public.clone(),
                    label: label.clone(),
                    only,
                },
            )?;
            emit_plan(&plan, cli, ui)?;
            if cli.dry_run || plan.is_empty() {
                return Ok(0);
            }
            let key = context.require_key()?;
            context.codec.preflight()?;
            for line in exec::apply(
                &plan,
                &context.repo,
                &context.codec,
                context.custody.as_ref(),
                &key,
            )? {
                sayln!(ui, "{line}");
            }

            let after = wiring::snapshot(context)?;
            let covered = after.payloads_with(&public);
            ui.blank_line();
            sayln!(ui, "label:      {label}");
            sayln!(ui, "public key: {public}");
            sayln!(
                ui,
                "reads:      {}",
                if covered.is_empty() {
                    "(none)".to_owned()
                } else {
                    covered
                        .iter()
                        .map(|payload| payload.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            );
            ui.blank_line();
            sayln!(ui, "their machine:");
            sayln!(ui, "  mise install");
            sayln!(
                ui,
                "  lockset key import      # paste the private key they were given"
            );
            sayln!(ui, "  lockset run -- terraform plan");
            Ok(0)
        }
        PersonCommand::Remove {
            label,
            keep_data_key,
        } => {
            let label = Label::parse(label)?;
            if label.is_reserved() {
                return Err(usage::error(format!(
                    "{label} is a reserved label; use revoke --label {label}"
                )));
            }
            let snapshot = wiring::snapshot(context)?;
            let plan = ops::revoke(
                &snapshot,
                &RevokeRequest {
                    target: RevokeTarget::Label(label),
                    keep_data_key: *keep_data_key,
                    force: false,
                },
            )?;
            finish(context, cli, plan, ui)
        }
    }
}

fn grant(
    context: &wiring::Context,
    cli: &Cli,
    public: &str,
    label: &str,
    only: Option<&str>,
    ui: &mut Ui,
) -> Result<u8> {
    let request = GrantRequest {
        key: PubKey::parse(public)?,
        label: Label::parse(label)?,
        only: match only {
            Some(list) => Some(payload_list(list)?),
            None => None,
        },
    };
    let snapshot = wiring::snapshot(context)?;
    let plan = ops::grant(&snapshot, &request)?;
    finish(context, cli, plan, ui)
}

fn revoke(
    context: &wiring::Context,
    cli: &Cli,
    public: Option<&str>,
    label: Option<&str>,
    keep_data_key: bool,
    force: bool,
    ui: &mut Ui,
) -> Result<u8> {
    let snapshot = wiring::snapshot(context)?;
    let target = match (public, label) {
        (Some(public), None) => RevokeTarget::Key(PubKey::parse(public)?),
        (None, Some(label)) => RevokeTarget::Label(Label::parse(label)?),
        _ => return Err(usage::error("pass either a public key or --label")),
    };
    let request = RevokeRequest {
        target,
        keep_data_key,
        force,
    };
    let plan = ops::revoke(&snapshot, &request)?;
    finish(context, cli, plan, ui)
}

/// Render a plan, then require the identity only when the plan is applied, so a
/// `--dry-run` (and a keyless CI check) can inspect any plan without custody.
fn finish(context: &wiring::Context, cli: &Cli, plan: Plan, ui: &mut Ui) -> Result<u8> {
    emit_plan(&plan, cli, ui)?;
    if cli.dry_run || plan.is_empty() {
        return Ok(0);
    }
    let key = context.require_key()?;
    context.codec.preflight()?;
    for line in exec::apply(
        &plan,
        &context.repo,
        &context.codec,
        context.custody.as_ref(),
        &key,
    )? {
        sayln!(ui, "{line}");
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// A parent environment holding the identity, a sops override, and an
    /// unrelated CI secret.
    fn parent() -> Vec<(OsString, OsString)> {
        vec![
            ("PATH".into(), "/usr/bin".into()),
            ("HOME".into(), "/home/dev".into()),
            ("TMPDIR".into(), "/tmp".into()),
            ("LANG".into(), "C.UTF-8".into()),
            ("LOCKSET_AGE_KEY".into(), "AGE-SECRET-KEY-1PARENT".into()),
            ("SOPS_AGE_KEY_FILE".into(), "/tmp/key.txt".into()),
            ("CI_JOB_TOKEN".into(), "unrelated-secret".into()),
        ]
    }

    fn envs(command: &std::process::Command) -> BTreeMap<String, String> {
        command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.unwrap_or_default().to_string_lossy().into_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn the_run_child_does_not_inherit_the_identity() {
        let command = child_command(
            "build",
            &["--release".to_owned()],
            vec![("TOKEN".to_owned(), "from-payload".to_owned())],
            ChildEnv::Scrubbed,
            parent(),
        );
        let envs = envs(&command);

        assert_eq!(envs.get("TOKEN").map(String::as_str), Some("from-payload"));
        assert_eq!(envs.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert!(!envs.contains_key("LOCKSET_AGE_KEY"));
        assert!(!envs.contains_key("SOPS_AGE_KEY_FILE"));
        // Everything else is still the parent's, as scrubbing promises.
        assert_eq!(
            envs.get("CI_JOB_TOKEN").map(String::as_str),
            Some("unrelated-secret")
        );
    }

    #[test]
    fn clean_env_keeps_only_the_allowlist_and_the_payload() {
        let command = child_command(
            "build",
            &[],
            vec![("TOKEN".to_owned(), "from-payload".to_owned())],
            ChildEnv::Clean,
            parent(),
        );
        let envs = envs(&command);

        assert_eq!(envs.get("TOKEN").map(String::as_str), Some("from-payload"));
        for name in ["PATH", "HOME", "TMPDIR", "LANG"] {
            assert!(envs.contains_key(name), "{name} must survive --clean-env");
        }
        assert!(!envs.contains_key("CI_JOB_TOKEN"), "{envs:?}");
        assert!(!envs.contains_key("LOCKSET_AGE_KEY"), "{envs:?}");
        assert!(!envs.contains_key("SOPS_AGE_KEY_FILE"), "{envs:?}");
    }

    #[test]
    fn a_payload_cannot_smuggle_a_reserved_variable() {
        let envs = vec![("SOPS_AGE_KEY".to_owned(), "AGE-SECRET-KEY-1X".to_owned())];

        let error = exported_payload(envs.clone(), false).unwrap_err();
        assert!(error.to_string().contains("SOPS_AGE_KEY"));
        assert!(exported_payload(envs, true).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_signal_status_becomes_128_plus_the_signal() {
        use std::os::unix::process::ExitStatusExt;

        assert_eq!(
            exit_status_code(std::process::ExitStatus::from_raw(15)),
            143
        );
        assert_eq!(exit_status_code(std::process::ExitStatus::from_raw(9)), 137);
    }

    #[cfg(unix)]
    #[test]
    fn a_normal_exit_status_keeps_its_code() {
        use std::os::unix::process::ExitStatusExt;

        assert_eq!(exit_status_code(std::process::ExitStatus::from_raw(0)), 0);
        assert_eq!(
            exit_status_code(std::process::ExitStatus::from_raw(7 << 8)),
            7
        );
    }

    #[test]
    fn pass_custody_leaves_the_environment_inherited() {
        // Nothing is set or removed: the child inherits the parent environment,
        // identity included, which is exactly what the flag asks for.
        let command = child_command("build", &[], Vec::new(), ChildEnv::Inherited, parent());

        assert_eq!(command.get_envs().count(), 0);
    }
}
