mod cli;
mod input;
mod render;
mod usage;
mod wiring;

use std::ffi::OsString;
use std::io::IsTerminal;
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use lockset_core::ops::{self, GrantRequest, RevokeRequest, RevokeTarget};
use lockset_core::{
    exec, Change, Check, CheckReport, Codec, DuplicateKeys, IdentityReport, Label, PathId, Plan,
    PubKey, SecretValue, StatusReport,
};

use crate::cli::{Cli, Command, KeyCommand, PersonCommand};

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
        Command::Status { .. } | Command::Who | Command::Check | Command::Doctor => Ok(true),
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

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(usage::exit_code(&error))
        }
    }
}

fn run() -> Result<u8> {
    let cli = Cli::parse();
    json_requested(&cli)?;
    let context = wiring::Context::detect(&cli)?;
    let _lock = wiring::mutation_lock(&cli, &context)?;

    match &cli.command {
        Command::Status { strict } => {
            let report = StatusReport::new(&wiring::snapshot(&context)?);
            if cli.json {
                println!("{}", render::json(&report)?);
            } else {
                println!("{}", render::status(&report));
            }
            if *strict {
                let findings = report.strict_findings();
                if !findings.is_empty() {
                    eprintln!("strict: {} finding(s)", findings.len());
                    for finding in &findings {
                        eprintln!("  {finding}");
                    }
                    return Ok(1);
                }
            }
            Ok(0)
        }
        Command::Who => {
            let report = IdentityReport::new(&wiring::snapshot(&context)?);
            if cli.json {
                println!("{}", render::json(&report)?);
            } else {
                println!("{}", render::who(&report));
            }
            Ok(0)
        }
        Command::Check => check(&context, &cli),
        Command::Doctor => doctor(&context, &cli),
        Command::Set {
            key,
            payload,
            stdin,
            from_env,
            value_file,
            allow_empty,
        } => set(
            &context,
            &cli,
            key,
            payload,
            &input::ValueSource {
                stdin: *stdin,
                from_env: from_env.as_deref(),
                file: value_file.as_deref(),
                allow_empty: *allow_empty,
            },
        ),
        Command::Rotate { all, payload } => rotate(&context, &cli, *all, payload),
        Command::Person { command } => person(&context, &cli, command),
        Command::Export {
            payload,
            format,
            last_wins,
            first_wins,
        } => export(
            &context,
            payload,
            *format,
            duplicate_policy(*last_wins, *first_wins),
        ),
        Command::Run {
            payload,
            pass_custody,
            clean_env,
            last_wins,
            first_wins,
            argv,
        } => run_command(
            &context,
            payload,
            argv,
            child_env(*pass_custody, *clean_env),
            duplicate_policy(*last_wins, *first_wins),
        ),
        Command::Key { command } => key(&context, &cli, command),
        Command::Grant {
            public,
            label,
            only,
        } => grant(&context, &cli, public, label, only.as_deref()),
        Command::Revoke {
            public,
            label,
            keep_data_key,
            force,
        } => revoke(
            &context,
            &cli,
            public.as_deref(),
            label.as_deref(),
            *keep_data_key,
            *force,
        ),
    }
}

/// The default payload `run` and `set` fall back to.
const DEFAULT_PAYLOAD: &str = "secrets/prod/infra.env";

/// Preflight for a pipeline: repo, sops, custody, identity, coverage, payloads,
/// and the CI custody policy. Every item is a finding, so the exit code is 1
/// when anything is off and the failing check is named.
fn doctor(context: &wiring::Context, cli: &Cli) -> Result<u8> {
    let mut checks: Vec<Check> = Vec::new();

    let snapshot = match wiring::snapshot(context) {
        Ok(snapshot) => {
            checks.push(Check {
                name: "repo".into(),
                ok: true,
                detail: context.root.display().to_string(),
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
        detail: "only LOCKSET_AGE_KEY and the lockset-age-key item are read".into(),
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

            let has_default = status
                .payloads
                .iter()
                .any(|payload| payload.path.as_str() == DEFAULT_PAYLOAD);
            checks.push(Check {
                name: "default payload".into(),
                ok: has_default,
                detail: if has_default {
                    DEFAULT_PAYLOAD.to_owned()
                } else {
                    format!("{DEFAULT_PAYLOAD} (missing; pass --payload)")
                },
            });
        }
        None => {
            for name in ["identity", "coverage", "payloads", "default payload"] {
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
        println!("{}", render::json(&report)?);
    } else {
        println!("{}", render::check(&report));
    }
    Ok(if report.failed() == 0 { 0 } else { 1 })
}

fn check(context: &wiring::Context, cli: &Cli) -> Result<u8> {
    let snapshot = wiring::snapshot(context)?;
    let mut results = ops::checks(&snapshot);

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
        println!("{}", render::json(&report)?);
    } else {
        println!("{}", render::check(&report));
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
    eprintln!("warning: the exported values are secret material; mask them in CI logs");
    print!("{}", render::export(format, &values)?);
    Ok(0)
}

fn run_command(
    context: &wiring::Context,
    payload: &[String],
    argv: &[String],
    mode: ChildEnv,
    duplicates: DuplicateKeys,
) -> Result<u8> {
    let ids: Vec<PathId> = if payload.is_empty() {
        vec![payload_id("secrets/prod/infra.env")?]
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
    let mut command = child_command(program, rest, envs, mode, std::env::vars_os());

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

fn key(context: &wiring::Context, cli: &Cli, command: &KeyCommand) -> Result<u8> {
    match command {
        KeyCommand::Import {
            file,
            stdin,
            from_env,
            force,
        } => {
            let key = input::read_key(file.as_deref(), *stdin, from_env.as_deref())?;
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
                render::plan(&plan, true, cli.json)?;
                return Ok(0);
            }
            exec::apply(
                &plan,
                &context.repo,
                &context.codec,
                context.custody.as_ref(),
                &key,
            )?;

            println!("public key: {public}");
            println!(
                "label:      {}",
                label
                    .as_ref()
                    .map(|label| label.to_string())
                    .unwrap_or_else(|| "unlabelled".into())
            );
            println!("stored in:  {}", context.custody.kind());

            let covered = snapshot.payloads_with(&public);
            if covered.is_empty() {
                eprintln!("warning: {public} is not a recipient of any payload yet");
                eprintln!("  ask an operator: lockset grant {public} --label dev-<name>");
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
            println!(
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
            println!("custody:    {}", context.custody.kind());
            match context.custody.get()? {
                Some(key) => {
                    let public = key.public()?;
                    let snapshot = wiring::snapshot(context)?;
                    println!("public key: {public}");
                    println!(
                        "label:      {}",
                        snapshot
                            .label_for(&public)
                            .map(|label| label.to_string())
                            .unwrap_or_else(|| "unlabelled".into())
                    );
                    println!(
                        "opens:      {} payload(s)",
                        snapshot.payloads_with(&public).len()
                    );
                }
                None => println!("no key in custody"),
            }
            Ok(0)
        }
        KeyCommand::Forget { yes } => {
            if !*yes && !cli.dry_run {
                if !std::io::stdin().is_terminal() {
                    return Err(usage::error("refusing to remove the key without --yes"));
                }
                if !input::confirm("remove the key from custody?")? {
                    println!("kept");
                    return Ok(0);
                }
            }
            let mut plan = Plan::default();
            plan.push(Change::ForgetKey {
                custody: context.custody.kind(),
            });
            if cli.dry_run {
                render::plan(&plan, true, cli.json)?;
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
            println!("removed the key from {}", context.custody.kind());
            Ok(0)
        }
    }
}

fn set(
    context: &wiring::Context,
    cli: &Cli,
    name: &str,
    payload: &str,
    source: &input::ValueSource<'_>,
) -> Result<u8> {
    if !lockset_core::meta::is_name(name) {
        return Err(usage::error(format!("invalid key name: {name}")));
    }
    let id = payload_id(payload)?;
    let snapshot = wiring::snapshot(context)?;
    if snapshot.payload(&id).is_none() {
        if let Some(error) = snapshot.payload_error(&id) {
            return Err(usage::error(format!(
                "cannot use {}: {}",
                error.id, error.error
            )));
        }
        return Err(usage::error(format!("no such payload: {payload}")));
    }
    let value = input::read_value(source)?;

    let mut plan = Plan::default();
    plan.push(Change::SetValue {
        payload: id.clone(),
        name: name.to_owned(),
        value: SecretValue::new(value),
    });
    plan.expect(&snapshot.digests);
    if cli.dry_run {
        render::plan(&plan, true, cli.json)?;
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
        println!("{line}");
    }
    Ok(0)
}

fn rotate(context: &wiring::Context, cli: &Cli, all: bool, payload: &[String]) -> Result<u8> {
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
    finish(context, cli, plan)
}

fn person(context: &wiring::Context, cli: &Cli, command: &PersonCommand) -> Result<u8> {
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
            render::plan(&plan, cli.dry_run, cli.json)?;
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
                println!("{line}");
            }

            let after = wiring::snapshot(context)?;
            let covered = after.payloads_with(&public);
            println!();
            println!("label:      {label}");
            println!("public key: {public}");
            println!(
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
            println!();
            println!("their machine:");
            println!("  mise install");
            println!("  lockset key import      # paste the private key they were given");
            println!("  lockset run -- terraform plan");
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
            finish(context, cli, plan)
        }
    }
}

fn grant(
    context: &wiring::Context,
    cli: &Cli,
    public: &str,
    label: &str,
    only: Option<&str>,
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
    finish(context, cli, plan)
}

fn revoke(
    context: &wiring::Context,
    cli: &Cli,
    public: Option<&str>,
    label: Option<&str>,
    keep_data_key: bool,
    force: bool,
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
    finish(context, cli, plan)
}

/// Render a plan, then require the identity only when the plan is applied, so a
/// `--dry-run` (and a keyless CI check) can inspect any plan without custody.
fn finish(context: &wiring::Context, cli: &Cli, plan: Plan) -> Result<u8> {
    render::plan(&plan, cli.dry_run, cli.json)?;
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
        println!("{line}");
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
