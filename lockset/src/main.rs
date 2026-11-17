mod cli;
mod input;
mod render;
mod usage;
mod wiring;

use std::ffi::OsString;
use std::io::IsTerminal;
use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::Parser;
use lockset_core::ops::{self, Check, GrantRequest, RevokeRequest, RevokeTarget};
use lockset_core::{exec, Change, Codec, Label, PathId, Plan, PubKey, SecretValue};

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

/// Whether to print the plan as JSON. JSON describes a plan, so it needs a dry
/// run and a command that builds one; anything else is a usage error rather
/// than a flag that quietly does nothing.
fn plan_json(cli: &Cli) -> Result<bool> {
    if !cli.json {
        return Ok(false);
    }
    if !cli.dry_run {
        return Err(usage::error("--json prints a plan; pass --dry-run with it"));
    }
    match &cli.command {
        Command::Set { .. }
        | Command::Rotate { .. }
        | Command::Person { .. }
        | Command::Grant { .. }
        | Command::Revoke { .. }
        | Command::Key { .. } => Ok(true),
        Command::Status | Command::Who | Command::Check | Command::Run { .. } => Err(usage::error(
            "--json prints plans; this command has no JSON output",
        )),
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
    plan_json(&cli)?;
    let context = wiring::Context::detect(&cli)?;
    let _lock = wiring::mutation_lock(&cli, &context)?;

    match &cli.command {
        Command::Status => {
            println!("{}", ops::status(&wiring::snapshot(&context)?).render());
            Ok(0)
        }
        Command::Who => {
            println!("{}", ops::who(&wiring::snapshot(&context)?).render());
            Ok(0)
        }
        Command::Check => check(&context),
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
        Command::Run {
            payload,
            pass_custody,
            argv,
        } => run_command(&context, payload, argv, *pass_custody),
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

fn check(context: &wiring::Context) -> Result<u8> {
    let snapshot = wiring::snapshot(context)?;
    let mut results = ops::checks(&snapshot);

    if let Some(identity) = &snapshot.identity {
        let is_admin = identity
            .label
            .as_ref()
            .is_some_and(|label| label.as_str() == "admin");
        if is_admin {
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
    }

    let failed = results.iter().filter(|check| !check.ok).count();
    for check in &results {
        println!(
            "{:<44} {:<4} {}",
            check.name,
            if check.ok { "ok" } else { "FAIL" },
            check.detail
        );
    }
    Ok(if failed == 0 { 0 } else { 1 })
}

fn run_command(
    context: &wiring::Context,
    payload: &[String],
    argv: &[String],
    pass_custody: bool,
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
    let envs = exported_payload(ops::env_for(&context.codec, &ids, &key)?, pass_custody)?;

    let (program, rest) = argv
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("run needs a command after --"))?;
    let status = child_command(program, rest, envs, pass_custody, std::env::vars_os()).status()?;
    Ok(status.code().unwrap_or(1) as u8)
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
            bail!(
                "payload variable {name} is an identity or sops variable; \
                 run keeps those out of the child (--pass-custody exports it deliberately)"
            );
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
    pass_custody: bool,
    parent_env: impl IntoIterator<Item = (OsString, OsString)>,
) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    command.args(rest);
    if !pass_custody {
        command
            .env_clear()
            .envs(lockset_tools::env::without_identity(parent_env));
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
                    bail!("{label} identities are never installed on a machine");
                }
            }
            if let Some(existing) = context.custody.get()? {
                let existing_public = existing.public()?;
                if existing_public != public && !*force {
                    bail!(
                        "custody already holds a different identity ({existing_public}); pass --force to replace it"
                    );
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
                    anyhow::anyhow!(
                        "the key was stored, but it cannot open {}: {error}",
                        payload.id
                    )
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
                    bail!("refusing to remove the key without --yes");
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
            let key = context
                .custody
                .get()?
                .ok_or_else(|| anyhow::anyhow!("no key in custody"))?;
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
        bail!("invalid key name: {name}");
    }
    let id = payload_id(payload)?;
    let snapshot = wiring::snapshot(context)?;
    if snapshot.payload(&id).is_none() {
        if let Some(error) = snapshot.payload_error(&id) {
            bail!("cannot use {}: {}", error.id, error.error);
        }
        bail!("no such payload: {payload}");
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
        bail!("rotating a data key rewrites every value; pass --all or explicit --payload");
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
                bail!("{label} is a reserved label; use grant/revoke for estate identities");
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
                bail!("{label} is a reserved label; use revoke --label {label}");
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
        _ => bail!("pass either a public key or --label"),
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

    /// A parent environment holding the identity and a sops override.
    fn parent() -> Vec<(OsString, OsString)> {
        vec![
            ("PATH".into(), "/usr/bin".into()),
            ("LOCKSET_AGE_KEY".into(), "AGE-SECRET-KEY-1PARENT".into()),
            ("SOPS_AGE_KEY_FILE".into(), "/tmp/key.txt".into()),
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
            false,
            parent(),
        );
        let envs = envs(&command);

        assert_eq!(envs.get("TOKEN").map(String::as_str), Some("from-payload"));
        assert_eq!(envs.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert!(!envs.contains_key("LOCKSET_AGE_KEY"));
        assert!(!envs.contains_key("SOPS_AGE_KEY_FILE"));
    }

    #[test]
    fn a_payload_cannot_smuggle_a_reserved_variable() {
        let envs = vec![("SOPS_AGE_KEY".to_owned(), "AGE-SECRET-KEY-1X".to_owned())];

        let error = exported_payload(envs.clone(), false).unwrap_err();
        assert!(error.to_string().contains("SOPS_AGE_KEY"));
        assert!(exported_payload(envs, true).is_ok());
    }

    #[test]
    fn pass_custody_leaves_the_environment_inherited() {
        // Nothing is set or removed: the child inherits the parent environment,
        // identity included, which is exactly what the flag asks for.
        let command = child_command("build", &[], Vec::new(), true, parent());

        assert_eq!(command.get_envs().count(), 0);
    }
}
