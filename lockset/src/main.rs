mod cli;
mod input;
mod render;
mod wiring;

use std::io::IsTerminal;
use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::Parser;
use lockset_core::ops::{self, Check, GrantRequest, RevokeRequest, RevokeTarget};
use lockset_core::{exec, Change, Codec, Label, PathId, Plan, PubKey, SecretKey};

use crate::cli::{Cli, Command, KeyCommand, PersonCommand};

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<u8> {
    let cli = Cli::parse();
    let context = wiring::Context::detect(&cli)?;

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
        } => set(&context, &cli, key, payload, *stdin, from_env.as_deref()),
        Command::Rotate { all, payload } => rotate(&context, &cli, *all, payload),
        Command::Person { command } => person(&context, &cli, command),
        Command::Run { payload, argv } => run_command(&context, payload, argv),
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

fn run_command(context: &wiring::Context, payload: &[String], argv: &[String]) -> Result<u8> {
    let ids: Vec<PathId> = if payload.is_empty() {
        vec![PathId::new("secrets/prod/infra.env")]
    } else {
        payload.iter().map(PathId::new).collect()
    };
    let key = context.require_key()?;
    let envs = ops::env_for(&context.codec, &ids, &key)?;

    let (program, rest) = argv
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("run needs a command after --"))?;
    let status = std::process::Command::new(program)
        .args(rest)
        .envs(envs)
        .status()?;
    Ok(status.code().unwrap_or(1) as u8)
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
                render::plan(&plan, true);
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
            if !*yes {
                if !std::io::stdin().is_terminal() {
                    bail!("refusing to remove the key without --yes");
                }
                if !input::confirm("remove the key from custody?")? {
                    println!("kept");
                    return Ok(0);
                }
            }
            let key = context
                .custody
                .get()?
                .ok_or_else(|| anyhow::anyhow!("no key in custody"))?;
            let mut plan = Plan::default();
            plan.push(Change::ForgetKey {
                custody: context.custody.kind(),
            });
            if cli.dry_run {
                render::plan(&plan, true);
                return Ok(0);
            }
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
    stdin: bool,
    from_env: Option<&str>,
) -> Result<u8> {
    if !lockset_core::meta::is_name(name) {
        bail!("invalid key name: {name}");
    }
    let id = PathId::new(payload);
    let snapshot = wiring::snapshot(context)?;
    if snapshot.payload(&id).is_none() {
        bail!("no such payload: {payload}");
    }
    let key = context.require_key()?;
    let value = input::read_value(stdin, from_env)?;

    let mut plan = Plan::default();
    plan.push(Change::SetValue {
        payload: id.clone(),
        name: name.to_owned(),
        value: value.to_string(),
    });
    if cli.dry_run {
        render::plan(&plan, true);
        return Ok(0);
    }
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
    let snapshot = wiring::snapshot(context)?;
    let key = context.require_key()?;
    let ids: Option<Vec<PathId>> = if all {
        None
    } else {
        Some(payload.iter().map(PathId::new).collect())
    };
    let plan = ops::rotate(&snapshot, ids.as_deref())?;
    finish(context, cli, plan, &key)
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
            let snapshot = wiring::snapshot(context)?;
            let key = context.require_key()?;
            let plan = ops::grant(
                &snapshot,
                &GrantRequest {
                    key: public.clone(),
                    label: label.clone(),
                    only: only.as_deref().map(payload_list),
                },
            )?;
            render::plan(&plan, cli.dry_run);
            if cli.dry_run || plan.is_empty() {
                return Ok(0);
            }
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
            let key = context.require_key()?;
            let plan = ops::revoke(
                &snapshot,
                &RevokeRequest {
                    target: RevokeTarget::Label(label),
                    keep_data_key: *keep_data_key,
                    force: false,
                },
            )?;
            finish(context, cli, plan, &key)
        }
    }
}

fn payload_list(list: &str) -> Vec<PathId> {
    list.split(',').map(|p| PathId::new(p.trim())).collect()
}

fn grant(
    context: &wiring::Context,
    cli: &Cli,
    public: &str,
    label: &str,
    only: Option<&str>,
) -> Result<u8> {
    let snapshot = wiring::snapshot(context)?;
    let key = context.require_key()?;
    let request = GrantRequest {
        key: PubKey::parse(public)?,
        label: Label::parse(label)?,
        only: only.map(|list| list.split(',').map(|p| PathId::new(p.trim())).collect()),
    };
    let plan = ops::grant(&snapshot, &request)?;
    finish(context, cli, plan, &key)
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
    let key = context.require_key()?;
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
    finish(context, cli, plan, &key)
}

fn finish(context: &wiring::Context, cli: &Cli, plan: Plan, key: &SecretKey) -> Result<u8> {
    render::plan(&plan, cli.dry_run);
    if cli.dry_run || plan.is_empty() {
        return Ok(0);
    }
    for line in exec::apply(
        &plan,
        &context.repo,
        &context.codec,
        context.custody.as_ref(),
        key,
    )? {
        println!("{line}");
    }
    Ok(0)
}
