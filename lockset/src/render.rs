use anyhow::{Context, Result};
use lockset_core::{Change, Plan};

/// Print the plan. `--json` prints the plan itself; the caller validates that
/// it asked for a dry run of a command that builds one.
pub fn plan(plan: &Plan, dry_run: bool, json: bool) -> Result<()> {
    if json {
        let text = serde_json::to_string_pretty(plan).context("cannot encode the plan as JSON")?;
        println!("{text}");
        return Ok(());
    }
    for note in &plan.notes {
        println!("{note}");
    }
    for warning in &plan.warnings {
        println!("warning: {warning}");
    }
    if dry_run {
        if plan.changes.is_empty() {
            println!("nothing to do");
        }
        for item in &plan.changes {
            println!("would {}", describe(item));
        }
    }
    Ok(())
}

pub fn describe(item: &Change) -> String {
    match item {
        Change::WriteFile { path, .. } => format!("write {path}"),
        Change::UpdateKeys { payload } => format!("re-wrap {payload}"),
        Change::RotateDataKey { payload } => format!("rotate the data key of {payload}"),
        Change::SetValue {
            payload,
            name,
            value: _,
        } => format!("set {name} in {payload}"),
        Change::StoreKey { custody } => format!("store the key in {custody}"),
        Change::ForgetKey { custody } => format!("remove the key from {custody}"),
    }
}
