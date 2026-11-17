use anyhow::{Context, Result};
use lockset_core::report::{CheckReport, IdentityReport, PlanDocument, StatusReport};
use lockset_core::{Change, Plan};
use serde::Serialize;

use crate::cli::ExportFormat;

/// Serialize a `--json` document.
pub fn json<T: Serialize>(document: &T) -> Result<String> {
    serde_json::to_string_pretty(document).context("cannot encode the document as JSON")
}

/// A blank line between sections, only when the previous line is not blank.
fn gap(lines: &mut Vec<String>) {
    if lines.last().is_some_and(|line| !line.is_empty()) {
        lines.push(String::new());
    }
}

fn join(lines: Vec<String>) -> String {
    lines.join("\n")
}

/// `status` as text: the same facts the JSON document carries.
pub fn status(report: &StatusReport) -> String {
    let mut lines = Vec::new();

    match (&report.identity, &report.identity_error) {
        (Some(identity), _) => lines.push(format!(
            "identity: {} ({}) via {}",
            identity.public.as_str(),
            identity
                .label
                .as_ref()
                .map(|label| label.to_string())
                .unwrap_or_else(|| "unlabelled".into()),
            identity.custody
        )),
        (None, Some(error)) => lines.push(format!("identity: unavailable — {error}")),
        (None, None) => lines.push(
            "identity: none — set LOCKSET_AGE_KEY, pass --custody file:<path>, \
             or run `lockset key import`"
                .into(),
        ),
    }

    if let Some(coverage) = &report.coverage {
        if coverage.missing.is_empty() {
            lines.push(format!("coverage: opens all {} payloads", coverage.total));
        } else {
            lines.push(format!(
                "coverage: opens {}/{} payloads; missing: {}",
                coverage.opens,
                coverage.total,
                coverage
                    .missing
                    .iter()
                    .map(|path| path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    gap(&mut lines);
    lines.push(format!(
        "{:<34} {:>4} {:>10} {:>6}",
        "payload", "keys", "recipients", "empty"
    ));
    for payload in &report.payloads {
        lines.push(format!(
            "{:<34} {:>4} {:>10} {:>6}",
            payload.path.as_str(),
            payload.keys,
            payload.recipients,
            payload.empty
        ));
    }

    if !report.identities.is_empty() {
        gap(&mut lines);
        lines.push("identities:".into());
        for identity in &report.identities {
            lines.push(format!(
                "  {:<12} {}  {} payload(s)",
                identity.label,
                identity.public.as_str(),
                identity.payloads
            ));
        }
    }

    if !report.payload_errors.is_empty() {
        gap(&mut lines);
        lines.push(format!(
            "unreadable payloads: {}",
            report.payload_errors.len()
        ));
        for error in &report.payload_errors {
            lines.push(format!("  {}: {}", error.id, error.error));
        }
    }

    gap(&mut lines);
    if report.drift.is_empty() {
        lines.push("drift: none".into());
    } else {
        lines.push(format!("drift: {} issue(s)", report.drift.len()));
        for note in &report.drift {
            lines.push(format!("  {note}"));
        }
    }

    gap(&mut lines);
    if report.empty_values == 0 {
        lines.push("empty values: none".into());
    } else {
        lines.push(format!(
            "empty values: {} (fill with `lockset set`)",
            report.empty_values
        ));
    }

    gap(&mut lines);
    lines.push(report.next.clone());

    join(lines)
}

/// `who` as text: the identity map.
pub fn who(report: &IdentityReport) -> String {
    let mut lines = vec![format!(
        "{:<12} {:<64} {:>10}  {}",
        "identity", "public key", "payloads", "local"
    )];
    for identity in &report.identities {
        lines.push(format!(
            "{:<12} {:<64} {:>10}  {}",
            identity.label,
            identity.public.as_str(),
            identity.payloads,
            if identity.local { "yes" } else { "" }
        ));
    }
    join(lines)
}

/// `check` as text: one line per invariant.
pub fn check(report: &CheckReport) -> String {
    let lines: Vec<String> = report
        .checks
        .iter()
        .map(|check| {
            format!(
                "{:<44} {:<4} {}",
                check.name,
                if check.ok { "ok" } else { "FAIL" },
                check.detail
            )
        })
        .collect();
    join(lines)
}

/// Print the plan. `--json` prints the plan document; otherwise notes and
/// warnings go to stderr so stdout carries only the plan itself.
pub fn plan(plan: &Plan, dry_run: bool, json: bool) -> Result<()> {
    if json {
        println!("{}", self::json(&PlanDocument::new(plan))?);
        return Ok(());
    }
    for note in &plan.notes {
        log::info!("{note}");
    }
    for warning in &plan.warnings {
        log::warn!("{warning}");
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

/// A `lockset.toml` fragment listing the identities the `.sops.yaml` comments
/// currently name: the one-time conversion the README documents. Comment
/// labels are migration input, so nothing here is written for the user.
pub fn identities_toml(snapshot: &lockset_core::Snapshot) -> String {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    for rule in snapshot.sops.rules() {
        for recipient in &rule.recipients {
            let Some(label) = recipient.label.as_ref() else {
                continue;
            };
            let pair = (label.as_str(), recipient.key.as_str());
            if !pairs.contains(&pair) {
                pairs.push(pair);
            }
        }
    }
    pairs.sort_unstable();
    let mut out =
        String::from("# Append this to lockset.toml: labels taken from the .sops.yaml comments.\n");
    for (label, key) in pairs {
        out.push_str(&format!(
            "\n[[identities]]\nlabel = \"{label}\"\npublic = \"{key}\"\n"
        ));
    }
    out
}

/// The requested serialization of the merged payload values. The values are
/// secret material: they appear here by design, escaped so the format stays
/// valid, and nowhere else.
pub fn export(format: ExportFormat, values: &[(String, String)]) -> Result<String> {
    Ok(match format {
        ExportFormat::Dotenv => values
            .iter()
            .map(|(name, value)| format!("{name}={value}\n"))
            .collect(),
        ExportFormat::Json => {
            let map: std::collections::BTreeMap<&str, &str> = values
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            let text =
                serde_json::to_string_pretty(&map).context("cannot encode the values as JSON")?;
            format!("{text}\n")
        }
        ExportFormat::Sh => values
            .iter()
            .map(|(name, value)| format!("export {name}='{}'\n", value.replace('\'', "'\\''")))
            .collect(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn values() -> Vec<(String, String)> {
        vec![
            ("TOKEN".to_owned(), "abc".to_owned()),
            ("QUOTE".to_owned(), "it's".to_owned()),
        ]
    }

    #[test]
    fn dotenv_writes_name_value_lines() {
        assert_eq!(
            export(ExportFormat::Dotenv, &values()).unwrap(),
            "TOKEN=abc\nQUOTE=it's\n"
        );
    }

    #[test]
    fn json_writes_one_object() {
        let text = export(ExportFormat::Json, &values()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert_eq!(parsed["TOKEN"], "abc");
        assert_eq!(parsed["QUOTE"], "it's");
    }

    #[test]
    fn sh_escapes_single_quotes() {
        assert_eq!(
            export(ExportFormat::Sh, &values()).unwrap(),
            concat!("export TOKEN='abc'\n", "export QUOTE='it'\\''s'\n")
        );
    }
}
