//! Machine-readable reports: the data behind the text views and the `--json`
//! documents. Rendering lives in the CLI; nothing here touches a port.

use serde::Serialize;

use crate::model::{PathId, PubKey};
use crate::plan::Plan;
use crate::snapshot::{IdentityView, PayloadError, Snapshot};

/// The version of every `--json` document. Bump it when a field changes shape.
pub const SCHEMA_VERSION: u32 = 1;

/// `status --json`: readiness of the machine and the payload set.
#[derive(Debug, Clone, Serialize)]
pub struct StatusReport {
    pub schema_version: u32,
    pub root: String,
    pub identity: Option<IdentityView>,
    pub identity_error: Option<String>,
    pub coverage: Option<Coverage>,
    pub payloads: Vec<PayloadRow>,
    pub payload_errors: Vec<PayloadError>,
    pub identities: Vec<IdentityRow>,
    pub drift: Vec<String>,
    pub empty_values: usize,
    pub next: String,
}

impl StatusReport {
    pub fn new(snapshot: &Snapshot) -> Self {
        let empty_values: usize = snapshot.payloads.iter().map(|p| p.empty.len()).sum();
        Self {
            schema_version: SCHEMA_VERSION,
            root: snapshot.root.clone(),
            identity: snapshot.identity.clone(),
            identity_error: snapshot.identity_error.clone(),
            coverage: snapshot
                .identity
                .as_ref()
                .map(|identity| Coverage::new(snapshot, identity)),
            payloads: snapshot.payloads.iter().map(PayloadRow::new).collect(),
            payload_errors: snapshot.payload_errors.clone(),
            identities: identity_rows(snapshot),
            drift: snapshot.drift(),
            empty_values,
            next: next_step(snapshot),
        }
    }
}

impl StatusReport {
    /// What `status --strict` refuses to accept: a missing identity, unreadable
    /// payloads, drift, or empty values. Each entry names the finding, so a
    /// pipeline can gate on the exit code without parsing the table.
    pub fn strict_findings(&self) -> Vec<String> {
        let mut findings = Vec::new();
        if self.identity.is_none() {
            findings.push(match &self.identity_error {
                Some(error) => format!("identity: unavailable — {error}"),
                None => "identity: none".to_owned(),
            });
        }
        for error in &self.payload_errors {
            findings.push(format!("unreadable: {}: {}", error.id, error.error));
        }
        for note in &self.drift {
            findings.push(format!("drift: {note}"));
        }
        if self.empty_values > 0 {
            findings.push(format!("empty values: {}", self.empty_values));
        }
        findings
    }
}

/// What the local identity can open.
#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub opens: usize,
    pub total: usize,
    pub missing: Vec<PathId>,
}

impl Coverage {
    fn new(snapshot: &Snapshot, identity: &IdentityView) -> Self {
        let missing: Vec<PathId> = snapshot
            .payloads_missing(&identity.public)
            .into_iter()
            .map(|payload| payload.id.clone())
            .collect();
        Self {
            opens: snapshot.payloads.len().saturating_sub(missing.len()),
            total: snapshot.payloads.len(),
            missing,
        }
    }
}

/// One row of the payload table: counts, never values.
#[derive(Debug, Clone, Serialize)]
pub struct PayloadRow {
    pub path: PathId,
    pub keys: usize,
    pub recipients: usize,
    pub empty: usize,
}

impl PayloadRow {
    fn new(payload: &crate::meta::PayloadMeta) -> Self {
        Self {
            path: payload.id.clone(),
            keys: payload.keys.len(),
            recipients: payload.recipients.len(),
            empty: payload.empty.len(),
        }
    }
}

/// One label from `.sops.yaml`, and whether it is the local key.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityRow {
    pub label: String,
    pub public: PubKey,
    pub payloads: usize,
    pub local: bool,
}

pub fn identity_rows(snapshot: &Snapshot) -> Vec<IdentityRow> {
    let local = snapshot.identity.as_ref().map(|identity| &identity.public);
    snapshot
        .labels()
        .into_iter()
        .map(|(label, key, ids)| IdentityRow {
            local: local == Some(&key),
            label: label.to_string(),
            public: key,
            payloads: ids.len(),
        })
        .collect()
}

/// `who --json`: the identity map.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityReport {
    pub schema_version: u32,
    pub identities: Vec<IdentityRow>,
}

impl IdentityReport {
    pub fn new(snapshot: &Snapshot) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            identities: identity_rows(snapshot),
        }
    }
}

/// One invariant, as data.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

/// `check --json`: every invariant that ran.
#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    pub schema_version: u32,
    pub checks: Vec<Check>,
}

impl CheckReport {
    pub fn new(checks: Vec<Check>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            checks,
        }
    }

    pub fn failed(&self) -> usize {
        self.checks.iter().filter(|check| !check.ok).count()
    }
}

/// `--dry-run --json`: the plan a command would apply. `SetValue.value` is
/// serialized as `null`; the plan carries no key material.
#[derive(Debug, Serialize)]
pub struct PlanDocument<'a> {
    pub schema_version: u32,
    pub plan: &'a Plan,
}

impl<'a> PlanDocument<'a> {
    pub fn new(plan: &'a Plan) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            plan,
        }
    }
}

/// The suggestion line of `status`, derived from the same facts the report
/// lists.
pub fn next_step(snapshot: &Snapshot) -> String {
    if snapshot.identity.is_none() {
        return "next: lockset key import".into();
    }
    if !snapshot.payload_errors.is_empty() {
        return "next: fix the unreadable payloads above".into();
    }
    if !snapshot.drift().is_empty() {
        return "next: fix the .sops.yaml / payload drift above".into();
    }
    if let Some(payload) = snapshot.payloads.iter().find(|p| !p.empty.is_empty()) {
        return format!("next: lockset set <KEY> --payload {}", payload.id);
    }
    "ready".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CustodyKind, PubKey};
    use crate::snapshot::PayloadError;

    fn report() -> StatusReport {
        StatusReport {
            schema_version: SCHEMA_VERSION,
            root: ".".into(),
            identity: None,
            identity_error: None,
            coverage: None,
            payloads: Vec::new(),
            payload_errors: vec![PayloadError {
                id: PathId::parse("secrets/bad.env").unwrap(),
                error: "boom".into(),
            }],
            identities: Vec::new(),
            drift: vec!["secrets/a.env: drift".into()],
            empty_values: 2,
            next: "next: lockset key import".into(),
        }
    }

    #[test]
    fn strict_findings_name_every_failure_class() {
        let findings = report().strict_findings();

        assert_eq!(findings.len(), 4, "{findings:?}");
        assert!(findings[0].contains("identity: none"), "{findings:?}");
        assert!(
            findings[1].contains("unreadable: secrets/bad.env: boom"),
            "{findings:?}"
        );
        assert!(
            findings[2].contains("drift: secrets/a.env: drift"),
            "{findings:?}"
        );
        assert!(findings[3].contains("empty values: 2"), "{findings:?}");
    }

    #[test]
    fn a_clean_report_has_no_strict_findings() {
        let mut clean = report();
        clean.identity = Some(IdentityView {
            public: PubKey::parse("age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x")
                .unwrap(),
            custody: CustodyKind::Memory,
            label: None,
        });
        clean.payload_errors.clear();
        clean.drift.clear();
        clean.empty_values = 0;

        assert!(clean.strict_findings().is_empty());
    }

    #[test]
    fn an_unavailable_identity_is_a_strict_finding() {
        let mut report = report();
        report.identity_error = Some("keyring unavailable".into());

        let findings = report.strict_findings();
        assert!(
            findings[0].contains("identity: unavailable — keyring unavailable"),
            "{findings:?}"
        );
    }
}
