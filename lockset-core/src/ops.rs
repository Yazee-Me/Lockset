use crate::model::{Label, PathId, PubKey};
use crate::ports::Codec;
use crate::snapshot::Snapshot;
use crate::{Error, Result};

#[derive(Debug, Default, Clone)]
pub struct Report {
    pub lines: Vec<String>,
}

impl Report {
    pub fn line(&mut self, line: impl Into<String>) {
        self.lines.push(line.into());
    }

    pub fn blank(&mut self) {
        if self.lines.last().is_some_and(|l| !l.is_empty()) {
            self.lines.push(String::new());
        }
    }

    pub fn render(&self) -> String {
        let mut out = self.lines.join("\n");
        out.push('\n');
        out
    }
}

#[derive(Debug, Clone)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

/// Readiness of the machine and the payload set. Read-only by construction.
pub fn status(snapshot: &Snapshot) -> Report {
    let mut report = Report::default();

    match (&snapshot.identity, &snapshot.identity_error) {
        (Some(identity), _) => report.line(format!(
            "identity: {} ({}) via {}",
            identity.public.as_str(),
            identity
                .label
                .as_ref()
                .map(|l| l.to_string())
                .unwrap_or_else(|| "unlabelled".into()),
            identity.custody
        )),
        (None, Some(error)) => report.line(format!("identity: unavailable — {error}")),
        (None, None) => report.line(
            "identity: none — set LOCKSET_AGE_KEY, pass --custody file:<path>, \
             or run `lockset key import`",
        ),
    }

    if let Some(identity) = &snapshot.identity {
        let missing = snapshot.payloads_missing(&identity.public);
        if missing.is_empty() {
            report.line(format!(
                "coverage: opens all {} payloads",
                snapshot.payloads.len()
            ));
        } else {
            report.line(format!(
                "coverage: opens {}/{} payloads; missing: {}",
                snapshot.payloads.len() - missing.len(),
                snapshot.payloads.len(),
                missing
                    .iter()
                    .map(|p| p.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    report.blank();
    report.line(format!(
        "{:<34} {:>4} {:>10} {:>6}",
        "payload", "keys", "recipients", "empty"
    ));
    for payload in &snapshot.payloads {
        report.line(format!(
            "{:<34} {:>4} {:>10} {:>6}",
            payload.id.as_str(),
            payload.keys.len(),
            payload.recipients.len(),
            payload.empty.len()
        ));
    }

    let labels = snapshot.labels();
    if !labels.is_empty() {
        report.blank();
        report.line("identities:");
        for (label, key, ids) in labels {
            report.line(format!(
                "  {:<12} {}  {} payload(s)",
                label.as_str(),
                key.as_str(),
                ids.len()
            ));
        }
    }

    let drift = snapshot.drift();
    report.blank();
    if drift.is_empty() {
        report.line("drift: none");
    } else {
        report.line(format!("drift: {} issue(s)", drift.len()));
        for note in drift {
            report.line(format!("  {note}"));
        }
    }

    let empties: usize = snapshot.payloads.iter().map(|p| p.empty.len()).sum();
    report.blank();
    if empties == 0 {
        report.line("empty values: none");
    } else {
        report.line(format!("empty values: {empties} (fill with `lockset set`)"));
    }

    report.blank();
    report.line(next_step(snapshot));
    report
}

fn next_step(snapshot: &Snapshot) -> String {
    if snapshot.identity.is_none() {
        return "next: lockset key import".into();
    }
    let drift = snapshot.drift();
    if !drift.is_empty() {
        return "next: fix the .sops.yaml / payload drift above".into();
    }
    if snapshot.payloads.iter().any(|p| !p.empty.is_empty()) {
        return "next: lockset set <KEY> --payload secrets/prod/infra.env".into();
    }
    "ready".into()
}

/// The identity map: who can read what, and whether that is the local key.
pub fn who(snapshot: &Snapshot) -> Report {
    let mut report = Report::default();
    report.line(format!(
        "{:<12} {:<64} {:>10}  {}",
        "identity", "public key", "payloads", "local"
    ));
    let local = snapshot.identity.as_ref().map(|i| &i.public);
    for (label, key, ids) in snapshot.labels() {
        report.line(format!(
            "{:<12} {:<64} {:>10}  {}",
            label.as_str(),
            key.as_str(),
            ids.len(),
            if local == Some(&key) { "yes" } else { "" }
        ));
    }
    report
}

/// Invariants that never need a private key, plus the local-key coverage.
pub fn checks(snapshot: &Snapshot) -> Vec<Check> {
    let mut out = Vec::new();

    out.push(match (&snapshot.identity, &snapshot.identity_error) {
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
            detail: "none — set LOCKSET_AGE_KEY, pass --custody file:<path>, or run \
                     `lockset key import`"
                .into(),
        },
    });

    let not_ciphertext: Vec<&str> = snapshot
        .payloads
        .iter()
        .filter(|p| !p.encrypted)
        .map(|p| p.id.as_str())
        .collect();
    out.push(Check {
        name: "payloads are ciphertext".into(),
        ok: not_ciphertext.is_empty(),
        detail: if not_ciphertext.is_empty() {
            format!("{} payloads", snapshot.payloads.len())
        } else {
            not_ciphertext.join(", ")
        },
    });

    let plaintext: Vec<String> = snapshot
        .payloads
        .iter()
        .flat_map(|p| p.plaintext.iter().map(move |k| format!("{}:{k}", p.id)))
        .collect();
    out.push(Check {
        name: "no plaintext values".into(),
        ok: plaintext.is_empty(),
        detail: plaintext.join(", "),
    });

    let drift = snapshot.drift();
    out.push(Check {
        name: "labels and recipients agree".into(),
        ok: drift.is_empty(),
        detail: drift.join("; "),
    });

    let admin = snapshot
        .sops
        .rules()
        .iter()
        .flat_map(|r| r.recipients.iter())
        .find(|r| r.label.as_ref().is_some_and(|l| l.as_str() == "admin"))
        .map(|r| r.key.clone());
    match admin {
        Some(admin) => {
            let missing = snapshot.payloads_missing(&admin);
            out.push(Check {
                name: "admin opens every payload".into(),
                ok: missing.is_empty(),
                detail: missing
                    .iter()
                    .map(|p| p.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        }
        None => out.push(Check {
            name: "admin opens every payload".into(),
            ok: false,
            detail: "no recipient is labelled admin".into(),
        }),
    }

    if let Some(identity) = &snapshot.identity {
        let missing = snapshot.payloads_missing(&identity.public);
        out.push(Check {
            name: "local identity opens every payload".into(),
            ok: missing.is_empty(),
            detail: missing
                .iter()
                .map(|p| p.id.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        });
    }

    out
}

pub struct GrantRequest {
    pub key: PubKey,
    pub label: Label,
    pub only: Option<Vec<PathId>>,
}

/// Plan: add a recipient to the targeted rules, then re-wrap those payloads.
pub fn grant(snapshot: &Snapshot, request: &GrantRequest) -> Result<crate::plan::Plan> {
    let rules = snapshot.sops.rules();
    let targets: Vec<usize> = match &request.only {
        None => (0..rules.len()).collect(),
        Some(ids) => {
            let mut out = Vec::new();
            for id in ids {
                let index = snapshot
                    .sops
                    .rule_index_for(id.as_str())?
                    .ok_or_else(|| Error::invalid(format!("no .sops.yaml rule matches {id}")))?;
                if !out.contains(&index) {
                    out.push(index);
                }
            }
            out
        }
    };

    let mut sets: Vec<Vec<crate::sopsfile::Recipient>> =
        rules.iter().map(|r| r.recipients.clone()).collect();
    let mut added = Vec::new();
    for index in &targets {
        if !sets[*index].iter().any(|r| r.key == request.key) {
            sets[*index].push(crate::sopsfile::Recipient {
                key: request.key.clone(),
                label: Some(request.label.clone()),
            });
            added.push(*index);
        }
    }

    let mut plan = crate::plan::Plan::default();
    if added.is_empty() {
        plan.note(format!(
            "{} is already a recipient of the targeted payloads",
            request.key
        ));
        return Ok(plan);
    }

    let text = snapshot.sops.render_with(&sets)?;
    plan.push(crate::plan::Change::WriteFile {
        path: PathId::parse(".sops.yaml")?,
        contents: text,
    });
    for payload in &snapshot.payloads {
        let matched = snapshot.sops.rule_indexes_for(payload.id.as_str())?;
        if matched.iter().any(|i| targets.contains(i)) {
            plan.push(crate::plan::Change::UpdateKeys {
                payload: payload.id.clone(),
            });
        }
    }
    plan.note(format!(
        "grant {} as {} on {} payload(s)",
        request.key,
        request.label,
        plan.changes.len().saturating_sub(1)
    ));

    let same_label: Vec<&PubKey> = rules
        .iter()
        .flat_map(|r| r.recipients.iter())
        .filter(|r| r.label.as_ref() == Some(&request.label))
        .map(|r| &r.key)
        .collect();
    if same_label.iter().any(|k| **k != request.key) {
        plan.warn(format!(
            "label {} now names more than one key; revoke the retired key to make it unambiguous",
            request.label
        ));
    }
    plan.expect(&snapshot.digests);
    Ok(plan)
}

/// Plan: rotate the data key (and re-encrypt every value) of the selected
/// payloads. Values are preserved by the codec; only the key changes.
pub fn rotate(snapshot: &Snapshot, only: Option<&[PathId]>) -> Result<crate::plan::Plan> {
    let targets: Vec<PathId> = match only {
        None => snapshot.payloads.iter().map(|p| p.id.clone()).collect(),
        Some(ids) => {
            let mut out: Vec<PathId> = Vec::new();
            for id in ids {
                if snapshot.payload(id).is_none() {
                    return Err(Error::invalid(format!("no such payload: {id}")));
                }
                if !out.contains(id) {
                    out.push(id.clone());
                }
            }
            out
        }
    };
    if targets.is_empty() {
        return Err(Error::invalid("no payloads to rotate"));
    }
    let mut plan = crate::plan::Plan::default();
    for id in &targets {
        plan.push(crate::plan::Change::RotateDataKey {
            payload: id.clone(),
        });
    }
    plan.note(format!(
        "rotate the data key of {} payload(s); values are unchanged",
        targets.len()
    ));
    plan.expect(&snapshot.digests);
    Ok(plan)
}

pub enum RevokeTarget {
    Key(PubKey),
    Label(Label),
}

pub struct RevokeRequest {
    pub target: RevokeTarget,
    pub keep_data_key: bool,
    pub force: bool,
}

/// Plan: drop a recipient from `.sops.yaml`, re-wrap, and (by default) rotate
/// the data key so future values are unreadable to the retired key.
pub fn revoke(snapshot: &Snapshot, request: &RevokeRequest) -> Result<crate::plan::Plan> {
    let key = match &request.target {
        RevokeTarget::Key(key) => key.clone(),
        RevokeTarget::Label(label) => {
            let keys: Vec<&PubKey> = snapshot
                .sops
                .rules()
                .iter()
                .flat_map(|r| r.recipients.iter())
                .filter(|r| r.label.as_ref() == Some(label))
                .map(|r| &r.key)
                .collect();
            let mut unique: Vec<&PubKey> = Vec::new();
            for k in keys {
                if !unique.contains(&k) {
                    unique.push(k);
                }
            }
            match unique.len() {
                0 => {
                    return Err(Error::invalid(format!(
                        "no identity labelled {label} in .sops.yaml"
                    )))
                }
                1 => unique[0].clone(),
                _ => {
                    return Err(Error::refused(format!(
                        "label {label} names {} keys; pass the public key instead",
                        unique.len()
                    )))
                }
            }
        }
    };

    if let Some(identity) = &snapshot.identity {
        if identity.public == key && !request.force {
            return Err(Error::refused(format!(
                "{} is this machine's identity (via {}); revoke it from another admin machine so \
                 this one keeps its key, or pass --force to decommission this machine deliberately",
                key, identity.custody
            )));
        }
    }

    let rules = snapshot.sops.rules();
    let mut sets: Vec<Vec<crate::sopsfile::Recipient>> =
        rules.iter().map(|r| r.recipients.clone()).collect();
    let mut affected = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        if !rule.contains(&key) {
            continue;
        }
        let before = sets[index].len();
        sets[index].retain(|r| r.key != key);
        if sets[index].is_empty() {
            return Err(Error::refused(format!(
                "removing {} would leave rule '{}' with no recipients",
                key, rule.path_regex
            )));
        }
        if sets[index].len() != before {
            affected.push(index);
        }
    }
    if affected.is_empty() {
        return Err(Error::invalid(format!(
            "{} is not a recipient in .sops.yaml",
            key
        )));
    }

    let text = snapshot.sops.render_with(&sets)?;
    let mut plan = crate::plan::Plan::default();
    plan.push(crate::plan::Change::WriteFile {
        path: PathId::parse(".sops.yaml")?,
        contents: text,
    });

    let mut touched = Vec::new();
    for payload in &snapshot.payloads {
        if !payload.has(&key) {
            continue;
        }
        touched.push(payload.id.clone());
        plan.push(crate::plan::Change::UpdateKeys {
            payload: payload.id.clone(),
        });
        if !request.keep_data_key {
            plan.push(crate::plan::Change::RotateDataKey {
                payload: payload.id.clone(),
            });
        }
    }

    if request.keep_data_key {
        plan.note(format!(
            "data keys kept; {} can still read the current values until they are rotated",
            key
        ));
    } else {
        plan.note(
            "the retired key still opens commits made before this one: rotate what it could read at the issuer",
        );
    }
    plan.note(format!(
        "affected: {}",
        touched
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    plan.expect(&snapshot.digests);
    Ok(plan)
}

/// Values for a child process, in memory only.
pub fn env_for(
    codec: &dyn Codec,
    ids: &[PathId],
    key: &crate::model::SecretKey,
) -> Result<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = Vec::new();
    for id in ids {
        let plain = codec.decrypt(id, key)?;
        let text = String::from_utf8(plain)
            .map_err(|_| Error::failed(format!("{id} does not decrypt to UTF-8")))?;
        for (name, value) in crate::dotenv::parse(&text) {
            if let Some(existing) = out.iter_mut().find(|(n, _)| n == &name) {
                existing.1 = value;
            } else {
                out.push((name, value));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CustodyKind;
    use crate::snapshot::IdentityView;
    use crate::sopsfile::SopsFile;

    const A: &str = "age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x";
    const B: &str = "age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q";
    const C: &str = "age1y4gs9hk93n3mpvhwydaq7uz4mn3a0esf0wfh3md2v2qz4hye9frsfpelwh";

    fn sops() -> SopsFile {
        SopsFile::parse(&format!(
            "creation_rules:\n- path_regex: secrets/prod/infra\\.env$\n  age: {A},{B},{C} # admin,recovery,ci\n- path_regex: secrets/prod/host-main\\.env$\n  age: {A},{B} # admin,recovery\n"
        ))
        .unwrap()
    }

    fn payload(id: &str, recipients: &[&str]) -> crate::meta::PayloadMeta {
        let mut text = String::from("K1=ENC[a,type:str]\n");
        for (i, recipient) in recipients.iter().enumerate() {
            text.push_str(&format!("sops_age__list_{i}__map_enc=x\n"));
            text.push_str(&format!("sops_age__list_{i}__map_recipient={recipient}\n"));
        }
        text.push_str("sops_version=3.13.3\nsops_mac=ENC[a,type:str]\n");
        crate::meta::parse(PathId::parse(id).unwrap(), &text).unwrap()
    }

    fn snapshot(identity: Option<&str>) -> Snapshot {
        let payloads = vec![
            payload("secrets/prod/infra.env", &[A, B, C]),
            payload("secrets/prod/host-main.env", &[A, B]),
        ];
        let identity = identity.map(|public| IdentityView {
            public: PubKey::parse(public).unwrap(),
            custody: CustodyKind::Memory,
            label: Some(Label::parse("admin").unwrap()),
        });
        Snapshot::new(".", sops(), payloads, identity)
    }

    #[test]
    fn status_reports_identity_and_drift() {
        let report = status(&snapshot(Some(A))).render();
        assert!(report.contains("identity: age1p243yl"));
        assert!(report.contains("coverage: opens all 2 payloads"));
        assert!(report.contains("drift: none"));
    }

    #[test]
    fn checks_pass_for_a_consistent_snapshot() {
        let checks = checks(&snapshot(Some(A)));
        assert!(checks.iter().all(|c| c.ok), "{:?}", checks);
    }

    #[test]
    fn status_names_the_missing_identity() {
        let report = status(&snapshot(None)).render();
        assert!(report.contains("identity: none"), "{report}");
        assert!(!report.contains("coverage:"), "{report}");
    }

    #[test]
    fn status_reports_an_unavailable_identity_with_its_reason() {
        let report = status(&snapshot(None).identity_unavailable("no session keyring")).render();
        assert!(
            report.contains("identity: unavailable — no session keyring"),
            "{report}"
        );
    }

    #[test]
    fn checks_flag_a_missing_identity() {
        let checks = checks(&snapshot(None));
        let identity = checks.iter().find(|c| c.name == "identity").unwrap();
        assert!(!identity.ok);
        assert!(identity.detail.contains("key import"), "{identity:?}");
    }

    #[test]
    fn checks_report_a_custody_failure() {
        let checks = checks(&snapshot(None).identity_unavailable("cannot read the keyring item"));
        let identity = checks.iter().find(|c| c.name == "identity").unwrap();
        assert!(!identity.ok);
        assert!(
            identity.detail.contains("cannot read the keyring item"),
            "{identity:?}"
        );
    }

    #[test]
    fn checks_flag_missing_admin() {
        let mut sops = sops();
        let rendered = sops
            .render_with(
                &sops
                    .rules()
                    .iter()
                    .map(|r| {
                        r.recipients
                            .iter()
                            .filter(|r| r.label.as_ref().is_some_and(|l| l.as_str() != "admin"))
                            .cloned()
                            .collect()
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        sops = SopsFile::parse(&rendered).unwrap();
        let snap = Snapshot::new(
            ".",
            sops,
            vec![payload("secrets/prod/infra.env", &[B, C])],
            None,
        );
        let checks = checks(&snap);
        let admin = checks.iter().find(|c| c.name.contains("admin")).unwrap();
        assert!(!admin.ok);
    }

    #[test]
    fn rotate_covers_every_payload_by_default() {
        let plan = rotate(&snapshot(Some(A)), None).unwrap();
        assert_eq!(plan.changes.len(), 2);
        assert!(plan
            .changes
            .iter()
            .all(|c| matches!(c, crate::plan::Change::RotateDataKey { .. })));
    }

    #[test]
    fn rotate_rejects_an_unknown_payload() {
        let ids = vec![PathId::parse("secrets/prod/nope.env").unwrap()];
        assert!(rotate(&snapshot(Some(A)), Some(&ids)).is_err());
    }

    #[test]
    fn grant_scopes_to_the_named_payload() {
        let snap = snapshot(Some(A));
        let request = GrantRequest {
            key: PubKey::parse("age1y4gs9hk93n3mpvhwydaq7uz4mn3a0esf0wfh3md2v2qz4hye9frsfpelwh")
                .unwrap(),
            label: Label::parse("dev-test").unwrap(),
            only: Some(vec![PathId::parse("secrets/prod/host-main.env").unwrap()]),
        };
        let plan = grant(&snap, &request).unwrap();
        assert_eq!(plan.changes.len(), 2);
        let text = match &plan.changes[0] {
            crate::plan::Change::WriteFile { contents, .. } => contents.clone(),
            other => panic!("expected a write, got {other:?}"),
        };
        assert!(!text.lines().next().unwrap().contains("dev-test"));
        assert!(text.contains("admin,recovery,dev-test"));
    }

    #[test]
    fn grant_is_idempotent() {
        let plan = grant(
            &snapshot(Some(A)),
            &GrantRequest {
                key: PubKey::parse(A).unwrap(),
                label: Label::parse("admin").unwrap(),
                only: None,
            },
        )
        .unwrap();
        assert!(plan.is_empty());
        assert!(plan.notes[0].contains("already a recipient"));
    }

    #[test]
    fn revoke_refuses_the_local_identity_without_force() {
        let request = RevokeRequest {
            target: RevokeTarget::Label(Label::parse("admin").unwrap()),
            keep_data_key: false,
            force: false,
        };
        let error = revoke(&snapshot(Some(A)), &request).unwrap_err();
        assert!(
            error.to_string().contains("from another admin machine"),
            "{error}"
        );
    }

    #[test]
    fn revoke_rotates_the_data_key_by_default() {
        let request = RevokeRequest {
            target: RevokeTarget::Label(Label::parse("ci").unwrap()),
            keep_data_key: false,
            force: false,
        };
        let plan = revoke(&snapshot(Some(A)), &request).unwrap();
        assert!(plan
            .changes
            .iter()
            .any(|c| matches!(c, crate::plan::Change::RotateDataKey { .. })));
        assert!(plan
            .changes
            .iter()
            .any(|c| matches!(c, crate::plan::Change::UpdateKeys { .. })));
    }

    #[test]
    fn revoke_keeps_the_data_key_when_asked() {
        let request = RevokeRequest {
            target: RevokeTarget::Label(Label::parse("ci").unwrap()),
            keep_data_key: true,
            force: false,
        };
        let plan = revoke(&snapshot(Some(A)), &request).unwrap();
        assert!(!plan
            .changes
            .iter()
            .any(|c| matches!(c, crate::plan::Change::RotateDataKey { .. })));
    }

    #[test]
    fn revoke_refuses_to_empty_a_rule() {
        let sops = SopsFile::parse(&format!(
            "creation_rules:\n- path_regex: secrets/prod/infra\\.env$\n  age: {C} # ci\n"
        ))
        .unwrap();
        let snap = Snapshot::new(
            ".",
            sops,
            vec![payload("secrets/prod/infra.env", &[C])],
            None,
        );
        let request = RevokeRequest {
            target: RevokeTarget::Key(PubKey::parse(C).unwrap()),
            keep_data_key: false,
            force: false,
        };
        let error = revoke(&snap, &request).unwrap_err();
        assert!(error.to_string().contains("no recipients"));
    }
}
