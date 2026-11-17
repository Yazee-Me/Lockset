use crate::model::{Label, PathId, PubKey};
use crate::ports::Codec;
use crate::report::Check;
use crate::snapshot::Snapshot;
use crate::{Error, Result};

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

    out.push(Check {
        name: "payloads parse".into(),
        ok: snapshot.payload_errors.is_empty(),
        detail: if snapshot.payload_errors.is_empty() {
            format!("{} payloads", snapshot.payloads.len())
        } else {
            snapshot
                .payload_errors
                .iter()
                .map(|error| format!("{}: {}", error.id, error.error))
                .collect::<Vec<_>>()
                .join("; ")
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

    let empty: Vec<String> = snapshot
        .payloads
        .iter()
        .flat_map(|p| p.empty.iter().map(move |k| format!("{}:{k}", p.id)))
        .collect();
    out.push(Check {
        name: "no empty values".into(),
        ok: empty.is_empty(),
        detail: if empty.is_empty() {
            "none".into()
        } else {
            empty.join(", ")
        },
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
        crate::meta::require_dotenv(id)?;
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
        let report = crate::report::StatusReport::new(&snapshot(Some(A)));

        assert_eq!(report.identity.as_ref().map(|i| i.public.as_str()), Some(A));
        let coverage = report.coverage.as_ref().unwrap();
        assert_eq!((coverage.opens, coverage.total), (2, 2));
        assert!(coverage.missing.is_empty());
        assert!(report.drift.is_empty());
        assert_eq!(report.payloads.len(), 2);
        assert_eq!(report.schema_version, crate::report::SCHEMA_VERSION);
    }

    #[test]
    fn checks_pass_for_a_consistent_snapshot() {
        let checks = checks(&snapshot(Some(A)));
        assert!(checks.iter().all(|c| c.ok), "{:?}", checks);
    }

    #[test]
    fn status_names_the_missing_identity() {
        let report = crate::report::StatusReport::new(&snapshot(None));

        assert!(report.identity.is_none());
        assert!(report.coverage.is_none());
        assert!(report.next.contains("key import"), "{report:?}");
    }

    #[test]
    fn status_reports_an_unavailable_identity_with_its_reason() {
        let report = crate::report::StatusReport::new(
            &snapshot(None).identity_unavailable("no session keyring"),
        );

        assert_eq!(report.identity_error.as_deref(), Some("no session keyring"));
    }

    struct FakeCodec(&'static str);

    impl Codec for FakeCodec {
        fn decrypt(&self, _id: &PathId, _key: &crate::model::SecretKey) -> Result<Vec<u8>> {
            Ok(self.0.as_bytes().to_vec())
        }
        fn rewrap(&self, _id: &PathId, _key: &crate::model::SecretKey) -> Result<()> {
            Ok(())
        }
        fn rekey(&self, _id: &PathId, _key: &crate::model::SecretKey) -> Result<()> {
            Ok(())
        }
        fn set_value(
            &self,
            _id: &PathId,
            _name: &str,
            _value: &str,
            _key: &crate::model::SecretKey,
        ) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn checks_flag_empty_values() {
        let text = format!(
            "EMPTY=\nTOKEN=ENC[a,type:str]\nsops_age__list_0__map_enc=x\nsops_age__list_0__map_recipient={A}\nsops_version=3.13.3\nsops_mac=ENC[a,type:str]\n"
        );
        let payload =
            crate::meta::parse(PathId::parse("secrets/prod/empty.env").unwrap(), &text).unwrap();
        let snap = Snapshot::new(".", sops(), vec![payload], None);

        let checks = checks(&snap);
        let empty = checks
            .iter()
            .find(|check| check.name == "no empty values")
            .unwrap();

        assert!(!empty.ok);
        assert!(
            empty.detail.contains("secrets/prod/empty.env:EMPTY"),
            "{empty:?}"
        );
    }

    #[test]
    fn env_for_reads_dotenv_payloads() {
        let key = crate::model::SecretKey::generate();
        let codec = FakeCodec("A=1\nB=2\n");

        let envs = env_for(&codec, &[PathId::parse("secrets/a.env").unwrap()], &key).unwrap();

        assert_eq!(envs.len(), 2);
        assert!(envs.contains(&("A".to_owned(), "1".to_owned())), "{envs:?}");
    }

    #[test]
    fn env_for_rejects_a_payload_that_is_not_dotenv() {
        let key = crate::model::SecretKey::generate();
        let codec = FakeCodec("A: 1\n");

        let error = env_for(&codec, &[PathId::parse("secrets/a.yaml").unwrap()], &key).unwrap_err();

        assert!(error.to_string().contains("dotenv"), "{error}");
        assert!(error.to_string().contains("a.yaml"), "{error}");
    }

    #[test]
    fn status_and_checks_report_payload_errors_with_the_path() {
        let error = crate::snapshot::PayloadError {
            id: PathId::parse("secrets/bad.env").unwrap(),
            error: "not an age public key: 'nope'".to_owned(),
        };
        let snap = snapshot(Some(A)).with_payload_errors(vec![error]);

        let report = crate::report::StatusReport::new(&snap);
        assert_eq!(report.payload_errors.len(), 1);
        assert_eq!(report.payload_errors[0].id.as_str(), "secrets/bad.env");
        assert!(
            report.payload_errors[0]
                .error
                .contains("not an age public key"),
            "{:?}",
            report.payload_errors
        );
        assert!(
            report.next.contains("fix the unreadable payloads"),
            "{}",
            report.next
        );

        let checks = checks(&snap);
        let parse = checks.iter().find(|c| c.name == "payloads parse").unwrap();
        assert!(!parse.ok);
        assert!(
            parse.detail.contains("secrets/bad.env") && parse.detail.contains("not an age"),
            "{parse:?}"
        );
    }

    #[test]
    fn a_snapshot_without_payload_errors_passes_the_parse_check() {
        let checks = checks(&snapshot(Some(A)));
        let parse = checks.iter().find(|c| c.name == "payloads parse").unwrap();
        assert!(parse.ok);
        assert!(parse.detail.contains("2 payloads"), "{parse:?}");
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
