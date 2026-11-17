use std::collections::BTreeMap;

use serde::Serialize;

use crate::meta::PayloadMeta;
use crate::model::{CustodyKind, Label, PathId, PubKey};
use crate::sopsfile::SopsFile;

/// The local private key, when custody has one.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityView {
    pub public: PubKey,
    pub custody: CustodyKind,
    pub label: Option<Label>,
}

/// A payload that could not be read or parsed. Reports surface it and carry on
/// with the rest; unrelated payloads stay usable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PayloadError {
    pub id: PathId,
    pub error: String,
}

/// Everything the read-only operations need, assembled by the caller from
/// ports. Ops never fetch anything themselves.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub root: String,
    pub sops: SopsFile,
    pub payloads: Vec<PayloadMeta>,
    pub identity: Option<IdentityView>,
    /// Why custody failed instead of simply holding nothing. Reports stay
    /// usable; `check` records this as a finding.
    pub identity_error: Option<String>,
    /// Digest of every file read into this snapshot, keyed by path. A plan
    /// copies the digests of the files it touches, so an apply can tell that an
    /// input changed in between.
    pub digests: BTreeMap<PathId, String>,
    /// Payloads that could not be read or parsed, with the reason.
    pub payload_errors: Vec<PayloadError>,
}

impl Snapshot {
    pub fn new(
        root: impl Into<String>,
        sops: SopsFile,
        payloads: Vec<PayloadMeta>,
        identity: Option<IdentityView>,
    ) -> Self {
        Self {
            root: root.into(),
            sops,
            payloads,
            identity,
            identity_error: None,
            digests: BTreeMap::new(),
            payload_errors: Vec::new(),
        }
    }

    /// Attach the payloads that could not be parsed.
    pub fn with_payload_errors(mut self, errors: Vec<PayloadError>) -> Self {
        self.payload_errors = errors;
        self
    }

    /// The parse error recorded for a payload, when it has one.
    pub fn payload_error(&self, id: &PathId) -> Option<&PayloadError> {
        self.payload_errors.iter().find(|error| &error.id == id)
    }

    /// Attach the digests of the files this snapshot was built from.
    pub fn with_digests(mut self, digests: BTreeMap<PathId, String>) -> Self {
        self.digests = digests;
        self
    }

    /// Record the custody failure behind a missing identity.
    pub fn identity_unavailable(mut self, error: impl Into<String>) -> Self {
        self.identity_error = Some(error.into());
        self
    }

    pub fn label_for(&self, key: &PubKey) -> Option<Label> {
        self.sops.rules().iter().find_map(|r| r.label_of(key))
    }

    pub fn payloads_with(&self, key: &PubKey) -> Vec<&PayloadMeta> {
        self.payloads.iter().filter(|p| p.has(key)).collect()
    }

    pub fn payloads_missing(&self, key: &PubKey) -> Vec<&PayloadMeta> {
        self.payloads.iter().filter(|p| !p.has(key)).collect()
    }

    pub fn payload(&self, id: &PathId) -> Option<&PayloadMeta> {
        self.payloads.iter().find(|p| &p.id == id)
    }

    /// Label -> key -> payloads that carry it, in `.sops.yaml` order.
    pub fn labels(&self) -> Vec<(Label, PubKey, Vec<PathId>)> {
        let mut out: Vec<(Label, PubKey, Vec<PathId>)> = Vec::new();
        for rule in self.sops.rules() {
            for recipient in &rule.recipients {
                let Some(label) = recipient.label.clone() else {
                    continue;
                };
                let ids: Vec<PathId> = self
                    .payloads
                    .iter()
                    .filter(|p| p.has(&recipient.key))
                    .map(|p| p.id.clone())
                    .collect();
                match out
                    .iter_mut()
                    .find(|(l, k, _)| l == &label && k == &recipient.key)
                {
                    Some((_, _, existing)) => {
                        for id in ids {
                            if !existing.contains(&id) {
                                existing.push(id);
                            }
                        }
                    }
                    None => out.push((label, recipient.key.clone(), ids)),
                }
            }
        }
        out
    }

    /// Drift between `.sops.yaml` and the payload metadata, plus unlabelled
    /// recipients. Both are reported, never repaired here.
    pub fn drift(&self) -> Vec<String> {
        let mut notes = self.sops.drift();
        for payload in &self.payloads {
            match self.sops.rule_indexes_for(payload.id.as_str()) {
                Ok(indexes) if indexes.is_empty() => notes.push(format!(
                    "{}: no .sops.yaml rule matches this payload",
                    payload.id
                )),
                Ok(indexes) => {
                    let mut rule_keys: Vec<&PubKey> = Vec::new();
                    for i in indexes {
                        rule_keys.extend(self.sops.rules()[i].recipients.iter().map(|r| &r.key));
                    }
                    for key in &payload.recipients {
                        if !rule_keys.contains(&key) {
                            notes.push(format!(
                                "{}: lists {} but no matching rule does",
                                payload.id, key
                            ));
                        }
                    }
                    for key in rule_keys {
                        if !payload.has(key) {
                            notes.push(format!(
                                "{}: a matching rule lists {} but the payload does not",
                                payload.id, key
                            ));
                        }
                    }
                }
                Err(e) => notes.push(format!("{}: {e}", payload.id)),
            }
        }
        notes
    }
}
