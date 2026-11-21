use std::collections::BTreeMap;

use serde::Serialize;

use crate::config::IdentityRegistry;
use crate::meta::PayloadMeta;
use crate::model::{CustodyKind, Label, PathId, PubKey};
use crate::sopsfile::SopsFile;
use crate::{Error, Result};

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
    /// The sops config file this snapshot was built from, repo-relative.
    pub sops_path: PathId,
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
    /// The configured identity registry. When it is not empty, its labels win
    /// over `.sops.yaml` comments, which become a migration input.
    pub registry: IdentityRegistry,
    /// The config file, repo-relative, when this snapshot may rewrite it. A
    /// registry edit needs the file; read-only reports do not.
    pub config_path: Option<PathId>,
    /// The bytes of that config file, as read for this snapshot.
    pub config_text: Option<String>,
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
            sops_path: PathId::parse(crate::config::DEFAULT_SOPS_CONFIG)
                .expect("the default sops config path is valid"),
            sops,
            payloads,
            identity,
            identity_error: None,
            digests: BTreeMap::new(),
            payload_errors: Vec::new(),
            registry: IdentityRegistry::default(),
            config_path: None,
            config_text: None,
        }
    }

    /// Attach the identity registry from `lockset.toml`.
    pub fn with_registry(mut self, registry: IdentityRegistry) -> Self {
        self.registry = registry;
        self
    }

    /// Record the config file this snapshot may rewrite.
    pub fn with_config_document(mut self, path: PathId, text: String) -> Self {
        self.config_path = Some(path);
        self.config_text = Some(text);
        self
    }

    /// The config file and its bytes, for a plan that edits the registry. A
    /// config outside the repository (or no file at all) has nothing to plan.
    pub fn config_document(&self) -> Result<(&PathId, &str)> {
        match (&self.config_path, &self.config_text) {
            (Some(path), Some(text)) => Ok((path, text)),
            _ => Err(Error::refused(
                "the registry lives in lockset.toml, but this snapshot has no editable config \
                 document; pass --config with the file inside the repository",
            )),
        }
    }

    /// Record the sops config file this snapshot came from.
    pub fn with_sops_path(mut self, path: PathId) -> Self {
        self.sops_path = path;
        self
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

    /// The label of `key`: the registry first, then a comment as fallback.
    pub fn label_for(&self, key: &PubKey) -> Option<Label> {
        self.registry
            .label_for(key)
            .cloned()
            .or_else(|| self.sops.rules().iter().find_map(|r| r.label_of(key)))
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

    /// Label -> key -> payloads that carry it: the registry in config order,
    /// then any comment label the registry does not cover, in `.sops.yaml`
    /// order. The config wins, so a conflict appears once, with its label.
    pub fn labels(&self) -> Vec<(Label, PubKey, Vec<PathId>)> {
        let payloads_for = |key: &PubKey| -> Vec<PathId> {
            self.payloads
                .iter()
                .filter(|p| p.has(key))
                .map(|p| p.id.clone())
                .collect()
        };
        let mut out: Vec<(Label, PubKey, Vec<PathId>)> = self
            .registry
            .identities()
            .iter()
            .map(|identity| {
                (
                    identity.label.clone(),
                    identity.public.clone(),
                    payloads_for(&identity.public),
                )
            })
            .collect();
        if !self.registry.is_empty() {
            // Comment labels are migration input: show only the keys the
            // registry does not know, so a conflict is not listed twice.
            for rule in self.sops.rules() {
                for recipient in &rule.recipients {
                    let Some(label) = recipient.label.clone() else {
                        continue;
                    };
                    if self.registry.label_for(&recipient.key).is_some() {
                        continue;
                    }
                    match out
                        .iter_mut()
                        .find(|(l, k, _)| l == &label && k == &recipient.key)
                    {
                        Some((_, _, existing)) => {
                            for id in payloads_for(&recipient.key) {
                                if !existing.contains(&id) {
                                    existing.push(id);
                                }
                            }
                        }
                        None => {
                            out.push((label, recipient.key.clone(), payloads_for(&recipient.key)))
                        }
                    }
                }
            }
            return out;
        }
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
    /// recipients. Both are reported, never repaired here. Comments are
    /// migration-only once a registry exists, so an unlabelled recipient is
    /// not drift then: the registry carries the label.
    pub fn drift(&self) -> Vec<String> {
        let mut notes = if self.registry.is_empty() {
            self.sops.drift()
        } else {
            Vec::new()
        };
        if !self.registry.is_empty() {
            for rule in self.sops.rules() {
                for recipient in &rule.recipients {
                    let Some(comment) = recipient.label.as_ref() else {
                        continue;
                    };
                    match self.registry.label_for(&recipient.key) {
                        Some(label) if label != comment => notes.push(format!(
                            "{}: lockset.toml labels it {label}, but the .sops.yaml comment says {comment}",
                            recipient.key
                        )),
                        Some(_) => {}
                        None => notes.push(format!(
                            "{}: the .sops.yaml comment labels it {comment}, but lockset.toml has no identity for it",
                            recipient.key
                        )),
                    }
                }
            }
        }
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
