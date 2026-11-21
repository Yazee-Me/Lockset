use std::collections::BTreeMap;
use std::fmt;

use serde::{Serialize, Serializer};
use zeroize::Zeroizing;

use crate::model::{CustodyKind, PathId};

/// A secret value carried by a plan. It prints and serializes as redacted and
/// zeroizes its buffer when dropped, so a plan can be logged, debugged, or
/// turned into JSON without carrying the plaintext.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(Zeroizing<String>);

impl SecretValue {
    pub fn new(value: Zeroizing<String>) -> Self {
        Self(value)
    }

    /// The only way to reach the plaintext: hand it to the codec.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Serialize for SecretValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_none()
    }
}

/// One unit of work the caller executes through a port. The core never
/// performs I/O itself, so `--dry-run` and tests share the same path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Change {
    WriteFile {
        path: PathId,
        contents: String,
    },
    UpdateKeys {
        payload: PathId,
    },
    RotateDataKey {
        payload: PathId,
    },
    /// One value, written through the codec. The value is secret material: it
    /// is redacted in `Debug` and serialized as `null`.
    SetValue {
        payload: PathId,
        name: String,
        value: SecretValue,
    },
    /// One value removed, then the payload re-encrypted with its recipients
    /// unchanged. The value itself never enters the plan.
    UnsetValue {
        payload: PathId,
        name: String,
    },
    /// Open the payload in `$SOPS_EDITOR` and re-encrypt it in place.
    EditPayload {
        payload: PathId,
    },
    StoreKey {
        custody: CustodyKind,
    },
    ForgetKey {
        custody: CustodyKind,
    },
}

impl Change {
    /// The file this change mutates, if any.
    pub fn path(&self) -> Option<&PathId> {
        match self {
            Change::WriteFile { path, .. } => Some(path),
            Change::UpdateKeys { payload } => Some(payload),
            Change::RotateDataKey { payload } => Some(payload),
            Change::SetValue { payload, .. } => Some(payload),
            Change::UnsetValue { payload, .. } => Some(payload),
            Change::EditPayload { payload } => Some(payload),
            Change::StoreKey { .. } | Change::ForgetKey { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Plan {
    pub changes: Vec<Change>,
    pub notes: Vec<String>,
    pub warnings: Vec<String>,
    /// Digest of every file this plan touches, taken when the plan was built.
    /// `exec::apply` refuses to write a file whose bytes have changed since.
    #[serde(skip)]
    pub expected: BTreeMap<PathId, String>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn push(&mut self, change: Change) {
        self.changes.push(change);
    }

    pub fn note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    pub fn warn(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    /// Record the digests of the files this plan touches so the apply can
    /// refuse input that changed after the snapshot.
    pub fn expect(&mut self, digests: &BTreeMap<PathId, String>) {
        for path in self.changes.iter().filter_map(Change::path) {
            if let Some(digest) = digests.get(path) {
                self.expected.insert(path.clone(), digest.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_with_value(value: &str) -> Plan {
        let mut plan = Plan::default();
        plan.push(Change::SetValue {
            payload: PathId::parse("secrets/dev.env").unwrap(),
            name: "TOKEN".to_owned(),
            value: SecretValue::new(Zeroizing::new(value.to_owned())),
        });
        plan
    }

    #[test]
    fn debug_never_shows_the_value() {
        let plan = plan_with_value("hunter2");

        let debug = format!("{plan:?}");

        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(debug.contains("TOKEN"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }

    #[test]
    fn json_names_the_key_but_not_the_value() {
        let plan = plan_with_value("hunter2");

        let json = serde_json::to_value(&plan).unwrap();

        assert_eq!(json["changes"][0]["type"], "set_value");
        assert_eq!(json["changes"][0]["payload"], "secrets/dev.env");
        assert_eq!(json["changes"][0]["name"], "TOKEN");
        assert_eq!(json["changes"][0]["value"], serde_json::Value::Null);
        assert!(!json.to_string().contains("hunter2"), "{json}");
    }
}
