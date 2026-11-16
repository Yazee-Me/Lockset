use crate::model::{CustodyKind, PathId};

/// One unit of work the caller executes through a port. The core never
/// performs I/O itself, so `--dry-run` and tests share the same path.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// One value, written through the codec. The value is secret material and
    /// must never be rendered by `describe`/`Display`.
    SetValue {
        payload: PathId,
        name: String,
        value: String,
    },
    StoreKey {
        custody: CustodyKind,
    },
    ForgetKey {
        custody: CustodyKind,
    },
}

#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub changes: Vec<Change>,
    pub notes: Vec<String>,
    pub warnings: Vec<String>,
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
}
