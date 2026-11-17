use std::path::{Path, PathBuf};

use lockset_core::{Error, PathId, Repo, Result};

/// Payloads and `.sops.yaml` on the local filesystem. This is the only crate
/// that knows paths are paths.
pub struct FsRepo {
    root: PathBuf,
}

impl FsRepo {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `PathId` already excludes absolute paths and traversal, so joining is
    /// the whole job here.
    fn resolve(&self, id: &PathId) -> PathBuf {
        self.root.join(id.as_str())
    }
}

impl Repo for FsRepo {
    fn list(&self, prefix: &PathId) -> Result<Vec<PathId>> {
        let base = self.root.join(prefix.as_str());
        let mut out = Vec::new();
        collect(&base, &self.root, &mut out)?;
        out.sort();
        Ok(out)
    }

    fn read(&self, id: &PathId) -> Result<Vec<u8>> {
        let path = self.resolve(id);
        std::fs::read(&path).map_err(|e| Error::failed(format!("cannot read {id}: {e}")))
    }

    fn write(&self, id: &PathId, bytes: &[u8]) -> Result<()> {
        let path = self.resolve(id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::failed(format!("cannot create {}: {e}", parent.display())))?;
        }
        let tmp = path.with_file_name(format!(
            ".{}.lockset-{}",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("tmp"),
            std::process::id()
        ));
        std::fs::write(&tmp, bytes)
            .map_err(|e| Error::failed(format!("cannot write {}: {e}", tmp.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &path).map_err(|e| Error::failed(format!("cannot replace {id}: {e}")))
    }
}

fn collect(dir: &Path, root: &Path, out: &mut Vec<PathId>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    let entries = std::fs::read_dir(dir)
        .map_err(|e| Error::failed(format!("cannot list {}: {e}", dir.display())))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| Error::failed(format!("cannot list {}: {e}", dir.display())))?;
        let path = entry.path();
        if path.is_dir() {
            collect(&path, root, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("env") {
            if let Ok(rel) = path.strip_prefix(root) {
                let rel = rel.to_string_lossy().replace('\\', "/");
                out.push(PathId::parse(&rel)?);
            }
        }
    }
    Ok(())
}
