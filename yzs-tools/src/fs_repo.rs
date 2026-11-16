use std::path::{Path, PathBuf};

use yzs_core::{Error, PathId, Repo, Result};

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

    fn resolve(&self, id: &PathId) -> Result<PathBuf> {
        let rel = id.as_str();
        let unsafe_path = rel.starts_with('/')
            || rel
                .split('/')
                .any(|segment| segment.is_empty() || segment == "..");
        if unsafe_path {
            return Err(Error::invalid(format!(
                "refusing an absolute or traversing path: {rel}"
            )));
        }
        Ok(self.root.join(rel))
    }
}

impl Repo for FsRepo {
    fn list(&self, prefix: &str) -> Result<Vec<PathId>> {
        let base = self.root.join(prefix);
        let mut out = Vec::new();
        collect(&base, &self.root, &mut out)
            .map_err(|e| Error::failed(format!("cannot list {}: {e}", base.display())))?;
        out.sort();
        Ok(out)
    }

    fn read(&self, id: &PathId) -> Result<Vec<u8>> {
        let path = self.resolve(id)?;
        std::fs::read(&path).map_err(|e| Error::failed(format!("cannot read {id}: {e}")))
    }

    fn write(&self, id: &PathId, bytes: &[u8]) -> Result<()> {
        let path = self.resolve(id)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::failed(format!("cannot create {}: {e}", parent.display())))?;
        }
        let tmp = path.with_file_name(format!(
            ".{}.yzs-{}",
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

fn collect(dir: &Path, root: &Path, out: &mut Vec<PathId>) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect(&path, root, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("env") {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(PathId::new(rel.to_string_lossy().replace('\\', "/")));
            }
        }
    }
    Ok(())
}
