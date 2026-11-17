use std::collections::BTreeSet;
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
        let mut seen = BTreeSet::new();
        collect(&base, &self.root, &mut seen, &mut out)?;
        out.sort();
        Ok(out)
    }

    fn read(&self, id: &PathId) -> Result<Vec<u8>> {
        let path = self.resolve(id);
        std::fs::read(&path).map_err(|e| Error::failed(format!("cannot read {id}: {e}")))
    }

    fn write(&self, id: &PathId, bytes: &[u8]) -> Result<()> {
        use std::io::Write;

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
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Created private, so a rewrite never widens the mode of a secret.
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .map_err(|e| Error::failed(format!("cannot write {}: {e}", tmp.display())))?;
        file.write_all(bytes)
            .map_err(|e| Error::failed(format!("cannot write {}: {e}", tmp.display())))?;
        // The bytes must be on disk before the rename can be observed.
        file.sync_all()
            .map_err(|e| Error::failed(format!("cannot flush {}: {e}", tmp.display())))?;
        drop(file);
        std::fs::rename(&tmp, &path)
            .map_err(|e| Error::failed(format!("cannot replace {id}: {e}")))?;
        // The rename itself must be durable as well.
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(|e| Error::failed(format!("cannot flush {}: {e}", parent.display())))?;
        }
        Ok(())
    }
}

/// Hidden files (`.gitkeep`, editor temporaries) are not payloads; everything
/// else under the payload directory is listed, so an unsupported payload is
/// reported rather than silently skipped.
fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with('.'))
}

/// Discover payload files without following symlinks: a symlink can duplicate
/// a payload or loop the tree, so it is skipped. Canonical paths are deduped so
/// no payload is reported twice.
fn collect(
    dir: &Path,
    root: &Path,
    seen: &mut BTreeSet<PathBuf>,
    out: &mut Vec<PathId>,
) -> Result<()> {
    // `symlink_metadata` does not follow the prefix either, so a symlinked
    // `secrets` directory is skipped instead of being walked twice.
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(Error::failed(format!(
                "cannot inspect {}: {error}",
                dir.display()
            )))
        }
    }
    let entries = std::fs::read_dir(dir)
        .map_err(|e| Error::failed(format!("cannot list {}: {e}", dir.display())))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| Error::failed(format!("cannot list {}: {e}", dir.display())))?;
        let file_type = entry.file_type().map_err(|error| {
            Error::failed(format!(
                "cannot inspect {}: {error}",
                entry.path().display()
            ))
        })?;
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            collect(&path, root, seen, out)?;
        } else if file_type.is_file() && !is_hidden(&path) {
            let canonical = path.canonicalize().map_err(|error| {
                Error::failed(format!("cannot resolve {}: {error}", path.display()))
            })?;
            if !seen.insert(canonical) {
                continue;
            }
            let rel = path.strip_prefix(root).map_err(|_| {
                Error::failed(format!("{} is outside the repository", path.display()))
            })?;
            let rel = rel.to_string_lossy().replace('\\', "/");
            out.push(PathId::parse(&rel)?);
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("lockset-fs-repo-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("secrets/sub")).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ids(repo: &FsRepo) -> Vec<String> {
        repo.list(&PathId::parse("secrets").unwrap())
            .unwrap()
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect()
    }

    #[test]
    fn listing_skips_symlinks_and_never_duplicates_a_payload() {
        let root = TempDir::new("symlinks");
        std::fs::write(root.0.join("secrets/a.env"), "A=1\n").unwrap();
        std::fs::write(root.0.join("secrets/sub/b.env"), "B=1\n").unwrap();
        // A symlinked file would duplicate a.env; a symlinked directory would
        // duplicate sub; a self-referential symlink would loop the tree.
        symlink(
            root.0.join("secrets/a.env"),
            root.0.join("secrets/link.env"),
        )
        .unwrap();
        symlink(root.0.join("secrets/sub"), root.0.join("secrets/alias")).unwrap();
        symlink("../..", root.0.join("secrets/sub/loop")).unwrap();

        let repo = FsRepo::new(&root.0);

        assert_eq!(ids(&repo), ["secrets/a.env", "secrets/sub/b.env"]);
    }

    #[test]
    fn listing_includes_unsupported_files_and_skips_hidden_ones() {
        let root = TempDir::new("formats");
        std::fs::write(root.0.join("secrets/a.env"), "A=1\n").unwrap();
        std::fs::write(root.0.join("secrets/config.yaml"), "A: 1\n").unwrap();
        std::fs::write(root.0.join("secrets/.gitkeep"), "").unwrap();

        assert_eq!(
            ids(&FsRepo::new(&root.0)),
            ["secrets/a.env", "secrets/config.yaml"]
        );
    }

    #[test]
    fn a_symlinked_prefix_is_not_followed() {
        let root = TempDir::new("prefix");
        std::fs::write(root.0.join("secrets/a.env"), "A=1\n").unwrap();
        std::fs::create_dir_all(root.0.join("real")).unwrap();
        std::fs::write(root.0.join("real/b.env"), "B=1\n").unwrap();
        symlink(root.0.join("real"), root.0.join("linked")).unwrap();

        let repo = FsRepo::new(&root.0);

        assert!(repo
            .list(&PathId::parse("linked").unwrap())
            .unwrap()
            .is_empty());
    }
}
