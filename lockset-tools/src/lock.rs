//! An advisory lock that serializes repository mutations across processes.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use lockset_core::{Error, Result};

/// The repository mutation lock: a file only one lockset process may hold.
/// Dropping it releases the lock.
#[derive(Debug)]
pub struct Lock {
    path: PathBuf,
}

impl Lock {
    /// Take the lock, waiting up to `timeout` for the current holder to finish.
    /// A timeout is a conflict: nothing was changed and the command can be
    /// retried.
    pub fn acquire(root: &Path, timeout: Duration) -> Result<Self> {
        let path = lock_path(root)?;
        let deadline = Instant::now() + timeout;
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    let _ = writeln!(file, "pid {}", std::process::id());
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if Instant::now() >= deadline {
                        return Err(Error::conflict(format!(
                            "another lockset is changing this repository ({}); waited {}s. \
                             If no other process is running, remove that file",
                            path.display(),
                            timeout.as_secs()
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => {
                    return Err(Error::failed(format!(
                        "cannot take the repository lock {}: {error}",
                        path.display()
                    )))
                }
            }
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// `.git/lockset.lock` when there is a git directory (following the `gitdir:`
/// pointer of a worktree), otherwise `.lockset.lock` at the root.
fn lock_path(root: &Path) -> Result<PathBuf> {
    let dotgit = root.join(".git");
    if dotgit.is_dir() {
        return Ok(dotgit.join("lockset.lock"));
    }
    if dotgit.is_file() {
        let text = std::fs::read_to_string(&dotgit)
            .map_err(|error| Error::failed(format!("cannot read {}: {error}", dotgit.display())))?;
        if let Some(dir) = text
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("gitdir:"))
        {
            let dir = Path::new(dir.trim());
            let dir = if dir.is_absolute() {
                dir.to_path_buf()
            } else {
                root.join(dir)
            };
            if dir.is_dir() {
                return Ok(dir.join("lockset.lock"));
            }
        }
    }
    Ok(root.join(".lockset.lock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("lockset-lock-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_held_lock_makes_the_next_one_a_conflict() {
        let root = TempDir::new("held");
        let _held = Lock::acquire(&root.0, Duration::ZERO).unwrap();

        let error = Lock::acquire(&root.0, Duration::from_millis(30)).unwrap_err();

        assert!(matches!(error, Error::Conflict(_)), "{error:?}");
        assert!(error.to_string().contains("another lockset"), "{error}");
        assert!(root.0.join(".lockset.lock").exists());
    }

    #[test]
    fn releasing_the_lock_lets_the_next_process_in() {
        let root = TempDir::new("released");
        {
            let _held = Lock::acquire(&root.0, Duration::ZERO).unwrap();
        }

        let again = Lock::acquire(&root.0, Duration::from_millis(50));

        assert!(again.is_ok(), "{:?}", again.err());
    }

    #[test]
    fn a_git_directory_holds_the_lock_outside_the_worktree() {
        let root = TempDir::new("git");
        std::fs::create_dir_all(root.0.join(".git")).unwrap();

        let _held = Lock::acquire(&root.0, Duration::ZERO).unwrap();

        assert!(root.0.join(".git/lockset.lock").exists());
        assert!(!root.0.join(".lockset.lock").exists());
    }
}
