//! Tool and OS bindings for Lockset.
//!
//! The core knows nothing about these; each module here is one adapter:
//! filesystem (`FsRepo`), the sops CLI (`SopsCodec`), credential custody
//! (`Custody`: env, file, OS keyring, memory), and child-process environment
//! hygiene (`env`).
//!
//! # Example
//!
//! Adapters read what they are given and nothing else, which is what makes a
//! test or an action able to substitute them.
//!
//! ```
//! use lockset_core::{Custody, CustodyKind, PathId, Repo};
//! use lockset_tools::custody::EnvCustody;
//! use lockset_tools::fs_repo::FsRepo;
//!
//! let dir = std::env::temp_dir().join(format!("lockset-tools-doc-{}", std::process::id()));
//! std::fs::create_dir_all(dir.join("secrets")).unwrap();
//! std::fs::write(dir.join("secrets/dev.env"), "TOKEN=1\n").unwrap();
//!
//! let repo = FsRepo::new(&dir);
//! let payloads = repo.list(&PathId::parse("secrets")?)?;
//! assert_eq!(payloads[0].as_str(), "secrets/dev.env");
//!
//! let custody = EnvCustody::new("LOCKSET_AGE_KEY");
//! assert_eq!(custody.kind(), CustodyKind::Env);
//!
//! std::fs::remove_dir_all(&dir).ok();
//! # Ok::<(), lockset_core::Error>(())
//! ```

pub mod custody;
pub mod env;
pub mod fs_repo;
pub mod lock;
pub mod sops;
