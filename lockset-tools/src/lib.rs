//! Tool and OS bindings for Lockset.
//!
//! The core knows nothing about these; each module here is one adapter:
//! filesystem (`FsRepo`), the sops CLI (`SopsCodec`), credential custody
//! (`Custody`: env, file, OS keyring, memory), and child-process environment
//! hygiene (`env`).

pub mod custody;
pub mod env;
pub mod fs_repo;
pub mod sops;
