//! Tool and OS bindings for Lockset.
//!
//! The core knows nothing about these; each module here is one adapter:
//! filesystem (`FsRepo`), the sops CLI (`SopsCodec`), and credential custody
//! (`Custody`: env, file, OS keyring, memory).

pub mod custody;
pub mod fs_repo;
pub mod sops;
