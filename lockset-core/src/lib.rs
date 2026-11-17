//! Tool- and OS-agnostic model for repository secrets.
//!
//! Nothing in this crate spawns a process, reads the environment, touches the
//! filesystem, or branches on the target OS. Every external capability is a
//! port (`Codec`, `Custody`, `Repo`) implemented by another crate.

pub mod dotenv;
pub mod error;
pub mod exec;
pub mod meta;
pub mod model;
pub mod ops;
pub mod plan;
pub mod ports;
pub mod snapshot;
pub mod sopsfile;

pub use error::{Error, Result};
pub use model::{CustodyKind, Label, PathId, PubKey, SecretKey};
pub use plan::{Change, Plan, SecretValue};
pub use ports::{Codec, Custody, Repo};
pub use snapshot::{IdentityView, Snapshot};
