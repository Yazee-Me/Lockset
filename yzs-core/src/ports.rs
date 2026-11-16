use crate::model::{CustodyKind, PathId, SecretKey};
use crate::Result;

/// Payload cryptography. The only component that knows the on-disk format.
pub trait Codec {
    fn decrypt(&self, id: &PathId, key: &SecretKey) -> Result<Vec<u8>>;
    /// Re-wrap the data key for the current recipients (sops `updatekeys`).
    fn rewrap(&self, id: &PathId, key: &SecretKey) -> Result<()>;
    /// New data key, values re-encrypted (sops `rotate`).
    fn rekey(&self, id: &PathId, key: &SecretKey) -> Result<()>;
    /// Set one value and re-encrypt; every other value must survive untouched.
    fn set_value(&self, id: &PathId, name: &str, value: &str, key: &SecretKey) -> Result<()>;
}

/// Where the local private key lives. No OS API in this trait.
pub trait Custody {
    fn get(&self) -> Result<Option<SecretKey>>;
    fn set(&self, key: &SecretKey) -> Result<()>;
    fn forget(&self) -> Result<()>;
    fn kind(&self) -> CustodyKind;
}

/// Repository artifacts: payloads and `.sops.yaml`, addressed by relative path.
pub trait Repo {
    fn list(&self, prefix: &str) -> Result<Vec<PathId>>;
    fn read(&self, id: &PathId) -> Result<Vec<u8>>;
    fn write(&self, id: &PathId, bytes: &[u8]) -> Result<()>;
}
