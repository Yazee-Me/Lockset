//! Content digests for change detection between a snapshot and an apply.

use std::fmt::Write;

use sha2::{Digest, Sha256};

/// A digest of file bytes. It is not a security boundary: it detects an input
/// that changed between building a plan and applying it.
pub fn digest(bytes: &[u8]) -> String {
    let sum = Sha256::digest(bytes);
    let mut text = String::with_capacity(sum.len() * 2);
    for byte in sum {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_follows_the_bytes() {
        assert_eq!(digest(b""), digest(b""));
        assert_ne!(digest(b"a"), digest(b"b"));
        assert_eq!(digest(b"a").len(), 64);
    }
}
