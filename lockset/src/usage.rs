//! The usage/config error the CLI reports with exit 2.

use std::fmt;

/// A bad argument or repository value. It maps to the CLI's usage/config exit
/// code and is always raised before a codec or repo call.
#[derive(Debug)]
pub struct Usage(String);

impl fmt::Display for Usage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Usage {}

pub fn error(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Usage(message.into()))
}

/// 2 for a bad invocation, 5 for a conflict, 6 when a mutation stopped
/// part-way, 1 otherwise.
pub fn exit_code(error: &anyhow::Error) -> u8 {
    if error.downcast_ref::<Usage>().is_some() {
        return 2;
    }
    match error.downcast_ref::<lockset_core::Error>() {
        Some(lockset_core::Error::Conflict(_)) => 5,
        Some(lockset_core::Error::Partial(_)) => 6,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_separate_usage_failure_and_partial_apply() {
        assert_eq!(exit_code(&error("bad argument")), 2);
        assert_eq!(exit_code(&anyhow::anyhow!("plain failure")), 1);
        assert_eq!(
            exit_code(&anyhow::Error::from(lockset_core::Error::conflict(
                "another process holds the lock"
            ))),
            5
        );
        assert_eq!(
            exit_code(&anyhow::Error::from(lockset_core::Error::partial(
                "stopped part-way"
            ))),
            6
        );
    }
}
