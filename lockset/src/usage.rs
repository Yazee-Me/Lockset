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

/// The contract, also printed by `--help` and documented in the README:
///
/// | code | meaning |
/// | --- | --- |
/// | 0 | ok |
/// | 1 | findings (a failed check, a strict status finding, or a runtime failure) |
/// | 2 | usage or configuration |
/// | 3 | custody or authentication |
/// | 4 | external tool (sops) |
/// | 5 | conflict or lock |
/// | 6 | partial apply |
pub fn exit_code(error: &anyhow::Error) -> u8 {
    if error.downcast_ref::<Usage>().is_some() {
        return 2;
    }
    match error.downcast_ref::<lockset_core::Error>() {
        Some(lockset_core::Error::Custody(_)) => 3,
        Some(lockset_core::Error::Tool(_)) => 4,
        Some(lockset_core::Error::Conflict(_)) => 5,
        Some(lockset_core::Error::Partial(_)) => 6,
        Some(lockset_core::Error::Invalid(_) | lockset_core::Error::Refused(_)) => 2,
        _ => 1,
    }
}

/// The contract as the CLI prints it in `--help`.
pub const HELP: &str = "Exit codes:
  0  ok
  1  findings (failed check, strict status finding, runtime failure)
  2  usage or configuration
  3  custody or authentication
  4  external tool (sops)
  5  conflict or lock
  6  partial apply";

#[cfg(test)]
mod tests {
    use super::*;

    fn core(error: lockset_core::Error) -> u8 {
        exit_code(&anyhow::Error::from(error))
    }

    #[test]
    fn every_error_class_has_its_documented_code() {
        // 1: findings and the runtime catch-all.
        assert_eq!(exit_code(&anyhow::anyhow!("plain failure")), 1);
        assert_eq!(core(lockset_core::Error::failed("disk full")), 1);

        // 2: usage and configuration.
        assert_eq!(exit_code(&error("bad argument")), 2);
        assert_eq!(core(lockset_core::Error::invalid("bad label")), 2);
        assert_eq!(
            core(lockset_core::Error::refused("would empty the rule")),
            2
        );

        // 3: custody and authentication.
        assert_eq!(core(lockset_core::Error::custody("no identity")), 3);

        // 4: the external tool.
        assert_eq!(core(lockset_core::Error::tool("sops failed")), 4);

        // 5: conflict or lock.
        assert_eq!(
            core(lockset_core::Error::conflict(
                "another process holds the lock"
            )),
            5
        );

        // 6: partial apply.
        assert_eq!(core(lockset_core::Error::partial("stopped part-way")), 6);
    }
}
