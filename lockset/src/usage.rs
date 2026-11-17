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

pub fn exit_code(error: &anyhow::Error) -> u8 {
    if error.downcast_ref::<Usage>().is_some() {
        2
    } else {
        1
    }
}
