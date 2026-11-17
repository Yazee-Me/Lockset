//! The sops version this crate is written against, parsed as data so a
//! repository can require a different minimum through `lockset.toml`.

use std::fmt;

/// The oldest sops this crate is written against, when nothing configures one.
pub const MIN_VERSION: Version = Version {
    major: 3,
    minor: 13,
    patch: 0,
};

/// A parsed `sops --version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Version {
    /// Parse a `major.minor[.patch]` string, as `codec.min_version` holds one.
    pub fn parse(text: &str) -> Option<Version> {
        let mut parts = text.trim().split('.');
        let (Some(major), Some(minor)) = (parts.next(), parts.next()) else {
            return None;
        };
        let (Ok(major), Ok(minor)) = (major.parse(), minor.parse()) else {
            return None;
        };
        let patch = match parts.next() {
            Some(patch) => patch.parse().ok()?,
            None => 0,
        };
        if parts.next().is_some() {
            return None;
        }
        Some(Version {
            major,
            minor,
            patch,
        })
    }
}

/// The first `major.minor[.patch]` token in `sops --version` output.
pub fn parse_version(text: &str) -> Option<Version> {
    for word in text.split_whitespace() {
        let word = word.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
        if let Some(version) = Version::parse(word) {
            return Some(version);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_version_string_parses_and_round_trips() {
        assert_eq!(
            Version::parse("3.13"),
            Some(Version {
                major: 3,
                minor: 13,
                patch: 0
            })
        );
        assert_eq!(
            Version::parse("3.14.2").map(|v| v.to_string()),
            Some("3.14.2".into())
        );
        assert_eq!(Version::parse("3"), None);
        assert_eq!(Version::parse("3.13.0.1"), None);
        assert_eq!(Version::parse("three.thirteen"), None);
    }

    #[test]
    fn the_version_is_found_inside_sops_output() {
        assert_eq!(
            parse_version("sops 3.13.3 (latest)").map(|v| v.to_string()),
            Some("3.13.3".into())
        );
        assert_eq!(parse_version("no version here"), None);
    }

    #[test]
    fn ordering_compares_each_component() {
        assert!(Version::parse("3.13.9") < Version::parse("3.14.0"));
        assert!(Version::parse("3.13.0") > Version::parse("3.12.9"));
    }
}
