use std::fmt;
use std::str::FromStr;

use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

use crate::{Error, Result};

/// A recipient label, as recorded in the trailing comment of an `age:` line.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Label(String);

impl Label {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let starts_digit = s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(true);
        let valid = !s.is_empty()
            && !starts_digit
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
        if !valid {
            return Err(Error::invalid(format!(
                "invalid label '{s}': lowercase letters, digits, '-' or '_', not starting with a digit"
            )));
        }
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_reserved(&self) -> bool {
        matches!(self.as_str(), "admin" | "recovery" | "ci")
    }

    /// Identities that must never be installed on a machine.
    pub fn is_offmachine(&self) -> bool {
        matches!(self.as_str(), "recovery" | "ci")
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Label {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// An age public key, exactly as it appears in `.sops.yaml` and the payload metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct PubKey(String);

impl PubKey {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if !s.starts_with("age1") || s.len() < 50 || !s.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(Error::invalid(format!(
                "not an age public key: '{}'",
                truncate(s)
            )));
        }
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for PubKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// A private age identity. Never printed, never serialized, zeroized on drop.
pub struct SecretKey(SecretString);

impl SecretKey {
    /// Parse a pasted blob: an `age-keygen` file (comments and all), a key
    /// wrapped in the recovery banner, or a bare key line. Exactly one key is
    /// accepted; anything else is an error that never quotes the input.
    pub fn from_text(text: &str) -> Result<Self> {
        let mut found: Vec<&str> = Vec::new();
        for line in text.lines() {
            let line = line.trim().trim_matches('"').trim_matches('\'');
            if line.starts_with("AGE-SECRET-KEY-1") {
                found.push(line);
            } else if line.starts_with("AGE-PLUGIN-") {
                return Err(Error::invalid(
                    "this is a plugin identity (AGE-PLUGIN-); plugin-backed keys are not supported yet",
                ));
            }
        }
        match found.len() {
            0 => Err(Error::invalid(
                "no AGE-SECRET-KEY-1... identity found in the input",
            )),
            1 => Self::from_value(found[0]),
            n => Err(Error::invalid(format!(
                "found {n} age identities in the input; pass exactly one"
            ))),
        }
    }

    pub fn from_value(value: &str) -> Result<Self> {
        let identity = parse_identity(value)?;
        let canonical = identity.to_string();
        Ok(Self(SecretString::from(
            canonical.expose_secret().to_owned(),
        )))
    }

    pub fn generate() -> Self {
        let identity = age::x25519::Identity::generate();
        Self(SecretString::from(
            identity.to_string().expose_secret().to_owned(),
        ))
    }

    pub fn public(&self) -> Result<PubKey> {
        let identity = parse_identity(self.0.expose_secret())?;
        PubKey::parse(&identity.to_public().to_string())
    }

    /// Only for handing the key to a trusted child process.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

fn parse_identity(value: &str) -> Result<age::x25519::Identity> {
    value
        .trim()
        .parse::<age::x25519::Identity>()
        .map_err(|_| Error::invalid("not a valid age identity"))
}

fn truncate(s: &str) -> String {
    if s.len() <= 16 {
        s.to_owned()
    } else {
        format!("{}…", &s[..16])
    }
}

/// A path relative to the repository root: a payload or `.sops.yaml`.
///
/// `parse` is the only constructor, so every `Repo` and `Codec` call receives a
/// path that stays inside the repository and that an external tool cannot read
/// as an option.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct PathId(String);

impl PathId {
    /// Reject anything that could leave the repository or change how a child
    /// process reads the argument: an absolute path, an empty or `..` segment,
    /// a backslash, or a leading `-`.
    pub fn parse(s: &str) -> Result<Self> {
        let why = if s.is_empty() {
            Some("the path is empty")
        } else if s.starts_with('/') {
            Some("the path is absolute")
        } else if s.contains('\\') {
            Some("backslashes are not separators here")
        } else if s.starts_with('-') {
            Some("a leading '-' reads as an option")
        } else if s.split('/').any(str::is_empty) {
            Some("it has an empty segment")
        } else if s.split('/').any(|segment| segment == "..") {
            Some("'..' leaves the repository")
        } else {
            None
        };
        match why {
            Some(why) => Err(Error::invalid(format!("invalid path '{s}': {why}"))),
            None => Ok(Self(s.to_owned())),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PathId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CustodyKind {
    Keyring,
    Env,
    File,
    Memory,
    /// No identity source is configured and the run is not interactive.
    None,
}

impl fmt::Display for CustodyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CustodyKind::Keyring => "keyring",
            CustodyKind::Env => "env",
            CustodyKind::File => "file",
            CustodyKind::Memory => "memory",
            CustodyKind::None => "none",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_ids_reject_paths_that_leave_the_repository_or_read_as_options() {
        for value in [
            "",
            "../key.txt",
            "secrets/../../key.txt",
            "secrets/../key.txt",
            "/etc/passwd",
            "secrets//dev.env",
            "secrets/",
            "secrets\\dev.env",
            "-x",
        ] {
            let error = PathId::parse(value).expect_err(value);
            assert!(
                error.to_string().contains(value),
                "the error must name the offending value: {error}"
            );
        }
    }

    #[test]
    fn path_ids_accept_repository_relative_paths() {
        for value in [
            ".sops.yaml",
            "secrets/dev.env",
            "secrets/prod/host-main.env",
        ] {
            assert_eq!(PathId::parse(value).unwrap().as_str(), value);
        }
    }

    #[test]
    fn label_rules() {
        assert!(Label::parse("admin").is_ok());
        assert!(Label::parse("dev-jack").is_ok());
        assert!(Label::parse("Admin").is_err());
        assert!(Label::parse("2fa").is_err());
        assert!(Label::parse("").is_err());
    }

    #[test]
    fn pubkey_rules() {
        assert!(
            PubKey::parse("age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x").is_ok()
        );
        assert!(PubKey::parse("age1short").is_err());
        assert!(PubKey::parse("ssh-ed25519 AAAA").is_err());
    }

    #[test]
    fn key_from_generated_roundtrip() {
        let key = SecretKey::generate();
        let public = key.public().unwrap();
        assert!(public.as_str().starts_with("age1"));
        let again = SecretKey::from_text(key.expose()).unwrap();
        assert_eq!(again.public().unwrap(), public);
    }

    #[test]
    fn key_from_age_keygen_file() {
        let key = SecretKey::generate();
        let file = format!(
            "# created: 2026-10-27T00:00:00Z\n# public key: {}\n{}\n",
            key.public().unwrap(),
            key.expose()
        );
        let parsed = SecretKey::from_text(&file).unwrap();
        assert_eq!(parsed.public().unwrap(), key.public().unwrap());
    }

    #[test]
    fn key_from_banner() {
        let key = SecretKey::generate();
        let text = format!(
            "----- recovery private key: custody is yours -----\n{}\n----- end -----\n",
            key.expose()
        );
        assert_eq!(
            SecretKey::from_text(&text).unwrap().public().unwrap(),
            key.public().unwrap()
        );
    }

    #[test]
    fn rejects_ambiguity_and_empty() {
        let a = SecretKey::generate();
        let b = SecretKey::generate();
        let text = format!("{}\n{}", a.expose(), b.expose());
        assert!(SecretKey::from_text(&text).is_err());
        assert!(SecretKey::from_text("nothing here").is_err());
        assert!(SecretKey::from_text("").is_err());
    }
}
