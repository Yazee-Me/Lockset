//! `lockset.toml`: the repository's conventions as data. Parsed from text, so
//! this module never reads a file; the CLI decides which file to parse.
//!
//! Precedence, highest first, is flags, environment, this file, then the
//! defaults below. Every field is optional: a repository without the file gets
//! the defaults, and a default payload is never invented — `run` and `set` ask
//! for one instead.

use serde::Deserialize;

use crate::meta::require_dotenv;
use crate::model::{Label, PathId};
use crate::version::{parse_version, Version, MIN_VERSION};
use crate::{Error, Result};

/// The sops config file a repository uses when nothing configures one.
pub const DEFAULT_SOPS_CONFIG: &str = ".sops.yaml";

/// The payload patterns a repository discovers when nothing configures them:
/// every non-hidden file under `secrets/`, so an unsupported format is
/// reported instead of silently skipped.
pub const DEFAULT_PAYLOAD_GLOBS: &[&str] = &["secrets/**/*"];

/// The label that must open every payload, when nothing configures one.
pub const DEFAULT_ADMIN_LABEL: &str = "admin";

/// The prefix a person's label suggests, when nothing configures one.
pub const DEFAULT_PERSON_PREFIX: &str = "dev-";

/// The environment variable holding the identity, by default.
pub const DEFAULT_KEY_ENV: &str = "LOCKSET_AGE_KEY";

/// The keychain item the identity lives in, by default.
pub const DEFAULT_KEYCHAIN_ITEM: &str = "lockset-age-key";

/// The sops binary a repository runs, by default.
pub const DEFAULT_SOPS_BIN: &str = "sops";

/// A parsed, validated `lockset.toml`.
#[derive(Debug, Clone)]
pub struct Config {
    /// The sops config file, repo-relative.
    pub sops_config: PathId,
    /// Which files are payloads, matched against repo-relative paths.
    pub payload_globs: Globs,
    /// The payloads `run` and `set` fall back to; empty means "ask".
    pub default_payloads: Vec<PathId>,
    pub labels: Labels,
    pub custody: CustodyConfig,
    pub codec: CodecConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sops_config: PathId::parse(DEFAULT_SOPS_CONFIG)
                .expect("the default sops config path is valid"),
            payload_globs: Globs::default(),
            default_payloads: Vec::new(),
            labels: Labels::default(),
            custody: CustodyConfig::default(),
            codec: CodecConfig::default(),
        }
    }
}

impl Config {
    /// Parse and validate the file. Every error names the field, so a typo is
    /// actionable and exits 2.
    pub fn parse(text: &str) -> Result<Self> {
        let raw: Raw = toml::from_str(text)
            .map_err(|error| Error::invalid(format!("not valid TOML: {error}")))?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: Raw) -> Result<Self> {
        let default = Config::default();

        let sops_config = match raw.repo.sops_config {
            Some(value) => path("repo.sops_config", &value)?,
            None => default.sops_config,
        };

        let payload_globs = match raw.repo.payload_globs {
            Some(patterns) => Globs::new(&patterns)?,
            None => default.payload_globs,
        };

        let default_payloads = match raw.repo.default_payloads {
            Some(values) => values
                .iter()
                .map(|value| {
                    let id = path("repo.default_payloads", value)?;
                    require_dotenv(&id).map_err(|error| {
                        Error::invalid(format!("repo.default_payloads: {error}"))
                    })?;
                    Ok(id)
                })
                .collect::<Result<Vec<_>>>()?,
            None => Vec::new(),
        };

        let labels = match raw.labels.admin {
            Some(value) => Labels {
                admin: Label::parse(&value)
                    .map_err(|error| Error::invalid(format!("labels.admin: {error}")))?,
                ..Labels::default()
            },
            None => Labels::default(),
        };
        let labels = match raw.labels.person_prefix {
            Some(prefix) => Labels {
                person_prefix: validated_prefix(&prefix)?,
                ..labels
            },
            None => labels,
        };

        let mut custody = CustodyConfig::default();
        if let Some(kind) = raw.custody.kind {
            custody.kind = validated_kind(&kind)?;
        }
        if let Some(env) = raw.custody.env {
            custody.env = non_empty("custody.env", &env)?.to_owned();
        }
        if let Some(item) = raw.custody.keychain_item {
            custody.keychain_item = non_empty("custody.keychain_item", &item)?.to_owned();
        }

        let mut codec = CodecConfig::default();
        if let Some(bin) = raw.codec.sops {
            codec.sops = non_empty("codec.sops", &bin)?.to_owned();
        }
        if let Some(text) = raw.codec.min_version {
            codec.min_version = parse_version(&text).ok_or_else(|| {
                Error::invalid(format!(
                    "codec.min_version: '{text}' is not a version like 3.13.0"
                ))
            })?;
        }

        Ok(Self {
            sops_config,
            payload_globs,
            default_payloads,
            labels,
            custody,
            codec,
        })
    }

    /// Whether this repository names at least one default payload.
    pub fn has_default_payloads(&self) -> bool {
        !self.default_payloads.is_empty()
    }
}

/// Label conventions the model itself consults (the admin coverage check).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Labels {
    /// The label that must open every payload.
    pub admin: Label,
    /// The prefix a person's label gets (`dev-<name>`).
    pub person_prefix: String,
}

impl Default for Labels {
    fn default() -> Self {
        Self {
            admin: Label::parse(DEFAULT_ADMIN_LABEL).expect("the default admin label is valid"),
            person_prefix: DEFAULT_PERSON_PREFIX.to_owned(),
        }
    }
}

/// Where the identity comes from when no flag and no environment select it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyConfig {
    /// `auto`, `env`, `keyring`, `file:<path>`, or `none`.
    pub kind: String,
    /// The variable `env` custody reads.
    pub env: String,
    /// The keychain item `keyring` custody reads.
    pub keychain_item: String,
}

impl Default for CustodyConfig {
    fn default() -> Self {
        Self {
            kind: "auto".to_owned(),
            env: DEFAULT_KEY_ENV.to_owned(),
            keychain_item: DEFAULT_KEYCHAIN_ITEM.to_owned(),
        }
    }
}

/// How the codec runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecConfig {
    /// The sops binary; `--sops` and `LOCKSET_SOPS` still win.
    pub sops: String,
    /// The oldest sops accepted by the preflight.
    pub min_version: Version,
}

impl Default for CodecConfig {
    fn default() -> Self {
        Self {
            sops: DEFAULT_SOPS_BIN.to_owned(),
            min_version: MIN_VERSION,
        }
    }
}

/// Repo-relative globs: `*` and `?` stop at `/`, `**/` spans any number of
/// directories (none included), and a bare `**` spans the rest of the path.
#[derive(Debug, Clone)]
pub struct Globs {
    patterns: Vec<regex::Regex>,
}

impl Default for Globs {
    fn default() -> Self {
        Self {
            patterns: DEFAULT_PAYLOAD_GLOBS
                .iter()
                .map(|glob| compile(glob).expect("the default glob is valid"))
                .collect(),
        }
    }
}

impl Globs {
    pub fn new(patterns: &[String]) -> Result<Self> {
        if patterns.is_empty() {
            return Err(Error::invalid(
                "repo.payload_globs: name at least one pattern, or omit the field for the default",
            ));
        }
        let patterns = patterns
            .iter()
            .enumerate()
            .map(|(index, glob)| {
                compile(glob).map_err(|error| {
                    Error::invalid(format!("repo.payload_globs[{index}]: {error}"))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { patterns })
    }

    pub fn matches(&self, path: &str) -> bool {
        self.patterns.iter().any(|pattern| pattern.is_match(path))
    }
}

fn compile(glob: &str) -> Result<regex::Regex> {
    if glob.trim().is_empty() {
        return Err(Error::invalid("empty pattern"));
    }
    if glob.starts_with('/') || glob.contains('\\') {
        return Err(Error::invalid(format!(
            "'{glob}' must be repo-relative with forward slashes"
        )));
    }
    if glob.split('/').any(|segment| segment == "..") {
        return Err(Error::invalid(format!(
            "'{glob}' must not leave the repository"
        )));
    }
    let mut out = String::from("^");
    let chars: Vec<char> = glob.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' if chars.get(i + 1) == Some(&'*') => {
                if chars.get(i + 2) == Some(&'/') {
                    out.push_str("(?:[^/]+/)*");
                    i += 3;
                } else {
                    out.push_str(".*");
                    i += 2;
                }
            }
            '*' => {
                out.push_str("[^/]*");
                i += 1;
            }
            '?' => {
                out.push_str("[^/]");
                i += 1;
            }
            other => {
                out.push_str(&regex::escape(&other.to_string()));
                i += 1;
            }
        }
    }
    out.push('$');
    regex::Regex::new(&out)
        .map_err(|error| Error::invalid(format!("'{glob}' is not a valid glob: {error}")))
}

fn path(field: &str, value: &str) -> Result<PathId> {
    PathId::parse(value).map_err(|error| Error::invalid(format!("{field}: {error}")))
}

fn non_empty<'a>(field: &str, value: &'a str) -> Result<&'a str> {
    if value.trim().is_empty() {
        return Err(Error::invalid(format!("{field} cannot be empty")));
    }
    Ok(value)
}

fn validated_prefix(prefix: &str) -> Result<String> {
    let prefix = non_empty("labels.person_prefix", prefix)?;
    // The prefix is joined with a name, so it must be a label fragment.
    if !prefix
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        || !prefix.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err(Error::invalid(format!(
            "labels.person_prefix: '{prefix}' must be lowercase letters, digits, and dashes"
        )));
    }
    Ok(prefix.to_owned())
}

fn validated_kind(kind: &str) -> Result<String> {
    let known = matches!(kind, "auto" | "none" | "env" | "keyring")
        || kind.starts_with("keyring:")
        || kind.starts_with("file:");
    if !known {
        return Err(Error::invalid(format!(
            "custody.kind: '{kind}' is not one of auto, env, keyring, keyring:<service>, file:<path>, none"
        )));
    }
    Ok(kind.to_owned())
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    #[serde(default)]
    repo: RawRepo,
    #[serde(default)]
    labels: RawLabels,
    #[serde(default)]
    custody: RawCustody,
    #[serde(default)]
    codec: RawCodec,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRepo {
    sops_config: Option<String>,
    payload_globs: Option<Vec<String>>,
    default_payloads: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLabels {
    admin: Option<String>,
    person_prefix: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCustody {
    kind: Option<String>,
    env: Option<String>,
    keychain_item: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCodec {
    sops: Option<String>,
    min_version: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_file_is_the_documented_defaults() {
        let config = Config::parse("").unwrap();

        assert_eq!(config.sops_config.as_str(), ".sops.yaml");
        assert!(config.payload_globs.matches("secrets/prod/infra.env"));
        assert!(config.payload_globs.matches("secrets/a.env"));
        assert!(!config.payload_globs.matches("conf/a.env"));
        assert!(!config.payload_globs.matches(".sops.yaml"));
        assert!(config.default_payloads.is_empty());
        assert!(!config.has_default_payloads());
        assert_eq!(config.labels.admin.as_str(), "admin");
        assert_eq!(config.labels.person_prefix, "dev-");
        assert_eq!(config.custody.kind, "auto");
        assert_eq!(config.custody.env, "LOCKSET_AGE_KEY");
        assert_eq!(config.custody.keychain_item, "lockset-age-key");
        assert_eq!(config.codec.sops, "sops");
        assert_eq!(config.codec.min_version, MIN_VERSION);
    }

    #[test]
    fn every_field_is_read() {
        let config = Config::parse(
            r#"
[repo]
sops_config = "sops/settings.yaml"
payload_globs = ["conf/**/*.env", "secrets/*.env"]
default_payloads = ["conf/dev.env", "secrets/dev.env"]

[labels]
admin = "ops"
person_prefix = "person-"

[custody]
kind = "file:/run/secrets/age-key"
env = "MY_AGE_KEY"
keychain_item = "my-item"

[codec]
sops = "/usr/local/bin/sops"
min_version = "3.14.0"
"#,
        )
        .unwrap();

        assert_eq!(config.sops_config.as_str(), "sops/settings.yaml");
        assert!(config.payload_globs.matches("conf/nested/dev.env"));
        assert!(config.payload_globs.matches("secrets/dev.env"));
        assert!(!config.payload_globs.matches("secrets/nested/dev.env"));
        assert_eq!(config.default_payloads.len(), 2);
        assert_eq!(config.labels.admin.as_str(), "ops");
        assert_eq!(config.labels.person_prefix, "person-");
        assert_eq!(config.custody.kind, "file:/run/secrets/age-key");
        assert_eq!(config.custody.env, "MY_AGE_KEY");
        assert_eq!(config.custody.keychain_item, "my-item");
        assert_eq!(config.codec.sops, "/usr/local/bin/sops");
        assert_eq!(config.codec.min_version.to_string(), "3.14.0");
    }

    #[test]
    fn an_unknown_field_is_refused_by_name() {
        let error = Config::parse("[repo]\nbogus = 1\n").unwrap_err();

        assert!(error.to_string().contains("bogus"), "{error}");
    }

    #[test]
    fn a_bad_pattern_names_the_field_and_the_pattern() {
        let error = Config::parse(
            r#"
[repo]
payload_globs = ["secrets/*.env", "../outside/*.env"]
"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("payload_globs[1]"), "{error}");
        assert!(error.to_string().contains("must not leave"), "{error}");

        let empty = Config::parse("[repo]\npayload_globs = []\n").unwrap_err();
        assert!(empty.to_string().contains("payload_globs"), "{empty}");
    }

    #[test]
    fn a_bad_default_payload_names_the_field() {
        let error = Config::parse("[repo]\ndefault_payloads = [\"/abs/dev.env\"]\n").unwrap_err();
        assert!(
            error.to_string().contains("repo.default_payloads"),
            "{error}"
        );

        let yaml = Config::parse("[repo]\ndefault_payloads = [\"secrets/a.yaml\"]\n").unwrap_err();
        assert!(yaml.to_string().contains("dotenv"), "{yaml}");
    }

    #[test]
    fn a_bad_min_version_is_refused() {
        let error = Config::parse("[codec]\nmin_version = \"latest\"\n").unwrap_err();

        assert!(error.to_string().contains("codec.min_version"), "{error}");
        assert!(error.to_string().contains("latest"), "{error}");
    }

    #[test]
    fn an_unknown_custody_kind_is_refused() {
        let error = Config::parse("[custody]\nkind = \"magic\"\n").unwrap_err();

        assert!(error.to_string().contains("custody.kind"), "{error}");
        assert!(error.to_string().contains("file:<path>"), "{error}");
    }

    #[test]
    fn a_single_star_does_not_cross_a_directory_boundary() {
        let globs = Globs::new(&["secrets/*.env".to_owned()]).unwrap();

        assert!(globs.matches("secrets/dev.env"));
        assert!(!globs.matches("secrets/prod/dev.env"));
    }

    #[test]
    fn a_question_mark_matches_one_character() {
        let globs = Globs::new(&["secrets/?.env".to_owned()]).unwrap();

        assert!(globs.matches("secrets/a.env"));
        assert!(!globs.matches("secrets/ab.env"));
    }
}
