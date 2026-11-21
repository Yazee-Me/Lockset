//! `lockset.toml`: the repository's conventions as data. Parsed from text, so
//! this module never reads a file; the CLI decides which file to parse.
//!
//! Precedence, highest first, is flags, environment, this file, then the
//! defaults below. Every field is optional: a repository without the file gets
//! the defaults, and a default payload is never invented — `run` and `set` ask
//! for one instead.

use serde::Deserialize;

use crate::meta::require_dotenv;
use crate::model::{Label, PathId, PubKey};
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

/// The role that marks the identity which must open every payload.
pub const ADMIN_ROLE: &str = "admin";

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
    /// The identity registry: labels, public keys, and roles. Empty in a
    /// repository that still keeps labels in `.sops.yaml` comments.
    pub registry: IdentityRegistry,
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
            registry: IdentityRegistry::default(),
        }
    }
}

impl Config {
    /// Parse and validate the file. Every error names the field, so a typo is
    /// actionable and exits 2.
    ///
    /// ```
    /// use lockset_core::config::Config;
    ///
    /// let config = Config::parse(
    ///     "[repo]\ndefault_payloads = [\"secrets/dev.env\"]\n[codec]\nmin_version = \"3.14.0\"\n",
    /// )?;
    /// assert_eq!(config.default_payloads.len(), 1);
    /// assert_eq!(config.codec.min_version.to_string(), "3.14.0");
    ///
    /// // A typo names the field instead of silently changing behaviour.
    /// let error = Config::parse("[repo]\nbogus = 1\n").unwrap_err();
    /// assert!(error.to_string().contains("bogus"));
    /// # Ok::<(), lockset_core::Error>(())
    /// ```
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
        if let Some(account) = raw.custody.keychain_account {
            custody.keychain_account =
                Some(non_empty("custody.keychain_account", &account)?.to_owned());
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
            registry: IdentityRegistry::from_raw(&raw.identities)?,
        })
    }

    /// Whether this repository names at least one default payload.
    pub fn has_default_payloads(&self) -> bool {
        !self.default_payloads.is_empty()
    }
}

/// One identity the repository knows: its label, public key, and roles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub label: Label,
    pub public: PubKey,
    /// Free-form tags; `admin` marks the identity that must open every payload.
    pub roles: Vec<Label>,
}

impl Identity {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r.as_str() == role)
    }
}

/// The configured identity registry. Labels win over `.sops.yaml` comments;
/// comments are read only as a migration input and for drift reporting.
#[derive(Debug, Clone, Default)]
pub struct IdentityRegistry {
    identities: Vec<Identity>,
}

impl IdentityRegistry {
    pub fn new(identities: Vec<Identity>) -> Self {
        Self { identities }
    }

    fn from_raw(raw: &[RawIdentity]) -> Result<Self> {
        let mut identities: Vec<Identity> = Vec::with_capacity(raw.len());
        for (index, entry) in raw.iter().enumerate() {
            let label = Label::parse(&entry.label)
                .map_err(|error| Error::invalid(format!("identities[{index}].label: {error}")))?;
            let public = PubKey::parse(&entry.public)
                .map_err(|error| Error::invalid(format!("identities[{index}].public: {error}")))?;
            if let Some(other) = identities.iter().find(|i| i.label == label) {
                return Err(Error::invalid(format!(
                    "identities[{index}].label: '{label}' is already the label of {}",
                    other.public
                )));
            }
            if let Some(other) = identities.iter().find(|i| i.public == public) {
                return Err(Error::invalid(format!(
                    "identities[{index}].public: {public} is already registered as '{}'",
                    other.label
                )));
            }
            let mut roles: Vec<Label> = Vec::with_capacity(entry.roles.len());
            for role in &entry.roles {
                let role = Label::parse(role).map_err(|error| {
                    Error::invalid(format!("identities[{index}].roles: {error}"))
                })?;
                if !roles.contains(&role) {
                    roles.push(role);
                }
            }
            identities.push(Identity {
                label,
                public,
                roles,
            });
        }
        Ok(Self { identities })
    }

    pub fn identities(&self) -> &[Identity] {
        &self.identities
    }

    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    pub fn label_for(&self, key: &PubKey) -> Option<&Label> {
        self.identities
            .iter()
            .find(|identity| &identity.public == key)
            .map(|identity| &identity.label)
    }

    pub fn keys_for_label(&self, label: &Label) -> Vec<&PubKey> {
        self.identities
            .iter()
            .filter(|identity| &identity.label == label)
            .map(|identity| &identity.public)
            .collect()
    }

    /// The keys marked with the `admin` role.
    pub fn admin_keys(&self) -> Vec<&PubKey> {
        self.identities
            .iter()
            .filter(|identity| identity.has_role(ADMIN_ROLE))
            .map(|identity| &identity.public)
            .collect()
    }
}

/// Append a `[[identities]]` block to `lockset.toml`, leaving every other byte
/// alone. `roles` is omitted so a new entry carries no role; the result is
/// parsed before it is returned, so a rewrite can never produce a file Lockset
/// would refuse.
pub fn append_identity(text: &str, identity: &Identity) -> Result<String> {
    let mut out = String::with_capacity(text.len() + 96);
    out.push_str(text);
    if !out.is_empty() {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        // One blank line separates the block from whatever came before it.
        if !out.ends_with("\n\n") {
            out.push('\n');
        }
    }
    out.push_str(&format!(
        "[[identities]]\nlabel = \"{}\"\npublic = \"{}\"\n",
        identity.label, identity.public
    ));
    Config::parse(&out).map_err(|error| {
        Error::invalid(format!(
            "cannot register {} in lockset.toml: {error}",
            identity.public
        ))
    })?;
    Ok(out)
}

/// Remove the `[[identities]]` block that registers `key`, from its header
/// through its last key/value line (a blank line or comment before the next
/// table header belongs to that block). At most one extra blank line is
/// collapsed; every other line is preserved byte for byte. The result is
/// parsed before it is returned.
pub fn remove_identity(text: &str, key: &PubKey) -> Result<String> {
    let Some((start, end)) = identity_block(text, key) else {
        return Err(Error::invalid(format!(
            "{key} is not registered in lockset.toml"
        )));
    };
    let mut out = String::with_capacity(text.len());
    out.push_str(&text[..start]);
    let tail = &text[end..];
    // The block sat between blank lines: keep one separator, not two.
    let joined = if out.is_empty() || (out.ends_with("\n\n") && tail.starts_with('\n')) {
        tail.strip_prefix('\n').unwrap_or(tail)
    } else {
        tail
    };
    out.push_str(joined);
    if joined.is_empty() && out.ends_with("\n\n") {
        out.pop();
    }
    Config::parse(&out).map_err(|error| {
        Error::invalid(format!("cannot remove {key} from lockset.toml: {error}"))
    })?;
    Ok(out)
}

/// The byte range of the `[[identities]]` block that registers `key`, header
/// included, ending after its last key/value line. A blank line or comment
/// before the next table header belongs to the next block, not this one, so a
/// removal never carries it away.
fn identity_block(text: &str, key: &PubKey) -> Option<(usize, usize)> {
    let mut lines: Vec<(usize, usize, &str)> = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        lines.push((offset, offset + line.len(), line));
        offset += line.len();
    }
    let headers: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, (_, _, line))| line.trim_start().starts_with('['))
        .map(|(index, _)| index)
        .collect();
    for (position, &start) in headers.iter().enumerate() {
        let end = headers.get(position + 1).copied().unwrap_or(lines.len());
        if !lines[start].2.trim_start().starts_with("[[identities]]") {
            continue;
        }
        if !lines[start..end]
            .iter()
            .any(|(_, _, line)| registers(line, key))
        {
            continue;
        }
        let mut last = start;
        for (index, (_, _, line)) in lines.iter().enumerate().take(end).skip(start) {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                last = index;
            }
        }
        return Some((lines[start].0, lines[last].1));
    }
    None
}

/// Whether a TOML line is `public = "<key>"`.
fn registers(line: &str, key: &PubKey) -> bool {
    let Some((name, value)) = line.split_once('=') else {
        return false;
    };
    if name.trim() != "public" {
        return false;
    }
    let value = value.trim();
    let quoted = value
        .strip_prefix('"')
        .and_then(|rest| rest.split('"').next())
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|rest| rest.split('\'').next())
        });
    quoted.or_else(|| value.split_whitespace().next()) == Some(key.as_str())
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

/// The custody forms `--custody`, `LOCKSET_CUSTODY`, and `custody.kind` accept.
/// A parsed spec, so the grammar is data and every caller fails closed the
/// same way: an unknown or incomplete form is a usage error (exit 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodySpec {
    /// `env` or `env:<NAME>`: the key comes from a variable.
    Env(Option<String>),
    /// `keyring` or `keyring:<SERVICE>`: the OS credential store.
    Keyring(Option<String>),
    /// `file:<path>`: an explicit key file outside the repository.
    File(String),
    /// `none`: no identity source at all.
    None,
}

impl CustodySpec {
    /// The forms, for an error message that tells the user what to type.
    pub const FORMS: &'static str =
        "env, env:<NAME>, keyring, keyring:<service>, file:<absolute path>, or none";

    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        Ok(match text {
            "" => {
                return Err(Error::invalid(format!(
                    "empty custody spec; use {}",
                    Self::FORMS
                )))
            }
            "env" | "env:" => Self::Env(None),
            "keyring" | "keyring:" => Self::Keyring(None),
            "none" => Self::None,
            other => {
                if let Some(name) = other.strip_prefix("env:") {
                    // The text is trimmed, so this cannot be empty here.
                    Self::Env(Some(name.trim().to_owned()))
                } else if let Some(service) = other.strip_prefix("keyring:") {
                    Self::Keyring(Some(service.trim().to_owned()))
                } else if let Some(path) = other.strip_prefix("file:") {
                    let path = path.trim();
                    if path.is_empty() {
                        return Err(Error::invalid(
                            "file: custody needs a path to the key (file:<absolute path>)",
                        ));
                    }
                    Self::File(path.to_owned())
                } else {
                    return Err(Error::invalid(format!(
                        "unknown custody '{other}'; use {}",
                        Self::FORMS
                    )));
                }
            }
        })
    }
}

/// Where the identity comes from when no flag and no environment select it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyConfig {
    /// `auto`, or any [`CustodySpec`] form (`env`, `env:<NAME>`, `keyring`,
    /// `keyring:<service>`, `file:<path>`, `none`).
    pub kind: String,
    /// The variable bare `env` custody reads.
    pub env: String,
    /// The keychain service bare `keyring` custody reads.
    pub keychain_item: String,
    /// The keychain account; `None` means the current user.
    pub keychain_account: Option<String>,
}

impl Default for CustodyConfig {
    fn default() -> Self {
        Self {
            kind: "auto".to_owned(),
            env: DEFAULT_KEY_ENV.to_owned(),
            keychain_item: DEFAULT_KEYCHAIN_ITEM.to_owned(),
            keychain_account: None,
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
    if kind == "auto" {
        return Ok(kind.to_owned());
    }
    // The config shares the flag's grammar, so both fail closed the same way.
    CustodySpec::parse(kind).map_err(|error| Error::invalid(format!("custody.kind: {error}")))?;
    Ok(kind.trim().to_owned())
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    #[serde(default)]
    repo: RawRepo,
    #[serde(default)]
    identities: Vec<RawIdentity>,
    #[serde(default)]
    labels: RawLabels,
    #[serde(default)]
    custody: RawCustody,
    #[serde(default)]
    codec: RawCodec,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentity {
    label: String,
    public: String,
    #[serde(default)]
    roles: Vec<String>,
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
    keychain_account: Option<String>,
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
    fn every_custody_form_parses() {
        for (text, expected) in [
            ("env", CustodySpec::Env(None)),
            ("env:", CustodySpec::Env(None)),
            (
                "env:DEPLOY_KEY",
                CustodySpec::Env(Some("DEPLOY_KEY".into())),
            ),
            ("keyring", CustodySpec::Keyring(None)),
            ("keyring:", CustodySpec::Keyring(None)),
            (
                "keyring:lockset-age-key-app",
                CustodySpec::Keyring(Some("lockset-age-key-app".into())),
            ),
            (
                "file:/run/secrets/age-key",
                CustodySpec::File("/run/secrets/age-key".into()),
            ),
            ("none", CustodySpec::None),
        ] {
            assert_eq!(CustodySpec::parse(text).unwrap(), expected, "{text}");
        }
    }

    #[test]
    fn an_invalid_custody_form_fails_closed_and_lists_the_forms() {
        let unknown = CustodySpec::parse("magic").unwrap_err();
        assert!(unknown.to_string().contains("unknown custody"), "{unknown}");
        assert!(unknown.to_string().contains("env:<NAME>"), "{unknown}");
        assert!(
            unknown.to_string().contains("file:<absolute path>"),
            "{unknown}"
        );

        let no_path = CustodySpec::parse("file:").unwrap_err();
        assert!(no_path.to_string().contains("path"), "{no_path}");

        // Whitespace after the colon means the bare form.
        assert_eq!(
            CustodySpec::parse("env:   ").unwrap(),
            CustodySpec::Env(None)
        );

        let empty = CustodySpec::parse("   ").unwrap_err();
        assert!(empty.to_string().contains("empty custody spec"), "{empty}");
    }

    #[test]
    fn the_config_kind_shares_the_flag_grammar() {
        let config = Config::parse("[custody]\nkind = \"env:DEPLOY_KEY\"\n").unwrap();
        assert_eq!(config.custody.kind, "env:DEPLOY_KEY");

        let error = Config::parse("[custody]\nkind = \"magic\"\n").unwrap_err();
        assert!(error.to_string().contains("custody.kind"), "{error}");
        assert!(error.to_string().contains("env:<NAME>"), "{error}");
    }

    #[test]
    fn the_keychain_account_is_per_repo() {
        let config = Config::parse(
            "[custody]\nkind = \"keyring\"\nkeychain_item = \"lockset-age-key-app\"\nkeychain_account = \"ci\"\n",
        )
        .unwrap();
        assert_eq!(config.custody.keychain_item, "lockset-age-key-app");
        assert_eq!(config.custody.keychain_account.as_deref(), Some("ci"));

        let empty = Config::parse("[custody]\nkeychain_account = \"  \"\n").unwrap_err();
        assert!(empty.to_string().contains("keychain_account"), "{empty}");
    }

    #[test]
    fn an_unknown_custody_kind_is_refused() {
        let error = Config::parse("[custody]\nkind = \"magic\"\n").unwrap_err();

        assert!(error.to_string().contains("custody.kind"), "{error}");
        assert!(
            error.to_string().contains("file:<absolute path>"),
            "{error}"
        );
    }

    const ADMIN: &str = "age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x";
    const ALICE: &str = "age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q";
    const CAROL: &str = "age1y4gs9hk93n3mpvhwydaq7uz4mn3a0esf0wfh3md2v2qz4hye9frsfpelwh";

    #[test]
    fn identities_parse_with_labels_keys_and_roles() {
        let config = Config::parse(&format!(
            r#"
[[identities]]
label = "admin"
public = "{ADMIN}"
roles = ["admin", "admin"]

[[identities]]
label = "dev-alice"
public = "{ALICE}"
"#
        ))
        .unwrap();

        assert_eq!(config.registry.identities().len(), 2);
        let admin = &config.registry.identities()[0];
        assert_eq!(admin.label.as_str(), "admin");
        assert_eq!(admin.public.as_str(), ADMIN);
        assert_eq!(admin.roles.len(), 1, "roles are deduped");
        assert!(admin.has_role("admin"));

        let alice = &config.registry.identities()[1];
        assert!(alice.roles.is_empty());
        assert_eq!(
            config
                .registry
                .label_for(&PubKey::parse(ALICE).unwrap())
                .map(|label| label.as_str()),
            Some("dev-alice")
        );
        assert_eq!(config.registry.admin_keys().len(), 1);
        assert_eq!(
            config
                .registry
                .keys_for_label(&Label::parse("dev-alice").unwrap())
                .len(),
            1
        );
    }

    #[test]
    fn a_duplicate_label_or_key_is_refused_by_name() {
        let duplicate_label = Config::parse(&format!(
            "[[identities]]\nlabel = \"admin\"\npublic = \"{ADMIN}\"\n[[identities]]\nlabel = \"admin\"\npublic = \"{ALICE}\"\n"
        ))
        .unwrap_err();
        assert!(
            duplicate_label
                .to_string()
                .contains("identities[1].label: 'admin' is already the label"),
            "{duplicate_label}"
        );

        let duplicate_key = Config::parse(&format!(
            "[[identities]]\nlabel = \"admin\"\npublic = \"{ADMIN}\"\n[[identities]]\nlabel = \"dev-alice\"\npublic = \"{ADMIN}\"\n"
        ))
        .unwrap_err();
        assert!(
            duplicate_key.to_string().contains("identities[1].public"),
            "{duplicate_key}"
        );
    }

    #[test]
    fn an_identity_field_error_names_the_entry() {
        let bad_key = Config::parse("[[identities]]\nlabel = \"admin\"\npublic = \"not-a-key\"\n")
            .unwrap_err();
        assert!(
            bad_key.to_string().contains("identities[0].public"),
            "{bad_key}"
        );

        let bad_label = Config::parse(&format!(
            "[[identities]]\nlabel = \"Admin\"\npublic = \"{ADMIN}\"\n"
        ))
        .unwrap_err();
        assert!(
            bad_label.to_string().contains("identities[0].label"),
            "{bad_label}"
        );

        let bad_role = Config::parse(&format!(
            "[[identities]]\nlabel = \"admin\"\npublic = \"{ADMIN}\"\nroles = [\"Not A Role\"]\n"
        ))
        .unwrap_err();
        assert!(
            bad_role.to_string().contains("identities[0].roles"),
            "{bad_role}"
        );
    }

    fn identity(label: &str, key: &str, roles: &[&str]) -> Identity {
        Identity {
            label: Label::parse(label).unwrap(),
            public: PubKey::parse(key).unwrap(),
            roles: roles
                .iter()
                .map(|role| Label::parse(role).unwrap())
                .collect(),
        }
    }

    #[test]
    fn append_identity_keeps_every_other_line_and_parses() {
        let before =
            "# conventions\n[codec]\nsops = \"sops\" # pinned\n\n[labels]\nadmin = \"ops\"\n";
        let after = append_identity(before, &identity("dev-alice", ALICE, &[])).unwrap();

        assert_eq!(
            after,
            format!("{before}\n[[identities]]\nlabel = \"dev-alice\"\npublic = \"{ALICE}\"\n")
        );
        let config = Config::parse(&after).unwrap();
        assert_eq!(
            config
                .registry
                .label_for(&PubKey::parse(ALICE).unwrap())
                .map(Label::as_str),
            Some("dev-alice")
        );
        assert!(config.registry.identities()[0].roles.is_empty());
    }

    #[test]
    fn append_identity_creates_the_registry_in_an_empty_file() {
        let after = append_identity("", &identity("admin", ADMIN, &[])).unwrap();

        assert!(after.starts_with("[[identities]]\n"), "{after}");
        assert!(!after.starts_with('\n'), "no leading blank line: {after}");
        assert_eq!(
            Config::parse(&after).unwrap().registry.identities().len(),
            1
        );
    }

    #[test]
    fn remove_identity_keeps_the_other_entries_and_their_roles() {
        let text = format!(
            "[codec]\nsops = \"sops\"\n\n[[identities]]\nlabel = \"admin\"\npublic = \"{ADMIN}\"\nroles = [\"admin\"]\n\n[[identities]]\nlabel = \"dev-alice\"\npublic = \"{ALICE}\"\nroles = [\"ci\"]\n\n[[identities]]\nlabel = \"dev-carol\"\npublic = \"{CAROL}\"\n"
        );
        let after = remove_identity(&text, &PubKey::parse(ALICE).unwrap()).unwrap();

        assert!(
            after.contains(&format!(
                "[[identities]]\nlabel = \"admin\"\npublic = \"{ADMIN}\"\nroles = [\"admin\"]\n"
            )),
            "{after}"
        );
        assert!(
            after.contains(&format!(
                "[[identities]]\nlabel = \"dev-carol\"\npublic = \"{CAROL}\"\n"
            )),
            "{after}"
        );
        assert!(!after.contains(ALICE), "{after}");
        assert_eq!(after.matches("[[identities]]").count(), 2, "{after}");
        assert!(!after.contains("\n\n\n"), "one blank line stays: {after}");

        let config = Config::parse(&after).unwrap();
        assert_eq!(config.registry.identities().len(), 2);
        assert!(config.registry.identities()[0].has_role("admin"));
    }

    #[test]
    fn remove_identity_preserves_comments_around_the_block() {
        let text = format!(
            "# top\n[codec]\nsops = \"sops\"\n\n# the admin entry\n[[identities]]\nlabel = \"admin\"\npublic = \"{ADMIN}\"\n\n# a person\n[[identities]]\nlabel = \"dev-alice\"\npublic = \"{ALICE}\"\n\n# footer\n"
        );
        let after = remove_identity(&text, &PubKey::parse(ADMIN).unwrap()).unwrap();

        assert!(
            after.starts_with("# top\n[codec]\nsops = \"sops\"\n"),
            "{after}"
        );
        assert!(after.contains("# the admin entry\n"), "{after}");
        assert!(after.contains("# a person\n[[identities]]"), "{after}");
        assert!(after.contains("# footer"), "{after}");
        assert!(!after.contains(ADMIN), "{after}");
        Config::parse(&after).unwrap();
    }

    #[test]
    fn removing_an_absent_key_is_an_error() {
        let text = format!("[[identities]]\nlabel = \"admin\"\npublic = \"{ADMIN}\"\n");

        let error = remove_identity(&text, &PubKey::parse(ALICE).unwrap()).unwrap_err();

        assert!(error.to_string().contains("not registered"), "{error}");
        assert!(error.to_string().contains(ALICE), "{error}");
    }

    #[test]
    fn a_malformed_registry_rewrite_never_escapes() {
        // A `[` value that looks like a table header must not split the block.
        let text = format!(
            "[[identities]]\nlabel = \"admin\"\npublic = \"{ADMIN}\"\nroles = [\"admin\"]\n"
        );
        let appended = append_identity(&text, &identity("admin", ALICE, &[])).unwrap_err();
        assert!(appended.to_string().contains("lockset.toml"), "{appended}");

        let empty = remove_identity("", &PubKey::parse(ADMIN).unwrap()).unwrap_err();
        assert!(empty.to_string().contains("not registered"), "{empty}");
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
