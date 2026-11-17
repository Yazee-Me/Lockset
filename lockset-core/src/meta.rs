use crate::model::{PathId, PubKey};
use crate::{Error, Result};

/// What can be learned about a payload without decrypting it. `check` and
/// `status` are built on this; only `run`/`read` need the private key.
#[derive(Debug, Clone)]
pub struct PayloadMeta {
    pub id: PathId,
    pub recipients: Vec<PubKey>,
    pub keys: Vec<String>,
    pub empty: Vec<String>,
    pub plaintext: Vec<String>,
    pub encrypted: bool,
}

impl PayloadMeta {
    pub fn has(&self, key: &PubKey) -> bool {
        self.recipients.iter().any(|r| r == key)
    }
}

/// Parse a sops payload. Lockset supports one payload format: dotenv (`.env`),
/// whose metadata is a set of flat `sops_*` keys. Anything else is rejected by
/// name and by content instead of being half-parsed.
pub fn parse(id: PathId, text: &str) -> Result<PayloadMeta> {
    if !is_dotenv(&id) {
        return Err(Error::invalid(format!(
            "not a dotenv payload; {DOTENV_ONLY}"
        )));
    }
    if looks_like_yaml_or_json(text) {
        return Err(Error::invalid(format!(
            "{id} carries a YAML/JSON sops block; lockset supports dotenv (.env) payloads only"
        )));
    }
    let meta_at = metadata_start(text);
    let (values, meta) = match meta_at {
        Some(i) => text.split_at(i),
        None => (text, ""),
    };

    let mut keys = Vec::new();
    let mut empty = Vec::new();
    let mut plaintext = Vec::new();
    for line in values.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if !is_name(name) || name.starts_with("sops_") {
            continue;
        }
        keys.push(name.to_owned());
        if value.is_empty() {
            empty.push(name.to_owned());
        } else if !value.starts_with("ENC[") {
            plaintext.push(name.to_owned());
        }
    }

    let encrypted = !meta.is_empty();
    let recipients = if meta.is_empty() {
        Vec::new()
    } else {
        parse_recipients(meta)?
    };

    Ok(PayloadMeta {
        id,
        recipients,
        keys,
        empty,
        plaintext,
        encrypted,
    })
}

/// The format rule in one sentence, shared by the errors that state it.
const DOTENV_ONLY: &str =
    "lockset supports .env payloads only — YAML/JSON payloads are not implemented";

/// The only payload format lockset handles: a file whose name ends in `.env`.
pub fn is_dotenv(id: &PathId) -> bool {
    id.as_str().ends_with(".env")
}

/// Reject a payload that is not dotenv, naming it and the supported format.
pub fn require_dotenv(id: &PathId) -> Result<()> {
    if is_dotenv(id) {
        return Ok(());
    }
    Err(Error::refused(format!(
        "{id} is not a dotenv payload; {DOTENV_ONLY}"
    )))
}

/// What sops writes for a YAML or JSON payload: a `sops:` block, or a JSON
/// object. Neither is accepted in a dotenv payload.
fn looks_like_yaml_or_json(text: &str) -> bool {
    text.trim_start().starts_with('{')
        || text
            .lines()
            .any(|line| line.trim_start().starts_with("sops:"))
}

/// Byte offset where the dotenv sops metadata begins: the first `sops_` line.
fn metadata_start(text: &str) -> Option<usize> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let body = line.trim_start();
        if body.starts_with("sops_") {
            return Some(offset);
        }
        offset += line.len();
    }
    None
}

fn parse_recipients(meta: &str) -> Result<Vec<PubKey>> {
    flat_recipients(meta)
}

fn flat_recipients(meta: &str) -> Result<Vec<PubKey>> {
    let mut out = Vec::new();
    for line in meta.lines() {
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name.starts_with("sops_age__list_") && name.ends_with("__map_recipient") {
            out.push(PubKey::parse(value)?);
        }
    }
    Ok(out)
}

pub fn is_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x";
    const B: &str = "age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q";

    /// Real shape: sops dotenv writes metadata as flat `sops_*` keys.
    fn flat_payload() -> String {
        format!(
            "CLOUDFLARE_TUNNEL_TOKEN_MAIN=ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\n\
             COOLIFY_DB_PASSWORD=\n\
             sops_age__list_0__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\\nYWdl\n\
             sops_age__list_0__map_recipient={A}\n\
             sops_age__list_1__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\\nYWdl\n\
             sops_age__list_1__map_recipient={B}\n\
             sops_lastmodified=2026-10-27T00:00:00Z\n\
             sops_mac=ENC[AES256_GCM,data:zzz,iv:yyy,tag:xxx,type:str]\n\
             sops_version=3.13.3\n"
        )
    }

    #[test]
    fn parses_flat_dotenv_metadata() {
        let meta = parse(
            PathId::parse("secrets/prod/host-main.env").unwrap(),
            &flat_payload(),
        )
        .unwrap();
        assert!(meta.encrypted);
        assert_eq!(
            meta.keys,
            vec!["CLOUDFLARE_TUNNEL_TOKEN_MAIN", "COOLIFY_DB_PASSWORD"]
        );
        assert_eq!(meta.empty, vec!["COOLIFY_DB_PASSWORD"]);
        assert!(meta.plaintext.is_empty());
        assert_eq!(meta.recipients.len(), 2);
        assert!(meta.has(&PubKey::parse(A).unwrap()));
    }

    #[test]
    fn a_yaml_payload_is_rejected_by_name() {
        let text = format!(
            "CLOUDFLARE_TUNNEL_TOKEN_MAIN: ENC[AES256_GCM,data:abc,type:str]\n\
             sops:\n    age:\n        - recipient: {A}\n          enc: |\n            x\n    version: 3.13.3\n"
        );

        let error = parse(PathId::parse("secrets/prod/x.yaml").unwrap(), &text).unwrap_err();

        assert!(error.to_string().contains("dotenv"), "{error}");
        assert!(error.to_string().contains("YAML/JSON"), "{error}");
    }

    #[test]
    fn a_json_payload_is_rejected_by_name() {
        let error = parse(
            PathId::parse("secrets/prod/x.json").unwrap(),
            "{\"A\": \"ENC[a,type:str]\"}\n",
        )
        .unwrap_err();

        assert!(error.to_string().contains("dotenv"), "{error}");
    }

    #[test]
    fn a_dotenv_file_holding_yaml_metadata_is_rejected() {
        let text = "A=secret\nsops:\n    version: 3.13.3\n";

        let error = parse(PathId::parse("secrets/prod/x.env").unwrap(), text).unwrap_err();

        assert!(error.to_string().contains("YAML/JSON"), "{error}");
    }

    #[test]
    fn flags_plaintext_values() {
        let text = "A=secret\nB=ENC[AES256_GCM,data:abc,type:str]\n";
        let meta = parse(PathId::parse("secrets/prod/x.env").unwrap(), text).unwrap();
        assert_eq!(meta.plaintext, vec!["A"]);
    }

    #[test]
    fn plain_file_is_not_encrypted() {
        let meta = parse(PathId::parse("secrets/prod/x.env").unwrap(), "A=1\nB=2\n").unwrap();
        assert!(!meta.encrypted);
        assert!(meta.recipients.is_empty());
        assert_eq!(meta.keys.len(), 2);
    }
}
