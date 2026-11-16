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

/// Parse a sops payload. Dotenv files carry their metadata as flat `sops_*`
/// keys; YAML/JSON files carry a `sops:` block. Both are supported.
pub fn parse(id: PathId, text: &str) -> Result<PayloadMeta> {
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

/// Byte offset where the sops metadata begins: the first `sops_` line
/// (dotenv) or the `sops:` block (YAML).
fn metadata_start(text: &str) -> Option<usize> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let body = line.trim_start();
        if body.starts_with("sops_") || body.starts_with("sops:") {
            return Some(offset);
        }
        offset += line.len();
    }
    None
}

fn parse_recipients(meta: &str) -> Result<Vec<PubKey>> {
    let flat = flat_recipients(meta)?;
    if !flat.is_empty() {
        return Ok(flat);
    }
    yaml_recipients(meta)
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

fn yaml_recipients(meta: &str) -> Result<Vec<PubKey>> {
    let start = meta.find("sops:").unwrap_or(0);
    let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&meta[start..])
        .map_err(|e| Error::invalid(format!("cannot parse the sops metadata: {e}")))?;
    let Some(age) = value.get("sops").and_then(|sops| sops.get("age")) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    match age {
        serde_yaml_ng::Value::Sequence(items) => {
            for item in items {
                if let Some(key) = item.get("recipient").and_then(|r| r.as_str()) {
                    out.push(PubKey::parse(key)?);
                }
            }
        }
        serde_yaml_ng::Value::Mapping(map) => {
            if let Some(key) = map.get("recipient").and_then(|r| r.as_str()) {
                out.push(PubKey::parse(key)?);
            }
        }
        _ => {}
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
        let meta = parse(PathId::new("secrets/prod/host-main.env"), &flat_payload()).unwrap();
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
    fn parses_yaml_metadata() {
        let text = format!(
            "CLOUDFLARE_TUNNEL_TOKEN_MAIN: ENC[AES256_GCM,data:abc,type:str]\n\
             sops:\n    age:\n        - recipient: {A}\n          enc: |\n            x\n    version: 3.13.3\n"
        );
        let meta = parse(PathId::new("secrets/prod/x.yaml"), &text).unwrap();
        assert!(meta.encrypted);
        assert_eq!(meta.recipients.len(), 1);
    }

    #[test]
    fn flags_plaintext_values() {
        let text = "A=secret\nsops:\n    version: 3.13.3\n";
        let meta = parse(PathId::new("secrets/prod/x.env"), text).unwrap();
        assert_eq!(meta.plaintext, vec!["A"]);
    }

    #[test]
    fn plain_file_is_not_encrypted() {
        let meta = parse(PathId::new("secrets/prod/x.env"), "A=1\nB=2\n").unwrap();
        assert!(!meta.encrypted);
        assert!(meta.recipients.is_empty());
        assert_eq!(meta.keys.len(), 2);
    }
}
