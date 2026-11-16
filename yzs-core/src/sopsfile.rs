use std::ops::Range;

use regex::Regex;

use crate::model::{Label, PubKey};
use crate::{Error, Result};

/// One recipient of a payload, with the label recorded next to it in
/// `.sops.yaml`. The label is optional because a hand-edited file can drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    pub key: PubKey,
    pub label: Option<Label>,
}

/// One creation rule: which payload paths it covers and who can read them.
#[derive(Debug, Clone)]
pub struct Rule {
    pub path_regex: String,
    pub recipients: Vec<Recipient>,
    /// Byte range of the whole `age:` line, newline included when present.
    /// Rewriting uses it to touch nothing else in the file.
    pub age_span: Range<usize>,
    pub indent: String,
}

impl Rule {
    pub fn label_of(&self, key: &PubKey) -> Option<Label> {
        self.recipients
            .iter()
            .find(|r| &r.key == key)
            .and_then(|r| r.label.clone())
    }

    pub fn contains(&self, key: &PubKey) -> bool {
        self.recipients.iter().any(|r| &r.key == key)
    }
}

/// `.sops.yaml`, parsed just enough to answer "who can read what" and to
/// rewrite one line per rule without disturbing comments or layout.
#[derive(Debug, Clone)]
pub struct SopsFile {
    text: String,
    rules: Vec<Rule>,
}

impl SopsFile {
    pub fn parse(text: &str) -> Result<Self> {
        let rule_re = Regex::new(r"^\s*-\s*path_regex:\s*(.+?)\s*$").expect("static regex");
        let age_re = Regex::new(r"^\s*age:\s*(.*?)\s*$").expect("static regex");

        let mut rules: Vec<Rule> = Vec::new();
        let mut offset = 0usize;
        for line in text.split_inclusive('\n') {
            let start = offset;
            offset += line.len();
            let body = line.trim_end_matches(['\n', '\r']);

            if let Some(caps) = rule_re.captures(body) {
                let re = caps[1].trim().trim_matches('"').trim_matches('\'');
                rules.push(Rule {
                    path_regex: re.to_owned(),
                    recipients: Vec::new(),
                    age_span: start..start,
                    indent: String::new(),
                });
                continue;
            }
            let Some(caps) = age_re.captures(body) else {
                continue;
            };
            let Some(rule) = rules.last_mut() else {
                continue;
            };
            if !rule.age_span.is_empty() {
                continue;
            }
            let indent_len = body.len() - body.trim_start().len();
            rule.indent = body[..indent_len].to_owned();
            let value = caps[1].trim();
            let (keys, comment) = match value.split_once('#') {
                Some((k, c)) => (k, Some(c)),
                None => (value, None),
            };
            let keys: Vec<&str> = keys
                .split(',')
                .map(str::trim)
                .map(|k| k.trim_matches('"').trim_matches('\''))
                .filter(|k| !k.is_empty())
                .collect();
            if keys.is_empty() {
                return Err(Error::invalid(format!(
                    "rule '{}' has an empty age: list",
                    rule.path_regex
                )));
            }
            let labels: Vec<&str> = comment
                .map(|c| {
                    c.split(',')
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            let mut recipients = Vec::with_capacity(keys.len());
            for (i, key) in keys.iter().enumerate() {
                let key = PubKey::parse(key)?;
                // A label that does not parse is drift, not a parse failure.
                let label = labels.get(i).and_then(|l| Label::parse(l).ok());
                recipients.push(Recipient { key, label });
            }
            rule.recipients = recipients;
            rule.age_span = start..offset;
        }

        if rules.is_empty() {
            return Err(Error::invalid(
                ".sops.yaml has no `- path_regex:` creation rule",
            ));
        }
        for rule in &rules {
            if rule.age_span.is_empty() {
                return Err(Error::invalid(format!(
                    "rule '{}' has no age: line",
                    rule.path_regex
                )));
            }
        }

        Ok(Self {
            text: text.to_owned(),
            rules,
        })
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Index of the first rule whose pattern matches `path`.
    pub fn rule_index_for(&self, path: &str) -> Result<Option<usize>> {
        for (i, rule) in self.rules.iter().enumerate() {
            if Self::matches(&rule.path_regex, path)? {
                return Ok(Some(i));
            }
        }
        Ok(None)
    }

    pub fn rule_indexes_for(&self, path: &str) -> Result<Vec<usize>> {
        let mut out = Vec::new();
        for (i, rule) in self.rules.iter().enumerate() {
            if Self::matches(&rule.path_regex, path)? {
                out.push(i);
            }
        }
        Ok(out)
    }

    fn matches(pattern: &str, path: &str) -> Result<bool> {
        let re = Regex::new(pattern)
            .map_err(|e| Error::failed(format!("invalid path_regex '{pattern}': {e}")))?;
        Ok(re.is_match(path))
    }

    /// Render the file with a new recipient list per rule. Everything outside
    /// the `age:` lines is byte-identical to the input.
    pub fn render_with(&self, new_sets: &[Vec<Recipient>]) -> Result<String> {
        if new_sets.len() != self.rules.len() {
            return Err(Error::failed("internal: recipient set count mismatch"));
        }
        let mut out = String::with_capacity(self.text.len());
        let mut pos = 0usize;
        for (rule, set) in self.rules.iter().zip(new_sets.iter()) {
            out.push_str(&self.text[pos..rule.age_span.start]);
            let keys: Vec<&str> = set.iter().map(|r| r.key.as_str()).collect();
            let labelled = set.iter().all(|r| r.label.is_some());
            let comment = if labelled && !set.is_empty() {
                let labels: Vec<String> = set
                    .iter()
                    .filter_map(|r| r.label.as_ref().map(|l| l.to_string()))
                    .collect();
                format!(" # {}", labels.join(","))
            } else {
                String::new()
            };
            out.push_str(&format!(
                "{}age: {}{}",
                rule.indent,
                keys.join(","),
                comment
            ));
            if self.text[rule.age_span.clone()].ends_with('\n') {
                out.push('\n');
            }
            pos = rule.age_span.end;
        }
        out.push_str(&self.text[pos..]);
        Ok(out)
    }

    /// Labels that name more than one key, or keys with no label.
    pub fn drift(&self) -> Vec<String> {
        let mut notes = Vec::new();
        for rule in &self.rules {
            for r in &rule.recipients {
                if r.label.is_none() {
                    notes.push(format!(
                        "{}: recipient {} has no label",
                        rule.path_regex, r.key
                    ));
                }
            }
            if rule.recipients.iter().any(|r| r.label.is_some())
                && rule.recipients.iter().any(|r| r.label.is_none())
            {
                notes.push(format!(
                    "{}: labels and recipients are not aligned (a count mismatch)",
                    rule.path_regex
                ));
            }
        }
        let mut by_label: Vec<(String, PubKey)> = Vec::new();
        for rule in &self.rules {
            for r in &rule.recipients {
                if let Some(label) = &r.label {
                    by_label.push((label.to_string(), r.key.clone()));
                }
            }
        }
        let mut seen: Vec<(String, PubKey)> = Vec::new();
        for (label, key) in &by_label {
            if let Some((_, other)) = seen.iter().find(|(l, k)| l == label && k != key) {
                notes.push(format!("label {label} names two keys ({other} and {key})"));
                break;
            }
            if !seen.iter().any(|(l, k)| l == label && k == key) {
                seen.push((label.clone(), key.clone()));
            }
        }
        notes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x";
    const B: &str = "age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q";
    const C: &str = "age1y4gs9hk93n3mpvhwydaq7uz4mn3a0esf0wfh3md2v2qz4hye9frsfpelwh";

    fn fixture() -> String {
        format!(
            "# comment kept\ncreation_rules:\n- path_regex: secrets/prod/infra\\.env$\n  age: {A},{B},{C} # admin,recovery,ci\n- path_regex: secrets/prod/host-main\\.env$\n  age: {A},{B} # admin,recovery\n"
        )
    }

    #[test]
    fn parses_rules_and_labels() {
        let f = SopsFile::parse(&fixture()).unwrap();
        assert_eq!(f.rules().len(), 2);
        assert_eq!(f.rules()[0].recipients.len(), 3);
        assert_eq!(
            f.rules()[0].recipients[2].label.as_ref().unwrap().as_str(),
            "ci"
        );
        assert_eq!(f.rules()[1].recipients.len(), 2);
    }

    #[test]
    fn matches_paths() {
        let f = SopsFile::parse(&fixture()).unwrap();
        assert_eq!(f.rule_index_for("secrets/prod/infra.env").unwrap(), Some(0));
        assert_eq!(f.rule_index_for("secrets/prod/other.env").unwrap(), None);
    }

    #[test]
    fn render_changes_only_the_age_line() {
        let f = SopsFile::parse(&fixture()).unwrap();
        let mut sets: Vec<Vec<Recipient>> =
            f.rules().iter().map(|r| r.recipients.clone()).collect();
        sets[1].pop();
        let out = f.render_with(&sets).unwrap();
        let expected = format!(
            "# comment kept\ncreation_rules:\n- path_regex: secrets/prod/infra\\.env$\n  age: {A},{B},{C} # admin,recovery,ci\n- path_regex: secrets/prod/host-main\\.env$\n  age: {A} # admin\n"
        );
        assert_eq!(out, expected);
        // The result parses back into the same shape.
        let again = SopsFile::parse(&out).unwrap();
        assert_eq!(again.rules()[1].recipients.len(), 1);
    }

    #[test]
    fn add_is_idempotent_by_pubkey() {
        let f = SopsFile::parse(&fixture()).unwrap();
        let mut sets: Vec<Vec<Recipient>> =
            f.rules().iter().map(|r| r.recipients.clone()).collect();
        if !sets[0].iter().any(|r| r.key.as_str() == A) {
            sets[0].push(Recipient {
                key: PubKey::parse(A).unwrap(),
                label: Some(Label::parse("admin").unwrap()),
            });
        }
        let out = f.render_with(&sets).unwrap();
        assert_eq!(out, f.text());
    }

    #[test]
    fn flags_drift() {
        let text =
            format!("creation_rules:\n- path_regex: secrets/prod/infra\\.env$\n  age: {A},{B}\n");
        let f = SopsFile::parse(&text).unwrap();
        assert_eq!(f.drift().len(), 2);
    }
}
