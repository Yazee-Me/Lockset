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

/// The trailing comment on an `age:` line. `labels` is set only when the whole
/// comment is a comma-separated label list, so rewriting may regenerate it; any
/// other comment is free text and is preserved byte-for-byte, because a hand
/// edit or another tool put it there.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Comment {
    pub raw: String,
    pub labels: Option<Vec<Label>>,
}

impl Comment {
    fn parse(text: &str) -> Self {
        let raw = text.trim().to_owned();
        if raw.is_empty() {
            return Self::default();
        }
        let mut labels = Vec::new();
        for token in raw.split(',') {
            match Label::parse(token.trim()) {
                Ok(label) => labels.push(label),
                Err(_) => return Self { raw, labels: None },
            }
        }
        Self {
            raw,
            labels: Some(labels),
        }
    }

    /// The label at `index`, when the comment is a label list.
    fn label_at(&self, index: usize) -> Option<Label> {
        self.labels
            .as_ref()
            .and_then(|labels| labels.get(index).cloned())
    }
}

/// The recipient backend a rule declares. Lockset reads and rewrites `age:`
/// lines only; another backend is parsed and reported so a mixed repository
/// works, and refused only when a mutation targets that rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleKind {
    /// An `age:` line.
    Age,
    /// Another sops backend, by its key name (`kms`, `gcp_kms`, …).
    Other(String),
    /// A rule with no recipient line at all.
    None,
}

/// One creation rule: which payload paths it covers and who can read them.
#[derive(Debug, Clone)]
pub struct Rule {
    pub path_regex: String,
    pub recipients: Vec<Recipient>,
    pub kind: RuleKind,
    /// The trailing comment, kept so a rewrite never loses free text.
    pub comment: Comment,
    /// Byte range of the whole `age:` line, newline included when present.
    /// Rewriting uses it to touch nothing else in the file.
    pub age_span: Option<Range<usize>>,
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

    /// Whether lockset can read and rewrite this rule's recipients.
    pub fn is_age(&self) -> bool {
        self.kind == RuleKind::Age
    }

    /// The backend's name, for a message: `age`, `kms`, or `no recipients`.
    pub fn backend(&self) -> &str {
        match &self.kind {
            RuleKind::Age => "age",
            RuleKind::Other(name) => name,
            RuleKind::None => "no recipients",
        }
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
        // The other recipient backends sops accepts. A rule keyed by one of
        // them parses; only a mutation that has to rewrite `age:` refuses.
        let other_re =
            Regex::new(r"^\s*(pgp|kms|gcp_kms|azure_kv|hc_vault_transit_uri):\s*(.*?)\s*$")
                .expect("static regex");

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
                    kind: RuleKind::None,
                    comment: Comment::default(),
                    age_span: None,
                    indent: String::new(),
                });
                continue;
            }
            let Some(rule) = rules.last_mut() else {
                continue;
            };
            if let Some(caps) = other_re.captures(body) {
                if rule.kind == RuleKind::None {
                    rule.kind = RuleKind::Other(caps[1].to_owned());
                }
                continue;
            }
            let Some(caps) = age_re.captures(body) else {
                continue;
            };
            if rule.age_span.is_some() {
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
            let comment = comment.map(Comment::parse).unwrap_or_default();
            let mut recipients = Vec::with_capacity(keys.len());
            for (i, key) in keys.iter().enumerate() {
                let key = PubKey::parse(key)?;
                // A label that does not parse is drift, not a parse failure.
                recipients.push(Recipient {
                    key,
                    label: comment.label_at(i),
                });
            }
            rule.recipients = recipients;
            rule.comment = comment;
            rule.kind = RuleKind::Age;
            rule.age_span = Some(start..offset);
        }

        if rules.is_empty() {
            return Err(Error::invalid(
                ".sops.yaml has no `- path_regex:` creation rule",
            ));
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

    /// Rules lockset cannot rewrite, for the per-rule report.
    pub fn non_age_rules(&self) -> Vec<&Rule> {
        self.rules.iter().filter(|rule| !rule.is_age()).collect()
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
            let Some(span) = &rule.age_span else {
                // No `age:` line to replace: the rule stays byte-identical. A
                // caller that wanted to change it refuses before rendering.
                if !set.is_empty() {
                    return Err(Error::failed(format!(
                        "internal: rule '{}' has no age: line to rewrite",
                        rule.path_regex
                    )));
                }
                continue;
            };
            out.push_str(&self.text[pos..span.start]);
            let keys: Vec<&str> = set.iter().map(|r| r.key.as_str()).collect();
            out.push_str(&format!(
                "{}age: {}{}",
                rule.indent,
                keys.join(","),
                Self::rendered_comment_text(rule, set)
            ));
            // Keep the line ending the file already uses: a CRLF map must not
            // end up with mixed endings.
            let line = &self.text[span.clone()];
            if line.ends_with("\r\n") {
                out.push_str("\r\n");
            } else if line.ends_with('\n') {
                out.push('\n');
            }
            pos = span.end;
        }
        out.push_str(&self.text[pos..]);
        Ok(out)
    }

    /// The comment a rewrite writes: free text is preserved verbatim; a label
    /// list is regenerated only when every key has a label (the set's, else the
    /// rule's original), so a partial list is never silently dropped or
    /// misaligned.
    fn rendered_comment_text(rule: &Rule, set: &[Recipient]) -> String {
        if rule.comment.labels.is_none() && !rule.comment.raw.is_empty() {
            return format!(" # {}", rule.comment.raw);
        }
        let mut labels: Vec<Label> = Vec::with_capacity(set.len());
        for recipient in set {
            let label = recipient.label.clone().or_else(|| {
                rule.recipients
                    .iter()
                    .find(|old| old.key == recipient.key)
                    .and_then(|old| old.label.clone())
            });
            let Some(label) = label else {
                // Keep whatever the line said rather than lose or shift labels.
                return if rule.comment.raw.is_empty() {
                    String::new()
                } else {
                    format!(" # {}", rule.comment.raw)
                };
            };
            labels.push(label);
        }
        if labels.is_empty() {
            return String::new();
        }
        let joined = labels
            .iter()
            .map(|label| label.as_str())
            .collect::<Vec<_>>()
            .join(",");
        format!(" # {joined}")
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
    fn render_keeps_a_crlf_file_crlf() {
        let text = format!(
            "# kept\r\ncreation_rules:\r\n- path_regex: secrets/prod/infra\\.env$\r\n  age: {A},{B} # admin,recovery\r\n"
        );
        let file = SopsFile::parse(&text).unwrap();
        let mut sets: Vec<Vec<Recipient>> =
            file.rules().iter().map(|r| r.recipients.clone()).collect();
        sets[0].push(Recipient {
            key: PubKey::parse(C).unwrap(),
            label: Some(Label::parse("ci").unwrap()),
        });

        let out = file.render_with(&sets).unwrap();

        assert!(out.contains("\r\n"), "no CRLF left: {out:?}");
        assert!(
            !out.replace("\r\n", "").contains('\n'),
            "mixed line endings: {out:?}"
        );
        assert!(out.contains(C), "{out}");
        let again = SopsFile::parse(&out).unwrap();
        assert_eq!(again.rules()[0].recipients.len(), 3);
    }

    #[test]
    fn a_free_text_comment_survives_a_rewrite() {
        let text = format!(
            "creation_rules:\n- path_regex: secrets/.*\\.env$\n  age: {A},{B} # admin,recovery (managed by terraform)\n"
        );
        let file = SopsFile::parse(&text).unwrap();
        assert_eq!(file.rules()[0].comment.labels, None);
        let mut sets: Vec<Vec<Recipient>> =
            file.rules().iter().map(|r| r.recipients.clone()).collect();
        sets[0].push(Recipient {
            key: PubKey::parse(C).unwrap(),
            label: Some(Label::parse("dev-alice").unwrap()),
        });

        let out = file.render_with(&sets).unwrap();

        assert!(
            out.contains(" # admin,recovery (managed by terraform)\n"),
            "free text must survive: {out}"
        );
        assert!(out.contains(C), "{out}");
        assert!(SopsFile::parse(&out).is_ok());
    }

    #[test]
    fn a_label_only_comment_is_regenerated() {
        let file = SopsFile::parse(&fixture()).unwrap();
        assert!(file.rules()[0].comment.labels.is_some());
        let mut sets: Vec<Vec<Recipient>> =
            file.rules().iter().map(|r| r.recipients.clone()).collect();
        sets[0].retain(|r| r.key.as_str() != B);

        let out = file.render_with(&sets).unwrap();

        let first = out
            .lines()
            .find(|line| line.starts_with("  age: ") && !line.contains(B))
            .unwrap_or_default();
        assert_eq!(first, format!("  age: {A},{C} # admin,ci"), "{out}");
        assert!(!first.contains("recovery"), "{out}");
    }

    #[test]
    fn a_partial_label_list_is_kept_rather_than_misaligned() {
        let text =
            format!("creation_rules:\n- path_regex: secrets/.*\\.env$\n  age: {A},{B} # admin\n");
        let file = SopsFile::parse(&text).unwrap();
        let mut sets: Vec<Vec<Recipient>> =
            file.rules().iter().map(|r| r.recipients.clone()).collect();
        sets[0].push(Recipient {
            key: PubKey::parse(C).unwrap(),
            label: None,
        });

        let out = file.render_with(&sets).unwrap();

        assert!(
            out.contains(" # admin\n"),
            "the partial list stays as it was: {out}"
        );
    }

    #[test]
    fn mixed_rules_parse_and_report_per_rule() {
        let text = format!(
            "creation_rules:\n- path_regex: secrets/age/.*\\.env$\n  age: {A},{B} # admin,recovery\n- path_regex: secrets/kms/.*\\.env$\n  kms: arn:aws:kms:eu-west-1:1:key/abc\n- path_regex: secrets/bare/.*\\.env$\n"
        );

        let file = SopsFile::parse(&text).expect("a mixed file must parse");

        assert_eq!(file.rules().len(), 3);
        assert_eq!(file.rules()[0].kind, RuleKind::Age);
        assert_eq!(file.rules()[1].kind, RuleKind::Other("kms".into()));
        assert_eq!(file.rules()[1].backend(), "kms");
        assert_eq!(file.rules()[2].kind, RuleKind::None);
        assert_eq!(file.rules()[2].backend(), "no recipients");
        let reported: Vec<&str> = file
            .non_age_rules()
            .iter()
            .map(|rule| rule.path_regex.as_str())
            .collect();
        assert_eq!(
            reported,
            ["secrets/kms/.*\\.env$", "secrets/bare/.*\\.env$"]
        );
    }

    #[test]
    fn rendering_leaves_a_non_age_rule_byte_identical() {
        let text = format!(
            "creation_rules:\n- path_regex: secrets/age/.*\\.env$\n  age: {A},{B} # admin,recovery\n- path_regex: secrets/kms/.*\\.env$\n  kms: arn:aws:kms:eu-west-1:1:key/abc\n"
        );
        let file = SopsFile::parse(&text).unwrap();
        let mut sets: Vec<Vec<Recipient>> = file
            .rules()
            .iter()
            .map(|rule| rule.recipients.clone())
            .collect();
        sets[0].push(Recipient {
            key: PubKey::parse(C).unwrap(),
            label: Some(Label::parse("ci").unwrap()),
        });

        let out = file.render_with(&sets).unwrap();

        assert!(out.contains(C), "the age rule changed: {out}");
        assert!(
            out.contains("  kms: arn:aws:kms:eu-west-1:1:key/abc\n"),
            "the kms rule must stay byte-identical: {out}"
        );
        assert!(SopsFile::parse(&out).is_ok());
    }

    #[test]
    fn asking_to_rewrite_a_non_age_rule_is_an_internal_error() {
        let text = "creation_rules:\n- path_regex: secrets/kms/.*\\.env$\n  kms: arn:aws:kms:eu:1:key/abc\n";
        let file = SopsFile::parse(text).unwrap();
        let sets = vec![vec![Recipient {
            key: PubKey::parse(A).unwrap(),
            label: None,
        }]];

        let error = file.render_with(&sets).unwrap_err();

        assert!(error.to_string().contains("no age: line"), "{error}");
    }

    #[test]
    fn a_crlf_map_round_trips_byte_for_byte_when_nothing_changes() {
        let text = format!(
            "# kept\r\ncreation_rules:\r\n- path_regex: secrets/.*\\.env$\r\n  age: {A},{B} # admin,recovery (managed by terraform)\r\n"
        );
        let file = SopsFile::parse(&text).unwrap();
        let sets: Vec<Vec<Recipient>> = file.rules().iter().map(|r| r.recipients.clone()).collect();

        let out = file.render_with(&sets).unwrap();

        assert_eq!(out, text, "a no-op rewrite must not touch one byte");
    }

    #[test]
    fn a_crlf_map_keeps_every_line_ending_when_an_age_line_changes() {
        let text = format!(
            "# kept\r\ncreation_rules:\r\n- path_regex: secrets/.*\\.env$\r\n  age: {A},{B} # admin,recovery\r\n"
        );
        let file = SopsFile::parse(&text).unwrap();
        let mut sets: Vec<Vec<Recipient>> =
            file.rules().iter().map(|r| r.recipients.clone()).collect();
        sets[0].push(Recipient {
            key: PubKey::parse(C).unwrap(),
            label: Some(Label::parse("dev-alice").unwrap()),
        });

        let out = file.render_with(&sets).unwrap();

        assert!(
            out.contains(&format!("age: {A},{B},{C} # admin,recovery,dev-alice\r\n")),
            "{out:?}"
        );
        assert!(
            !out.replace("\r\n", "").contains('\n'),
            "mixed line endings: {out:?}"
        );
        assert!(out.starts_with("# kept\r\ncreation_rules:\r\n"), "{out:?}");
    }

    #[test]
    fn flags_drift() {
        let text =
            format!("creation_rules:\n- path_regex: secrets/prod/infra\\.env$\n  age: {A},{B}\n");
        let f = SopsFile::parse(&text).unwrap();
        assert_eq!(f.drift().len(), 2);
    }
}
