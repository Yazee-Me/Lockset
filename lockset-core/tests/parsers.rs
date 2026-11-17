//! Parser properties: the parsers never panic, successful values are
//! canonical, and rendering is idempotent. These are the invariants a
//! hand-written fuzz target exercises harder; proptest runs them in the normal
//! test suite on every OS.

use lockset_core::config::Config;
use lockset_core::model::{Label, PubKey};
use lockset_core::sopsfile::{Recipient, SopsFile};
use lockset_core::{dotenv, meta, PathId};
use proptest::prelude::*;
use proptest::string::string_regex;

/// Text that looks like a path or config: separators, dots, colons, quotes,
/// and control characters a shell or YAML parser might see.
fn messy() -> impl Strategy<Value = String> {
    string_regex(r#"[A-Za-z0-9_./\\: \t\n'"${}-]{0,60}"#).unwrap()
}

fn dotenv_ish() -> impl Strategy<Value = String> {
    string_regex(r#"[A-Za-z0-9_=.# \t\n'\"]{0,80}"#).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn path_ids_never_panic_and_are_canonical(text in messy()) {
        match PathId::parse(&text) {
            Ok(id) => {
                let value = id.as_str();
                prop_assert!(!value.contains('\\'), "{value:?} keeps a backslash");
                prop_assert!(!value.starts_with('/'), "{value:?} is absolute");
                prop_assert!(
                    value.split('/').all(|segment| {
                        !segment.is_empty()
                            && segment != "."
                            && segment != ".."
                            && !segment.contains(':')
                    }),
                    "{value:?} has an ambiguous segment"
                );
                // Canonical input parses to itself.
                let again = PathId::parse(value).expect("the canonical form parses");
                prop_assert_eq!(again.as_str(), value);
            }
            Err(error) => {
                prop_assert!(!error.to_string().is_empty());
            }
        }
    }

    #[test]
    fn dotenv_parse_never_panics_and_keeps_names_valid(text in dotenv_ish()) {
        for (name, value) in dotenv::parse(&text) {
            prop_assert!(meta::is_name(&name), "{name:?} is not a valid name");
            prop_assert!(!value.contains(['\r', '\n']), "{value:?} has a newline");
            prop_assert!(!name.starts_with("sops_"), "{name:?} is metadata");
        }
    }

    #[test]
    fn sopsfile_parse_never_panics_and_render_is_idempotent(text in dotenv_ish()) {
        match SopsFile::parse(&text) {
            Ok(file) => {
                let sets: Vec<Vec<Recipient>> = file
                    .rules()
                    .iter()
                    .map(|rule| rule.recipients.clone())
                    .collect();
                let rendered = file.render_with(&sets).expect("a no-op render");
                prop_assert_eq!(&rendered, file.text(), "a no-op render changed the file");
                // A rendered file still parses.
                prop_assert!(SopsFile::parse(&rendered).is_ok());
            }
            Err(error) => {
                prop_assert!(!error.to_string().is_empty());
            }
        }
    }

    #[test]
    fn meta_parse_never_panics(text in dotenv_ish()) {
        if let Ok(id) = PathId::parse("secrets/dev.env") {
            let _ = meta::parse(id, &text);
        }
    }

    #[test]
    fn labels_and_keys_never_panic(text in messy()) {
        let _ = Label::parse(&text);
        let _ = PubKey::parse(&text);
    }

    #[test]
    fn config_parse_never_panics(text in dotenv_ish()) {
        let _ = Config::parse(&text);
    }
}
