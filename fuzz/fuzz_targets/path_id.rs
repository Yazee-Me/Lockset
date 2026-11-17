#![no_main]

use libfuzzer_sys::fuzz_target;
use lockset_core::{model::PathId, Error};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match PathId::parse(text) {
        Ok(id) => {
            let value = id.as_str();
            // The canonical form never keeps a separator we reject and always
            // parses back to itself.
            assert!(!value.contains('\\'));
            assert!(!value.starts_with('/'));
            assert!(value.split('/').all(|segment| {
                !segment.is_empty() && segment != "." && segment != ".." && !segment.contains(':')
            }));
            let again = PathId::parse(value).expect("canonical paths parse");
            assert_eq!(again.as_str(), value);
        }
        Err(Error::Invalid(message)) => assert!(!message.is_empty()),
        Err(other) => panic!("a path parse used the wrong error class: {other:?}"),
    }
});
