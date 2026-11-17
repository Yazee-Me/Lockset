#![no_main]

use libfuzzer_sys::fuzz_target;
use lockset_core::sopsfile::{Recipient, SopsFile};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(file) = SopsFile::parse(text) else {
        return;
    };
    let sets: Vec<Vec<Recipient>> = file
        .rules()
        .iter()
        .map(|rule| rule.recipients.clone())
        .collect();
    // A rewrite with the same recipients is byte-identical, and the result
    // still parses.
    let rendered = file.render_with(&sets).expect("a no-op render succeeds");
    assert_eq!(rendered, file.text());
    SopsFile::parse(&rendered).expect("a rendered file parses");
});
