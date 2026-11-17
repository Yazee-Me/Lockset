#![no_main]

use libfuzzer_sys::fuzz_target;
use lockset_core::config::Config;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Parsing arbitrary text must answer with a value or an error, never a
    // panic or an internal invariant violation.
    let _ = Config::parse(text);
});
