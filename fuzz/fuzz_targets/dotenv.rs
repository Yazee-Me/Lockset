#![no_main]

use libfuzzer_sys::fuzz_target;
use lockset_core::{dotenv, meta};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for (name, value) in dotenv::parse(text) {
        assert!(meta::is_name(&name), "dotenv returned an invalid name: {name:?}");
        // A value never spans lines; a trailing CR is a line ending, an
        // embedded one stays part of the value (it cannot start a new env line).
        assert!(!value.contains('\n'), "a value spans lines: {value:?}");
        // No further name filter: `sops_*` keys are ordinary names to this
        // generic parser. sops writes its metadata only in the encrypted file,
        // decrypt strips it, and `meta` filters it for findings.
    }
});
