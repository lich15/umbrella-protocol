//! libFuzzer binary для SFrame header parser (RFC 9605 §4).
//! libFuzzer binary for SFrame header parser (RFC 9605 §4).
//!
//! Run: `cargo +nightly fuzz run fuzz_sframe_header_parse`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use umbrella_fuzz::fuzz_sframe_header_parse;

fuzz_target!(|data: &[u8]| {
    fuzz_sframe_header_parse(data);
});
