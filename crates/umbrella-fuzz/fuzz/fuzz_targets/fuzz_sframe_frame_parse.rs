//! libFuzzer binary для full SFrame frame parser через SframeContext.
//! libFuzzer binary for full SFrame frame parser via SframeContext.
//!
//! Run: `cargo +nightly fuzz run fuzz_sframe_frame_parse`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use umbrella_fuzz::fuzz_sframe_frame_parse;

fuzz_target!(|data: &[u8]| {
    fuzz_sframe_frame_parse(data);
});
