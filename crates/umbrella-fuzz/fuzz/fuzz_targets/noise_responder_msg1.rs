#![no_main]
//! libFuzzer target: Noise_IK responder на произвольном `msg1` не паникует.
//! libFuzzer target: Noise_IK responder on arbitrary `msg1` doesn't panic.
//!
//! Запуск: `cargo +nightly fuzz run noise_responder_msg1` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run noise_responder_msg1` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_noise_responder_msg1(data);
});
