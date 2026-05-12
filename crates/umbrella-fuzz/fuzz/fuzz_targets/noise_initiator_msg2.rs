#![no_main]
//! libFuzzer target: Noise_IK initiator на произвольном `msg2` не паникует.
//! libFuzzer target: Noise_IK initiator on arbitrary `msg2` doesn't panic.
//!
//! Запуск: `cargo +nightly fuzz run noise_initiator_msg2` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run noise_initiator_msg2` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_noise_initiator_msg2(data);
});
