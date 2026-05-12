#![no_main]
//! libFuzzer target: `unseal_v2` full pipeline не паникует на arbitrary V2 envelope wire bytes.
//! libFuzzer target: `unseal_v2` full pipeline never panics on arbitrary V2 envelope wire bytes.
//!
//! Запуск: `cargo +nightly fuzz run sealed_sender_v2_parser` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run sealed_sender_v2_parser` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_sealed_sender_v2_parser(data);
});
