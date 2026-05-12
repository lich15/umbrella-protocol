#![no_main]
//! libFuzzer target: `HybridSignature::from_bytes` должен отрабатывать любые байты без panic.
//! libFuzzer target: `HybridSignature::from_bytes` must handle any bytes without panic.
//!
//! Запуск: `cargo +nightly fuzz run hybrid_signature_parser` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run hybrid_signature_parser` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_hybrid_signature_parser(data);
});
