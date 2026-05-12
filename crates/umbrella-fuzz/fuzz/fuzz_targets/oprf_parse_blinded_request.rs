#![no_main]
//! libFuzzer target: `BlindedRequest::from_bytes` должен отрабатывать любые байты без panic.
//! libFuzzer target: `BlindedRequest::from_bytes` must handle any bytes without panic.
//!
//! Запуск: `cargo +nightly fuzz run oprf_parse_blinded_request` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run oprf_parse_blinded_request` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_oprf_parse_blinded_request(data);
});
