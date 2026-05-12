#![no_main]
//! libFuzzer target: `ServerEvaluation::from_bytes` должен отрабатывать любые байты без panic.
//! libFuzzer target: `ServerEvaluation::from_bytes` must handle any bytes without panic.
//!
//! Запуск: `cargo +nightly fuzz run oprf_parse_server_evaluation` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run oprf_parse_server_evaluation` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_oprf_parse_server_evaluation(data);
});
