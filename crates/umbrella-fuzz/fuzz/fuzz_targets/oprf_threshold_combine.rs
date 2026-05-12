#![no_main]
//! libFuzzer target: `threshold_combine` должен отрабатывать любые байты без panic.
//! libFuzzer target: `threshold_combine` must handle any bytes without panic.
//!
//! Запуск: `cargo +nightly fuzz run oprf_threshold_combine` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run oprf_threshold_combine` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_oprf_threshold_combine(data);
});
