#![no_main]
//! libFuzzer target: `parse_mls_envelope` должен отрабатывать на любом входе без panic.
//! libFuzzer target: `parse_mls_envelope` must handle any input without panicking.
//!
//! Запуск: `cargo +nightly fuzz run parse_mls_envelope` (из каталога `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run parse_mls_envelope` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_parse_mls_envelope(data);
});
