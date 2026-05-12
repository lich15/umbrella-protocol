#![no_main]
//! libFuzzer target: `strip_padding` должен отрабатывать любые байты без panic.
//! libFuzzer target: `strip_padding` must handle any bytes without panic.
//!
//! Запуск: `cargo +nightly fuzz run strip_padding` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run strip_padding` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_strip_padding(data);
});
