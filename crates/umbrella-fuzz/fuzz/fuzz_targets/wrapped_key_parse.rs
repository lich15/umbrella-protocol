#![no_main]
//! libFuzzer target: `WrappedKey::from_bytes` должен отрабатывать любые байты без panic.
//! libFuzzer target: `WrappedKey::from_bytes` must handle any bytes without panic.
//!
//! Запуск: `cargo +nightly fuzz run wrapped_key_parse` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run wrapped_key_parse` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_wrapped_key_parse(data);
});
