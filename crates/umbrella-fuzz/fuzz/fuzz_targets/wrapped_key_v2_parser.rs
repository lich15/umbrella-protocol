#![no_main]
//! libFuzzer target: `WrappedKeyV2::from_bytes` должен отрабатывать любые байты без panic.
//! libFuzzer target: `WrappedKeyV2::from_bytes` must handle any bytes without panic.
//!
//! Запуск: `cargo +nightly fuzz run wrapped_key_v2_parser` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run wrapped_key_v2_parser` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_wrapped_key_v2_parser(data);
});
