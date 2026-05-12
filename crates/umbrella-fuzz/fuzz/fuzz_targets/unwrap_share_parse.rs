#![no_main]
//! libFuzzer target: `ServerUnwrapShare::from_bytes` должен отрабатывать любые байты без panic.
//! libFuzzer target: `ServerUnwrapShare::from_bytes` must handle any bytes without panic.
//!
//! Запуск: `cargo +nightly fuzz run unwrap_share_parse` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run unwrap_share_parse` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_unwrap_share_parse(data);
});
