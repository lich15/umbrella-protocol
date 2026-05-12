#![no_main]
//! libFuzzer target: `XWingPublicKey::from_bytes` должен отрабатывать любые байты без panic.
//! libFuzzer target: `XWingPublicKey::from_bytes` must handle any bytes without panic.
//!
//! Запуск: `cargo +nightly fuzz run xwing_pubkey_parser` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run xwing_pubkey_parser` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_xwing_pubkey_parser(data);
});
