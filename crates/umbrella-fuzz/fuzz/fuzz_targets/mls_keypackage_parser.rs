#![no_main]
//! libFuzzer target: `KeyPackageIn::tls_deserialize` должен отрабатывать любые байты без panic.
//! libFuzzer target: `KeyPackageIn::tls_deserialize` must handle any bytes without panic.
//!
//! Запуск: `cargo +nightly fuzz run mls_keypackage_parser` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run mls_keypackage_parser` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_mls_keypackage_parser(data);
});
