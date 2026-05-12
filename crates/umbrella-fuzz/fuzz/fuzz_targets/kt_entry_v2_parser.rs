#![no_main]
//! libFuzzer target: `KtEntryV2::from_bytes` должен отрабатывать любые байты без panic.
//! libFuzzer target: `KtEntryV2::from_bytes` must handle any bytes without panic.
//!
//! Запуск: `cargo +nightly fuzz run kt_entry_v2_parser` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run kt_entry_v2_parser` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_kt_entry_v2_parser(data);
});
