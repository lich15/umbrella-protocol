#![no_main]
//! libFuzzer target: KT Merkle `verify_inclusion` должен отрабатывать любые байты без panic.
//! libFuzzer target: KT Merkle `verify_inclusion` must handle any bytes without panic.
//!
//! Запуск: `cargo +nightly fuzz run verify_inclusion` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run verify_inclusion` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_verify_inclusion(data);
});
