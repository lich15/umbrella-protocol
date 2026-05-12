#![no_main]
//! libFuzzer target: `xwing_decaps` на arbitrary 1120-байтовом ciphertext'е не паникует.
//! libFuzzer target: `xwing_decaps` on an arbitrary 1120-byte ciphertext never panics.
//!
//! Запуск: `cargo +nightly fuzz run xwing_ciphertext_parser` (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run xwing_ciphertext_parser` (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_xwing_ciphertext_parser(data);
});
