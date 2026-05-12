#![no_main]
//! libFuzzer target: `ml_kem_768_decaps` на arbitrary 1088-байтовом
//! ciphertext'е не паникует (FIPS 203 implicit rejection).
//! libFuzzer target: `ml_kem_768_decaps` on an arbitrary 1088-byte
//! ciphertext never panics (FIPS 203 implicit rejection).
//!
//! Block 10.27 (Phase 3 cross-cutting dev crates audit) — закрывает
//! 1 GAP col 1 row 10 KyberSlash в threat × crate matrix block 10.22.
//! Block 10.27 (Phase 3 cross-cutting dev crates audit) — closes the
//! 1 GAP at col 1 row 10 KyberSlash in the block 10.22 threat × crate
//! matrix.
//!
//! Запуск: `cargo +nightly fuzz run ml_kem_decapsulate_fuzz --features pq`
//! (из `crates/umbrella-fuzz/fuzz/`).
//! Invocation: `cargo +nightly fuzz run ml_kem_decapsulate_fuzz --features pq`
//! (from `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_ml_kem_decapsulate(data);
});
