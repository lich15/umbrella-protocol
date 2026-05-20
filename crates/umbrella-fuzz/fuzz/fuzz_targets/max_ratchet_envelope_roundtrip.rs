#![no_main]
//! libFuzzer target: `encode_v3 → try_decode_v3` roundtrip invariant. Любое sufficiently
//! long structurally-derived input через encode_v3 должен decode'иться bit-exact для всех
//! structural fields. Закрывает Task 3 carry-over из max_ratchet v3 spec 2026-05-21.
//!
//! libFuzzer target: `encode_v3 → try_decode_v3` roundtrip invariant. For any sufficiently
//! long structurally-split input, encoded bundle must decode bit-exact to original commit /
//! ciphertext / mac fields. Closes Task 3 carry-over.
//!
//! Запуск: `cargo +nightly fuzz run max_ratchet_envelope_roundtrip` (из каталога
//! `crates/umbrella-fuzz/fuzz/`).
//!
//! Run: `cargo +nightly fuzz run max_ratchet_envelope_roundtrip` (from
//! `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

// Task 3 (2026-05-21): codec lives в umbrella-mls; функция exported из umbrella-fuzz
// под host-crate feature `pq` (active через fuzz/Cargo.toml `features = ["pq"]`).
fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_max_ratchet_envelope_roundtrip(data);
});
