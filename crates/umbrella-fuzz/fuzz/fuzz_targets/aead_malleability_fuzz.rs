#![no_main]
//! libFuzzer target: `aead_malleability_fuzz` — AEAD ChaCha20-Poly1305 decrypt должен либо
//! decrypt валидный ciphertext, либо возвращать `AeadAuthFailure` без panic.
//!
//! libFuzzer target: `aead_malleability_fuzz` — AEAD ChaCha20-Poly1305 decrypt must either
//! decrypt a valid ciphertext or return `AeadAuthFailure` without panicking.
//!
//! Закрывает GAP Level 7 Fuzz × Row 10 KyberSlash из block 10.5b matrix submatrix
//! (`docs/audits/production-readiness-2026-05-09/README.md` line 484
//! «нет fuzz harness directly targeting AEAD/HKDF/SHA primitives»). Активный режим
//! retroactive pass session #65 (block 10.5b-active-retro) добавляет defence-in-depth
//! fuzz target поверх 26 adversarial tests из `tests/test_active_audit.rs`.
//!
//! Closes the GAP at Level 7 Fuzz × Row 10 KyberSlash from the block 10.5b matrix submatrix
//! (`docs/audits/production-readiness-2026-05-09/README.md` line 484 — "no
//! fuzz harness directly targeting AEAD/HKDF/SHA primitives"). The session #65 retroactive
//! active pass (block 10.5b-active-retro) adds a defence-in-depth fuzz target on top of the
//! 26 adversarial tests in `tests/test_active_audit.rs`.
//!
//! Запуск / Invocation: `cargo +nightly fuzz run aead_malleability_fuzz` (из
//! `crates/umbrella-fuzz/fuzz/`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    umbrella_fuzz::fuzz_aead_malleability(data);
});
