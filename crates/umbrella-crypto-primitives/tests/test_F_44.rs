//! Adversarial test для F-44 — `sha256_with_label` domain-separation collision, если label
//! содержит байт 0x00.
//! Adversarial test for F-44 — `sha256_with_label` domain-separation collision when the
//! label contains a 0x00 byte.
//!
//! Контекст / Context:
//! Конструкция `hash(label || 0x00 || data...)` устанавливает domain separation между
//! разными `label` значениями ТОЛЬКО при условии что `label` НЕ содержит байт `0x00`.
//! Если label может содержать `0x00` — возможна структурная коллизия:
//!   `(label="ab", data=["c\x00xyz"])` ↦ hash `SHA256("ab\x00c\x00xyz")`
//!   `(label="ab\x00c", data=["xyz"])` ↦ hash `SHA256("ab\x00c\x00xyz")`
//! Это идентичные хеши при разных `(label, data)` парах ↦ возможный сценарий несоответствия
//! в transcript hashing если label выбирается atacker-controlled.
//!
//! The construction `hash(label || 0x00 || data...)` provides domain separation between
//! distinct `label` values ONLY when the `label` does NOT contain a `0x00` byte. If labels
//! may contain `0x00`, a structural collision exists:
//!   `(label="ab", data=["c\x00xyz"])` ↦ hash `SHA256("ab\x00c\x00xyz")`
//!   `(label="ab\x00c", data=["xyz"])` ↦ hash `SHA256("ab\x00c\x00xyz")`
//! These are identical hashes for distinct `(label, data)` pairs ↦ a transcript-mismatch
//! scenario if the label is attacker-controlled.
//!
//! Mitigation status (block 10.5b): labels constrained к `&'static [u8]` (compile-time
//! controlled) + наша конвенция `umbrellax-<purpose>-vN` ASCII-only + `debug_assert!`
//! catches violations during development. Severity LOW (theoretical, no realized exposure).
//!
//! Этот тест документирует свойство коллизии (ИНФОРМАЦИОННО, не failing) + проверяет что
//! debug_assert ловит нарушения в debug сборках.
//!
//! Mitigation status (block 10.5b): labels constrained to `&'static [u8]` (compile-time
//! controlled) + our convention `umbrellax-<purpose>-vN` ASCII-only + `debug_assert!`
//! catches violations during development. Severity LOW (theoretical, no realized exposure).
//!
//! This test documents the collision property (INFORMATIONAL, not failing) + verifies
//! that `debug_assert!` catches violations in debug builds.

use sha2::{Digest, Sha256};

/// Документирует структурную коллизию sha256(label || 0x00 || data) при label с 0x00 байтом.
/// Documents the structural collision of sha256(label || 0x00 || data) when label contains 0x00.
#[test]
fn f_44_collision_demonstrated_when_label_contains_null_byte() {
    // Pair 1: label = "ab", data = "c\x00xyz"
    let mut h1 = Sha256::new();
    h1.update(b"ab"); // simulated label without 0x00
    h1.update([0x00]); // mandatory separator
    h1.update(b"c\x00xyz"); // data which contains 0x00 byte
    let hash1 = h1.finalize();

    // Pair 2: label = "ab\x00c", data = "xyz"
    let mut h2 = Sha256::new();
    h2.update(b"ab\x00c"); // simulated label which (illegally) contains 0x00
    h2.update([0x00]); // mandatory separator
    h2.update(b"xyz"); // clean data
    let hash2 = h2.finalize();

    // Both result in SHA256("ab\x00c\x00xyz") — identical hash, distinct (label, data) inputs.
    assert_eq!(
        hash1, hash2,
        "F-44 documented property: collision exists when label contains 0x00 byte; \
         our `&'static [u8]` ASCII-convention labels prevent realized exposure."
    );
}

/// Verifies debug_assert ловит нарушение в debug-сборке (skipped в release).
/// Verifies debug_assert catches the violation in debug builds (skipped in release).
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "domain-separation label must not contain 0x00 byte")]
fn f_44_debug_assert_catches_null_byte_label_sha256() {
    // Static label с 0x00 byte (нарушение конвенции).
    static BAD_LABEL: &[u8] = b"bad\x00label";
    // должен panic в debug; пропустить в release.
    let _ = umbrella_crypto_primitives::hash::sha256_with_label(BAD_LABEL, &[b"data"]);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "domain-separation label must not contain 0x00 byte")]
fn f_44_debug_assert_catches_null_byte_label_sha512() {
    static BAD_LABEL: &[u8] = b"bad\x00label";
    let _ = umbrella_crypto_primitives::hash::sha512_with_label(BAD_LABEL, &[b"data"]);
}

/// Sanity: valid ASCII label (umbrellax-* convention) работает без проблем.
/// Sanity: valid ASCII label (umbrellax-* convention) works without issue.
#[test]
fn f_44_clean_label_no_panic() {
    static GOOD_LABEL: &[u8] = b"umbrellax-test-v1";
    let h = umbrella_crypto_primitives::hash::sha256_with_label(GOOD_LABEL, &[b"data"]);
    assert_eq!(h.len(), 32);
}
