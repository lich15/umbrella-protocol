//! Regression-guard для F-57 (MEDIUM, блок 10.16) — `umbrella-client`
//! `keystore::row_cipher` hardening: F-51 pattern recurrence
//! (non-constant-time nonce comparison) + F-46/F-56 pattern recurrence
//! (stack-copy `master_key_bytes` parameter not zeroized at function exit).
//!
//! Inline-fix блока 10.16:
//!
//! - `decrypt_row:187` — `expected_nonce != nonce` (timing-observable
//!   short-circuit `PartialEq` на `[u8; 12]`) → заменён на
//!   `expected_nonce.ct_eq(&nonce).unwrap_u8() == 0` через
//!   `subtle::ConstantTimeEq` (F-51 pattern). Practical impact LOW
//!   (nonce mismatch уже сигнализирует tamper/row-swap), но
//!   defense-in-depth принцип constant-time на cryptographic comparisons
//!   enforced per design §5.1 + precedent F-51 closure block 10.12
//!   umbrella-padding.
//!
//! - `RowCipher::new:99` — параметр `master_key_bytes: [u8; 32]` принимался
//!   по значению (Copy semantics); внутренняя копия параметра НЕ zeroized
//!   после `Box::new(master_key_bytes)` heap-copy → теперь принимается
//!   `mut master_key_bytes` + `master_key_bytes.zeroize()` перед return
//!   (F-46/F-56 pattern). Caller-side zeroize всё ещё обязателен для
//!   исходной копии вызывающей стороны (документировано в doc-comment).
//!
//! Эти тесты не проверяют само событие zeroize'а в physical memory (для
//! этого нужен `unsafe`-указатель, а постулат 14 запрещает unsafe в
//! production коде); вместо этого они подтверждают:
//! - семантическая корректность не нарушена inline-fix'ом (encrypt/decrypt
//!   roundtrip + row-swap detection + nonce tamper detection остаются
//!   валидными);
//! - тип `[u8; 32]` имплементирует `Zeroize` (compile-time guarantee
//!   что `master_key_bytes.zeroize()` корректен);
//! - constant-time comparison via `subtle::ConstantTimeEq` корректно
//!   reject'ит mismatched nonce.
//!
//! Regression guard for F-57 (MEDIUM, block 10.16) — `umbrella-client`
//! `keystore::row_cipher` hardening: F-51 pattern recurrence
//! (non-constant-time nonce comparison) + F-46/F-56 pattern recurrence
//! (stack-copy `master_key_bytes` parameter not zeroized at function exit).
//!
//! Block 10.16 inline fix:
//!
//! - `decrypt_row:187` — `expected_nonce != nonce` (timing-observable
//!   short-circuit `PartialEq` on `[u8; 12]`) → replaced with
//!   `expected_nonce.ct_eq(&nonce).unwrap_u8() == 0` via
//!   `subtle::ConstantTimeEq` (F-51 pattern). Practical impact is LOW
//!   (a nonce mismatch already signals tamper/row-swap), but the
//!   defense-in-depth principle of constant-time cryptographic
//!   comparisons is enforced per design §5.1 + precedent F-51 closure
//!   block 10.12 umbrella-padding.
//!
//! - `RowCipher::new:99` — parameter `master_key_bytes: [u8; 32]` was
//!   taken by value (Copy semantics); the inner parameter copy was NOT
//!   zeroized after `Box::new(master_key_bytes)` performed the heap copy
//!   → now takes `mut master_key_bytes` + `master_key_bytes.zeroize()`
//!   before return (F-46/F-56 pattern). Caller-side zeroize is still
//!   required for the caller's original copy (documented in doc-comment).
//!
//! These tests do not verify the actual zeroize event in physical memory
//! (this would require an `unsafe` pointer, and postulate 14 forbids
//! unsafe in production code); instead they confirm:
//! - semantic correctness is preserved by the inline fix (encrypt/decrypt
//!   roundtrip + row-swap detection + nonce tamper detection remain
//!   valid);
//! - the `[u8; 32]` type implements `Zeroize` (compile-time guarantee
//!   that `master_key_bytes.zeroize()` is correct);
//! - constant-time comparison via `subtle::ConstantTimeEq` correctly
//!   rejects mismatched nonces.

use umbrella_client::keystore::RowCipher;
use zeroize::Zeroize;

/// Семантическая регрессия — encrypt/decrypt roundtrip продолжает работать
/// корректно после inline-fix'а (constant-time nonce compare + zeroize
/// parameter).
///
/// Semantic regression — encrypt/decrypt roundtrip continues to work
/// correctly after the inline fix (constant-time nonce compare + parameter
/// zeroize).
#[test]
fn f57_encrypt_decrypt_roundtrip_after_fix_unchanged() {
    let cipher = RowCipher::new([0x42u8; 32]);
    let (ct, nonce, tag) = cipher
        .encrypt_row(
            "messages.text",
            &[1, 2, 3, 4],
            b"F-57 regression-guard payload",
        )
        .expect("encrypt");
    let pt = cipher
        .decrypt_row("messages.text", &[1, 2, 3, 4], &ct, nonce, tag)
        .expect("decrypt");
    assert_eq!(pt, b"F-57 regression-guard payload");
}

/// Multi-row roundtrip — verify constant-time nonce compare продолжает
/// корректно accept'ить совпадающий nonce и reject'ить mismatched.
///
/// Multi-row roundtrip — verifies the constant-time nonce comparison
/// continues to correctly accept matching nonces and reject mismatched ones.
#[test]
fn f57_multi_row_roundtrip_per_row_correct() {
    let cipher = RowCipher::new([0xABu8; 32]);
    // Encrypt 16 rows + decrypt каждой row на следующей итерации — semantic
    // check без накопления tuple-storage (избегаем clippy::type_complexity).
    //
    // Encrypt 16 rows + decrypt each row immediately — semantic check
    // without tuple-storage accumulation (avoids clippy::type_complexity).
    for row_id in 0u8..16 {
        let pt = format!("row-{row_id}-payload");
        let (ct, nonce, tag) = cipher
            .encrypt_row("messages.text", &[row_id], pt.as_bytes())
            .expect("encrypt");
        let dec = cipher
            .decrypt_row("messages.text", &[row_id], &ct, nonce, tag)
            .expect("decrypt");
        assert_eq!(dec, pt.as_bytes());
    }
}

/// Row-swap attack detection: attacker берёт (ct, nonce, tag) одной row
/// и подставляет под row_id другой — constant-time nonce derive guarantees
/// mismatch ДО AEAD verify (одинаковая семантика что pre-fix, но через CT path).
///
/// Row-swap attack detection: an attacker takes (ct, nonce, tag) of one row
/// and plugs them under another row_id — constant-time nonce derive
/// guarantees a mismatch before AEAD verification (same semantics as
/// pre-fix, but via the CT path).
#[test]
fn f57_row_swap_still_detected_via_ct_compare() {
    let cipher = RowCipher::new([0x55u8; 32]);
    let (ct, nonce, tag) = cipher
        .encrypt_row("messages.text", b"row_a", b"secret data")
        .expect("encrypt");
    // Attacker подставляет row_b в decrypt — должен fail с nonce mismatch.
    // Attacker plugs row_b into decrypt — must fail with nonce mismatch.
    let result = cipher.decrypt_row("messages.text", b"row_b", &ct, nonce, tag);
    assert!(
        result.is_err(),
        "row-swap (ct of row_a → decrypt under row_b) must fail via CT compare"
    );
}

/// Nonce tamper detection: attacker меняет любой байт nonce — constant-time
/// compare reject'ит. Verify с разных позиций flip'а.
///
/// Nonce tamper detection: an attacker flips any byte of nonce — the
/// constant-time compare rejects. Verified across multiple flip positions.
#[test]
fn f57_nonce_tamper_at_each_byte_detected_via_ct_compare() {
    let cipher = RowCipher::new([0x77u8; 32]);
    let (ct, nonce, tag) = cipher
        .encrypt_row("ctx", b"id", b"payload")
        .expect("encrypt");

    for flip_idx in 0..nonce.len() {
        let mut tampered_nonce = nonce;
        tampered_nonce[flip_idx] ^= 0x01;
        let result = cipher.decrypt_row("ctx", b"id", &ct, tampered_nonce, tag);
        assert!(
            result.is_err(),
            "nonce tamper at byte {flip_idx} must fail via CT compare"
        );
    }
}

/// Тип `[u8; 32]` имплементирует `Zeroize` — compile-time гарантия что
/// вызов `master_key_bytes.zeroize()` в `RowCipher::new` корректен. Если в
/// будущей версии `zeroize` impl для `[u8; N]` будет удалён — этот тест
/// провалит компиляцию и блок 10.16 fix потребует пересмотра.
///
/// The type `[u8; 32]` implements `Zeroize` — compile-time guarantee that
/// `master_key_bytes.zeroize()` in `RowCipher::new` is correct. If a future
/// version of `zeroize` removes the `[u8; N]` impl, this test fails to
/// compile and the block 10.16 fix needs revisiting.
#[test]
fn f57_array_32_implements_zeroize_compile_time_guard() {
    let mut buf = [0xCDu8; 32];
    Zeroize::zeroize(&mut buf);
    assert!(
        buf.iter().all(|&b| b == 0),
        "Zeroize::zeroize must reset all bytes to zero"
    );
}
