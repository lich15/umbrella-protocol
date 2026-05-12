//! Regression-guard для F-56 (MEDIUM, блок 10.15) — F-46 pattern recurrence
//! в `umbrella-calls`: stack-копии секретного `sframe_key` в
//! `frame::SframeContext::{encrypt_frame, decrypt_frame}` и stack-копия
//! параметра `mls_exporter_output` в `derive::SframeBaseKey::from_mls_exporter`
//! не зануляются на выходе функции, что нарушает принцип Zeroize-discipline
//! из SPEC-06 §5.1 / §5.2 (по аналогии с F-39 в umbrella-pq и F-50 в
//! umbrella-sealed-sender).
//!
//! Inline-fix блока 10.15:
//! - `frame::SframeContext::encrypt_frame` и `decrypt_frame` передают
//!   `per_kid.key_bytes()` / `per_kid.salt_bytes()` напрямую по ссылке
//!   из `SecretBox` через `expose_secret`-обёртку — никакой stack-копии
//!   секрета.
//! - `derive::SframeBaseKey::from_mls_exporter` принимает параметр
//!   `mut mls_exporter_output: [u8; 64]` и зануляет его перед возвратом
//!   через `Zeroize::zeroize` (паттерн F-46 closure из блока 10.6 — 7 sites
//!   inline-fix через `.zeroize()` на каждом site stack-buffer'а).
//!
//! Эти тесты не проверяют само событие zeroize'а в physical memory (для
//! этого нужен `unsafe`-указатель, а постулат 14 запрещает unsafe в
//! production коде); вместо этого они подтверждают:
//! - семантическая корректность не нарушена inline-fix'ом (encrypt/decrypt
//!   roundtrip остаётся валидным; per-KID derivation остаётся
//!   детерминирован);
//! - тип `[u8; BASE_KEY_LEN]` имплементирует `Zeroize` (compile-time
//!   guarantee что `mls_exporter_output.zeroize()` корректен);
//! - RFC 9605 Appendix C cross-check проходит после fix'а (нет drift'а
//!   key-schedule pipeline'а).
//!
//! Regression guard for F-56 (MEDIUM, block 10.15) — F-46 pattern recurrence
//! in `umbrella-calls`: stack copies of the secret `sframe_key` in
//! `frame::SframeContext::{encrypt_frame, decrypt_frame}` and the stack
//! copy of the `mls_exporter_output` parameter of
//! `derive::SframeBaseKey::from_mls_exporter` are not zeroized at function
//! exit, which violates the Zeroize discipline of SPEC-06 §5.1 / §5.2
//! (analogous to F-39 in umbrella-pq and F-50 in umbrella-sealed-sender).
//!
//! Block 10.15 inline fix:
//! - `frame::SframeContext::encrypt_frame` and `decrypt_frame` pass
//!   `per_kid.key_bytes()` / `per_kid.salt_bytes()` directly by reference
//!   from `SecretBox` via the `expose_secret` wrapper — no stack copy of
//!   the secret.
//! - `derive::SframeBaseKey::from_mls_exporter` takes the parameter
//!   `mut mls_exporter_output: [u8; 64]` and zeroizes it before return via
//!   `Zeroize::zeroize` (F-46 closure pattern from block 10.6 — 7 sites
//!   inline-fix through `.zeroize()` on every stack-buffer site).
//!
//! These tests do not verify the actual zeroize event in physical memory
//! (this would require an `unsafe` pointer, and postulate 14 forbids
//! unsafe in production code); instead they confirm:
//! - semantic correctness is preserved by the inline fix (encrypt/decrypt
//!   roundtrip stays valid; per-KID derivation stays deterministic);
//! - the `[u8; BASE_KEY_LEN]` type implements `Zeroize` (compile-time
//!   guarantee that `mls_exporter_output.zeroize()` is correct);
//! - the RFC 9605 Appendix C cross-check passes after the fix (no
//!   key-schedule pipeline drift).

use umbrella_calls::{
    SframeBaseKey, SframeCiphersuite, SframeContext, BASE_KEY_LEN, SFRAME_KEY_LEN, SFRAME_SALT_LEN,
};
use zeroize::Zeroize;

/// Семантическая регрессия — encrypt/decrypt roundtrip продолжает работать
/// корректно после inline-fix'а (без stack-копий секретного `sframe_key`).
///
/// Если код в `frame.rs` будет случайно «откачен» к старому варианту
/// `let key = *per_kid.key_bytes();` — этот тест продолжит проходить (он
/// проверяет только функциональность, не наличие stack-копии). Однако его
/// присутствие документирует ожидание: roundtrip должен оставаться clean
/// после ANY изменения в этом scope. Любая семантическая регрессия
/// (например, неверный `aad` или `nonce`-derivation) сразу провалит этот
/// тест.
///
/// Semantic regression — encrypt/decrypt roundtrip continues to work
/// correctly after the inline fix (no stack copies of the secret
/// `sframe_key`).
///
/// If the code in `frame.rs` is accidentally rolled back to the old
/// `let key = *per_kid.key_bytes();` form, this test still passes (it
/// only checks functionality, not the absence of a stack copy). However,
/// its presence documents the expectation: the roundtrip must stay clean
/// after ANY change in this scope. Any semantic regression (a wrong `aad`
/// or `nonce` derivation) will immediately fail this test.
#[test]
fn f56_encrypt_decrypt_roundtrip_after_fix_unchanged() {
    let mut tx = SframeContext::new();
    tx.advance_epoch(SframeBaseKey::from_mls_exporter(
        [0x42; BASE_KEY_LEN],
        SframeCiphersuite::Aes256GcmSha512,
        7,
    ));
    let mut rx = SframeContext::new();
    rx.advance_epoch(SframeBaseKey::from_mls_exporter(
        [0x42; BASE_KEY_LEN],
        SframeCiphersuite::Aes256GcmSha512,
        7,
    ));

    let plaintext = b"F-56 regression-guard payload";
    let ct = tx.encrypt_frame(3, 100, plaintext).unwrap();
    let dec = rx.decrypt_frame(&ct).unwrap();

    assert_eq!(dec.plaintext, plaintext);
    assert_eq!(dec.counter, 100);
    assert_eq!(dec.sender_leaf, 3);
    assert_eq!(dec.epoch, 7);
}

/// Multi-frame: проверяем что несколько кадров от одного sender'а в одной
/// эпохе шифруются и расшифровываются корректно — это покрывает повторное
/// обращение к `per_kid.key_bytes()` (после fix'а — ссылка вместо копии).
///
/// Multi-frame: verifies that multiple frames from a single sender in a
/// single epoch encrypt/decrypt correctly — this covers repeated access
/// to `per_kid.key_bytes()` (after the fix — reference instead of copy).
#[test]
fn f56_multi_frame_roundtrip_per_kid_cache_unchanged() {
    let mut tx = SframeContext::new();
    tx.advance_epoch(SframeBaseKey::from_mls_exporter(
        [0xAB; BASE_KEY_LEN],
        SframeCiphersuite::Aes256GcmSha512,
        0,
    ));
    let mut rx = SframeContext::new();
    rx.advance_epoch(SframeBaseKey::from_mls_exporter(
        [0xAB; BASE_KEY_LEN],
        SframeCiphersuite::Aes256GcmSha512,
        0,
    ));

    for counter in 0..32 {
        let pt = format!("frame-{counter}");
        let ct = tx.encrypt_frame(5, counter, pt.as_bytes()).unwrap();
        let dec = rx.decrypt_frame(&ct).unwrap();
        assert_eq!(dec.plaintext, pt.as_bytes());
        assert_eq!(dec.counter, counter);
    }
}

/// Тип `[u8; BASE_KEY_LEN]` имплементирует `Zeroize` — compile-time
/// гарантия что вызов `mls_exporter_output.zeroize()` в `from_mls_exporter`
/// корректен. Если в будущей версии стандартной библиотеки или crate
/// `zeroize` Zeroize impl для `[u8; N]` будет удалён — этот тест провалит
/// компиляцию и блок 10.15 fix потребует пересмотра.
///
/// The type `[u8; BASE_KEY_LEN]` implements `Zeroize` — compile-time
/// guarantee that the call `mls_exporter_output.zeroize()` in
/// `from_mls_exporter` is correct. If a future version of the standard
/// library or the `zeroize` crate removes the Zeroize impl for `[u8; N]`,
/// this test will fail to compile and the block 10.15 fix will need
/// revisiting.
#[test]
fn f56_array_64_implements_zeroize_compile_time_guard() {
    let mut buf = [0xCDu8; BASE_KEY_LEN];
    // Если в будущем `[u8; 64]: Zeroize` сломается — следующая строка не
    // скомпилируется и тест провалится в compile-time.
    //
    // If `[u8; 64]: Zeroize` ever breaks, the next line will not compile
    // and the test will fail at compile time.
    Zeroize::zeroize(&mut buf);
    assert!(
        buf.iter().all(|&b| b == 0),
        "Zeroize::zeroize must reset all bytes to zero"
    );
}

/// `from_ikm` (universal constructor) и `from_mls_exporter` (fixed-size
/// API) дают идентичный PRK для одного и того же входа. Это страховка
/// против ситуации когда inline-fix `from_mls_exporter` (через
/// `mls_exporter_output.zeroize()`) случайно зануляет данные ДО `from_ikm`
/// вызова — порядок операций критичен. Если кто-то ошибочно поменяет
/// `mls_exporter_output.zeroize()` ↔ `Self::from_ikm(...)` строки —
/// `from_mls_exporter` начнёт возвращать PRK от all-zeros IKM, и этот
/// cross-check провалится.
///
/// `from_ikm` (universal constructor) and `from_mls_exporter` (fixed-size
/// API) produce an identical PRK for the same input. This is a safety net
/// against a situation where the inline fix in `from_mls_exporter`
/// (through `mls_exporter_output.zeroize()`) accidentally wipes the data
/// BEFORE the `from_ikm` call — operation order is critical. If someone
/// mistakenly swaps `mls_exporter_output.zeroize()` ↔ `Self::from_ikm(...)`
/// lines, `from_mls_exporter` will start returning a PRK from all-zeros
/// IKM and this cross-check will fail.
#[test]
fn f56_from_mls_exporter_and_from_ikm_produce_identical_per_kid_keys() {
    let ikm = [0xEFu8; BASE_KEY_LEN];

    let bk_a = SframeBaseKey::from_mls_exporter(ikm, SframeCiphersuite::Aes256GcmSha512, 0);
    let bk_b = SframeBaseKey::from_ikm(&ikm, SframeCiphersuite::Aes256GcmSha512, 0);

    let kid = 0xDEAD_BEEFu64;
    let per_kid_a = bk_a.derive_per_kid(kid);
    let per_kid_b = bk_b.derive_per_kid(kid);

    assert_eq!(
        per_kid_a.key_bytes().as_slice(),
        per_kid_b.key_bytes().as_slice(),
        "from_mls_exporter and from_ikm must produce identical PRK + per-KID key"
    );
    assert_eq!(
        per_kid_a.salt_bytes(),
        per_kid_b.salt_bytes(),
        "from_mls_exporter and from_ikm must produce identical PRK + per-KID salt"
    );
}

/// RFC 9605 Appendix C / sframe-wg test vector cross-check продолжает
/// проходить после inline-fix'а — это финальная страховка что
/// key-schedule pipeline (HKDF-Extract → HKDF-Expand → AEAD) семантически
/// не изменился. Любое изменение в `from_mls_exporter` либо в
/// `derive_per_kid`, которое сломает cross-impl interop с Google Meet /
/// Jitsi / webrtc-rs, провалит этот тест.
///
/// The RFC 9605 Appendix C / sframe-wg test vector cross-check still
/// passes after the inline fix — this is the final safety net that the
/// key-schedule pipeline (HKDF-Extract → HKDF-Expand → AEAD) is
/// semantically unchanged. Any change in `from_mls_exporter` or
/// `derive_per_kid` that breaks cross-impl interop with Google Meet /
/// Jitsi / webrtc-rs will fail this test.
#[test]
fn f56_rfc9605_vector_per_kid_key_unchanged_after_fix() {
    let v = &umbrella_vectors::sframe::AES_256_GCM_SHA512_128_VECTORS[0];

    // RFC 9605 test vector использует `base_key` произвольной длины
    // (16 байт в данном векторе — HKDF-Extract превращает в 64-байтовый
    // PRK). Конструктор `from_ikm` принимает `&[u8]`, поэтому RFC vector
    // cross-check естественно идёт через него. Семантическая эквивалентность
    // `from_mls_exporter` ↔ `from_ikm` для same input уже проверена в
    // `f56_from_mls_exporter_and_from_ikm_produce_identical_per_kid_keys`
    // выше — это даёт транзитивную гарантию что F-56 fix в
    // `from_mls_exporter` не сломал key-schedule pipeline.
    //
    // The RFC 9605 test vector uses `base_key` of arbitrary length (16
    // bytes in this vector — HKDF-Extract turns it into a 64-byte PRK).
    // The `from_ikm` constructor takes `&[u8]`, so the RFC vector
    // cross-check naturally goes through it. The semantic equivalence
    // `from_mls_exporter` ↔ `from_ikm` for the same input is already
    // verified in `f56_from_mls_exporter_and_from_ikm_produce_identical_per_kid_keys`
    // above — this gives a transitive guarantee that the F-56 fix in
    // `from_mls_exporter` did not break the key-schedule pipeline.
    let bk = SframeBaseKey::from_ikm(v.base_key, SframeCiphersuite::Aes256GcmSha512, 0);
    let per_kid = bk.derive_per_kid(v.kid);

    assert_eq!(
        per_kid.key_bytes().as_slice(),
        v.expected_sframe_key,
        "RFC 9605 Appendix C sframe_key must match after F-56 fix"
    );
    assert_eq!(
        per_kid.salt_bytes(),
        v.expected_sframe_salt,
        "RFC 9605 Appendix C sframe_salt must match after F-56 fix"
    );
    // Проверяем длины — параметризованные константы должны оставаться
    // строго RFC 9605 §5.2 для AES-256-GCM-SHA512-128.
    //
    // Verify lengths — parameterized constants must stay strictly per
    // RFC 9605 §5.2 for AES-256-GCM-SHA512-128.
    assert_eq!(per_kid.key_bytes().len(), SFRAME_KEY_LEN);
    assert_eq!(per_kid.salt_bytes().len(), SFRAME_SALT_LEN);
}
