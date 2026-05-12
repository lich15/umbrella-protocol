//! Application-level ChaCha20-Poly1305 per-row encryption для SQLite метаданных.
//!
//! ADR-010 Решение 5, подвариант C.1.2 — не используем SQLCipher, а шифруем
//! sensitive колонки в каждой строке **сами**. Плюсы: не тянем pinned
//! SQLCipher fork, post-compromise security (compromise master-key open'ит
//! сообщения, но не позволяет восстановить content без дополнительного
//! per-row nonce derive).
//!
//! # Схема
//!
//! 1. Master-ключ 256-bit получен через
//!    [`super::PersistentKeyStore::derive_storage_master_key`]
//!    (HKDF-SHA512 from identity-seed; `info = b"umbrellax-sqlite-master-v1"`).
//!    Хранится в `SecretBox<[u8; 32]>` + `ZeroizeOnDrop`.
//!
//! 2. Nonce **детерминированно** выведен из `(master_key, context, row_id)`
//!    через HKDF-SHA512 (12 байт output). Детерминизм допустим потому что
//!    `(context, row_id)` уникален per row (primary key); детерминированный
//!    nonce позволяет обнаружить row-swap атаку (attacker меняет местами
//!    шифр-тексты между двумя row'ами — на decrypt получим другой nonce и
//!    AEAD auth fail).
//!
//! 3. `aad = context` (e.g. `"messages.text"`) — защита от column-swap
//!    между разными таблицами с одинаковым row_id.
//!
//! 4. ChaCha20-Poly1305 `encrypt_in_place_detached` / `decrypt_in_place_detached`
//!    — AEAD с 128-bit tag.
//!
//! Application-level ChaCha20-Poly1305 per-row encryption for SQLite metadata.
//!
//! ADR-010 Decision 5, subvariant C.1.2 — no SQLCipher dependency; sensitive
//! columns are encrypted **by us** inside each row. Pros: no pinned
//! SQLCipher fork needed; post-compromise property (master-key leak reveals
//! messages but cannot re-derive content without the per-row nonce).
//!
//! # Scheme
//!
//! 1. 256-bit master-key from
//!    [`super::PersistentKeyStore::derive_storage_master_key`]
//!    (HKDF-SHA512 of identity-seed; `info = b"umbrellax-sqlite-master-v1"`).
//!    Held in `SecretBox<[u8; 32]>` + `ZeroizeOnDrop`.
//!
//! 2. Nonce **deterministically** derived from `(master_key, context, row_id)`
//!    via HKDF-SHA512 (12-byte output). Determinism is safe because
//!    `(context, row_id)` is unique per row (primary key); deterministic
//!    nonces detect row-swap attacks (attacker swapping ciphertexts between
//!    two rows → on decrypt we get a different nonce → AEAD auth fail).
//!
//! 3. `aad = context` (e.g. `"messages.text"`) — protection from
//!    column-swap across tables with overlapping row_ids.
//!
//! 4. ChaCha20-Poly1305 `encrypt_in_place_detached` /
//!    `decrypt_in_place_detached` — AEAD with a 128-bit tag.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::ClientError;

/// HKDF info-prefix для nonce derivation. Меняется при breaking change
/// схемы (тогда же bump SCHEMA_VERSION в `schema.rs`).
///
/// HKDF info-prefix for nonce derivation. Bumped on breaking schema change
/// (alongside `SCHEMA_VERSION` in `schema.rs`).
const NONCE_INFO_PREFIX: &[u8] = b"umbrellax-sqlite-row-nonce-v1";

/// Результат `encrypt_row`: `(ciphertext, nonce_12, tag_16)`. Три части
/// хранятся в отдельных колонках SQLite (`enc_payload`, `enc_nonce`,
/// `enc_tag`) — тип alias введён чтобы не провоцировать
/// `clippy::type_complexity` на сигнатуре метода.
///
/// Result of `encrypt_row`: `(ciphertext, nonce_12, tag_16)`. The three
/// parts sit in separate SQLite columns (`enc_payload`, `enc_nonce`,
/// `enc_tag`); the alias avoids `clippy::type_complexity` on the method
/// signature.
pub type EncryptedRow = (Vec<u8>, [u8; 12], [u8; 16]);

/// Шифратор строк SQLite. Держит master-ключ в `SecretBox<[u8; 32]>` с
/// `ZeroizeOnDrop` — при drop ключ zeroize'ится автоматически.
///
/// SQLite row cipher. Holds master-key in `SecretBox<[u8; 32]>` with
/// `ZeroizeOnDrop` — the key is zeroized on drop automatically.
pub struct RowCipher {
    master_key: SecretBox<[u8; 32]>,
}

impl RowCipher {
    /// Создать из derived master-ключа. `master_key_bytes` после вызова
    /// **обязан** быть занулён вызывающей стороной (или переданы через
    /// move-semantics которые guaranteed zeroize при drop).
    ///
    /// Параметр принимается по значению (Copy для `[u8; 32]`); локальная
    /// stack-копия параметра занулается перед возвратом из конструктора —
    /// caller-side zeroize всё равно остаётся обязательным для исходной
    /// копии вызывающей стороны (F-57 closure блок 10.16; F-46/F-56 pattern
    /// recurrence closure — defense-in-depth поверх caller's responsibility).
    ///
    /// Construct from a derived master-key. `master_key_bytes` **must** be
    /// zeroized by the caller after this call (or passed via move-semantics
    /// that zeroize on drop).
    ///
    /// The parameter is taken by value (Copy for `[u8; 32]`); the local
    /// stack copy of the parameter is zeroized before constructor return —
    /// the caller-side zeroize is still required for the caller's source
    /// copy (F-57 closure block 10.16; F-46/F-56 pattern recurrence closure
    /// — defense-in-depth on top of the caller's responsibility).
    #[must_use]
    pub fn new(mut master_key_bytes: [u8; 32]) -> Self {
        let cipher = Self {
            master_key: SecretBox::new(Box::new(master_key_bytes)),
        };
        // `Box::new(master_key_bytes)` копирует Copy-массив в heap-allocated
        // box; локальная stack-копия параметра остаётся валидной — зануляем
        // её explicit вызовом `.zeroize()` для defense-in-depth.
        //
        // `Box::new(master_key_bytes)` copies the Copy array into the
        // heap-allocated box; the local stack copy of the parameter remains
        // valid — we explicitly zeroize it here for defense-in-depth.
        master_key_bytes.zeroize();
        cipher
    }

    /// Зашифровать `plaintext` для строки с данным `context` и `row_id`.
    /// Возвращает `(ciphertext, nonce_12, tag_16)`.
    ///
    /// - `context` — идентификатор колонки/таблицы (e.g. `"messages.text"`),
    ///   используется и для derive nonce, и как AEAD `aad`.
    /// - `row_id` — primary-key байты строки; вместе с `context` формируют
    ///   уникальность nonce через HKDF.
    ///
    /// # Ошибки / Errors
    ///
    /// - [`ClientError::Storage`] — AEAD encrypt internal error (крайне
    ///   маловероятно для ChaCha20-Poly1305 на in-memory буфере; покрывает
    ///   edge-case size overflow).
    ///
    /// Encrypts `plaintext` for the row identified by `context` and `row_id`.
    /// Returns `(ciphertext, nonce_12, tag_16)`.
    ///
    /// - `context` — table/column identifier (e.g. `"messages.text"`); used
    ///   both for nonce derivation and as the AEAD `aad`.
    /// - `row_id` — the primary-key bytes of the row; together with
    ///   `context` they make the derived nonce unique via HKDF.
    ///
    /// # Errors
    ///
    /// - [`ClientError::Storage`] — AEAD encrypt internal error (extremely
    ///   unlikely for ChaCha20-Poly1305 on an in-memory buffer; covers the
    ///   size-overflow edge case).
    pub fn encrypt_row(
        &self,
        context: &str,
        row_id: &[u8],
        plaintext: &[u8],
    ) -> Result<EncryptedRow, ClientError> {
        let nonce_bytes = self.derive_nonce(context, row_id);
        let cipher = self.cipher();

        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce_bytes),
                context.as_bytes(),
                &mut buffer,
            )
            .map_err(|e| ClientError::Storage(format!("aead encrypt: {e}")))?;

        let tag_bytes: [u8; 16] = tag.into();
        Ok((buffer, nonce_bytes, tag_bytes))
    }

    /// Расшифровать `ciphertext`. Nonce **сверяется** с detereministically
    /// derived — mismatch сигналит tampering (row-swap / replay attack) до
    /// того как AEAD проверка вообще запустится. Аналогичный AEAD auth
    /// fail сработает если изменены context, row_id, ciphertext или tag.
    ///
    /// # Ошибки / Errors
    ///
    /// - [`ClientError::Storage("nonce mismatch ...")`] — полученный nonce
    ///   не совпадает с derived (подменили nonce в storage).
    /// - [`ClientError::Storage("aead decrypt ...")`] — AEAD auth failed
    ///   (ciphertext/context/row_id/tag/master-key tampering).
    ///
    /// Decrypts `ciphertext`. The nonce is **verified** against a
    /// deterministically derived value — a mismatch signals tampering
    /// (row-swap / replay attack) before the AEAD check even runs. The
    /// identical AEAD auth failure fires on any change to context, row_id,
    /// ciphertext, or tag.
    ///
    /// # Errors
    ///
    /// - [`ClientError::Storage("nonce mismatch ...")`] — the supplied
    ///   nonce does not match the derived one (nonce tampering in storage).
    /// - [`ClientError::Storage("aead decrypt ...")`] — AEAD auth failed
    ///   (ciphertext/context/row_id/tag/master-key tampering).
    pub fn decrypt_row(
        &self,
        context: &str,
        row_id: &[u8],
        ciphertext: &[u8],
        nonce: [u8; 12],
        tag: [u8; 16],
    ) -> Result<Vec<u8>, ClientError> {
        let expected_nonce = self.derive_nonce(context, row_id);
        // Constant-time сравнение через `subtle::ConstantTimeEq::ct_eq`
        // (F-57 closure блок 10.16; F-51 pattern recurrence closure).
        // Pre-fix `expected_nonce != nonce` использовал `PartialEq` на
        // `[u8; 12]`, который short-circuit'ится на первом несовпадающем
        // байте — теоретически даёт timing-observable «который байт
        // отличается». Practical impact LOW (nonce mismatch уже сигнализирует
        // tamper/row-swap; attacker уже выиграл), но defense-in-depth
        // принцип constant-time на cryptographic comparisons enforced
        // даже на «практически безопасных» path'ах per design §5.1
        // (precedent F-51 closure block 10.12 umbrella-padding).
        //
        // Constant-time comparison via `subtle::ConstantTimeEq::ct_eq`
        // (F-57 closure block 10.16; F-51 pattern recurrence closure).
        // The pre-fix `expected_nonce != nonce` used `PartialEq` on
        // `[u8; 12]` which short-circuits on the first mismatching byte —
        // theoretically giving a timing-observable «which byte differs»
        // signal. Practical impact is LOW (nonce mismatch already signals
        // tamper / row-swap; the attacker has already won), but the
        // defense-in-depth principle of constant-time on cryptographic
        // comparisons is enforced even on «practically safe» paths per
        // design §5.1 (precedent: F-51 closure block 10.12 umbrella-padding).
        if expected_nonce.ct_eq(&nonce).unwrap_u8() == 0 {
            return Err(ClientError::Storage(
                "nonce mismatch (tamper or row-swap attack)".into(),
            ));
        }

        let cipher = self.cipher();
        let mut buffer = ciphertext.to_vec();
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                context.as_bytes(),
                &mut buffer,
                Tag::from_slice(&tag),
            )
            .map_err(|e| ClientError::Storage(format!("aead decrypt: {e}")))?;
        Ok(buffer)
    }

    /// Внутренний helper: создаёт новый `ChaCha20Poly1305` instance. Key
    /// хранится в self под SecretBox; cipher-копия key'а living только на
    /// стеке этого вызова и дропается сразу.
    ///
    /// Internal helper: fresh `ChaCha20Poly1305` instance. The key lives in
    /// `self` under SecretBox; the cipher's copy of the key is stack-local
    /// to this call and dropped immediately after.
    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(self.master_key.expose_secret().as_slice()))
    }

    /// Nonce-derivation: HKDF-SHA512(master_key, info = PREFIX || context ||
    /// row_id) → `[u8; 12]`.
    ///
    /// Nonce derivation: HKDF-SHA512(master_key, info = PREFIX || context ||
    /// row_id) → `[u8; 12]`.
    fn derive_nonce(&self, context: &str, row_id: &[u8]) -> [u8; 12] {
        let mut info = Vec::with_capacity(NONCE_INFO_PREFIX.len() + context.len() + row_id.len());
        info.extend_from_slice(NONCE_INFO_PREFIX);
        info.extend_from_slice(context.as_bytes());
        info.extend_from_slice(row_id);

        let hk = Hkdf::<Sha512>::new(None, self.master_key.expose_secret().as_slice());
        let mut out = [0u8; 12];
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: HKDF-SHA512 12 bytes well under 255*64=16320 byte max"
        )]
        hk.expand(&info, &mut out)
            .expect("HKDF-SHA512 12 bytes is within the 255*64 = 16320 byte limit");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let cipher = RowCipher::new([0x42u8; 32]);
        let (ct, nonce, tag) = cipher
            .encrypt_row("messages.text", &[1, 2, 3, 4], b"hello world")
            .expect("encrypt on valid input is infallible");
        let pt = cipher
            .decrypt_row("messages.text", &[1, 2, 3, 4], &ct, nonce, tag)
            .expect("decrypt after encrypt is infallible");
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let cipher = RowCipher::new([0x42u8; 32]);
        let (mut ct, nonce, tag) = cipher
            .encrypt_row("test", b"id", b"secret data")
            .expect("encrypt");
        ct[0] ^= 0x01;
        let result = cipher.decrypt_row("test", b"id", &ct, nonce, tag);
        assert!(result.is_err(), "tamper of ciphertext must fail AEAD");
    }

    #[test]
    fn tampered_tag_fails() {
        let cipher = RowCipher::new([0x42u8; 32]);
        let (ct, nonce, mut tag) = cipher
            .encrypt_row("test", b"id", b"secret data")
            .expect("encrypt");
        tag[0] ^= 0x01;
        let result = cipher.decrypt_row("test", b"id", &ct, nonce, tag);
        assert!(result.is_err(), "tamper of tag must fail AEAD");
    }

    #[test]
    fn tampered_context_fails() {
        let cipher = RowCipher::new([0x42u8; 32]);
        let (ct, nonce, tag) = cipher
            .encrypt_row("contextA", b"id", b"data")
            .expect("encrypt");
        // context участвует и в nonce derive, и в aad — fail на nonce check.
        let result = cipher.decrypt_row("contextB", b"id", &ct, nonce, tag);
        assert!(
            result.is_err(),
            "different context must fail (nonce mismatch or AEAD)"
        );
    }

    #[test]
    fn tampered_row_id_fails() {
        let cipher = RowCipher::new([0x42u8; 32]);
        let (ct, nonce, tag) = cipher.encrypt_row("ctx", b"id1", b"data").expect("encrypt");
        let result = cipher.decrypt_row("ctx", b"id2", &ct, nonce, tag);
        assert!(result.is_err(), "different row_id must fail");
    }

    #[test]
    fn different_rows_have_different_nonces() {
        let cipher = RowCipher::new([0x42u8; 32]);
        let (_, nonce1, _) = cipher
            .encrypt_row("ctx", b"row1", b"data")
            .expect("encrypt");
        let (_, nonce2, _) = cipher
            .encrypt_row("ctx", b"row2", b"data")
            .expect("encrypt");
        assert_ne!(nonce1, nonce2, "deterministic nonce must vary with row_id");
    }

    #[test]
    fn tampered_nonce_fails_before_aead() {
        let cipher = RowCipher::new([0x42u8; 32]);
        let (ct, mut nonce, tag) = cipher.encrypt_row("ctx", b"id", b"data").expect("encrypt");
        nonce[0] ^= 0x01;
        let result = cipher.decrypt_row("ctx", b"id", &ct, nonce, tag);
        let err = result.expect_err("nonce tamper must fail");
        assert!(
            matches!(err, ClientError::Storage(ref s) if s.contains("nonce mismatch")),
            "expected nonce-mismatch error, got: {err:?}"
        );
    }

    #[test]
    fn encrypt_empty_plaintext_works() {
        let cipher = RowCipher::new([0x77u8; 32]);
        let (ct, nonce, tag) = cipher.encrypt_row("ctx", b"id", &[]).expect("encrypt");
        let pt = cipher
            .decrypt_row("ctx", b"id", &ct, nonce, tag)
            .expect("decrypt");
        assert_eq!(pt, Vec::<u8>::new());
    }

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// Property: любая тройка (context, row_id, plaintext) roundtrip'ает.
        /// Сколько бы случайных входов ни придумал генератор — decrypt даёт
        /// plaintext обратно бит-в-бит.
        ///
        /// Property: any (context, row_id, plaintext) triple roundtrips
        /// bit-for-bit. Whatever random inputs the generator produces,
        /// decrypt yields the original plaintext exactly.
        #[test]
        fn prop_roundtrip(
            context in "[a-zA-Z0-9._\\-]{1,32}",
            row_id in prop::collection::vec(any::<u8>(), 1..=64),
            plaintext in prop::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let cipher = RowCipher::new([0x55u8; 32]);
            let (ct, nonce, tag) = cipher
                .encrypt_row(&context, &row_id, &plaintext)
                .expect("encrypt on arbitrary input is infallible");
            let pt = cipher
                .decrypt_row(&context, &row_id, &ct, nonce, tag)
                .expect("decrypt after own encrypt is infallible");
            prop_assert_eq!(pt, plaintext);
        }

        /// Property: любая однобайтовая мутация ciphertext ломает AEAD.
        /// Демонстрирует что AEAD integrity покрывает **каждый** байт
        /// ciphertext — не только tag.
        ///
        /// Property: any single-byte mutation of ciphertext breaks AEAD.
        /// Demonstrates that AEAD integrity covers **every** ciphertext
        /// byte — not just the tag.
        #[test]
        fn prop_tampered_ciphertext_fails(
            context in "[a-zA-Z0-9._\\-]{1,32}",
            row_id in prop::collection::vec(any::<u8>(), 1..=64),
            plaintext in prop::collection::vec(any::<u8>(), 1..=4096),
            flip_idx_seed in 0usize..4096,
            flip_mask in 1u8..=255,
        ) {
            let cipher = RowCipher::new([0x55u8; 32]);
            let (mut ct, nonce, tag) = cipher
                .encrypt_row(&context, &row_id, &plaintext)
                .expect("encrypt");
            prop_assume!(!ct.is_empty());
            let idx = flip_idx_seed % ct.len();
            ct[idx] ^= flip_mask;
            let result = cipher.decrypt_row(&context, &row_id, &ct, nonce, tag);
            prop_assert!(result.is_err(), "tampered ct byte {idx} must fail AEAD");
        }

        /// Property: row-swap attack. Attacker берёт (ct, nonce, tag) одной
        /// row и подставляет их под row_id другой — deterministic nonce
        /// derive гарантирует mismatch (AEAD auth ещё даже не запускается).
        ///
        /// Property: row-swap attack. An attacker takes (ct, nonce, tag) of
        /// one row and plants them under a different row_id — the
        /// deterministic nonce derivation guarantees a mismatch (AEAD auth
        /// is not even reached).
        #[test]
        fn prop_row_swap_fails(
            context in "[a-zA-Z0-9._\\-]{1,32}",
            row_id_a in prop::collection::vec(any::<u8>(), 1..=64),
            row_id_b in prop::collection::vec(any::<u8>(), 1..=64),
            plaintext in prop::collection::vec(any::<u8>(), 1..=1024),
        ) {
            prop_assume!(row_id_a != row_id_b);
            let cipher = RowCipher::new([0x55u8; 32]);
            let (ct, nonce, tag) = cipher
                .encrypt_row(&context, &row_id_a, &plaintext)
                .expect("encrypt");
            // Подставляем row_id_b на decrypt.
            // Plug row_id_b into decrypt.
            let result = cipher.decrypt_row(&context, &row_id_b, &ct, nonce, tag);
            prop_assert!(
                result.is_err(),
                "row-swap (ct of row_id_a → decrypt under row_id_b) must fail"
            );
        }
    }
}
