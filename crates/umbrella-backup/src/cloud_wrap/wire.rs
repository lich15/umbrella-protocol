//! Wire-format Cloud-wrap: `CanonicalAad`, `CanonicalNonce`, `WrappedKey`.
//! Cloud-wrap wire format: `CanonicalAad`, `CanonicalNonce`, `WrappedKey`.
//!
//! Все многобайтовые числа в big-endian. Offsets фиксированы — изменение
//! любого ломает compatibility, требует version bump.
//!
//! All multi-byte numbers are big-endian. Offsets are fixed — any change
//! breaks compatibility and requires a version bump.

use core::convert::TryInto;

use hkdf::Hkdf;
use sha2::Sha512;

use crate::error::BackupError;

use super::params::{
    AEAD_BLOB_LEN, CHAT_ID_LEN, NONCE_LEN, POINT_LEN, PROTOCOL_VERSION, WRAPPED_KEY_LEN,
};

/// Длина Ed25519 public key в байтах.
/// Ed25519 public key length in bytes.
pub const ED25519_PUB_LEN: usize = 32;

/// Длина `CanonicalAad` в байтах.
/// `CanonicalAad` length in bytes.
pub const CANONICAL_AAD_LEN: usize = ED25519_PUB_LEN + ED25519_PUB_LEN + CHAT_ID_LEN + 8;

/// Domain separator для deterministic AEAD-nonce HKDF.
/// Domain separator for the deterministic AEAD-nonce HKDF.
pub const NONCE_DERIVATION_SALT: &[u8] = b"umbrellax-cloud-wrap-nonce-v1";

/// Canonical AAD для ChaCha20-Poly1305 wrap-операции.
/// Canonical AAD for the ChaCha20-Poly1305 wrap operation.
///
/// Связывает wrapped_blob с конкретным отправителем, получателем, чатом и
/// порядковым номером сообщения. Любое изменение одного bit'а в любом поле
/// ломает AEAD decrypt на получателе.
///
/// Binds the wrapped blob to a specific sender, recipient, chat, and message
/// sequence. Any bit-flip in any field breaks AEAD decrypt on the recipient.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalAad {
    /// Ed25519 public key отправителя (long-term identity).
    /// Sender's Ed25519 public key (long-term identity).
    pub sender_identity_pubkey: [u8; ED25519_PUB_LEN],
    /// Ed25519 public key устройства получателя (device-key, не identity).
    /// Recipient device's Ed25519 public key (device-key, not identity).
    pub recipient_device_pubkey: [u8; ED25519_PUB_LEN],
    /// Canonical chat_id (32 bytes, UUID canonicalized).
    /// Canonical chat_id (32 bytes, UUID canonicalized).
    pub chat_id: [u8; CHAT_ID_LEN],
    /// Порядковый номер сообщения в чате (monotonic per-chat).
    /// Message sequence number (monotonic per chat).
    pub msg_seq: u64,
}

/// `Debug` скрывает linkable metadata: sender, recipient и chat_id не печатаются.
/// `Debug` redacts linkable metadata: sender, recipient, and chat_id are not printed.
impl core::fmt::Debug for CanonicalAad {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CanonicalAad")
            .field(
                "sender_identity_pubkey_len",
                &self.sender_identity_pubkey.len(),
            )
            .field("sender_identity_pubkey", &"<redacted>")
            .field(
                "recipient_device_pubkey_len",
                &self.recipient_device_pubkey.len(),
            )
            .field("recipient_device_pubkey", &"<redacted>")
            .field("chat_id_len", &self.chat_id.len())
            .field("chat_id", &"<redacted>")
            .field("msg_seq", &self.msg_seq)
            .finish()
    }
}

impl CanonicalAad {
    /// Сериализация в фиксированный byte layout.
    /// Serialization in a fixed byte layout.
    ///
    /// Layout:
    /// ```text
    /// [0..32)   sender_identity_pubkey
    /// [32..64)  recipient_device_pubkey
    /// [64..96)  chat_id
    /// [96..104) msg_seq_be_u64
    /// ```
    #[must_use]
    pub fn canonical_bytes(&self) -> [u8; CANONICAL_AAD_LEN] {
        let mut out = [0u8; CANONICAL_AAD_LEN];
        let mut off = 0;
        out[off..off + ED25519_PUB_LEN].copy_from_slice(&self.sender_identity_pubkey);
        off += ED25519_PUB_LEN;
        out[off..off + ED25519_PUB_LEN].copy_from_slice(&self.recipient_device_pubkey);
        off += ED25519_PUB_LEN;
        out[off..off + CHAT_ID_LEN].copy_from_slice(&self.chat_id);
        off += CHAT_ID_LEN;
        out[off..off + 8].copy_from_slice(&self.msg_seq.to_be_bytes());
        out
    }
}

/// Детерминированный ChaCha20-Poly1305 nonce из `(chat_id, msg_seq)`.
/// Deterministic ChaCha20-Poly1305 nonce from `(chat_id, msg_seq)`.
///
/// Используется HKDF-SHA512 с salt `"umbrellax-cloud-wrap-nonce-v1"` и ikm
/// = `chat_id`, info = `msg_seq_be_u64`, length = 12 байт.
///
/// Детерминизм критичен: один и тот же (chat_id, msg_seq) всегда даёт один и
/// тот же nonce — это позволяет отправителю и получателю прийти к одному
/// AEAD-контексту без передачи nonce по сети.
///
/// Инвариант protocol-уровня: `msg_seq` монотонно возрастает в рамках
/// одного chat_id (enforced вызывающей стороной, обычно `message-svc` на
/// Umbrella server implementation через per-chat atomic counter). Повтор `(chat_id, msg_seq)` —
/// ошибка протокола и приводит к nonce-reuse (недопустимо для ChaCha20).
///
/// HKDF-SHA512 with salt `"umbrellax-cloud-wrap-nonce-v1"`, ikm = `chat_id`,
/// info = `msg_seq_be_u64`, length = 12 bytes. Determinism lets sender and
/// recipient arrive at the same AEAD context without transmitting the nonce.
/// The caller must enforce monotonic `msg_seq` per `chat_id` to avoid
/// nonce-reuse (a protocol-level invariant).
#[must_use]
pub fn canonical_nonce(chat_id: &[u8; CHAT_ID_LEN], msg_seq: u64) -> [u8; NONCE_LEN] {
    let hk = Hkdf::<Sha512>::new(Some(NONCE_DERIVATION_SALT), chat_id);
    let mut out = [0u8; NONCE_LEN];
    #[allow(
        unknown_lints,
        no_unwrap_in_lib,
        reason = "infallible: HKDF-SHA512 12-byte expansion always fits per RFC 5869"
    )]
    hk.expand(&msg_seq.to_be_bytes(), &mut out)
        .expect("HKDF-SHA512 12-byte expansion always fits");
    out
}

/// `WrappedKey` — wire-формат обёрнутого AEAD-ключа сообщения.
/// `WrappedKey` — wire format of a wrapped message AEAD key.
///
/// Layout (81 bytes):
/// ```text
/// [0..1)   version                 : u8 = 0x01
/// [1..33)  ephemeral_r_compressed  : 32 bytes (Ristretto255)
/// [33..81) aead_blob               : 48 bytes (32 ciphertext + 16 Poly1305 tag)
/// ```
///
/// Ровно 81 байт на каждое сообщение независимо от числа получателей — `R`
/// общий по протоколу, wrap делается один раз per message AEAD-key.
///
/// Exactly 81 bytes per message regardless of recipients — `R` is shared by
/// protocol, wrap is done once per message AEAD-key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WrappedKey {
    /// Версия (должна быть `PROTOCOL_VERSION`).
    /// Version (must equal `PROTOCOL_VERSION`).
    pub version: u8,
    /// Compressed Ristretto255 для `R = r · G`.
    /// Compressed Ristretto255 of `R = r · G`.
    pub ephemeral_r: [u8; POINT_LEN],
    /// AEAD-blob = ciphertext ‖ Poly1305 tag (48 bytes total).
    /// AEAD blob = ciphertext ‖ Poly1305 tag (48 bytes total).
    pub aead_blob: [u8; AEAD_BLOB_LEN],
}

/// `Debug` скрывает wrapped-key bytes: они не должны оставаться в диагностике.
/// `Debug` redacts wrapped-key bytes: they must not remain in diagnostics.
impl core::fmt::Debug for WrappedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WrappedKey")
            .field("version", &self.version)
            .field("ephemeral_r_len", &self.ephemeral_r.len())
            .field("ephemeral_r", &"<redacted>")
            .field("aead_blob_len", &self.aead_blob.len())
            .field("aead_blob", &"<redacted>")
            .finish()
    }
}

impl WrappedKey {
    /// Сериализация в фиксированный 81-байтовый буфер.
    /// Serialization into a fixed 81-byte buffer.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; WRAPPED_KEY_LEN] {
        let mut out = [0u8; WRAPPED_KEY_LEN];
        out[0] = self.version;
        out[1..1 + POINT_LEN].copy_from_slice(&self.ephemeral_r);
        out[1 + POINT_LEN..].copy_from_slice(&self.aead_blob);
        out
    }

    /// Парсинг 81 байта с валидацией версии и длины.
    /// Parse 81 bytes with version and length validation.
    ///
    /// # Errors
    /// - [`BackupError::WrappedKeyTruncated`] если `data.len() != WRAPPED_KEY_LEN`.
    /// - [`BackupError::WrappedKeyVersionMismatch`] если версия не `PROTOCOL_VERSION`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, BackupError> {
        if data.len() != WRAPPED_KEY_LEN {
            return Err(BackupError::WrappedKeyTruncated);
        }
        let version = data[0];
        if version != PROTOCOL_VERSION {
            return Err(BackupError::WrappedKeyVersionMismatch {
                expected: PROTOCOL_VERSION,
                found: version,
            });
        }
        let ephemeral_r: [u8; POINT_LEN] = data[1..1 + POINT_LEN]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        let aead_blob: [u8; AEAD_BLOB_LEN] = data[1 + POINT_LEN..]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        Ok(Self {
            version,
            ephemeral_r,
            aead_blob,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_aad() -> CanonicalAad {
        CanonicalAad {
            sender_identity_pubkey: [0x11; ED25519_PUB_LEN],
            recipient_device_pubkey: [0x22; ED25519_PUB_LEN],
            chat_id: [0x33; CHAT_ID_LEN],
            msg_seq: 0x0102_0304_0506_0708,
        }
    }

    #[test]
    fn canonical_aad_layout_offsets() {
        let aad = sample_aad();
        let bytes = aad.canonical_bytes();

        assert_eq!(bytes.len(), CANONICAL_AAD_LEN);
        assert_eq!(&bytes[..32], &[0x11u8; 32]);
        assert_eq!(&bytes[32..64], &[0x22u8; 32]);
        assert_eq!(&bytes[64..96], &[0x33u8; 32]);
        assert_eq!(
            &bytes[96..104],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn canonical_aad_debug_redacts_linkable_metadata() {
        let aad = sample_aad();

        let debug = format!("{aad:?}");

        assert!(
            !debug.contains("17, 17, 17, 17"),
            "Debug output must not leak sender pubkey bytes: {debug}"
        );
        assert!(
            !debug.contains("34, 34, 34, 34"),
            "Debug output must not leak recipient device pubkey bytes: {debug}"
        );
        assert!(
            !debug.contains("51, 51, 51, 51"),
            "Debug output must not leak chat id bytes: {debug}"
        );
        assert!(debug.contains("chat_id_len"));
    }

    #[test]
    fn canonical_aad_length_is_104_bytes() {
        assert_eq!(CANONICAL_AAD_LEN, 104);
    }

    #[test]
    fn canonical_nonce_is_deterministic_per_chat_and_seq() {
        let chat_id = [0x42u8; CHAT_ID_LEN];
        let a = canonical_nonce(&chat_id, 42);
        let b = canonical_nonce(&chat_id, 42);
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_nonce_differs_on_different_msg_seq() {
        let chat_id = [0x42u8; CHAT_ID_LEN];
        let a = canonical_nonce(&chat_id, 1);
        let b = canonical_nonce(&chat_id, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn canonical_nonce_differs_on_different_chat_id() {
        let a = canonical_nonce(&[0x01u8; CHAT_ID_LEN], 7);
        let b = canonical_nonce(&[0x02u8; CHAT_ID_LEN], 7);
        assert_ne!(a, b);
    }

    #[test]
    fn canonical_nonce_length_is_12_bytes() {
        let n = canonical_nonce(&[0u8; CHAT_ID_LEN], 0);
        assert_eq!(n.len(), NONCE_LEN);
        assert_eq!(n.len(), 12);
    }

    #[test]
    fn wrapped_key_roundtrip() {
        let wk = WrappedKey {
            version: PROTOCOL_VERSION,
            ephemeral_r: [0xAA; POINT_LEN],
            aead_blob: [0xBB; AEAD_BLOB_LEN],
        };
        let bytes = wk.to_bytes();
        assert_eq!(bytes.len(), WRAPPED_KEY_LEN);
        let parsed = WrappedKey::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, wk);
    }

    #[test]
    fn wrapped_key_debug_redacts_wrapped_key_material() {
        let wk = WrappedKey {
            version: PROTOCOL_VERSION,
            ephemeral_r: [0xAA; POINT_LEN],
            aead_blob: [0xBB; AEAD_BLOB_LEN],
        };

        let debug = format!("{wk:?}");

        assert!(
            !debug.contains("170, 170, 170, 170"),
            "Debug output must not leak ephemeral R bytes: {debug}"
        );
        assert!(
            !debug.contains("187, 187, 187, 187"),
            "Debug output must not leak wrapped AEAD blob bytes: {debug}"
        );
        assert!(debug.contains("aead_blob_len"));
    }

    #[test]
    fn wrapped_key_from_bytes_rejects_short() {
        let short = [0u8; WRAPPED_KEY_LEN - 1];
        let err = WrappedKey::from_bytes(&short).unwrap_err();
        assert!(matches!(err, BackupError::WrappedKeyTruncated));
    }

    #[test]
    fn wrapped_key_from_bytes_rejects_long() {
        let long = [0u8; WRAPPED_KEY_LEN + 1];
        let err = WrappedKey::from_bytes(&long).unwrap_err();
        assert!(matches!(err, BackupError::WrappedKeyTruncated));
    }

    #[test]
    fn wrapped_key_from_bytes_rejects_version_mismatch() {
        let mut bytes = [0u8; WRAPPED_KEY_LEN];
        bytes[0] = 0x02; // invalid version
        let err = WrappedKey::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            BackupError::WrappedKeyVersionMismatch {
                expected: 0x01,
                found: 0x02
            }
        ));
    }

    #[test]
    fn wrapped_key_from_bytes_rejects_empty() {
        let err = WrappedKey::from_bytes(&[]).unwrap_err();
        assert!(matches!(err, BackupError::WrappedKeyTruncated));
    }

    #[test]
    fn wrapped_key_layout_offsets() {
        let wk = WrappedKey {
            version: PROTOCOL_VERSION,
            ephemeral_r: {
                let mut r = [0u8; POINT_LEN];
                r[0] = 0xEF;
                r[31] = 0xFE;
                r
            },
            aead_blob: {
                let mut b = [0u8; AEAD_BLOB_LEN];
                b[0] = 0x10;
                b[47] = 0x01;
                b
            },
        };
        let bytes = wk.to_bytes();
        assert_eq!(bytes[0], PROTOCOL_VERSION);
        assert_eq!(bytes[1], 0xEF);
        assert_eq!(bytes[32], 0xFE);
        assert_eq!(bytes[33], 0x10);
        assert_eq!(bytes[80], 0x01);
    }
}
