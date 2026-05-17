//! Sealed Sender — HPKE-style envelope скрывающий отправителя от Delivery Service.
//! Sealed Sender — HPKE-style envelope hiding the sender from the Delivery Service.
//!
//! ## Что добавил блок 8.6 (Этап 8 PQ opt-in)
//!
//! - `version` (всегда compiled): `SealedSenderVersion { V1Classical=0x01,
//!   V2HybridXWing=0x02 }` — first-byte discriminator для V2 envelope.
//! - `hybrid_envelope` (под `feature = "pq"`): `seal_v2` / `unseal_v2` —
//!   X-Wing ephemeral KEM вместо classical X25519 ECDH; same inner protocol
//!   (sender_identity || signature || message + padding) что V1.
//! - V1 wire-format **не меняется** — existing `seal` / `unseal` работают
//!   identical. Caller'ы downstream choose path peek'ом первого байта.
//!
//! ## What block 8.6 adds (Stage 8 PQ opt-in)
//!
//! - `version` (always compiled): `SealedSenderVersion { V1Classical=0x01,
//!   V2HybridXWing=0x02 }` — first-byte discriminator for the V2 envelope.
//! - `hybrid_envelope` (under `feature = "pq"`): `seal_v2` / `unseal_v2` —
//!   X-Wing ephemeral KEM instead of classical X25519 ECDH; same inner
//!   protocol (sender_identity || signature || message + padding) as V1.
//! - The V1 wire format does **not** change — existing `seal` / `unseal` work
//!   identically. Downstream callers choose the path by peeking at the first byte.
//!
//! ## Модель угрозы
//!
//! Даже с MLS + blind-postman сервер видит `sender_index` в каждом MLSMessage и может
//! реконструировать социальный граф (кто пишет кому, как часто). Sealed Sender (Signal 2018)
//! оборачивает payload так, что сервер видит только получателя (group_id), не отправителя.
//! Отправитель аутентифицируется inner-подписью, которую проверяет только получатель.
//!
//! ## Конструкция
//!
//! Отправитель:
//! 1. Генерирует эфемерный X25519 keypair.
//! 2. ECDH с `recipient_identity_x25519_pub` → shared secret.
//! 3. HKDF(shared, salt=domain_sep, info=eph_pub‖recip_pub) → aead_key (32) + aead_nonce (12).
//! 4. Строит inner_plaintext = `sender_identity_pub || ed25519_signature || message`.
//!    Подпись покрывает `DOMAIN_SEP || eph_pub || message` — привязка к конкретному envelope.
//! 5. Паддит до бакета через umbrella-padding.
//! 6. AEAD encrypt с AD = `version || eph_pub || recip_pub`.
//! 7. Wire: `[0x01] || eph_pub || inner_ct`.
//!
//! Получатель делает обратные шаги: DH своим X25519-identity, выводит тот же ключ,
//! AEAD decrypt, strip padding, разбирает inner, проверяет ed25519-подпись.
//!
//! ## Threat model
//!
//! Even with MLS + blind-postman the server sees `sender_index` in every MLSMessage and can
//! reconstruct the social graph. Sealed Sender (Signal 2018) wraps the payload so the server
//! sees only the recipient (group_id), not the sender. The sender authenticates via an inner
//! signature visible only to the recipient.
//!
//! ## Construction
//!
//! Sender: ephemeral X25519 → ECDH with recipient X25519-identity → HKDF → AEAD encrypt
//! `sender_id_pub || signature || message` padded to bucket, with AD = version‖eph_pub‖recip_pub.
//! Wire: `version(1) || eph_pub(32) || ct`. Recipient reverses and verifies the signature.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "pq")]
pub mod hybrid_envelope;
pub mod self_destruct;
pub mod version;

#[cfg(feature = "pq")]
pub use hybrid_envelope::{seal_v2, unseal_v2, V2_DOMAIN_SEP, V2_MIN_WIRE_LEN};
pub use version::SealedSenderVersion;

use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;

use umbrella_crypto_primitives::aead::{AeadKey, AeadNonce, AEAD_KEY_LEN, AEAD_NONCE_LEN};
use umbrella_crypto_primitives::dh::{X25519Ephemeral, X25519Public, X25519_PUBLIC_LEN};
use umbrella_crypto_primitives::kdf::hkdf_sha256;
use umbrella_crypto_primitives::secret::SecretBytes;
use umbrella_crypto_primitives::sig::{
    Ed25519Signature, PublicVerifyingKey, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};
use umbrella_identity::{IdentityKeyPublic, IdentityX25519KeyPublic, KeyStore};
use umbrella_padding::{pad_to_bucket, strip_padding, PaddingError};

/// Версия wire-format (0x01).
/// Wire-format version (0x01).
pub const VERSION: u8 = 0x01;

/// Длина поля версии в wire. Wire version field length.
pub const VERSION_LEN: usize = 1;

/// Domain separator для HKDF info и inner-signature. ASCII literal.
/// Domain separator for HKDF info and inner signature. ASCII literal.
pub const DOMAIN_SEP: &[u8] = b"umbrellax-sealed-sender-v1";

/// Длина inner header = sender_identity_pub (32) + signature (64) = 96 байт.
/// Inner header length = sender_identity_pub (32) + signature (64) = 96 bytes.
pub const INNER_HEADER_LEN: usize = PUBLIC_KEY_LEN + SIGNATURE_LEN;

/// Минимальный wire: version + eph_pub + AEAD(bucket_min + tag). bucket_min = 256, tag = 16.
/// Minimum wire: version + eph_pub + AEAD(bucket_min + tag). bucket_min = 256, tag = 16.
pub const MIN_WIRE_LEN: usize = VERSION_LEN + X25519_PUBLIC_LEN + 256 + 16;

/// Максимальный application-payload (byte). Max bucket минус inner header минус padding-header.
/// Max application payload (bytes). Max bucket minus inner header minus padding header.
pub const MAX_PAYLOAD: usize = umbrella_padding::MAX_PAYLOAD - INNER_HEADER_LEN;

/// Ошибки Sealed Sender. Sealed Sender errors.
#[derive(Debug, Error)]
pub enum SealedSenderError {
    /// Wire слишком короткий или неверного формата.
    /// Wire too short or malformed.
    #[error("malformed sealed envelope wire: {reason}")]
    Malformed {
        /// Конкретная причина. Specific reason.
        reason: &'static str,
    },
    /// Версия wire-format не поддерживается (ожидается 0x01).
    /// Wire-format version unsupported (expected 0x01).
    #[error("unsupported sealed envelope version: {got}")]
    UnsupportedVersion {
        /// Полученная версия. Received version.
        got: u8,
    },
    /// Payload не помещается в максимальный padding bucket (1 МБ минус overhead).
    /// Payload does not fit in the maximum padding bucket (1 MiB minus overhead).
    #[error("payload too large: {payload_len} bytes (max {max})")]
    PayloadTooLarge {
        /// Длина запроса. Requested length.
        payload_len: usize,
        /// Максимум. Maximum.
        max: usize,
    },
    /// Ошибка padding (не валидный bucket, ненулевой байт в хвосте, tampered length).
    /// Padding error (invalid bucket, non-zero trailer, tampered length).
    #[error("padding error: {0}")]
    Padding(#[from] PaddingError),
    /// Ошибка нижележащей crypto-операции (AEAD fail, invalid key).
    /// Underlying crypto error (AEAD fail, invalid key).
    #[error("crypto error: {0}")]
    Crypto(#[from] umbrella_crypto_primitives::CryptoError),
    /// Inner ed25519-подпись не проходит verification.
    /// Inner Ed25519 signature verification failed.
    #[error("inner sender signature verification failed")]
    InvalidSignature,
    /// Sender identity public key не является валидной точкой Ed25519 curve.
    /// Sender identity public key is not a valid Ed25519 curve point.
    #[error("malformed sender identity public key")]
    MalformedSenderKey,

    // Этап 8 расширения (блок 8.6). V2 hybrid envelope (ADR-011 Решение 4
    // расширение). Stage 8 extensions (block 8.6).
    /// Wire-format envelope имеет version byte `0x02` (V2 hybrid X-Wing), но
    /// крейт скомпилирован без feature `pq`. Caller получает явный сигнал что
    /// для unseal нужно собрать с feature `pq` и предоставить X-Wing secret
    /// seed — никакого silent fallback на V1 (постулат 14).
    ///
    /// Wire-format envelope carries version byte `0x02` (V2 hybrid X-Wing)
    /// but the crate is compiled without feature `pq`. The caller gets an
    /// explicit signal that unsealing requires building with feature `pq` and
    /// providing the X-Wing secret seed — no silent fallback to V1
    /// (postulate 14).
    #[error("sealed envelope V2 requires feature `pq`: got version 0x{version:02x}")]
    PqFeatureRequired {
        /// Полученная версия. Received version.
        version: u8,
    },

    /// V2 wire-format invalid: длина не соответствует expected layout либо
    /// X-Wing ciphertext / shared secret имеют неверную длину. Содержит
    /// стабильный string tag (`"too_short"`, `"xwing_decaps_failed"`, и т.п.).
    ///
    /// V2 wire-format invalid: length does not match the expected layout or
    /// the X-Wing ciphertext / shared secret have wrong length. Carries a
    /// stable string tag (`"too_short"`, `"xwing_decaps_failed"`, etc.).
    #[error("invalid V2 sealed envelope: {0}")]
    InvalidV2Envelope(&'static str),
}

/// Псевдоним Result для крейта. Crate result alias.
pub type Result<T, E = SealedSenderError> = core::result::Result<T, E>;

/// Расшифрованный текст сообщения, который затирает память при удалении.
/// Decrypted message plaintext that zeroizes its memory on drop.
#[derive(Clone)]
pub struct OpenedMessage(Zeroizing<Vec<u8>>);

impl OpenedMessage {
    /// Создаёт сообщение из уже защищённого буфера.
    /// Creates a message from an already zeroizing buffer.
    pub(crate) fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    /// Возвращает байты сообщения без копирования.
    /// Returns the message bytes without copying.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Возвращает длину сообщения в байтах.
    /// Returns the message length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Проверяет, пустое ли сообщение.
    /// Returns whether the message is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Передаёт владение защищённым буфером вызывающему коду.
    /// Transfers ownership of the zeroizing buffer to the caller.
    #[must_use]
    pub fn into_zeroizing_vec(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl AsRef<[u8]> for OpenedMessage {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl core::ops::Deref for OpenedMessage {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl core::fmt::Debug for OpenedMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenedMessage")
            .field("len", &self.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl PartialEq for OpenedMessage {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for OpenedMessage {}

impl PartialEq<Vec<u8>> for OpenedMessage {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl PartialEq<&[u8]> for OpenedMessage {
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_slice() == *other
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for OpenedMessage {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.as_slice() == other.as_slice()
    }
}

/// Распакованный Sealed Sender envelope (после unseal).
/// Unpacked Sealed Sender envelope (after unseal).
#[derive(Clone, PartialEq, Eq)]
pub struct OpenedEnvelope {
    /// Публичный identity Ed25519-ключ отправителя (аутентифицирован inner-подписью).
    /// Sender public Ed25519 identity key (authenticated by the inner signature).
    pub sender_identity: IdentityKeyPublic,
    /// Плейнтекст сообщения, который затирается при удалении.
    /// Message plaintext, zeroized when dropped.
    pub message: OpenedMessage,
}

impl core::fmt::Debug for OpenedEnvelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenedEnvelope")
            .field("sender_identity", &self.sender_identity)
            .field("message_len", &self.message.len())
            .field("message", &"<redacted>")
            .finish()
    }
}

/// Запечатывает application-message так, чтобы сервер не видел отправителя.
///
/// - `keystore` — отправитель (identity pubkey + inner signature).
/// - `recipient_x25519_pub` — публичный X25519 identity получателя (из KT log).
/// - `message` — payload; west automatically padded до ближайшего bucket.
/// - `rng` — CSPRNG для эфемерного keypair.
///
/// Seals an application message so the server cannot see the sender.
///
/// - `keystore` — sender (identity pubkey + inner signature).
/// - `recipient_x25519_pub` — recipient's public X25519 identity (from KT log).
/// - `message` — payload; automatically padded to the nearest bucket.
/// - `rng` — CSPRNG for the ephemeral keypair.
pub fn seal<R: CryptoRng + RngCore>(
    keystore: &dyn KeyStore,
    recipient_x25519_pub: &IdentityX25519KeyPublic,
    message: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    if message.len() > MAX_PAYLOAD {
        return Err(SealedSenderError::PayloadTooLarge {
            payload_len: message.len(),
            max: MAX_PAYLOAD,
        });
    }

    let ephemeral = X25519Ephemeral::generate(rng);
    let eph_pub = ephemeral.public_key();
    let recipient_x25519 = X25519Public::from_bytes(recipient_x25519_pub.to_bytes())?;

    let shared = ephemeral.diffie_hellman(&recipient_x25519);
    let (aead_key, aead_nonce) = derive_keys(&shared, &eph_pub, recipient_x25519_pub)?;

    let sender_identity = keystore.identity_public();
    let sig_payload = signature_payload(&eph_pub, message);
    let sig = keystore.sign_with_identity(sig_payload.as_slice());

    // SPEC-08 §5.2 step 9 — `inner_plaintext` + `padded_blob` zeroize on drop
    // через `Zeroizing<Vec<u8>>` (row 11 cold-boot mitigation, F-50 closure).
    // SPEC-08 §5.2 step 9 — `inner_plaintext` + `padded_blob` zeroize on drop
    // via `Zeroizing<Vec<u8>>` (row 11 cold-boot mitigation, F-50 closure).
    let mut inner: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(INNER_HEADER_LEN + message.len()));
    inner.extend_from_slice(&sender_identity.to_bytes());
    inner.extend_from_slice(&sig.to_bytes());
    inner.extend_from_slice(message);

    let padded: Zeroizing<Vec<u8>> = Zeroizing::new(pad_to_bucket(&inner)?);

    let ad = aead_ad(&eph_pub, recipient_x25519_pub);
    let inner_ct = aead_key.encrypt(&aead_nonce, &ad, &padded)?;

    let mut wire = Vec::with_capacity(VERSION_LEN + X25519_PUBLIC_LEN + inner_ct.len());
    wire.push(VERSION);
    wire.extend_from_slice(&eph_pub.to_bytes());
    wire.extend_from_slice(&inner_ct);
    Ok(wire)
}

/// Раскрывает Sealed Sender envelope для получателя (X25519 приватный ключ в keystore).
///
/// При tampering / wrong recipient / неверной подписи — конкретный вариант ошибки.
///
/// Unseals a Sealed Sender envelope for the recipient (X25519 private key in keystore).
///
/// On tampering / wrong recipient / bad signature — the corresponding error variant.
pub fn unseal(keystore: &dyn KeyStore, wire: &[u8]) -> Result<OpenedEnvelope> {
    if wire.len() < MIN_WIRE_LEN {
        return Err(SealedSenderError::Malformed {
            reason: "wire shorter than minimum",
        });
    }
    if wire[0] != VERSION {
        return Err(SealedSenderError::UnsupportedVersion { got: wire[0] });
    }

    let mut eph_pub_bytes = [0u8; X25519_PUBLIC_LEN];
    eph_pub_bytes.copy_from_slice(&wire[VERSION_LEN..VERSION_LEN + X25519_PUBLIC_LEN]);
    let eph_pub = X25519Public::from_bytes(eph_pub_bytes)?;

    let inner_ct = &wire[VERSION_LEN + X25519_PUBLIC_LEN..];

    let eph_as_identity = IdentityX25519KeyPublic::from_bytes(&eph_pub_bytes).map_err(|_| {
        SealedSenderError::Malformed {
            reason: "ephemeral public key invalid",
        }
    })?;
    let shared = keystore.x25519_dh_with_identity(&eph_as_identity);

    let own_recipient_x25519 = keystore.identity_x25519_public();
    let (aead_key, aead_nonce) = derive_keys(&shared, &eph_pub, &own_recipient_x25519)?;

    let ad = aead_ad(&eph_pub, &own_recipient_x25519);
    // SPEC-08 §5.2 step 9 — `padded_blob` zeroize on drop через
    // `Zeroizing<Vec<u8>>`; `inner` — borrow в этот же буфер (row 11
    // cold-boot mitigation, F-50 closure).
    // SPEC-08 §5.2 step 9 — `padded_blob` zeroizes on drop via
    // `Zeroizing<Vec<u8>>`; `inner` is a borrow into the same buffer
    // (row 11 cold-boot mitigation, F-50 closure).
    let padded: Zeroizing<Vec<u8>> =
        Zeroizing::new(aead_key.decrypt(&aead_nonce, &ad, inner_ct)?);
    let inner = strip_padding(&padded)?;

    if inner.len() < INNER_HEADER_LEN {
        return Err(SealedSenderError::Malformed {
            reason: "inner plaintext shorter than header",
        });
    }

    let mut sender_id_bytes = [0u8; PUBLIC_KEY_LEN];
    sender_id_bytes.copy_from_slice(&inner[..PUBLIC_KEY_LEN]);
    let sender_identity = IdentityKeyPublic::from_bytes(&sender_id_bytes)
        .map_err(|_| SealedSenderError::MalformedSenderKey)?;

    let mut sig_bytes = [0u8; SIGNATURE_LEN];
    sig_bytes.copy_from_slice(&inner[PUBLIC_KEY_LEN..INNER_HEADER_LEN]);
    let sig = Ed25519Signature::from_bytes(&sig_bytes);

    let mut message = Zeroizing::new(Vec::with_capacity(inner.len() - INNER_HEADER_LEN));
    message.extend_from_slice(&inner[INNER_HEADER_LEN..]);

    let sig_payload = signature_payload(&eph_pub, message.as_slice());
    let vk = PublicVerifyingKey::from_bytes(&sender_id_bytes)
        .map_err(|_| SealedSenderError::MalformedSenderKey)?;
    vk.verify(sig_payload.as_slice(), &sig)
        .map_err(|_| SealedSenderError::InvalidSignature)?;

    Ok(OpenedEnvelope {
        sender_identity,
        message: OpenedMessage::from_zeroizing(message),
    })
}

fn derive_keys(
    shared: &SecretBytes<32>,
    eph_pub: &X25519Public,
    recipient_x25519_pub: &IdentityX25519KeyPublic,
) -> Result<(AeadKey, AeadNonce)> {
    let mut info = Vec::with_capacity(DOMAIN_SEP.len() + 2 * X25519_PUBLIC_LEN);
    info.extend_from_slice(DOMAIN_SEP);
    info.extend_from_slice(&eph_pub.to_bytes());
    info.extend_from_slice(&recipient_x25519_pub.to_bytes());

    let okm = hkdf_sha256::<{ AEAD_KEY_LEN + AEAD_NONCE_LEN }>(DOMAIN_SEP, shared.expose(), &info)?;
    let bytes = okm.expose();

    let mut key_bytes = SecretBytes::<AEAD_KEY_LEN>::zeroed();
    key_bytes
        .expose_mut()
        .copy_from_slice(&bytes[..AEAD_KEY_LEN]);
    let aead_key = AeadKey::from_bytes(&key_bytes);

    let mut nonce_raw = [0u8; AEAD_NONCE_LEN];
    nonce_raw.copy_from_slice(&bytes[AEAD_KEY_LEN..AEAD_KEY_LEN + AEAD_NONCE_LEN]);
    let aead_nonce = AeadNonce::from_bytes(nonce_raw);

    Ok((aead_key, aead_nonce))
}

fn signature_payload(eph_pub: &X25519Public, message: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(
        DOMAIN_SEP.len() + X25519_PUBLIC_LEN + message.len(),
    ));
    payload.extend_from_slice(DOMAIN_SEP);
    payload.extend_from_slice(&eph_pub.to_bytes());
    payload.extend_from_slice(message);
    payload
}

fn aead_ad(eph_pub: &X25519Public, recipient_x25519_pub: &IdentityX25519KeyPublic) -> Vec<u8> {
    let mut ad = Vec::with_capacity(VERSION_LEN + 2 * X25519_PUBLIC_LEN);
    ad.push(VERSION);
    ad.extend_from_slice(&eph_pub.to_bytes());
    ad.extend_from_slice(&recipient_x25519_pub.to_bytes());
    ad
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use rand_core::OsRng;
    use umbrella_identity::{Clock, IdentitySeed, InMemoryKeyStore, MnemonicLanguage, SystemClock};

    fn fresh_keystore() -> Arc<InMemoryKeyStore> {
        let mut rng = OsRng;
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        Arc::new(InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>).unwrap())
    }

    #[test]
    fn seal_unseal_round_trip_short_message() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let mut rng = OsRng;
        let wire = seal(
            alice.as_ref(),
            &bob.identity_x25519_public(),
            b"hello-bob",
            &mut rng,
        )
        .unwrap();
        let opened = unseal(bob.as_ref(), &wire).unwrap();
        assert_eq!(opened.sender_identity, alice.identity_public());
        assert_eq!(opened.message, b"hello-bob");
    }

    #[test]
    fn seal_unseal_empty_message() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let mut rng = OsRng;
        let wire = seal(alice.as_ref(), &bob.identity_x25519_public(), b"", &mut rng).unwrap();
        let opened = unseal(bob.as_ref(), &wire).unwrap();
        assert_eq!(opened.message, Vec::<u8>::new());
        assert_eq!(opened.sender_identity, alice.identity_public());
    }

    #[test]
    fn seal_unseal_boundary_bucket_transitions() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let mut rng = OsRng;
        for len in [0, 1, 100, 155, 156, 157, 900, 1000, 4000] {
            let msg = vec![0x42; len];
            let wire = seal(
                alice.as_ref(),
                &bob.identity_x25519_public(),
                &msg,
                &mut rng,
            )
            .unwrap();
            let opened = unseal(bob.as_ref(), &wire).unwrap();
            assert_eq!(opened.message, msg, "len={len}");
        }
    }

    #[test]
    fn wire_starts_with_version_byte_and_fits_bucket() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let mut rng = OsRng;
        let wire = seal(
            alice.as_ref(),
            &bob.identity_x25519_public(),
            b"hi",
            &mut rng,
        )
        .unwrap();
        assert_eq!(wire[0], VERSION);
        assert!(wire.len() >= MIN_WIRE_LEN);
    }

    #[test]
    fn ephemeral_pubkey_not_equal_to_identity_pubkey() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let mut rng = OsRng;
        let wire = seal(
            alice.as_ref(),
            &bob.identity_x25519_public(),
            b"hi",
            &mut rng,
        )
        .unwrap();
        let eph = &wire[VERSION_LEN..VERSION_LEN + X25519_PUBLIC_LEN];
        assert_ne!(eph, &bob.identity_x25519_public().to_bytes());
        assert_ne!(eph, &alice.identity_x25519_public().to_bytes());
    }

    #[test]
    fn unseal_rejects_wrong_version() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let mut rng = OsRng;
        let mut wire = seal(
            alice.as_ref(),
            &bob.identity_x25519_public(),
            b"hi",
            &mut rng,
        )
        .unwrap();
        wire[0] = 0x02;
        assert!(matches!(
            unseal(bob.as_ref(), &wire),
            Err(SealedSenderError::UnsupportedVersion { got: 0x02 })
        ));
    }

    #[test]
    fn unseal_rejects_too_short_wire() {
        let bob = fresh_keystore();
        let short = vec![0x01; MIN_WIRE_LEN - 1];
        assert!(matches!(
            unseal(bob.as_ref(), &short),
            Err(SealedSenderError::Malformed { .. })
        ));
    }

    #[test]
    fn unseal_rejects_tampered_ciphertext() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let mut rng = OsRng;
        let mut wire = seal(
            alice.as_ref(),
            &bob.identity_x25519_public(),
            b"hi",
            &mut rng,
        )
        .unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        let result = unseal(bob.as_ref(), &wire);
        assert!(matches!(result, Err(SealedSenderError::Crypto(_))));
    }

    #[test]
    fn unseal_rejects_tampered_ephemeral_pubkey() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let mut rng = OsRng;
        let mut wire = seal(
            alice.as_ref(),
            &bob.identity_x25519_public(),
            b"hi",
            &mut rng,
        )
        .unwrap();
        wire[VERSION_LEN] ^= 0x01;
        let result = unseal(bob.as_ref(), &wire);
        assert!(result.is_err(), "tamper eph_pub ломает DH и AEAD");
    }

    #[test]
    fn wrong_recipient_cannot_unseal() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let eve = fresh_keystore();
        let mut rng = OsRng;
        let wire = seal(
            alice.as_ref(),
            &bob.identity_x25519_public(),
            b"for-bob-only",
            &mut rng,
        )
        .unwrap();
        let result = unseal(eve.as_ref(), &wire);
        assert!(
            result.is_err(),
            "Eve (не получатель) не должна расшифровать envelope"
        );
    }

    #[test]
    fn recipient_learns_sender_identity() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let mut rng = OsRng;
        let wire = seal(
            alice.as_ref(),
            &bob.identity_x25519_public(),
            b"msg",
            &mut rng,
        )
        .unwrap();
        let opened = unseal(bob.as_ref(), &wire).unwrap();
        assert_eq!(opened.sender_identity, alice.identity_public());
    }

    #[test]
    fn opened_envelope_debug_redacts_message_plaintext() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let mut rng = OsRng;
        let wire = seal(
            alice.as_ref(),
            &bob.identity_x25519_public(),
            b"private-chat-secret",
            &mut rng,
        )
        .unwrap();

        let opened = unseal(bob.as_ref(), &wire).unwrap();
        let debug = format!("{opened:?}");

        assert!(
            !debug.contains("private-chat-secret"),
            "Debug output must not leak message plaintext"
        );
        assert!(
            !debug.contains("112, 114, 105, 118, 97, 116, 101"),
            "Debug output must not leak message bytes"
        );
    }

    #[test]
    fn opened_envelope_message_is_zeroizing_wrapper() {
        fn assert_zeroizing_message_type(_: &OpenedMessage) {}

        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let mut rng = OsRng;
        let wire = seal(
            alice.as_ref(),
            &bob.identity_x25519_public(),
            b"wipe-me-after-drop",
            &mut rng,
        )
        .unwrap();

        let opened = unseal(bob.as_ref(), &wire).unwrap();

        assert_zeroizing_message_type(&opened.message);
        assert_eq!(opened.message.as_ref(), b"wipe-me-after-drop");
    }

    #[test]
    fn same_message_twice_produces_different_wire() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let mut rng = OsRng;
        let w1 = seal(
            alice.as_ref(),
            &bob.identity_x25519_public(),
            b"x",
            &mut rng,
        )
        .unwrap();
        let w2 = seal(
            alice.as_ref(),
            &bob.identity_x25519_public(),
            b"x",
            &mut rng,
        )
        .unwrap();
        assert_ne!(
            w1, w2,
            "ephemeral X25519 должен делать каждый envelope уникальным"
        );
    }

    #[test]
    fn rejects_payload_over_max() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let mut rng = OsRng;
        let payload = vec![0u8; MAX_PAYLOAD + 1];
        let result = seal(
            alice.as_ref(),
            &bob.identity_x25519_public(),
            &payload,
            &mut rng,
        );
        assert!(matches!(
            result,
            Err(SealedSenderError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn accepts_payload_at_max() {
        let alice = fresh_keystore();
        let bob = fresh_keystore();
        let mut rng = OsRng;
        let payload = vec![0u8; MAX_PAYLOAD];
        let wire = seal(
            alice.as_ref(),
            &bob.identity_x25519_public(),
            &payload,
            &mut rng,
        )
        .expect("max payload должен проходить");
        let opened = unseal(bob.as_ref(), &wire).unwrap();
        assert_eq!(opened.message.len(), MAX_PAYLOAD);
    }

    // === Property-based ===

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(24))]

        #[test]
        fn prop_round_trip_random_payload(
            payload in proptest::collection::vec(proptest::num::u8::ANY, 0..2048)
        ) {
            let alice = fresh_keystore();
            let bob = fresh_keystore();
            let mut rng = OsRng;
            let wire = seal(alice.as_ref(), &bob.identity_x25519_public(), &payload, &mut rng).unwrap();
            let opened = unseal(bob.as_ref(), &wire).unwrap();
            proptest::prop_assert_eq!(opened.message, payload);
            proptest::prop_assert_eq!(opened.sender_identity, alice.identity_public());
        }

        #[test]
        fn prop_tamper_wire_byte_either_fails_or_changes_output(
            payload_len in 0usize..128,
            offset_seed in 0usize..10_000,
            xor_byte in 1u8..=255,
        ) {
            use std::panic::{catch_unwind, AssertUnwindSafe};
            let alice = fresh_keystore();
            let bob = fresh_keystore();
            let mut rng = OsRng;
            let payload = vec![0x42; payload_len];
            let mut wire = seal(alice.as_ref(), &bob.identity_x25519_public(), &payload, &mut rng).unwrap();
            let pos = offset_seed % wire.len();
            wire[pos] ^= xor_byte;
            let result = catch_unwind(AssertUnwindSafe(|| unseal(bob.as_ref(), &wire)));
            // Допустимо: Err, panic, либо Ok с payload != оригинал. Недопустимо: Ok с payload == оригинал.
            // Acceptable: Err, panic, or Ok with payload != original. Unacceptable: Ok with payload == original.
            if let Ok(Ok(opened)) = result {
                proptest::prop_assert!(
                    opened.message != payload || opened.sender_identity != alice.identity_public(),
                    "tamper пропускает оригинал как валидный — AEAD/signature forgery"
                );
            }
        }
    }
}
