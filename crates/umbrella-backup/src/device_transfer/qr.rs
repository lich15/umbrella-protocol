//! `DevicePairingQr` — бинарный payload QR-кода для Secret device-transfer.
//! `DevicePairingQr` — binary QR payload for Secret device-transfer.
//!
//! Старое устройство (responder) показывает QR, новое (initiator) сканирует.
//! QR содержит всё что initiator'у нужно для `Noise_IK` handshake + доказательство
//! что responder действительно owner identity-key (Ed25519 подпись под identity
//! ключом покрывает весь QR payload).
//!
//! Old device (responder) displays QR, new device (initiator) scans. QR
//! contains everything initiator needs for `Noise_IK` handshake plus proof
//! that responder owns the identity key (Ed25519 signature under the
//! identity key covers the entire QR payload).
//!
//! Layout (169 bytes binary):
//! ```text
//! [0..1)     version                    : u8 = 0x01
//! [1..33)    responder_identity_pubkey  : 32 bytes (Ed25519)
//! [33..65)   responder_ephemeral_static : 32 bytes (X25519)
//! [65..97)   pairing_challenge          : 32 bytes (CSPRNG)
//! [97..105)  expiry_unix_millis         : u64 BE
//! [105..169) identity_signature         : 64 bytes (Ed25519)
//! ```
//!
//! Base32 (RFC 4648 no padding) для отображения в QR даёт ~272 символа →
//! QR версии 11-12 (37×37..41×41 модулей, error-correction level M).
//!
//! Base32 (RFC 4648 no padding) for QR display yields ~272 characters →
//! QR version 11-12 (37×37..41×41 modules, error correction level M).

use core::convert::TryInto;

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey as DalekVerifyingKey};

use crate::error::BackupError;

/// Версия QR wire-format (текущая — 1). QR wire format version (current — 1).
pub const QR_VERSION: u8 = 0x01;

/// Длина identity / ephemeral public key в байтах (Ed25519 / X25519).
/// Identity / ephemeral public key length (Ed25519 / X25519).
pub const PUBKEY_LEN: usize = 32;

/// Длина pairing challenge в байтах. Pairing challenge length.
pub const PAIRING_CHALLENGE_LEN: usize = 32;

/// Длина Ed25519 signature. Ed25519 signature length.
pub const QR_SIG_LEN: usize = 64;

/// Полный размер QR binary payload в байтах.
/// Full size of the QR binary payload in bytes.
pub const QR_PAYLOAD_LEN: usize =
    1 + PUBKEY_LEN + PUBKEY_LEN + PAIRING_CHALLENGE_LEN + 8 + QR_SIG_LEN;

/// Domain separator для canonical QR signing input.
/// Domain separator for canonical QR signing input.
pub const QR_SIGNATURE_DOMAIN: &[u8] = b"umbrellax-device-pairing-qr-v1";

/// Длина canonical signing input (без domain separator) = payload minus signature.
const CANONICAL_QR_BODY_LEN: usize = 1 + PUBKEY_LEN + PUBKEY_LEN + PAIRING_CHALLENGE_LEN + 8;

/// QR-код для начала device-pairing. QR code to initiate device-pairing.
///
/// # Invariants
/// - `version == QR_VERSION` (enforced via [`Self::from_bytes`]).
/// - `expiry_unix_millis` в будущем относительно clock'а верификатора.
/// - `identity_signature` валидна под `responder_identity_pubkey` для
///   `canonical_signing_input()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePairingQr {
    /// Версия QR wire-format. QR wire format version.
    pub version: u8,
    /// Ed25519 long-term identity pubkey старого устройства.
    /// Ed25519 long-term identity pubkey of the old device.
    pub responder_identity_pubkey: [u8; PUBKEY_LEN],
    /// X25519 static pubkey эфемерной пары responder'а специально для этого QR.
    /// X25519 static pubkey of the responder's ephemeral pair for this QR.
    pub responder_ephemeral_static: [u8; PUBKEY_LEN],
    /// Случайное значение, привязывающее pairing к сессии (anti-replay).
    /// Random value binding pairing to a session (anti-replay).
    pub pairing_challenge: [u8; PAIRING_CHALLENGE_LEN],
    /// Unix-timestamp миллисекунд до которого QR действителен.
    /// Unix-millisecond timestamp until which the QR is valid.
    pub expiry_unix_millis: u64,
    /// Ed25519 подпись всего выше под `responder_identity_pubkey`.
    /// Ed25519 signature over all of the above, under `responder_identity_pubkey`.
    pub identity_signature: [u8; QR_SIG_LEN],
}

impl DevicePairingQr {
    /// Canonical signing input (то что подписывается `identity_signature`).
    /// Canonical signing input (what `identity_signature` signs).
    #[must_use]
    pub fn canonical_signing_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(QR_SIGNATURE_DOMAIN.len() + CANONICAL_QR_BODY_LEN);
        out.extend_from_slice(QR_SIGNATURE_DOMAIN);
        out.push(self.version);
        out.extend_from_slice(&self.responder_identity_pubkey);
        out.extend_from_slice(&self.responder_ephemeral_static);
        out.extend_from_slice(&self.pairing_challenge);
        out.extend_from_slice(&self.expiry_unix_millis.to_be_bytes());
        out
    }

    /// Сериализация в 169-байтовый payload.
    /// Serialization into the 169-byte payload.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; QR_PAYLOAD_LEN] {
        let mut out = [0u8; QR_PAYLOAD_LEN];
        let mut off = 0;
        out[off] = self.version;
        off += 1;
        out[off..off + PUBKEY_LEN].copy_from_slice(&self.responder_identity_pubkey);
        off += PUBKEY_LEN;
        out[off..off + PUBKEY_LEN].copy_from_slice(&self.responder_ephemeral_static);
        off += PUBKEY_LEN;
        out[off..off + PAIRING_CHALLENGE_LEN].copy_from_slice(&self.pairing_challenge);
        off += PAIRING_CHALLENGE_LEN;
        out[off..off + 8].copy_from_slice(&self.expiry_unix_millis.to_be_bytes());
        off += 8;
        out[off..off + QR_SIG_LEN].copy_from_slice(&self.identity_signature);
        out
    }

    /// Парсинг 169 байт с валидацией длины и версии. Подпись **не** проверяется —
    /// вызовите [`Self::verify_identity`] после успешного парсинга + [`Self::ensure_not_expired`].
    ///
    /// Parse 169 bytes with length and version validation. The signature is
    /// **not** verified here — call [`Self::verify_identity`] after parse +
    /// [`Self::ensure_not_expired`].
    ///
    /// # Errors
    /// - [`BackupError::QrPayloadTruncated`] если `data.len() != QR_PAYLOAD_LEN`.
    /// - [`BackupError::QrVersionMismatch`] если версия не совпадает.
    pub fn from_bytes(data: &[u8]) -> Result<Self, BackupError> {
        if data.len() != QR_PAYLOAD_LEN {
            return Err(BackupError::QrPayloadTruncated);
        }
        let version = data[0];
        if version != QR_VERSION {
            return Err(BackupError::QrVersionMismatch {
                expected: QR_VERSION,
                found: version,
            });
        }
        let mut off = 1;
        let responder_identity_pubkey: [u8; PUBKEY_LEN] = data[off..off + PUBKEY_LEN]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        off += PUBKEY_LEN;
        let responder_ephemeral_static: [u8; PUBKEY_LEN] =
            data[off..off + PUBKEY_LEN]
                .try_into()
                .map_err(|_| BackupError::InvalidWireFormat)?;
        off += PUBKEY_LEN;
        let pairing_challenge: [u8; PAIRING_CHALLENGE_LEN] = data[off..off + PAIRING_CHALLENGE_LEN]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        off += PAIRING_CHALLENGE_LEN;
        let expiry_bytes: [u8; 8] = data[off..off + 8]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        off += 8;
        let expiry_unix_millis = u64::from_be_bytes(expiry_bytes);
        let identity_signature: [u8; QR_SIG_LEN] = data[off..off + QR_SIG_LEN]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        Ok(Self {
            version,
            responder_identity_pubkey,
            responder_ephemeral_static,
            pairing_challenge,
            expiry_unix_millis,
            identity_signature,
        })
    }

    /// Base32 (RFC 4648, no padding) encoding для QR display.
    /// Base32 (RFC 4648, no padding) encoding for QR display.
    #[must_use]
    pub fn to_base32(&self) -> String {
        BASE32_NOPAD.encode(&self.to_bytes())
    }

    /// Декодирование из Base32 представления.
    /// Decode from base32 representation.
    ///
    /// # Errors
    /// - [`BackupError::InvalidWireFormat`] если строка не валидный base32.
    /// - Ошибки [`Self::from_bytes`] если длина/версия не совпали.
    pub fn from_base32(encoded: &str) -> Result<Self, BackupError> {
        let bytes = BASE32_NOPAD
            .decode(encoded.as_bytes())
            .map_err(|_| BackupError::InvalidWireFormat)?;
        Self::from_bytes(&bytes)
    }

    /// Проверить что QR не просрочен относительно clock'а.
    /// Verify that QR is not expired relative to clock.
    ///
    /// # Errors
    /// - [`BackupError::QrExpired`] если `now_unix_millis >= expiry_unix_millis`.
    pub fn ensure_not_expired(&self, now_unix_millis: u64) -> Result<(), BackupError> {
        if now_unix_millis >= self.expiry_unix_millis {
            return Err(BackupError::QrExpired);
        }
        Ok(())
    }

    /// Проверить Ed25519 identity-signature.
    /// Verify Ed25519 identity-signature.
    ///
    /// # Errors
    /// - [`BackupError::QrSignatureInvalid`] если подпись не проходит
    ///   или pubkey невалиден.
    pub fn verify_identity(&self) -> Result<(), BackupError> {
        let vk = DalekVerifyingKey::from_bytes(&self.responder_identity_pubkey)
            .map_err(|_| BackupError::QrSignatureInvalid)?;
        let sig = DalekSignature::from_bytes(&self.identity_signature);
        let canonical = self.canonical_signing_input();
        vk.verify(&canonical, &sig)
            .map_err(|_| BackupError::QrSignatureInvalid)
    }
}

/// Собрать подписанный QR. Вызывается на стороне responder'а перед показом.
///
/// Assemble a signed QR. Called on the responder side before display.
///
/// `signer` — callback к identity-key (обычно оборачивает
/// `umbrella_identity::KeyStore::sign_with_identity`).
///
/// # Errors
/// - [`BackupError::DeviceSigning`] если signer-callback вернул ошибку.
pub fn build_signed_qr<F>(
    responder_identity_pubkey: [u8; PUBKEY_LEN],
    responder_ephemeral_static: [u8; PUBKEY_LEN],
    pairing_challenge: [u8; PAIRING_CHALLENGE_LEN],
    expiry_unix_millis: u64,
    signer: F,
) -> Result<DevicePairingQr, BackupError>
where
    F: FnOnce(&[u8]) -> Result<[u8; QR_SIG_LEN], BackupError>,
{
    let mut qr = DevicePairingQr {
        version: QR_VERSION,
        responder_identity_pubkey,
        responder_ephemeral_static,
        pairing_challenge,
        expiry_unix_millis,
        identity_signature: [0u8; QR_SIG_LEN],
    };
    let canonical = qr.canonical_signing_input();
    qr.identity_signature = signer(&canonical)?;
    Ok(qr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};

    fn make_keypair() -> (SigningKey, DalekVerifyingKey) {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn sample_qr_fixed(expiry: u64) -> (DevicePairingQr, SigningKey) {
        let (sk, vk) = make_keypair();
        let mut eph = [0u8; PUBKEY_LEN];
        OsRng.fill_bytes(&mut eph);
        let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut chal);
        let qr = build_signed_qr(vk.to_bytes(), eph, chal, expiry, |payload| {
            Ok(sk.sign(payload).to_bytes())
        })
        .unwrap();
        (qr, sk)
    }

    #[test]
    fn qr_payload_length_is_169_bytes() {
        assert_eq!(QR_PAYLOAD_LEN, 169);
    }

    #[test]
    fn qr_canonical_input_length() {
        let (qr, _) = sample_qr_fixed(1_000);
        let canonical = qr.canonical_signing_input();
        // 30 bytes domain + 1 version + 32 + 32 + 32 + 8 = 135
        assert_eq!(
            canonical.len(),
            QR_SIGNATURE_DOMAIN.len() + CANONICAL_QR_BODY_LEN
        );
        assert_eq!(&canonical[..QR_SIGNATURE_DOMAIN.len()], QR_SIGNATURE_DOMAIN);
    }

    #[test]
    fn qr_roundtrip_bytes() {
        let (qr, _) = sample_qr_fixed(10_000);
        let bytes = qr.to_bytes();
        assert_eq!(bytes.len(), QR_PAYLOAD_LEN);
        let parsed = DevicePairingQr::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, qr);
    }

    #[test]
    fn qr_roundtrip_base32() {
        let (qr, _) = sample_qr_fixed(10_000);
        let enc = qr.to_base32();
        // ~272 chars
        assert!(
            enc.len() > 260 && enc.len() < 300,
            "unexpected base32 length: {}",
            enc.len()
        );
        let parsed = DevicePairingQr::from_base32(&enc).unwrap();
        assert_eq!(parsed, qr);
    }

    #[test]
    fn qr_from_bytes_rejects_short() {
        let err = DevicePairingQr::from_bytes(&[0u8; QR_PAYLOAD_LEN - 1]).unwrap_err();
        assert!(matches!(err, BackupError::QrPayloadTruncated));
    }

    #[test]
    fn qr_from_bytes_rejects_long() {
        let err = DevicePairingQr::from_bytes(&[0u8; QR_PAYLOAD_LEN + 1]).unwrap_err();
        assert!(matches!(err, BackupError::QrPayloadTruncated));
    }

    #[test]
    fn qr_from_bytes_rejects_version_mismatch() {
        let mut bytes = [0u8; QR_PAYLOAD_LEN];
        bytes[0] = 0x02;
        let err = DevicePairingQr::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            BackupError::QrVersionMismatch {
                expected: 0x01,
                found: 0x02
            }
        ));
    }

    #[test]
    fn qr_from_base32_rejects_garbage() {
        let err = DevicePairingQr::from_base32("not-valid-base32!").unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn qr_layout_offsets() {
        let qr = DevicePairingQr {
            version: QR_VERSION,
            responder_identity_pubkey: [0x11u8; PUBKEY_LEN],
            responder_ephemeral_static: [0x22u8; PUBKEY_LEN],
            pairing_challenge: [0x33u8; PAIRING_CHALLENGE_LEN],
            expiry_unix_millis: 0x0102_0304_0506_0708,
            identity_signature: [0x44u8; QR_SIG_LEN],
        };
        let bytes = qr.to_bytes();
        assert_eq!(bytes[0], QR_VERSION);
        assert_eq!(&bytes[1..33], &[0x11u8; 32]);
        assert_eq!(&bytes[33..65], &[0x22u8; 32]);
        assert_eq!(&bytes[65..97], &[0x33u8; 32]);
        assert_eq!(
            &bytes[97..105],
            &[0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(&bytes[105..169], &[0x44u8; 64]);
    }

    #[test]
    fn qr_verify_identity_accepts_genuine() {
        let (qr, _) = sample_qr_fixed(1_000);
        qr.verify_identity().expect("signed QR must verify");
    }

    #[test]
    fn qr_verify_rejects_tampered_identity_pubkey() {
        let (mut qr, _) = sample_qr_fixed(1_000);
        qr.responder_identity_pubkey[0] ^= 1;
        let err = qr.verify_identity().unwrap_err();
        assert!(matches!(err, BackupError::QrSignatureInvalid));
    }

    #[test]
    fn qr_verify_rejects_tampered_ephemeral_static() {
        let (mut qr, _) = sample_qr_fixed(1_000);
        qr.responder_ephemeral_static[0] ^= 1;
        let err = qr.verify_identity().unwrap_err();
        assert!(matches!(err, BackupError::QrSignatureInvalid));
    }

    #[test]
    fn qr_verify_rejects_tampered_pairing_challenge() {
        let (mut qr, _) = sample_qr_fixed(1_000);
        qr.pairing_challenge[0] ^= 1;
        let err = qr.verify_identity().unwrap_err();
        assert!(matches!(err, BackupError::QrSignatureInvalid));
    }

    #[test]
    fn qr_verify_rejects_tampered_expiry() {
        let (mut qr, _) = sample_qr_fixed(1_000);
        qr.expiry_unix_millis ^= 1;
        let err = qr.verify_identity().unwrap_err();
        assert!(matches!(err, BackupError::QrSignatureInvalid));
    }

    #[test]
    fn qr_verify_rejects_tampered_signature() {
        let (mut qr, _) = sample_qr_fixed(1_000);
        qr.identity_signature[0] ^= 1;
        let err = qr.verify_identity().unwrap_err();
        assert!(matches!(err, BackupError::QrSignatureInvalid));
    }

    #[test]
    fn qr_ensure_not_expired_works() {
        let (qr, _) = sample_qr_fixed(1_000);
        assert!(qr.ensure_not_expired(500).is_ok());
        // Equal is already expired.
        let err = qr.ensure_not_expired(1_000).unwrap_err();
        assert!(matches!(err, BackupError::QrExpired));
        let err = qr.ensure_not_expired(2_000).unwrap_err();
        assert!(matches!(err, BackupError::QrExpired));
    }

    #[test]
    fn build_signed_qr_propagates_signer_error() {
        let err = build_signed_qr(
            [0u8; PUBKEY_LEN],
            [0u8; PUBKEY_LEN],
            [0u8; PAIRING_CHALLENGE_LEN],
            1_000,
            |_| Err(BackupError::DeviceSigning("hw-unavailable")),
        )
        .unwrap_err();
        assert!(matches!(err, BackupError::DeviceSigning(_)));
    }
}
