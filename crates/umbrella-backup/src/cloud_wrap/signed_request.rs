//! `SignedUnwrapRequest` — подписанный запрос на partial unwrap к Sealed Server.
//! `SignedUnwrapRequest` — signed partial-unwrap request sent to Sealed Server.
//!
//! Pattern симметричен `umbrella-oprf::attestation::SignedOprfRequest`
//! (Этап 4.4): canonical signing input под domain-separator
//! `"umbrellax-cloud-unwrap-v1"`, платформенная attestation, Ed25519
//! device-signature. На серверной стороне Sealed Server проверяет подпись,
//! валидирует attestation, lookup-ит device_pubkey в KT перед вычислением
//! `partial = k_i · R`.
//!
//! Structurally mirrors `umbrella-oprf::attestation::SignedOprfRequest` from
//! Stage 4.4: canonical signing input under domain separator
//! `"umbrellax-cloud-unwrap-v1"`, platform attestation, Ed25519 device
//! signature. Sealed Server verifies signature, validates attestation, and
//! looks up `device_pubkey` in KT before computing `partial = k_i · R`.

use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey as DalekVerifyingKey};
use heapless::Vec as HVec;

use crate::error::BackupError;

use super::params::POINT_LEN;
use super::wire::ED25519_PUB_LEN;

/// Максимум байт в платформенном attestation token (см. SPEC-05 §7).
/// Maximum platform attestation token bytes (see SPEC-05 §7).
pub const MAX_ATTESTATION_TOKEN_BYTES: usize = 4096;

/// Длина server-issued nonce в байтах. Server-issued nonce length.
pub const NONCE_LEN: usize = 32;

/// Длина Ed25519 подписи в байтах. Ed25519 signature length.
pub const DEVICE_SIG_LEN: usize = 64;

/// Длина Ed25519 public key в байтах. Ed25519 public key length.
pub const DEVICE_PUBKEY_LEN: usize = 32;

/// Длина canonical chat_id в байтах. Canonical chat_id length.
pub const CHAT_ID_LEN: usize = 32;

/// Domain separator для canonical signing input `SignedUnwrapRequest`.
/// Domain separator for canonical signing input of `SignedUnwrapRequest`.
pub const SIGNATURE_DOMAIN_SEPARATOR: &[u8] = b"umbrellax-cloud-unwrap-v1";

/// Версия wire-format `SignedUnwrapRequest`. Increment при breaking изменениях.
/// Wire-format version for `SignedUnwrapRequest`. Bump on breaking changes.
pub const UNWRAP_WIRE_VERSION: u8 = 0x01;

/// Платформа источника attestation — те же теги что в OPRF (единая политика).
/// Attestation source platform — identical tags to the OPRF stack.
///
/// Теги байтов зафиксированы в ADR-005 / SPEC-05 и не должны расходиться.
/// Byte tags are fixed by ADR-005 / SPEC-05; must not drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Platform {
    /// Apple App Attest + DeviceCheck. iOS/iPadOS 14+.
    IOs = 0x01,
    /// Google Play Integrity API. Android 8+.
    Android = 0x02,
    /// WebAuthn passkey assertion. PWA / desktop browsers.
    Web = 0x03,
    /// Тестовый провайдер — **только для unit-тестов**. Testing only.
    Testing = 0xFF,
}

impl Platform {
    /// Байтовый тег. Byte tag.
    #[inline]
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Обратный декод из тега. Reverse decode from tag.
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x01 => Some(Self::IOs),
            0x02 => Some(Self::Android),
            0x03 => Some(Self::Web),
            0xFF => Some(Self::Testing),
            _ => None,
        }
    }
}

/// Платформенный attestation прикреплённый к unwrap-запросу.
/// Platform attestation attached to an unwrap request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformAttestation {
    /// Платформа источника. Source platform.
    pub platform: Platform,
    /// Opaque-байты токена (формат платформо-специфичен).
    /// Opaque token bytes (platform-specific format).
    pub token: HVec<u8, MAX_ATTESTATION_TOKEN_BYTES>,
}

impl PlatformAttestation {
    /// Создать с проверкой длины. Construct with length validation.
    ///
    /// # Errors
    /// - [`BackupError::InvalidAttestationShape`] если token пустой или > 4096.
    pub fn new(platform: Platform, token_bytes: &[u8]) -> Result<Self, BackupError> {
        if token_bytes.is_empty() || token_bytes.len() > MAX_ATTESTATION_TOKEN_BYTES {
            return Err(BackupError::InvalidAttestationShape);
        }
        let mut token: HVec<u8, MAX_ATTESTATION_TOKEN_BYTES> = HVec::new();
        token
            .extend_from_slice(token_bytes)
            .map_err(|_| BackupError::InvalidAttestationShape)?;
        Ok(Self { platform, token })
    }
}

/// Провайдер платформенного attestation token'а.
/// Platform attestation token provider.
///
/// Реализации — в `umbrella-ffi-swift` (Apple App Attest), `umbrella-ffi-kotlin`
/// (Play Integrity), WebAuthn bridge (browser). Тесты — `TestingAttestationProvider`.
pub trait AttestationProvider {
    /// Получить свежий attestation token, привязанный к `nonce`.
    /// Obtain a fresh attestation token bound to `nonce`.
    ///
    /// # Errors
    /// Платформенные ошибки транслируются в [`BackupError::InvalidAttestationShape`]
    /// или [`BackupError::DeviceSigning`].
    fn fresh_token(&self, nonce: &[u8; NONCE_LEN]) -> Result<PlatformAttestation, BackupError>;
}

/// Testing-провайдер: детерминистический token из префикса + nonce.
/// Testing provider: deterministic token from prefix + nonce.
#[derive(Debug, Clone)]
pub struct TestingAttestationProvider {
    prefix: HVec<u8, 64>,
}

impl TestingAttestationProvider {
    /// Создать с произвольным префиксом.
    pub fn new(prefix: &[u8]) -> Self {
        let mut p: HVec<u8, 64> = HVec::new();
        let to_take = prefix.len().min(64);
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: to_take ≤ 64 by .min(64) above; HVec capacity 64"
        )]
        p.extend_from_slice(&prefix[..to_take])
            .expect("prefix ≤ 64 bytes by construction");
        Self { prefix: p }
    }
}

impl Default for TestingAttestationProvider {
    fn default() -> Self {
        Self::new(b"umbrellax-test-cloud-unwrap")
    }
}

impl AttestationProvider for TestingAttestationProvider {
    fn fresh_token(&self, nonce: &[u8; NONCE_LEN]) -> Result<PlatformAttestation, BackupError> {
        let mut buf: HVec<u8, MAX_ATTESTATION_TOKEN_BYTES> = HVec::new();
        buf.extend_from_slice(&self.prefix)
            .map_err(|_| BackupError::InvalidAttestationShape)?;
        buf.extend_from_slice(nonce)
            .map_err(|_| BackupError::InvalidAttestationShape)?;
        Ok(PlatformAttestation {
            platform: Platform::Testing,
            token: buf,
        })
    }
}

/// Caнonical signing input для `SignedUnwrapRequest`.
/// Canonical signing input for `SignedUnwrapRequest`.
///
/// Формат:
/// ```text
/// "umbrellax-cloud-unwrap-v1"     // 25 bytes domain separator
/// || 0x01                          // 1 byte wire version
/// || ephemeral_r_compressed       // 32 bytes (Ristretto255)
/// || chat_id                       // 32 bytes
/// || recipient_device_pubkey       // 32 bytes (Ed25519 pub)
/// || timestamp_unix_millis (BE)    // 8 bytes
/// || server_nonce                  // 32 bytes
/// || platform_tag (1 byte)
/// || (u32 BE) token.len()          // 4 bytes length prefix
/// || attestation_token             // variable
/// ```
///
/// Эта последовательность — то что подписывается device-key. Любое изменение
/// любого байта ломает подпись.
#[must_use]
pub fn canonical_signing_input(
    ephemeral_r: &[u8; POINT_LEN],
    chat_id: &[u8; CHAT_ID_LEN],
    recipient_device_pubkey: &[u8; ED25519_PUB_LEN],
    timestamp_unix_millis: u64,
    server_nonce: &[u8; NONCE_LEN],
    attestation: &PlatformAttestation,
) -> Vec<u8> {
    let token_len = attestation.token.len();
    let capacity = SIGNATURE_DOMAIN_SEPARATOR.len()
        + 1
        + POINT_LEN
        + CHAT_ID_LEN
        + ED25519_PUB_LEN
        + 8
        + NONCE_LEN
        + 1
        + 4
        + token_len;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(SIGNATURE_DOMAIN_SEPARATOR);
    out.push(UNWRAP_WIRE_VERSION);
    out.extend_from_slice(ephemeral_r);
    out.extend_from_slice(chat_id);
    out.extend_from_slice(recipient_device_pubkey);
    out.extend_from_slice(&timestamp_unix_millis.to_be_bytes());
    out.extend_from_slice(server_nonce);
    out.push(attestation.platform.tag());
    out.extend_from_slice(&(token_len as u32).to_be_bytes());
    out.extend_from_slice(&attestation.token);
    out
}

/// Подписанный unwrap-запрос к Sealed Servers.
/// Signed unwrap request to Sealed Servers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedUnwrapRequest {
    /// `R = r · G` — ephemeral public point из `WrappedKey`.
    /// `R = r · G` — ephemeral public point taken from `WrappedKey`.
    pub ephemeral_r: [u8; POINT_LEN],
    /// Canonical chat_id. Canonical chat_id.
    pub chat_id: [u8; CHAT_ID_LEN],
    /// Ed25519 public key устройства-получателя (запросчик).
    /// Ed25519 public key of the recipient device (requester).
    pub recipient_device_pubkey: [u8; ED25519_PUB_LEN],
    /// Unix timestamp в миллисекундах, клиент-side при построении запроса.
    /// Unix timestamp in milliseconds, client-side on request construction.
    pub timestamp_unix_millis: u64,
    /// Server-issued freshness nonce (32 bytes).
    pub server_nonce: [u8; NONCE_LEN],
    /// Платформенный attestation.
    pub attestation: PlatformAttestation,
    /// Ed25519 подпись поверх `canonical_signing_input`.
    /// Ed25519 signature over `canonical_signing_input`.
    pub device_signature: [u8; DEVICE_SIG_LEN],
    /// Ed25519 public key того же device-key (для serverside verify).
    /// Ed25519 public key of the same device-key (for server-side verify).
    pub device_pubkey: [u8; ED25519_PUB_LEN],
}

/// Собрать подписанный запрос через signer-closure.
///
/// Assemble a signed request via signer closure.
///
/// `signer` обычно оборачивает `umbrella_identity::KeyStore::sign_with_device`
/// через adapter (Этап 5.4). Это позволяет крейту не зависеть от KeyStore API
/// напрямую.
///
/// `signer` usually wraps `umbrella_identity::KeyStore::sign_with_device`
/// through an adapter (Stage 5.4). This decouples the crate from the
/// KeyStore API directly.
///
/// # Errors
/// - [`BackupError::InvalidAttestationShape`] если провайдер вернул некорректный token.
/// - [`BackupError::DeviceSigning`] если signer-callback вернул ошибку.
#[allow(clippy::too_many_arguments)] // параллель с umbrella-oprf::attestation::seal_request
pub fn seal_unwrap_request<F>(
    ephemeral_r: [u8; POINT_LEN],
    chat_id: [u8; CHAT_ID_LEN],
    recipient_device_pubkey: [u8; ED25519_PUB_LEN],
    timestamp_unix_millis: u64,
    server_nonce: [u8; NONCE_LEN],
    attestation_provider: &dyn AttestationProvider,
    signer: F,
    device_pubkey_bytes: [u8; ED25519_PUB_LEN],
) -> Result<SignedUnwrapRequest, BackupError>
where
    F: FnOnce(&[u8]) -> Result<[u8; DEVICE_SIG_LEN], BackupError>,
{
    let attestation = attestation_provider.fresh_token(&server_nonce)?;
    let canonical = canonical_signing_input(
        &ephemeral_r,
        &chat_id,
        &recipient_device_pubkey,
        timestamp_unix_millis,
        &server_nonce,
        &attestation,
    );
    let signature = signer(&canonical)?;
    Ok(SignedUnwrapRequest {
        ephemeral_r,
        chat_id,
        recipient_device_pubkey,
        timestamp_unix_millis,
        server_nonce,
        attestation,
        device_signature: signature,
        device_pubkey: device_pubkey_bytes,
    })
}

/// Минимум фиксированной части wire-format `SignedUnwrapRequest` — всё, кроме
/// переменного attestation-token. Token может быть 0..=`MAX_ATTESTATION_TOKEN_BYTES`.
///
/// Minimum fixed portion of the `SignedUnwrapRequest` wire format — everything
/// except the variable-length attestation token
/// (0..=`MAX_ATTESTATION_TOKEN_BYTES`).
///
/// Layout фиксирован в [`SignedUnwrapRequest::to_bytes`].
pub const SIGNED_UNWRAP_REQUEST_FIXED_LEN: usize = SIGNATURE_DOMAIN_SEPARATOR.len()
    + 1
    + POINT_LEN
    + CHAT_ID_LEN
    + ED25519_PUB_LEN
    + 8
    + NONCE_LEN
    + 1
    + 4
    + DEVICE_SIG_LEN
    + DEVICE_PUBKEY_LEN;

/// Максимум wire-format `SignedUnwrapRequest`: фиксированная часть +
/// максимальный attestation token.
///
/// Maximum wire-format size: fixed portion plus max attestation-token bytes.
pub const SIGNED_UNWRAP_REQUEST_MAX_LEN: usize =
    SIGNED_UNWRAP_REQUEST_FIXED_LEN + MAX_ATTESTATION_TOKEN_BYTES;

impl SignedUnwrapRequest {
    /// Сериализация в wire-format для HTTP body.
    ///
    /// Layout (big-endian):
    /// ```text
    /// [0..25)       domain_separator "umbrellax-cloud-unwrap-v1"   // 25 bytes
    /// [25..26)      wire_version                                    // 1 byte
    /// [26..58)      ephemeral_r (Ristretto255 compressed)           // 32 bytes
    /// [58..90)      chat_id                                         // 32 bytes
    /// [90..122)     recipient_device_pubkey (Ed25519 pub)           // 32 bytes
    /// [122..130)    timestamp_unix_millis (u64 BE)                  // 8 bytes
    /// [130..162)    server_nonce                                    // 32 bytes
    /// [162..163)    platform_tag                                    // 1 byte
    /// [163..167)    token_len (u32 BE)                              // 4 bytes
    /// [167..167+N)  attestation_token                               // N bytes
    /// [..+64)       device_signature (Ed25519)                      // 64 bytes
    /// [..+32)       device_pubkey (Ed25519 pub)                     // 32 bytes
    /// ```
    ///
    /// Первые 167 + N байт бит-в-бит совпадают с [`canonical_signing_input`]
    /// (подписанная часть) плюс две дописываемые подписью части в конце.
    /// Любой bit-flip ломает [`Self::from_bytes`] либо (после parse) —
    /// [`verify_signed_unwrap_request`].
    ///
    /// Serialize to the wire format used as HTTP body. The first 167 + N bytes
    /// match [`canonical_signing_input`] exactly; a bit-flip anywhere either
    /// breaks [`Self::from_bytes`] or (post-parse) fails
    /// [`verify_signed_unwrap_request`].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let token_len = self.attestation.token.len();
        let mut out = Vec::with_capacity(SIGNED_UNWRAP_REQUEST_FIXED_LEN + token_len);
        out.extend_from_slice(SIGNATURE_DOMAIN_SEPARATOR);
        out.push(UNWRAP_WIRE_VERSION);
        out.extend_from_slice(&self.ephemeral_r);
        out.extend_from_slice(&self.chat_id);
        out.extend_from_slice(&self.recipient_device_pubkey);
        out.extend_from_slice(&self.timestamp_unix_millis.to_be_bytes());
        out.extend_from_slice(&self.server_nonce);
        out.push(self.attestation.platform.tag());
        out.extend_from_slice(&(token_len as u32).to_be_bytes());
        out.extend_from_slice(&self.attestation.token);
        out.extend_from_slice(&self.device_signature);
        out.extend_from_slice(&self.device_pubkey);
        out
    }

    /// Парсинг wire-format с полной валидацией layout, domain separator,
    /// версии, длин и platform-тега. Подпись при этом **не** проверяется —
    /// вызывающая сторона должна дополнительно дёрнуть
    /// [`verify_signed_unwrap_request`].
    ///
    /// # Errors
    /// - [`BackupError::InvalidWireFormat`] если длина меньше фиксированной
    ///   части, больше максимальной, domain separator не совпадает, версия
    ///   не `UNWRAP_WIRE_VERSION`, `token_len` превышает
    ///   `MAX_ATTESTATION_TOKEN_BYTES` или суммарная длина не соответствует
    ///   `token_len`.
    /// - [`BackupError::InvalidAttestationShape`] если platform tag неизвестен
    ///   или [`PlatformAttestation::new`] отвергает token.
    ///
    /// Parse a `SignedUnwrapRequest` with strict layout/domain/version checks.
    /// Signature is **not** verified here — callers must also run
    /// [`verify_signed_unwrap_request`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, BackupError> {
        if data.len() < SIGNED_UNWRAP_REQUEST_FIXED_LEN
            || data.len() > SIGNED_UNWRAP_REQUEST_MAX_LEN
        {
            return Err(BackupError::InvalidWireFormat);
        }

        let mut off = 0;

        if &data[off..off + SIGNATURE_DOMAIN_SEPARATOR.len()] != SIGNATURE_DOMAIN_SEPARATOR {
            return Err(BackupError::InvalidWireFormat);
        }
        off += SIGNATURE_DOMAIN_SEPARATOR.len();

        if data[off] != UNWRAP_WIRE_VERSION {
            return Err(BackupError::InvalidWireFormat);
        }
        off += 1;

        let ephemeral_r: [u8; POINT_LEN] = data[off..off + POINT_LEN]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        off += POINT_LEN;

        let chat_id: [u8; CHAT_ID_LEN] = data[off..off + CHAT_ID_LEN]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        off += CHAT_ID_LEN;

        let recipient_device_pubkey: [u8; ED25519_PUB_LEN] = data[off..off + ED25519_PUB_LEN]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        off += ED25519_PUB_LEN;

        let ts_bytes: [u8; 8] = data[off..off + 8]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        let timestamp_unix_millis = u64::from_be_bytes(ts_bytes);
        off += 8;

        let server_nonce: [u8; NONCE_LEN] = data[off..off + NONCE_LEN]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        off += NONCE_LEN;

        let platform = Platform::from_tag(data[off]).ok_or(BackupError::InvalidAttestationShape)?;
        off += 1;

        let token_len_bytes: [u8; 4] = data[off..off + 4]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        let token_len = u32::from_be_bytes(token_len_bytes) as usize;
        off += 4;

        if token_len > MAX_ATTESTATION_TOKEN_BYTES {
            return Err(BackupError::InvalidWireFormat);
        }
        if data.len() != SIGNED_UNWRAP_REQUEST_FIXED_LEN + token_len {
            return Err(BackupError::InvalidWireFormat);
        }

        let attestation = PlatformAttestation::new(platform, &data[off..off + token_len])?;
        off += token_len;

        let device_signature: [u8; DEVICE_SIG_LEN] = data[off..off + DEVICE_SIG_LEN]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        off += DEVICE_SIG_LEN;

        let device_pubkey: [u8; ED25519_PUB_LEN] = data[off..off + ED25519_PUB_LEN]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        off += ED25519_PUB_LEN;

        debug_assert_eq!(off, data.len(), "parser must consume all input");

        Ok(SignedUnwrapRequest {
            ephemeral_r,
            chat_id,
            recipient_device_pubkey,
            timestamp_unix_millis,
            server_nonce,
            attestation,
            device_signature,
            device_pubkey,
        })
    }
}

/// Верификация device-signature на `SignedUnwrapRequest`.
/// Verify device signature on `SignedUnwrapRequest`.
///
/// Используется unit-тестами и mock-сервером. В production Sealed Server
/// делает такую же проверку плюс attestation + KT lookup.
///
/// Used by unit tests and mock server. In production, Sealed Server does
/// the same check plus attestation + KT lookup.
///
/// # Errors
/// - [`BackupError::InvalidRistrettoEncoding`] если `device_pubkey` не Ed25519.
///   (Reused, semantically "invalid curve encoding".)
/// - [`BackupError::CryptoVerificationFailed`] если подпись не проходит.
pub fn verify_signed_unwrap_request(req: &SignedUnwrapRequest) -> Result<(), BackupError> {
    let vk = DalekVerifyingKey::from_bytes(&req.device_pubkey)
        .map_err(|_| BackupError::InvalidRistrettoEncoding)?;
    let sig = DalekSignature::from_bytes(&req.device_signature);
    let canonical = canonical_signing_input(
        &req.ephemeral_r,
        &req.chat_id,
        &req.recipient_device_pubkey,
        req.timestamp_unix_millis,
        &req.server_nonce,
        &req.attestation,
    );
    vk.verify(&canonical, &sig)
        .map_err(|_| BackupError::CryptoVerificationFailed)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};

    use super::*;

    fn fresh_nonce() -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut n);
        n
    }

    fn make_device_keypair() -> (SigningKey, DalekVerifyingKey) {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let sk = SigningKey::from_bytes(&secret);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn sample_r() -> [u8; POINT_LEN] {
        [0xAAu8; POINT_LEN]
    }

    fn sample_chat() -> [u8; CHAT_ID_LEN] {
        [0x33u8; CHAT_ID_LEN]
    }

    fn sign_with(sk: &SigningKey, message: &[u8]) -> [u8; DEVICE_SIG_LEN] {
        sk.sign(message).to_bytes()
    }

    #[test]
    fn platform_roundtrip_all_variants() {
        for p in [
            Platform::IOs,
            Platform::Android,
            Platform::Web,
            Platform::Testing,
        ] {
            assert_eq!(Platform::from_tag(p.tag()), Some(p));
        }
    }

    #[test]
    fn platform_from_tag_rejects_unknown() {
        assert_eq!(Platform::from_tag(0x00), None);
        assert_eq!(Platform::from_tag(0x04), None);
        assert_eq!(Platform::from_tag(0xFE), None);
    }

    #[test]
    fn platform_attestation_rejects_empty() {
        let err = PlatformAttestation::new(Platform::Testing, &[]).unwrap_err();
        assert!(matches!(err, BackupError::InvalidAttestationShape));
    }

    #[test]
    fn platform_attestation_rejects_oversize() {
        let buf = vec![0u8; MAX_ATTESTATION_TOKEN_BYTES + 1];
        let err = PlatformAttestation::new(Platform::Testing, &buf).unwrap_err();
        assert!(matches!(err, BackupError::InvalidAttestationShape));
    }

    #[test]
    fn platform_attestation_accepts_max_size() {
        let buf = vec![0x55u8; MAX_ATTESTATION_TOKEN_BYTES];
        let att = PlatformAttestation::new(Platform::Testing, &buf).unwrap();
        assert_eq!(att.token.len(), MAX_ATTESTATION_TOKEN_BYTES);
    }

    #[test]
    fn testing_provider_deterministic_for_same_nonce() {
        let p = TestingAttestationProvider::default();
        let nonce = [42u8; NONCE_LEN];
        let a = p.fresh_token(&nonce).unwrap();
        let b = p.fresh_token(&nonce).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn testing_provider_distinguishes_nonces() {
        let p = TestingAttestationProvider::default();
        let a = p.fresh_token(&[1u8; NONCE_LEN]).unwrap();
        let b = p.fresh_token(&[2u8; NONCE_LEN]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn canonical_signing_input_layout() {
        let r = sample_r();
        let chat = sample_chat();
        let rec = [0x22u8; ED25519_PUB_LEN];
        let ts = 0x0102_0304_0506_0708u64;
        let nonce = [0x77u8; NONCE_LEN];
        let att = PlatformAttestation::new(Platform::Testing, b"tkn").unwrap();

        let serialized = canonical_signing_input(&r, &chat, &rec, ts, &nonce, &att);

        let mut off = 0;
        assert_eq!(
            &serialized[off..off + SIGNATURE_DOMAIN_SEPARATOR.len()],
            SIGNATURE_DOMAIN_SEPARATOR
        );
        off += SIGNATURE_DOMAIN_SEPARATOR.len();
        assert_eq!(serialized[off], UNWRAP_WIRE_VERSION);
        off += 1;
        assert_eq!(&serialized[off..off + POINT_LEN], &r);
        off += POINT_LEN;
        assert_eq!(&serialized[off..off + CHAT_ID_LEN], &chat);
        off += CHAT_ID_LEN;
        assert_eq!(&serialized[off..off + ED25519_PUB_LEN], &rec);
        off += ED25519_PUB_LEN;
        assert_eq!(&serialized[off..off + 8], &ts.to_be_bytes());
        off += 8;
        assert_eq!(&serialized[off..off + NONCE_LEN], &nonce);
        off += NONCE_LEN;
        assert_eq!(serialized[off], Platform::Testing.tag());
        off += 1;
        let token_len = u32::from_be_bytes(serialized[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        assert_eq!(token_len, att.token.len());
        assert_eq!(&serialized[off..off + token_len], att.token.as_slice());
        assert_eq!(off + token_len, serialized.len());
    }

    #[test]
    fn seal_and_verify_happy_path() {
        let (sk, vk) = make_device_keypair();
        let p = TestingAttestationProvider::default();
        let r = sample_r();
        let chat = sample_chat();
        let rec = [0x22u8; ED25519_PUB_LEN];
        let ts = 1_700_000_000_000u64;
        let nonce = fresh_nonce();

        let req = seal_unwrap_request(
            r,
            chat,
            rec,
            ts,
            nonce,
            &p,
            |payload| Ok(sign_with(&sk, payload)),
            vk.to_bytes(),
        )
        .unwrap();

        verify_signed_unwrap_request(&req).expect("valid signature must verify");
    }

    #[test]
    fn verify_rejects_tampered_ephemeral_r() {
        let (sk, vk) = make_device_keypair();
        let p = TestingAttestationProvider::default();
        let nonce = fresh_nonce();
        let mut req = seal_unwrap_request(
            sample_r(),
            sample_chat(),
            [0x22u8; ED25519_PUB_LEN],
            123,
            nonce,
            &p,
            |pl| Ok(sign_with(&sk, pl)),
            vk.to_bytes(),
        )
        .unwrap();
        req.ephemeral_r[0] ^= 1;
        let err = verify_signed_unwrap_request(&req).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn verify_rejects_tampered_chat_id() {
        let (sk, vk) = make_device_keypair();
        let p = TestingAttestationProvider::default();
        let nonce = fresh_nonce();
        let mut req = seal_unwrap_request(
            sample_r(),
            sample_chat(),
            [0x22u8; ED25519_PUB_LEN],
            123,
            nonce,
            &p,
            |pl| Ok(sign_with(&sk, pl)),
            vk.to_bytes(),
        )
        .unwrap();
        req.chat_id[0] ^= 1;
        let err = verify_signed_unwrap_request(&req).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn verify_rejects_tampered_recipient_device_pubkey() {
        let (sk, vk) = make_device_keypair();
        let p = TestingAttestationProvider::default();
        let nonce = fresh_nonce();
        let mut req = seal_unwrap_request(
            sample_r(),
            sample_chat(),
            [0x22u8; ED25519_PUB_LEN],
            123,
            nonce,
            &p,
            |pl| Ok(sign_with(&sk, pl)),
            vk.to_bytes(),
        )
        .unwrap();
        req.recipient_device_pubkey[0] ^= 1;
        let err = verify_signed_unwrap_request(&req).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn verify_rejects_tampered_timestamp() {
        let (sk, vk) = make_device_keypair();
        let p = TestingAttestationProvider::default();
        let nonce = fresh_nonce();
        let mut req = seal_unwrap_request(
            sample_r(),
            sample_chat(),
            [0x22u8; ED25519_PUB_LEN],
            1_000,
            nonce,
            &p,
            |pl| Ok(sign_with(&sk, pl)),
            vk.to_bytes(),
        )
        .unwrap();
        req.timestamp_unix_millis = 2_000;
        let err = verify_signed_unwrap_request(&req).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn verify_rejects_tampered_nonce() {
        let (sk, vk) = make_device_keypair();
        let p = TestingAttestationProvider::default();
        let nonce = fresh_nonce();
        let mut req = seal_unwrap_request(
            sample_r(),
            sample_chat(),
            [0x22u8; ED25519_PUB_LEN],
            5,
            nonce,
            &p,
            |pl| Ok(sign_with(&sk, pl)),
            vk.to_bytes(),
        )
        .unwrap();
        req.server_nonce[0] ^= 1;
        let err = verify_signed_unwrap_request(&req).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn verify_rejects_tampered_token() {
        let (sk, vk) = make_device_keypair();
        let p = TestingAttestationProvider::default();
        let nonce = fresh_nonce();
        let mut req = seal_unwrap_request(
            sample_r(),
            sample_chat(),
            [0x22u8; ED25519_PUB_LEN],
            5,
            nonce,
            &p,
            |pl| Ok(sign_with(&sk, pl)),
            vk.to_bytes(),
        )
        .unwrap();
        let mut v = req.attestation.token.to_vec();
        if v.is_empty() {
            v.push(0);
        }
        v[0] ^= 1;
        req.attestation = PlatformAttestation::new(req.attestation.platform, &v).unwrap();
        let err = verify_signed_unwrap_request(&req).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn verify_rejects_wrong_device_pubkey() {
        let (sk, _vk_correct) = make_device_keypair();
        let (_sk_other, vk_other) = make_device_keypair();
        let p = TestingAttestationProvider::default();
        let nonce = fresh_nonce();
        let req = seal_unwrap_request(
            sample_r(),
            sample_chat(),
            [0x22u8; ED25519_PUB_LEN],
            5,
            nonce,
            &p,
            |pl| Ok(sign_with(&sk, pl)),
            vk_other.to_bytes(), // intentionally wrong
        )
        .unwrap();
        let err = verify_signed_unwrap_request(&req).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn verify_rejects_invalid_pubkey_encoding() {
        let (sk, vk) = make_device_keypair();
        let p = TestingAttestationProvider::default();
        let nonce = fresh_nonce();
        let mut req = seal_unwrap_request(
            sample_r(),
            sample_chat(),
            [0x22u8; ED25519_PUB_LEN],
            5,
            nonce,
            &p,
            |pl| Ok(sign_with(&sk, pl)),
            vk.to_bytes(),
        )
        .unwrap();
        req.device_pubkey = [0xFFu8; ED25519_PUB_LEN];
        let err = verify_signed_unwrap_request(&req).unwrap_err();
        assert!(matches!(
            err,
            BackupError::InvalidRistrettoEncoding | BackupError::CryptoVerificationFailed
        ));
    }

    #[test]
    fn seal_propagates_signer_error() {
        let p = TestingAttestationProvider::default();
        let nonce = fresh_nonce();
        let err = seal_unwrap_request(
            sample_r(),
            sample_chat(),
            [0x22u8; ED25519_PUB_LEN],
            5,
            nonce,
            &p,
            |_| Err(BackupError::DeviceSigning("hw-unavailable")),
            [0u8; ED25519_PUB_LEN],
        )
        .unwrap_err();
        assert!(matches!(err, BackupError::DeviceSigning(_)));
    }

    // =========================================================================
    // Wire-format tests — SignedUnwrapRequest::{to_bytes, from_bytes}
    // =========================================================================

    fn make_signed_request(token: &[u8]) -> SignedUnwrapRequest {
        let (sk, vk) = make_device_keypair();
        let attestation_provider =
            PlatformAttestation::new(Platform::Testing, token).expect("token within bounds");
        // Inline provider to keep requested token bytes verbatim.
        struct Fixed(PlatformAttestation);
        impl AttestationProvider for Fixed {
            fn fresh_token(
                &self,
                _nonce: &[u8; NONCE_LEN],
            ) -> Result<PlatformAttestation, BackupError> {
                Ok(self.0.clone())
            }
        }
        let p = Fixed(attestation_provider);
        seal_unwrap_request(
            sample_r(),
            sample_chat(),
            [0x22u8; ED25519_PUB_LEN],
            0x0102_0304_0506_0708u64,
            fresh_nonce(),
            &p,
            |pl| Ok(sign_with(&sk, pl)),
            vk.to_bytes(),
        )
        .expect("seal happy path")
    }

    #[test]
    fn signed_unwrap_request_wire_roundtrip_small_token() {
        let req = make_signed_request(b"small");
        let bytes = req.to_bytes();
        assert_eq!(
            bytes.len(),
            SIGNED_UNWRAP_REQUEST_FIXED_LEN + req.attestation.token.len()
        );
        let parsed = SignedUnwrapRequest::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(parsed, req);
        // Parsed request must also pass signature verification.
        verify_signed_unwrap_request(&parsed).expect("verify after roundtrip");
    }

    #[test]
    fn signed_unwrap_request_wire_roundtrip_max_token() {
        let big = vec![0xA5u8; MAX_ATTESTATION_TOKEN_BYTES];
        let req = make_signed_request(&big);
        let bytes = req.to_bytes();
        assert_eq!(bytes.len(), SIGNED_UNWRAP_REQUEST_MAX_LEN);
        let parsed = SignedUnwrapRequest::from_bytes(&bytes).expect("roundtrip at max size");
        assert_eq!(parsed, req);
        verify_signed_unwrap_request(&parsed).expect("verify at max size");
    }

    #[test]
    fn signed_unwrap_request_from_bytes_rejects_too_short() {
        let err = SignedUnwrapRequest::from_bytes(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn signed_unwrap_request_from_bytes_rejects_too_long() {
        let mut oversized = vec![0u8; SIGNED_UNWRAP_REQUEST_MAX_LEN + 1];
        oversized[..SIGNATURE_DOMAIN_SEPARATOR.len()].copy_from_slice(SIGNATURE_DOMAIN_SEPARATOR);
        oversized[SIGNATURE_DOMAIN_SEPARATOR.len()] = UNWRAP_WIRE_VERSION;
        let err = SignedUnwrapRequest::from_bytes(&oversized).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn signed_unwrap_request_from_bytes_rejects_wrong_domain() {
        let req = make_signed_request(b"x");
        let mut bytes = req.to_bytes();
        bytes[0] ^= 0x01; // corrupt domain separator
        let err = SignedUnwrapRequest::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn signed_unwrap_request_from_bytes_rejects_wrong_version() {
        let req = make_signed_request(b"x");
        let mut bytes = req.to_bytes();
        bytes[SIGNATURE_DOMAIN_SEPARATOR.len()] = 0x02; // unknown version byte
        let err = SignedUnwrapRequest::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn signed_unwrap_request_from_bytes_rejects_unknown_platform_tag() {
        let req = make_signed_request(b"x");
        let mut bytes = req.to_bytes();
        // Platform tag sits just before the 4-byte token_len field.
        let platform_off = SIGNATURE_DOMAIN_SEPARATOR.len()
            + 1
            + POINT_LEN
            + CHAT_ID_LEN
            + ED25519_PUB_LEN
            + 8
            + NONCE_LEN;
        bytes[platform_off] = 0x7F; // not a valid Platform variant tag
        let err = SignedUnwrapRequest::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, BackupError::InvalidAttestationShape));
    }

    #[test]
    fn signed_unwrap_request_from_bytes_rejects_token_len_overflow() {
        let req = make_signed_request(b"x");
        let mut bytes = req.to_bytes();
        let token_len_off = SIGNATURE_DOMAIN_SEPARATOR.len()
            + 1
            + POINT_LEN
            + CHAT_ID_LEN
            + ED25519_PUB_LEN
            + 8
            + NONCE_LEN
            + 1;
        let oversize = (MAX_ATTESTATION_TOKEN_BYTES as u32 + 1).to_be_bytes();
        bytes[token_len_off..token_len_off + 4].copy_from_slice(&oversize);
        let err = SignedUnwrapRequest::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn signed_unwrap_request_from_bytes_rejects_token_len_mismatch() {
        let req = make_signed_request(b"abc");
        let mut bytes = req.to_bytes();
        // Declare token_len = 4 while body really contains 3 bytes → length mismatch.
        let token_len_off = SIGNATURE_DOMAIN_SEPARATOR.len()
            + 1
            + POINT_LEN
            + CHAT_ID_LEN
            + ED25519_PUB_LEN
            + 8
            + NONCE_LEN
            + 1;
        bytes[token_len_off..token_len_off + 4].copy_from_slice(&4u32.to_be_bytes());
        let err = SignedUnwrapRequest::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }
}
