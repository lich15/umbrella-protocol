//! Device attestation обёртка для OPRF-запросов.
//! Device attestation wrapper for OPRF requests.
//!
//! Обязательный слой защиты от mass enumeration: Sealed Servers выполняют
//! OPRF **только** по запросам, в которых есть (а) платформенный
//! attestation token (Apple App Attest / Google Play Integrity / WebAuthn)
//! и (б) подпись device-key клиента поверх канонической сериализации
//! запроса. Без обоих слоёв защиты серверы отклоняют запрос даже если
//! ослеплённая точка сама по себе валидна.
//!
//! Крейт не выполняет саму платформенную attestation — это делает
//! нативный FFI-bridge (Swift / Kotlin / JavaScript). Здесь мы определяем
//! trait [`AttestationProvider`], каноническую сериализацию под подпись,
//! wire-формат [`SignedOprfRequest`] и верификацию.
//!
//! Mandatory defense against mass enumeration: Sealed Servers evaluate OPRF
//! only on requests carrying (a) a platform attestation token and
//! (b) device-key signature over canonical serialization. This crate does
//! not perform the platform attestation itself — that happens in native
//! FFI bridges. Here we define the `AttestationProvider` trait, canonical
//! signing input, wire format `SignedOprfRequest`, and verification.

use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey as DalekVerifyingKey};
use heapless::Vec as HVec;

use crate::error::OprfError;
use crate::primitives::{BlindedRequest, POINT_LEN};

/// Максимум байт в платформенном attestation token'е.
/// Maximum bytes in a platform attestation token.
///
/// 4096 байт с запасом покрывают: Apple App Attest (~400 bytes),
/// Google Play Integrity verdict JWS (~2KB), WebAuthn assertion (~500
/// bytes). Больше — отвергаем во избежание amplification attack на
/// serializer.
///
/// 4096 bytes cover with margin: Apple App Attest (~400 B), Google Play
/// Integrity verdict JWS (~2 KB), WebAuthn assertion (~500 B). Larger —
/// rejected to avoid serializer amplification.
pub const MAX_ATTESTATION_TOKEN_BYTES: usize = 4096;

/// Domain separator канонической сериализации под device-signature.
/// Domain separator for the canonical signing input.
pub const SIGNATURE_DOMAIN_SEPARATOR: &[u8] = b"umbrellax-oprf-request-v1";

/// Версия wire-формата `SignedOprfRequest`. Increment при несовместимых
/// изменениях (требует ADR + grace period).
///
/// Wire-format version for `SignedOprfRequest`. Bump on incompatible
/// changes (requires ADR + grace period).
pub const WIRE_VERSION: u8 = 0x01;

/// Длина серверного nonce в байтах. Server-issued nonce length.
pub const NONCE_LEN: usize = 32;

/// Длина Ed25519 подписи. Ed25519 signature length.
pub const DEVICE_SIG_LEN: usize = 64;

/// Длина публичного Ed25519 ключа. Ed25519 public key length.
pub const DEVICE_PUBKEY_LEN: usize = 32;

/// Платформа источника attestation. Attestation source platform.
///
/// Тег используется в канонической сериализации: изменение семантики
/// значения ломает подписи, требует version bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Platform {
    /// Apple App Attest + DeviceCheck (iOS / iPadOS 14+). iOS / iPadOS 14+.
    IOs = 0x01,
    /// Google Play Integrity API (Android 8+). Android 8+.
    Android = 0x02,
    /// WebAuthn passkey assertion (PWA / desktop browsers).
    Web = 0x03,
    /// Тестовый провайдер — **только для unit-тестов и mock-сервера**.
    /// Testing provider — **unit tests and mock server only**.
    Testing = 0xFF,
}

impl Platform {
    /// Байтовый тег для сериализации. Byte tag for serialization.
    #[inline]
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Обратная декодировка из тега. Reverse decode from tag.
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

/// Платформенный attestation (token от App Attest / Play Integrity / WebAuthn).
/// Platform attestation (App Attest / Play Integrity / WebAuthn token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformAttestation {
    /// Платформа источника. Source platform.
    pub platform: Platform,
    /// Opaque-байты токена (формат платформо-специфичен).
    /// Opaque token bytes (platform-specific format).
    pub token: HVec<u8, MAX_ATTESTATION_TOKEN_BYTES>,
}

impl PlatformAttestation {
    /// Создать с проверкой длины token'а. Create with token-length validation.
    ///
    /// # Errors
    /// - [`OprfError::InvalidAttestationShape`] если `token_bytes.is_empty()`
    ///   или длина > [`MAX_ATTESTATION_TOKEN_BYTES`].
    pub fn new(platform: Platform, token_bytes: &[u8]) -> Result<Self, OprfError> {
        if token_bytes.is_empty() || token_bytes.len() > MAX_ATTESTATION_TOKEN_BYTES {
            return Err(OprfError::InvalidAttestationShape);
        }
        let mut token: HVec<u8, MAX_ATTESTATION_TOKEN_BYTES> = HVec::new();
        token
            .extend_from_slice(token_bytes)
            .map_err(|_| OprfError::InvalidAttestationShape)?;
        Ok(Self { platform, token })
    }
}

/// Поставщик платформенного attestation token'а.
/// Platform attestation token provider.
///
/// Реализации:
/// - `umbrella-ffi-swift` — через Swift bridge к Apple App Attest + DeviceCheck.
/// - `umbrella-ffi-kotlin` — через Kotlin bridge к Google Play Integrity.
/// - Web — через JavaScript bridge к WebAuthn (out-of-scope Stage 4).
/// - Тесты — [`TestingAttestationProvider`].
///
/// Реализация **обязана** использовать `nonce` как freshness-proof
/// (включать его в payload, отправляемый platform service). Sealed Servers
/// проверяют совпадение nonce со своим (±5 минут).
pub trait AttestationProvider {
    /// Получить свежий attestation-token, привязанный к `nonce`.
    /// Obtain a fresh attestation token bound to `nonce`.
    ///
    /// # Errors
    /// Конкретные ошибки платформы транслируются в
    /// [`OprfError::InvalidAttestationShape`] или в другой подходящий
    /// вариант (реализация должна быть явной).
    fn fresh_token(&self, nonce: &[u8; NONCE_LEN]) -> Result<PlatformAttestation, OprfError>;
}

/// Testing-реализация `AttestationProvider`: отдаёт детерминистический
/// token из фиксированного префикса + nonce. НЕ для production.
///
/// Testing `AttestationProvider` returning a deterministic token from a
/// fixed prefix plus the nonce. NOT for production.
#[derive(Debug, Clone)]
pub struct TestingAttestationProvider {
    prefix: HVec<u8, 64>,
}

impl TestingAttestationProvider {
    /// Создать с произвольным префиксом (например идентификатором теста).
    /// Create with an arbitrary prefix (e.g. test identifier).
    pub fn new(prefix: &[u8]) -> Self {
        let mut p: HVec<u8, 64> = HVec::new();
        let to_take = prefix.len().min(64);
        // Ignore potential overflow; `p` is sized to fit.
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: to_take ≤ 64 by .min(64) above; HVec capacity 64"
        )]
        p.extend_from_slice(&prefix[..to_take])
            .expect("prefix fits into 64-byte HVec by construction");
        Self { prefix: p }
    }
}

impl Default for TestingAttestationProvider {
    fn default() -> Self {
        Self::new(b"umbrellax-test-attestation")
    }
}

impl AttestationProvider for TestingAttestationProvider {
    fn fresh_token(&self, nonce: &[u8; NONCE_LEN]) -> Result<PlatformAttestation, OprfError> {
        let mut buf: HVec<u8, MAX_ATTESTATION_TOKEN_BYTES> = HVec::new();
        buf.extend_from_slice(&self.prefix)
            .map_err(|_| OprfError::InvalidAttestationShape)?;
        buf.extend_from_slice(nonce)
            .map_err(|_| OprfError::InvalidAttestationShape)?;
        Ok(PlatformAttestation {
            platform: Platform::Testing,
            token: buf,
        })
    }
}

/// Каноническая сериализация request'а под device-signature.
/// Canonical serialization of the request for device-signature.
///
/// Формат:
/// ```text
/// "umbrellax-oprf-request-v1"        // 25 bytes domain separator
/// || 0x01                             // 1 byte wire version
/// || blinded_request (32 bytes)       // compressed Ristretto
/// || platform_tag (1 byte)            // Platform::tag()
/// || (u32 BE) token.len()             // token length prefix
/// || token                            // platform attestation
/// || nonce (32 bytes)                 // server-issued freshness
/// ```
///
/// Эта последовательность — то что подписывается device-key, а на
/// стороне сервера реконструируется и верифицируется.
pub fn canonical_signing_input(
    blinded: &BlindedRequest,
    attestation: &PlatformAttestation,
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let token_len = attestation.token.len();
    let capacity = SIGNATURE_DOMAIN_SEPARATOR.len()
        + 1
        + POINT_LEN
        + 1
        + core::mem::size_of::<u32>()
        + token_len
        + NONCE_LEN;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(SIGNATURE_DOMAIN_SEPARATOR);
    out.push(WIRE_VERSION);
    out.extend_from_slice(blinded.as_bytes());
    out.push(attestation.platform.tag());
    // token length as u32 BE (maximum 4096 fits in u16 but we align to u32 for
    // forward compatibility with larger tokens in future versions).
    out.extend_from_slice(&(token_len as u32).to_be_bytes());
    out.extend_from_slice(&attestation.token);
    out.extend_from_slice(nonce);
    out
}

/// Запрос к Sealed Servers с привязанной attestation + device-signature.
/// Request to Sealed Servers with attached attestation + device signature.
///
/// Создаётся функцией [`seal_request`], верифицируется функцией
/// [`verify_signed_request`]. Структура предназначена для передачи по
/// сети (все поля публичные, wire-format канонический).
#[derive(Debug, Clone)]
pub struct SignedOprfRequest {
    /// Ослеплённый OPRF-запрос. Blinded OPRF request.
    pub blinded: BlindedRequest,
    /// Платформенный attestation. Platform attestation.
    pub attestation: PlatformAttestation,
    /// Server-issued freshness nonce. 32 bytes.
    pub nonce: [u8; NONCE_LEN],
    /// Подпись device-key поверх canonical_signing_input.
    /// Device-key signature over canonical_signing_input.
    pub device_signature: [u8; DEVICE_SIG_LEN],
    /// Публичный device-key (32 байта). Device-key public bytes.
    ///
    /// Включён в запрос чтобы сервер мог верифицировать подпись и
    /// сопоставить identity с KT-записью. Не раскрывает секретного
    /// материала: public-key открыт по дизайну.
    pub device_pubkey: [u8; DEVICE_PUBKEY_LEN],
}

/// Собрать подписанный запрос: получить attestation-token, вычислить
/// canonical input, подписать device-key через signer-closure.
///
/// Assemble a signed request: obtain attestation token, compute canonical
/// input, sign with device-key via the signer closure.
///
/// `signer` — callback который вызывает `KeyStore::sign_with_device`
/// (чтобы крейт не зависел от умбрелловых FFI-типов напрямую — любой
/// caller может подключить свой KeyStore).
///
/// `device_pubkey_bytes` — публичный ключ соответствующего device-key.
/// Должен совпадать с тем, который подписывает signer (это caller
/// инвариант, проверяется верификацией).
///
/// # Errors
/// - [`OprfError::InvalidAttestationShape`] если провайдер вернул пустой
///   или слишком длинный token.
/// - [`OprfError::DeviceSigning`] если signer-callback вернул ошибку.
pub fn seal_request<F>(
    blinded: BlindedRequest,
    attestation_provider: &dyn AttestationProvider,
    nonce: [u8; NONCE_LEN],
    signer: F,
    device_pubkey_bytes: [u8; DEVICE_PUBKEY_LEN],
) -> Result<SignedOprfRequest, OprfError>
where
    F: FnOnce(&[u8]) -> Result<[u8; DEVICE_SIG_LEN], OprfError>,
{
    let attestation = attestation_provider.fresh_token(&nonce)?;
    let canonical = canonical_signing_input(&blinded, &attestation, &nonce);
    let signature = signer(&canonical)?;
    Ok(SignedOprfRequest {
        blinded,
        attestation,
        nonce,
        device_signature: signature,
        device_pubkey: device_pubkey_bytes,
    })
}

/// Верификация подписи device-key на полученном `SignedOprfRequest`.
/// Verify device-key signature on a received `SignedOprfRequest`.
///
/// Проверка что подпись валидна поверх canonical serialization
/// **и** что публичный ключ декодируется как валидный Ed25519 point.
///
/// Checks that signature is valid over canonical serialization **and**
/// that the public key decodes as a valid Ed25519 point.
///
/// # Errors
/// - [`OprfError::InvalidRistrettoEncoding`] (reused as general encoding
///   error) если `device_pubkey` не валидный Ed25519 public key.
/// - [`OprfError::CryptoVerificationFailed`] если подпись не проходит.
pub fn verify_signed_request(req: &SignedOprfRequest) -> Result<(), OprfError> {
    // Декодируем public key.
    let vk = DalekVerifyingKey::from_bytes(&req.device_pubkey)
        .map_err(|_| OprfError::InvalidRistrettoEncoding)?;
    let sig = DalekSignature::from_bytes(&req.device_signature);
    let canonical = canonical_signing_input(&req.blinded, &req.attestation, &req.nonce);
    vk.verify(&canonical, &sig)
        .map_err(|_| OprfError::CryptoVerificationFailed)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};

    use super::*;
    use crate::primitives::{blind, POINT_LEN};
    use crate::OprfInput;

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

    fn sign_with(sk: &SigningKey, message: &[u8]) -> [u8; DEVICE_SIG_LEN] {
        sk.sign(message).to_bytes()
    }

    #[test]
    fn platform_roundtrip() {
        for p in [
            Platform::IOs,
            Platform::Android,
            Platform::Web,
            Platform::Testing,
        ] {
            let tag = p.tag();
            assert_eq!(Platform::from_tag(tag), Some(p));
        }
    }

    #[test]
    fn platform_from_tag_unknown_returns_none() {
        assert_eq!(Platform::from_tag(0x00), None);
        assert_eq!(Platform::from_tag(0x04), None);
        assert_eq!(Platform::from_tag(0xFE), None);
    }

    #[test]
    fn platform_attestation_rejects_empty() {
        let err = PlatformAttestation::new(Platform::Testing, &[]).unwrap_err();
        assert!(matches!(err, OprfError::InvalidAttestationShape));
    }

    #[test]
    fn platform_attestation_rejects_oversize() {
        let buf = vec![0u8; MAX_ATTESTATION_TOKEN_BYTES + 1];
        let err = PlatformAttestation::new(Platform::Testing, &buf).unwrap_err();
        assert!(matches!(err, OprfError::InvalidAttestationShape));
    }

    #[test]
    fn platform_attestation_accepts_max_size() {
        let buf = vec![0x55u8; MAX_ATTESTATION_TOKEN_BYTES];
        let att = PlatformAttestation::new(Platform::Testing, &buf).unwrap();
        assert_eq!(att.token.len(), MAX_ATTESTATION_TOKEN_BYTES);
    }

    #[test]
    fn testing_provider_emits_deterministic_for_same_nonce() {
        let provider = TestingAttestationProvider::default();
        let nonce = [42u8; NONCE_LEN];
        let a = provider.fresh_token(&nonce).unwrap();
        let b = provider.fresh_token(&nonce).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn testing_provider_distinguishes_nonces() {
        let provider = TestingAttestationProvider::default();
        let a = provider.fresh_token(&[1u8; NONCE_LEN]).unwrap();
        let b = provider.fresh_token(&[2u8; NONCE_LEN]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn canonical_signing_input_structure() {
        let input = OprfInput::new(b"x").unwrap();
        let (blinded, _) = blind(input, &mut OsRng).unwrap();
        let attestation = PlatformAttestation::new(Platform::Testing, b"tkn").unwrap();
        let nonce = [7u8; NONCE_LEN];

        let serialized = canonical_signing_input(&blinded, &attestation, &nonce);

        // Разметка полей:
        // [0..25) domain separator
        // [25..26) wire version
        // [26..58) blinded (32B)
        // [58..59) platform tag
        // [59..63) token length (u32 BE)
        // [63..63+token.len()) token
        // [63+token.len() .. +32) nonce
        assert_eq!(
            &serialized[..SIGNATURE_DOMAIN_SEPARATOR.len()],
            SIGNATURE_DOMAIN_SEPARATOR
        );
        let mut off = SIGNATURE_DOMAIN_SEPARATOR.len();
        assert_eq!(serialized[off], WIRE_VERSION);
        off += 1;
        assert_eq!(&serialized[off..off + POINT_LEN], blinded.as_bytes());
        off += POINT_LEN;
        assert_eq!(serialized[off], Platform::Testing.tag());
        off += 1;
        let token_len = u32::from_be_bytes(serialized[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        assert_eq!(token_len, attestation.token.len());
        assert_eq!(
            &serialized[off..off + token_len],
            attestation.token.as_slice()
        );
        off += token_len;
        assert_eq!(&serialized[off..off + NONCE_LEN], &nonce);
        assert_eq!(off + NONCE_LEN, serialized.len());
    }

    #[test]
    fn seal_and_verify_happy_path() {
        let (sk, vk) = make_device_keypair();
        let provider = TestingAttestationProvider::default();
        let input = OprfInput::new(b"+12125551212").unwrap();
        let (blinded, _state) = blind(input, &mut OsRng).unwrap();
        let nonce = fresh_nonce();

        let signed = seal_request(
            blinded,
            &provider,
            nonce,
            |payload| Ok(sign_with(&sk, payload)),
            vk.to_bytes(),
        )
        .unwrap();

        verify_signed_request(&signed).expect("valid request must verify");
    }

    #[test]
    fn verify_rejects_tampered_blinded() {
        let (sk, vk) = make_device_keypair();
        let provider = TestingAttestationProvider::default();
        let input = OprfInput::new(b"x").unwrap();
        let (blinded, _) = blind(input, &mut OsRng).unwrap();
        let nonce = fresh_nonce();

        let mut signed = seal_request(
            blinded,
            &provider,
            nonce,
            |payload| Ok(sign_with(&sk, payload)),
            vk.to_bytes(),
        )
        .unwrap();

        // Tamper blinded by generating новый request и подменяя blinded в уже
        // подписанном объекте (подпись теперь не соответствует canonical input).
        let input2 = OprfInput::new(b"y").unwrap();
        let (blinded2, _) = blind(input2, &mut OsRng).unwrap();
        signed.blinded = blinded2;

        let err = verify_signed_request(&signed).unwrap_err();
        assert!(matches!(err, OprfError::CryptoVerificationFailed));
    }

    #[test]
    fn verify_rejects_tampered_nonce() {
        let (sk, vk) = make_device_keypair();
        let provider = TestingAttestationProvider::default();
        let input = OprfInput::new(b"x").unwrap();
        let (blinded, _) = blind(input, &mut OsRng).unwrap();
        let nonce = fresh_nonce();

        let mut signed = seal_request(
            blinded,
            &provider,
            nonce,
            |payload| Ok(sign_with(&sk, payload)),
            vk.to_bytes(),
        )
        .unwrap();

        signed.nonce[0] ^= 1;
        let err = verify_signed_request(&signed).unwrap_err();
        assert!(matches!(err, OprfError::CryptoVerificationFailed));
    }

    #[test]
    fn verify_rejects_tampered_token() {
        let (sk, vk) = make_device_keypair();
        let provider = TestingAttestationProvider::default();
        let input = OprfInput::new(b"x").unwrap();
        let (blinded, _) = blind(input, &mut OsRng).unwrap();
        let nonce = fresh_nonce();

        let mut signed = seal_request(
            blinded,
            &provider,
            nonce,
            |payload| Ok(sign_with(&sk, payload)),
            vk.to_bytes(),
        )
        .unwrap();

        // Tamper token (flip 1 bit).
        let new_token = {
            let mut v = signed.attestation.token.to_vec();
            if v.is_empty() {
                v.push(0);
            }
            v[0] ^= 1;
            v
        };
        signed.attestation =
            PlatformAttestation::new(signed.attestation.platform, &new_token).unwrap();

        let err = verify_signed_request(&signed).unwrap_err();
        assert!(matches!(err, OprfError::CryptoVerificationFailed));
    }

    #[test]
    fn verify_rejects_wrong_device_pubkey() {
        let (sk, _vk_correct) = make_device_keypair();
        let (_sk_other, vk_other) = make_device_keypair();
        let provider = TestingAttestationProvider::default();
        let input = OprfInput::new(b"x").unwrap();
        let (blinded, _) = blind(input, &mut OsRng).unwrap();
        let nonce = fresh_nonce();

        let signed = seal_request(
            blinded,
            &provider,
            nonce,
            |payload| Ok(sign_with(&sk, payload)),
            vk_other.to_bytes(), // INTENTIONALLY WRONG pubkey
        )
        .unwrap();

        let err = verify_signed_request(&signed).unwrap_err();
        assert!(matches!(err, OprfError::CryptoVerificationFailed));
    }

    #[test]
    fn verify_rejects_invalid_pubkey_encoding() {
        let (sk, vk) = make_device_keypair();
        let provider = TestingAttestationProvider::default();
        let input = OprfInput::new(b"x").unwrap();
        let (blinded, _) = blind(input, &mut OsRng).unwrap();
        let nonce = fresh_nonce();

        let mut signed = seal_request(
            blinded,
            &provider,
            nonce,
            |payload| Ok(sign_with(&sk, payload)),
            vk.to_bytes(),
        )
        .unwrap();

        // Invalid Ed25519 public key encoding: set all bits to 1.
        signed.device_pubkey = [0xFFu8; DEVICE_PUBKEY_LEN];

        let err = verify_signed_request(&signed).unwrap_err();
        // Either Invalid encoding OR verification failed — both are correct rejections.
        assert!(matches!(
            err,
            OprfError::InvalidRistrettoEncoding | OprfError::CryptoVerificationFailed
        ));
    }

    #[test]
    fn seal_propagates_signer_error() {
        let provider = TestingAttestationProvider::default();
        let input = OprfInput::new(b"x").unwrap();
        let (blinded, _) = blind(input, &mut OsRng).unwrap();
        let nonce = fresh_nonce();

        let err = seal_request(
            blinded,
            &provider,
            nonce,
            |_| Err(OprfError::DeviceSigning("hw-unavailable")),
            [0u8; DEVICE_PUBKEY_LEN],
        )
        .unwrap_err();
        assert!(matches!(err, OprfError::DeviceSigning(_)));
    }
}
