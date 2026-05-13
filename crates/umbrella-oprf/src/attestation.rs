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
#[cfg(test)]
use umbrella_platform_verifier::AndroidPlayIntegrityConfig;
use umbrella_platform_verifier::{
    AndroidPlayIntegrityVerifier, AppleAppAttestVerifier, DevicePublicKey, PlatformKind,
    PlatformVerificationContext, PlatformVerifier, PlatformVerifierError, RegisteredPlatformKey,
    WebAuthnVerifier,
};

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

/// Разрешённое окно свежести для боевой серверной проверки.
/// Freshness window for production server-side verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionFreshnessPolicy {
    /// Максимальный возраст server nonce. Maximum server nonce age.
    pub max_nonce_age_millis: u64,
    /// Допустимый перекос времени в будущее. Allowed future clock skew.
    pub max_future_skew_millis: u64,
}

impl Default for ProductionFreshnessPolicy {
    fn default() -> Self {
        Self {
            max_nonce_age_millis: 5 * 60 * 1000,
            max_future_skew_millis: 30 * 1000,
        }
    }
}

/// Состояние устройства из серверного снимка журнала ключей.
/// Device state from the server-side key-transparency snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionDeviceState {
    /// Устройства нет в снимке. Device is absent from the snapshot.
    Unknown,
    /// Устройство ждёт подтверждения. Device awaits approval.
    Pending,
    /// Устройство отозвано. Device is revoked.
    Revoked,
    /// Устройство активно. Device is active.
    Active {
        /// Время разрешения устройства. Device authorization time.
        authorized_since_unix_millis: u64,
    },
    /// Первое активное устройство или восстановление после катастрофы.
    /// First active device or catastrophic-recovery bootstrap.
    BootstrapActive {
        /// Время разрешения устройства. Device authorization time.
        authorized_since_unix_millis: u64,
    },
}

/// Тип платформенного проверяющего.
/// Platform verifier kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformVerifierKind {
    /// Настоящий проверяющий пока не подключён. Real verifier is not wired yet.
    Unavailable,
    /// Apple App Attest. Apple App Attest.
    AppleAppAttest,
    /// Android Play Integrity. Android Play Integrity.
    AndroidPlayIntegrity,
    /// WebAuthn. WebAuthn.
    WebAuthn,
    /// Только для тестов, запрещён в боевом контексте.
    /// Test-only, rejected in production context.
    TestOnly,
}

/// Вход платформенного проверяющего.
/// Input passed to a platform attestation verifier.
#[derive(Debug, Clone, Copy)]
pub struct PlatformVerificationInput<'a> {
    /// Платформа запроса. Request platform.
    pub platform: Platform,
    /// Байты токена. Token bytes.
    pub token: &'a [u8],
    /// Серверный вызов. Server nonce.
    pub server_nonce: &'a [u8; NONCE_LEN],
    /// Публичный ключ устройства. Device public key.
    pub device_pubkey: &'a [u8; DEVICE_PUBKEY_LEN],
    /// Текущее серверное время. Current server time.
    pub now_unix_millis: u64,
}

/// Платформенный проверяющий для боевого серверного пути.
/// Platform verifier for the production server-side path.
pub trait ProductionPlatformVerifier: std::fmt::Debug {
    /// Тип проверяющего. Verifier kind.
    fn kind(&self) -> PlatformVerifierKind;

    /// Проверить платформенный токен.
    /// Verify the platform token.
    ///
    /// # Errors
    /// Возвращает точную причину отказа.
    fn verify_platform_attestation(
        &self,
        input: PlatformVerificationInput<'_>,
    ) -> Result<(), OprfError>;
}

/// Хранилище использованных серверных вызовов для боевой OPRF-проверки.
/// Store of consumed server nonces for production OPRF verification.
pub trait ProductionNonceReplayGuard: std::fmt::Debug {
    /// Проверить и записать одноразовый серверный вызов.
    /// Check and record a one-time server nonce.
    ///
    /// # Errors
    /// Возвращает [`OprfError::ProductionServerNonceReplay`], если вызов уже был
    /// принят ранее.
    fn check_and_record_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        now_unix_millis: u64,
    ) -> Result<(), OprfError>;
}

/// Проверяющий, который честно закрывает путь до подключения настоящей платформы.
/// Verifier that fail-closes until real platform validation is wired.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableProductionPlatformVerifier;

impl ProductionPlatformVerifier for UnavailableProductionPlatformVerifier {
    fn kind(&self) -> PlatformVerifierKind {
        PlatformVerifierKind::Unavailable
    }

    fn verify_platform_attestation(
        &self,
        input: PlatformVerificationInput<'_>,
    ) -> Result<(), OprfError> {
        Err(OprfError::ProductionAttestationVerifierUnavailable {
            platform_tag: input.platform.tag(),
        })
    }
}

/// Адаптер общего платформенного слоя для OPRF.
/// Shared platform-verifier adapter for OPRF.
#[derive(Debug, Clone)]
pub enum SharedPlatformVerifierForOprf {
    /// Apple App Attest. Apple App Attest.
    Apple {
        /// Проверяющий. Verifier.
        verifier: AppleAppAttestVerifier,
        /// Ожидаемый App ID. Expected App ID.
        app_id: String,
    },
    /// Android Play Integrity. Android Play Integrity.
    Android {
        /// Проверяющий. Verifier.
        verifier: AndroidPlayIntegrityVerifier,
        /// Ожидаемое имя пакета. Expected package name.
        package_name: String,
    },
    /// WebAuthn. WebAuthn.
    Web {
        /// Проверяющий. Verifier.
        verifier: WebAuthnVerifier,
        /// Ожидаемый сайт. Expected site.
        site: String,
        /// Сохранённый ключ. Stored key.
        registered_key: RegisteredPlatformKey,
    },
}

impl SharedPlatformVerifierForOprf {
    /// Создать адаптер Apple.
    /// Create an Apple adapter.
    #[must_use]
    pub fn apple(verifier: AppleAppAttestVerifier, app_id: impl Into<String>) -> Self {
        Self::Apple {
            verifier,
            app_id: app_id.into(),
        }
    }

    /// Создать адаптер Android.
    /// Create an Android adapter.
    #[must_use]
    pub fn android(
        verifier: AndroidPlayIntegrityVerifier,
        package_name: impl Into<String>,
    ) -> Self {
        Self::Android {
            verifier,
            package_name: package_name.into(),
        }
    }

    /// Создать адаптер WebAuthn.
    /// Create a WebAuthn adapter.
    #[must_use]
    pub fn web(site: impl Into<String>, public_key: DevicePublicKey, last_counter: u32) -> Self {
        Self::Web {
            verifier: WebAuthnVerifier,
            site: site.into(),
            registered_key: RegisteredPlatformKey {
                public_key,
                last_counter,
            },
        }
    }

    /// Создать адаптер Android для тестов.
    /// Create an Android adapter for tests.
    #[cfg(test)]
    fn android_for_test(package_name: &str, google_verification_configured: bool) -> Self {
        Self::android(
            AndroidPlayIntegrityVerifier::new(AndroidPlayIntegrityConfig {
                package_name: package_name.to_string(),
                google_verification_configured,
            }),
            package_name,
        )
    }
}

fn request_platform_kind(platform: Platform) -> Option<PlatformVerifierKind> {
    match platform {
        Platform::IOs => Some(PlatformVerifierKind::AppleAppAttest),
        Platform::Android => Some(PlatformVerifierKind::AndroidPlayIntegrity),
        Platform::Web => Some(PlatformVerifierKind::WebAuthn),
        Platform::Testing => None,
    }
}

fn oprf_platform_error(err: PlatformVerifierError) -> OprfError {
    OprfError::ProductionPlatformVerificationFailed(err.to_string())
}

impl ProductionPlatformVerifier for SharedPlatformVerifierForOprf {
    fn kind(&self) -> PlatformVerifierKind {
        match self {
            Self::Apple { .. } => PlatformVerifierKind::AppleAppAttest,
            Self::Android { .. } => PlatformVerifierKind::AndroidPlayIntegrity,
            Self::Web { .. } => PlatformVerifierKind::WebAuthn,
        }
    }

    fn verify_platform_attestation(
        &self,
        input: PlatformVerificationInput<'_>,
    ) -> Result<(), OprfError> {
        if request_platform_kind(input.platform) != Some(self.kind()) {
            return Err(oprf_platform_error(PlatformVerifierError::PlatformMismatch));
        }

        match self {
            Self::Apple { verifier, app_id } => verifier
                .verify(PlatformVerificationContext {
                    platform: PlatformKind::AppleAppAttest,
                    token: input.token,
                    server_nonce: input.server_nonce,
                    device_pubkey: input.device_pubkey,
                    app_or_site: app_id.as_str(),
                    now_unix_millis: input.now_unix_millis,
                    registered_key: None,
                })
                .map(|_| ())
                .map_err(oprf_platform_error),
            Self::Android {
                verifier,
                package_name,
            } => verifier
                .verify(PlatformVerificationContext {
                    platform: PlatformKind::AndroidPlayIntegrity,
                    token: input.token,
                    server_nonce: input.server_nonce,
                    device_pubkey: input.device_pubkey,
                    app_or_site: package_name.as_str(),
                    now_unix_millis: input.now_unix_millis,
                    registered_key: None,
                })
                .map(|_| ())
                .map_err(oprf_platform_error),
            Self::Web {
                verifier,
                site,
                registered_key,
            } => verifier
                .verify(PlatformVerificationContext {
                    platform: PlatformKind::WebAuthn,
                    token: input.token,
                    server_nonce: input.server_nonce,
                    device_pubkey: input.device_pubkey,
                    app_or_site: site.as_str(),
                    now_unix_millis: input.now_unix_millis,
                    registered_key: Some(registered_key),
                })
                .map(|_| ())
                .map_err(oprf_platform_error),
        }
    }
}

/// Контекст боевой проверки OPRF-запроса.
/// Production verification context for an OPRF request.
#[derive(Debug)]
pub struct ProductionOprfVerificationContext<'a> {
    expected_server_nonce: [u8; NONCE_LEN],
    server_nonce_issued_at_unix_millis: u64,
    now_unix_millis: u64,
    freshness: ProductionFreshnessPolicy,
    device_state: ProductionDeviceState,
    platform_verifier: &'a dyn ProductionPlatformVerifier,
    nonce_replay_guard: &'a dyn ProductionNonceReplayGuard,
}

impl<'a> ProductionOprfVerificationContext<'a> {
    /// Создать боевой контекст.
    /// Create a production context.
    ///
    /// # Errors
    /// - [`OprfError::ProductionTestVerifierRejected`] если передан тестовый проверяющий.
    pub fn new(
        expected_server_nonce: [u8; NONCE_LEN],
        server_nonce_issued_at_unix_millis: u64,
        now_unix_millis: u64,
        freshness: ProductionFreshnessPolicy,
        device_state: ProductionDeviceState,
        platform_verifier: &'a dyn ProductionPlatformVerifier,
        nonce_replay_guard: &'a dyn ProductionNonceReplayGuard,
    ) -> Result<Self, OprfError> {
        if platform_verifier.kind() == PlatformVerifierKind::TestOnly {
            return Err(OprfError::ProductionTestVerifierRejected);
        }
        Ok(Self {
            expected_server_nonce,
            server_nonce_issued_at_unix_millis,
            now_unix_millis,
            freshness,
            device_state,
            platform_verifier,
            nonce_replay_guard,
        })
    }
}

fn check_production_nonce(
    request_nonce: &[u8; NONCE_LEN],
    expected_nonce: &[u8; NONCE_LEN],
) -> Result<(), OprfError> {
    if request_nonce != expected_nonce {
        return Err(OprfError::ProductionServerNonceMismatch);
    }
    Ok(())
}

fn check_production_freshness(
    nonce_issued_at_unix_millis: u64,
    now_unix_millis: u64,
    freshness: ProductionFreshnessPolicy,
) -> Result<(), OprfError> {
    if nonce_issued_at_unix_millis > now_unix_millis {
        let skew_millis = nonce_issued_at_unix_millis - now_unix_millis;
        if skew_millis > freshness.max_future_skew_millis {
            return Err(OprfError::ProductionServerNonceIssuedInFuture {
                skew_millis,
                max_future_skew_millis: freshness.max_future_skew_millis,
            });
        }
    } else {
        let age_millis = now_unix_millis - nonce_issued_at_unix_millis;
        if age_millis > freshness.max_nonce_age_millis {
            return Err(OprfError::ProductionServerNonceExpired {
                age_millis,
                max_age_millis: freshness.max_nonce_age_millis,
            });
        }
    }
    Ok(())
}

fn check_production_device_state(
    state: ProductionDeviceState,
    nonce_issued_at_unix_millis: u64,
) -> Result<(), OprfError> {
    let authorized_since_unix_millis = match state {
        ProductionDeviceState::Unknown => return Err(OprfError::ProductionDeviceUnknown),
        ProductionDeviceState::Pending => {
            return Err(OprfError::ProductionDevicePendingAuthorization);
        }
        ProductionDeviceState::Revoked => return Err(OprfError::ProductionDeviceRevoked),
        ProductionDeviceState::Active {
            authorized_since_unix_millis,
        }
        | ProductionDeviceState::BootstrapActive {
            authorized_since_unix_millis,
        } => authorized_since_unix_millis,
    };

    if authorized_since_unix_millis > nonce_issued_at_unix_millis {
        return Err(OprfError::ProductionDeviceNotActiveYet {
            authorized_since_unix_millis,
            nonce_issued_at_unix_millis,
        });
    }

    Ok(())
}

/// Боевая проверка подписанного OPRF-запроса с серверным контекстом.
/// Production verification for signed OPRF requests with server context.
///
/// Порядок строгий: подпись, nonce, свежесть, устройство, платформа.
/// Strict order: signature, nonce, freshness, device, platform.
///
/// # Errors
/// Возвращает первую причину отказа в указанном порядке.
pub fn verify_signed_request_for_production_with_context(
    req: &SignedOprfRequest,
    ctx: &ProductionOprfVerificationContext<'_>,
) -> Result<(), OprfError> {
    verify_signed_request(req)?;
    check_production_nonce(&req.nonce, &ctx.expected_server_nonce)?;
    check_production_freshness(
        ctx.server_nonce_issued_at_unix_millis,
        ctx.now_unix_millis,
        ctx.freshness,
    )?;
    check_production_device_state(ctx.device_state, ctx.server_nonce_issued_at_unix_millis)?;
    match req.attestation.platform {
        Platform::Testing => Err(OprfError::CryptoVerificationFailed),
        Platform::IOs | Platform::Android | Platform::Web => {
            ctx.platform_verifier
                .verify_platform_attestation(PlatformVerificationInput {
                    platform: req.attestation.platform,
                    token: req.attestation.token.as_slice(),
                    server_nonce: &req.nonce,
                    device_pubkey: &req.device_pubkey,
                    now_unix_millis: ctx.now_unix_millis,
                })?;
            ctx.nonce_replay_guard
                .check_and_record_nonce(&req.nonce, ctx.now_unix_millis)
        }
    }
}

/// Боевая проверка подписанного OPRF-запроса.
/// Production verification for a signed OPRF request.
///
/// Сначала проверяет device-signature, затем закрыто отказывает тестовой
/// платформе и всем настоящим платформам, пока platform-specific verifier
/// не связан до конца.
///
/// Checks the device signature first, then fail-closes for the test platform
/// and for real platforms until the platform-specific verifier is wired.
///
/// # Errors
/// - [`OprfError::CryptoVerificationFailed`] если подпись неверна или запрос
///   использует [`Platform::Testing`].
/// - [`OprfError::ProductionAttestationVerifierUnavailable`] если подпись
///   валидна, но настоящий platform verifier ещё не подключён.
pub fn verify_signed_request_for_production(req: &SignedOprfRequest) -> Result<(), OprfError> {
    verify_signed_request(req)?;
    match req.attestation.platform {
        Platform::Testing => Err(OprfError::CryptoVerificationFailed),
        Platform::IOs | Platform::Android | Platform::Web => {
            Err(OprfError::ProductionAttestationVerifierUnavailable {
                platform_tag: req.attestation.platform.tag(),
            })
        }
    }
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

    #[derive(Debug, Default)]
    struct CountingUnavailableVerifier {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl CountingUnavailableVerifier {
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl ProductionPlatformVerifier for CountingUnavailableVerifier {
        fn kind(&self) -> PlatformVerifierKind {
            PlatformVerifierKind::Unavailable
        }

        fn verify_platform_attestation(
            &self,
            input: PlatformVerificationInput<'_>,
        ) -> Result<(), OprfError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(OprfError::ProductionAttestationVerifierUnavailable {
                platform_tag: input.platform.tag(),
            })
        }
    }

    #[derive(Debug, Default)]
    struct TestOnlySuccessVerifier;

    impl ProductionPlatformVerifier for TestOnlySuccessVerifier {
        fn kind(&self) -> PlatformVerifierKind {
            PlatformVerifierKind::TestOnly
        }

        fn verify_platform_attestation(
            &self,
            _input: PlatformVerificationInput<'_>,
        ) -> Result<(), OprfError> {
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct AcceptingAndroidVerifier;

    impl ProductionPlatformVerifier for AcceptingAndroidVerifier {
        fn kind(&self) -> PlatformVerifierKind {
            PlatformVerifierKind::AndroidPlayIntegrity
        }

        fn verify_platform_attestation(
            &self,
            input: PlatformVerificationInput<'_>,
        ) -> Result<(), OprfError> {
            assert_eq!(input.platform, Platform::Android);
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct RecordingNonceReplayGuard {
        seen: std::sync::Mutex<std::collections::HashSet<[u8; NONCE_LEN]>>,
    }

    impl ProductionNonceReplayGuard for RecordingNonceReplayGuard {
        fn check_and_record_nonce(
            &self,
            nonce: &[u8; NONCE_LEN],
            _now_unix_millis: u64,
        ) -> Result<(), OprfError> {
            let mut seen = self
                .seen
                .lock()
                .map_err(|_| OprfError::ProductionServerNonceReplay)?;
            if !seen.insert(*nonce) {
                return Err(OprfError::ProductionServerNonceReplay);
            }
            Ok(())
        }
    }

    fn production_android_oprf_request(
        sk: &SigningKey,
        vk: &DalekVerifyingKey,
        nonce: [u8; NONCE_LEN],
    ) -> SignedOprfRequest {
        let input = OprfInput::new(b"+15550101010").unwrap();
        let (blinded, _state) = blind(input, &mut OsRng).unwrap();
        let attestation =
            PlatformAttestation::new(Platform::Android, b"play-integrity-token").unwrap();
        let canonical = canonical_signing_input(&blinded, &attestation, &nonce);
        SignedOprfRequest {
            blinded,
            attestation,
            nonce,
            device_signature: sign_with(sk, &canonical),
            device_pubkey: vk.to_bytes(),
        }
    }

    fn active_device_state() -> ProductionDeviceState {
        ProductionDeviceState::Active {
            authorized_since_unix_millis: 1_700_000_000_000,
        }
    }

    fn production_context<'a>(
        verifier: &'a dyn ProductionPlatformVerifier,
        replay_guard: &'a dyn ProductionNonceReplayGuard,
        expected_server_nonce: [u8; NONCE_LEN],
        nonce_issued_at_unix_millis: u64,
        now_unix_millis: u64,
        device_state: ProductionDeviceState,
    ) -> ProductionOprfVerificationContext<'a> {
        ProductionOprfVerificationContext::new(
            expected_server_nonce,
            nonce_issued_at_unix_millis,
            now_unix_millis,
            ProductionFreshnessPolicy::default(),
            device_state,
            verifier,
            replay_guard,
        )
        .expect("context must be valid for non-test-only verifier")
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
    fn production_policy_rejects_testing_attestation_even_after_valid_signature() {
        let (sk, vk) = make_device_keypair();
        let provider = TestingAttestationProvider::default();
        let input = OprfInput::new(b"+15550101010").unwrap();
        let (blinded, _state) = blind(input, &mut OsRng).unwrap();
        let signed = seal_request(
            blinded,
            &provider,
            fresh_nonce(),
            |payload| Ok(sign_with(&sk, payload)),
            vk.to_bytes(),
        )
        .unwrap();

        verify_signed_request(&signed).expect("signature-only verifier accepts test token");
        let err = verify_signed_request_for_production(&signed).unwrap_err();
        assert!(matches!(err, OprfError::CryptoVerificationFailed));
    }

    #[test]
    fn production_policy_rejects_real_platform_until_verifier_is_wired() {
        let (sk, vk) = make_device_keypair();
        let input = OprfInput::new(b"+15550101010").unwrap();
        let (blinded, _state) = blind(input, &mut OsRng).unwrap();
        let nonce = fresh_nonce();
        let attestation =
            PlatformAttestation::new(Platform::Android, b"play-integrity-token").unwrap();
        let canonical = canonical_signing_input(&blinded, &attestation, &nonce);
        let signed = SignedOprfRequest {
            blinded,
            attestation,
            nonce,
            device_signature: sign_with(&sk, &canonical),
            device_pubkey: vk.to_bytes(),
        };

        verify_signed_request(&signed).expect("signature-only verifier accepts Android token");
        let err = verify_signed_request_for_production(&signed).unwrap_err();
        assert!(matches!(
            err,
            OprfError::ProductionAttestationVerifierUnavailable { platform_tag }
                if platform_tag == Platform::Android.tag()
        ));
    }

    #[test]
    fn production_context_rejects_test_only_platform_verifier() {
        let nonce = fresh_nonce();
        let replay_guard = RecordingNonceReplayGuard::default();
        let err = ProductionOprfVerificationContext::new(
            nonce,
            1_700_000_000_000,
            1_700_000_000_001,
            ProductionFreshnessPolicy::default(),
            active_device_state(),
            &TestOnlySuccessVerifier,
            &replay_guard,
        )
        .unwrap_err();
        assert!(matches!(err, OprfError::ProductionTestVerifierRejected));
    }

    #[test]
    fn production_context_rejects_bad_signature_before_platform_verifier() {
        let (sk, vk) = make_device_keypair();
        let nonce = fresh_nonce();
        let mut signed = production_android_oprf_request(&sk, &vk, nonce);
        signed.device_signature[0] ^= 1;
        let verifier = CountingUnavailableVerifier::default();
        let replay_guard = RecordingNonceReplayGuard::default();
        let ctx = production_context(
            &verifier,
            &replay_guard,
            nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            active_device_state(),
        );
        let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();
        assert!(matches!(err, OprfError::CryptoVerificationFailed));
        assert_eq!(verifier.calls(), 0);
    }

    #[test]
    fn production_context_rejects_server_nonce_mismatch() {
        let (sk, vk) = make_device_keypair();
        let request_nonce = fresh_nonce();
        let expected_nonce = fresh_nonce();
        let signed = production_android_oprf_request(&sk, &vk, request_nonce);
        let verifier = CountingUnavailableVerifier::default();
        let replay_guard = RecordingNonceReplayGuard::default();
        let ctx = production_context(
            &verifier,
            &replay_guard,
            expected_nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            active_device_state(),
        );
        let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();
        assert!(matches!(err, OprfError::ProductionServerNonceMismatch));
        assert_eq!(verifier.calls(), 0);
    }

    #[test]
    fn production_context_rejects_expired_server_nonce() {
        let (sk, vk) = make_device_keypair();
        let nonce = fresh_nonce();
        let signed = production_android_oprf_request(&sk, &vk, nonce);
        let verifier = CountingUnavailableVerifier::default();
        let replay_guard = RecordingNonceReplayGuard::default();
        let ctx = production_context(
            &verifier,
            &replay_guard,
            nonce,
            1_700_000_000_000,
            1_700_000_400_001,
            active_device_state(),
        );
        let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();
        assert!(matches!(
            err,
            OprfError::ProductionServerNonceExpired { .. }
        ));
        assert_eq!(verifier.calls(), 0);
    }

    #[test]
    fn production_context_rejects_future_server_nonce_issue_time() {
        let (sk, vk) = make_device_keypair();
        let nonce = fresh_nonce();
        let signed = production_android_oprf_request(&sk, &vk, nonce);
        let verifier = CountingUnavailableVerifier::default();
        let replay_guard = RecordingNonceReplayGuard::default();
        let ctx = production_context(
            &verifier,
            &replay_guard,
            nonce,
            1_700_000_400_001,
            1_700_000_000_000,
            active_device_state(),
        );
        let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();
        assert!(matches!(
            err,
            OprfError::ProductionServerNonceIssuedInFuture { .. }
        ));
        assert_eq!(verifier.calls(), 0);
    }

    #[test]
    fn production_context_rejects_unknown_pending_and_revoked_devices() {
        let (sk, vk) = make_device_keypair();
        let nonce = fresh_nonce();
        let signed = production_android_oprf_request(&sk, &vk, nonce);
        let verifier = CountingUnavailableVerifier::default();
        let replay_guard = RecordingNonceReplayGuard::default();

        let ctx = production_context(
            &verifier,
            &replay_guard,
            nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            ProductionDeviceState::Unknown,
        );
        let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();
        assert!(matches!(err, OprfError::ProductionDeviceUnknown));

        let ctx = production_context(
            &verifier,
            &replay_guard,
            nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            ProductionDeviceState::Pending,
        );
        let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();
        assert!(matches!(
            err,
            OprfError::ProductionDevicePendingAuthorization
        ));

        let ctx = production_context(
            &verifier,
            &replay_guard,
            nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            ProductionDeviceState::Revoked,
        );
        let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();
        assert!(matches!(err, OprfError::ProductionDeviceRevoked));
        assert_eq!(verifier.calls(), 0);
    }

    #[test]
    fn production_context_active_device_reaches_platform_verifier_fail_closed() {
        let (sk, vk) = make_device_keypair();
        let nonce = fresh_nonce();
        let signed = production_android_oprf_request(&sk, &vk, nonce);
        let verifier = CountingUnavailableVerifier::default();
        let replay_guard = RecordingNonceReplayGuard::default();
        let ctx = production_context(
            &verifier,
            &replay_guard,
            nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            active_device_state(),
        );
        let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();
        assert!(matches!(
            err,
            OprfError::ProductionAttestationVerifierUnavailable { platform_tag }
                if platform_tag == Platform::Android.tag()
        ));
        assert_eq!(verifier.calls(), 1);
    }

    #[test]
    fn production_context_rejects_replayed_server_nonce_after_first_success() {
        let (sk, vk) = make_device_keypair();
        let nonce = fresh_nonce();
        let signed = production_android_oprf_request(&sk, &vk, nonce);
        let verifier = AcceptingAndroidVerifier;
        let replay_guard = RecordingNonceReplayGuard::default();
        let ctx = ProductionOprfVerificationContext::new(
            nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            ProductionFreshnessPolicy::default(),
            active_device_state(),
            &verifier,
            &replay_guard,
        )
        .expect("context with real verifier and replay guard is valid");

        verify_signed_request_for_production_with_context(&signed, &ctx)
            .expect("first use of server nonce is accepted");
        let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();

        assert!(matches!(err, OprfError::ProductionServerNonceReplay));
    }

    #[test]
    fn production_context_android_platform_uses_shared_platform_verifier() {
        let (sk, vk) = make_device_keypair();
        let nonce = fresh_nonce();
        let signed = production_android_oprf_request(&sk, &vk, nonce);
        let verifier = SharedPlatformVerifierForOprf::android_for_test("com.umbrella.app", false);
        let replay_guard = RecordingNonceReplayGuard::default();
        let ctx = production_context(
            &verifier,
            &replay_guard,
            nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            active_device_state(),
        );
        let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();
        assert!(matches!(
            err,
            OprfError::ProductionPlatformVerificationFailed(_)
        ));
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
