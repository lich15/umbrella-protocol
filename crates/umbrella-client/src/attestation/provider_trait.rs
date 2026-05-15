//! [`AttestationProvider`] — async callback interface для platform attestation.
//!
//! Реализации:
//! - **iOS** (блок 7.8): native Swift через `DCAppAttestService.shared.attestKey`
//!   (Apple App Attest). Callback проходит uniffi FFI.
//! - **Android** (блок 7.9): native Kotlin через `IntegrityManager.requestIntegrityToken`
//!   (Google Play Integrity). Callback проходит uniffi FFI.
//! - **Тесты** — [`StaticTestAttestationProvider`], детерминированный
//!   `prefix || server_nonce`.
//!
//! Sealed Servers проверяют что `server_nonce` (32 bytes) встроен в token
//! внутри JWS payload, и что token выдан в окне ±5 минут от текущего времени
//! сервера. Поэтому native-реализация обязана передавать nonce в platform
//! attestation service как `clientDataHash` (iOS) или `nonce` (Android).
//!
//! Типы [`Platform`] и [`PlatformAttestation`] — re-export из
//! `umbrella-backup::cloud_wrap::signed_request`. Это canonical wire-format
//! для cloud-unwrap flow (SPEC-12 §A.7). Параллельная `umbrella-oprf::attestation`
//! копия этих типов используется **только** OPRF-flow (SPEC-05 contact
//! discovery) — это не нарушение DRY, а намеренное разделение crate-boundary
//! (нижние слои не хотят зависеть друг от друга).
//!
//! Async callback interface for platform attestation.
//!
//! Implementations:
//! - **iOS** (Block 7.8): native Swift via
//!   `DCAppAttestService.shared.attestKey` (Apple App Attest). Callback goes
//!   through uniffi FFI.
//! - **Android** (Block 7.9): native Kotlin via
//!   `IntegrityManager.requestIntegrityToken` (Google Play Integrity). Callback
//!   goes through uniffi FFI.
//! - **Tests** — [`StaticTestAttestationProvider`], deterministic
//!   `prefix || server_nonce`.
//!
//! Sealed Servers verify that `server_nonce` (32 bytes) is embedded in the
//! token's JWS payload and that the token was issued within a ±5-minute window
//! relative to server time. Thus native implementations must forward the nonce
//! to the platform attestation service as `clientDataHash` (iOS) or `nonce`
//! (Android).
//!
//! [`Platform`] and [`PlatformAttestation`] are re-exported from
//! `umbrella-backup::cloud_wrap::signed_request`. They are the canonical
//! wire-format types for the cloud-unwrap flow (SPEC-12 §A.7). A parallel copy
//! exists in `umbrella-oprf::attestation` and is used **only** by the OPRF
//! flow (SPEC-05 contact discovery) — this is not a DRY violation but an
//! intentional crate-boundary split (lower crates must not depend on each
//! other).

use async_trait::async_trait;
use thiserror::Error;

pub use umbrella_backup::cloud_wrap::signed_request::{Platform, PlatformAttestation};

/// Ошибки platform attestation, видимые каллеру (Rust-стороне).
///
/// Нативный bridge конвертирует платформенные ошибки Apple App Attest
/// (`DCError`) и Google Play Integrity (`IntegrityServiceException`) в
/// соответствующие варианты этого enum'а. Каждая причина имеет семантическое
/// значение для UX (например, `AppNotEligible` → показать пользователю что
/// устройство jailbroken/rooted и отказаться от работы; `ServiceUnavailable`
/// → retry с backoff).
///
/// Platform attestation errors visible to the (Rust) caller.
///
/// The native bridge translates Apple App Attest (`DCError`) and Google Play
/// Integrity (`IntegrityServiceException`) errors into variants of this enum.
/// Each cause has UX meaning (e.g. `AppNotEligible` → show the user the device
/// is jailbroken/rooted and refuse to proceed; `ServiceUnavailable` → retry
/// with backoff).
#[derive(Debug, Error)]
pub enum AttestationError {
    /// Платформенный attestation-сервис недоступен (сеть, downtime, throttling).
    /// Retry with exponential backoff.
    ///
    /// Platform attestation service is unavailable (network, downtime,
    /// throttling). Retry with exponential backoff.
    #[error("platform attestation service unavailable")]
    ServiceUnavailable,

    /// Attestation-сервис отверг `server_nonce` (обычно — несвежий nonce).
    /// Caller должен запросить новый nonce у сервера и повторить.
    ///
    /// Attestation service rejected `server_nonce` (usually a stale nonce).
    /// Caller should refresh nonce from server and retry.
    #[error("server_nonce rejected by platform attestation service")]
    NonceRejected,

    /// Платформенный вызов не завершился за отведённое время.
    /// Caller может retry; на клиентах с плохой сетью — увеличить deadline.
    ///
    /// Platform call did not complete within deadline. Caller can retry;
    /// devices with poor connectivity should raise the deadline.
    #[error("platform attestation timed out")]
    Timeout,

    /// Получен token некорректной формы (пустой, слишком длинный,
    /// malformed JWS). Сигналит баг native bridge'а либо тампер устройства.
    ///
    /// Received token has invalid shape (empty, oversized, malformed JWS).
    /// Indicates a native-bridge bug or device tampering.
    #[error("attestation token has invalid shape: {0}")]
    InvalidShape(String),

    /// Приложение не проходит platform integrity check (jailbroken iOS /
    /// rooted Android / emulator). Permanent — retry бесполезен.
    ///
    /// Application failed platform integrity check (jailbroken iOS / rooted
    /// Android / emulator). Permanent — retrying is pointless.
    #[error("application not eligible for attestation (jailbreak/root/emulator)")]
    AppNotEligible,

    /// Native-specific ошибка, не покрываемая остальными вариантами.
    /// Содержит исходное сообщение от платформы для diagnostics.
    ///
    /// Native-specific error not covered by other variants. Carries the
    /// original platform message for diagnostics.
    #[error("native attestation error: {0}")]
    Native(String),
}

/// Async callback для получения свежего platform attestation token.
///
/// Контракт:
/// 1. Возвращаемый token **обязан** содержать `server_nonce` в проверяемой
///    серверной стороной форме (для iOS — в `clientDataHash` App Attest, для
///    Android — в `nonce` поля Play Integrity request). Это гарантирует
///    freshness (±5 минут окно на серверной стороне).
/// 2. `platform()` возвращает идентификатор источника, совпадающий с байтом
///    тегa в wire-format `SignedUnwrapRequest` (см.
///    [`Platform::tag`]).
/// 3. Реализация должна быть `Send + Sync` для использования как
///    `Arc<dyn AttestationProvider>` внутри `ClientCore`.
///
/// Async callback returning a fresh platform attestation token.
///
/// Contract:
/// 1. The returned token **must** embed `server_nonce` in a form that the
///    server can verify (for iOS — `clientDataHash` of App Attest; for Android
///    — the `nonce` field of the Play Integrity request). This ensures
///    freshness (±5-minute window on the server side).
/// 2. `platform()` returns the source identifier matching the tag byte in the
///    `SignedUnwrapRequest` wire format (see [`Platform::tag`]).
/// 3. Implementations must be `Send + Sync` so they can be used as
///    `Arc<dyn AttestationProvider>` inside `ClientCore`.
#[async_trait]
pub trait AttestationProvider: Send + Sync {
    /// Получить свежий attestation token с встроенным `server_nonce`.
    /// Выданный token валиден в окне ±5 минут от момента issuing.
    ///
    /// # Errors
    /// См. варианты [`AttestationError`].
    ///
    /// Obtain a fresh attestation token with `server_nonce` embedded. The
    /// issued token is valid within a ±5-minute window from the issuing time.
    ///
    /// # Errors
    /// See [`AttestationError`] variants.
    async fn fresh_token(
        &self,
        server_nonce: [u8; 32],
    ) -> Result<PlatformAttestation, AttestationError>;

    /// Platform tag для identification. Ожидается совпадение с байтом тега,
    /// который native-реализация вкладывает в `PlatformAttestation::platform`.
    ///
    /// Platform tag used for identification. Must match the tag byte that the
    /// native implementation places into `PlatformAttestation::platform`.
    fn platform(&self) -> Platform;
}

/// Детерминистический `AttestationProvider` для unit- и integration-тестов.
///
/// Формирует token как `prefix || server_nonce` и возвращает его с указанной
/// платформой. Предназначен **только** для тестовой инфраструктуры; сервер-сайд
/// Sealed Servers в продакшне отверает tokens с `Platform::Testing` тегом.
///
/// Deterministic `AttestationProvider` for unit and integration tests.
///
/// Builds the token as `prefix || server_nonce` and returns it with the given
/// platform. Intended **only** for test infrastructure; in production Sealed
/// Servers reject tokens carrying the `Platform::Testing` tag.
#[derive(Clone)]
pub struct StaticTestAttestationProvider {
    platform: Platform,
    token_prefix: Vec<u8>,
}

/// `Debug` скрывает deterministic token prefix, чтобы тестовый путь не учил логировать токены.
/// `Debug` redacts the deterministic token prefix so the test path never normalizes token logging.
impl core::fmt::Debug for StaticTestAttestationProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticTestAttestationProvider")
            .field("platform", &self.platform)
            .field("token_prefix_len", &self.token_prefix.len())
            .field("token_prefix", &"<redacted>")
            .finish()
    }
}

impl StaticTestAttestationProvider {
    /// Создать тестовый провайдер с заданной платформой и префиксом token'а.
    /// Префикс должен быть таким, чтобы `prefix.len() + 32 ≤ 4096` —
    /// иначе `fresh_token` вернёт [`AttestationError::InvalidShape`].
    ///
    /// Construct a test provider with the given platform and token prefix.
    /// The prefix must satisfy `prefix.len() + 32 ≤ 4096`; otherwise
    /// `fresh_token` returns [`AttestationError::InvalidShape`].
    #[must_use]
    pub fn new(platform: Platform, token_prefix: Vec<u8>) -> Self {
        Self {
            platform,
            token_prefix,
        }
    }
}

#[async_trait]
impl AttestationProvider for StaticTestAttestationProvider {
    async fn fresh_token(
        &self,
        server_nonce: [u8; 32],
    ) -> Result<PlatformAttestation, AttestationError> {
        let mut token_bytes = Vec::with_capacity(self.token_prefix.len() + server_nonce.len());
        token_bytes.extend_from_slice(&self.token_prefix);
        token_bytes.extend_from_slice(&server_nonce);
        PlatformAttestation::new(self.platform, &token_bytes)
            .map_err(|e| AttestationError::InvalidShape(format!("{e}")))
    }

    fn platform(&self) -> Platform {
        self.platform
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_provider_embeds_nonce_into_token() {
        let provider =
            StaticTestAttestationProvider::new(Platform::IOs, b"ios-test-prefix-".to_vec());
        let nonce = [0x42u8; 32];
        let att = provider
            .fresh_token(nonce)
            .await
            .expect("token must be built");
        assert_eq!(att.platform, Platform::IOs);
        // Token ends with the 32-byte server_nonce (prefix || nonce layout).
        let token_bytes: &[u8] = att.token.as_slice();
        assert!(token_bytes.len() >= 32);
        assert_eq!(&token_bytes[token_bytes.len() - 32..], &nonce);
    }

    #[tokio::test]
    async fn static_provider_different_nonces_produce_different_tokens() {
        let provider = StaticTestAttestationProvider::new(Platform::Android, b"and-".to_vec());
        let a = provider.fresh_token([0x01u8; 32]).await.unwrap();
        let b = provider.fresh_token([0x02u8; 32]).await.unwrap();
        assert_ne!(a.token.as_slice(), b.token.as_slice());
    }

    #[tokio::test]
    async fn static_provider_reports_platform_for_all_variants() {
        for p in [
            Platform::IOs,
            Platform::Android,
            Platform::Web,
            Platform::Testing,
        ] {
            let provider = StaticTestAttestationProvider::new(p, b"p".to_vec());
            assert_eq!(provider.platform(), p);
            let att = provider
                .fresh_token([0u8; 32])
                .await
                .expect("prefix + nonce fits");
            assert_eq!(att.platform, p);
        }
    }

    #[tokio::test]
    async fn static_provider_rejects_oversize_prefix() {
        // 4096 - 32 = 4064 — maximum prefix that still leaves room for the
        // 32-byte nonce. Anything larger must round-trip through
        // `InvalidShape`.
        let oversize = vec![0u8; 4096];
        let provider = StaticTestAttestationProvider::new(Platform::Testing, oversize);
        let err = provider
            .fresh_token([0u8; 32])
            .await
            .expect_err("oversize prefix must be rejected");
        assert!(
            matches!(err, AttestationError::InvalidShape(_)),
            "expected InvalidShape, got {err:?}"
        );
    }

    #[test]
    fn attestation_provider_trait_object_is_send_sync() {
        fn assert_bounds<T: ?Sized + Send + Sync>() {}
        assert_bounds::<dyn AttestationProvider>();
    }

    #[test]
    fn static_test_attestation_provider_debug_redacts_token_prefix() {
        let provider =
            StaticTestAttestationProvider::new(Platform::Testing, b"test-token-prefix".to_vec());

        let debug = format!("{provider:?}");

        assert!(
            !debug.contains("test-token-prefix"),
            "Debug output must not leak deterministic attestation token prefix: {debug}"
        );
        assert!(
            debug.contains("token_prefix_len"),
            "Debug output should keep token prefix length metadata: {debug}"
        );
    }

    #[test]
    fn static_provider_is_send_sync_and_clone() {
        fn assert_clone<T: Clone>() {}
        fn assert_send_sync<T: Send + Sync>() {}
        assert_clone::<StaticTestAttestationProvider>();
        assert_send_sync::<StaticTestAttestationProvider>();
    }
}
