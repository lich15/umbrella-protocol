//! Общие типы платформенной проверки.
//! Common platform-verification types.

use crate::error::{PlatformVerifierError, Result};

/// Максимальный размер платформенного токена.
/// Maximum accepted platform token size.
pub const MAX_PLATFORM_TOKEN_BYTES: usize = 4096;

/// Проверить размер токена.
/// Validate platform token size.
pub fn validate_token_size(token: &[u8], max: usize) -> Result<()> {
    if token.is_empty() {
        return Err(PlatformVerifierError::EmptyToken);
    }
    if token.len() > max {
        return Err(PlatformVerifierError::TokenTooLarge {
            got: token.len(),
            max,
        });
    }
    Ok(())
}

/// Серверный одноразовый вызов.
/// Server-issued one-time nonce.
pub type ServerNonce = [u8; 32];

/// Публичный ключ устройства.
/// Device public key bytes.
pub type DevicePublicKey = [u8; 32];

/// Платформа проверяемого доказательства.
/// Platform of the proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformKind {
    /// Apple App Attest. Apple App Attest.
    AppleAppAttest,
    /// Android Play Integrity. Android Play Integrity.
    AndroidPlayIntegrity,
    /// WebAuthn. WebAuthn.
    WebAuthn,
}

/// Сохранённый платформенный ключ или запись.
/// Stored platform key or record.
#[derive(Clone, PartialEq, Eq)]
pub struct RegisteredPlatformKey {
    /// Публичный ключ проверки подписи. Public signature verification key.
    pub public_key: DevicePublicKey,
    /// Последний принятый счётчик. Last accepted counter.
    pub last_counter: u32,
}

/// `Debug` скрывает platform public key как linkable device material.
/// `Debug` redacts the platform public key as linkable device material.
impl core::fmt::Debug for RegisteredPlatformKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegisteredPlatformKey")
            .field("public_key_len", &self.public_key.len())
            .field("public_key", &"<redacted>")
            .field("last_counter", &self.last_counter)
            .finish()
    }
}

/// Вход платформенного проверяющего.
/// Input for a platform verifier.
#[derive(Clone)]
pub struct PlatformVerificationContext<'a> {
    /// Ожидаемая платформа. Expected platform.
    pub platform: PlatformKind,
    /// Токен платформы. Platform token bytes.
    pub token: &'a [u8],
    /// Серверный вызов. Server nonce.
    pub server_nonce: &'a ServerNonce,
    /// Публичный ключ устройства. Device public key.
    pub device_pubkey: &'a DevicePublicKey,
    /// Ожидаемое имя приложения или сайта. Expected app id or site.
    pub app_or_site: &'a str,
    /// Текущее серверное время. Current server time.
    pub now_unix_millis: u64,
    /// Сохранённая платформенная запись. Stored platform record.
    pub registered_key: Option<&'a RegisteredPlatformKey>,
}

/// `Debug` скрывает platform token перед попаданием в серверные журналы.
/// `Debug` redacts the platform token before it can reach server logs.
impl core::fmt::Debug for PlatformVerificationContext<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PlatformVerificationContext")
            .field("platform", &self.platform)
            .field("token_len", &self.token.len())
            .field("token", &"<redacted>")
            .field("server_nonce_len", &self.server_nonce.len())
            .field("server_nonce", &"<redacted>")
            .field("device_pubkey_len", &self.device_pubkey.len())
            .field("device_pubkey", &"<redacted>")
            .field("app_or_site_len", &self.app_or_site.len())
            .field("app_or_site", &"<redacted>")
            .field("now_unix_millis", &self.now_unix_millis)
            .field("registered_key_present", &self.registered_key.is_some())
            .finish()
    }
}

/// Успешный результат проверки.
/// Successful verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformVerifierOutput {
    /// Новый счётчик, который сервер должен сохранить.
    /// New counter the server should store.
    pub new_counter: Option<u32>,
}

/// Общий интерфейс платформенного проверяющего.
/// Common platform verifier interface.
pub trait PlatformVerifier: core::fmt::Debug {
    /// Проверить платформенное доказательство.
    /// Verify a platform proof.
    fn verify(&self, ctx: PlatformVerificationContext<'_>) -> Result<PlatformVerifierOutput>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PlatformVerifierError;

    #[test]
    fn token_guard_rejects_empty() {
        let err = match validate_token_size(&[], MAX_PLATFORM_TOKEN_BYTES) {
            Ok(()) => panic!("empty token must be rejected"),
            Err(err) => err,
        };
        assert!(matches!(err, PlatformVerifierError::EmptyToken));
    }

    #[test]
    fn token_guard_rejects_oversize() {
        let token = vec![0u8; MAX_PLATFORM_TOKEN_BYTES + 1];
        let err = match validate_token_size(&token, MAX_PLATFORM_TOKEN_BYTES) {
            Ok(()) => panic!("oversized token must be rejected"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            PlatformVerifierError::TokenTooLarge { got, max }
                if got == MAX_PLATFORM_TOKEN_BYTES + 1 && max == MAX_PLATFORM_TOKEN_BYTES
        ));
    }

    #[test]
    fn token_guard_accepts_non_empty_within_limit() {
        if let Err(err) = validate_token_size(b"x", MAX_PLATFORM_TOKEN_BYTES) {
            panic!("non-empty token within the limit must be accepted: {err:?}");
        }
    }

    #[test]
    fn platform_verification_context_debug_redacts_token() {
        let nonce = [1u8; 32];
        let device_pubkey = [2u8; 32];
        let registered = RegisteredPlatformKey {
            public_key: device_pubkey,
            last_counter: 7,
        };
        let ctx = PlatformVerificationContext {
            platform: PlatformKind::AndroidPlayIntegrity,
            token: b"platform-token-secret",
            server_nonce: &nonce,
            device_pubkey: &device_pubkey,
            app_or_site: "io.umbrellax.app",
            now_unix_millis: 1_700_000_000_000,
            registered_key: Some(&registered),
        };

        let debug = format!("{ctx:?}");

        assert!(
            !debug.contains("112, 108, 97, 116, 102, 111, 114, 109"),
            "Debug output must not leak platform verification token bytes: {debug}"
        );
        assert!(
            debug.contains("token_len"),
            "Debug output should keep token length metadata for diagnostics: {debug}"
        );
        assert!(
            !debug.contains("server_nonce: [")
                && !debug.contains("device_pubkey: [")
                && !debug.contains("io.umbrellax.app"),
            "Debug output must not leak platform verifier nonce, device key, or app/site: {debug}"
        );
        assert!(
            debug.contains("server_nonce_len")
                && debug.contains("device_pubkey_len")
                && debug.contains("app_or_site_len")
                && debug.contains("registered_key_present"),
            "Debug output should keep safe verifier metadata: {debug}"
        );
    }
}
