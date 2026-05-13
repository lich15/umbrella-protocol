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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredPlatformKey {
    /// Публичный ключ проверки подписи. Public signature verification key.
    pub public_key: DevicePublicKey,
    /// Последний принятый счётчик. Last accepted counter.
    pub last_counter: u32,
}

/// Вход платформенного проверяющего.
/// Input for a platform verifier.
#[derive(Debug, Clone)]
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
        let err = validate_token_size(&[], MAX_PLATFORM_TOKEN_BYTES).unwrap_err();
        assert!(matches!(err, PlatformVerifierError::EmptyToken));
    }

    #[test]
    fn token_guard_rejects_oversize() {
        let token = vec![0u8; MAX_PLATFORM_TOKEN_BYTES + 1];
        let err = validate_token_size(&token, MAX_PLATFORM_TOKEN_BYTES).unwrap_err();
        assert!(matches!(
            err,
            PlatformVerifierError::TokenTooLarge { got, max }
                if got == MAX_PLATFORM_TOKEN_BYTES + 1 && max == MAX_PLATFORM_TOKEN_BYTES
        ));
    }

    #[test]
    fn token_guard_accepts_non_empty_within_limit() {
        validate_token_size(b"x", MAX_PLATFORM_TOKEN_BYTES).unwrap();
    }
}
