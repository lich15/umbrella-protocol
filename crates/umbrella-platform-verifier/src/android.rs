//! Android Play Integrity проверяющий.
//! Android Play Integrity verifier.

use crate::error::{PlatformVerifierError, Result};
use crate::types::{
    validate_token_size, PlatformKind, PlatformVerificationContext, PlatformVerifier,
    PlatformVerifierOutput, MAX_PLATFORM_TOKEN_BYTES,
};

/// Настройки Android Play Integrity.
/// Android Play Integrity config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidPlayIntegrityConfig {
    /// Имя пакета. Package name.
    pub package_name: String,
    /// Подключена ли проверка Гугл или локальные ключи.
    /// Whether Google verification or local keys are wired.
    pub google_verification_configured: bool,
}

/// Строгий Android Play Integrity проверяющий.
/// Strict Android Play Integrity verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidPlayIntegrityVerifier {
    config: AndroidPlayIntegrityConfig,
}

impl AndroidPlayIntegrityVerifier {
    /// Создать проверяющий. Create verifier.
    #[must_use]
    pub fn new(config: AndroidPlayIntegrityConfig) -> Self {
        Self { config }
    }
}

impl PlatformVerifier for AndroidPlayIntegrityVerifier {
    fn verify(&self, ctx: PlatformVerificationContext<'_>) -> Result<PlatformVerifierOutput> {
        if ctx.platform != PlatformKind::AndroidPlayIntegrity {
            return Err(PlatformVerifierError::PlatformMismatch);
        }

        validate_token_size(ctx.token, MAX_PLATFORM_TOKEN_BYTES)?;

        if self.config.package_name.is_empty() {
            return Err(PlatformVerifierError::IncompleteConfiguration(
                "android package name is required",
            ));
        }

        if ctx.app_or_site != self.config.package_name {
            return Err(PlatformVerifierError::AppOrSiteMismatch);
        }

        if !self.config.google_verification_configured {
            return Err(PlatformVerifierError::ExternalTrustMaterialRequired(
                "google play integrity decode/verify path or local keys",
            ));
        }

        Err(PlatformVerifierError::ExternalTrustMaterialRequired(
            "android play integrity full verification is not implemented in this local phase",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PlatformVerifierError;
    use crate::types::{PlatformKind, PlatformVerificationContext, PlatformVerifier};

    const SERVER_NONCE: [u8; 32] = [7u8; 32];
    const DEVICE_PUBKEY: [u8; 32] = [9u8; 32];

    fn ctx<'a>(token: &'a [u8], package: &'a str) -> PlatformVerificationContext<'a> {
        PlatformVerificationContext {
            platform: PlatformKind::AndroidPlayIntegrity,
            token,
            server_nonce: &SERVER_NONCE,
            device_pubkey: &DEVICE_PUBKEY,
            app_or_site: package,
            now_unix_millis: 1_700_000_000_000,
            registered_key: None,
        }
    }

    fn verifier(google_verification_configured: bool) -> AndroidPlayIntegrityVerifier {
        AndroidPlayIntegrityVerifier::new(AndroidPlayIntegrityConfig {
            package_name: "com.umbrella.app".into(),
            google_verification_configured,
        })
    }

    fn reject(
        verifier: &AndroidPlayIntegrityVerifier,
        ctx: PlatformVerificationContext<'_>,
    ) -> PlatformVerifierError {
        match verifier.verify(ctx) {
            Ok(out) => panic!("android play integrity proof must be rejected, got {out:?}"),
            Err(err) => err,
        }
    }

    #[test]
    fn android_rejects_empty_token() {
        let err = reject(&verifier(false), ctx(b"", "com.umbrella.app"));
        assert!(matches!(err, PlatformVerifierError::EmptyToken));
    }

    #[test]
    fn android_rejects_missing_package_name() {
        let verifier = AndroidPlayIntegrityVerifier::new(AndroidPlayIntegrityConfig {
            package_name: "".into(),
            google_verification_configured: false,
        });
        let err = reject(&verifier, ctx(b"token", "com.umbrella.app"));
        assert!(matches!(
            err,
            PlatformVerifierError::IncompleteConfiguration(_)
        ));
    }

    #[test]
    fn android_rejects_wrong_package_before_google_work() {
        let err = reject(&verifier(false), ctx(b"token", "com.evil.app"));
        assert!(matches!(err, PlatformVerifierError::AppOrSiteMismatch));
    }

    #[test]
    fn android_fails_closed_without_google_verification() {
        let err = reject(&verifier(false), ctx(b"nested-jwe-jws", "com.umbrella.app"));
        assert!(matches!(
            err,
            PlatformVerifierError::ExternalTrustMaterialRequired(_)
        ));
    }

    #[test]
    fn android_still_fails_closed_when_google_flag_is_only_a_placeholder() {
        let err = reject(&verifier(true), ctx(b"nested-jwe-jws", "com.umbrella.app"));
        assert!(matches!(
            err,
            PlatformVerifierError::ExternalTrustMaterialRequired(_)
        ));
    }
}
