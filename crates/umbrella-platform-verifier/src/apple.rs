//! Apple App Attest проверяющий.
//! Apple App Attest verifier.

use crate::error::{PlatformVerifierError, Result};
use crate::types::{
    validate_token_size, PlatformKind, PlatformVerificationContext, PlatformVerifier,
    PlatformVerifierOutput, MAX_PLATFORM_TOKEN_BYTES,
};

/// Среда App Attest.
/// App Attest environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleAppAttestEnvironment {
    /// Разработка. Development.
    Development,
    /// Бой. Production.
    Production,
}

/// Настройки Apple App Attest.
/// Apple App Attest config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleAppAttestConfig {
    /// Team ID. Team ID.
    pub team_id: String,
    /// Bundle ID. Bundle ID.
    pub bundle_id: String,
    /// Среда. Environment.
    pub environment: AppleAppAttestEnvironment,
    /// Подключены ли корни доверия Apple.
    /// Whether Apple trust roots are wired.
    pub trust_roots_configured: bool,
}

/// Строгий Apple App Attest проверяющий.
/// Strict Apple App Attest verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleAppAttestVerifier {
    config: AppleAppAttestConfig,
}

impl AppleAppAttestVerifier {
    /// Создать проверяющий. Create verifier.
    #[must_use]
    pub fn new(config: AppleAppAttestConfig) -> Self {
        Self { config }
    }
}

impl PlatformVerifier for AppleAppAttestVerifier {
    fn verify(&self, ctx: PlatformVerificationContext<'_>) -> Result<PlatformVerifierOutput> {
        if ctx.platform != PlatformKind::AppleAppAttest {
            return Err(PlatformVerifierError::PlatformMismatch);
        }

        validate_token_size(ctx.token, MAX_PLATFORM_TOKEN_BYTES)?;

        if self.config.team_id.is_empty() || self.config.bundle_id.is_empty() {
            return Err(PlatformVerifierError::IncompleteConfiguration(
                "apple team_id and bundle_id are required",
            ));
        }

        let expected_app_id = format!("{}.{}", self.config.team_id, self.config.bundle_id);
        if ctx.app_or_site != expected_app_id {
            return Err(PlatformVerifierError::AppOrSiteMismatch);
        }

        if !self.config.trust_roots_configured {
            return Err(PlatformVerifierError::ExternalTrustMaterialRequired(
                "apple app attest root chain and attestation/assertion parser",
            ));
        }

        Err(PlatformVerifierError::ExternalTrustMaterialRequired(
            "apple app attest full verification is not implemented in this local phase",
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

    fn ctx<'a>(token: &'a [u8], app: &'a str) -> PlatformVerificationContext<'a> {
        PlatformVerificationContext {
            platform: PlatformKind::AppleAppAttest,
            token,
            server_nonce: &SERVER_NONCE,
            device_pubkey: &DEVICE_PUBKEY,
            app_or_site: app,
            now_unix_millis: 1_700_000_000_000,
            registered_key: None,
        }
    }

    fn verifier(trust_roots_configured: bool) -> AppleAppAttestVerifier {
        AppleAppAttestVerifier::new(AppleAppAttestConfig {
            team_id: "TEAMID1234".into(),
            bundle_id: "com.umbrella.app".into(),
            environment: AppleAppAttestEnvironment::Production,
            trust_roots_configured,
        })
    }

    fn reject(
        verifier: &AppleAppAttestVerifier,
        ctx: PlatformVerificationContext<'_>,
    ) -> PlatformVerifierError {
        match verifier.verify(ctx) {
            Ok(out) => panic!("apple app attest proof must be rejected, got {out:?}"),
            Err(err) => err,
        }
    }

    #[test]
    fn apple_rejects_empty_token() {
        let err = reject(&verifier(false), ctx(b"", "TEAMID1234.com.umbrella.app"));
        assert!(matches!(err, PlatformVerifierError::EmptyToken));
    }

    #[test]
    fn apple_rejects_missing_bundle_id_config() {
        let verifier = AppleAppAttestVerifier::new(AppleAppAttestConfig {
            team_id: "TEAMID1234".into(),
            bundle_id: "".into(),
            environment: AppleAppAttestEnvironment::Production,
            trust_roots_configured: false,
        });
        let err = reject(&verifier, ctx(b"token", "TEAMID1234.com.umbrella.app"));
        assert!(matches!(
            err,
            PlatformVerifierError::IncompleteConfiguration(_)
        ));
    }

    #[test]
    fn apple_rejects_wrong_app_id_before_trust_work() {
        let err = reject(&verifier(false), ctx(b"token", "OTHER.com.umbrella.app"));
        assert!(matches!(err, PlatformVerifierError::AppOrSiteMismatch));
    }

    #[test]
    fn apple_fails_closed_without_trust_roots() {
        let err = reject(
            &verifier(false),
            ctx(b"real-looking-cbor", "TEAMID1234.com.umbrella.app"),
        );
        assert!(matches!(
            err,
            PlatformVerifierError::ExternalTrustMaterialRequired(_)
        ));
    }

    #[test]
    fn apple_still_fails_closed_when_trust_flag_is_only_a_placeholder() {
        let err = reject(
            &verifier(true),
            ctx(b"real-looking-cbor", "TEAMID1234.com.umbrella.app"),
        );
        assert!(matches!(
            err,
            PlatformVerifierError::ExternalTrustMaterialRequired(_)
        ));
    }
}
