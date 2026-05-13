//! Apple App Attest проверяющий.
//! Apple App Attest verifier.

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
