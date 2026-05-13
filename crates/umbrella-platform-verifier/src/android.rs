//! Android Play Integrity проверяющий.
//! Android Play Integrity verifier.

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
