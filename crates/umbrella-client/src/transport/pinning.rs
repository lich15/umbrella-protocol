//! SPKI (SubjectPublicKeyInfo) pinning placeholder для TLS соединений к
//! `Umbrella server implementation` сервисам (design §5.1).
//!
//! Блок 7.4 кладёт только структуры — `SpkiPin` (32 байта SHA-256 над
//! SubjectPublicKeyInfo в DER) и `PinningConfig` (primary + optional backup).
//! Custom `rustls::ServerCertVerifier` подключается в блоке 7.8 при deployment
//! `Umbrella server implementation` в production — тогда же hardcoded pins попадают в clientshipment
//! (через `ClientConfig::sealed_server_pins`).
//!
//! Двойная стратегия (primary + backup) нужна для graceful cert rotation без
//! принудительного обновления всех клиентов одновременно: server переходит
//! на backup-key, через n дней rotate обратно, перезапускает pin'ы в client.
//!
//! SPKI (SubjectPublicKeyInfo) pinning placeholder for TLS connections to
//! `Umbrella server implementation` services (design §5.1).
//!
//! Block 7.4 ships only the data types — `SpkiPin` (SHA-256 over DER-encoded
//! SubjectPublicKeyInfo) and `PinningConfig` (primary + optional backup).
//! Custom `rustls::ServerCertVerifier` is wired in Block 7.8 at production
//! deployment of `Umbrella server implementation`; hardcoded pins ship with the client at that
//! point via `ClientConfig::sealed_server_pins`.
//!
//! Dual-pin strategy (primary + backup) enables graceful cert rotation
//! without forcing every client to update simultaneously: server swaps to
//! backup key, days later rotates back, new pins ship to clients.

use sha2::{Digest, Sha256};

/// Длина SPKI pin в байтах (SHA-256 output).
/// SPKI pin length in bytes (SHA-256 output).
pub const SPKI_PIN_LEN: usize = 32;

/// SHA-256 hash над SubjectPublicKeyInfo (RFC 5280 §4.1.2.7) сервера.
///
/// Используется для certificate pinning: при TLS handshake `rustls`
/// `ServerCertVerifier` хеширует полученный server SPKI и сравнивает с
/// `primary` или `backup` pin. Несовпадение — fail handshake с
/// `rustls::Error::UnknownIssuer`.
///
/// SHA-256 over the server's SubjectPublicKeyInfo (RFC 5280 §4.1.2.7).
/// Used for certificate pinning in a custom `rustls::ServerCertVerifier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpkiPin(pub [u8; SPKI_PIN_LEN]);

impl SpkiPin {
    /// Вычислить pin из DER-encoded SubjectPublicKeyInfo.
    /// Compute a pin from DER-encoded SubjectPublicKeyInfo.
    #[must_use]
    pub fn from_spki_der(spki_der: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(spki_der);
        let digest = hasher.finalize();
        let mut out = [0u8; SPKI_PIN_LEN];
        out.copy_from_slice(&digest);
        Self(out)
    }

    /// Создать pin из заранее известного hash-а (используется для hardcoded
    /// pins в `ClientConfig`).
    ///
    /// Construct a pin from a known hash (used for hardcoded pins in
    /// `ClientConfig`).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SPKI_PIN_LEN]) -> Self {
        Self(bytes)
    }

    /// Сырой hash.
    /// Raw hash.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SPKI_PIN_LEN] {
        &self.0
    }
}

/// Конфигурация pinning'а для одного Sealed Server или другой endpoint.
///
/// `primary` — ожидаемый хеш SPKI текущего сертификата. `backup` — optional,
/// используется для graceful rotation: cert renewal через backup key даёт
/// окно когда server отвечает backup-подписанным cert, а клиенты с старой
/// primary всё ещё подключаются. После rollout нового client с
/// `primary = new_backup` — старый primary становится legacy и удаляется.
///
/// Pinning configuration for a single Sealed Server or other endpoint.
/// `primary` is the expected SPKI hash of the current certificate; `backup`
/// is optional and used for graceful cert rotation.
#[derive(Debug, Clone)]
pub struct PinningConfig {
    /// Primary (ожидаемый) SPKI pin. Primary expected SPKI pin.
    pub primary: SpkiPin,
    /// Optional backup pin — для graceful rotation без принудительного
    /// обновления клиентов. Optional backup pin for graceful rotation.
    pub backup: Option<SpkiPin>,
}

impl PinningConfig {
    /// Создать конфигурацию с только primary pin'ом (без backup).
    /// Construct a config with only a primary pin (no backup).
    #[must_use]
    pub const fn single(primary: SpkiPin) -> Self {
        Self {
            primary,
            backup: None,
        }
    }

    /// Создать конфигурацию с primary + backup pin.
    /// Construct a config with primary + backup pin.
    #[must_use]
    pub const fn dual(primary: SpkiPin, backup: SpkiPin) -> Self {
        Self {
            primary,
            backup: Some(backup),
        }
    }

    /// Проверить, совпадает ли переданный pin с primary или backup.
    /// Check whether a given pin matches primary or backup.
    #[must_use]
    pub fn matches(&self, candidate: &SpkiPin) -> bool {
        &self.primary == candidate
            || self
                .backup
                .as_ref()
                .map(|b| b == candidate)
                .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_from_spki_der_deterministic() {
        let spki = b"pretend-der-encoded-SubjectPublicKeyInfo";
        let pin_a = SpkiPin::from_spki_der(spki);
        let pin_b = SpkiPin::from_spki_der(spki);
        assert_eq!(pin_a, pin_b);
    }

    #[test]
    fn pin_from_spki_der_differs_for_different_input() {
        let a = SpkiPin::from_spki_der(b"cert-a");
        let b = SpkiPin::from_spki_der(b"cert-b");
        assert_ne!(a, b);
    }

    #[test]
    fn pinning_config_single_no_backup() {
        let pin = SpkiPin::from_bytes([1u8; SPKI_PIN_LEN]);
        let config = PinningConfig::single(pin);
        assert!(config.matches(&pin));
        assert!(config.backup.is_none());
        let other = SpkiPin::from_bytes([2u8; SPKI_PIN_LEN]);
        assert!(!config.matches(&other));
    }

    #[test]
    fn pinning_config_dual_matches_both() {
        let primary = SpkiPin::from_bytes([1u8; SPKI_PIN_LEN]);
        let backup = SpkiPin::from_bytes([2u8; SPKI_PIN_LEN]);
        let config = PinningConfig::dual(primary, backup);
        assert!(config.matches(&primary));
        assert!(config.matches(&backup));
        let other = SpkiPin::from_bytes([3u8; SPKI_PIN_LEN]);
        assert!(!config.matches(&other));
    }

    #[test]
    fn spki_pin_const_size_32() {
        assert_eq!(SPKI_PIN_LEN, 32);
        assert_eq!(std::mem::size_of::<SpkiPin>(), SPKI_PIN_LEN);
    }
}
