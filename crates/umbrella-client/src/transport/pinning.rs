//! Проверка закреплённых SPKI-ключей для боевого TLS.
//!
//! Этот модуль не заменяет обычную проверку сертификата. Он оборачивает
//! `rustls::ServerCertVerifier`: сначала системный проверяющий подтверждает
//! цепочку, срок действия и имя сервера, затем Umbrella сравнивает SHA-256 над
//! DER-encoded SubjectPublicKeyInfo с заранее закреплёнными ключами.
//!
//! SPKI pin verification for production TLS.
//!
//! This module does not replace normal certificate validation. It wraps a
//! `rustls::ServerCertVerifier`: the platform verifier first checks the chain,
//! validity period, and server name; Umbrella then compares SHA-256 over the
//! DER-encoded SubjectPublicKeyInfo with configured pins.

use std::collections::BTreeMap;
use std::sync::Arc;

use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Ошибка проверки закреплённого SPKI-ключа.
/// Error raised by SPKI pin verification.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PinningVerifierError {
    /// Сертификат пустой или не является DER-encoded X.509.
    /// Certificate is empty or is not DER-encoded X.509.
    #[error("invalid certificate DER")]
    InvalidCertificateDer,

    /// Для имени сервера нет закреплённых ключей.
    /// No pins are configured for this server name.
    #[error("no SPKI pins configured for server name {server_name}")]
    MissingPins {
        /// Имя сервера. Server name.
        server_name: String,
    },

    /// Сертификат разобран, но его SPKI не совпал с pin-ами.
    /// Certificate parsed, but its SPKI did not match configured pins.
    #[error("SPKI pin mismatch for server name {server_name}")]
    PinMismatch {
        /// Имя сервера. Server name.
        server_name: String,
    },

    /// IP-адреса не допускаются в pin map боевого клиента.
    /// IP addresses are not accepted in the production pin map.
    #[error("unsupported TLS server name for SPKI pinning: {server_name}")]
    UnsupportedServerName {
        /// Имя сервера. Server name.
        server_name: String,
    },
}

/// Извлечь SPKI pin из DER-encoded сертификата.
/// Extract an SPKI pin from a DER-encoded certificate.
///
/// # Errors
/// Возвращает [`PinningVerifierError::InvalidCertificateDer`], если вход не
/// является корректным X.509 DER-сертификатом.
///
/// Returns [`PinningVerifierError::InvalidCertificateDer`] if the input is not
/// a valid X.509 DER certificate.
pub fn extract_spki_pin_from_cert_der(
    certificate_der: &[u8],
) -> Result<SpkiPin, PinningVerifierError> {
    if certificate_der.is_empty() {
        return Err(PinningVerifierError::InvalidCertificateDer);
    }
    let certificate = Certificate::from_der(certificate_der)
        .map_err(|_| PinningVerifierError::InvalidCertificateDer)?;
    let spki_der = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| PinningVerifierError::InvalidCertificateDer)?;
    Ok(SpkiPin::from_spki_der(&spki_der))
}

/// `rustls` проверяющий, который усиливает обычную проверку сертификата SPKI pin-ами.
/// `rustls` verifier that strengthens normal certificate validation with SPKI pins.
#[derive(Debug)]
pub struct SpkiPinningVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    pins_by_host: BTreeMap<String, PinningConfig>,
}

impl SpkiPinningVerifier {
    /// Создать проверяющий с картой `host -> pins`.
    /// Create a verifier from a `host -> pins` map.
    ///
    /// # Errors
    /// Возвращает [`PinningVerifierError::UnsupportedServerName`], если имя
    /// хоста пустое после нормализации.
    ///
    /// Returns [`PinningVerifierError::UnsupportedServerName`] if a host name
    /// is empty after normalization.
    pub fn new(
        inner: Arc<dyn ServerCertVerifier>,
        pins_by_host: BTreeMap<String, PinningConfig>,
    ) -> Result<Self, PinningVerifierError> {
        let mut normalized = BTreeMap::new();
        for (raw_host, pins) in pins_by_host {
            let host = normalize_dns_host(&raw_host);
            if host.is_empty() {
                return Err(PinningVerifierError::UnsupportedServerName {
                    server_name: raw_host,
                });
            }
            normalized.insert(host, pins);
        }
        Ok(Self {
            inner,
            pins_by_host: normalized,
        })
    }

    #[cfg(test)]
    fn from_single_host_for_test(
        host: &str,
        pins: PinningConfig,
        inner: Arc<dyn ServerCertVerifier>,
    ) -> Result<Self, PinningVerifierError> {
        let mut map = BTreeMap::new();
        map.insert(host.to_string(), pins);
        Self::new(inner, map)
    }

    fn verify_pin(
        &self,
        server_name: &ServerName<'_>,
        certificate_der: &[u8],
    ) -> Result<(), PinningVerifierError> {
        let host = server_name_to_dns_host(server_name)?;
        let configured =
            self.pins_by_host
                .get(&host)
                .ok_or_else(|| PinningVerifierError::MissingPins {
                    server_name: host.clone(),
                })?;
        let candidate = extract_spki_pin_from_cert_der(certificate_der)?;
        if configured.matches(&candidate) {
            Ok(())
        } else {
            Err(PinningVerifierError::PinMismatch { server_name: host })
        }
    }
}

impl ServerCertVerifier for SpkiPinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        self.verify_pin(server_name, end_entity.as_ref())
            .map_err(|e| RustlsError::General(e.to_string()))?;
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn server_name_to_dns_host(server_name: &ServerName<'_>) -> Result<String, PinningVerifierError> {
    match server_name {
        ServerName::DnsName(name) => Ok(normalize_dns_host(name.as_ref())),
        ServerName::IpAddress(addr) => Err(PinningVerifierError::UnsupportedServerName {
            server_name: std::net::IpAddr::from(*addr).to_string(),
        }),
        _ => Err(PinningVerifierError::UnsupportedServerName {
            server_name: server_name.to_str().into_owned(),
        }),
    }
}

pub(crate) fn normalize_dns_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{
        CertificateError, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
    };

    #[derive(Debug, Clone, Copy)]
    enum InnerMode {
        Accept,
        Reject,
    }

    #[derive(Debug)]
    struct TestInnerVerifier {
        mode: InnerMode,
        calls: Arc<AtomicUsize>,
    }

    impl TestInnerVerifier {
        fn accepting(calls: Arc<AtomicUsize>) -> Arc<Self> {
            Arc::new(Self {
                mode: InnerMode::Accept,
                calls,
            })
        }

        fn rejecting(calls: Arc<AtomicUsize>) -> Arc<Self> {
            Arc::new(Self {
                mode: InnerMode::Reject,
                calls,
            })
        }
    }

    impl ServerCertVerifier for TestInnerVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, RustlsError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.mode {
                InnerMode::Accept => Ok(ServerCertVerified::assertion()),
                InnerMode::Reject => Err(RustlsError::InvalidCertificate(
                    CertificateError::UnknownIssuer,
                )),
            }
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
    }

    fn cert_der(host: &str) -> Vec<u8> {
        let CertifiedKey { cert, .. } =
            generate_simple_self_signed(vec![host.to_string()]).expect("test cert");
        cert.der().as_ref().to_vec()
    }

    fn verifier_for(
        host: &str,
        pins: PinningConfig,
        inner: Arc<dyn ServerCertVerifier>,
    ) -> SpkiPinningVerifier {
        SpkiPinningVerifier::from_single_host_for_test(host, pins, inner).expect("verifier")
    }

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

    #[test]
    fn real_certificate_primary_pin_accepts_after_inner_verifier_accepts() {
        let host = "sealed-0.umbrella.example";
        let der = cert_der(host);
        let pin = extract_spki_pin_from_cert_der(&der).expect("spki pin");
        let calls = Arc::new(AtomicUsize::new(0));
        let verifier = verifier_for(
            host,
            PinningConfig::single(pin),
            TestInnerVerifier::accepting(Arc::clone(&calls)),
        );
        let name = ServerName::try_from(host).expect("dns name");

        verifier
            .verify_server_cert(
                &CertificateDer::from(der),
                &[],
                &name,
                &[],
                UnixTime::now(),
            )
            .expect("matching pin is accepted");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn backup_pin_accepts_real_certificate_for_rotation() {
        let host = "sealed-0.umbrella.example";
        let der = cert_der(host);
        let backup = extract_spki_pin_from_cert_der(&der).expect("spki pin");
        let primary = SpkiPin::from_bytes([0xA5; SPKI_PIN_LEN]);
        let calls = Arc::new(AtomicUsize::new(0));
        let verifier = verifier_for(
            host,
            PinningConfig::dual(primary, backup),
            TestInnerVerifier::accepting(calls),
        );
        let name = ServerName::try_from(host).expect("dns name");

        verifier
            .verify_server_cert(
                &CertificateDer::from(der),
                &[],
                &name,
                &[],
                UnixTime::now(),
            )
            .expect("backup pin is accepted");
    }

    #[test]
    fn wrong_key_for_same_server_is_rejected_after_inner_accepts() {
        let host = "sealed-0.umbrella.example";
        let honest_der = cert_der(host);
        let attacker_der = cert_der(host);
        let honest_pin = extract_spki_pin_from_cert_der(&honest_der).expect("spki pin");
        let calls = Arc::new(AtomicUsize::new(0));
        let verifier = verifier_for(
            host,
            PinningConfig::single(honest_pin),
            TestInnerVerifier::accepting(Arc::clone(&calls)),
        );
        let name = ServerName::try_from(host).expect("dns name");

        let err = verifier
            .verify_server_cert(
                &CertificateDer::from(attacker_der),
                &[],
                &name,
                &[],
                UnixTime::now(),
            )
            .unwrap_err();

        assert!(format!("{err}").contains("SPKI pin mismatch"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn matching_pin_does_not_bypass_inner_certificate_failure() {
        let host = "sealed-0.umbrella.example";
        let der = cert_der(host);
        let pin = extract_spki_pin_from_cert_der(&der).expect("spki pin");
        let calls = Arc::new(AtomicUsize::new(0));
        let verifier = verifier_for(
            host,
            PinningConfig::single(pin),
            TestInnerVerifier::rejecting(Arc::clone(&calls)),
        );
        let name = ServerName::try_from(host).expect("dns name");

        let err = verifier
            .verify_server_cert(
                &CertificateDer::from(der),
                &[],
                &name,
                &[],
                UnixTime::now(),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            RustlsError::InvalidCertificate(CertificateError::UnknownIssuer)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unknown_dns_name_is_rejected_even_when_inner_accepts() {
        let known_host = "sealed-0.umbrella.example";
        let unknown_host = "sealed-1.umbrella.example";
        let der = cert_der(known_host);
        let pin = extract_spki_pin_from_cert_der(&der).expect("spki pin");
        let verifier = verifier_for(
            known_host,
            PinningConfig::single(pin),
            TestInnerVerifier::accepting(Arc::new(AtomicUsize::new(0))),
        );
        let name = ServerName::try_from(unknown_host).expect("dns name");

        let err = verifier
            .verify_server_cert(
                &CertificateDer::from(der),
                &[],
                &name,
                &[],
                UnixTime::now(),
            )
            .unwrap_err();

        assert!(format!("{err}").contains("no SPKI pins configured"));
    }

    #[test]
    fn invalid_certificate_der_returns_error_not_panic() {
        let err = extract_spki_pin_from_cert_der(b"not a certificate").unwrap_err();
        assert_eq!(err, PinningVerifierError::InvalidCertificateDer);
    }
}
