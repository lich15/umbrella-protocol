# Production Transport Pinning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Заменить честный отказ боевого HTTP/2-транспорта настоящей проверкой системного сертификата плюс закреплённого SPKI-ключа.

**Architecture:** В `umbrella-client` появляется обёртка над `rustls::client::danger::ServerCertVerifier`: сначала работает обычная системная проверка сертификата, потом извлекается SPKI из DER-сертификата и сравнивается с закреплёнными ключами для имени сервера. Внутренний боевой сборщик транспорта начинает строить `reqwest::Client` через готовый `rustls::ClientConfig`, но публичный FFI-запуск остаётся закрыт по оставшимся воротам: attestation, мобильные мосты и серверная связка.

**Tech Stack:** Rust workspace, `reqwest 0.13.3`, `rustls 0.23.40`, `rustls-platform-verifier 0.7.0`, `x509-cert 0.2.5`, `rcgen 0.14.8`, Cargo locked tests, Markdown docs.

---

## Источники Правды

- `docs/WORKING_RULES.md`
- `docs/superpowers/specs/2026-05-13-production-transport-pinning-design.md`
- `docs/superpowers/specs/2026-05-13-protocol-compliance-hardening-phase2-design.md`
- `docs/security/production-readiness-boundaries.md`
- `docs/README.md`
- `README.md`
- `scripts/audit-public-access-notices.sh`
- `crates/umbrella-client/src/transport/pinning.rs`
- `crates/umbrella-client/src/transport/http2_client.rs`
- `crates/umbrella-ffi/src/export/client.rs`
- `crates/umbrella-ffi/tests/production_bootstrap.rs`

Свежие источники, проверенные 2026-05-13:

- `reqwest 0.13.3`: `tls_version_min` актуален; `tls_backend_preconfigured` принимает готовый TLS-backend и падает при неизвестном типе.
  <https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html>
- `rustls-platform-verifier 0.7.0`: системный проверяющий рекомендуется как лучший обычный выбор для клиентской проверки TLS; Android требует отдельной инициализации.
  <https://docs.rs/rustls-platform-verifier/latest/rustls_platform_verifier/>
- `x509-cert 0.2.5`: `TbsCertificateInner` содержит `subject_public_key_info`, а тип реализует DER-кодирование через `Encode`.
  <https://docs.rs/x509-cert/latest/x509_cert/certificate/struct.TbsCertificateInner.html>
- `rcgen 0.14.8`: свежий генератор тестовых X.509-сертификатов; используется только в dev-зависимости для настоящих DER-сертификатов в атакующих тестах.
  <https://docs.rs/rcgen/latest/rcgen/>

## File Structure

- Modify `Cargo.toml`: добавить прямые workspace-зависимости для проверяющего слоя и тестовых сертификатов.
- Modify `crates/umbrella-client/Cargo.toml`: подключить `rustls`, `rustls-platform-verifier`, `x509-cert`; подключить `rcgen` только в dev-зависимости.
- Modify `crates/umbrella-client/src/transport/pinning.rs`: заменить текст про placeholder на настоящий SPKI verifier, ошибки, извлечение SPKI и атакующие тесты.
- Modify `crates/umbrella-client/src/transport/http2_client.rs`: собрать production pin map, создать `rustls::ClientConfig` с системным проверяющим и pinning verifier, заменить fail-fast builder на рабочий внутренний builder.
- Modify `crates/umbrella-client/src/transport/mod.rs`: экспортировать проверяющий слой, если он нужен тестам и внутренним интеграциям.
- Modify `crates/umbrella-ffi/src/export/client.rs`: убрать TLS/pinning из причины публичного отказа, оставить отказ по оставшимся воротам.
- Modify `crates/umbrella-ffi/tests/production_bootstrap.rs`: доказать, что публичный FFI всё ещё закрыт, но больше не врёт про незавершённый TLS/pinning.
- Modify `docs/security/production-readiness-boundaries.md`: перенести HTTP/2/TLS pinning из “не подключено” в “внутренний транспорт подключён, публичный bootstrap закрыт”.
- Modify `docs/README.md`, `README.md`, `scripts/audit-public-access-notices.sh`: синхронизировать публичные заявления и аудит.

## Implementation Tasks

### Task 1: Dependency Gate And Baseline

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/umbrella-client/Cargo.toml`

- [ ] **Step 1: Confirm clean worktree and initialized submodules**

Run:

```bash
git status --short --branch
git submodule status --recursive
```

Expected:

```text
## codex/production-transport-pinning
 a0eb41def0cf227034bde19b7c11e62ab2a74a03 crates/umbrella-tests/cross_impl/aws_mls_rs ...
 47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6 crates/umbrella-tests/cross_impl/openmls ...
```

- [ ] **Step 2: Record baseline test gate**

Run:

```bash
cargo test --workspace --all-features --locked
```

Expected:

```text
test result: ok
```

- [ ] **Step 3: Add direct dependencies**

In root `Cargo.toml`, under the TLS dependencies, add:

```toml
rustls-platform-verifier = "0.7.0"
x509-cert = { version = "0.2.5", default-features = false }
```

Under dev tooling, add:

```toml
rcgen = "0.14.8"
```

In `crates/umbrella-client/Cargo.toml`, under `reqwest = { workspace = true }`, add:

```toml
rustls = { workspace = true }
rustls-platform-verifier = { workspace = true }
x509-cert = { workspace = true }
```

In `crates/umbrella-client/Cargo.toml`, under `[dev-dependencies]`, add:

```toml
rcgen = { workspace = true }
```

- [ ] **Step 4: Update lockfile once, then return to locked commands**

Run:

```bash
cargo check -p umbrella-client --all-features
```

Expected:

```text
Finished `dev` profile
```

- [ ] **Step 5: Verify supply-chain policy after adding dependencies**

Run:

```bash
cargo deny check
```

Expected:

```text
advisories ok, bans ok, licenses ok, sources ok
```

- [ ] **Step 6: Commit dependency iteration**

Run:

```bash
git add Cargo.toml crates/umbrella-client/Cargo.toml Cargo.lock
git commit -m "client: add tls pinning dependencies"
```

### Task 2: Real SPKI Pinning Verifier

**Files:**
- Modify: `crates/umbrella-client/src/transport/pinning.rs`

- [ ] **Step 1: Add failing attack tests**

In `crates/umbrella-client/src/transport/pinning.rs`, replace the current `#[cfg(test)] mod tests` with this expanded module. These tests must fail before the implementation because the verifier types and functions do not exist yet.

```rust
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
```

- [ ] **Step 2: Run red tests**

Run:

```bash
cargo test -p umbrella-client transport::pinning --all-features --locked
```

Expected current failure:

```text
cannot find type `SpkiPinningVerifier`
cannot find function `extract_spki_pin_from_cert_der`
```

- [ ] **Step 3: Replace placeholder module text and add verifier code**

In `crates/umbrella-client/src/transport/pinning.rs`, replace the module header and add these imports after `use sha2::{Digest, Sha256};`:

```rust
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
```

```rust
use std::collections::BTreeMap;
use std::sync::Arc;

use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use thiserror::Error;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;
```

Add this code after `impl PinningConfig`:

```rust
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
    pub fn new(
        inner: Arc<dyn ServerCertVerifier>,
        pins_by_host: BTreeMap<String, PinningConfig>,
    ) -> Result<Self, PinningVerifierError> {
        let mut normalized = BTreeMap::new();
        for (host, pins) in pins_by_host {
            let host = normalize_dns_host(&host);
            if host.is_empty() {
                return Err(PinningVerifierError::UnsupportedServerName {
                    server_name: host,
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
        let configured = self
            .pins_by_host
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

fn server_name_to_dns_host(
    server_name: &ServerName<'_>,
) -> Result<String, PinningVerifierError> {
    match server_name {
        ServerName::DnsName(name) => Ok(normalize_dns_host(name.as_ref())),
        ServerName::IpAddress(addr) => Err(PinningVerifierError::UnsupportedServerName {
            server_name: addr.to_string(),
        }),
        _ => Err(PinningVerifierError::UnsupportedServerName {
            server_name: server_name.to_str().into_owned(),
        }),
    }
}

pub(crate) fn normalize_dns_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}
```

- [ ] **Step 4: Run focused pinning tests**

Run:

```bash
cargo test -p umbrella-client transport::pinning --all-features --locked
```

Expected:

```text
test result: ok
```

- [ ] **Step 5: Commit verifier iteration**

Run:

```bash
git add crates/umbrella-client/src/transport/pinning.rs
git commit -m "client: verify production tls spki pins"
```

### Task 3: Wire Production HTTP/2 Builder

**Files:**
- Modify: `crates/umbrella-client/src/transport/http2_client.rs`
- Modify: `crates/umbrella-client/src/transport/mod.rs`

- [ ] **Step 1: Add failing builder and config tests**

In `crates/umbrella-client/src/transport/http2_client.rs`, inside the existing tests module, replace `production_client_build_stays_gated_until_tls_pinning_verifier_is_wired` with:

```rust
    #[test]
    fn production_pin_map_rejects_conflicting_pins_for_same_host() {
        let mut cfg = production_config_with_urls(vec![
            "https://shared.umbrella.example",
            "https://sealed-1.umbrella.example",
            "https://sealed-2.umbrella.example",
            "https://sealed-3.umbrella.example",
            "https://sealed-4.umbrella.example",
        ]);
        cfg.postman = endpoint("https://shared.umbrella.example", 99);

        let err = cfg.pins_by_host().unwrap_err();
        assert!(format!("{err}").contains("conflicting SPKI pins"));
    }

    #[test]
    fn production_client_builds_with_real_pinning_verifier() {
        let cfg = production_config_with_urls(vec![
            "https://sealed-0.umbrella.example",
            "https://sealed-1.umbrella.example",
            "https://sealed-2.umbrella.example",
            "https://sealed-3.umbrella.example",
            "https://sealed-4.umbrella.example",
        ]);

        let client = build_production_http2_client(Http2Config::default(), &cfg)
            .expect("production client builds when pinned config is valid");
        let clone = Arc::clone(&client);
        assert!(Arc::ptr_eq(&client, &clone));
    }
```

Add this test near the forbidden-host tests:

```rust
    #[test]
    fn production_transport_rejects_ip_literal_hosts() {
        let cfg = production_config_with_urls(vec![
            "https://192.0.2.10",
            "https://sealed-1.umbrella.example",
            "https://sealed-2.umbrella.example",
            "https://sealed-3.umbrella.example",
            "https://sealed-4.umbrella.example",
        ]);

        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("test host"));
    }
```

- [ ] **Step 2: Run red tests**

Run:

```bash
cargo test -p umbrella-client transport::http2_client::tests::production --all-features --locked
```

Expected current failure:

```text
method not found: `pins_by_host`
production_client_builds_with_real_pinning_verifier panicked because builder still returns fail-fast TLS pinning error
```

- [ ] **Step 3: Import the real verifier**

In `crates/umbrella-client/src/transport/http2_client.rs`, change the imports to:

```rust
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use reqwest::{tls, Client, ClientBuilder, Url};

use crate::error::ClientError;
use crate::transport::{
    normalize_dns_host, PinningConfig, SpkiPinningVerifier, SEALED_SERVER_COUNT,
};
```

- [ ] **Step 4: Add `pins_by_host` and stricter host checks**

Inside `impl ProductionHttp2Config`, after `validate`, add:

```rust
    /// Собрать карту `host -> pins` для TLS verifier.
    /// Build the `host -> pins` map for the TLS verifier.
    pub fn pins_by_host(&self) -> Result<BTreeMap<String, PinningConfig>, ClientError> {
        self.validate()?;
        let mut pins = BTreeMap::new();
        for endpoint in &self.sealed_servers {
            insert_endpoint_pins(&mut pins, endpoint)?;
        }
        insert_endpoint_pins(&mut pins, &self.postman)?;
        insert_endpoint_pins(&mut pins, &self.kt)?;
        insert_endpoint_pins(&mut pins, &self.call_relay)?;
        Ok(pins)
    }
```

After `validate_production_endpoint`, add:

```rust
fn insert_endpoint_pins(
    pins: &mut BTreeMap<String, PinningConfig>,
    endpoint: &PinnedServiceEndpoint,
) -> Result<(), ClientError> {
    let parsed = Url::parse(&endpoint.url)
        .map_err(|e| ClientError::Network(format!("production endpoint parse: {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| ClientError::Network("production endpoint missing host".into()))?;
    let host = normalize_dns_host(host);
    if let Some(existing) = pins.get(&host) {
        if existing != &endpoint.pins {
            return Err(ClientError::Network(format!(
                "conflicting SPKI pins for production host {host}"
            )));
        }
        return Ok(());
    }
    pins.insert(host, endpoint.pins.clone());
    Ok(())
}
```

In `is_forbidden_production_host`, add private and documentation ranges:

```rust
        || h.starts_with("10.")
        || h.starts_with("192.168.")
        || h.starts_with("172.16.")
        || h.starts_with("172.17.")
        || h.starts_with("172.18.")
        || h.starts_with("172.19.")
        || h.starts_with("172.20.")
        || h.starts_with("172.21.")
        || h.starts_with("172.22.")
        || h.starts_with("172.23.")
        || h.starts_with("172.24.")
        || h.starts_with("172.25.")
        || h.starts_with("172.26.")
        || h.starts_with("172.27.")
        || h.starts_with("172.28.")
        || h.starts_with("172.29.")
        || h.starts_with("172.30.")
        || h.starts_with("172.31.")
        || h.starts_with("192.0.2.")
        || h.starts_with("198.51.100.")
        || h.starts_with("203.0.113.")
        || h == "[::1]"
        || h.eq_ignore_ascii_case("::1")
```

- [ ] **Step 5: Share the reqwest builder path**

Replace `build_http2_client` body with:

```rust
pub fn build_http2_client(config: Http2Config) -> Result<Arc<Client>, ClientError> {
    build_http2_client_with_builder(
        config,
        ClientBuilder::new()
            .use_rustls_tls()
            .tls_version_min(tls::Version::TLS_1_3),
    )
}

fn build_http2_client_with_builder(
    config: Http2Config,
    builder: ClientBuilder,
) -> Result<Arc<Client>, ClientError> {
    let client = builder
        .http2_prior_knowledge()
        .http2_keep_alive_interval(config.http2_keepalive_interval)
        .http2_keep_alive_timeout(HTTP2_KEEPALIVE_TIMEOUT)
        .http2_keep_alive_while_idle(true)
        .connect_timeout(config.connect_timeout)
        .timeout(config.total_timeout)
        .user_agent(config.user_agent)
        .tcp_nodelay(true)
        .https_only(true)
        .build()
        .map_err(|e| ClientError::Network(format!("reqwest client build: {e}")))?;
    Ok(Arc::new(client))
}
```

- [ ] **Step 6: Replace the production fail-fast builder**

Replace `build_production_http2_client` with:

```rust
/// Проверить боевую настройку и создать HTTP/2 клиент с системной проверкой
/// сертификата плюс закреплёнными SPKI-ключами.
///
/// Validate production config and build an HTTP/2 client with platform
/// certificate verification plus SPKI pinning.
///
/// # Errors
/// - [`ClientError::Network`] если настройка похожа на тестовую.
/// - [`ClientError::Network`] если системный TLS verifier не инициализируется.
/// - [`ClientError::Network`] если `reqwest` не принимает готовый TLS backend.
pub fn build_production_http2_client(
    config: Http2Config,
    production: &ProductionHttp2Config,
) -> Result<Arc<Client>, ClientError> {
    let pins = production.pins_by_host()?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let platform_verifier = rustls_platform_verifier::Verifier::new(Arc::clone(&provider))
        .map_err(|e| ClientError::Network(format!("platform TLS verifier: {e}")))?;
    let pinning_verifier =
        SpkiPinningVerifier::new(Arc::new(platform_verifier), pins).map_err(|e| {
            ClientError::Network(format!("production SPKI pinning verifier: {e}"))
        })?;
    let tls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ClientError::Network(format!("rustls TLS 1.3 config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(pinning_verifier))
        .with_no_client_auth();

    build_http2_client_with_builder(
        config,
        ClientBuilder::new().tls_backend_preconfigured(tls_config),
    )
}
```

- [ ] **Step 7: Re-export verifier helpers for crate-internal transport**

In `crates/umbrella-client/src/transport/mod.rs`, update the pinning export:

```rust
pub use pinning::{
    extract_spki_pin_from_cert_der, normalize_dns_host, PinningConfig, PinningVerifierError,
    SpkiPin, SpkiPinningVerifier, SPKI_PIN_LEN,
};
```

- [ ] **Step 8: Run focused transport tests**

Run:

```bash
cargo test -p umbrella-client transport::http2_client --all-features --locked
cargo test -p umbrella-client transport::pinning --all-features --locked
```

Expected:

```text
test result: ok
```

- [ ] **Step 9: Commit transport wiring**

Run:

```bash
git add crates/umbrella-client/src/transport/http2_client.rs crates/umbrella-client/src/transport/mod.rs
git commit -m "client: wire production http2 tls pinning"
```

### Task 4: Public FFI Honesty After Transport Is Internally Wired

**Files:**
- Modify: `crates/umbrella-ffi/src/export/client.rs`
- Modify: `crates/umbrella-ffi/tests/production_bootstrap.rs`

- [ ] **Step 1: Tighten FFI tests so the public error is honest**

In `crates/umbrella-ffi/tests/production_bootstrap.rs`, update `assert_production_bootstrap_unavailable`:

```rust
fn assert_production_bootstrap_unavailable(err: UmbrellaError) {
    match err {
        UmbrellaError::Internal(message) => {
            assert!(message.contains("production bootstrap is not available"));
            assert!(message.contains("test constructors"));
            assert!(message.contains("production attestation verifier"));
            assert!(message.contains("mobile bridge"));
            assert!(message.contains("server integration paths"));
            assert!(
                !message.contains("TLS pinning"),
                "TLS pinning is now wired for the internal production transport"
            );
            assert!(
                !message.contains("production HTTP/2 transport gate"),
                "HTTP/2 production builder is now internally wired"
            );
        }
        other => panic!("expected Internal production-bootstrap error, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run red FFI test**

Run:

```bash
cargo test -p umbrella-ffi public_bootstrap --locked
```

Expected current failure:

```text
TLS pinning is now wired for the internal production transport
```

- [ ] **Step 3: Update FFI fail-fast message**

In `crates/umbrella-ffi/src/export/client.rs`, replace `production_bootstrap_unavailable` with:

```rust
fn production_bootstrap_unavailable() -> UmbrellaError {
    UmbrellaError::Internal(
        "production bootstrap is not available: public FFI must not use test constructors until the production attestation verifier, mobile bridge, and server integration paths are wired end to end"
            .into(),
    )
}
```

- [ ] **Step 4: Run focused FFI tests**

Run:

```bash
cargo test -p umbrella-ffi public_bootstrap --locked
cargo test -p umbrella-ffi public_bootstrap --features pq --locked
```

Expected:

```text
test result: ok
```

- [ ] **Step 5: Commit FFI honesty update**

Run:

```bash
git add crates/umbrella-ffi/src/export/client.rs crates/umbrella-ffi/tests/production_bootstrap.rs
git commit -m "ffi: keep bootstrap gated after transport pinning"
```

### Task 5: Documentation And Public Audit Truthfulness

**Files:**
- Modify: `docs/security/production-readiness-boundaries.md`
- Modify: `docs/README.md`
- Modify: `README.md`
- Modify: `scripts/audit-public-access-notices.sh`

- [ ] **Step 1: Update readiness boundary document**

In `docs/security/production-readiness-boundaries.md`, replace the closed-gates bullets for HTTP/2 and TLS pinning with this English text:

```markdown
- HTTP/2 transport: the internal production builder validates real deployment
  hosts and builds a `reqwest` client with system certificate verification plus
  SPKI pinning. This does not open public FFI bootstrap yet.
- TLS pinning: placeholder acceptance is forbidden; the production transport
  uses a real `rustls` verifier that checks the normal certificate result first
  and only then checks the configured SPKI pins.
```

Replace the Russian bullets with:

```markdown
- HTTP/2 транспорт: внутренний боевой сборщик проверяет настоящие адреса
  развёртывания и собирает `reqwest`-клиент с системной проверкой сертификата
  плюс закреплёнными SPKI-ключами. Это ещё не открывает публичный FFI-запуск.
- TLS pinning: заглушка, которая “просто проходит”, запрещена; боевой
  транспорт использует настоящий `rustls`-проверяющий, который сначала
  проверяет обычный результат сертификата и только потом сверяет закреплённые
  SPKI-ключи.
```

- [ ] **Step 2: Update public status docs**

In `docs/README.md` and `README.md`, change any sentence that says production HTTP/2 transport or TLS pinning still fail closed to:

```markdown
The internal production HTTP/2 builder now wires platform certificate
verification together with SPKI pinning. Public FFI bootstrap remains gated
until production attestation, mobile bridges, and server integration are wired
end to end.
```

Russian text:

```markdown
Внутренний боевой сборщик HTTP/2 теперь связывает системную проверку
сертификата с закреплёнными SPKI-ключами. Публичный FFI-запуск остаётся закрыт,
пока не связаны боевая attestation-проверка, мобильные мосты и серверная
интеграция.
```

- [ ] **Step 3: Update audit script requirements**

In `scripts/audit-public-access-notices.sh`, replace the readiness-boundary pinning check:

```bash
require_pattern "docs/security/production-readiness-boundaries.md" "TLS pinning"
```

with:

```bash
require_pattern "docs/security/production-readiness-boundaries.md" "system certificate verification plus SPKI pinning|системной проверкой сертификата.*SPKI"
```

Add checks for the public FFI boundary:

```bash
require_pattern "docs/README.md" "Public FFI bootstrap remains gated|Публичный FFI-запуск остаётся закрыт"
require_pattern "README.md" "Public FFI bootstrap remains gated|Публичный FFI-запуск остаётся закрыт"
```

- [ ] **Step 4: Verify docs and public notice audit**

Run:

```bash
bash scripts/audit-public-access-notices.sh
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
```

Expected:

```text
public access notices OK
Finished `dev` profile
```

- [ ] **Step 5: Commit docs**

Run:

```bash
git add docs/security/production-readiness-boundaries.md docs/README.md README.md scripts/audit-public-access-notices.sh
git commit -m "docs: mark internal tls pinning wired"
```

### Task 6: Final Verification

**Files:**
- No new source files beyond previous tasks.

- [ ] **Step 1: Run formatting**

Run:

```bash
cargo fmt --all -- --check
```

Expected:

```text
exit code 0
```

- [ ] **Step 2: Run focused security tests**

Run:

```bash
cargo test -p umbrella-client transport::pinning --all-features --locked
cargo test -p umbrella-client transport::http2_client --all-features --locked
cargo test -p umbrella-ffi public_bootstrap --locked
cargo test -p umbrella-ffi public_bootstrap --features pq --locked
```

Expected:

```text
test result: ok
```

- [ ] **Step 3: Run lint, docs, supply-chain and public audit gates**

Run:

```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
cargo deny check
bash scripts/audit-public-access-notices.sh
```

Expected:

```text
clippy exits 0
cargo doc exits 0
cargo deny exits 0
public access notices OK
```

- [ ] **Step 4: Run full release test gate**

Run:

```bash
cargo test --workspace --all-features --locked
```

Expected:

```text
test result: ok
```

- [ ] **Step 5: Confirm clean workspace**

Run:

```bash
git status --short
```

Expected:

```text

```

## Self-Review

1. Spec coverage:
   - Обычная проверка сертификата перед pinning покрыта тестом `matching_pin_does_not_bypass_inner_certificate_failure`.
   - Primary и backup pin покрыты тестами с настоящими DER-сертификатами.
   - Подмена ключа для того же имени сервера покрыта тестом `wrong_key_for_same_server_is_rejected_after_inner_accepts`.
   - Неизвестное имя сервера покрыто тестом `unknown_dns_name_is_rejected_even_when_inner_accepts`.
   - Внутренний production builder перестаёт возвращать ошибку “verifier is not wired” и покрыт тестом `production_client_builds_with_real_pinning_verifier`.
   - Публичный FFI остаётся закрыт по оставшимся воротам и больше не говорит, что TLS pinning не подключён.
   - Документы и публичный аудит обновляются в отдельной задаче.

2. Placeholder scan:
   - В плане нет запрещённых пустых маркеров, нет шагов без кода и нет ссылок на неопределённые функции.
   - Единственное намеренное будущее состояние: публичный FFI-запуск остаётся закрытым по конкретным оставшимся воротам.

3. Type consistency:
   - `SpkiPinningVerifier`, `PinningVerifierError`, `extract_spki_pin_from_cert_der` определяются в Task 2 и используются в Task 3.
   - `ProductionHttp2Config::pins_by_host` определяется в Task 3 и используется в production builder.
   - `normalize_dns_host` определяется в `pinning.rs` и реэкспортируется через `transport/mod.rs` перед использованием в `http2_client.rs`.
