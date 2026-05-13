# Protocol Compliance Hardening Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Закрыть Фазу 2 утверждённой спецификации: боевой транспорт, аттестация, звонки, мобильные мосты, серверные связки и формальные проверки не должны выглядеть готовыми без настоящих ворот безопасности.

**Architecture:** Внедрение идёт четырьмя независимыми срезами. Каждый срез сначала доказывает текущий обход или ложное заявление тестом/командой, затем добавляет fail-closed границу, обновляет документы и коммитится отдельно. Реальный боевой путь открывается только там, где проверка покрыта тестом в этом репозитории; иначе публичный путь остаётся закрытым понятной ошибкой.

**Tech Stack:** Rust workspace, Cargo locked tests, reqwest 0.13, rustls 0.23, UniFFI, shell audit scripts, Markdown docs, formal verification scripts.

---

## Source Of Truth

- `docs/WORKING_RULES.md`
- `docs/superpowers/specs/2026-05-13-protocol-compliance-hardening-design.md`
- `docs/superpowers/specs/2026-05-13-protocol-compliance-hardening-phase2-design.md`
- `README.md`
- `docs/README.md`
- `docs/security/release-manifest-v1.0.0.txt`
- `.local-private/specs/SPEC-05-OPRF-CONTACT-DISCOVERY.md`
- `.local-private/specs/SPEC-06-CALLS-AND-IP-PRIVACY.md`
- `.local-private/specs/SPEC-11-MULTI-DEVICE.md`
- `.local-private/specs/SPEC-12-BACKUP.md`
- `crates/umbrella-client/src/transport/pinning.rs`
- `crates/umbrella-client/src/transport/http2_client.rs`
- `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`
- `crates/umbrella-oprf/src/attestation.rs`
- `crates/umbrella-ffi/src/export/client.rs`
- `scripts/audit-public-access-notices.sh`

## File Structure

- Modify `crates/umbrella-client/src/transport/pinning.rs`: derive equality for pin configs so production endpoint configs can be compared in tests.
- Modify `crates/umbrella-client/src/transport/http2_client.rs`: add typed production transport config, strict URL validation, and a gated production builder.
- Modify `crates/umbrella-client/src/transport/mod.rs`: re-export new transport config types.
- Modify `crates/umbrella-backup/src/error.rs`: add a precise error for unavailable production attestation verification.
- Modify `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`: split signature-only verification from production policy verification.
- Modify `crates/umbrella-oprf/src/error.rs`: add the matching production attestation error.
- Modify `crates/umbrella-oprf/src/attestation.rs`: add OPRF production policy verification.
- Modify `crates/umbrella-ffi/src/export/client.rs`: keep public bootstrap fail-fast, but make the error name the Phase 2 gates explicitly.
- Modify `crates/umbrella-ffi/tests/production_bootstrap.rs`: verify the public error mentions transport and production attestation gates.
- Create `docs/security/production-readiness-boundaries.md`: public table of which paths are test-only, scaffolded, or production-gated.
- Modify `README.md`, `docs/README.md`, `docs/security/release-manifest-v1.0.0.txt`: align public claims with Phase 2 gates.
- Modify `scripts/audit-public-access-notices.sh`: require the new truthful production-gate notices.
- Create `docs/audits/formal-lint-status-2026-05-13.md`: record actual status of formal and local lint commands.

## Implementation Tasks

### 1. Add Production Transport Gates

**Files:**
- Modify: `crates/umbrella-client/src/transport/pinning.rs`
- Modify: `crates/umbrella-client/src/transport/http2_client.rs`
- Modify: `crates/umbrella-client/src/transport/mod.rs`

- [ ] **Step 1: Re-read the transport source and current tests**

Run:

```bash
sed -n '1,260p' crates/umbrella-client/src/transport/pinning.rs
sed -n '1,280p' crates/umbrella-client/src/transport/http2_client.rs
cargo test -p umbrella-client transport::http2_client --locked
```

Expected:

```text
test result: ok
```

- [ ] **Step 2: Add failing production transport tests**

In `crates/umbrella-client/src/transport/http2_client.rs`, inside the existing `#[cfg(test)] mod tests`, add these tests after `build_http2_client_accepts_custom_user_agent`:

```rust
    fn pin(byte: u8) -> PinningConfig {
        PinningConfig::single(SpkiPin::from_bytes([byte; SPKI_PIN_LEN]))
    }

    fn endpoint(url: &str, byte: u8) -> PinnedServiceEndpoint {
        PinnedServiceEndpoint::new(url.to_string(), pin(byte))
    }

    fn production_config_with_urls(sealed: Vec<&str>) -> ProductionHttp2Config {
        ProductionHttp2Config {
            sealed_servers: sealed
                .into_iter()
                .enumerate()
                .map(|(idx, url)| endpoint(url, (idx + 1) as u8))
                .collect(),
            postman: endpoint("https://postman.umbrella.example", 11),
            kt: endpoint("https://kt.umbrella.example", 12),
            call_relay: endpoint("https://relay.umbrella.example", 13),
        }
    }

    #[test]
    fn production_transport_rejects_http_url() {
        let cfg = production_config_with_urls(vec![
            "http://sealed-0.umbrella.example",
            "https://sealed-1.umbrella.example",
            "https://sealed-2.umbrella.example",
            "https://sealed-3.umbrella.example",
            "https://sealed-4.umbrella.example",
        ]);

        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("must use https"));
    }

    #[test]
    fn production_transport_rejects_test_hosts() {
        let cfg = production_config_with_urls(vec![
            "https://localhost",
            "https://sealed-1.umbrella.example",
            "https://sealed-2.umbrella.example",
            "https://sealed-3.umbrella.example",
            "https://sealed-4.umbrella.example",
        ]);

        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("test host"));
    }

    #[test]
    fn production_transport_rejects_wrong_sealed_server_count() {
        let cfg = production_config_with_urls(vec![
            "https://sealed-0.umbrella.example",
            "https://sealed-1.umbrella.example",
            "https://sealed-2.umbrella.example",
            "https://sealed-3.umbrella.example",
        ]);

        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("exactly 5 pinned sealed servers"));
    }

    #[test]
    fn production_transport_validation_accepts_realistic_pinned_https_config() {
        let cfg = production_config_with_urls(vec![
            "https://sealed-0.umbrella.example",
            "https://sealed-1.umbrella.example",
            "https://sealed-2.umbrella.example",
            "https://sealed-3.umbrella.example",
            "https://sealed-4.umbrella.example",
        ]);

        cfg.validate().expect("pinned https config validates");
    }

    #[test]
    fn production_client_build_stays_gated_until_tls_pinning_verifier_is_wired() {
        let cfg = production_config_with_urls(vec![
            "https://sealed-0.umbrella.example",
            "https://sealed-1.umbrella.example",
            "https://sealed-2.umbrella.example",
            "https://sealed-3.umbrella.example",
            "https://sealed-4.umbrella.example",
        ]);

        let err = build_production_http2_client(Http2Config::default(), &cfg).unwrap_err();
        let message = format!("{err}");
        assert!(message.contains("production TLS pinning verifier is not wired"));
    }
```

- [ ] **Step 3: Run the new tests and confirm red signal**

Run:

```bash
cargo test -p umbrella-client production_transport --locked
```

Expected current failure:

```text
cannot find type `PinnedServiceEndpoint`
cannot find type `ProductionHttp2Config`
cannot find function `build_production_http2_client`
```

- [ ] **Step 4: Derive equality for pin configs**

In `crates/umbrella-client/src/transport/pinning.rs`, change the `PinningConfig` derive:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinningConfig {
```

- [ ] **Step 5: Add production transport config and validation**

In `crates/umbrella-client/src/transport/http2_client.rs`, update the imports:

```rust
use reqwest::{tls, Client, ClientBuilder, Url};

use crate::error::ClientError;
use crate::transport::{PinningConfig, SpkiPin, SPKI_PIN_LEN, SEALED_SERVER_COUNT};
```

Then add this code after `impl Default for Http2Config`:

```rust
/// Боевой endpoint с обязательным закреплением ключа сертификата.
/// Production endpoint with mandatory certificate-key pinning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedServiceEndpoint {
    /// URL сервиса. Service URL.
    pub url: String,
    /// Основной и запасной закреплённые ключи. Primary and backup pins.
    pub pins: PinningConfig,
}

impl PinnedServiceEndpoint {
    /// Создать endpoint с уже заданными pin-ами.
    /// Construct an endpoint with explicit pins.
    #[must_use]
    pub fn new(url: String, pins: PinningConfig) -> Self {
        Self { url, pins }
    }
}

/// Боевая настройка HTTP/2 транспорта.
/// Production HTTP/2 transport configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionHttp2Config {
    /// Ровно пять запечатанных серверов. Exactly five Sealed Servers.
    pub sealed_servers: Vec<PinnedServiceEndpoint>,
    /// Почтовый сервис. Blind postman service.
    pub postman: PinnedServiceEndpoint,
    /// Журнал ключей. Key-transparency service.
    pub kt: PinnedServiceEndpoint,
    /// Релей звонков. Call relay service.
    pub call_relay: PinnedServiceEndpoint,
}

impl ProductionHttp2Config {
    /// Проверить, что боевая настройка не похожа на стенд.
    /// Validate that production config is not a test setup.
    pub fn validate(&self) -> Result<(), ClientError> {
        if self.sealed_servers.len() != SEALED_SERVER_COUNT {
            return Err(ClientError::Network(format!(
                "production transport requires exactly {SEALED_SERVER_COUNT} pinned sealed servers, got {}",
                self.sealed_servers.len()
            )));
        }

        for (idx, endpoint) in self.sealed_servers.iter().enumerate() {
            validate_production_endpoint(&format!("sealed_server_urls[{idx}]"), endpoint)?;
        }
        validate_production_endpoint("postman_url", &self.postman)?;
        validate_production_endpoint("kt_url", &self.kt)?;
        validate_production_endpoint("call_relay_url", &self.call_relay)?;
        Ok(())
    }
}

fn validate_production_endpoint(
    role: &str,
    endpoint: &PinnedServiceEndpoint,
) -> Result<(), ClientError> {
    let parsed = Url::parse(&endpoint.url)
        .map_err(|e| ClientError::Network(format!("{role} parse: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(ClientError::Network(format!(
            "{role} must use https in production"
        )));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| ClientError::Network(format!("{role} missing host")))?;
    if is_forbidden_production_host(host) {
        return Err(ClientError::Network(format!(
            "{role} uses test host {host}; production transport requires real deployment hosts"
        )));
    }
    Ok(())
}

fn is_forbidden_production_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h.is_empty()
        || h == "localhost"
        || h.ends_with(".localhost")
        || h == "127.0.0.1"
        || h == "0.0.0.0"
        || h == "::1"
        || h.ends_with(".invalid")
        || h.ends_with(".example.invalid")
}
```

- [ ] **Step 6: Add a gated production HTTP/2 builder**

In `crates/umbrella-client/src/transport/http2_client.rs`, after `build_http2_client`, add:

```rust
/// Проверить боевую настройку и создать HTTP/2 клиент только когда
/// `rustls`-проверяющий с закреплением сертификатов связан до конца.
///
/// Сейчас функция намеренно отказывает после валидации: публичный FFI
/// bootstrap остаётся закрытым, пока `ServerCertVerifier` с SPKI pinning не
/// будет покрыт настоящим тестом.
///
/// Validate production config and build an HTTP/2 client only after the
/// `rustls` certificate verifier with SPKI pinning is wired end to end.
///
/// # Errors
/// - [`ClientError::Network`] если настройка похожа на тестовую.
/// - [`ClientError::Network`] с fail-fast причиной, пока production verifier
///   не связан.
pub fn build_production_http2_client(
    _config: Http2Config,
    production: &ProductionHttp2Config,
) -> Result<Arc<Client>, ClientError> {
    production.validate()?;
    Err(ClientError::Network(
        "production TLS pinning verifier is not wired in this crate; public bootstrap remains gated"
            .into(),
    ))
}
```

- [ ] **Step 7: Replace deprecated TLS method**

In `build_http2_client`, change:

```rust
.min_tls_version(tls::Version::TLS_1_3)
```

to:

```rust
.tls_version_min(tls::Version::TLS_1_3)
```

- [ ] **Step 8: Re-export production transport types**

In `crates/umbrella-client/src/transport/mod.rs`, change the HTTP/2 re-export:

```rust
pub use http2_client::{
    build_http2_client, build_production_http2_client, Http2Config, PinnedServiceEndpoint,
    ProductionHttp2Config,
};
```

- [ ] **Step 9: Verify focused transport tests**

Run:

```bash
cargo test -p umbrella-client production_transport --locked
cargo test -p umbrella-client transport::http2_client --locked
```

Expected final result for both:

```text
test result: ok
```

- [ ] **Step 10: Commit transport gate**

Run:

```bash
git add crates/umbrella-client/src/transport/pinning.rs crates/umbrella-client/src/transport/http2_client.rs crates/umbrella-client/src/transport/mod.rs
git commit -m "client: gate production http2 transport"
```

### 2. Add Production Attestation Policy Gates

**Files:**
- Modify: `crates/umbrella-backup/src/error.rs`
- Modify: `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`
- Modify: `crates/umbrella-oprf/src/error.rs`
- Modify: `crates/umbrella-oprf/src/attestation.rs`

- [ ] **Step 1: Reproduce current signature-only behavior**

Run:

```bash
cargo test -p umbrella-backup seal_and_verify_happy_path --locked
cargo test -p umbrella-oprf seal_and_verify_happy_path --locked
```

Expected:

```text
test result: ok
```

This confirms the current helper verifies signatures but does not represent full production attestation verification.

- [ ] **Step 2: Add failing cloud-unwrap production policy tests**

In `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`, inside the existing tests module, add after `seal_and_verify_happy_path`:

```rust
    #[test]
    fn production_policy_rejects_testing_platform_even_with_valid_signature() {
        let (sk, vk) = make_device_keypair();
        let p = TestingAttestationProvider::default();
        let req = seal_unwrap_request(
            sample_r(),
            sample_chat(),
            [0x22u8; ED25519_PUB_LEN],
            1_700_000_000_000u64,
            fresh_nonce(),
            &p,
            |payload| Ok(sign_with(&sk, payload)),
            vk.to_bytes(),
        )
        .unwrap();

        verify_signed_unwrap_request(&req).expect("signature-only helper remains test-compatible");
        let err = verify_signed_unwrap_request_for_production(&req).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn production_policy_fails_closed_for_ios_until_real_verifier_is_wired() {
        let (sk, vk) = make_device_keypair();
        let attestation = PlatformAttestation::new(Platform::IOs, b"ios-shaped-token").unwrap();
        let nonce = fresh_nonce();
        let canonical = canonical_signing_input(
            &sample_r(),
            &sample_chat(),
            &[0x22u8; ED25519_PUB_LEN],
            1_700_000_000_000u64,
            &nonce,
            &attestation,
        );
        let req = SignedUnwrapRequest {
            ephemeral_r: sample_r(),
            chat_id: sample_chat(),
            recipient_device_pubkey: [0x22u8; ED25519_PUB_LEN],
            timestamp_unix_millis: 1_700_000_000_000u64,
            server_nonce: nonce,
            attestation,
            device_signature: sign_with(&sk, &canonical),
            device_pubkey: vk.to_bytes(),
        };

        let err = verify_signed_unwrap_request_for_production(&req).unwrap_err();
        assert!(matches!(
            err,
            BackupError::ProductionAttestationVerifierUnavailable { .. }
        ));
    }
```

- [ ] **Step 3: Add failing OPRF production policy tests**

In `crates/umbrella-oprf/src/attestation.rs`, inside the existing tests module, add after the happy signature verification test:

```rust
    #[test]
    fn production_policy_rejects_testing_platform_even_with_valid_signature() {
        let (sk, vk) = make_device_keypair();
        let input = OprfInput::new(b"+15550101010").unwrap();
        let (blinded, _state) = blind(input, &mut OsRng).unwrap();
        let provider = TestingAttestationProvider::default();
        let req = seal_request(
            blinded,
            &provider,
            fresh_nonce(),
            |payload| Ok(sign_with(&sk, payload)),
            vk.to_bytes(),
        )
        .unwrap();

        verify_signed_request(&req).expect("signature-only helper remains test-compatible");
        let err = verify_signed_request_for_production(&req).unwrap_err();
        assert!(matches!(err, OprfError::CryptoVerificationFailed));
    }
```

- [ ] **Step 4: Run red tests**

Run:

```bash
cargo test -p umbrella-backup production_policy --locked
cargo test -p umbrella-oprf production_policy --locked
```

Expected current failure:

```text
cannot find function `verify_signed_unwrap_request_for_production`
cannot find function `verify_signed_request_for_production`
```

- [ ] **Step 5: Add backup production attestation error**

In `crates/umbrella-backup/src/error.rs`, after `InvalidAttestationShape`, add:

```rust
    /// Боевой проверяющий код для платформенного attestation ещё не связан.
    /// Production platform-attestation verifier is not wired yet.
    #[error("production attestation verifier unavailable for platform tag {platform_tag:#x}")]
    ProductionAttestationVerifierUnavailable {
        /// Platform tag из wire-format. Platform tag from wire format.
        platform_tag: u8,
    },
```

- [ ] **Step 6: Add cloud-unwrap production verifier**

In `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`, after `verify_signed_unwrap_request`, add:

```rust
/// Боевая policy-проверка `SignedUnwrapRequest`.
///
/// Сначала проверяет device-signature, затем запрещает тестовую платформу.
/// Реальная проверка iOS/Android/Web token-ов должна быть связана отдельным
/// серверным verifier-ом; до этого боевой путь fail-closed.
///
/// Production policy verification for `SignedUnwrapRequest`.
///
/// # Errors
/// - [`BackupError::CryptoVerificationFailed`] для `Platform::Testing`.
/// - [`BackupError::ProductionAttestationVerifierUnavailable`] для настоящих
///   платформ, пока их verifier не связан.
pub fn verify_signed_unwrap_request_for_production(
    req: &SignedUnwrapRequest,
) -> Result<(), BackupError> {
    verify_signed_unwrap_request(req)?;
    match req.attestation.platform {
        Platform::Testing => Err(BackupError::CryptoVerificationFailed),
        Platform::IOs | Platform::Android | Platform::Web => {
            Err(BackupError::ProductionAttestationVerifierUnavailable {
                platform_tag: req.attestation.platform.tag(),
            })
        }
    }
}
```

- [ ] **Step 7: Add OPRF production attestation error**

In `crates/umbrella-oprf/src/error.rs`, after `InvalidAttestationShape`, add:

```rust
    /// Боевой проверяющий код для платформенного attestation ещё не связан.
    /// Production platform-attestation verifier is not wired yet.
    #[error("production attestation verifier unavailable for platform tag {platform_tag:#x}")]
    ProductionAttestationVerifierUnavailable {
        /// Platform tag из wire-format. Platform tag from wire format.
        platform_tag: u8,
    },
```

- [ ] **Step 8: Add OPRF production verifier**

In `crates/umbrella-oprf/src/attestation.rs`, after `verify_signed_request`, add:

```rust
/// Боевая policy-проверка `SignedOprfRequest`.
///
/// Signature-only verification is not enough for production contact
/// discovery. Testing attestation is rejected, and real platform token
/// verification remains fail-closed until the verifier is wired.
pub fn verify_signed_request_for_production(req: &SignedOprfRequest) -> Result<(), OprfError> {
    verify_signed_request(req)?;
    match req.attestation.platform {
        Platform::Testing => Err(OprfError::CryptoVerificationFailed),
        Platform::IOs | Platform::Android | Platform::Web => {
            Err(OprfError::ProductionAttestationVerifierUnavailable {
                platform_tag: req.attestation.platform.tag(),
            })
        }
    }
}
```

- [ ] **Step 9: Run focused attestation policy tests**

Run:

```bash
cargo test -p umbrella-backup production_policy --locked
cargo test -p umbrella-oprf production_policy --locked
```

Expected:

```text
test result: ok
```

- [ ] **Step 10: Run related package tests**

Run:

```bash
cargo test -p umbrella-backup --all-features --locked
cargo test -p umbrella-oprf --all-features --locked
```

Expected:

```text
test result: ok
```

- [ ] **Step 11: Commit attestation gates**

Run:

```bash
git add crates/umbrella-backup/src/error.rs crates/umbrella-backup/src/cloud_wrap/signed_request.rs crates/umbrella-oprf/src/error.rs crates/umbrella-oprf/src/attestation.rs
git commit -m "attestation: fail closed for production test platform"
```

### 3. Add Public Readiness Boundaries For FFI, Calls, Mobile, And Servers

**Files:**
- Modify: `crates/umbrella-ffi/src/export/client.rs`
- Modify: `crates/umbrella-ffi/tests/production_bootstrap.rs`
- Create: `docs/security/production-readiness-boundaries.md`
- Modify: `README.md`
- Modify: `docs/README.md`
- Modify: `docs/security/release-manifest-v1.0.0.txt`
- Modify: `scripts/audit-public-access-notices.sh`

- [ ] **Step 1: Add stricter FFI error test**

In `crates/umbrella-ffi/tests/production_bootstrap.rs`, update `assert_production_bootstrap_unavailable` so it requires the Phase 2 gates:

```rust
fn assert_production_bootstrap_unavailable(err: UmbrellaError) {
    match err {
        UmbrellaError::Internal(message) => {
            assert!(message.contains("production bootstrap is not available"));
            assert!(message.contains("test constructors"));
            assert!(message.contains("production attestation verifier"));
            assert!(message.contains("mobile bridge"));
            assert!(message.contains("server integration paths"));
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
assertion failed: message.contains("production attestation verifier")
```

- [ ] **Step 3: Update public FFI bootstrap error**

In `crates/umbrella-ffi/src/export/client.rs`, replace `production_bootstrap_unavailable` with:

```rust
fn production_bootstrap_unavailable() -> UmbrellaError {
    UmbrellaError::Internal(
        "production bootstrap is not available: public FFI must not use test constructors until the production attestation verifier, mobile bridge, and server integration paths are wired end to end"
            .into(),
    )
}
```

- [ ] **Step 4: Create public readiness boundary document**

Create `docs/security/production-readiness-boundaries.md`:

```markdown
# Границы боевой готовности

Дата: 2026-05-13

Этот документ фиксирует, какие публичные пути являются боевыми, какие являются
стендами, а какие закрыты до полной связки.

| Участок | Текущий статус | Что разрешено | Что запрещено |
|---|---|---|---|
| Публичный FFI bootstrap | Закрыт строгой ошибкой | Проверка входных данных и понятный отказ | Возвращать тестовый клиент как боевой |
| HTTP/2 транспорт | Есть общий клиент и проверка формы боевой настройки | Тестовые стенды и подготовка production config | Создавать боевой клиент без TLS pinning verifier |
| Закрепление сертификатов | Типы pin-ов есть, боевой verifier ещё не открыт | Проверять pin-ы как данные | Утверждать, что TLS pinning уже защищает публичный клиент |
| Cloud unwrap attestation | Signature-only helper и production policy gate | Тестировать подпись и форму токена | Принимать `Platform::Testing` в боевом пути |
| OPRF attestation | Signature-only helper и production policy gate | Тестировать подпись и форму токена | Принимать `Platform::Testing` в боевом пути |
| Звонки | Криптографические и локальные сценарии | Проверять SFrame, fingerprint, anti-replay и локальные модели | Называть полный публичный звонковый путь готовым без серверной связки |
| Kotlin/Swift мосты | Обёртки и сборочные пути | Проверять генерацию и сборку привязок | Обещать боевой запуск, когда Rust FFI возвращает fail-fast |
| Серверные связки | В этом репозитории не развёрнуты | Описывать контракт и тестировать локальные wire-форматы | Подменять серверную инфраструктуру mock-ом и называть это боем |
| Формальные проверки и местные правила | Статус фиксируется отдельным аудитом | Запускать команды и записывать результат | Говорить "проверено", если команда не прошла сейчас |

Боевой путь можно открыть только после отдельного плана, где каждая строка
получит настоящий тест или проверяемую внешнюю интеграцию.
```

- [ ] **Step 5: Update public docs**

In `README.md` and `docs/README.md`, add a short paragraph near the current status section:

```markdown
Phase 2 hardening is active: public client bootstrap, production HTTP/2
transport, TLS pinning, production attestation verification, mobile bridges,
call integration, and server integration are treated as gated until their
required checks are wired end to end. See
`docs/security/production-readiness-boundaries.md`.
```

Russian text:

```markdown
Фаза 2 приведения к документам активна: публичный запуск клиента, боевой
HTTP/2 транспорт, закрепление сертификатов, боевая проверка аттестации,
мобильные мосты, звонки и серверные связки считаются закрытыми воротами, пока
их обязательные проверки не связаны до конца. См.
`docs/security/production-readiness-boundaries.md`.
```

In `docs/security/release-manifest-v1.0.0.txt`, add:

```text
Phase 2 status: production bootstrap, production transport, TLS pinning,
production attestation verification, mobile bridges, call integration, and
server integration are gated until their required checks are wired end to end.
```

- [ ] **Step 6: Strengthen public notice audit**

In `scripts/audit-public-access-notices.sh`, after the existing `docs/security/release-manifest-v1.0.0.txt` check, add:

```bash
require_pattern "README.md" "Phase 2 hardening is active|Фаза 2 приведения к документам активна"
require_pattern "docs/README.md" "Phase 2 hardening is active|Фаза 2 приведения к документам активна"
require_pattern "docs/security/release-manifest-v1.0.0.txt" "Phase 2 status"
require_pattern "docs/security/production-readiness-boundaries.md" "Platform::Testing|TLS pinning|FFI bootstrap"
```

- [ ] **Step 7: Verify public readiness checks**

Run:

```bash
cargo test -p umbrella-ffi public_bootstrap --locked
cargo test -p umbrella-ffi public_bootstrap --features pq --locked
bash scripts/audit-public-access-notices.sh
```

Expected:

```text
test result: ok
public access notices OK
```

- [ ] **Step 8: Commit public readiness boundaries**

Run:

```bash
git add crates/umbrella-ffi/src/export/client.rs crates/umbrella-ffi/tests/production_bootstrap.rs README.md docs/README.md docs/security/release-manifest-v1.0.0.txt docs/security/production-readiness-boundaries.md scripts/audit-public-access-notices.sh
git commit -m "docs: gate public production readiness claims"
```

### 4. Audit Formal And Local Lint Claims

**Files:**
- Create: `docs/audits/formal-lint-status-2026-05-13.md`
- Modify: `README.md`
- Modify: `docs/README.md`

- [ ] **Step 1: Prepare an evidence directory**

Run:

```bash
mkdir -p target/phase2-formal-lint-evidence
```

Expected:

```text
exit code 0
```

- [ ] **Step 2: Run formatting and clippy**

Run each command separately and store its output:

```bash
set +e
cargo fmt --all -- --check > target/phase2-formal-lint-evidence/fmt.out 2>&1
echo $? > target/phase2-formal-lint-evidence/fmt.exit
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings > target/phase2-formal-lint-evidence/clippy.out 2>&1
echo $? > target/phase2-formal-lint-evidence/clippy.exit
set -e
```

Expected handling:

```text
If a command exits 0, record "Проходит" and the final success line.
If a command exits nonzero, do not hide it; record "Красная" and the first actionable error line.
```

- [ ] **Step 3: Run docs and formal commands**

Run each command separately and store its output:

```bash
set +e
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked > target/phase2-formal-lint-evidence/doc.out 2>&1
echo $? > target/phase2-formal-lint-evidence/doc.exit
bash scripts/verify-formal-production-readiness.sh > target/phase2-formal-lint-evidence/formal-production-readiness.out 2>&1
echo $? > target/phase2-formal-lint-evidence/formal-production-readiness.exit
bash scripts/verify-proverif-models.sh > target/phase2-formal-lint-evidence/proverif.out 2>&1
echo $? > target/phase2-formal-lint-evidence/proverif.exit
bash scripts/verify-tamarin-models.sh > target/phase2-formal-lint-evidence/tamarin.out 2>&1
echo $? > target/phase2-formal-lint-evidence/tamarin.exit
set -e
```

Expected handling:

```text
If external tools are missing, record the missing tool as the root cause.
If a model fails, record the failing model and command.
If a command passes, record "Проходит".
```

- [ ] **Step 4: Run local lint command**

Run and store the output:

```bash
set +e
DYLINT_RUSTFLAGS="-D warnings" cargo dylint --all --path crates/umbrella-lints --workspace -- --ignore-rust-version --all-targets --all-features --locked > target/phase2-formal-lint-evidence/dylint.out 2>&1
echo $? > target/phase2-formal-lint-evidence/dylint.exit
set -e
```

Expected handling:

```text
If cargo-dylint or dylint-link is missing or version-conflicted, record that exact root cause.
If lint findings appear, record the first finding file and lint name.
If it passes, record "Проходит".
```

- [ ] **Step 5: Generate the status document from actual command results**

Create `docs/audits/formal-lint-status-2026-05-13.md` only after Steps 2-4 are complete by running this generator:

```bash
row() {
  local command="$1"
  local stem="$2"
  local next_if_red="$3"
  local exit_code
  local first_line
  local status
  local next

  exit_code="$(cat "target/phase2-formal-lint-evidence/${stem}.exit")"
  first_line="$(grep -m 1 -E '[^[:space:]]' "target/phase2-formal-lint-evidence/${stem}.out" || true)"
  if [[ -z "$first_line" ]]; then
    first_line="нет вывода"
  fi

  if [[ "$exit_code" == "0" ]]; then
    status="Проходит"
    next="Оставить как текущие ворота выпуска"
  else
    status="Красная"
    next="$next_if_red"
  fi

  printf '| `%s` | %s | exit %s; %s | %s |\n' "$command" "$status" "$exit_code" "$first_line" "$next"
}

{
  printf '# Статус формальных проверок и местных правил\n\n'
  printf 'Дата: 2026-05-13\n\n'
  printf 'Этот документ фиксирует фактический запуск команд, которые README называет\n'
  printf 'формальными проверками или местными правилами кода.\n\n'
  printf '| Команда | Статус | Фактический результат | Следующий шаг |\n'
  printf '|---|---|---|---|\n'
  row 'cargo fmt --all -- --check' fmt 'Исправить форматирование и повторить команду'
  row 'cargo clippy --workspace --all-targets --all-features --locked -- -D warnings' clippy 'Исправить lint или вынести конкретный пункт в утверждённый риск'
  row 'RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked' doc 'Исправить rustdoc-предупреждение и повторить команду'
  row 'bash scripts/verify-formal-production-readiness.sh' formal-production-readiness 'Указать недостающий инструмент или failing model и завести отдельный план'
  row 'bash scripts/verify-proverif-models.sh' proverif 'Указать недостающий ProVerif или failing model и завести отдельный план'
  row 'bash scripts/verify-tamarin-models.sh' tamarin 'Указать недостающий Tamarin или failing model и завести отдельный план'
  row 'DYLINT_RUSTFLAGS="-D warnings" cargo dylint --all --path crates/umbrella-lints --workspace -- --ignore-rust-version --all-targets --all-features --locked' dylint 'Указать конфликт версии, недостающий инструмент или первый lint finding'
  printf '\nКоманда считается текущими воротами выпуска только если её строка имеет статус `Проходит`.\n'
} > docs/audits/formal-lint-status-2026-05-13.md
```

- [ ] **Step 6: Update README status wording**

In `README.md` and `docs/README.md`, update the formal-checks section with:

```markdown
The current status of formal verification and local lint gates is recorded in
`docs/audits/formal-lint-status-2026-05-13.md`. A command is a current release
gate only when that file says it passes for this repository state.
```

Russian text:

```markdown
Текущий статус формальных проверок и местных правил кода записан в
`docs/audits/formal-lint-status-2026-05-13.md`. Команда считается текущими
воротами выпуска только если в этом файле указано, что она проходит для этого
состояния репозитория.
```

- [ ] **Step 7: Verify no unfilled status remains**

Run:

```bash
rg -n "команда не вывела текста|No libraries were found|--manifest-path crates/umbrella-lints" docs/audits/formal-lint-status-2026-05-13.md
```

Expected:

```text
No matches unless a command genuinely produced no output. If there is a match,
replace that row's factual result with "exit N; output отсутствует" and keep
the actual exit code.
```

- [ ] **Step 8: Commit formal and lint truthfulness**

Run:

```bash
git add docs/audits/formal-lint-status-2026-05-13.md README.md docs/README.md
git commit -m "docs: record formal and lint gate status"
```

### 5. Final Workspace Verification

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

- [ ] **Step 2: Run focused Phase 2 tests**

Run:

```bash
cargo test -p umbrella-client production_transport --locked
cargo test -p umbrella-backup production_policy --locked
cargo test -p umbrella-oprf production_policy --locked
cargo test -p umbrella-ffi public_bootstrap --locked
cargo test -p umbrella-ffi public_bootstrap --features pq --locked
```

Expected:

```text
test result: ok
```

- [ ] **Step 3: Run documentation and public notice gates**

Run:

```bash
bash scripts/audit-public-access-notices.sh
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
```

Expected:

```text
public access notices OK
exit code 0
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

## Notes For Implementers

- Do not open public production bootstrap in this phase. It remains fail-fast until transport pinning, production attestation verification, mobile bridges, and server integrations are wired end to end.
- Do not remove test constructors or test providers. Rename and gate them clearly instead.
- Do not treat missing external formal tools as success. Record the missing tool and update claims.
- Keep public Rust interface comments bilingual where behavior changes.
- Each task must commit before moving to the next task.
