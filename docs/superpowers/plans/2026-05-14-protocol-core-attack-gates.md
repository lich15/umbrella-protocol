# Protocol Core Attack Gates Implementation Plan

> **Historical note (2026-05-20 reconciliation):** This plan documents the pre-v3.0.0 implementation track for protocol core attack gates. The work has been superseded by:
> - Pass 5 ship-blocker closure + `docs/security/protocol-core-attack-gates.md`
>
> The unchecked task boxes below are planning text, not the current active task list. Current status lives в `docs/security/current-status.md` + `docs/audits/ROUND-1-TO-7-SUMMARY.md`.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** довести ядро Umbrella Protocol до честных боевых атакующих ворот: повтор, подмена, откат, плохой адрес, тестовая платформа и смешение версий либо отвергаются кодом, либо явно записаны как неоткрытая граница выпуска.

**Architecture:** изменения остаются внутри Umbrella Protocol и не трогают `/Users/daniel/Documents/Projects/Messenger/rust_1mlrd`. Главная новая граница: боевые контексты OPRF и cloud-backup получают обязательный тип защиты от повторного использования серверного вызова. Остальные крейты усиливаются точечными отрицательными тестами и общей матрицей доказательств.

**Tech Stack:** Rust, Cargo locked gates, Ed25519, WebAuthn, rustls SPKI pinning, Ristretto255 OPRF/backup, Sealed Sender V1/V2, Markdown-документация на русском и английском.

---

## File Structure

- Modify: `crates/umbrella-oprf/src/error.rs` — добавить точную ошибку повтора серверного вызова.
- Modify: `crates/umbrella-oprf/src/attestation.rs` — добавить обязательный `ProductionNonceReplayGuard`, подключить его к `ProductionOprfVerificationContext`, покрыть реальным тестом повтора.
- Modify: `crates/umbrella-oprf/src/lib.rs` — переэкспортировать новый боевой тип.
- Modify: `crates/umbrella-backup/src/error.rs` — добавить точную ошибку повтора серверного вызова.
- Modify: `crates/umbrella-backup/src/cloud_wrap/signed_request.rs` — добавить обязательный `ProductionNonceReplayGuard`, подключить его к `ProductionUnwrapVerificationContext`, покрыть реальным тестом повтора.
- Modify: `crates/umbrella-backup/src/cloud_wrap/mod.rs` — переэкспортировать новый боевой тип.
- Modify: `crates/umbrella-client/src/transport/http2_client.rs` — расширить запрет боевых адресов на link-local, CGNAT, IPv6 local, documentation ranges через парсинг IP.
- Modify: `crates/umbrella-platform-verifier/src/web.rs` — добавить отрицательный WebAuthn-тест на несовпадение публичного ключа устройства и зарегистрированного ключа.
- Create: `docs/security/protocol-core-attack-gates.md` — публичная матрица “атака → проверка → статус”.
- Modify: `docs/security/current-status.md` — обновить дату и короткий статус Фазы 3А.
- Modify: `docs/security/production-readiness-boundaries.md` — добавить границу по повтору серверных вызовов и матрице атак.
- Modify: `docs/README.md`, `README.md` — добавить ссылку на новую матрицу.
- Create: `scripts/audit-protocol-core-attack-gates.sh` — локальный аудит, который не даёт убрать ключевые ворота.
- Modify: `scripts/audit-public-access-notices.sh` — требовать ссылку на новую матрицу.

---

### Task 1: OPRF Production Nonce Replay Gate

**Files:**
- Modify: `crates/umbrella-oprf/src/error.rs`
- Modify: `crates/umbrella-oprf/src/attestation.rs`
- Modify: `crates/umbrella-oprf/src/lib.rs`

- [ ] **Step 1: Write the failing replay test**

In `crates/umbrella-oprf/src/attestation.rs`, inside the existing `#[cfg(test)] mod tests`, add these helpers after `TestOnlySuccessVerifier`:

```rust
#[derive(Debug, Default)]
struct AcceptingAndroidVerifier;

impl ProductionPlatformVerifier for AcceptingAndroidVerifier {
    fn kind(&self) -> PlatformVerifierKind {
        PlatformVerifierKind::AndroidPlayIntegrity
    }

    fn verify_platform_attestation(
        &self,
        input: PlatformVerificationInput<'_>,
    ) -> Result<(), OprfError> {
        assert_eq!(input.platform, Platform::Android);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct RecordingNonceReplayGuard {
    seen: std::sync::Mutex<std::collections::HashSet<[u8; NONCE_LEN]>>,
}

impl ProductionNonceReplayGuard for RecordingNonceReplayGuard {
    fn check_and_record_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        _now_unix_millis: u64,
    ) -> Result<(), OprfError> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| OprfError::ProductionServerNonceReplay)?;
        if !seen.insert(*nonce) {
            return Err(OprfError::ProductionServerNonceReplay);
        }
        Ok(())
    }
}
```

Add this test after `production_context_active_device_reaches_platform_verifier_fail_closed`:

```rust
#[test]
fn production_context_rejects_replayed_server_nonce_after_first_success() {
    let (sk, vk) = make_device_keypair();
    let nonce = fresh_nonce();
    let signed = production_android_oprf_request(&sk, &vk, nonce);
    let verifier = AcceptingAndroidVerifier;
    let replay_guard = RecordingNonceReplayGuard::default();
    let ctx = ProductionOprfVerificationContext::new(
        nonce,
        1_700_000_000_000,
        1_700_000_000_100,
        ProductionFreshnessPolicy::default(),
        active_device_state(),
        &verifier,
        &replay_guard,
    )
    .expect("context with real verifier and replay guard is valid");

    verify_signed_request_for_production_with_context(&signed, &ctx)
        .expect("first use of server nonce is accepted");
    let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();

    assert!(matches!(err, OprfError::ProductionServerNonceReplay));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbrella-oprf production_context_rejects_replayed_server_nonce_after_first_success --all-features --locked
```

Expected: FAIL at compile time because `ProductionNonceReplayGuard` and `OprfError::ProductionServerNonceReplay` do not exist and `ProductionOprfVerificationContext::new` does not take the replay guard yet.

- [ ] **Step 3: Add the OPRF replay error**

In `crates/umbrella-oprf/src/error.rs`, after `ProductionServerNonceMismatch`, add:

```rust
    /// Серверный вызов уже был использован и не может дать второй OPRF-ответ.
    /// Server nonce was already consumed and cannot yield a second OPRF response.
    #[error("production server nonce replay")]
    ProductionServerNonceReplay,
```

- [ ] **Step 4: Add the OPRF replay guard trait and context field**

In `crates/umbrella-oprf/src/attestation.rs`, after `ProductionPlatformVerifier`, add:

```rust
/// Хранилище использованных серверных вызовов для боевой OPRF-проверки.
/// Store of consumed server nonces for production OPRF verification.
pub trait ProductionNonceReplayGuard: std::fmt::Debug {
    /// Проверить и записать одноразовый серверный вызов.
    /// Check and record a one-time server nonce.
    ///
    /// # Errors
    /// Возвращает [`OprfError::ProductionServerNonceReplay`], если вызов уже был
    /// принят ранее.
    fn check_and_record_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        now_unix_millis: u64,
    ) -> Result<(), OprfError>;
}
```

Change `ProductionOprfVerificationContext` to store the guard:

```rust
pub struct ProductionOprfVerificationContext<'a> {
    expected_server_nonce: [u8; NONCE_LEN],
    server_nonce_issued_at_unix_millis: u64,
    now_unix_millis: u64,
    freshness: ProductionFreshnessPolicy,
    device_state: ProductionDeviceState,
    platform_verifier: &'a dyn ProductionPlatformVerifier,
    nonce_replay_guard: &'a dyn ProductionNonceReplayGuard,
}
```

Change `ProductionOprfVerificationContext::new` signature and initializer:

```rust
    pub fn new(
        expected_server_nonce: [u8; NONCE_LEN],
        server_nonce_issued_at_unix_millis: u64,
        now_unix_millis: u64,
        freshness: ProductionFreshnessPolicy,
        device_state: ProductionDeviceState,
        platform_verifier: &'a dyn ProductionPlatformVerifier,
        nonce_replay_guard: &'a dyn ProductionNonceReplayGuard,
    ) -> Result<Self, OprfError> {
        if platform_verifier.kind() == PlatformVerifierKind::TestOnly {
            return Err(OprfError::ProductionTestVerifierRejected);
        }
        Ok(Self {
            expected_server_nonce,
            server_nonce_issued_at_unix_millis,
            now_unix_millis,
            freshness,
            device_state,
            platform_verifier,
            nonce_replay_guard,
        })
    }
```

- [ ] **Step 5: Record nonce only after all production checks pass**

In `verify_signed_request_for_production_with_context`, replace the final `match` with:

```rust
    match req.attestation.platform {
        Platform::Testing => Err(OprfError::CryptoVerificationFailed),
        Platform::IOs | Platform::Android | Platform::Web => {
            ctx.platform_verifier
                .verify_platform_attestation(PlatformVerificationInput {
                    platform: req.attestation.platform,
                    token: req.attestation.token.as_slice(),
                    server_nonce: &req.nonce,
                    device_pubkey: &req.device_pubkey,
                    now_unix_millis: ctx.now_unix_millis,
                })?;
            ctx.nonce_replay_guard
                .check_and_record_nonce(&req.nonce, ctx.now_unix_millis)
        }
    }
```

- [ ] **Step 6: Update existing OPRF tests for the new constructor**

In the OPRF test helper `production_context`, add a `replay_guard` parameter:

```rust
    fn production_context<'a>(
        verifier: &'a dyn ProductionPlatformVerifier,
        replay_guard: &'a dyn ProductionNonceReplayGuard,
        expected_server_nonce: [u8; NONCE_LEN],
        nonce_issued_at_unix_millis: u64,
        now_unix_millis: u64,
        device_state: ProductionDeviceState,
    ) -> ProductionOprfVerificationContext<'a> {
        ProductionOprfVerificationContext::new(
            expected_server_nonce,
            nonce_issued_at_unix_millis,
            now_unix_millis,
            ProductionFreshnessPolicy::default(),
            device_state,
            verifier,
            replay_guard,
        )
        .expect("context must be valid for non-test-only verifier")
    }
```

At each existing call site, create a local guard and pass it:

```rust
        let replay_guard = RecordingNonceReplayGuard::default();
        let ctx = production_context(
            &verifier,
            &replay_guard,
            nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            active_device_state(),
        );
```

For `production_context_rejects_test_only_platform_verifier`, create a guard and pass it into `ProductionOprfVerificationContext::new`.

- [ ] **Step 7: Re-export the OPRF replay guard**

In `crates/umbrella-oprf/src/lib.rs`, add `ProductionNonceReplayGuard` to the existing `pub use attestation::{ ... }` list:

```rust
    PlatformVerifierKind, ProductionDeviceState, ProductionFreshnessPolicy,
    ProductionNonceReplayGuard, ProductionOprfVerificationContext, ProductionPlatformVerifier,
```

- [ ] **Step 8: Run focused OPRF tests**

Run:

```bash
cargo test -p umbrella-oprf production_context --all-features --locked
cargo test -p umbrella-oprf verify_rejects_tampered_nonce --all-features --locked
```

Expected: PASS. The first command must include the new replay test and the old production context tests.

- [ ] **Step 9: Commit OPRF replay gate**

```bash
git add crates/umbrella-oprf/src/error.rs crates/umbrella-oprf/src/attestation.rs crates/umbrella-oprf/src/lib.rs
git commit -m "oprf: reject production nonce replay"
```

---

### Task 2: Backup Production Nonce Replay Gate

**Files:**
- Modify: `crates/umbrella-backup/src/error.rs`
- Modify: `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`
- Modify: `crates/umbrella-backup/src/cloud_wrap/mod.rs`

- [ ] **Step 1: Write the failing backup replay test**

In `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`, inside the existing test module, add after `TestOnlySuccessVerifier`:

```rust
#[derive(Debug, Default)]
struct AcceptingIosVerifier;

impl ProductionPlatformVerifier for AcceptingIosVerifier {
    fn kind(&self) -> PlatformVerifierKind {
        PlatformVerifierKind::AppleAppAttest
    }

    fn verify_platform_attestation(
        &self,
        input: PlatformVerificationInput<'_>,
    ) -> Result<(), BackupError> {
        assert_eq!(input.platform, Platform::IOs);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct RecordingNonceReplayGuard {
    seen: std::sync::Mutex<std::collections::HashSet<[u8; NONCE_LEN]>>,
}

impl ProductionNonceReplayGuard for RecordingNonceReplayGuard {
    fn check_and_record_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        _now_unix_millis: u64,
    ) -> Result<(), BackupError> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| BackupError::ProductionServerNonceReplay)?;
        if !seen.insert(*nonce) {
            return Err(BackupError::ProductionServerNonceReplay);
        }
        Ok(())
    }
}
```

Add after `production_context_active_device_reaches_platform_verifier_fail_closed`:

```rust
#[test]
fn production_context_rejects_replayed_server_nonce_after_first_success() {
    let (sk, vk) = make_device_keypair();
    let nonce = fresh_nonce();
    let req = production_ios_unwrap_request(&sk, &vk, nonce, 1_700_000_000_050);
    let verifier = AcceptingIosVerifier;
    let replay_guard = RecordingNonceReplayGuard::default();
    let ctx = ProductionUnwrapVerificationContext::new(
        nonce,
        1_700_000_000_000,
        1_700_000_000_100,
        ProductionFreshnessPolicy::default(),
        active_device_state(),
        u64::MAX,
        &verifier,
        &replay_guard,
    )
    .expect("context with real verifier and replay guard is valid");

    verify_signed_unwrap_request_for_production_with_context(&req, &ctx)
        .expect("first use of server nonce is accepted");
    let err = verify_signed_unwrap_request_for_production_with_context(&req, &ctx).unwrap_err();

    assert!(matches!(err, BackupError::ProductionServerNonceReplay));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbrella-backup production_context_rejects_replayed_server_nonce_after_first_success --all-features --locked
```

Expected: FAIL at compile time because `ProductionNonceReplayGuard` and `BackupError::ProductionServerNonceReplay` do not exist and `ProductionUnwrapVerificationContext::new` does not take the replay guard yet.

- [ ] **Step 3: Add the backup replay error**

In `crates/umbrella-backup/src/error.rs`, after `ProductionServerNonceMismatch`, add:

```rust
    /// Серверный вызов уже был использован и не может дать вторую долю ключа.
    /// Server nonce was already consumed and cannot yield a second key share.
    #[error("production server nonce replay")]
    ProductionServerNonceReplay,
```

- [ ] **Step 4: Add backup replay guard trait and context field**

In `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`, after `ProductionPlatformVerifier`, add:

```rust
/// Хранилище использованных серверных вызовов для боевой проверки развёртки ключа.
/// Store of consumed server nonces for production unwrap verification.
pub trait ProductionNonceReplayGuard: std::fmt::Debug {
    /// Проверить и записать одноразовый серверный вызов.
    /// Check and record a one-time server nonce.
    ///
    /// # Errors
    /// Возвращает [`BackupError::ProductionServerNonceReplay`], если вызов уже
    /// был принят ранее.
    fn check_and_record_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        now_unix_millis: u64,
    ) -> Result<(), BackupError>;
}
```

Change `ProductionUnwrapVerificationContext` to store the guard:

```rust
pub struct ProductionUnwrapVerificationContext<'a> {
    expected_server_nonce: [u8; NONCE_LEN],
    server_nonce_issued_at_unix_millis: u64,
    now_unix_millis: u64,
    freshness: ProductionFreshnessPolicy,
    device_state: ProductionDeviceState,
    envelope_timestamp_unix_millis: u64,
    platform_verifier: &'a dyn ProductionPlatformVerifier,
    nonce_replay_guard: &'a dyn ProductionNonceReplayGuard,
}
```

Change `ProductionUnwrapVerificationContext::new` signature and initializer:

```rust
    pub fn new(
        expected_server_nonce: [u8; NONCE_LEN],
        server_nonce_issued_at_unix_millis: u64,
        now_unix_millis: u64,
        freshness: ProductionFreshnessPolicy,
        device_state: ProductionDeviceState,
        envelope_timestamp_unix_millis: u64,
        platform_verifier: &'a dyn ProductionPlatformVerifier,
        nonce_replay_guard: &'a dyn ProductionNonceReplayGuard,
    ) -> Result<Self, BackupError> {
        if platform_verifier.kind() == PlatformVerifierKind::TestOnly {
            return Err(BackupError::ProductionTestVerifierRejected);
        }
        Ok(Self {
            expected_server_nonce,
            server_nonce_issued_at_unix_millis,
            now_unix_millis,
            freshness,
            device_state,
            envelope_timestamp_unix_millis,
            platform_verifier,
            nonce_replay_guard,
        })
    }
```

- [ ] **Step 5: Record nonce only after all production unwrap checks pass**

In `verify_signed_unwrap_request_for_production_with_context`, replace the final `match` with:

```rust
    match req.attestation.platform {
        Platform::Testing => Err(BackupError::CryptoVerificationFailed),
        Platform::IOs | Platform::Android | Platform::Web => {
            ctx.platform_verifier
                .verify_platform_attestation(PlatformVerificationInput {
                    platform: req.attestation.platform,
                    token: req.attestation.token.as_slice(),
                    server_nonce: &req.server_nonce,
                    device_pubkey: &req.device_pubkey,
                    now_unix_millis: ctx.now_unix_millis,
                })?;
            ctx.nonce_replay_guard
                .check_and_record_nonce(&req.server_nonce, ctx.now_unix_millis)
        }
    }
```

- [ ] **Step 6: Update existing backup tests for the new constructor**

Change the test helper `production_context` to accept the guard:

```rust
    fn production_context<'a>(
        verifier: &'a dyn ProductionPlatformVerifier,
        replay_guard: &'a dyn ProductionNonceReplayGuard,
        expected_server_nonce: [u8; NONCE_LEN],
        nonce_issued_at_unix_millis: u64,
        now_unix_millis: u64,
        device_state: ProductionDeviceState,
    ) -> ProductionUnwrapVerificationContext<'a> {
        ProductionUnwrapVerificationContext::new(
            expected_server_nonce,
            nonce_issued_at_unix_millis,
            now_unix_millis,
            ProductionFreshnessPolicy::default(),
            device_state,
            u64::MAX,
            verifier,
            replay_guard,
        )
        .expect("context must be valid for non-test-only verifier")
    }
```

At each existing call site, create a local guard and pass it:

```rust
        let replay_guard = RecordingNonceReplayGuard::default();
        let ctx = production_context(
            &verifier,
            &replay_guard,
            nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            active_device_state(),
        );
```

For `production_context_rejects_test_only_platform_verifier`, create a guard and pass it into `ProductionUnwrapVerificationContext::new`.

- [ ] **Step 7: Re-export the backup replay guard**

In `crates/umbrella-backup/src/cloud_wrap/mod.rs`, add `ProductionNonceReplayGuard` to the `pub use signed_request::{ ... }` list:

```rust
    PlatformAttestation, PlatformVerificationInput, PlatformVerifierKind, ProductionDeviceState,
    ProductionFreshnessPolicy, ProductionNonceReplayGuard, ProductionPlatformVerifier,
```

- [ ] **Step 8: Run focused backup tests**

Run:

```bash
cargo test -p umbrella-backup production_context --all-features --locked
cargo test -p umbrella-backup mock_transport_rejects_replayed_server_nonce --all-features --locked
```

Expected: PASS. The first command must include the new replay test and the old production context tests.

- [ ] **Step 9: Commit backup replay gate**

```bash
git add crates/umbrella-backup/src/error.rs crates/umbrella-backup/src/cloud_wrap/signed_request.rs crates/umbrella-backup/src/cloud_wrap/mod.rs
git commit -m "backup: reject production nonce replay"
```

---

### Task 3: Endpoint And WebAuthn Fail-Closed Gaps

**Files:**
- Modify: `crates/umbrella-client/src/transport/http2_client.rs`
- Modify: `crates/umbrella-platform-verifier/src/web.rs`

- [ ] **Step 1: Add failing endpoint-host tests**

In `crates/umbrella-client/src/transport/http2_client.rs`, inside the existing tests module, add after `production_transport_rejects_ip_literal_hosts`:

```rust
    #[test]
    fn production_transport_rejects_link_local_and_cgnat_hosts() {
        for url in ["https://169.254.169.254", "https://100.64.0.10"] {
            let cfg = production_config_with_urls(vec![
                url,
                "https://sealed-1.umbrella.example",
                "https://sealed-2.umbrella.example",
                "https://sealed-3.umbrella.example",
                "https://sealed-4.umbrella.example",
            ]);

            let err = cfg.validate().unwrap_err();
            assert!(
                format!("{err}").contains("test host"),
                "{url} must be rejected, got {err}"
            );
        }
    }

    #[test]
    fn production_transport_rejects_ipv6_local_hosts() {
        for url in ["https://[::1]", "https://[fd00::1]", "https://[fe80::1]"] {
            let cfg = production_config_with_urls(vec![
                url,
                "https://sealed-1.umbrella.example",
                "https://sealed-2.umbrella.example",
                "https://sealed-3.umbrella.example",
                "https://sealed-4.umbrella.example",
            ]);

            let err = cfg.validate().unwrap_err();
            assert!(
                format!("{err}").contains("test host"),
                "{url} must be rejected, got {err}"
            );
        }
    }
```

- [ ] **Step 2: Run endpoint tests to verify they fail**

Run:

```bash
cargo test -p umbrella-client production_transport_rejects_link_local_and_cgnat_hosts --all-features --locked
cargo test -p umbrella-client production_transport_rejects_ipv6_local_hosts --all-features --locked
```

Expected: FAIL because `169.254.169.254`, `100.64.0.10`, `fd00::1`, and `fe80::1` are not all rejected by the current string-prefix filter.

- [ ] **Step 3: Replace endpoint filtering with parsed IP rules**

In `crates/umbrella-client/src/transport/http2_client.rs`, replace `is_forbidden_production_host` with:

```rust
fn is_forbidden_production_host(host: &str) -> bool {
    let trimmed = host.trim_end_matches('.');
    let h = trimmed
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if h.is_empty()
        || h == "localhost"
        || h.ends_with(".localhost")
        || h.ends_with(".invalid")
        || h.ends_with(".example.invalid")
    {
        return true;
    }

    match h.parse::<std::net::IpAddr>() {
        Ok(ip) => is_forbidden_production_ip(ip),
        Err(_) => false,
    }
}

fn is_forbidden_production_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || octets == [255, 255, 255, 255]
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        }
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            v6.is_unspecified()
                || v6.is_loopback()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}
```

- [ ] **Step 4: Add WebAuthn registered-key mismatch test**

In `crates/umbrella-platform-verifier/src/web.rs`, inside the existing tests module, add after `webauthn_accepts_matching_site_challenge_signature_and_counter`:

```rust
    #[test]
    fn webauthn_rejects_context_device_key_not_registered_key() {
        let sk = keypair();
        let registered_pubkey = sk.verifying_key().to_bytes();
        let attacker = keypair();
        let attacker_pubkey = attacker.verifying_key().to_bytes();
        let nonce = [7u8; 32];
        let token = signed_token(&sk, "app.umbrella.example", &nonce, 2);
        let registered = RegisteredPlatformKey {
            public_key: registered_pubkey,
            last_counter: 1,
        };

        let err = rejected_error(
            context(
                &token,
                &nonce,
                &attacker_pubkey,
                &registered,
                "app.umbrella.example",
            ),
            "context device key mismatch",
        );

        assert!(matches!(err, PlatformVerifierError::DeviceKeyMismatch));
    }
```

- [ ] **Step 5: Run focused tests**

Run:

```bash
cargo test -p umbrella-client production_transport_rejects_link_local_and_cgnat_hosts --all-features --locked
cargo test -p umbrella-client production_transport_rejects_ipv6_local_hosts --all-features --locked
cargo test -p umbrella-platform-verifier webauthn_rejects_context_device_key_not_registered_key --all-features --locked
```

Expected: PASS.

- [ ] **Step 6: Commit endpoint and WebAuthn hardening**

```bash
git add crates/umbrella-client/src/transport/http2_client.rs crates/umbrella-platform-verifier/src/web.rs
git commit -m "client: reject local production endpoints"
```

---

### Task 4: Attack Coverage Matrix And Audit Script

**Files:**
- Create: `docs/security/protocol-core-attack-gates.md`
- Create: `scripts/audit-protocol-core-attack-gates.sh`
- Modify: `scripts/audit-public-access-notices.sh`

- [ ] **Step 1: Create the attack coverage matrix**

Create `docs/security/protocol-core-attack-gates.md` with:

```markdown
# Protocol Core Attack Gates

Дата: 2026-05-14

## Русский

Этот файл фиксирует, какие атаки ядро Umbrella Protocol проверяет локально.
Статус “закрыто тестом” означает, что есть Rust-тест, который ломает путь при
подмене, повторе, откате или неверной версии. Статус “граница выпуска” означает,
что публичный боевой запуск остаётся закрыт, пока внешняя часть не подключена.

| Область | Атака | Статус | Доказательство |
|---|---|---|---|
| Устройства | тестовая платформа в боевом пути | закрыто тестом | `production_policy_rejects_testing_attestation_even_after_valid_signature` в `umbrella-oprf` и `umbrella-backup` |
| Устройства | неизвестное, ожидающее или отозванное устройство | закрыто тестом | `production_context_rejects_unknown_pending_and_revoked_devices` |
| Устройства | откат WebAuthn-счётчика | закрыто тестом | `webauthn_rejects_counter_rollback` |
| Устройства | WebAuthn ключ в контексте не совпадает с зарегистрированным | закрыто тестом | `webauthn_rejects_context_device_key_not_registered_key` |
| Транспорт | `http://`, локальные, частные, link-local, CGNAT, IPv6-local адреса в боевой настройке | закрыто тестом | `production_transport_rejects_http_url`, `production_transport_rejects_test_hosts`, `production_transport_rejects_link_local_and_cgnat_hosts`, `production_transport_rejects_ipv6_local_hosts` |
| Транспорт | неверный SPKI pin | закрыто тестом | `wrong_key_for_same_server_is_rejected_after_inner_accepts` |
| Транспорт | pin не должен обходить обычную проверку сертификата | закрыто тестом | `matching_pin_does_not_bypass_inner_certificate_failure` |
| KT | root без достаточных подписей | закрыто тестом | `two_of_five_signatures_rejected` |
| KT | подмена root, epoch или подписи | закрыто тестом | `tampered_root_all_signatures_invalid`, `tampered_epoch_all_signatures_invalid`, `tampered_signature_bit_flip_invalid` |
| KT | split-view при трёх злых свидетелях | честная граница | `threshold_compromised_views_can_verify_but_safety_numbers_diverge`: локально обе версии могут пройти, поэтому нужен gossip/self-monitoring |
| OPRF | подмена blinded, token, nonce или device key | закрыто тестом | `verify_rejects_tampered_blinded`, `verify_rejects_tampered_token`, `verify_rejects_tampered_nonce`, `verify_rejects_wrong_device_pubkey` |
| OPRF | повтор серверного вызова | закрыто тестом | `production_context_rejects_replayed_server_nonce_after_first_success` |
| Backup | подмена chat_id, recipient, timestamp, token, nonce или device key | закрыто тестом | `verify_rejects_tampered_chat_id`, `verify_rejects_tampered_recipient_device_pubkey`, `verify_rejects_tampered_timestamp`, `verify_rejects_tampered_token`, `verify_rejects_tampered_nonce`, `verify_rejects_wrong_device_pubkey` |
| Backup | повтор серверного вызова | закрыто тестом | `production_context_rejects_replayed_server_nonce_after_first_success` и `mock_transport_rejects_replayed_server_nonce` |
| Backup | V1/V2 rollback или смешение форматов | закрыто тестом | `v1_v2_mixed_corpus.rs` |
| Sealed Sender | подмена ciphertext, ключа получателя, версии | закрыто тестом | `phd_real_attacks_sealed_sender.rs`, `v1_v2_mixed_corpus.rs`, `v2_envelope_roundtrip.rs` |
| Sealed Sender | replay к другому получателю | закрыто тестом | `real_attack_replay_envelope_to_different_recipient_aad_blocks` |
| Sealed Sender | V1 как V2 и V2 как V1 | закрыто тестом | `real_attack_cross_version_replay_v1_to_v2_blocked` |

Оставшиеся границы выпуска:

- публичный FFI-запуск клиента остаётся закрыт;
- Apple App Attest и Android Play Integrity закрыто отказывают без внешних корней доверия и разбора токенов;
- боевые свидетели KT должны быть развёрнуты отдельно, потому что локальный код не может сам доказать отсутствие split-view при захвате трёх свидетелей;
- интеграция с настоящими серверами ещё не считается готовой.

## English

This file records local attack gates for the Umbrella Protocol core. “Covered by
test” means there is a Rust test that rejects tampering, replay, rollback, or
wrong-version input. “Release boundary” means the public production path remains
closed until the external part is wired.
```

- [ ] **Step 2: Add the audit script**

Create `scripts/audit-protocol-core-attack-gates.sh` with:

```bash
#!/usr/bin/env bash
set -euo pipefail

failed=0

require_pattern() {
  local file="$1"
  local pattern="$2"

  if [[ ! -f "$file" ]]; then
    echo "missing $file" >&2
    failed=1
    return
  fi

  if ! grep -Eqi "$pattern" "$file"; then
    echo "$file does not contain required protocol gate: $pattern" >&2
    failed=1
  fi
}

require_pattern "crates/umbrella-oprf/src/attestation.rs" "ProductionNonceReplayGuard"
require_pattern "crates/umbrella-oprf/src/error.rs" "ProductionServerNonceReplay"
require_pattern "crates/umbrella-backup/src/cloud_wrap/signed_request.rs" "ProductionNonceReplayGuard"
require_pattern "crates/umbrella-backup/src/error.rs" "ProductionServerNonceReplay"
require_pattern "crates/umbrella-client/src/transport/http2_client.rs" "100\\.64|is_forbidden_production_ip"
require_pattern "crates/umbrella-client/src/transport/http2_client.rs" "169\\.254|is_link_local"
require_pattern "crates/umbrella-platform-verifier/src/web.rs" "webauthn_rejects_context_device_key_not_registered_key"
require_pattern "crates/umbrella-kt/tests/phd_attacks.rs" "threshold_compromised_views_can_verify_but_safety_numbers_diverge"
require_pattern "crates/umbrella-sealed-sender/tests/phd_real_attacks_sealed_sender.rs" "real_attack_cross_version_replay_v1_to_v2_blocked"
require_pattern "docs/security/protocol-core-attack-gates.md" "повтор серверного вызова"
require_pattern "docs/security/protocol-core-attack-gates.md" "split-view"

if [[ "$failed" -ne 0 ]]; then
  exit "$failed"
fi

echo "protocol core attack gates OK"
```

Make it executable:

```bash
chmod +x scripts/audit-protocol-core-attack-gates.sh
```

- [ ] **Step 3: Wire the public notice audit to the new matrix**

In `scripts/audit-public-access-notices.sh`, after the `production-readiness-boundaries.md` checks, add:

```bash
require_pattern "docs/security/protocol-core-attack-gates.md" "повтор серверного вызова"
require_pattern "docs/security/protocol-core-attack-gates.md" "split-view"
```

- [ ] **Step 4: Run documentation audits**

Run:

```bash
bash scripts/audit-protocol-core-attack-gates.sh
bash scripts/audit-public-access-notices.sh
```

Expected: PASS with:

```text
protocol core attack gates OK
public access notices OK
```

- [ ] **Step 5: Commit matrix and audit script**

```bash
git add docs/security/protocol-core-attack-gates.md scripts/audit-protocol-core-attack-gates.sh scripts/audit-public-access-notices.sh
git commit -m "docs: add protocol attack gate matrix"
```

---

### Task 5: Public Status Documents

**Files:**
- Modify: `docs/security/current-status.md`
- Modify: `docs/security/production-readiness-boundaries.md`
- Modify: `docs/README.md`
- Modify: `README.md`

- [ ] **Step 1: Update current status**

In `docs/security/current-status.md`, change `Дата: 2026-05-13` to:

```markdown
Дата: 2026-05-14
```

In the Russian “Что уже реализовано и описано” list, add:

```markdown
- матрица боевых атакующих ворот ядра протокола:
  `docs/security/protocol-core-attack-gates.md`;
- обязательная защита от повторного использования серверного вызова в боевых
  контекстах OPRF и развёртки резервного ключа.
```

In the English “Implemented and currently documented” list, add:

```markdown
- protocol-core attack gate matrix:
  `docs/security/protocol-core-attack-gates.md`;
- mandatory server-nonce replay rejection in the production OPRF and backup
  unwrap contexts.
```

- [ ] **Step 2: Update production readiness boundaries**

In `docs/security/production-readiness-boundaries.md`, change `Дата: 2026-05-13` to:

```markdown
Дата: 2026-05-14
```

Add to the Russian closed gates list:

```markdown
- Повтор серверного вызова: боевые контексты OPRF и развёртки резервного ключа
  требуют явный `ProductionNonceReplayGuard`. Первый принятый запрос записывает
  вызов как использованный, повтор того же вызова отвергается.
- Матрица атак ядра: `docs/security/protocol-core-attack-gates.md` фиксирует,
  какие подмены, повторы, откаты и смешения версий покрыты Rust-тестами.
```

Add to the English closed gates list:

```markdown
- Server nonce replay: production OPRF and backup unwrap contexts require an
  explicit `ProductionNonceReplayGuard`. The first accepted request records the
  nonce as consumed, and a second use of the same nonce is rejected.
- Core attack matrix: `docs/security/protocol-core-attack-gates.md` records
  which tamper, replay, rollback, and mixed-version cases are covered by Rust
  tests.
```

- [ ] **Step 3: Add README links**

In both `README.md` and `docs/README.md`, add one sentence near the current hardening-status links:

```markdown
Боевые атакующие ворота ядра протокола записаны в
[`docs/security/protocol-core-attack-gates.md`](docs/security/protocol-core-attack-gates.md).
```

For `docs/README.md`, use the correct relative link:

```markdown
Боевые атакующие ворота ядра протокола записаны в
[`security/protocol-core-attack-gates.md`](security/protocol-core-attack-gates.md).
```

- [ ] **Step 4: Run audits**

Run:

```bash
bash scripts/audit-protocol-core-attack-gates.sh
bash scripts/audit-public-access-notices.sh
```

Expected: PASS.

- [ ] **Step 5: Commit status docs**

```bash
git add docs/security/current-status.md docs/security/production-readiness-boundaries.md README.md docs/README.md
git commit -m "docs: update protocol core readiness status"
```

---

### Task 6: Final Rust Gates

**Files:**
- No direct edits unless a gate exposes a real issue.

- [ ] **Step 1: Run focused package gates**

Run:

```bash
cargo test -p umbrella-platform-verifier --all-features --locked
cargo test -p umbrella-client --all-features --locked
cargo test -p umbrella-kt --all-features --locked
cargo test -p umbrella-oprf --all-features --locked
cargo test -p umbrella-backup --all-features --locked
cargo test -p umbrella-sealed-sender --all-features --locked
```

Expected: all PASS.

- [ ] **Step 2: Run workspace formatting and lint gates**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Expected: both PASS.

- [ ] **Step 3: Run documentation build**

Run:

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
```

Expected: PASS.

- [ ] **Step 4: Run full workspace test**

Run:

```bash
cargo test --workspace --all-features --locked
```

Expected: PASS. If this exposes unrelated pre-existing failures, record exact failing crate, test name, and error in `docs/security/current-status.md`, then fix any failure caused by this phase before claiming success.

- [ ] **Step 5: Run public and protocol audits**

Run:

```bash
bash scripts/audit-protocol-core-attack-gates.sh
bash scripts/audit-public-access-notices.sh
```

Expected: PASS.

- [ ] **Step 6: Commit final verification note if documents changed**

If `docs/security/current-status.md` was updated with final gate results, run:

```bash
git add docs/security/current-status.md
git commit -m "docs: record protocol core gate results"
```

If no files changed after verification, do not create an empty commit.

---

## Self-Review Checklist

- Spec coverage: covered by Task 1 for OPRF replay, Task 2 for backup replay, Task 3 for endpoint/WebAuthn gaps, Task 4 for KT/sealed-sender/client/platform matrix, Task 5 for public docs, Task 6 for final gates.
- Scope: no task touches `/Users/daniel/Documents/Projects/Messenger/rust_1mlrd`.
- Production honesty: public FFI remains closed; Apple and Android platform checks remain fail-closed without external trust material.
- Test reality: replay tests require first production-context success and second refusal; endpoint tests use real rejected URL inputs; WebAuthn mismatch test uses a signed token with a different context device key.
- Placeholder scan: no task relies on an unnamed later implementation.
- Type consistency: OPRF and backup intentionally use same trait name inside different crate namespaces: `ProductionNonceReplayGuard`.
