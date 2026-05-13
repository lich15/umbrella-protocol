# Production Attestation Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a strict server-side production attestation gate for cloud unwrap and OPRF requests without opening public FFI bootstrap.

**Architecture:** Keep the existing signature-only helpers for tests, then add contextual production verifiers that check signature, server nonce, freshness, device state, platform, and an explicit platform verifier. Real iOS, Android, and Web platform verification still fail closed through an unavailable verifier until their own implementations are built.

**Tech Stack:** Rust 1.95 workspace, `umbrella-backup`, `umbrella-oprf`, existing Ed25519 signing helpers, existing ADR-008 device state model, `cargo test`, `cargo clippy`, `cargo doc`.

---

## Source Documents

- `docs/WORKING_RULES.md`
- `docs/superpowers/specs/2026-05-13-production-attestation-gate-design.md`
- `docs/security/production-readiness-boundaries.md`
- `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`
- `crates/umbrella-oprf/src/attestation.rs`
- `crates/umbrella-backup/src/cloud_wrap/transport.rs`

## File Structure

- Modify `crates/umbrella-backup/src/error.rs`: add precise production gate errors for nonce, freshness, unknown device, and test-only verifier misuse.
- Modify `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`: add cloud unwrap production context, device state input, platform verifier trait, unavailable verifier, and contextual production verification.
- Modify `crates/umbrella-backup/src/cloud_wrap/mod.rs`: re-export the new production verifier types.
- Modify `crates/umbrella-oprf/src/error.rs`: add matching production gate errors for OPRF.
- Modify `crates/umbrella-oprf/src/attestation.rs`: add OPRF production context, device state input, platform verifier trait, unavailable verifier, and contextual production verification.
- Modify `crates/umbrella-oprf/src/lib.rs`: re-export the new production verifier types.
- Modify `docs/security/production-readiness-boundaries.md`: record that the server-side production attestation gate is contextual and fail-closed, while real platform verifiers remain closed.
- Modify `docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase1.md`: add a top note that the file is historical, not an active checklist.
- Modify `docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase2.md`: add a top note that the file is historical, not an active checklist.
- Modify `README.md`, `docs/README.md`, and `docs/security/release-manifest-v1.0.0.txt` only if implementation changes the public status wording.

---

## Task 1: Backup Production Gate Red Tests

**Files:**
- Modify: `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`

- [ ] **Step 1: Add failing tests for contextual cloud unwrap production verification**

Inside `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`, in the existing `#[cfg(test)] mod tests`, add these helpers after the existing `sign_with` helper:

```rust
    #[derive(Debug, Default)]
    struct CountingUnavailableVerifier {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl CountingUnavailableVerifier {
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl ProductionPlatformVerifier for CountingUnavailableVerifier {
        fn kind(&self) -> PlatformVerifierKind {
            PlatformVerifierKind::Unavailable
        }

        fn verify_platform_attestation(
            &self,
            input: PlatformVerificationInput<'_>,
        ) -> Result<(), BackupError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(BackupError::ProductionAttestationVerifierUnavailable {
                platform_tag: input.platform.tag(),
            })
        }
    }

    #[derive(Debug, Default)]
    struct TestOnlySuccessVerifier;

    impl ProductionPlatformVerifier for TestOnlySuccessVerifier {
        fn kind(&self) -> PlatformVerifierKind {
            PlatformVerifierKind::TestOnly
        }

        fn verify_platform_attestation(
            &self,
            _input: PlatformVerificationInput<'_>,
        ) -> Result<(), BackupError> {
            Ok(())
        }
    }

    fn production_ios_unwrap_request(
        sk: &SigningKey,
        vk: &DalekVerifyingKey,
        nonce: [u8; NONCE_LEN],
        timestamp_unix_millis: u64,
    ) -> SignedUnwrapRequest {
        let r = sample_r();
        let chat = sample_chat();
        let rec = [0x22u8; ED25519_PUB_LEN];
        let attestation = PlatformAttestation::new(Platform::IOs, b"ios-app-attest-token").unwrap();
        let canonical = canonical_signing_input(&r, &chat, &rec, timestamp_unix_millis, &nonce, &attestation);
        SignedUnwrapRequest {
            ephemeral_r: r,
            chat_id: chat,
            recipient_device_pubkey: rec,
            timestamp_unix_millis,
            server_nonce: nonce,
            attestation,
            device_signature: sign_with(sk, &canonical),
            device_pubkey: vk.to_bytes(),
        }
    }

    fn active_device_state() -> ProductionDeviceState {
        ProductionDeviceState::Active {
            authorized_since_unix_millis: 1_700_000_000_000,
            history_cutoff_unix_millis: 0,
        }
    }

    fn production_context<'a>(
        verifier: &'a dyn ProductionPlatformVerifier,
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
        )
        .expect("context must be valid for non-test-only verifier")
    }
```

Then add these tests near the existing production policy tests:

```rust
    #[test]
    fn production_context_rejects_test_only_platform_verifier() {
        let nonce = fresh_nonce();
        let err = ProductionUnwrapVerificationContext::new(
            nonce,
            1_700_000_000_000,
            1_700_000_000_001,
            ProductionFreshnessPolicy::default(),
            active_device_state(),
            u64::MAX,
            &TestOnlySuccessVerifier,
        )
        .unwrap_err();
        assert!(matches!(err, BackupError::ProductionTestVerifierRejected));
    }

    #[test]
    fn production_context_rejects_bad_signature_before_platform_verifier() {
        let (sk, vk) = make_device_keypair();
        let nonce = fresh_nonce();
        let mut req = production_ios_unwrap_request(&sk, &vk, nonce, 1_700_000_000_050);
        req.device_signature[0] ^= 1;
        let verifier = CountingUnavailableVerifier::default();
        let ctx = production_context(
            &verifier,
            nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            active_device_state(),
        );
        let err = verify_signed_unwrap_request_for_production_with_context(&req, &ctx).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
        assert_eq!(verifier.calls(), 0, "bad signatures must not reach platform verification");
    }

    #[test]
    fn production_context_rejects_server_nonce_mismatch() {
        let (sk, vk) = make_device_keypair();
        let request_nonce = fresh_nonce();
        let expected_nonce = fresh_nonce();
        let req = production_ios_unwrap_request(&sk, &vk, request_nonce, 1_700_000_000_050);
        let verifier = CountingUnavailableVerifier::default();
        let ctx = production_context(
            &verifier,
            expected_nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            active_device_state(),
        );
        let err = verify_signed_unwrap_request_for_production_with_context(&req, &ctx).unwrap_err();
        assert!(matches!(err, BackupError::ProductionServerNonceMismatch));
        assert_eq!(verifier.calls(), 0);
    }

    #[test]
    fn production_context_rejects_expired_server_nonce() {
        let (sk, vk) = make_device_keypair();
        let nonce = fresh_nonce();
        let req = production_ios_unwrap_request(&sk, &vk, nonce, 1_700_000_000_050);
        let verifier = CountingUnavailableVerifier::default();
        let ctx = production_context(
            &verifier,
            nonce,
            1_700_000_000_000,
            1_700_000_400_001,
            active_device_state(),
        );
        let err = verify_signed_unwrap_request_for_production_with_context(&req, &ctx).unwrap_err();
        assert!(matches!(err, BackupError::ProductionServerNonceExpired { .. }));
        assert_eq!(verifier.calls(), 0);
    }

    #[test]
    fn production_context_rejects_future_request_timestamp() {
        let (sk, vk) = make_device_keypair();
        let nonce = fresh_nonce();
        let req = production_ios_unwrap_request(&sk, &vk, nonce, 1_700_000_400_001);
        let verifier = CountingUnavailableVerifier::default();
        let ctx = production_context(
            &verifier,
            nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            active_device_state(),
        );
        let err = verify_signed_unwrap_request_for_production_with_context(&req, &ctx).unwrap_err();
        assert!(matches!(err, BackupError::ProductionRequestTimestampInFuture { .. }));
        assert_eq!(verifier.calls(), 0);
    }

    #[test]
    fn production_context_rejects_unknown_pending_and_revoked_devices() {
        let (sk, vk) = make_device_keypair();
        let nonce = fresh_nonce();
        let req = production_ios_unwrap_request(&sk, &vk, nonce, 1_700_000_000_050);
        let verifier = CountingUnavailableVerifier::default();
        for (state, expected) in [
            (ProductionDeviceState::Unknown, "unknown"),
            (ProductionDeviceState::Pending, "pending"),
            (ProductionDeviceState::Revoked, "revoked"),
        ] {
            let ctx = production_context(
                &verifier,
                nonce,
                1_700_000_000_000,
                1_700_000_000_100,
                state,
            );
            let err = verify_signed_unwrap_request_for_production_with_context(&req, &ctx).unwrap_err();
            match expected {
                "unknown" => assert!(matches!(err, BackupError::ProductionDeviceUnknown)),
                "pending" => assert!(matches!(err, BackupError::DevicePendingAuthorization)),
                "revoked" => assert!(matches!(err, BackupError::DeviceRevoked)),
                _ => unreachable!(),
            }
        }
        assert_eq!(verifier.calls(), 0);
    }

    #[test]
    fn production_context_active_device_reaches_platform_verifier_fail_closed() {
        let (sk, vk) = make_device_keypair();
        let nonce = fresh_nonce();
        let req = production_ios_unwrap_request(&sk, &vk, nonce, 1_700_000_000_050);
        let verifier = CountingUnavailableVerifier::default();
        let ctx = production_context(
            &verifier,
            nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            active_device_state(),
        );
        let err = verify_signed_unwrap_request_for_production_with_context(&req, &ctx).unwrap_err();
        assert!(matches!(
            err,
            BackupError::ProductionAttestationVerifierUnavailable { platform_tag }
                if platform_tag == Platform::IOs.tag()
        ));
        assert_eq!(verifier.calls(), 1);
    }
```

- [ ] **Step 2: Run the backup red tests**

Run:

```bash
cargo test -p umbrella-backup --all-features --locked production_context_
```

Expected: compilation fails because `ProductionPlatformVerifier`, `PlatformVerifierKind`, `PlatformVerificationInput`, `ProductionDeviceState`, `ProductionUnwrapVerificationContext`, `ProductionFreshnessPolicy`, and `verify_signed_unwrap_request_for_production_with_context` do not exist yet.

---

## Task 2: Backup Production Gate Implementation

**Files:**
- Modify: `crates/umbrella-backup/src/error.rs`
- Modify: `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`
- Modify: `crates/umbrella-backup/src/cloud_wrap/mod.rs`

- [ ] **Step 1: Add precise backup error variants**

In `crates/umbrella-backup/src/error.rs`, after `ProductionAttestationVerifierUnavailable`, add:

```rust
    /// Тестовый платформенный проверяющий нельзя использовать в боевом контексте.
    /// Test-only platform verifier cannot be used in a production context.
    #[error("test-only attestation verifier rejected in production context")]
    ProductionTestVerifierRejected,

    /// Серверный вызов в запросе не совпал с выданным сервером вызовом.
    /// Request server nonce does not match the server-issued nonce.
    #[error("production server nonce mismatch")]
    ProductionServerNonceMismatch,

    /// Серверный вызов старше разрешённого окна свежести.
    /// Server-issued nonce is older than the allowed freshness window.
    #[error("production server nonce expired: age {age_millis} ms > max {max_age_millis} ms")]
    ProductionServerNonceExpired {
        /// Возраст вызова в миллисекундах. Nonce age in milliseconds.
        age_millis: u64,
        /// Максимальный возраст в миллисекундах. Maximum age in milliseconds.
        max_age_millis: u64,
    },

    /// Серверный вызов имеет время выдачи из будущего дальше допустимого перекоса.
    /// Server nonce issue time is too far in the future.
    #[error("production server nonce issued in future: skew {skew_millis} ms > max {max_future_skew_millis} ms")]
    ProductionServerNonceIssuedInFuture {
        /// Перекос в миллисекундах. Future skew in milliseconds.
        skew_millis: u64,
        /// Максимально допустимый перекос. Maximum allowed future skew.
        max_future_skew_millis: u64,
    },

    /// Время запроса из будущего дальше допустимого перекоса.
    /// Request timestamp is too far in the future.
    #[error("production request timestamp in future: skew {skew_millis} ms > max {max_future_skew_millis} ms")]
    ProductionRequestTimestampInFuture {
        /// Перекос в миллисекундах. Future skew in milliseconds.
        skew_millis: u64,
        /// Максимально допустимый перекос. Maximum allowed future skew.
        max_future_skew_millis: u64,
    },

    /// Устройство отсутствует в боевом снимке журнала ключей.
    /// Device is absent from the production key-transparency state snapshot.
    #[error("production device unknown")]
    ProductionDeviceUnknown,

    /// Устройство ещё не было разрешено в момент запроса.
    /// Device was not authorized yet at the request timestamp.
    #[error("production device not active yet: authorized_since {authorized_since_unix_millis} > request {request_timestamp_unix_millis}")]
    ProductionDeviceNotActiveYet {
        /// Когда устройство становится разрешённым. When the device becomes authorized.
        authorized_since_unix_millis: u64,
        /// Время запроса. Request timestamp.
        request_timestamp_unix_millis: u64,
    },
```

- [ ] **Step 2: Add production verification types to backup**

In `crates/umbrella-backup/src/cloud_wrap/signed_request.rs`, after the existing `verify_signed_unwrap_request` function, add:

```rust
/// Разрешённое окно свежести для боевой серверной проверки.
/// Freshness window for production server-side verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionFreshnessPolicy {
    /// Максимальный возраст server nonce. Maximum server nonce age.
    pub max_nonce_age_millis: u64,
    /// Допустимый перекос времени в будущее. Allowed future clock skew.
    pub max_future_skew_millis: u64,
    /// Максимальный возраст timestamp самого запроса. Maximum request timestamp age.
    pub max_request_age_millis: u64,
}

impl Default for ProductionFreshnessPolicy {
    fn default() -> Self {
        Self {
            max_nonce_age_millis: 5 * 60 * 1000,
            max_future_skew_millis: 30 * 1000,
            max_request_age_millis: 5 * 60 * 1000,
        }
    }
}

/// Состояние устройства из серверного снимка журнала ключей.
/// Device state from the server-side key-transparency snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionDeviceState {
    /// Устройства нет в снимке. Device is absent from the snapshot.
    Unknown,
    /// Устройство ждёт подтверждения. Device awaits approval.
    Pending,
    /// Устройство отозвано. Device is revoked.
    Revoked,
    /// Устройство активно. Device is active.
    Active {
        /// Время разрешения устройства. Device authorization time.
        authorized_since_unix_millis: u64,
        /// Граница истории. History cutoff.
        history_cutoff_unix_millis: u64,
    },
    /// Первое активное устройство или восстановление после катастрофы.
    /// First active device or catastrophic-recovery bootstrap.
    BootstrapActive {
        /// Время разрешения устройства. Device authorization time.
        authorized_since_unix_millis: u64,
        /// Граница истории. History cutoff.
        history_cutoff_unix_millis: u64,
    },
}

/// Тип платформенного проверяющего.
/// Platform verifier kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformVerifierKind {
    /// Настоящий проверяющий пока не подключён. Real verifier is not wired yet.
    Unavailable,
    /// Apple App Attest. Apple App Attest.
    AppleAppAttest,
    /// Android Play Integrity. Android Play Integrity.
    AndroidPlayIntegrity,
    /// WebAuthn. WebAuthn.
    WebAuthn,
    /// Только для тестов, запрещён в боевом контексте.
    /// Test-only, rejected in production context.
    TestOnly,
}

/// Вход платформенного проверяющего.
/// Input passed to a platform attestation verifier.
#[derive(Debug, Clone, Copy)]
pub struct PlatformVerificationInput<'a> {
    /// Платформа запроса. Request platform.
    pub platform: Platform,
    /// Байты токена. Token bytes.
    pub token: &'a [u8],
    /// Серверный вызов. Server nonce.
    pub server_nonce: &'a [u8; NONCE_LEN],
    /// Публичный ключ устройства. Device public key.
    pub device_pubkey: &'a [u8; DEVICE_PUBKEY_LEN],
    /// Текущее серверное время. Current server time.
    pub now_unix_millis: u64,
}

/// Платформенный проверяющий для боевого серверного пути.
/// Platform verifier for the production server-side path.
pub trait ProductionPlatformVerifier {
    /// Тип проверяющего. Verifier kind.
    fn kind(&self) -> PlatformVerifierKind;

    /// Проверить платформенный токен.
    /// Verify the platform token.
    ///
    /// # Errors
    /// Возвращает точную причину отказа.
    fn verify_platform_attestation(
        &self,
        input: PlatformVerificationInput<'_>,
    ) -> Result<(), BackupError>;
}

/// Проверяющий, который честно закрывает путь до подключения настоящей платформы.
/// Verifier that fail-closes until real platform validation is wired.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableProductionPlatformVerifier;

impl ProductionPlatformVerifier for UnavailableProductionPlatformVerifier {
    fn kind(&self) -> PlatformVerifierKind {
        PlatformVerifierKind::Unavailable
    }

    fn verify_platform_attestation(
        &self,
        input: PlatformVerificationInput<'_>,
    ) -> Result<(), BackupError> {
        Err(BackupError::ProductionAttestationVerifierUnavailable {
            platform_tag: input.platform.tag(),
        })
    }
}

/// Контекст боевой проверки unwrap-запроса.
/// Production verification context for an unwrap request.
pub struct ProductionUnwrapVerificationContext<'a> {
    expected_server_nonce: [u8; NONCE_LEN],
    server_nonce_issued_at_unix_millis: u64,
    now_unix_millis: u64,
    freshness: ProductionFreshnessPolicy,
    device_state: ProductionDeviceState,
    envelope_timestamp_unix_millis: u64,
    platform_verifier: &'a dyn ProductionPlatformVerifier,
}

impl<'a> ProductionUnwrapVerificationContext<'a> {
    /// Создать боевой контекст.
    /// Create a production context.
    ///
    /// # Errors
    /// - [`BackupError::ProductionTestVerifierRejected`] если передан тестовый проверяющий.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        expected_server_nonce: [u8; NONCE_LEN],
        server_nonce_issued_at_unix_millis: u64,
        now_unix_millis: u64,
        freshness: ProductionFreshnessPolicy,
        device_state: ProductionDeviceState,
        envelope_timestamp_unix_millis: u64,
        platform_verifier: &'a dyn ProductionPlatformVerifier,
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
        })
    }
}
```

- [ ] **Step 3: Add backup contextual verification helpers**

In the same file, after the context implementation, add:

```rust
fn check_production_nonce(
    request_nonce: &[u8; NONCE_LEN],
    expected_nonce: &[u8; NONCE_LEN],
) -> Result<(), BackupError> {
    if request_nonce != expected_nonce {
        return Err(BackupError::ProductionServerNonceMismatch);
    }
    Ok(())
}

fn check_production_freshness(
    request_timestamp_unix_millis: u64,
    nonce_issued_at_unix_millis: u64,
    now_unix_millis: u64,
    freshness: ProductionFreshnessPolicy,
) -> Result<(), BackupError> {
    if nonce_issued_at_unix_millis > now_unix_millis {
        let skew_millis = nonce_issued_at_unix_millis - now_unix_millis;
        if skew_millis > freshness.max_future_skew_millis {
            return Err(BackupError::ProductionServerNonceIssuedInFuture {
                skew_millis,
                max_future_skew_millis: freshness.max_future_skew_millis,
            });
        }
    } else {
        let age_millis = now_unix_millis - nonce_issued_at_unix_millis;
        if age_millis > freshness.max_nonce_age_millis {
            return Err(BackupError::ProductionServerNonceExpired {
                age_millis,
                max_age_millis: freshness.max_nonce_age_millis,
            });
        }
    }

    if request_timestamp_unix_millis > now_unix_millis {
        let skew_millis = request_timestamp_unix_millis - now_unix_millis;
        if skew_millis > freshness.max_future_skew_millis {
            return Err(BackupError::ProductionRequestTimestampInFuture {
                skew_millis,
                max_future_skew_millis: freshness.max_future_skew_millis,
            });
        }
    } else if now_unix_millis - request_timestamp_unix_millis > freshness.max_request_age_millis {
        return Err(BackupError::ProductionServerNonceExpired {
            age_millis: now_unix_millis - request_timestamp_unix_millis,
            max_age_millis: freshness.max_request_age_millis,
        });
    }

    Ok(())
}

fn check_production_device_state(
    state: ProductionDeviceState,
    request_timestamp_unix_millis: u64,
    envelope_timestamp_unix_millis: u64,
) -> Result<(), BackupError> {
    let (authorized_since_unix_millis, history_cutoff_unix_millis) = match state {
        ProductionDeviceState::Unknown => return Err(BackupError::ProductionDeviceUnknown),
        ProductionDeviceState::Pending => return Err(BackupError::DevicePendingAuthorization),
        ProductionDeviceState::Revoked => return Err(BackupError::DeviceRevoked),
        ProductionDeviceState::Active {
            authorized_since_unix_millis,
            history_cutoff_unix_millis,
        }
        | ProductionDeviceState::BootstrapActive {
            authorized_since_unix_millis,
            history_cutoff_unix_millis,
        } => (authorized_since_unix_millis, history_cutoff_unix_millis),
    };

    if authorized_since_unix_millis > request_timestamp_unix_millis {
        return Err(BackupError::ProductionDeviceNotActiveYet {
            authorized_since_unix_millis,
            request_timestamp_unix_millis,
        });
    }

    if history_cutoff_unix_millis > 0 && envelope_timestamp_unix_millis < history_cutoff_unix_millis
    {
        return Err(BackupError::HistoryCutoffApplies {
            envelope_timestamp: envelope_timestamp_unix_millis,
            cutoff: history_cutoff_unix_millis,
        });
    }

    Ok(())
}
```

- [ ] **Step 4: Add the contextual backup production verifier**

After the helpers, add:

```rust
/// Боевая проверка signed unwrap request с серверным контекстом.
/// Production verification for signed unwrap requests with server context.
///
/// Порядок строгий: подпись, nonce, свежесть, устройство, платформа.
/// Strict order: signature, nonce, freshness, device, platform.
///
/// # Errors
/// Возвращает первую причину отказа в указанном порядке.
pub fn verify_signed_unwrap_request_for_production_with_context(
    req: &SignedUnwrapRequest,
    ctx: &ProductionUnwrapVerificationContext<'_>,
) -> Result<(), BackupError> {
    verify_signed_unwrap_request(req)?;
    check_production_nonce(&req.server_nonce, &ctx.expected_server_nonce)?;
    check_production_freshness(
        req.timestamp_unix_millis,
        ctx.server_nonce_issued_at_unix_millis,
        ctx.now_unix_millis,
        ctx.freshness,
    )?;
    check_production_device_state(
        ctx.device_state,
        req.timestamp_unix_millis,
        ctx.envelope_timestamp_unix_millis,
    )?;
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
                })
        }
    }
}
```

Keep the existing `verify_signed_unwrap_request_for_production(req)` function, but replace its body with a compatibility fail-closed wrapper:

```rust
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

- [ ] **Step 5: Re-export backup production verifier types**

In `crates/umbrella-backup/src/cloud_wrap/mod.rs`, extend the existing `pub use signed_request` list with these names:

```rust
    verify_signed_unwrap_request_for_production_with_context, PlatformVerificationInput,
    PlatformVerifierKind, ProductionDeviceState, ProductionFreshnessPolicy,
    ProductionPlatformVerifier, ProductionUnwrapVerificationContext,
    UnavailableProductionPlatformVerifier,
```

- [ ] **Step 6: Run backup tests**

Run:

```bash
cargo test -p umbrella-backup --all-features --locked production_context_
cargo test -p umbrella-backup --all-features --locked
```

Expected: all backup tests pass.

- [ ] **Step 7: Commit backup iteration**

Run:

```bash
git add crates/umbrella-backup/src/error.rs crates/umbrella-backup/src/cloud_wrap/signed_request.rs crates/umbrella-backup/src/cloud_wrap/mod.rs
git commit -m "backup: add production attestation gate"
```

---

## Task 3: OPRF Production Gate Red Tests

**Files:**
- Modify: `crates/umbrella-oprf/src/attestation.rs`

- [ ] **Step 1: Add failing tests for contextual OPRF production verification**

Inside `crates/umbrella-oprf/src/attestation.rs`, in the existing `#[cfg(test)] mod tests`, add these helpers after the existing `sign_with` helper:

```rust
    #[derive(Debug, Default)]
    struct CountingUnavailableVerifier {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl CountingUnavailableVerifier {
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl ProductionPlatformVerifier for CountingUnavailableVerifier {
        fn kind(&self) -> PlatformVerifierKind {
            PlatformVerifierKind::Unavailable
        }

        fn verify_platform_attestation(
            &self,
            input: PlatformVerificationInput<'_>,
        ) -> Result<(), OprfError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(OprfError::ProductionAttestationVerifierUnavailable {
                platform_tag: input.platform.tag(),
            })
        }
    }

    #[derive(Debug, Default)]
    struct TestOnlySuccessVerifier;

    impl ProductionPlatformVerifier for TestOnlySuccessVerifier {
        fn kind(&self) -> PlatformVerifierKind {
            PlatformVerifierKind::TestOnly
        }

        fn verify_platform_attestation(
            &self,
            _input: PlatformVerificationInput<'_>,
        ) -> Result<(), OprfError> {
            Ok(())
        }
    }

    fn production_android_oprf_request(
        sk: &SigningKey,
        vk: &DalekVerifyingKey,
        nonce: [u8; NONCE_LEN],
    ) -> SignedOprfRequest {
        let input = OprfInput::new(b"+15550101010").unwrap();
        let (blinded, _state) = blind(input, &mut OsRng).unwrap();
        let attestation =
            PlatformAttestation::new(Platform::Android, b"play-integrity-token").unwrap();
        let canonical = canonical_signing_input(&blinded, &attestation, &nonce);
        SignedOprfRequest {
            blinded,
            attestation,
            nonce,
            device_signature: sign_with(sk, &canonical),
            device_pubkey: vk.to_bytes(),
        }
    }

    fn active_device_state() -> ProductionDeviceState {
        ProductionDeviceState::Active {
            authorized_since_unix_millis: 1_700_000_000_000,
        }
    }

    fn production_context<'a>(
        verifier: &'a dyn ProductionPlatformVerifier,
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
        )
        .expect("context must be valid for non-test-only verifier")
    }
```

Then add these tests near the existing production policy tests:

```rust
    #[test]
    fn production_context_rejects_test_only_platform_verifier() {
        let nonce = fresh_nonce();
        let err = ProductionOprfVerificationContext::new(
            nonce,
            1_700_000_000_000,
            1_700_000_000_001,
            ProductionFreshnessPolicy::default(),
            active_device_state(),
            &TestOnlySuccessVerifier,
        )
        .unwrap_err();
        assert!(matches!(err, OprfError::ProductionTestVerifierRejected));
    }

    #[test]
    fn production_context_rejects_bad_signature_before_platform_verifier() {
        let (sk, vk) = make_device_keypair();
        let nonce = fresh_nonce();
        let mut signed = production_android_oprf_request(&sk, &vk, nonce);
        signed.device_signature[0] ^= 1;
        let verifier = CountingUnavailableVerifier::default();
        let ctx = production_context(
            &verifier,
            nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            active_device_state(),
        );
        let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();
        assert!(matches!(err, OprfError::CryptoVerificationFailed));
        assert_eq!(verifier.calls(), 0);
    }

    #[test]
    fn production_context_rejects_server_nonce_mismatch() {
        let (sk, vk) = make_device_keypair();
        let request_nonce = fresh_nonce();
        let expected_nonce = fresh_nonce();
        let signed = production_android_oprf_request(&sk, &vk, request_nonce);
        let verifier = CountingUnavailableVerifier::default();
        let ctx = production_context(
            &verifier,
            expected_nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            active_device_state(),
        );
        let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();
        assert!(matches!(err, OprfError::ProductionServerNonceMismatch));
        assert_eq!(verifier.calls(), 0);
    }

    #[test]
    fn production_context_rejects_expired_server_nonce() {
        let (sk, vk) = make_device_keypair();
        let nonce = fresh_nonce();
        let signed = production_android_oprf_request(&sk, &vk, nonce);
        let verifier = CountingUnavailableVerifier::default();
        let ctx = production_context(
            &verifier,
            nonce,
            1_700_000_000_000,
            1_700_000_400_001,
            active_device_state(),
        );
        let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();
        assert!(matches!(err, OprfError::ProductionServerNonceExpired { .. }));
        assert_eq!(verifier.calls(), 0);
    }

    #[test]
    fn production_context_rejects_unknown_pending_and_revoked_devices() {
        let (sk, vk) = make_device_keypair();
        let nonce = fresh_nonce();
        let signed = production_android_oprf_request(&sk, &vk, nonce);
        let verifier = CountingUnavailableVerifier::default();
        for (state, expected) in [
            (ProductionDeviceState::Unknown, "unknown"),
            (ProductionDeviceState::Pending, "pending"),
            (ProductionDeviceState::Revoked, "revoked"),
        ] {
            let ctx = production_context(
                &verifier,
                nonce,
                1_700_000_000_000,
                1_700_000_000_100,
                state,
            );
            let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();
            match expected {
                "unknown" => assert!(matches!(err, OprfError::ProductionDeviceUnknown)),
                "pending" => assert!(matches!(err, OprfError::ProductionDevicePendingAuthorization)),
                "revoked" => assert!(matches!(err, OprfError::ProductionDeviceRevoked)),
                _ => unreachable!(),
            }
        }
        assert_eq!(verifier.calls(), 0);
    }

    #[test]
    fn production_context_active_device_reaches_platform_verifier_fail_closed() {
        let (sk, vk) = make_device_keypair();
        let nonce = fresh_nonce();
        let signed = production_android_oprf_request(&sk, &vk, nonce);
        let verifier = CountingUnavailableVerifier::default();
        let ctx = production_context(
            &verifier,
            nonce,
            1_700_000_000_000,
            1_700_000_000_100,
            active_device_state(),
        );
        let err = verify_signed_request_for_production_with_context(&signed, &ctx).unwrap_err();
        assert!(matches!(
            err,
            OprfError::ProductionAttestationVerifierUnavailable { platform_tag }
                if platform_tag == Platform::Android.tag()
        ));
        assert_eq!(verifier.calls(), 1);
    }
```

- [ ] **Step 2: Run the OPRF red tests**

Run:

```bash
cargo test -p umbrella-oprf --all-features --locked production_context_
```

Expected: compilation fails because the contextual production verifier types and function do not exist yet.

---

## Task 4: OPRF Production Gate Implementation

**Files:**
- Modify: `crates/umbrella-oprf/src/error.rs`
- Modify: `crates/umbrella-oprf/src/attestation.rs`
- Modify: `crates/umbrella-oprf/src/lib.rs`

- [ ] **Step 1: Add precise OPRF error variants**

In `crates/umbrella-oprf/src/error.rs`, after `ProductionAttestationVerifierUnavailable`, add:

```rust
    /// Тестовый платформенный проверяющий нельзя использовать в боевом контексте.
    /// Test-only platform verifier cannot be used in a production context.
    #[error("test-only attestation verifier rejected in production context")]
    ProductionTestVerifierRejected,

    /// Серверный вызов в запросе не совпал с выданным сервером вызовом.
    /// Request server nonce does not match the server-issued nonce.
    #[error("production server nonce mismatch")]
    ProductionServerNonceMismatch,

    /// Серверный вызов старше разрешённого окна свежести.
    /// Server-issued nonce is older than the allowed freshness window.
    #[error("production server nonce expired: age {age_millis} ms > max {max_age_millis} ms")]
    ProductionServerNonceExpired {
        /// Возраст вызова в миллисекундах. Nonce age in milliseconds.
        age_millis: u64,
        /// Максимальный возраст в миллисекундах. Maximum age in milliseconds.
        max_age_millis: u64,
    },

    /// Серверный вызов имеет время выдачи из будущего дальше допустимого перекоса.
    /// Server nonce issue time is too far in the future.
    #[error("production server nonce issued in future: skew {skew_millis} ms > max {max_future_skew_millis} ms")]
    ProductionServerNonceIssuedInFuture {
        /// Перекос в миллисекундах. Future skew in milliseconds.
        skew_millis: u64,
        /// Максимально допустимый перекос. Maximum allowed future skew.
        max_future_skew_millis: u64,
    },

    /// Устройство отсутствует в боевом снимке журнала ключей.
    /// Device is absent from the production key-transparency state snapshot.
    #[error("production device unknown")]
    ProductionDeviceUnknown,

    /// Устройство ожидает подтверждения.
    /// Device awaits approval.
    #[error("production device pending authorization")]
    ProductionDevicePendingAuthorization,

    /// Устройство отозвано.
    /// Device is revoked.
    #[error("production device revoked")]
    ProductionDeviceRevoked,

    /// Устройство ещё не было разрешено в момент выдачи server nonce.
    /// Device was not authorized yet when the server nonce was issued.
    #[error("production device not active yet: authorized_since {authorized_since_unix_millis} > nonce issued at {nonce_issued_at_unix_millis}")]
    ProductionDeviceNotActiveYet {
        /// Когда устройство становится разрешённым. When the device becomes authorized.
        authorized_since_unix_millis: u64,
        /// Когда был выдан nonce. Nonce issue time.
        nonce_issued_at_unix_millis: u64,
    },
```

- [ ] **Step 2: Add OPRF production verification types**

In `crates/umbrella-oprf/src/attestation.rs`, after the existing `verify_signed_request` function, add:

```rust
/// Разрешённое окно свежести для боевой серверной проверки.
/// Freshness window for production server-side verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionFreshnessPolicy {
    /// Максимальный возраст server nonce. Maximum server nonce age.
    pub max_nonce_age_millis: u64,
    /// Допустимый перекос времени в будущее. Allowed future clock skew.
    pub max_future_skew_millis: u64,
}

impl Default for ProductionFreshnessPolicy {
    fn default() -> Self {
        Self {
            max_nonce_age_millis: 5 * 60 * 1000,
            max_future_skew_millis: 30 * 1000,
        }
    }
}

/// Состояние устройства из серверного снимка журнала ключей.
/// Device state from the server-side key-transparency snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionDeviceState {
    /// Устройства нет в снимке. Device is absent from the snapshot.
    Unknown,
    /// Устройство ждёт подтверждения. Device awaits approval.
    Pending,
    /// Устройство отозвано. Device is revoked.
    Revoked,
    /// Устройство активно. Device is active.
    Active {
        /// Время разрешения устройства. Device authorization time.
        authorized_since_unix_millis: u64,
    },
    /// Первое активное устройство или восстановление после катастрофы.
    /// First active device or catastrophic-recovery bootstrap.
    BootstrapActive {
        /// Время разрешения устройства. Device authorization time.
        authorized_since_unix_millis: u64,
    },
}

/// Тип платформенного проверяющего.
/// Platform verifier kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformVerifierKind {
    /// Настоящий проверяющий пока не подключён. Real verifier is not wired yet.
    Unavailable,
    /// Apple App Attest. Apple App Attest.
    AppleAppAttest,
    /// Android Play Integrity. Android Play Integrity.
    AndroidPlayIntegrity,
    /// WebAuthn. WebAuthn.
    WebAuthn,
    /// Только для тестов, запрещён в боевом контексте.
    /// Test-only, rejected in production context.
    TestOnly,
}

/// Вход платформенного проверяющего.
/// Input passed to a platform attestation verifier.
#[derive(Debug, Clone, Copy)]
pub struct PlatformVerificationInput<'a> {
    /// Платформа запроса. Request platform.
    pub platform: Platform,
    /// Байты токена. Token bytes.
    pub token: &'a [u8],
    /// Серверный вызов. Server nonce.
    pub server_nonce: &'a [u8; NONCE_LEN],
    /// Публичный ключ устройства. Device public key.
    pub device_pubkey: &'a [u8; DEVICE_PUBKEY_LEN],
    /// Текущее серверное время. Current server time.
    pub now_unix_millis: u64,
}

/// Платформенный проверяющий для боевого серверного пути.
/// Platform verifier for the production server-side path.
pub trait ProductionPlatformVerifier {
    /// Тип проверяющего. Verifier kind.
    fn kind(&self) -> PlatformVerifierKind;

    /// Проверить платформенный токен.
    /// Verify the platform token.
    ///
    /// # Errors
    /// Возвращает точную причину отказа.
    fn verify_platform_attestation(
        &self,
        input: PlatformVerificationInput<'_>,
    ) -> Result<(), OprfError>;
}

/// Проверяющий, который честно закрывает путь до подключения настоящей платформы.
/// Verifier that fail-closes until real platform validation is wired.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableProductionPlatformVerifier;

impl ProductionPlatformVerifier for UnavailableProductionPlatformVerifier {
    fn kind(&self) -> PlatformVerifierKind {
        PlatformVerifierKind::Unavailable
    }

    fn verify_platform_attestation(
        &self,
        input: PlatformVerificationInput<'_>,
    ) -> Result<(), OprfError> {
        Err(OprfError::ProductionAttestationVerifierUnavailable {
            platform_tag: input.platform.tag(),
        })
    }
}

/// Контекст боевой проверки OPRF-запроса.
/// Production verification context for an OPRF request.
pub struct ProductionOprfVerificationContext<'a> {
    expected_server_nonce: [u8; NONCE_LEN],
    server_nonce_issued_at_unix_millis: u64,
    now_unix_millis: u64,
    freshness: ProductionFreshnessPolicy,
    device_state: ProductionDeviceState,
    platform_verifier: &'a dyn ProductionPlatformVerifier,
}

impl<'a> ProductionOprfVerificationContext<'a> {
    /// Создать боевой контекст.
    /// Create a production context.
    ///
    /// # Errors
    /// - [`OprfError::ProductionTestVerifierRejected`] если передан тестовый проверяющий.
    pub fn new(
        expected_server_nonce: [u8; NONCE_LEN],
        server_nonce_issued_at_unix_millis: u64,
        now_unix_millis: u64,
        freshness: ProductionFreshnessPolicy,
        device_state: ProductionDeviceState,
        platform_verifier: &'a dyn ProductionPlatformVerifier,
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
        })
    }
}
```

- [ ] **Step 3: Add OPRF contextual verification helpers**

In the same file, after the context implementation, add:

```rust
fn check_production_nonce(
    request_nonce: &[u8; NONCE_LEN],
    expected_nonce: &[u8; NONCE_LEN],
) -> Result<(), OprfError> {
    if request_nonce != expected_nonce {
        return Err(OprfError::ProductionServerNonceMismatch);
    }
    Ok(())
}

fn check_production_freshness(
    nonce_issued_at_unix_millis: u64,
    now_unix_millis: u64,
    freshness: ProductionFreshnessPolicy,
) -> Result<(), OprfError> {
    if nonce_issued_at_unix_millis > now_unix_millis {
        let skew_millis = nonce_issued_at_unix_millis - now_unix_millis;
        if skew_millis > freshness.max_future_skew_millis {
            return Err(OprfError::ProductionServerNonceIssuedInFuture {
                skew_millis,
                max_future_skew_millis: freshness.max_future_skew_millis,
            });
        }
    } else {
        let age_millis = now_unix_millis - nonce_issued_at_unix_millis;
        if age_millis > freshness.max_nonce_age_millis {
            return Err(OprfError::ProductionServerNonceExpired {
                age_millis,
                max_age_millis: freshness.max_nonce_age_millis,
            });
        }
    }
    Ok(())
}

fn check_production_device_state(
    state: ProductionDeviceState,
    nonce_issued_at_unix_millis: u64,
) -> Result<(), OprfError> {
    let authorized_since_unix_millis = match state {
        ProductionDeviceState::Unknown => return Err(OprfError::ProductionDeviceUnknown),
        ProductionDeviceState::Pending => return Err(OprfError::ProductionDevicePendingAuthorization),
        ProductionDeviceState::Revoked => return Err(OprfError::ProductionDeviceRevoked),
        ProductionDeviceState::Active {
            authorized_since_unix_millis,
        }
        | ProductionDeviceState::BootstrapActive {
            authorized_since_unix_millis,
        } => authorized_since_unix_millis,
    };

    if authorized_since_unix_millis > nonce_issued_at_unix_millis {
        return Err(OprfError::ProductionDeviceNotActiveYet {
            authorized_since_unix_millis,
            nonce_issued_at_unix_millis,
        });
    }

    Ok(())
}
```

- [ ] **Step 4: Add the contextual OPRF production verifier**

After the helpers, add:

```rust
/// Боевая проверка подписанного OPRF-запроса с серверным контекстом.
/// Production verification for signed OPRF requests with server context.
///
/// Порядок строгий: подпись, nonce, свежесть, устройство, платформа.
/// Strict order: signature, nonce, freshness, device, platform.
///
/// # Errors
/// Возвращает первую причину отказа в указанном порядке.
pub fn verify_signed_request_for_production_with_context(
    req: &SignedOprfRequest,
    ctx: &ProductionOprfVerificationContext<'_>,
) -> Result<(), OprfError> {
    verify_signed_request(req)?;
    check_production_nonce(&req.nonce, &ctx.expected_server_nonce)?;
    check_production_freshness(
        ctx.server_nonce_issued_at_unix_millis,
        ctx.now_unix_millis,
        ctx.freshness,
    )?;
    check_production_device_state(ctx.device_state, ctx.server_nonce_issued_at_unix_millis)?;
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
                })
        }
    }
}
```

Keep the existing `verify_signed_request_for_production(req)` function as a fail-closed compatibility wrapper.

- [ ] **Step 5: Re-export OPRF production verifier types**

In `crates/umbrella-oprf/src/lib.rs`, extend the existing `pub use attestation` list with these names:

```rust
    verify_signed_request_for_production_with_context, PlatformVerificationInput,
    PlatformVerifierKind, ProductionDeviceState, ProductionFreshnessPolicy,
    ProductionOprfVerificationContext, ProductionPlatformVerifier,
    UnavailableProductionPlatformVerifier,
```

- [ ] **Step 6: Run OPRF tests**

Run:

```bash
cargo test -p umbrella-oprf --all-features --locked production_context_
cargo test -p umbrella-oprf --all-features --locked
```

Expected: all OPRF tests pass.

- [ ] **Step 7: Commit OPRF iteration**

Run:

```bash
git add crates/umbrella-oprf/src/error.rs crates/umbrella-oprf/src/attestation.rs crates/umbrella-oprf/src/lib.rs
git commit -m "oprf: add production attestation gate"
```

---

## Task 5: Public Truth And Historical Plan Cleanup

**Files:**
- Modify: `docs/security/production-readiness-boundaries.md`
- Modify: `docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase1.md`
- Modify: `docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase2.md`
- Modify: `README.md` only if wording still says the server-side attestation gate is absent rather than contextual and fail-closed.
- Modify: `docs/README.md` only if wording still says the server-side attestation gate is absent rather than contextual and fail-closed.
- Modify: `docs/security/release-manifest-v1.0.0.txt` only if wording still says the server-side attestation gate is absent rather than contextual and fail-closed.

- [ ] **Step 1: Update production readiness boundary**

In `docs/security/production-readiness-boundaries.md`, replace the English attestation bullet with:

```markdown
- Attestation: `Platform::Testing` is rejected by production verifiers. The
  server-side production gate now checks signature, server nonce, freshness,
  device state, and platform verifier ordering for cloud unwrap and OPRF.
  iOS, Android, and Web token verification still fail closed until their real
  platform verifiers are wired.
```

Replace the Russian attestation bullet with:

```markdown
- Attestation: `Platform::Testing` отвергается боевыми проверяющими. Серверная
  боевая дверь теперь проверяет подпись, серверный вызов, свежесть, состояние
  устройства и порядок вызова платформенного проверяющего для развёртки
  облачного ключа и OPRF. iOS, Android и Web всё ещё закрыто отказывают, пока
  не подключены настоящие платформенные проверяющие.
```

- [ ] **Step 2: Mark old Phase 1 plan as historical**

At the top of `docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase1.md`, after the heading, add:

```markdown
> Historical note, 2026-05-13: this file is a planning record, not the current
> active checklist. Later commits implemented and superseded the listed Phase 1
> items. Current production boundaries live in
> `docs/security/production-readiness-boundaries.md`.
```

- [ ] **Step 3: Mark old Phase 2 plan as historical**

At the top of `docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase2.md`, after the heading, add:

```markdown
> Historical note, 2026-05-13: this file is a planning record, not the current
> active checklist. Transport pinning was later completed in
> `docs/superpowers/plans/2026-05-13-production-transport-pinning.md`; current
> production boundaries live in `docs/security/production-readiness-boundaries.md`.
```

- [ ] **Step 4: Run documentation checks**

Run:

```bash
bash scripts/audit-public-access-notices.sh
rg -n "production TLS pinning verifier is not wired|transport pinning, production attestation verification, mobile bridges" docs README.md
```

Expected:

- public access audit prints `public access notices OK`;
- the `rg` command may still find historical plan records, but must not find stale current status wording in `README.md`, `docs/README.md`, `docs/security/production-readiness-boundaries.md`, or `docs/security/release-manifest-v1.0.0.txt`.

- [ ] **Step 5: Commit documentation iteration**

Run:

```bash
git add docs/security/production-readiness-boundaries.md docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase1.md docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase2.md README.md docs/README.md docs/security/release-manifest-v1.0.0.txt
git commit -m "docs: record production attestation gate boundary"
```

If `README.md`, `docs/README.md`, or `docs/security/release-manifest-v1.0.0.txt` were unchanged, `git add` still succeeds and the commit will include only changed files.

---

## Task 6: Focused Verification

**Files:**
- No source edits unless a verification command exposes a real issue.

- [ ] **Step 1: Run focused package checks**

Run:

```bash
cargo test -p umbrella-backup --all-features --locked production_context_
cargo test -p umbrella-oprf --all-features --locked production_context_
cargo test -p umbrella-backup --all-features --locked
cargo test -p umbrella-oprf --all-features --locked
```

Expected: all pass.

- [ ] **Step 2: Run client and FFI guard checks**

Run:

```bash
cargo test -p umbrella-client --all-features --locked attestation
cargo test -p umbrella-ffi public_bootstrap --locked
cargo test -p umbrella-ffi public_bootstrap --features pq --locked
```

Expected:

- client attestation tests pass;
- public FFI bootstrap still fails closed;
- public FFI error still names production attestation, mobile bridge, and server integration gates.

- [ ] **Step 3: Run style and docs gates**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
bash scripts/audit-public-access-notices.sh
```

Expected: all commands exit 0.

- [ ] **Step 4: Commit verification record if docs changed**

If any status document needs an evidence note, update the relevant document and commit:

```bash
git add docs
git commit -m "docs: record attestation gate verification"
```

If no files changed, do not create an empty commit.

---

## Task 7: Full Release Gate

**Files:**
- No source edits unless the full gate exposes a real issue.

- [ ] **Step 1: Run full workspace tests**

Run:

```bash
cargo test --workspace --all-features --locked
```

Expected: all tests and doc-tests pass. The sealed-sender 100k random-input test may run for several minutes.

- [ ] **Step 2: Confirm clean branch**

Run:

```bash
git status --short --branch
git log --oneline -8
```

Expected:

- branch is `codex/production-attestation-gate`;
- no uncommitted files;
- latest commits include backup, OPRF, docs, and optional verification commits.

- [ ] **Step 3: Summarize remaining production blockers**

Final status must state in plain Russian:

- server-side attestation gate is stricter and contextual;
- real Apple App Attest, Android Play Integrity, and WebAuthn token verification are still closed until separate phases;
- public FFI bootstrap remains closed;
- mobile bridges and real server deployment remain future gates.

Do not say the whole system is production-ready.
