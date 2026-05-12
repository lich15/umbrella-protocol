//! Integration-тесты attestation callback + async sealing helper.
//!
//! Фокус: сквозные сценарии, пересекающие границы модулей
//! `umbrella_client::attestation` ↔ `umbrella_backup::cloud_wrap::signed_request`
//! ↔ `ed25519_dalek`. Unit-тесты на [`StaticTestAttestationProvider`] и
//! wrap-err проверки — в модульных `#[cfg(test)]` secциях
//! `attestation::provider_trait` и `attestation::unwrap_sealing` соответственно.
//!
//! Integration tests for the attestation callback plus the async sealing
//! helper. These cover end-to-end scenarios crossing
//! `umbrella_client::attestation` ↔
//! `umbrella_backup::cloud_wrap::signed_request` ↔ `ed25519_dalek`. Unit
//! coverage for [`StaticTestAttestationProvider`] and error-wrapping paths
//! lives in the module-local `#[cfg(test)]` sections of
//! `attestation::provider_trait` and `attestation::unwrap_sealing`.

use std::sync::Arc;

use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use umbrella_backup::cloud_wrap::signed_request::{
    verify_signed_unwrap_request, SIGNED_UNWRAP_REQUEST_FIXED_LEN,
};
use umbrella_client::{
    seal_unwrap_request_with_async_attestation, AttestationError, AttestationProvider, ClientError,
    Platform, PlatformAttestation, StaticTestAttestationProvider,
};

fn fresh_server_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    OsRng.fill_bytes(&mut n);
    n
}

fn fresh_signing_key() -> SigningKey {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    SigningKey::from_bytes(&secret)
}

#[tokio::test]
async fn arc_dyn_provider_end_to_end_signs_verifiable_unwrap_request() {
    // `Arc<dyn AttestationProvider + Send + Sync>` — в точности то, что
    // держит `ClientCore::attestation` в SPEC-12 §A.6 / design §4.4. Тест
    // гарантирует, что helper принимает такую обёртку (coerce &*arc в
    // &dyn AttestationProvider работает без явных casts).
    let provider: Arc<dyn AttestationProvider + Send + Sync> = Arc::new(
        StaticTestAttestationProvider::new(Platform::IOs, b"ios-harness-integration-".to_vec()),
    );
    let sk = fresh_signing_key();
    let vk = sk.verifying_key();
    let server_nonce = fresh_server_nonce();

    let req = seal_unwrap_request_with_async_attestation(
        [0xAAu8; 32],
        [0x33u8; 32],
        [0x22u8; 32],
        1_700_000_000_000u64,
        server_nonce,
        provider.as_ref(),
        |payload| Ok(sk.sign(payload).to_bytes()),
        vk.to_bytes(),
    )
    .await
    .expect("end-to-end sealing must succeed");

    // Provider metadata must propagate into wire-format.
    assert_eq!(req.attestation.platform, Platform::IOs);
    assert_eq!(req.server_nonce, server_nonce);
    assert_eq!(req.device_pubkey, vk.to_bytes());

    // Verify Ed25519 signature over canonical input — full round-trip that
    // Sealed Server would perform on receipt.
    verify_signed_unwrap_request(&req).expect("signature must verify");

    // Wire-format bytes include the fixed part plus token length.
    let wire = req.to_bytes();
    assert!(wire.len() >= SIGNED_UNWRAP_REQUEST_FIXED_LEN);
    assert_eq!(
        wire.len(),
        SIGNED_UNWRAP_REQUEST_FIXED_LEN + req.attestation.token.len()
    );
}

#[tokio::test]
async fn custom_async_provider_can_plug_into_helper() {
    /// Тестовый провайдер, имитирующий async-вызов с tokio::yield_now — этим
    /// проверяем, что await-точка внутри helper'а сохраняется и не
    /// блокирует исполнитель.
    ///
    /// Test provider that fakes an async call by yielding once. Ensures the
    /// helper's await point is preserved and does not block the executor.
    struct YieldingProvider {
        platform: Platform,
    }

    #[async_trait]
    impl AttestationProvider for YieldingProvider {
        async fn fresh_token(
            &self,
            server_nonce: [u8; 32],
        ) -> Result<PlatformAttestation, AttestationError> {
            tokio::task::yield_now().await;
            let mut token = b"yield-prefix-".to_vec();
            token.extend_from_slice(&server_nonce);
            PlatformAttestation::new(self.platform, &token)
                .map_err(|e| AttestationError::InvalidShape(format!("{e}")))
        }

        fn platform(&self) -> Platform {
            self.platform
        }
    }

    let provider = YieldingProvider {
        platform: Platform::Android,
    };
    let sk = fresh_signing_key();
    let vk = sk.verifying_key();

    let req = seal_unwrap_request_with_async_attestation(
        [0xBBu8; 32],
        [0x44u8; 32],
        [0x11u8; 32],
        1_700_000_000_500u64,
        fresh_server_nonce(),
        &provider,
        |payload| Ok(sk.sign(payload).to_bytes()),
        vk.to_bytes(),
    )
    .await
    .expect("yielding provider must not break the helper");

    assert_eq!(req.attestation.platform, Platform::Android);
    verify_signed_unwrap_request(&req).expect("signature valid");
}

#[tokio::test]
async fn provider_errors_surface_as_client_error_attestation() {
    /// Провайдер, всегда возвращающий `AppNotEligible` — permanent error,
    /// не retriable. Проверяем, что `?` оператор правильно конвертирует
    /// `AttestationError` → `ClientError::Attestation(_)` сохраняя variant.
    ///
    /// Provider that always returns `AppNotEligible` — a permanent,
    /// non-retriable error. Verifies that the `?` operator converts
    /// `AttestationError` → `ClientError::Attestation(_)` preserving the
    /// variant.
    struct NotEligible;

    #[async_trait]
    impl AttestationProvider for NotEligible {
        async fn fresh_token(
            &self,
            _server_nonce: [u8; 32],
        ) -> Result<PlatformAttestation, AttestationError> {
            Err(AttestationError::AppNotEligible)
        }

        fn platform(&self) -> Platform {
            Platform::IOs
        }
    }

    let sk = fresh_signing_key();
    let vk = sk.verifying_key();

    let err = seal_unwrap_request_with_async_attestation(
        [0xCCu8; 32],
        [0x55u8; 32],
        [0x66u8; 32],
        1_700_000_001_000u64,
        fresh_server_nonce(),
        &NotEligible,
        |_| panic!("signer must not run when provider fails upstream"),
        vk.to_bytes(),
    )
    .await
    .expect_err("provider failure must propagate");

    match err {
        ClientError::Attestation(AttestationError::AppNotEligible) => {}
        other => panic!("expected ClientError::Attestation(AppNotEligible), got {other:?}"),
    }
}

#[tokio::test]
async fn different_nonces_yield_distinct_wire_bytes() {
    // Server-issued nonce участвует в canonical signing input и в token
    // payload — значит два запроса с разными nonce должны дать разные
    // wire-bytes вплоть до сигнатуры. Это инвариант freshness: replay
    // вcтарых запросов невозможен.
    //
    // Server-issued nonce participates in both canonical signing input and
    // the token payload — two requests with distinct nonces must produce
    // distinct wire bytes all the way through the signature. This is the
    // freshness invariant that prevents replay of old requests.
    let provider = StaticTestAttestationProvider::new(Platform::Testing, b"freshness-".to_vec());
    let sk = fresh_signing_key();
    let vk = sk.verifying_key();

    let vk_bytes = vk.to_bytes();
    let make_request = |nonce: [u8; 32]| {
        let sk = sk.clone();
        let provider = provider.clone();
        async move {
            seal_unwrap_request_with_async_attestation(
                [0xDDu8; 32],
                [0x77u8; 32],
                [0x99u8; 32],
                1_700_000_002_000u64,
                nonce,
                &provider,
                |payload| Ok(sk.sign(payload).to_bytes()),
                vk_bytes,
            )
            .await
            .expect("seal must succeed")
        }
    };

    let a = make_request([0x01u8; 32]).await;
    let b = make_request([0x02u8; 32]).await;

    assert_ne!(a.server_nonce, b.server_nonce);
    assert_ne!(
        a.attestation.token.as_slice(),
        b.attestation.token.as_slice()
    );
    assert_ne!(a.device_signature, b.device_signature);
    assert_ne!(a.to_bytes(), b.to_bytes());
}
