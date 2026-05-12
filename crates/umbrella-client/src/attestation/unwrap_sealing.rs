//! Async sealing helper для `SignedUnwrapRequest`, работающий с
//! [`AttestationProvider`] (async).
//!
//! `umbrella-backup::cloud_wrap::signed_request::seal_unwrap_request` —
//! **синхронная** функция: она принимает `&dyn AttestationProvider` (sync
//! trait в umbrella-backup) и зовёт `attestation_provider.fresh_token(&nonce)`
//! прямо на вызывающем потоке. Для uniffi FFI-callback (native Swift/Kotlin
//! через `DCAppAttestService` / `IntegrityManager`) вызов async по
//! определению, блокировать его через `tokio::task::block_in_place` +
//! `runtime_handle.block_on` небезопасно:
//!
//! 1. Паника на single-threaded `tokio::runtime` (постулат 14 запрещает
//!    panics в библиотеке).
//! 2. Возможная deadlock-картина при вложенных Runtime-активациях.
//!
//! Вместо адаптера делаем симметричную async-версию: фаза getting token —
//! `await`, фаза signing и wire-сборки — sync (копия того же алгоритма что
//! в `seal_unwrap_request`, но в client-crate, с `ClientError`).
//! Параллель — `AsyncUnwrapTransport` в блоке 7.4 (Вариант C в TODO.md).
//!
//! Async sealing helper for `SignedUnwrapRequest` that works with the async
//! [`AttestationProvider`].
//!
//! `umbrella-backup::cloud_wrap::signed_request::seal_unwrap_request` is a
//! **synchronous** function: it takes `&dyn AttestationProvider` (the sync
//! trait in umbrella-backup) and calls `attestation_provider.fresh_token(&nonce)`
//! on the caller's thread. For a uniffi FFI callback (native Swift/Kotlin via
//! `DCAppAttestService` / `IntegrityManager`) the call is inherently async;
//! bridging it through `tokio::task::block_in_place` +
//! `runtime_handle.block_on` is unsafe:
//!
//! 1. Panics on a single-threaded `tokio::runtime` (Postulate 14 forbids
//!    library panics).
//! 2. Possible deadlock on nested runtime activations.
//!
//! Instead we provide a symmetric async version: obtaining the token is
//! `await`, signing and wire assembly are sync (a copy of the
//! `seal_unwrap_request` algorithm, but in the client crate with
//! `ClientError`). Mirrors `AsyncUnwrapTransport` from Block 7.4 (Variant C in
//! TODO.md).

use umbrella_backup::cloud_wrap::signed_request::{canonical_signing_input, SignedUnwrapRequest};

use crate::attestation::provider_trait::AttestationProvider;
use crate::error::ClientError;

/// Async-аналог
/// [`umbrella_backup::cloud_wrap::signed_request::seal_unwrap_request`],
/// использующий async [`AttestationProvider`].
///
/// Алгоритм:
/// 1. `provider.fresh_token(server_nonce).await` → `PlatformAttestation`.
/// 2. `canonical_signing_input(...)` — sync, собирает байт-последовательность
///    под подпись (domain separator + wire version + поля + token).
/// 3. `signer(canonical_pre_image)` — sync callback, возвращает Ed25519 64-byte
///    signature. Signer остаётся sync т.к. production путь через
///    `umbrella-identity::KeyStore::sign_with_device` — synchronous API
///    (hardware-backed signing на стороне FFI-bridge'а в umbrella-ffi);
///    любая async-работа для обращения к Secure Enclave / StrongBox
///    происходит внутри native-реализации, не пересекая Rust async границу.
/// 4. Вернуть `SignedUnwrapRequest` готовый к сериализации через
///    [`SignedUnwrapRequest::to_bytes`] и отправке через
///    [`crate::transport::async_unwrap::AsyncUnwrapTransport::dispatch`].
///
/// Ошибки attestation конвертируются в [`ClientError::Attestation`] через
/// `#[from]`. Ошибки signer'а пробрасываются как есть (signer уже возвращает
/// `Result<_, ClientError>`).
///
/// # Errors
/// - [`ClientError::Attestation`] если провайдер не смог выдать token.
/// - Любой `ClientError` возвращённый signer-callback'ом (например
///   [`ClientError::Platform`] при недоступности Secure Enclave).
///
/// Async counterpart of
/// [`umbrella_backup::cloud_wrap::signed_request::seal_unwrap_request`] that
/// uses the async [`AttestationProvider`].
///
/// Algorithm:
/// 1. `provider.fresh_token(server_nonce).await` → `PlatformAttestation`.
/// 2. `canonical_signing_input(...)` — sync, builds the byte sequence to be
///    signed (domain separator + wire version + fields + token).
/// 3. `signer(canonical_pre_image)` — sync callback returning the 64-byte
///    Ed25519 signature. The signer stays sync because production routes
///    through `umbrella-identity::KeyStore::sign_with_device` — a synchronous
///    API (hardware-backed signing on the FFI bridge in umbrella-ffi); any
///    async work to reach Secure Enclave / StrongBox happens inside the native
///    implementation and does not cross the Rust async boundary.
/// 4. Return the `SignedUnwrapRequest` ready to be serialized via
///    [`SignedUnwrapRequest::to_bytes`] and dispatched via
///    [`crate::transport::async_unwrap::AsyncUnwrapTransport::dispatch`].
///
/// Attestation errors are converted to [`ClientError::Attestation`] via
/// `#[from]`. Signer errors are returned unchanged (the signer already returns
/// `Result<_, ClientError>`).
///
/// # Errors
/// - [`ClientError::Attestation`] if the provider could not issue a token.
/// - Any `ClientError` returned by the signer callback (e.g.
///   [`ClientError::Platform`] when the Secure Enclave is unavailable).
#[allow(clippy::too_many_arguments)]
pub async fn seal_unwrap_request_with_async_attestation<F>(
    ephemeral_r: [u8; 32],
    chat_id: [u8; 32],
    recipient_device_pubkey: [u8; 32],
    timestamp_unix_millis: u64,
    server_nonce: [u8; 32],
    attestation_provider: &(dyn AttestationProvider + '_),
    signer: F,
    device_pubkey_bytes: [u8; 32],
) -> Result<SignedUnwrapRequest, ClientError>
where
    F: FnOnce(&[u8]) -> Result<[u8; 64], ClientError>,
{
    let attestation = attestation_provider.fresh_token(server_nonce).await?;
    let canonical = canonical_signing_input(
        &ephemeral_r,
        &chat_id,
        &recipient_device_pubkey,
        timestamp_unix_millis,
        &server_nonce,
        &attestation,
    );
    let signature = signer(&canonical)?;
    Ok(SignedUnwrapRequest {
        ephemeral_r,
        chat_id,
        recipient_device_pubkey,
        timestamp_unix_millis,
        server_nonce,
        attestation,
        device_signature: signature,
        device_pubkey: device_pubkey_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::provider_trait::{
        AttestationError, AttestationProvider, Platform, StaticTestAttestationProvider,
    };
    use async_trait::async_trait;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};
    use umbrella_backup::cloud_wrap::signed_request::{
        verify_signed_unwrap_request, PlatformAttestation,
    };

    fn fresh_nonce() -> [u8; 32] {
        let mut n = [0u8; 32];
        OsRng.fill_bytes(&mut n);
        n
    }

    fn fresh_device_keypair() -> SigningKey {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        SigningKey::from_bytes(&secret)
    }

    #[tokio::test]
    async fn seal_with_async_attestation_produces_verifiable_request() {
        let sk = fresh_device_keypair();
        let vk = sk.verifying_key();
        let provider =
            StaticTestAttestationProvider::new(Platform::Testing, b"test-prefix".to_vec());
        let nonce = fresh_nonce();

        let req = seal_unwrap_request_with_async_attestation(
            [0xAAu8; 32],
            [0x33u8; 32],
            [0x22u8; 32],
            1_700_000_000_000u64,
            nonce,
            &provider,
            |payload| {
                let sig = sk.sign(payload);
                Ok(sig.to_bytes())
            },
            vk.to_bytes(),
        )
        .await
        .expect("seal must succeed on happy path");

        assert_eq!(req.server_nonce, nonce);
        assert_eq!(req.attestation.platform, Platform::Testing);
        verify_signed_unwrap_request(&req).expect("signature must verify after async sealing");
    }

    #[tokio::test]
    async fn seal_with_async_attestation_propagates_provider_error() {
        /// Provider который всегда возвращает `ServiceUnavailable`.
        /// Provider that always returns `ServiceUnavailable`.
        struct AlwaysUnavailable;

        #[async_trait]
        impl AttestationProvider for AlwaysUnavailable {
            async fn fresh_token(
                &self,
                _server_nonce: [u8; 32],
            ) -> Result<PlatformAttestation, AttestationError> {
                Err(AttestationError::ServiceUnavailable)
            }

            fn platform(&self) -> Platform {
                Platform::IOs
            }
        }

        let sk = fresh_device_keypair();
        let vk = sk.verifying_key();
        let err = seal_unwrap_request_with_async_attestation(
            [0xAAu8; 32],
            [0x33u8; 32],
            [0x22u8; 32],
            1_700_000_000_000u64,
            fresh_nonce(),
            &AlwaysUnavailable,
            |_| panic!("signer must not be called when provider fails"),
            vk.to_bytes(),
        )
        .await
        .expect_err("provider error must propagate");
        assert!(
            matches!(
                err,
                ClientError::Attestation(AttestationError::ServiceUnavailable)
            ),
            "expected ClientError::Attestation(ServiceUnavailable), got {err:?}"
        );
    }

    #[tokio::test]
    async fn seal_with_async_attestation_propagates_signer_error() {
        let provider = StaticTestAttestationProvider::new(Platform::Android, b"and-".to_vec());
        let err = seal_unwrap_request_with_async_attestation(
            [0xAAu8; 32],
            [0x33u8; 32],
            [0x22u8; 32],
            1_700_000_000_000u64,
            fresh_nonce(),
            &provider,
            |_| Err(ClientError::Platform("enclave unavailable".to_string())),
            [0u8; 32],
        )
        .await
        .expect_err("signer error must propagate");
        match &err {
            ClientError::Platform(msg) => assert_eq!(msg, "enclave unavailable"),
            other => panic!("expected ClientError::Platform, got {other:?}"),
        }
    }
}
