//! F-CLIENT-FACADE-1 closure session 10d (2026-05-19): contract tests for
//! SFrame multi-party media encryption (RFC 9605) wire-up at `CallSession`
//! facade. Fourth piece of session 10 milestone closure.
//!
//! ## Scope reordering
//!
//! Original 10d plan was "SRTP encrypt/decrypt (webrtc-srtp integration)";
//! reordered to **SFrame integration** for this sub-block since the
//! `umbrella-calls::sframe` primitives are fully implemented (RFC 9605
//! complete) и facade-level wire-up is mechanical glue, while
//! webrtc-srtp integration requires non-trivial DTLS handshake driving
//! coupling (deferred to a later session).
//!
//! ## What's wired
//!
//! `CallSession` now owns `sframe_context: Arc<Mutex<SframeContext>>`
//! and exposes 4 public methods:
//!
//! 1. `install_sframe_epoch(mls_exporter_output, ciphersuite, epoch)` —
//!    HKDF-Extract'es the MLS exporter into an `SframeBaseKey` and
//!    advances the SFrame context. Up to 3 epochs cached for graceful
//!    overlap during MLS commits.
//! 2. `sframe_current_epoch() -> Option<u64>` — gate / diagnostic.
//! 3. `sframe_encrypt_frame(sender_leaf, counter, plaintext) ->
//!    Result<Vec<u8>>` — RFC 9605 wire format `header || ct || tag`.
//! 4. `sframe_decrypt_frame(bytes) -> Result<DecryptedFrame>` —
//!    replay-check + AEAD verify; returns plaintext с parsed metadata.
//!
//! ## Coverage (8 scenarios)
//!
//! 1. `sframe_current_epoch()` is `None` on a freshly-constructed
//!    session (no MLS exporter installed yet).
//! 2. `install_sframe_epoch()` then `sframe_current_epoch()` returns
//!    the installed epoch.
//! 3. `sframe_encrypt_frame` before any epoch installed →
//!    `CallError::MlsExporterUnavailable`.
//! 4. Encrypt → decrypt round-trip yields the original plaintext.
//! 5. Decrypt of tampered ciphertext → `CallError::AeadAuthFailure`.
//! 6. Replay (decrypting same counter twice) → `CallError::Replay`.
//! 7. Installing a second epoch keeps both reachable (decrypt for
//!    older epoch still works pre-eviction).
//! 8. Decrypt for an evicted epoch (4th install kicks out the 1st) →
//!    `CallError::StaleEpoch`.

use std::sync::Arc;

use async_trait::async_trait;
use rand::rngs::OsRng;

use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_calls::sframe::ciphersuite::SframeCiphersuite;
use umbrella_calls::{CallError, CallPolicy};

use umbrella_client::call::{
    CallSession, MediaError, MediaFrame, MediaSink, MediaSource, ModeEnforcement,
};
use umbrella_client::error::ClientError;
use umbrella_client::facade::chat_common::{PeerId, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT};
use umbrella_client::{ClientConfig, ClientCore};

use umbrella_identity::{IdentitySeed, MnemonicLanguage};

fn test_config() -> ClientConfig {
    ClientConfig {
        sealed_server_urls: (1..=5).map(|i| format!("http://stub-{i}:8080")).collect(),
        postman_url: "http://stub-postman:8080".into(),
        kt_url: "http://stub-kt:8080".into(),
        call_relay_url: "http://stub-call-relay:8080".into(),
        kt_monitor_interval_secs: 3600,
        wrapping_params: WrappingParams {
            version: 0x01,
            main_pubkey: [0u8; 32],
            server_pubkeys: [[0u8; 32]; 5],
            config: ThresholdConfig::new(3, 5).expect("3-of-5"),
        },
        default_ciphersuite: UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
    }
}

#[allow(deprecated, reason = "test seed pattern")]
fn test_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

struct NullSource;
#[async_trait]
impl MediaSource for NullSource {
    async fn pull_audio_frame(&self) -> Result<MediaFrame, MediaError> {
        Err(MediaError::Native("test".into()))
    }
    async fn pull_video_frame(&self) -> Result<MediaFrame, MediaError> {
        Err(MediaError::Native("test".into()))
    }
}

struct NullSink;
#[async_trait]
impl MediaSink for NullSink {
    async fn push_audio_frame(&self, _: MediaFrame) -> Result<(), MediaError> {
        Ok(())
    }
    async fn push_video_frame(&self, _: MediaFrame) -> Result<(), MediaError> {
        Ok(())
    }
}

async fn fresh_session() -> CallSession {
    let core = ClientCore::new_for_test(test_config(), test_seed())
        .await
        .expect("new_for_test");
    CallSession::start_with_enforcement(
        core,
        PeerId([0x99; 32]),
        CallPolicy::default(),
        ModeEnforcement::CloudMode,
        Arc::new(NullSource),
        Arc::new(NullSink),
    )
    .await
    .expect("start_with_enforcement")
}

const TEST_EXPORTER_1: [u8; 64] = [0xAAu8; 64];
const TEST_EXPORTER_2: [u8; 64] = [0xBBu8; 64];

// ============================================================================
// 1. Pre-install: no epoch
// ============================================================================

#[tokio::test]
async fn sframe_current_epoch_is_none_before_install() {
    let session = fresh_session().await;
    assert!(
        session.sframe_current_epoch().await.is_none(),
        "freshly constructed session has no SFrame epoch"
    );
}

// ============================================================================
// 2. install_sframe_epoch → current_epoch returns installed value
// ============================================================================

#[tokio::test]
async fn install_sframe_epoch_then_current_epoch_returns_installed_value() {
    let session = fresh_session().await;
    session
        .install_sframe_epoch(TEST_EXPORTER_1, SframeCiphersuite::Aes256GcmSha512, 7)
        .await;
    assert_eq!(session.sframe_current_epoch().await, Some(7));
}

// ============================================================================
// 3. encrypt before install fails MlsExporterUnavailable
// ============================================================================

#[tokio::test]
async fn sframe_encrypt_frame_before_epoch_install_fails_closed_mls_exporter_unavailable() {
    let session = fresh_session().await;
    let err = session
        .sframe_encrypt_frame(0, 0, b"plaintext")
        .await
        .expect_err("MUST fail without epoch installed");
    assert!(
        matches!(err, ClientError::Call(CallError::MlsExporterUnavailable)),
        "expected MlsExporterUnavailable, got {err:?}"
    );
}

// ============================================================================
// 4. Encrypt → decrypt round-trip
// ============================================================================

#[tokio::test]
async fn sframe_encrypt_decrypt_round_trip_yields_original_plaintext() {
    let session = fresh_session().await;
    session
        .install_sframe_epoch(TEST_EXPORTER_1, SframeCiphersuite::Aes256GcmSha512, 0x42)
        .await;

    let plaintext = b"hello SFrame world";
    let wire = session
        .sframe_encrypt_frame(0, 0, plaintext)
        .await
        .expect("encrypt");
    let decrypted = session.sframe_decrypt_frame(&wire).await.expect("decrypt");
    assert_eq!(
        decrypted.plaintext.as_slice(),
        plaintext.as_slice(),
        "round-trip plaintext MUST equal input"
    );
}

// ============================================================================
// 5. Tampered ciphertext fails AeadAuthFailure
// ============================================================================

#[tokio::test]
async fn sframe_decrypt_frame_tampered_ciphertext_fails_aead_auth() {
    let session = fresh_session().await;
    session
        .install_sframe_epoch(TEST_EXPORTER_1, SframeCiphersuite::Aes256GcmSha512, 1)
        .await;

    let mut wire = session
        .sframe_encrypt_frame(0, 0, b"to tamper")
        .await
        .expect("encrypt");
    // Flip a byte in the middle of the ciphertext (skip header).
    let last = wire.len() - 5;
    wire[last] ^= 0x01;

    let err = session
        .sframe_decrypt_frame(&wire)
        .await
        .expect_err("tampered ciphertext MUST fail");
    assert!(
        matches!(err, ClientError::Call(CallError::AeadAuthFailure)),
        "expected AeadAuthFailure, got {err:?}"
    );
}

// ============================================================================
// 6. Replay of same counter fails
// ============================================================================

#[tokio::test]
async fn sframe_decrypt_frame_replay_fails_call_error_replay() {
    let session = fresh_session().await;
    session
        .install_sframe_epoch(TEST_EXPORTER_1, SframeCiphersuite::Aes256GcmSha512, 2)
        .await;

    let wire = session
        .sframe_encrypt_frame(0, 0, b"replay-target")
        .await
        .expect("encrypt");
    // First decrypt succeeds
    session
        .sframe_decrypt_frame(&wire)
        .await
        .expect("first decrypt OK");
    // Second decrypt of the SAME bytes fails replay
    let err = session
        .sframe_decrypt_frame(&wire)
        .await
        .expect_err("second decrypt MUST fail replay");
    assert!(
        matches!(err, ClientError::Call(CallError::Replay { .. })),
        "expected Replay, got {err:?}"
    );
}

// ============================================================================
// 7. Two epochs both reachable pre-eviction
// ============================================================================

#[tokio::test]
async fn sframe_two_consecutive_epochs_both_decrypt_correctly() {
    let session = fresh_session().await;
    session
        .install_sframe_epoch(TEST_EXPORTER_1, SframeCiphersuite::Aes256GcmSha512, 1)
        .await;
    // Encrypt under epoch 1
    let wire_e1 = session
        .sframe_encrypt_frame(0, 0, b"e1-frame")
        .await
        .expect("encrypt e1");

    // Advance to epoch 2 — both should remain in cache (EPOCH_CACHE_SIZE = 3)
    session
        .install_sframe_epoch(TEST_EXPORTER_2, SframeCiphersuite::Aes256GcmSha512, 2)
        .await;
    assert_eq!(session.sframe_current_epoch().await, Some(2));

    // Encrypt under epoch 2
    let wire_e2 = session
        .sframe_encrypt_frame(1, 0, b"e2-frame")
        .await
        .expect("encrypt e2");

    // Decrypt both — even though epoch 2 is current, epoch 1 is still cached
    let dec_e1 = session
        .sframe_decrypt_frame(&wire_e1)
        .await
        .expect("dec e1");
    let dec_e2 = session
        .sframe_decrypt_frame(&wire_e2)
        .await
        .expect("dec e2");
    assert_eq!(dec_e1.plaintext.as_slice(), b"e1-frame");
    assert_eq!(dec_e2.plaintext.as_slice(), b"e2-frame");
}

// ============================================================================
// 8. Evicted epoch (4 installs) → StaleEpoch on old decrypt
// ============================================================================

#[tokio::test]
async fn sframe_decrypt_frame_evicted_epoch_fails_stale_epoch() {
    let session = fresh_session().await;

    // Install epoch 1, encrypt under it
    session
        .install_sframe_epoch([0x01u8; 64], SframeCiphersuite::Aes256GcmSha512, 1)
        .await;
    let wire_old = session
        .sframe_encrypt_frame(0, 0, b"old-epoch-frame")
        .await
        .expect("encrypt under epoch 1");

    // Install 3 more epochs (2, 3, 4) — epoch 1 evicted (cache size 3)
    session
        .install_sframe_epoch([0x02u8; 64], SframeCiphersuite::Aes256GcmSha512, 2)
        .await;
    session
        .install_sframe_epoch([0x03u8; 64], SframeCiphersuite::Aes256GcmSha512, 3)
        .await;
    session
        .install_sframe_epoch([0x04u8; 64], SframeCiphersuite::Aes256GcmSha512, 4)
        .await;
    assert_eq!(session.sframe_current_epoch().await, Some(4));

    // Decrypt of the old frame MUST fail StaleEpoch
    let err = session
        .sframe_decrypt_frame(&wire_old)
        .await
        .expect_err("decrypt of evicted epoch MUST fail");
    assert!(
        matches!(err, ClientError::Call(CallError::StaleEpoch { .. })),
        "expected StaleEpoch, got {err:?}"
    );
}
