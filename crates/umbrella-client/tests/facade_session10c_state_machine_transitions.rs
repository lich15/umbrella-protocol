//! F-CLIENT-FACADE-1 closure session 10c (2026-05-19): contract tests for
//! `CallSession` state machine transition methods. Third piece of
//! session 10 (calls subsystem) milestone closure.
//!
//! ## Scope
//!
//! Pre-10c, `CallSession::state` could only change via two paths:
//! - Construction via `start_with_enforcement` → initial state
//!   `Signalling`.
//! - `hangup()` → `Terminated(LocalHangup)`.
//!
//! The intermediate states (`IceGathering`, `IceChecking`,
//! `DtlsHandshake`, `Connected`, `Reconnecting`) were defined в the
//! enum but unreachable through the facade — the signalling driver
//! had no way to advance the lifecycle. Session 10c adds public
//! transition methods so the signalling driver can drive the
//! lifecycle as ICE / DTLS / SRTP phases complete.
//!
//! ## Coverage (8 scenarios)
//!
//! 1. Initial state is `Signalling` (pre-existing — pinned again to
//!    guard against regressions when adding new transition methods).
//! 2. `begin_ice_gathering()` transitions `Signalling → IceGathering`.
//! 3. `mark_ice_complete()` transitions to `DtlsHandshake` (collapses
//!    IceGathering + IceChecking at facade level).
//! 4. `mark_connected()` fails closed когда SRTP is not keyed —
//!    `ClientError::Internal("mark_connected: SRTP pipeline not
//!    keyed ...")` — gate against advertising "Connected" while
//!    media path is unready.
//! 5. `mark_connected()` succeeds after `install_srtp_keying()` and
//!    transitions to `Connected`.
//! 6. `mark_terminated(RemoteHangup)` transitions to
//!    `Terminated(RemoteHangup)`.
//! 7. `mark_terminated(IceFailure)` transitions to
//!    `Terminated(IceFailure)`.
//! 8. Happy-path full traversal Signalling → IceGathering →
//!    DtlsHandshake → install_srtp_keying → mark_connected → Connected
//!    → mark_terminated(RemoteHangup).

use std::sync::Arc;

use async_trait::async_trait;
use rand::rngs::OsRng;

use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_calls::CallPolicy;

use umbrella_client::call::{
    CallSession, CallState, CallTerminationReason, MediaError, MediaFrame, MediaSink, MediaSource,
    ModeEnforcement,
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
        PeerId([0x77; 32]),
        CallPolicy::default(),
        ModeEnforcement::CloudMode,
        Arc::new(NullSource),
        Arc::new(NullSink),
    )
    .await
    .expect("start_with_enforcement")
}

fn sample_srtp_material() -> umbrella_client::call::srtp_pipeline::SrtpKeyingMaterial {
    use umbrella_client::call::srtp_pipeline::{SrtpKeyingMaterial, SrtpProfile};
    SrtpKeyingMaterial {
        key: vec![0x11; 64],
        salt: vec![0x22; 24],
        profile: SrtpProfile::AeadAes256Gcm,
    }
}

// ============================================================================
// 1. Initial state pin
// ============================================================================

#[tokio::test]
async fn initial_state_is_signalling_post_construction() {
    let session = fresh_session().await;
    assert_eq!(session.state().await, CallState::Signalling);
}

// ============================================================================
// 2. begin_ice_gathering: Signalling → IceGathering
// ============================================================================

#[tokio::test]
async fn begin_ice_gathering_transitions_signalling_to_ice_gathering() {
    let session = fresh_session().await;
    assert_eq!(session.state().await, CallState::Signalling);
    session.begin_ice_gathering().await;
    assert_eq!(session.state().await, CallState::IceGathering);
}

// ============================================================================
// 3. mark_ice_complete: → DtlsHandshake
// ============================================================================

#[tokio::test]
async fn mark_ice_complete_transitions_to_dtls_handshake() {
    let session = fresh_session().await;
    session.begin_ice_gathering().await;
    session.mark_ice_complete().await;
    assert_eq!(session.state().await, CallState::DtlsHandshake);
}

// ============================================================================
// 4. mark_connected fails closed when SRTP not keyed
// ============================================================================

#[tokio::test]
async fn mark_connected_fails_closed_when_srtp_not_keyed() {
    let session = fresh_session().await;
    assert!(!session.is_srtp_keyed().await, "rig invariant: not keyed");

    let err = session
        .mark_connected()
        .await
        .expect_err("MUST fail when SRTP not keyed");
    match err {
        ClientError::Internal(msg) => {
            assert!(
                msg.contains("SRTP pipeline not keyed"),
                "diagnostic must mention SRTP gate, got: {msg}"
            );
        }
        other => panic!("expected Internal, got {other:?}"),
    }
    // State NOT advanced
    assert_ne!(session.state().await, CallState::Connected);
}

// ============================================================================
// 5. mark_connected succeeds after install_srtp_keying
// ============================================================================

#[tokio::test]
async fn mark_connected_succeeds_after_install_srtp_keying() {
    let session = fresh_session().await;
    session
        .install_srtp_keying(sample_srtp_material())
        .await
        .expect("install_srtp_keying");
    assert!(session.is_srtp_keyed().await);

    session
        .mark_connected()
        .await
        .expect("mark_connected after keying");
    assert_eq!(session.state().await, CallState::Connected);
}

// ============================================================================
// 6. mark_terminated(RemoteHangup) transitions to Terminated(RemoteHangup)
// ============================================================================

#[tokio::test]
async fn mark_terminated_with_remote_hangup_reason_transitions_to_terminated_remote() {
    let session = fresh_session().await;
    session
        .mark_terminated(CallTerminationReason::RemoteHangup)
        .await;
    assert_eq!(
        session.state().await,
        CallState::Terminated(CallTerminationReason::RemoteHangup)
    );
}

// ============================================================================
// 7. mark_terminated(IceFailure) transitions to Terminated(IceFailure)
// ============================================================================

#[tokio::test]
async fn mark_terminated_with_ice_failure_reason_transitions_correctly() {
    let session = fresh_session().await;
    session
        .mark_terminated(CallTerminationReason::IceFailure)
        .await;
    assert_eq!(
        session.state().await,
        CallState::Terminated(CallTerminationReason::IceFailure)
    );
}

// ============================================================================
// 8. Happy path full lifecycle traversal
// ============================================================================

#[tokio::test]
async fn happy_path_full_lifecycle_signalling_to_connected_to_terminated_remote() {
    let session = fresh_session().await;

    assert_eq!(session.state().await, CallState::Signalling);
    session.begin_ice_gathering().await;
    assert_eq!(session.state().await, CallState::IceGathering);

    session.mark_ice_complete().await;
    assert_eq!(session.state().await, CallState::DtlsHandshake);

    session
        .install_srtp_keying(sample_srtp_material())
        .await
        .expect("install");
    session.mark_connected().await.expect("mark_connected");
    assert_eq!(session.state().await, CallState::Connected);

    session
        .mark_terminated(CallTerminationReason::RemoteHangup)
        .await;
    assert_eq!(
        session.state().await,
        CallState::Terminated(CallTerminationReason::RemoteHangup)
    );
}
