//! F-CLIENT-FACADE-1 closure session 10b (2026-05-19): contract tests for
//! the **DTLS fingerprint binding + SRTP keying facade API** on
//! `CallSession`. Second piece of session 10 (calls subsystem) milestone
//! closure.
//!
//! ## Scope
//!
//! Pre-10b, the `DtlsRunner` (identity-bound DTLS fingerprint) и the
//! `SrtpPipeline` (keying material slot) were owned by `CallSession`
//! but **not exposed** at facade level. The signalling layer (Block 7.10
//! integration) needs:
//!
//! 1. `local_dtls_fingerprint()` — to include в outgoing offer.
//! 2. `dtls_session_nonce()` — peer needs this for expected fingerprint
//!    derivation.
//! 3. `verify_remote_dtls_fingerprint(peer_pubkey, remote_fp)` — to
//!    validate the answer's fingerprint matches the peer's KT-published
//!    identity.
//! 4. `install_srtp_keying(material)` — to commit the keying material
//!    extracted from the DTLS handshake exporter (RFC 5764 §4.2).
//! 5. `is_srtp_keyed()` — to gate the `Connected` state transition.
//!
//! Session 10b adds these as public methods on `CallSession`. State
//! machine driving (transition Signalling → IceGathering → ... →
//! Connected) is intentionally NOT included — that's session 10c+.
//! Networking integration (real DTLS handshake) stays behind Block 7.10
//! integration boundary; this layer is purely facade-level glue.
//!
//! ## Coverage
//!
//! 1. `local_dtls_fingerprint()` returns the derived fingerprint
//!    matching `IdentityDtlsFingerprint::derive(identity_pk, nonce)`
//!    for the session's identity + nonce.
//! 2. `dtls_session_nonce()` returns a non-zero 16-byte value
//!    (random per session).
//! 3. `verify_remote_dtls_fingerprint` succeeds when the peer's
//!    fingerprint matches `derive(peer_pubkey, our_nonce)`.
//! 4. `verify_remote_dtls_fingerprint` fails closed when peer_pubkey
//!    does not match the one used to derive the fingerprint.
//! 5. `verify_remote_dtls_fingerprint` fails closed when fingerprint
//!    is tampered (derived from wrong nonce).
//! 6. `is_srtp_keyed()` is false on a freshly-constructed session.
//! 7. `install_srtp_keying` then `is_srtp_keyed` returns true.
//! 8. Two sessions have independent nonces (random isolation).

use std::sync::Arc;

use async_trait::async_trait;
use rand::rngs::OsRng;

use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_calls::{CallError, CallPolicy, IdentityDtlsFingerprint};

use umbrella_client::call::{
    CallSession, MediaError, MediaFrame, MediaSink, MediaSource, ModeEnforcement,
};
use umbrella_client::error::ClientError;
use umbrella_client::facade::chat_common::{PeerId, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT};
use umbrella_client::{ClientConfig, ClientCore};

use umbrella_identity::{IdentitySeed, MnemonicLanguage};

// ============================================================================
// Test rig
// ============================================================================

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
            config: ThresholdConfig::new(3, 5).expect("3-of-5 ThresholdConfig"),
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

async fn fresh_core() -> Arc<ClientCore> {
    ClientCore::new_for_test(test_config(), test_seed())
        .await
        .expect("new_for_test")
}

async fn start(core: Arc<ClientCore>, peer: PeerId) -> CallSession {
    CallSession::start_with_enforcement(
        core,
        peer,
        CallPolicy::default(),
        ModeEnforcement::CloudMode,
        Arc::new(NullSource),
        Arc::new(NullSink),
    )
    .await
    .expect("start_with_enforcement")
}

// ============================================================================
// 1. local_dtls_fingerprint() matches derive(identity_pk, nonce)
// ============================================================================

#[tokio::test]
async fn local_dtls_fingerprint_equals_derive_of_identity_and_session_nonce() {
    let core = fresh_core().await;
    let identity_pk = core
        .identity_verifying_key()
        .expect("identity_verifying_key");
    let session = start(core, PeerId([0xCC; 32])).await;

    let nonce = session.dtls_session_nonce().await;
    let local_fp = session.local_dtls_fingerprint().await;

    let expected = IdentityDtlsFingerprint::derive(&identity_pk, &nonce);
    assert_eq!(
        local_fp, expected,
        "local_dtls_fingerprint must equal derive(identity_pk, session_nonce)"
    );
}

// ============================================================================
// 2. dtls_session_nonce non-zero (random)
// ============================================================================

#[tokio::test]
async fn dtls_session_nonce_is_random_nonzero() {
    let core = fresh_core().await;
    let session = start(core, PeerId([0x33; 32])).await;
    let nonce = session.dtls_session_nonce().await;
    assert_ne!(
        nonce, [0u8; 16],
        "session_nonce MUST be random, not all-zero"
    );
}

// ============================================================================
// 3. verify_remote_dtls_fingerprint succeeds on matching peer
// ============================================================================

#[tokio::test]
async fn verify_remote_dtls_fingerprint_ok_on_matching_peer_pubkey_and_nonce() {
    let core = fresh_core().await;
    let peer_pubkey = [0xBB; 32];
    let session = start(core, PeerId(peer_pubkey)).await;

    let our_nonce = session.dtls_session_nonce().await;
    let peer_fp = IdentityDtlsFingerprint::derive(&peer_pubkey, &our_nonce);

    session
        .verify_remote_dtls_fingerprint(&peer_pubkey, &peer_fp)
        .await
        .expect("verify_remote OK on matching peer fingerprint");
}

// ============================================================================
// 4. verify_remote_dtls_fingerprint fails on wrong peer pubkey
// ============================================================================

#[tokio::test]
async fn verify_remote_dtls_fingerprint_err_on_wrong_peer_pubkey() {
    let core = fresh_core().await;
    let actual_peer = [0xBB; 32];
    let wrong_peer = [0xDD; 32];
    let session = start(core, PeerId(actual_peer)).await;

    let our_nonce = session.dtls_session_nonce().await;
    // Fingerprint derived from ACTUAL peer pk, but we claim it's WRONG peer.
    let peer_fp = IdentityDtlsFingerprint::derive(&actual_peer, &our_nonce);

    let err = session
        .verify_remote_dtls_fingerprint(&wrong_peer, &peer_fp)
        .await
        .expect_err("MUST fail when claimed peer pubkey doesn't match derived");
    assert!(
        matches!(err, ClientError::Call(CallError::IdentityBindingFailed)),
        "MUST surface IdentityBindingFailed, got: {err:?}"
    );
}

// ============================================================================
// 5. verify_remote_dtls_fingerprint fails on tampered fingerprint (wrong nonce)
// ============================================================================

#[tokio::test]
async fn verify_remote_dtls_fingerprint_err_on_tampered_fingerprint() {
    let core = fresh_core().await;
    let peer_pubkey = [0xBB; 32];
    let session = start(core, PeerId(peer_pubkey)).await;

    // Tampered fingerprint: derived with WRONG nonce — adversary substituted.
    let tampered = IdentityDtlsFingerprint::derive(&peer_pubkey, &[0xFFu8; 16]);

    let err = session
        .verify_remote_dtls_fingerprint(&peer_pubkey, &tampered)
        .await
        .expect_err("MUST fail when fingerprint nonce is wrong");
    assert!(
        matches!(err, ClientError::Call(CallError::IdentityBindingFailed)),
        "MUST surface IdentityBindingFailed for tampered fp, got: {err:?}"
    );
}

// ============================================================================
// 6. is_srtp_keyed false on fresh session
// ============================================================================

#[tokio::test]
async fn is_srtp_keyed_false_on_freshly_constructed_session() {
    let core = fresh_core().await;
    let session = start(core, PeerId([0x44; 32])).await;
    assert!(
        !session.is_srtp_keyed().await,
        "freshly constructed session has no SRTP keying — Connected state un-gated"
    );
}

// ============================================================================
// 7. install_srtp_keying transitions is_srtp_keyed
// ============================================================================

#[tokio::test]
async fn install_srtp_keying_then_is_srtp_keyed_returns_true() {
    use umbrella_client::call::srtp_pipeline::{SrtpKeyingMaterial, SrtpProfile};

    let core = fresh_core().await;
    let session = start(core, PeerId([0x55; 32])).await;
    assert!(!session.is_srtp_keyed().await);

    let material = SrtpKeyingMaterial {
        key: vec![0x77; 64],
        salt: vec![0x88; 24],
        profile: SrtpProfile::AeadAes256Gcm,
    };
    session
        .install_srtp_keying(material)
        .await
        .expect("install_srtp_keying");

    assert!(
        session.is_srtp_keyed().await,
        "post install_srtp_keying: is_srtp_keyed MUST be true"
    );
}

// ============================================================================
// 8. Two sessions have independent random nonces
// ============================================================================

#[tokio::test]
async fn two_sessions_have_distinct_random_session_nonces() {
    let core_a = fresh_core().await;
    let core_b = fresh_core().await;
    let s_a = start(core_a, PeerId([0x11; 32])).await;
    let s_b = start(core_b, PeerId([0x11; 32])).await;

    let n_a = s_a.dtls_session_nonce().await;
    let n_b = s_b.dtls_session_nonce().await;
    assert_ne!(
        n_a, n_b,
        "two sessions MUST have distinct random nonces — DTLS replay-binding invariant"
    );
}
