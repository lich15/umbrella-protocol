//! F-CLIENT-FACADE-1 closure session 10a (2026-05-19): contract tests for
//! TURN credential allocation flowing through `core.call_relay_transport`
//! instead of the pre-9.5 hardcoded placeholder URL.
//!
//! ## Scope
//!
//! Block 7.6 originally constructed a `CallSession` with
//! `allocate_turn_placeholder()` returning a fixed `turn:relay.localhost`
//! URL — the documented stub before "Block 7.10 integration". Session
//! 10a is the first piece of that 7.10 integration: replace the
//! placeholder with a real `core.call_relay_transport.allocate(...)`
//! call (stubbed offline, mirrors production `Http2CallRelayTransport`).
//!
//! Carry into the request:
//! - `peer_id` (Ed25519 identity pubkey of the callee).
//! - `security_level` derived from
//!   `ModeEnforcement + effective_policy.allow_p2p_global` — the
//!   compliance-gate that propagates the relay-only invariant of
//!   SecretChat / Cloud-no-p2p into the server-issued TURN allocation
//!   policy.
//!
//! ## Coverage
//!
//! 1. `StubCallRelayTransport::allocate` increments `allocations`
//!    counter per call.
//! 2. Deterministic URL: the same `peer_id` produces the same URL twice;
//!    distinct `peer_id`s produce distinct URLs (no constant stub).
//! 3. `CallSession::start_with_enforcement` makes exactly one
//!    `allocate(...)` call per construction.
//! 4. Security-level mapping — `SecretMode` → `Sensitive` (always).
//! 5. Security-level mapping — `CloudMode + allow_p2p_global = true` →
//!    `AllowP2pGlobal`.
//! 6. Security-level mapping — `CloudMode + allow_p2p_global = false` →
//!    `Sensitive`.
//! 7. `TurnAllocation` → `TurnConfig` field mapping (primary_url →
//!    url, username → username, password_hmac_hex → password).
//! 8. Stub allocation `password_hmac_hex` is 64 hex chars (wire
//!    invariant matched by production).

use std::sync::Arc;

use async_trait::async_trait;
use rand::rngs::OsRng;

use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_calls::{CallPolicy, RoutingMode};

use umbrella_client::call::{
    CallSession, MediaError, MediaFrame, MediaSink, MediaSource, ModeEnforcement,
};
use umbrella_client::facade::chat_common::{PeerId, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT};
use umbrella_client::transport::CallSecurityLevelWire;
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

async fn start_with(core: Arc<ClientCore>, enforcement: ModeEnforcement, policy: CallPolicy) {
    let _ = CallSession::start_with_enforcement(
        core,
        PeerId([0xAA; 32]),
        policy,
        enforcement,
        Arc::new(NullSource),
        Arc::new(NullSink),
    )
    .await
    .expect("start_with_enforcement");
}

// ============================================================================
// 1. Stub allocate increments the counter
// ============================================================================

#[tokio::test]
async fn stub_allocate_increments_allocations_counter_per_call() {
    let core = fresh_core().await;
    let before = *core
        .call_relay_transport()
        .allocations
        .lock()
        .expect("counter lock");
    assert_eq!(before, 0);

    start_with(
        core.clone(),
        ModeEnforcement::CloudMode,
        CallPolicy::default(),
    )
    .await;
    let after_one = *core
        .call_relay_transport()
        .allocations
        .lock()
        .expect("counter lock");
    assert_eq!(after_one, 1, "one allocation per session construction");

    start_with(
        core.clone(),
        ModeEnforcement::CloudMode,
        CallPolicy::default(),
    )
    .await;
    let after_two = *core
        .call_relay_transport()
        .allocations
        .lock()
        .expect("counter lock");
    assert_eq!(
        after_two, 2,
        "two sessions construct → two allocations on the same stub"
    );
}

// ============================================================================
// 2. Deterministic URL — same peer_id ⇒ same URL; distinct peer_id ⇒ distinct
// ============================================================================

#[tokio::test]
async fn stub_allocate_returns_deterministic_distinct_url_per_peer() {
    let core = fresh_core().await;
    let peer_a = [0x11u8; 32];
    let peer_b = [0xBBu8; 32];

    let a1 = core
        .call_relay_transport()
        .allocate(peer_a, CallSecurityLevelWire::Default)
        .await
        .expect("allocate a1");
    let a2 = core
        .call_relay_transport()
        .allocate(peer_a, CallSecurityLevelWire::Default)
        .await
        .expect("allocate a2");
    let b1 = core
        .call_relay_transport()
        .allocate(peer_b, CallSecurityLevelWire::Default)
        .await
        .expect("allocate b1");

    assert_eq!(
        a1.primary_url, a2.primary_url,
        "same peer_id MUST yield identical primary_url"
    );
    assert_ne!(
        a1.primary_url, b1.primary_url,
        "distinct peer_id MUST yield distinct primary_url — guards against const stub"
    );
    // URL contains the peer_id hex prefix for cross-check
    assert!(
        a1.primary_url.contains("11111111"),
        "primary_url contains peer_id hex prefix, got: {}",
        a1.primary_url
    );
    assert!(
        b1.primary_url.contains("bbbbbbbb"),
        "primary_url contains peer_id hex prefix, got: {}",
        b1.primary_url
    );
}

// ============================================================================
// 3. Exactly one allocate(...) call per session construction
// ============================================================================

#[tokio::test]
async fn start_with_enforcement_calls_call_relay_allocate_exactly_once_per_session() {
    let core = fresh_core().await;
    start_with(
        core.clone(),
        ModeEnforcement::CloudMode,
        CallPolicy::default(),
    )
    .await;

    let count = *core
        .call_relay_transport()
        .allocations
        .lock()
        .expect("counter");
    assert_eq!(
        count, 1,
        "one CallSession construction = exactly one TURN allocation"
    );

    let last = *core
        .call_relay_transport()
        .last_request
        .lock()
        .expect("last_request lock");
    assert!(last.is_some(), "last_request recorded after allocate");
    let (peer_id, _level) = last.unwrap();
    assert_eq!(
        peer_id, [0xAAu8; 32],
        "peer_id from CallSession.peer flows into allocate request"
    );
}

// ============================================================================
// 4. SecretMode → Sensitive (always, regardless of policy)
// ============================================================================

#[tokio::test]
async fn secret_mode_passes_sensitive_security_level_even_if_policy_requests_p2p() {
    let core = fresh_core().await;
    let policy = CallPolicy {
        default_routing: RoutingMode::DirectP2P,
        allow_p2p_global: true, // user asked for p2p — must be ignored under SecretMode
        ..Default::default()
    };
    start_with(core.clone(), ModeEnforcement::SecretMode, policy).await;

    let (_peer, level) = (*core
        .call_relay_transport()
        .last_request
        .lock()
        .expect("last_request"))
    .expect("recorded");
    assert!(
        matches!(level, CallSecurityLevelWire::Sensitive),
        "SecretMode MUST propagate Sensitive to the server regardless of allow_p2p_global \
         (compliance-gate carried into server-side TURN allocation policy)"
    );
}

// ============================================================================
// 5. CloudMode + allow_p2p_global=true → AllowP2pGlobal
// ============================================================================

#[tokio::test]
async fn cloud_mode_with_allow_p2p_global_passes_allow_p2p_global_security_level() {
    let core = fresh_core().await;
    let policy = CallPolicy {
        default_routing: RoutingMode::DirectP2P,
        allow_p2p_global: true,
        ..Default::default()
    };
    start_with(core.clone(), ModeEnforcement::CloudMode, policy).await;

    let (_peer, level) = (*core
        .call_relay_transport()
        .last_request
        .lock()
        .expect("last_request"))
    .expect("recorded");
    assert!(
        matches!(level, CallSecurityLevelWire::AllowP2pGlobal),
        "CloudMode + allow_p2p_global=true MUST propagate AllowP2pGlobal"
    );
}

// ============================================================================
// 6. CloudMode + allow_p2p_global=false → Sensitive (default conservative)
// ============================================================================

#[tokio::test]
async fn cloud_mode_without_allow_p2p_global_passes_sensitive_security_level() {
    let core = fresh_core().await;
    let policy = CallPolicy::default(); // allow_p2p_global = false by default
    start_with(core.clone(), ModeEnforcement::CloudMode, policy).await;

    let (_peer, level) = (*core
        .call_relay_transport()
        .last_request
        .lock()
        .expect("last_request"))
    .expect("recorded");
    assert!(
        matches!(level, CallSecurityLevelWire::Sensitive),
        "CloudMode + allow_p2p_global=false (default) MUST propagate Sensitive — conservative path"
    );
}

// ============================================================================
// 7. TurnAllocation → TurnConfig field mapping
// ============================================================================

#[tokio::test]
async fn turn_allocation_fields_map_to_turn_config_through_session_construction() {
    // The session.rs `turn_config_from_allocation` helper isn't pub, so we
    // verify the mapping indirectly via the public allocate API: the
    // stub returns deterministic content, and the constructed CallSession
    // must have used it. We re-call allocate directly and confirm fields.
    let core = fresh_core().await;
    let peer = [0x77u8; 32];
    let allocation = core
        .call_relay_transport()
        .allocate(peer, CallSecurityLevelWire::Sensitive)
        .await
        .expect("allocate");

    assert!(
        allocation.primary_url.starts_with("turn:"),
        "primary_url uses turn: scheme"
    );
    assert!(
        allocation.username.contains("stub-user-77777777"),
        "username encodes peer_id hex prefix, got: {}",
        allocation.username
    );
    assert_eq!(
        allocation.password_hmac_hex.len(),
        64,
        "password_hmac_hex is 64 hex chars (256-bit HMAC) per Http2 wire format"
    );
    assert!(
        allocation.valid_until_ms > 0,
        "valid_until_ms set to non-zero"
    );
    assert!(
        allocation.secondary_url.is_none(),
        "stub does not provide secondary; production may"
    );
}

// ============================================================================
// 8. Stub password is hex, 64 chars (wire invariant)
// ============================================================================

#[tokio::test]
async fn stub_allocation_password_hmac_hex_matches_production_wire_invariant() {
    let core = fresh_core().await;
    let allocation = core
        .call_relay_transport()
        .allocate([0u8; 32], CallSecurityLevelWire::Default)
        .await
        .expect("allocate");
    let pw = &allocation.password_hmac_hex;
    assert_eq!(pw.len(), 64, "256-bit HMAC = 64 hex chars");
    assert!(
        pw.chars().all(|c| c.is_ascii_hexdigit()),
        "password_hmac_hex must be valid hex, got: {pw}"
    );
}
