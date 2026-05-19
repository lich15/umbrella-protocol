//! F-CLIENT-FACADE-1 closure session 9e (2026-05-19): contract tests for
//! the **post-rotation HW identity state refresh** — the cleanup of the
//! session 9d deferral. Verifies that after [`rotate_identity_full`] the
//! `core.hw_identity_state` (handle + cached verifying-key) reflects the
//! new identity instead of going stale, so subsequent calls to
//! `core.hw_identity_handle()` / `core.identity_verifying_key()` /
//! `core.has_hw_identity()` see post-rotation values.
//!
//! ## Background
//!
//! Session 9d's `rotate_identity_full` facade swapped `core.mls_keystore`
//! atomically after publish but explicitly left
//! `core.hw_identity_handle` / `core.hw_verifying_key` stale (documented
//! in the session 9d commit). Session 9e wraps both fields together in
//! `RwLock<HwIdentityState>` and extends the facade to call
//! `core.swap_hw_identity(new_handle, new_vk)` after the mls_keystore
//! swap, so the **full ClientCore state** is consistent post-rotation.
//!
//! ## Coverage
//!
//! 1. Post-rotation `hw_identity_handle()` returns `Some(new_handle)`
//!    (not the stale old_handle).
//! 2. Post-rotation `identity_verifying_key()` returns the new pubkey.
//! 3. Post-rotation `has_hw_identity()` remains `true` (rotation didn't
//!    accidentally clear the HW state — it just replaced).
//! 4. Pre-rotation snapshot matches bootstrap state (rig invariant).
//! 5. `hw_identity_state_snapshot()` returns a coherent `(handle, vk)`
//!    pair — both reflect the same identity (atomic-state invariant).
//! 6. Sequential rotations chain HW state correctly: rotation #2 reads
//!    v1 state as starting point and yields v2 state.
//! 7. Legacy (no-HW) path: `hw_identity_handle()` returns `None` and
//!    `identity_verifying_key()` falls back to in-heap `IdentityKey`.
//! 8. Snapshot via `hw_identity_state_snapshot()` returns matching
//!    `(handle, vk)` after rotation — same atomicity as in-flight.

use std::sync::Arc;

use rand_core::{OsRng, RngCore};

use umbrella_backup::cloud_wrap::identity_rotation::CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN;
use umbrella_backup::cloud_wrap::{RotationReason, ThresholdConfig, WrappingParams};

use umbrella_client::facade::chat_common::UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT;
use umbrella_client::identity::rotate_identity_full;
use umbrella_client::keystore::hw_callback::{
    HwKeyHandle, MockHwKeystore, PersistentKeyStoreCallback,
};
use umbrella_client::keystore::HwBackedKeyStore;
use umbrella_client::{ClientConfig, UmbrellaClient};

use umbrella_identity::{IdentitySeed, KeyStore, MnemonicLanguage};

const TEST_ROTATION_TIMESTAMP: u64 = 1_716_500_000_000;

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

#[allow(deprecated, reason = "test seed gen pattern")]
fn test_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

fn fresh_proof() -> [u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN] {
    let mut proof = [0u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN];
    OsRng.fill_bytes(&mut proof);
    proof[0] |= 0x01;
    proof
}

async fn setup_rotation_rig() -> (
    Arc<UmbrellaClient>,
    Arc<MockHwKeystore>,
    HwKeyHandle,
    [u8; 32],
) {
    // Use the production-path HW bootstrap so `hw_callback` is `Some` and
    // `has_hw_identity()` returns true. `new_with_hw_callback` populates
    // `hw_callback` + `hw_identity_state` and creates a throwaway
    // `InMemoryKeyStore` as `mls_keystore`. To make the test coherent we
    // then swap `mls_keystore` to a `HwBackedKeyStore` wrapping the same
    // handle/vk, so `core.mls_keystore().identity_public() ==
    // core.identity_verifying_key()` — required by the
    // `rotate_identity_full` layer-1 pre-flight cross-check.
    let mock = Arc::new(MockHwKeystore::new());
    let callback: Arc<dyn PersistentKeyStoreCallback> = mock.clone();
    let client = UmbrellaClient::bootstrap_with_hw_callback(
        test_config(),
        callback.clone(),
        "session-9e.rig.bootstrap",
    )
    .await
    .expect("bootstrap_with_hw_callback");
    let core = client.core();
    let handle = core
        .hw_identity_handle()
        .expect("hw_identity_handle present");
    let vk = core
        .identity_verifying_key()
        .expect("identity_verifying_key");

    let hw_keystore = HwBackedKeyStore::new(0, callback.clone(), handle.clone(), vk)
        .expect("HwBackedKeyStore::new");
    let mls_keystore: Arc<dyn KeyStore> = Arc::new(hw_keystore);
    core.swap_mls_keystore(mls_keystore);
    (client, mock, handle, vk)
}

// ============================================================================
// 1. Rig invariant — pre-rotation state matches bootstrap
// ============================================================================

#[tokio::test]
async fn pre_rotation_hw_state_matches_bootstrap_handle_and_verifying_key() {
    let (client, _mock, bootstrap_handle, bootstrap_vk) = setup_rotation_rig().await;
    let core = client.core();

    let snapshot = core.hw_identity_state_snapshot();
    assert_eq!(
        snapshot.handle.as_ref(),
        Some(&bootstrap_handle),
        "snapshot.handle must match bootstrap"
    );
    assert_eq!(
        snapshot.verifying_key,
        Some(bootstrap_vk),
        "snapshot.verifying_key must match bootstrap"
    );
    assert!(core.has_hw_identity(), "has_hw_identity true at rig start");
}

// ============================================================================
// 2. Post-rotation: hw_identity_handle reflects new handle
// ============================================================================

#[tokio::test]
async fn post_rotation_hw_identity_handle_returns_new_handle_not_old() {
    let (client, mock, old_handle, _old_pk) = setup_rotation_rig().await;
    let core = client.core();

    let outcome = rotate_identity_full(
        &core,
        mock.clone(),
        old_handle.clone(),
        "session-9e.handle-refresh.new",
        RotationReason::PlannedRotation,
        TEST_ROTATION_TIMESTAMP,
        fresh_proof(),
    )
    .await
    .expect("rotate");

    let post = core.hw_identity_handle().expect("handle present");
    assert_eq!(
        post, outcome.new_identity_handle,
        "post-rotation hw_identity_handle MUST equal outcome.new_identity_handle"
    );
    assert_ne!(
        post, old_handle,
        "post-rotation hw_identity_handle MUST NOT be the stale pre-rotation handle"
    );
    assert_eq!(
        post.label(),
        "session-9e.handle-refresh.new",
        "handle alias persisted from rotation call"
    );
}

// ============================================================================
// 3. Post-rotation: identity_verifying_key returns new pubkey
// ============================================================================

#[tokio::test]
async fn post_rotation_identity_verifying_key_returns_new_pubkey() {
    let (client, mock, old_handle, old_pk) = setup_rotation_rig().await;
    let core = client.core();

    let pre = core
        .identity_verifying_key()
        .expect("pre identity_verifying_key");
    assert_eq!(pre, old_pk, "pre-rotation accessor returns old pk");

    let outcome = rotate_identity_full(
        &core,
        mock.clone(),
        old_handle,
        "session-9e.vk-refresh.new",
        RotationReason::PlannedRotation,
        TEST_ROTATION_TIMESTAMP,
        fresh_proof(),
    )
    .await
    .expect("rotate");

    let post = core
        .identity_verifying_key()
        .expect("post identity_verifying_key");
    assert_eq!(
        post, outcome.new_identity_pubkey,
        "post-rotation identity_verifying_key MUST equal outcome.new_identity_pubkey"
    );
    assert_ne!(
        post, old_pk,
        "post-rotation identity_verifying_key MUST NOT be the stale old pubkey"
    );
}

// ============================================================================
// 4. Post-rotation: has_hw_identity preserved
// ============================================================================

#[tokio::test]
async fn post_rotation_has_hw_identity_still_true() {
    let (client, mock, old_handle, _old_pk) = setup_rotation_rig().await;
    let core = client.core();

    assert!(core.has_hw_identity(), "pre-rotation has_hw_identity true");

    let _ = rotate_identity_full(
        &core,
        mock.clone(),
        old_handle,
        "session-9e.has-hw.new",
        RotationReason::PlannedRotation,
        TEST_ROTATION_TIMESTAMP,
        fresh_proof(),
    )
    .await
    .expect("rotate");

    assert!(
        core.has_hw_identity(),
        "post-rotation has_hw_identity MUST stay true — rotation replaced, did not clear"
    );
}

// ============================================================================
// 5. Snapshot atomicity — (handle, vk) coherent in single read
// ============================================================================

#[tokio::test]
async fn post_rotation_snapshot_returns_coherent_handle_and_verifying_key_pair() {
    let (client, mock, old_handle, _old_pk) = setup_rotation_rig().await;
    let core = client.core();

    let outcome = rotate_identity_full(
        &core,
        mock.clone(),
        old_handle,
        "session-9e.atomic.new",
        RotationReason::PlannedRotation,
        TEST_ROTATION_TIMESTAMP,
        fresh_proof(),
    )
    .await
    .expect("rotate");

    let snapshot = core.hw_identity_state_snapshot();
    assert_eq!(
        snapshot.handle.as_ref(),
        Some(&outcome.new_identity_handle),
        "snapshot.handle MUST equal outcome.new_identity_handle"
    );
    assert_eq!(
        snapshot.verifying_key,
        Some(outcome.new_identity_pubkey),
        "snapshot.verifying_key MUST equal outcome.new_identity_pubkey"
    );
    // Cross-check via the mock: the snapshot's handle resolves to the
    // snapshot's verifying_key inside the keystore — no drift between
    // facade's cache and HW callback's view.
    let mock_vk = mock
        .verifying_key(&snapshot.handle.expect("handle"))
        .expect("vk via callback");
    assert_eq!(
        mock_vk, outcome.new_identity_pubkey,
        "snapshot handle's mock-side verifying_key MUST equal cached snapshot vk"
    );
}

// ============================================================================
// 6. Sequential rotations chain HW state
// ============================================================================

#[tokio::test]
async fn two_rotations_chain_hw_identity_state_correctly() {
    let (client, mock, handle_v0, pk_v0) = setup_rotation_rig().await;
    let core = client.core();

    let outcome_v1 = rotate_identity_full(
        &core,
        mock.clone(),
        handle_v0.clone(),
        "session-9e.chain.v1",
        RotationReason::PlannedRotation,
        TEST_ROTATION_TIMESTAMP,
        fresh_proof(),
    )
    .await
    .expect("rotate #1");

    let snap_v1 = core.hw_identity_state_snapshot();
    assert_eq!(
        snap_v1.handle.as_ref(),
        Some(&outcome_v1.new_identity_handle)
    );
    assert_eq!(snap_v1.verifying_key, Some(outcome_v1.new_identity_pubkey));
    assert_ne!(snap_v1.verifying_key, Some(pk_v0));

    let outcome_v2 = rotate_identity_full(
        &core,
        mock.clone(),
        outcome_v1.new_identity_handle.clone(),
        "session-9e.chain.v2",
        RotationReason::IdentityCompromise,
        TEST_ROTATION_TIMESTAMP + 1,
        fresh_proof(),
    )
    .await
    .expect("rotate #2");

    let snap_v2 = core.hw_identity_state_snapshot();
    assert_eq!(
        snap_v2.handle.as_ref(),
        Some(&outcome_v2.new_identity_handle)
    );
    assert_eq!(snap_v2.verifying_key, Some(outcome_v2.new_identity_pubkey));
    assert_ne!(
        snap_v2.handle, snap_v1.handle,
        "v2 handle MUST differ from v1"
    );
    assert_ne!(
        snap_v2.verifying_key, snap_v1.verifying_key,
        "v2 vk MUST differ from v1"
    );
    assert_ne!(
        snap_v2.verifying_key,
        Some(pk_v0),
        "v2 vk MUST differ from v0"
    );

    // Accessor surfaces also reflect v2 state
    assert_eq!(
        core.hw_identity_handle().as_ref(),
        Some(&outcome_v2.new_identity_handle),
        "hw_identity_handle accessor reflects v2 post-chain"
    );
    assert_eq!(
        core.identity_verifying_key()
            .expect("identity_verifying_key"),
        outcome_v2.new_identity_pubkey,
        "identity_verifying_key accessor reflects v2 post-chain"
    );
}

// ============================================================================
// 7. Legacy (no-HW) path unaffected — hw_identity_handle is None
// ============================================================================

#[tokio::test]
async fn legacy_path_returns_no_hw_identity_state_and_falls_back_to_in_heap_identity() {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test");
    let core = client.core();

    // Legacy path: no HW callback, no HW state populated. `hw_identity_handle()`
    // returns None; `identity_verifying_key()` falls back to in-heap
    // IdentityKey; `has_hw_identity()` is false.
    assert!(
        !core.has_hw_identity(),
        "legacy path: has_hw_identity MUST be false"
    );
    assert!(
        core.hw_identity_handle().is_none(),
        "legacy path: hw_identity_handle MUST return None"
    );

    let snapshot = core.hw_identity_state_snapshot();
    assert!(
        snapshot.handle.is_none(),
        "legacy snapshot.handle MUST be None"
    );
    assert!(
        snapshot.verifying_key.is_none(),
        "legacy snapshot.verifying_key MUST be None"
    );

    let vk = core
        .identity_verifying_key()
        .expect("legacy path: identity_verifying_key reads in-heap identity");
    assert_eq!(
        vk,
        core.mls_keystore().identity_public().to_bytes(),
        "legacy fallback reads from in-heap IdentityKey, matches mls_keystore identity"
    );
}

// ============================================================================
// 8. Manual swap_hw_identity respects atomic-state invariant
// ============================================================================

#[tokio::test]
async fn manual_swap_hw_identity_updates_both_handle_and_verifying_key_atomically() {
    let (client, _mock, _old_handle, _old_pk) = setup_rotation_rig().await;
    let core = client.core();

    let synthetic_handle = HwKeyHandle::new("session-9e.manual-swap.target");
    let mut synthetic_vk = [0u8; 32];
    OsRng.fill_bytes(&mut synthetic_vk);
    // Make it a valid Ed25519 point — clear the high bit so it decodes.
    // (Not strictly required for this test since hw_verifying_key is
    // stored as raw [u8; 32] without decode; but lighter-touch
    // future-proofing.)
    synthetic_vk[31] &= 0x7F;

    core.swap_hw_identity(synthetic_handle.clone(), synthetic_vk);

    let snap = core.hw_identity_state_snapshot();
    assert_eq!(snap.handle, Some(synthetic_handle.clone()));
    assert_eq!(snap.verifying_key, Some(synthetic_vk));

    // Accessor surfaces also see the new state
    assert_eq!(core.hw_identity_handle(), Some(synthetic_handle));
    assert_eq!(
        core.identity_verifying_key().expect("vk"),
        synthetic_vk,
        "identity_verifying_key returns the swapped HW vk (HW path wins over legacy fallback)"
    );
}
