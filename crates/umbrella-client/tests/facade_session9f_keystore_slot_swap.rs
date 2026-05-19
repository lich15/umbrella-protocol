//! F-CLIENT-FACADE-1 closure session 9f (2026-05-19): contract tests for
//! the **canonical `core.keystore()` slot refresh post-rotation**. Closes
//! the last stale-state deferral from sessions 9d + 9e — the F-IDENT-1
//! partition invariant (`Some(HwBackedKeyStore)` на hw path / `None` на
//! legacy) is now preserved across identity rotation.
//!
//! ## Background
//!
//! Pre-9f, `rotate_identity_full` swapped `core.mls_keystore` (9d) and
//! `core.hw_identity_state` (9e), but left `core.keystore()` returning
//! the bootstrap-time `HwBackedKeyStore` wrapping the **old** handle /
//! verifying-key. No production code consumes `core.keystore()` today
//! (Block 7.2 facades use inline `InMemoryKeyStore::open`), but the
//! accessor is forward-compatibility API for Block 7.4+ facade
//! consolidation. Stale-state там был latent bug waiting для пробуждения.
//!
//! Session 9f wraps the slot in `std::sync::RwLock`, adds
//! `core.swap_keystore(...)` method, and extends `rotate_identity_full`
//! Layer 4 to swap the slot in tandem with `swap_mls_keystore` —
//! both accessors now return `Arc::ptr_eq`-identical pointers (the
//! same `Arc<HwBackedKeyStore>` was created once and routed to both
//! slots).
//!
//! ## Coverage (4 scenarios)
//!
//! 1. Pre-rotation rig invariant: `core.keystore()` returns
//!    `Some(...)` matching bootstrap state.
//! 2. Post-rotation `core.keystore()` returns the NEW `HwBackedKeyStore`
//!    — its `identity_public()` equals `outcome.new_identity_pubkey`,
//!    NOT the stale `old_pk`.
//! 3. Post-rotation `Arc::ptr_eq(mls_keystore, keystore.unwrap())` —
//!    both accessors return the same Arc, confirming no duplicate
//!    state.
//! 4. Legacy (no-HW) path: `core.keystore()` returns `None` and stays
//!    `None` (rotation is HW-only; legacy path doesn't even reach
//!    rotation orchestration).

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

const TEST_ROTATION_TIMESTAMP: u64 = 1_716_700_000_000;

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
    let mock = Arc::new(MockHwKeystore::new());
    let callback: Arc<dyn PersistentKeyStoreCallback> = mock.clone();
    let client = UmbrellaClient::bootstrap_with_hw_callback(
        test_config(),
        callback.clone(),
        "session-9f.rig.bootstrap",
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
    // Mirror what new_with_hw_callback's `keystore` slot now holds, so
    // pre-rotation invariant matches: both slots reference HwBackedKeyStore
    // bound to the bootstrap handle. Production-shaped: the bootstrap
    // pre-populates both slots via new_with_hw_callback; here we replace
    // mls_keystore + keystore with the freshly-built one так что
    // identity_public() coherent with HW callback's verifying_key.
    core.swap_mls_keystore(mls_keystore.clone());
    core.swap_keystore(Some(mls_keystore));
    (client, mock, handle, vk)
}

// ============================================================================
// 1. Pre-rotation rig invariant
// ============================================================================

#[tokio::test]
async fn pre_rotation_keystore_slot_is_some_matching_bootstrap_identity() {
    let (client, _mock, _bootstrap_handle, bootstrap_vk) = setup_rotation_rig().await;
    let core = client.core();

    let keystore = core
        .keystore()
        .expect("hw bootstrap MUST populate core.keystore()");
    assert_eq!(
        keystore.identity_public().to_bytes(),
        bootstrap_vk,
        "keystore.identity_public() matches bootstrap verifying_key"
    );
}

// ============================================================================
// 2. Post-rotation: core.keystore() returns new HwBackedKeyStore
// ============================================================================

#[tokio::test]
async fn post_rotation_keystore_slot_returns_new_hw_backed_keystore_not_stale() {
    let (client, mock, old_handle, old_pk) = setup_rotation_rig().await;
    let core = client.core();

    let outcome = rotate_identity_full(
        &core,
        mock.clone(),
        old_handle,
        "session-9f.keystore-refresh.new",
        RotationReason::PlannedRotation,
        TEST_ROTATION_TIMESTAMP,
        fresh_proof(),
    )
    .await
    .expect("rotate");

    let keystore = core
        .keystore()
        .expect("post-rotation core.keystore() MUST be Some — F-IDENT-1 partition invariant");
    assert_eq!(
        keystore.identity_public().to_bytes(),
        outcome.new_identity_pubkey,
        "post-rotation core.keystore().identity_public() MUST equal new pubkey"
    );
    assert_ne!(
        keystore.identity_public().to_bytes(),
        old_pk,
        "post-rotation core.keystore() MUST NOT return stale pre-rotation HwBackedKeyStore"
    );
}

// ============================================================================
// 3. Atomic-identity: mls_keystore + keystore reference SAME Arc post-rotation
// ============================================================================

#[tokio::test]
async fn post_rotation_mls_keystore_and_keystore_return_arc_pointer_equal_references() {
    let (client, mock, old_handle, _old_pk) = setup_rotation_rig().await;
    let core = client.core();

    let _outcome = rotate_identity_full(
        &core,
        mock.clone(),
        old_handle,
        "session-9f.arc-eq.new",
        RotationReason::PlannedRotation,
        TEST_ROTATION_TIMESTAMP,
        fresh_proof(),
    )
    .await
    .expect("rotate");

    let mls = core.mls_keystore();
    let keystore = core.keystore().expect("post-rotation keystore Some");

    assert!(
        Arc::ptr_eq(&mls, &keystore),
        "post-rotation mls_keystore and keystore MUST be the same Arc (no duplicate state)"
    );
}

// ============================================================================
// 4. Legacy (no-HW) path unaffected — keystore stays None
// ============================================================================

#[tokio::test]
async fn legacy_path_keystore_slot_stays_none() {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test");
    let core = client.core();

    assert!(
        core.keystore().is_none(),
        "legacy bootstrap: core.keystore() MUST be None — Block 7.2 facade pattern preserved"
    );

    // Manual swap to None roundtrip — verifies swap_keystore API works
    // symmetric for None case (defense-in-depth on the API itself).
    core.swap_keystore(None);
    assert!(
        core.keystore().is_none(),
        "after explicit swap_keystore(None) the slot stays None"
    );
}
