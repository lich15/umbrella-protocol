//! F-CLIENT-FACADE-1 closure session 9d (2026-05-19): contract tests for
//! [`umbrella_client::identity::rotate_identity_full`] — full identity-
//! rotation orchestration on top of the session 9a wire codec + session
//! 9b publish-only facade, threading through the HW-backed
//! [`PersistentKeyStoreCallback`] (`Q1 = Option C` per design spec
//! `2026-05-19-f-client-facade-1-session-9-identity-rotation-design.md`).
//!
//! ## Coverage matrix (per design spec section 4.3)
//!
//! 1. Happy path: rotation succeeds end-to-end, outcome bundle holds new
//!    handle + new pubkey + 235-byte published size; transport receives
//!    correctly-prefixed wire frame; mls_keystore post-swap reports new
//!    pubkey.
//! 2. Round-trip: published wire bytes decode back to typed record via
//!    `decode_kt_entry_identity_rotation`; record fields match facade
//!    inputs byte-for-byte.
//! 3. Local state swap: after rotation
//!    `core.mls_keystore().identity_public()` returns new pubkey
//!    (acceptance criterion #9 of design spec).
//! 4. Wire-frame prefix: published bytes start with
//!    `KT_ENTRY_IDENTITY_ROTATION_PREFIX = 0x06`.
//! 5. Both Ed25519 signatures in the published record verify under their
//!    respective pubkeys over `record.canonical_signing_input()` —
//!    the strongest end-to-end correctness gate.
//! 6. Pre-flight `old_pk` mismatch: when `mls_keystore.identity_public()`
//!    disagrees with `hw_callback.verifying_key(old_handle)`, facade
//!    refuses with `ClientError::Internal("rotation pre-flight:
//!    old_identity_pubkey mismatch ...")` BEFORE calling HW callback —
//!    no new HW material generated, no publish.
//! 7. HW callback `KeyNotFound` propagates as `ClientError::Platform`.
//! 8. Two sequential rotations chain correctly: rotation #2 reads new_pk
//!    from #1 as its "old_pk", publishes a second wire frame; both
//!    frames decode and verify; mls_keystore returns the most-recent
//!    pubkey.
//! 9. `kt_witness_set` and `kt_transport_handle` are unchanged across
//!    rotation — the swap is mls_keystore-scoped, not infra-scoped.
//! 10. Unknown `rotation_reason` tag (mock keystore reject path) surfaces
//!     as `ClientError::Platform` without HW state mutation.
//!
//! ## Test fixture
//!
//! Each test sets up a `UmbrellaClient::bootstrap_for_test` baseline then
//! overrides `core.mls_keystore` to wrap a [`MockHwKeystore`]-backed
//! [`HwBackedKeyStore`] so that
//! `core.mls_keystore().identity_public()` is coherent with
//! `hw_callback.verifying_key(handle)`. This mirrors production wiring
//! (post-`new_with_hw_callback` + Block 7.4+ Hw-MLS device-key callback)
//! while remaining testable without a real iOS / Android device.
//!
//! ## Why parametric `hw_callback` + `old_handle` (not read from `core`)
//!
//! The facade signature
//! `rotate_identity_full(core, hw_callback, old_handle, ...)` takes both
//! parameters explicitly rather than reading from `core.hw_callback` /
//! `core.hw_identity_handle`. Reasons:
//!
//! 1. Test ergonomics — `core.hw_callback` is `pub(crate)`; integration
//!    tests cannot inject it without an additional setter.
//! 2. Decoupling — production callers (FFI layer) can supply their own
//!    callback if they wrap `core.hw_callback` (e.g. for telemetry).
//! 3. Single-responsibility — the facade is pure orchestration; ClientCore
//!    holds shared transport state but does not need to be the source
//!    of truth for the HW callback wiring.

use std::sync::Arc;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};

use umbrella_backup::cloud_wrap::identity_rotation::{
    canonical_signing_input_rotation, CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN,
};
use umbrella_backup::cloud_wrap::{
    RotationReason, ThresholdConfig, WrappingParams, AUTHORIZATION_WIRE_VERSION,
};

use umbrella_client::error::ClientError;
use umbrella_client::facade::chat_common::UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT;
use umbrella_client::identity::{rotate_identity_full, RotationOutcomeFull};
use umbrella_client::keystore::hw_callback::{
    bootstrap_hw_identity, HwKeyHandle, MockHwKeystore, PersistentKeyStoreCallback,
};
use umbrella_client::keystore::HwBackedKeyStore;
use umbrella_client::{ClientConfig, UmbrellaClient};

use umbrella_identity::{IdentitySeed, KeyStore, MnemonicLanguage};
use umbrella_kt::{
    decode_kt_entry_identity_rotation, KT_ENTRY_IDENTITY_ROTATION_PREFIX,
    KT_ENTRY_IDENTITY_ROTATION_WIRE_LEN,
};

const TEST_ROTATION_TIMESTAMP: u64 = 1_716_000_000_000;

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

#[allow(
    deprecated,
    reason = "test seed gen — same pattern as facade_session9b_identity_rotation_publish.rs"
)]
fn test_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

fn fresh_proof() -> [u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN] {
    let mut proof = [0u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN];
    OsRng.fill_bytes(&mut proof);
    proof[0] |= 0x01; // guard against all-zero CSPRNG edge case
    proof
}

/// Build a `UmbrellaClient` whose `core.mls_keystore()` returns the
/// `HwBackedKeyStore` wrapping the freshly-bootstrapped `MockHwKeystore`
/// identity. The mock and handle are returned so tests can drive
/// rotation directly and inspect mock state.
async fn setup_rotation_rig() -> (
    Arc<UmbrellaClient>,
    Arc<MockHwKeystore>,
    HwKeyHandle,
    [u8; 32],
) {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test");
    let mock = Arc::new(MockHwKeystore::new());
    let callback: Arc<dyn PersistentKeyStoreCallback> = mock.clone();
    let (handle, vk) = bootstrap_hw_identity(&callback, "session-9d.rig.bootstrap")
        .expect("bootstrap_hw_identity for rotation rig");
    let hw_keystore = HwBackedKeyStore::new(0, callback.clone(), handle.clone(), vk)
        .expect("HwBackedKeyStore::new for rotation rig");
    let mls_keystore: Arc<dyn KeyStore> = Arc::new(hw_keystore);
    client.core().swap_mls_keystore(mls_keystore);
    (client, mock, handle, vk)
}

// ============================================================================
// 1. Happy path
// ============================================================================

#[tokio::test]
async fn rotation_full_happy_path_returns_full_outcome_with_new_handle() {
    let (client, mock, old_handle, old_pk) = setup_rotation_rig().await;
    let core = client.core();
    let proof = fresh_proof();

    let kt_pub_count_before = core.kt_transport().published_entry_count();
    assert_eq!(
        kt_pub_count_before, 0,
        "test rig starts with empty KT publish log"
    );

    let outcome: RotationOutcomeFull = rotate_identity_full(
        &core,
        mock.clone(),
        old_handle.clone(),
        "session-9d.rotated.label",
        RotationReason::PlannedRotation,
        TEST_ROTATION_TIMESTAMP,
        proof,
    )
    .await
    .expect("rotate_identity_full happy path");

    assert_eq!(
        outcome.old_identity_pubkey, old_pk,
        "outcome reflects pre-rotation old_pk"
    );
    assert_ne!(
        outcome.new_identity_pubkey, old_pk,
        "rotation must yield a new pubkey"
    );
    assert_eq!(
        outcome.rotation_timestamp, TEST_ROTATION_TIMESTAMP,
        "outcome echoes caller-supplied timestamp"
    );
    assert_eq!(
        outcome.published_entry_size, KT_ENTRY_IDENTITY_ROTATION_WIRE_LEN,
        "ADR-008 EntryType 0x06 wire frame is always 235 bytes"
    );
    assert_eq!(
        outcome.new_identity_handle.label(),
        "session-9d.rotated.label",
        "outcome carries the requested HW handle alias"
    );

    let kt_pub_count_after = core.kt_transport().published_entry_count();
    assert_eq!(
        kt_pub_count_after,
        kt_pub_count_before + 1,
        "exactly one wire frame published"
    );
}

// ============================================================================
// 2. Round-trip: published wire bytes decode back to typed record
// ============================================================================

#[tokio::test]
async fn rotation_full_published_record_decodes_round_trip_byte_exact() {
    let (client, mock, old_handle, old_pk) = setup_rotation_rig().await;
    let core = client.core();
    let proof = fresh_proof();

    let outcome = rotate_identity_full(
        &core,
        mock.clone(),
        old_handle.clone(),
        "session-9d.round-trip.label",
        RotationReason::IdentityCompromise,
        TEST_ROTATION_TIMESTAMP,
        proof,
    )
    .await
    .expect("rotate_identity_full");

    let published_wire = core
        .kt_transport()
        .published_entries_snapshot()
        .into_iter()
        .next()
        .expect("at least one published wire frame");
    assert_eq!(
        published_wire.len(),
        KT_ENTRY_IDENTITY_ROTATION_WIRE_LEN,
        "wire frame length matches ADR-008 EntryType 0x06"
    );
    assert_eq!(
        published_wire[0], KT_ENTRY_IDENTITY_ROTATION_PREFIX,
        "wire frame prefix is 0x06"
    );

    let decoded = decode_kt_entry_identity_rotation(&published_wire)
        .expect("decode_kt_entry_identity_rotation succeeds");
    assert_eq!(decoded.version, AUTHORIZATION_WIRE_VERSION);
    assert_eq!(decoded.old_identity_pubkey, old_pk);
    assert_eq!(decoded.new_identity_pubkey, outcome.new_identity_pubkey);
    assert_eq!(decoded.rotation_timestamp, TEST_ROTATION_TIMESTAMP);
    assert_eq!(decoded.rotation_reason, RotationReason::IdentityCompromise);
    assert_eq!(decoded.code_recovery_public_half_proof, proof);
}

// ============================================================================
// 3. Local state swap: mls_keystore post-rotation returns new pubkey
// ============================================================================

#[tokio::test]
async fn rotation_full_swaps_mls_keystore_to_return_new_pubkey() {
    let (client, mock, old_handle, old_pk) = setup_rotation_rig().await;
    let core = client.core();

    // Pre-rotation: identity_public matches old_pk
    let pre_rotation_pk = core.mls_keystore().identity_public().to_bytes();
    assert_eq!(
        pre_rotation_pk, old_pk,
        "rig invariant: mls_keystore identity matches HW bootstrap vk"
    );

    let outcome = rotate_identity_full(
        &core,
        mock.clone(),
        old_handle.clone(),
        "session-9d.swap.label",
        RotationReason::PlannedRotation,
        TEST_ROTATION_TIMESTAMP,
        fresh_proof(),
    )
    .await
    .expect("rotate_identity_full");

    // Post-rotation: identity_public reflects new pubkey via swapped keystore
    let post_rotation_pk = core.mls_keystore().identity_public().to_bytes();
    assert_eq!(
        post_rotation_pk, outcome.new_identity_pubkey,
        "design spec acceptance #9: core.mls_keystore().identity_public() returns new pubkey post-rotation"
    );
    assert_ne!(
        post_rotation_pk, old_pk,
        "mls_keystore must NOT continue to return the old pubkey"
    );
}

// ============================================================================
// 4. Both Ed25519 signatures in the published record verify
// ============================================================================

#[tokio::test]
async fn rotation_full_published_record_signatures_verify_under_both_pubkeys() {
    let (client, mock, old_handle, old_pk) = setup_rotation_rig().await;
    let core = client.core();
    let proof = fresh_proof();
    let reason = RotationReason::CatastrophicRecovery;

    let outcome = rotate_identity_full(
        &core,
        mock.clone(),
        old_handle.clone(),
        "session-9d.dual-sig-verify.label",
        reason,
        TEST_ROTATION_TIMESTAMP,
        proof,
    )
    .await
    .expect("rotate_identity_full");

    let wire = core
        .kt_transport()
        .published_entries_snapshot()
        .into_iter()
        .next()
        .expect("published frame");
    let record = decode_kt_entry_identity_rotation(&wire).expect("decode");

    let canonical = canonical_signing_input_rotation(
        AUTHORIZATION_WIRE_VERSION,
        &old_pk,
        &outcome.new_identity_pubkey,
        TEST_ROTATION_TIMESTAMP,
        reason,
        &proof,
    );

    let old_vk = VerifyingKey::from_bytes(&old_pk).expect("old_pk decodes as Ed25519");
    let new_vk =
        VerifyingKey::from_bytes(&outcome.new_identity_pubkey).expect("new_pk decodes as Ed25519");

    let old_sig = Signature::from_slice(&record.old_identity_signature).expect("64-byte old sig");
    let new_sig = Signature::from_slice(&record.new_identity_signature).expect("64-byte new sig");

    old_vk
        .verify(&canonical, &old_sig)
        .expect("old_identity_signature MUST verify under old_pk over canonical input");
    new_vk
        .verify(&canonical, &new_sig)
        .expect("new_identity_signature MUST verify under new_pk over canonical input");
}

// ============================================================================
// 5. Pre-flight old_pk mismatch — refuses before HW callback called
// ============================================================================

#[tokio::test]
async fn rotation_full_rejects_old_pk_mismatch_between_mls_keystore_and_hw_callback() {
    // Setup an inconsistent state: mls_keystore reports vk_b but
    // hw_callback.verifying_key(handle_a) reports vk_a (≠ vk_b). The
    // facade must catch this in layer 1 (pre-flight cross-check) before
    // any HW state mutation or publish.
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap");
    let core = client.core();

    let mock = Arc::new(MockHwKeystore::new());
    let callback: Arc<dyn PersistentKeyStoreCallback> = mock.clone();
    let (handle_a, _vk_a) =
        bootstrap_hw_identity(&callback, "session-9d.mismatch.a").expect("bootstrap identity a");
    let (_handle_b, vk_b) =
        bootstrap_hw_identity(&callback, "session-9d.mismatch.b").expect("bootstrap identity b");

    // Wire HwBackedKeyStore with HANDLE_A but cached pubkey VK_B —
    // intentional mismatch.
    let hw_keystore = HwBackedKeyStore::new(0, callback.clone(), handle_a.clone(), vk_b)
        .expect("HwBackedKeyStore::new accepts arbitrary vk");
    let mls_keystore: Arc<dyn KeyStore> = Arc::new(hw_keystore);
    core.swap_mls_keystore(mls_keystore);

    let kt_pub_before = core.kt_transport().published_entry_count();
    let mock_len_before = mock.len();

    let result = rotate_identity_full(
        &core,
        mock.clone(),
        handle_a,
        "session-9d.mismatch.new",
        RotationReason::PlannedRotation,
        TEST_ROTATION_TIMESTAMP,
        fresh_proof(),
    )
    .await;

    match result {
        Err(ClientError::Internal(msg)) => {
            assert!(
                msg.contains("rotation pre-flight"),
                "error message must point at pre-flight stage, got: {msg}"
            );
            assert!(
                msg.contains("old_identity_pubkey mismatch"),
                "error must explicitly call out the mismatch, got: {msg}"
            );
        }
        other => panic!("expected ClientError::Internal mismatch, got {other:?}"),
    }

    assert_eq!(
        core.kt_transport().published_entry_count(),
        kt_pub_before,
        "no publish on pre-flight rejection"
    );
    assert_eq!(
        mock.len(),
        mock_len_before,
        "no new HW material generated on pre-flight rejection"
    );
}

// ============================================================================
// 6. HW callback KeyNotFound propagates as ClientError::Platform
// ============================================================================

#[tokio::test]
async fn rotation_full_propagates_hw_callback_key_not_found_as_platform_error() {
    // Bootstrap a baseline rig, then drop the actual handle from the
    // mock keystore — simulates a user-side keychain wipe between
    // bootstrap and rotation.
    let (client, mock, old_handle, _old_pk) = setup_rotation_rig().await;
    let core = client.core();
    let kt_pub_before = core.kt_transport().published_entry_count();

    mock.delete_identity(&old_handle).expect("delete identity");

    let result = rotate_identity_full(
        &core,
        mock.clone(),
        old_handle,
        "session-9d.keynotfound.new",
        RotationReason::PlannedRotation,
        TEST_ROTATION_TIMESTAMP,
        fresh_proof(),
    )
    .await;

    match result {
        Err(ClientError::Platform(msg)) => {
            assert!(
                msg.contains("hw key not found")
                    || msg.contains("hw_callback.verifying_key")
                    || msg.contains("verifying_key"),
                "diagnostic must reflect the KeyNotFound source, got: {msg}"
            );
        }
        other => panic!("expected ClientError::Platform, got {other:?}"),
    }
    assert_eq!(
        core.kt_transport().published_entry_count(),
        kt_pub_before,
        "no publish when pre-flight verifying_key fails"
    );
}

// ============================================================================
// 7. Two sequential rotations chain correctly
// ============================================================================

#[tokio::test]
async fn rotation_full_two_sequential_rotations_chain_pubkeys_correctly() {
    let (client, mock, handle_v0, pk_v0) = setup_rotation_rig().await;
    let core = client.core();

    // Rotation #1: v0 → v1
    let outcome_v1 = rotate_identity_full(
        &core,
        mock.clone(),
        handle_v0.clone(),
        "session-9d.chain.v1",
        RotationReason::PlannedRotation,
        TEST_ROTATION_TIMESTAMP,
        fresh_proof(),
    )
    .await
    .expect("rotation #1");

    assert_eq!(outcome_v1.old_identity_pubkey, pk_v0);
    assert_eq!(
        core.mls_keystore().identity_public().to_bytes(),
        outcome_v1.new_identity_pubkey,
        "post-rotation #1: mls_keystore reflects v1"
    );

    // Rotation #2: v1 → v2 (reads new old_pk = v1 from swapped mls_keystore)
    let outcome_v2 = rotate_identity_full(
        &core,
        mock.clone(),
        outcome_v1.new_identity_handle.clone(),
        "session-9d.chain.v2",
        RotationReason::IdentityCompromise,
        TEST_ROTATION_TIMESTAMP + 1,
        fresh_proof(),
    )
    .await
    .expect("rotation #2");

    assert_eq!(
        outcome_v2.old_identity_pubkey, outcome_v1.new_identity_pubkey,
        "rotation #2 picks up post-#1 pubkey as its old_pk"
    );
    assert_ne!(
        outcome_v2.new_identity_pubkey, outcome_v1.new_identity_pubkey,
        "rotation #2 yields a fresh v2 pubkey"
    );
    assert_ne!(outcome_v2.new_identity_pubkey, pk_v0, "v2 distinct from v0");

    // Final mls_keystore state reflects v2
    assert_eq!(
        core.mls_keystore().identity_public().to_bytes(),
        outcome_v2.new_identity_pubkey,
        "post-rotation #2: mls_keystore reflects v2"
    );

    // Both wire frames published
    assert_eq!(
        core.kt_transport().published_entry_count(),
        2,
        "two publish operations across the chain"
    );

    // Both decode successfully and chain consistently
    let frames = core.kt_transport().published_entries_snapshot();
    let frame_v1 = decode_kt_entry_identity_rotation(&frames[0]).expect("decode v1 frame");
    let frame_v2 = decode_kt_entry_identity_rotation(&frames[1]).expect("decode v2 frame");
    assert_eq!(frame_v1.old_identity_pubkey, pk_v0);
    assert_eq!(frame_v1.new_identity_pubkey, outcome_v1.new_identity_pubkey);
    assert_eq!(frame_v2.old_identity_pubkey, outcome_v1.new_identity_pubkey);
    assert_eq!(frame_v2.new_identity_pubkey, outcome_v2.new_identity_pubkey);
}

// ============================================================================
// 8. kt_witness_set / kt_transport handle unchanged
// ============================================================================

#[tokio::test]
async fn rotation_full_does_not_disturb_kt_witness_set_or_transport_arc_identity() {
    let (client, mock, old_handle, _old_pk) = setup_rotation_rig().await;
    let core = client.core();

    let kt_witness_len_before = core.kt_witness_set().await.len();
    let kt_transport_arc_before = Arc::as_ptr(&core.kt_transport());

    let _ = rotate_identity_full(
        &core,
        mock.clone(),
        old_handle,
        "session-9d.witness-set.new",
        RotationReason::PlannedRotation,
        TEST_ROTATION_TIMESTAMP,
        fresh_proof(),
    )
    .await
    .expect("rotate");

    let kt_witness_len_after = core.kt_witness_set().await.len();
    let kt_transport_arc_after = Arc::as_ptr(&core.kt_transport());

    assert_eq!(
        kt_witness_len_before, kt_witness_len_after,
        "kt_witness_set len unchanged across rotation (rotation is identity-scoped, not infra-scoped)"
    );
    assert_eq!(
        kt_transport_arc_before, kt_transport_arc_after,
        "kt_transport Arc identity stable across rotation"
    );
}

// ============================================================================
// 9. Unknown rotation reason tag — HW callback rejects, facade surfaces
// ============================================================================

/// Custom mock that always returns an "unknown tag" error from
/// `rotate_identity`, simulating either a buggy native impl or a caller
/// passing an out-of-range RotationReason. We can't construct a
/// `RotationReason` from an unknown tag in safe Rust, so this test
/// directly wraps `MockHwKeystore` and intercepts the rotate call.
struct ForceUnknownTagCallback {
    inner: Arc<MockHwKeystore>,
}

impl PersistentKeyStoreCallback for ForceUnknownTagCallback {
    fn generate_identity(
        &self,
        label: String,
    ) -> Result<HwKeyHandle, umbrella_client::keystore::hw_callback::HwKeystoreError> {
        self.inner.generate_identity(label)
    }
    fn sign_identity(
        &self,
        handle: &HwKeyHandle,
        data: &[u8],
    ) -> Result<Vec<u8>, umbrella_client::keystore::hw_callback::HwKeystoreError> {
        self.inner.sign_identity(handle, data)
    }
    fn wrap_secret(
        &self,
        handle: &HwKeyHandle,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, umbrella_client::keystore::hw_callback::HwKeystoreError> {
        self.inner.wrap_secret(handle, plaintext)
    }
    fn unwrap_secret(
        &self,
        handle: &HwKeyHandle,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, umbrella_client::keystore::hw_callback::HwKeystoreError> {
        self.inner.unwrap_secret(handle, ciphertext)
    }
    fn delete_identity(
        &self,
        handle: &HwKeyHandle,
    ) -> Result<(), umbrella_client::keystore::hw_callback::HwKeystoreError> {
        self.inner.delete_identity(handle)
    }
    fn verifying_key(
        &self,
        handle: &HwKeyHandle,
    ) -> Result<[u8; 32], umbrella_client::keystore::hw_callback::HwKeystoreError> {
        self.inner.verifying_key(handle)
    }
    fn rotate_identity(
        &self,
        _old_identity_handle: &HwKeyHandle,
        _new_identity_label: String,
        _old_identity_pubkey: [u8; 32],
        _rotation_timestamp: u64,
        _rotation_reason_tag: u8,
        _proof: [u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN],
    ) -> Result<
        umbrella_client::keystore::hw_callback::RotatedIdentityArtifact,
        umbrella_client::keystore::hw_callback::HwKeystoreError,
    > {
        Err(
            umbrella_client::keystore::hw_callback::HwKeystoreError::Native(
                "simulated unknown rotation_reason_tag rejection".into(),
            ),
        )
    }
}

#[tokio::test]
async fn rotation_full_surfaces_hw_callback_rotation_failure_as_platform_error() {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap");
    let core = client.core();

    let inner_mock = Arc::new(MockHwKeystore::new());
    let inner_callback: Arc<dyn PersistentKeyStoreCallback> = inner_mock.clone();
    let (handle, vk) =
        bootstrap_hw_identity(&inner_callback, "session-9d.force-fail.boot").expect("bootstrap");

    let force_fail: Arc<dyn PersistentKeyStoreCallback> = Arc::new(ForceUnknownTagCallback {
        inner: inner_mock.clone(),
    });

    let hw_keystore =
        HwBackedKeyStore::new(0, force_fail.clone(), handle.clone(), vk).expect("HwBackedKeyStore");
    core.swap_mls_keystore(Arc::new(hw_keystore));

    let kt_pub_before = core.kt_transport().published_entry_count();
    let mock_len_before = inner_mock.len();

    let result = rotate_identity_full(
        &core,
        force_fail.clone(),
        handle,
        "session-9d.force-fail.new",
        RotationReason::PlannedRotation,
        TEST_ROTATION_TIMESTAMP,
        fresh_proof(),
    )
    .await;

    match result {
        Err(ClientError::Platform(msg)) => {
            assert!(
                msg.contains("hw_callback.rotate_identity failed"),
                "diagnostic must point at HW callback failure source, got: {msg}"
            );
        }
        other => panic!("expected ClientError::Platform, got {other:?}"),
    }

    assert_eq!(
        core.kt_transport().published_entry_count(),
        kt_pub_before,
        "no publish on HW rotation failure"
    );
    assert_eq!(
        inner_mock.len(),
        mock_len_before,
        "no HW material added through the failing facade path"
    );
}

// ============================================================================
// 10. Outcome new_identity_handle round-trips into HwBackedKeyStore swap
// ============================================================================

#[tokio::test]
async fn rotation_full_swapped_keystore_routes_signing_through_new_handle() {
    // After rotation, signing via the swapped mls_keystore must use the
    // new handle (verified by checking that signatures verify under the
    // new pubkey, not the old).
    let (client, mock, old_handle, old_pk) = setup_rotation_rig().await;
    let core = client.core();

    let outcome = rotate_identity_full(
        &core,
        mock.clone(),
        old_handle,
        "session-9d.routing.new",
        RotationReason::PlannedRotation,
        TEST_ROTATION_TIMESTAMP,
        fresh_proof(),
    )
    .await
    .expect("rotation");

    // Sign a message through the swapped keystore.
    let post_swap = core.mls_keystore();
    let msg = b"post-rotation-routing-check";
    let sig = post_swap.sign_with_identity(msg);
    let sig_bytes: [u8; 64] = sig.to_bytes();
    let sig_obj = Signature::from_slice(&sig_bytes).expect("64-byte sig");

    let new_vk = VerifyingKey::from_bytes(&outcome.new_identity_pubkey).expect("new pk decodes");
    new_vk
        .verify(msg, &sig_obj)
        .expect("post-swap keystore signing routes through new_identity_handle");

    // Negative: old vk MUST NOT verify the post-rotation signature.
    let old_vk = VerifyingKey::from_bytes(&old_pk).expect("old pk decodes");
    assert!(
        old_vk.verify(msg, &sig_obj).is_err(),
        "old pubkey must not validate the new signature"
    );
}
