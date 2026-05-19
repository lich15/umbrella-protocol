//! F-CLIENT-FACADE-1 closure session 9c (2026-05-19): contract tests for
//! [`umbrella_client::device_authorization`] facade — publish-only device
//! authorization flows для ADR-008 EntryType 0x04 (approval) и 0x05
//! (revocation). Mirror'ит session 9b structure (publish-only, Q1-independent).
//!
//! ## Coverage
//!
//! Approval (0x04, 147-byte wire frame) — 6 tests:
//! 1. Happy path: real Ed25519 sig from approver SK → verify_self_consistent
//!    passes → publish → 147-byte wire frame on transport.
//! 2. Round-trip: published bytes decode back via session 9a' codec.
//! 3. Fail-closed: `policy_flags` with reserved bit set → early reject
//!    `InvalidAuthorizationEntryWire("policy_flags_reserved_bits_set")`.
//! 4. Fail-closed: invalid (random-bytes) approver signature → verify fails.
//! 5. Counter increment: `published_entry_count()` increments by 1 per
//!    successful call.
//! 6. Wire size invariant: published frame size == 147 bytes constant.
//!
//! Revocation (0x05, 138-byte wire frame) — 6 tests:
//! 1. Happy path: real Ed25519 sig from revoker SK → verify_self_consistent
//!    passes → publish → 138-byte wire frame.
//! 2. Self-revocation explicitly allowed (revoked == revoker).
//! 3. Round-trip: published bytes decode back via session 9a' codec.
//! 4. Fail-closed: invalid (random-bytes) revoker signature → verify fails.
//! 5. Counter increment: `published_entry_count()` increments by 1.
//! 6. Wire size invariant: published frame size == 138 bytes.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};

use umbrella_backup::cloud_wrap::{
    canonical_signing_input_approval, canonical_signing_input_revocation,
    AUTHORIZATION_WIRE_VERSION, POLICY_FLAG_HIGH_SECURITY,
};
use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};

use umbrella_client::device_authorization::{
    publish_device_authorization_approval, publish_device_authorization_revocation,
};
use umbrella_client::error::ClientError;
use umbrella_client::facade::chat_common::UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT;
use umbrella_client::{ClientConfig, UmbrellaClient};

use umbrella_identity::{IdentitySeed, MnemonicLanguage};
use umbrella_kt::{
    decode_kt_authorization_entry, KtAuthorizationEntry, KtError,
    KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_WIRE_LEN,
    KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_WIRE_LEN,
};

const TEST_AUTHORIZED_SINCE: u64 = 1_715_000_000_000;
const TEST_HISTORY_CUTOFF: u64 = 1_700_000_000_000;
const TEST_REVOCATION_TS: u64 = 1_716_000_000_000;

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
            config: ThresholdConfig::new(3, 5).expect("3-of-5"),
        },
        default_ciphersuite: UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
    }
}

#[allow(deprecated)]
fn test_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

async fn bootstrap_client() -> Arc<UmbrellaClient> {
    UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test")
}

fn fresh_keypair() -> (SigningKey, [u8; 32]) {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let sk = SigningKey::from_bytes(&secret);
    let vk = sk.verifying_key().to_bytes();
    (sk, vk)
}

// ============================================================================
// Tests — DeviceAuthorizationApproval (0x04)
// ============================================================================

#[tokio::test]
async fn publish_approval_happy_path_pushes_147_byte_wire_frame() {
    let alice = bootstrap_client().await;
    let (approver_sk, approver_pk) = fresh_keypair();
    let (_new_sk, new_pk) = fresh_keypair();
    let policy_flags = 0x00;

    let canonical = canonical_signing_input_approval(
        AUTHORIZATION_WIRE_VERSION,
        &new_pk,
        &approver_pk,
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        policy_flags,
    );
    let approver_sig = approver_sk.sign(&canonical).to_bytes();

    let outcome = publish_device_authorization_approval(
        &alice.core(),
        new_pk,
        approver_pk,
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        policy_flags,
        approver_sig,
    )
    .await
    .expect("publish honest approval");

    assert_eq!(
        outcome.published_entry_size,
        KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_WIRE_LEN
    );
    assert_eq!(outcome.timestamp, TEST_AUTHORIZED_SINCE);
    assert_eq!(alice.core().kt_transport().published_entry_count(), 1);
}

#[tokio::test]
async fn publish_approval_round_trip_decodes_via_dispatcher_to_approval_variant() {
    let alice = bootstrap_client().await;
    let (approver_sk, approver_pk) = fresh_keypair();
    let (_new_sk, new_pk) = fresh_keypair();
    let policy_flags = POLICY_FLAG_HIGH_SECURITY;
    let canonical = canonical_signing_input_approval(
        AUTHORIZATION_WIRE_VERSION,
        &new_pk,
        &approver_pk,
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        policy_flags,
    );
    let approver_sig = approver_sk.sign(&canonical).to_bytes();

    publish_device_authorization_approval(
        &alice.core(),
        new_pk,
        approver_pk,
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        policy_flags,
        approver_sig,
    )
    .await
    .expect("publish");

    let snapshot = alice.core().kt_transport().published_entries_snapshot();
    assert_eq!(snapshot.len(), 1);
    let decoded = decode_kt_authorization_entry(&snapshot[0]).expect("dispatch decode");
    match decoded {
        KtAuthorizationEntry::Approval(record) => {
            assert_eq!(record.new_device_pubkey, new_pk);
            assert_eq!(record.approver_device_pubkey, approver_pk);
            assert_eq!(record.authorized_since_timestamp, TEST_AUTHORIZED_SINCE);
            assert_eq!(record.history_cutoff_timestamp, TEST_HISTORY_CUTOFF);
            assert_eq!(record.policy_flags, policy_flags);
            assert_eq!(record.approver_signature, approver_sig);
        }
        other => panic!("expected Approval variant, got {other:?}"),
    }
}

#[tokio::test]
async fn publish_approval_fails_closed_when_policy_flags_has_reserved_bit_set() {
    let alice = bootstrap_client().await;
    let (_approver_sk, approver_pk) = fresh_keypair();
    let (_new_sk, new_pk) = fresh_keypair();
    // Bit 1 is reserved → must be 0. Set it to trip the policy_flags guard.
    let policy_flags = 0x02; // = 0b0000_0010, reserved bit 1 set

    let result = publish_device_authorization_approval(
        &alice.core(),
        new_pk,
        approver_pk,
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        policy_flags,
        [0u8; 64],
    )
    .await;

    match result {
        Err(ClientError::Kt(KtError::InvalidAuthorizationEntryWire(tag))) => {
            assert_eq!(
                tag, "policy_flags_reserved_bits_set",
                "reserved-bit policy_flags must surface as \
                 InvalidAuthorizationEntryWire(\"policy_flags_reserved_bits_set\"); \
                 got tag={tag}"
            );
        }
        other => panic!("policy_flags reserved bit set MUST fail-close early; got {other:?}"),
    }

    assert_eq!(
        alice.core().kt_transport().published_entry_count(),
        0,
        "no publish must occur when policy_flags guard fires"
    );
}

#[tokio::test]
async fn publish_approval_fails_closed_with_invalid_signature_random_bytes() {
    let alice = bootstrap_client().await;
    let (_approver_sk, approver_pk) = fresh_keypair();
    let (_new_sk, new_pk) = fresh_keypair();
    let mut bogus_sig = [0u8; 64];
    OsRng.fill_bytes(&mut bogus_sig);

    let result = publish_device_authorization_approval(
        &alice.core(),
        new_pk,
        approver_pk,
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        0x00,
        bogus_sig,
    )
    .await;

    assert!(
        matches!(result, Err(ClientError::Internal(_))),
        "invalid sig MUST fail-close at verify_self_consistent; got {result:?}"
    );
    assert_eq!(alice.core().kt_transport().published_entry_count(), 0);
}

#[tokio::test]
async fn publish_approval_fails_closed_with_signature_over_wrong_canonical_input() {
    // Caller signs canonical for different (new_pk, approver_pk) but submits
    // the actual record fields — signature won't validate against
    // approver_pk over the actual canonical input.
    let alice = bootstrap_client().await;
    let (approver_sk, approver_pk) = fresh_keypair();
    let (_new_sk_intended, new_pk_intended) = fresh_keypair();
    let (_other_sk, other_pk) = fresh_keypair();

    // Sign canonical for `other_pk` as the new_device, but publish with
    // `new_pk_intended`.
    let canonical_wrong = canonical_signing_input_approval(
        AUTHORIZATION_WIRE_VERSION,
        &other_pk,
        &approver_pk,
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        0x00,
    );
    let sig_over_wrong = approver_sk.sign(&canonical_wrong).to_bytes();

    let result = publish_device_authorization_approval(
        &alice.core(),
        new_pk_intended, // doesn't match what was signed
        approver_pk,
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        0x00,
        sig_over_wrong,
    )
    .await;

    assert!(
        matches!(result, Err(ClientError::Internal(_))),
        "sig over wrong canonical input MUST fail-close; got {result:?}"
    );
    assert_eq!(alice.core().kt_transport().published_entry_count(), 0);
}

#[tokio::test]
async fn publish_approval_counter_increments_once_per_successful_publish() {
    let alice = bootstrap_client().await;
    assert_eq!(alice.core().kt_transport().published_entry_count(), 0);

    // Two successive honest publishes.
    for i in 0..2 {
        let (approver_sk, approver_pk) = fresh_keypair();
        let (_new_sk, new_pk) = fresh_keypair();
        let canonical = canonical_signing_input_approval(
            AUTHORIZATION_WIRE_VERSION,
            &new_pk,
            &approver_pk,
            TEST_AUTHORIZED_SINCE + i,
            TEST_HISTORY_CUTOFF,
            0x00,
        );
        let approver_sig = approver_sk.sign(&canonical).to_bytes();

        publish_device_authorization_approval(
            &alice.core(),
            new_pk,
            approver_pk,
            TEST_AUTHORIZED_SINCE + i,
            TEST_HISTORY_CUTOFF,
            0x00,
            approver_sig,
        )
        .await
        .expect("publish");
    }

    assert_eq!(
        alice.core().kt_transport().published_entry_count(),
        2,
        "two honest publishes → counter = 2"
    );
}

// ============================================================================
// Tests — DeviceAuthorizationRevocation (0x05)
// ============================================================================

#[tokio::test]
async fn publish_revocation_happy_path_pushes_138_byte_wire_frame() {
    let alice = bootstrap_client().await;
    let (revoker_sk, revoker_pk) = fresh_keypair();
    let (_revoked_sk, revoked_pk) = fresh_keypair();

    let canonical = canonical_signing_input_revocation(
        AUTHORIZATION_WIRE_VERSION,
        &revoked_pk,
        &revoker_pk,
        TEST_REVOCATION_TS,
    );
    let revoker_sig = revoker_sk.sign(&canonical).to_bytes();

    let outcome = publish_device_authorization_revocation(
        &alice.core(),
        revoked_pk,
        revoker_pk,
        TEST_REVOCATION_TS,
        revoker_sig,
    )
    .await
    .expect("publish honest revocation");

    assert_eq!(
        outcome.published_entry_size,
        KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_WIRE_LEN
    );
    assert_eq!(outcome.timestamp, TEST_REVOCATION_TS);
    assert_eq!(alice.core().kt_transport().published_entry_count(), 1);
}

#[tokio::test]
async fn publish_revocation_allows_self_revocation_revoked_equals_revoker() {
    // SPEC-11 §4: self-revocation is legitimate (device retires itself).
    // No early reject for revoked_pk == revoker_pk.
    let alice = bootstrap_client().await;
    let (sk, pk) = fresh_keypair();

    let canonical = canonical_signing_input_revocation(
        AUTHORIZATION_WIRE_VERSION,
        &pk, // revoked == revoker
        &pk,
        TEST_REVOCATION_TS,
    );
    let sig = sk.sign(&canonical).to_bytes();

    let outcome =
        publish_device_authorization_revocation(&alice.core(), pk, pk, TEST_REVOCATION_TS, sig)
            .await
            .expect("self-revocation MUST succeed");
    assert_eq!(
        outcome.published_entry_size,
        KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_WIRE_LEN
    );
}

#[tokio::test]
async fn publish_revocation_round_trip_decodes_via_dispatcher_to_revocation_variant() {
    let alice = bootstrap_client().await;
    let (revoker_sk, revoker_pk) = fresh_keypair();
    let (_, revoked_pk) = fresh_keypair();
    let canonical = canonical_signing_input_revocation(
        AUTHORIZATION_WIRE_VERSION,
        &revoked_pk,
        &revoker_pk,
        TEST_REVOCATION_TS,
    );
    let revoker_sig = revoker_sk.sign(&canonical).to_bytes();

    publish_device_authorization_revocation(
        &alice.core(),
        revoked_pk,
        revoker_pk,
        TEST_REVOCATION_TS,
        revoker_sig,
    )
    .await
    .expect("publish");

    let snapshot = alice.core().kt_transport().published_entries_snapshot();
    assert_eq!(snapshot.len(), 1);
    let decoded = decode_kt_authorization_entry(&snapshot[0]).expect("dispatch decode");
    match decoded {
        KtAuthorizationEntry::Revocation(record) => {
            assert_eq!(record.revoked_device_pubkey, revoked_pk);
            assert_eq!(record.revoker_device_pubkey, revoker_pk);
            assert_eq!(record.revocation_timestamp, TEST_REVOCATION_TS);
            assert_eq!(record.revoker_signature, revoker_sig);
        }
        other => panic!("expected Revocation variant, got {other:?}"),
    }
}

#[tokio::test]
async fn publish_revocation_fails_closed_with_invalid_signature_random_bytes() {
    let alice = bootstrap_client().await;
    let (_revoker_sk, revoker_pk) = fresh_keypair();
    let (_, revoked_pk) = fresh_keypair();
    let mut bogus_sig = [0u8; 64];
    OsRng.fill_bytes(&mut bogus_sig);

    let result = publish_device_authorization_revocation(
        &alice.core(),
        revoked_pk,
        revoker_pk,
        TEST_REVOCATION_TS,
        bogus_sig,
    )
    .await;

    assert!(matches!(result, Err(ClientError::Internal(_))));
    assert_eq!(alice.core().kt_transport().published_entry_count(), 0);
}

#[tokio::test]
async fn publish_revocation_counter_increments_once_per_successful_publish() {
    let alice = bootstrap_client().await;
    assert_eq!(alice.core().kt_transport().published_entry_count(), 0);

    for i in 0..3 {
        let (revoker_sk, revoker_pk) = fresh_keypair();
        let (_, revoked_pk) = fresh_keypair();
        let canonical = canonical_signing_input_revocation(
            AUTHORIZATION_WIRE_VERSION,
            &revoked_pk,
            &revoker_pk,
            TEST_REVOCATION_TS + i,
        );
        let revoker_sig = revoker_sk.sign(&canonical).to_bytes();

        publish_device_authorization_revocation(
            &alice.core(),
            revoked_pk,
            revoker_pk,
            TEST_REVOCATION_TS + i,
            revoker_sig,
        )
        .await
        .expect("publish");
    }

    assert_eq!(
        alice.core().kt_transport().published_entry_count(),
        3,
        "three honest publishes → counter = 3"
    );
}

#[tokio::test]
async fn publish_revocation_wire_size_invariant_138_bytes() {
    // Constant pin — guards against accidental wire-format change.
    assert_eq!(KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_WIRE_LEN, 138);
}

#[tokio::test]
async fn publish_approval_wire_size_invariant_147_bytes() {
    // Constant pin — guards against accidental wire-format change.
    assert_eq!(KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_WIRE_LEN, 147);
}
