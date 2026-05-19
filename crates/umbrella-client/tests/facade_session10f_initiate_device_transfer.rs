//! F-CLIENT-FACADE-1 closure session 10f (2026-05-19): contract tests for
//! `initiate_device_transfer` — sixth and FINAL piece of session 10 milestone
//! closure, taking F-CLIENT-FACADE-1 9.94 → **10/10**.
//!
//! ## What's wired
//!
//! `initiate_device_transfer(core, hw_callback, approver_handle,
//! new_device_pubkey, ...)` orchestrates a 5-layer defence-in-depth chain
//! for an existing approver device to authorize a new device per SPEC-11
//! §4 device add flow:
//!
//! 1. policy_flags reserved-bits guard (pre-HW fail-closed).
//! 2. Resolve approver pubkey via `hw_callback.verifying_key(approver_handle)`.
//! 3. Self-approval (new == approver) rejection.
//! 4. HW sign the canonical approval input via `sign_identity`.
//! 5. Publish via session 9c `publish_device_authorization_approval`
//!    (Ed25519 re-verify under embedded approver pubkey).
//!
//! ## Coverage (9 scenarios)
//!
//! 1. Happy path: published 147-byte approval wire frame, KT counter
//!    increments, timestamp matches authorized_since_timestamp.
//! 2. Policy-flags reserved bits → `KtError::InvalidAuthorizationEntryWire(
//!    "policy_flags_reserved_bits_set")`, KT counter unchanged.
//! 3. Self-approval (new_device_pubkey == approver pubkey) → Internal.
//! 4. Published record's `approver_signature` Ed25519-verifies against
//!    `approver_device_pubkey` over `canonical_signing_input_approval`
//!    (end-to-end signature correctness check).
//! 5. HW `verifying_key` returns error → Platform.
//! 6. HW `sign_identity` returns error → Platform.
//! 7. HW signature wrong length (e.g., 65 bytes) → Internal.
//! 8. Published wire frame's first byte is the KT_ENTRY_DEVICE_AUTH_APPROVAL
//!    prefix (0x04) — confirms session 9c codec path was taken.
//! 9. Multiple successive `initiate_device_transfer` calls produce
//!    distinct wire frames (sequential publishing, no idempotency
//!    misbehaviour).

use std::sync::Arc;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand_core::OsRng;

use umbrella_backup::cloud_wrap::{
    canonical_signing_input_approval, ThresholdConfig, WrappingParams, AUTHORIZATION_WIRE_VERSION,
};

use umbrella_client::device_authorization::initiate_device_transfer;
use umbrella_client::error::ClientError;
use umbrella_client::facade::chat_common::UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT;
use umbrella_client::keystore::hw_callback::{
    bootstrap_hw_identity, HwKeyHandle, HwKeystoreError, MockHwKeystore, PersistentKeyStoreCallback,
};
use umbrella_client::{ClientConfig, UmbrellaClient};

use umbrella_identity::{IdentitySeed, MnemonicLanguage};
use umbrella_kt::{
    decode_kt_entry_device_authorization_approval, DEVICE_PUBKEY_LEN,
    KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_PREFIX,
};

const TEST_AUTHORIZED_SINCE: u64 = 1_716_000_000_000;
const TEST_HISTORY_CUTOFF: u64 = 1_716_000_000_000 - 86_400_000; // 24h prior
const VALID_POLICY_FLAGS: u8 = 0x01; // bit 0 set, reserved bits clear

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

/// Build a client + mock HW keystore + bootstrapped approver handle/pubkey.
/// Mirrors the session 9d `setup_rotation_rig` pattern, narrower scope:
/// only the HW + handle + pubkey are returned (no mls_keystore swap, since
/// `initiate_device_transfer` does not touch mls_keystore).
async fn setup_initiate_rig() -> (
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
    let (handle, vk) = bootstrap_hw_identity(&callback, "session-10f.rig.approver")
        .expect("bootstrap_hw_identity");
    (client, mock, handle, vk)
}

/// Build a deterministic 32-byte "new device pubkey" distinct from approver.
fn distinct_new_device_pubkey() -> [u8; DEVICE_PUBKEY_LEN] {
    let mut pk = [0u8; DEVICE_PUBKEY_LEN];
    for (i, b) in pk.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(0x80); // pattern unlikely to collide с random Ed25519 pk
    }
    pk
}

// ============================================================================
// 1. Happy path: 147-byte wire frame published, KT counter increments
// ============================================================================

#[tokio::test]
async fn initiate_device_transfer_happy_path_publishes_147_byte_frame() {
    let (client, mock, approver_handle, _approver_pk) = setup_initiate_rig().await;
    let core = client.core();
    let new_device_pubkey = distinct_new_device_pubkey();

    let kt_pub_count_before = core.kt_transport().published_entry_count();

    let outcome = initiate_device_transfer(
        &core,
        mock.clone(),
        approver_handle,
        new_device_pubkey,
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        VALID_POLICY_FLAGS,
    )
    .await
    .expect("initiate happy path");

    assert_eq!(
        outcome.published_entry_size, 147,
        "approval wire frame must be 147 bytes per session 9a' codec"
    );
    assert_eq!(
        outcome.timestamp, TEST_AUTHORIZED_SINCE,
        "outcome timestamp must echo authorized_since_timestamp"
    );

    let kt_pub_count_after = core.kt_transport().published_entry_count();
    assert_eq!(
        kt_pub_count_after,
        kt_pub_count_before + 1,
        "KT publish counter MUST increment by 1 on successful initiate"
    );
}

// ============================================================================
// 2. Policy_flags reserved bits rejected before HW round-trip
// ============================================================================

#[tokio::test]
async fn initiate_device_transfer_rejects_policy_flags_reserved_bits() {
    let (client, mock, approver_handle, _approver_pk) = setup_initiate_rig().await;
    let core = client.core();
    let new_device_pubkey = distinct_new_device_pubkey();

    let kt_pub_count_before = core.kt_transport().published_entry_count();

    // bit 7 set — falls inside POLICY_FLAGS_RESERVED_MASK (0xFE).
    let invalid_policy_flags = 0x80u8;
    let err = initiate_device_transfer(
        &core,
        mock,
        approver_handle,
        new_device_pubkey,
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        invalid_policy_flags,
    )
    .await
    .expect_err("reserved bits MUST fail closed");

    assert!(
        matches!(
            err,
            ClientError::Kt(umbrella_kt::KtError::InvalidAuthorizationEntryWire(
                "policy_flags_reserved_bits_set"
            ))
        ),
        "expected KtError::InvalidAuthorizationEntryWire policy_flags_reserved_bits_set, got: {err:?}"
    );

    let kt_pub_count_after = core.kt_transport().published_entry_count();
    assert_eq!(
        kt_pub_count_after, kt_pub_count_before,
        "KT publish counter MUST NOT change on reserved-bits rejection"
    );
}

// ============================================================================
// 3. Self-approval rejected (new == approver)
// ============================================================================

#[tokio::test]
async fn initiate_device_transfer_rejects_self_approval() {
    let (client, mock, approver_handle, approver_pk) = setup_initiate_rig().await;
    let core = client.core();

    let err = initiate_device_transfer(
        &core,
        mock,
        approver_handle,
        approver_pk, // new == approver — self-approval bug
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        VALID_POLICY_FLAGS,
    )
    .await
    .expect_err("self-approval MUST be rejected");

    assert!(
        matches!(&err, ClientError::Internal(msg) if msg.contains("self-approval not allowed")),
        "expected Internal self-approval rejection, got: {err:?}"
    );
}

// ============================================================================
// 4. Published record's approver_signature Ed25519-verifies under approver_pk
// ============================================================================

#[tokio::test]
async fn initiate_device_transfer_published_signature_verifies_under_approver_pubkey() {
    let (client, mock, approver_handle, approver_pk) = setup_initiate_rig().await;
    let core = client.core();
    let new_device_pubkey = distinct_new_device_pubkey();

    initiate_device_transfer(
        &core,
        mock,
        approver_handle,
        new_device_pubkey,
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        VALID_POLICY_FLAGS,
    )
    .await
    .expect("initiate happy path");

    // Pull the published wire frame from stub transport, decode, then
    // Ed25519-verify the signature against the approver's pubkey.
    let frames = core.kt_transport().published_entries_snapshot();
    let wire = frames.last().expect("at least one published entry").clone();
    let record = decode_kt_entry_device_authorization_approval(&wire).expect("decode 0x04 entry");

    let canonical = canonical_signing_input_approval(
        AUTHORIZATION_WIRE_VERSION,
        &record.new_device_pubkey,
        &record.approver_device_pubkey,
        record.authorized_since_timestamp,
        record.history_cutoff_timestamp,
        record.policy_flags,
    );

    let vk = VerifyingKey::from_bytes(&approver_pk).expect("approver_pk decodes");
    let sig = Signature::from_bytes(&record.approver_signature);
    vk.verify(&canonical, &sig)
        .expect("approver_signature MUST Ed25519-verify under approver_pk over canonical input");

    // Cross-check embedded fields.
    assert_eq!(
        record.approver_device_pubkey, approver_pk,
        "embedded approver_device_pubkey must equal HW pubkey"
    );
    assert_eq!(
        record.new_device_pubkey, new_device_pubkey,
        "embedded new_device_pubkey must equal caller input"
    );
}

// ============================================================================
// 5. HW verifying_key error → Platform
// ============================================================================

/// Mock that returns an error on `verifying_key` to exercise Layer 2 failure.
struct VerifyingKeyErrMock;

impl PersistentKeyStoreCallback for VerifyingKeyErrMock {
    fn generate_identity(&self, _label: String) -> Result<HwKeyHandle, HwKeystoreError> {
        unimplemented!("not used in this test")
    }
    fn sign_identity(
        &self,
        _handle: &HwKeyHandle,
        _data: &[u8],
    ) -> Result<Vec<u8>, HwKeystoreError> {
        unimplemented!("never reached — verifying_key fails first")
    }
    fn wrap_secret(
        &self,
        _handle: &HwKeyHandle,
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, HwKeystoreError> {
        unimplemented!()
    }
    fn unwrap_secret(
        &self,
        _handle: &HwKeyHandle,
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, HwKeystoreError> {
        unimplemented!()
    }
    fn delete_identity(&self, _handle: &HwKeyHandle) -> Result<(), HwKeystoreError> {
        unimplemented!()
    }
    fn verifying_key(&self, _handle: &HwKeyHandle) -> Result<[u8; 32], HwKeystoreError> {
        Err(HwKeystoreError::Native("verifying_key stub failure".into()))
    }
}

#[tokio::test]
async fn initiate_device_transfer_propagates_verifying_key_failure_as_platform() {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test");
    let core = client.core();
    let mock = Arc::new(VerifyingKeyErrMock);
    let handle = HwKeyHandle::new("session-10f.verify-fail-mock".to_string());
    let new_device_pubkey = distinct_new_device_pubkey();

    let err = initiate_device_transfer(
        &core,
        mock,
        handle,
        new_device_pubkey,
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        VALID_POLICY_FLAGS,
    )
    .await
    .expect_err("verifying_key failure MUST propagate");

    assert!(
        matches!(&err, ClientError::Platform(msg) if msg.contains("verifying_key")),
        "expected Platform with verifying_key context, got: {err:?}"
    );
}

// ============================================================================
// 6. HW sign_identity error → Platform
// ============================================================================

/// Mock that returns valid verifying_key but errors on sign_identity.
struct SignErrMock {
    pubkey: [u8; 32],
}

impl PersistentKeyStoreCallback for SignErrMock {
    fn generate_identity(&self, _label: String) -> Result<HwKeyHandle, HwKeystoreError> {
        unimplemented!()
    }
    fn sign_identity(
        &self,
        _handle: &HwKeyHandle,
        _data: &[u8],
    ) -> Result<Vec<u8>, HwKeystoreError> {
        Err(HwKeystoreError::Native("sign_identity stub failure".into()))
    }
    fn wrap_secret(
        &self,
        _handle: &HwKeyHandle,
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, HwKeystoreError> {
        unimplemented!()
    }
    fn unwrap_secret(
        &self,
        _handle: &HwKeyHandle,
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, HwKeystoreError> {
        unimplemented!()
    }
    fn delete_identity(&self, _handle: &HwKeyHandle) -> Result<(), HwKeystoreError> {
        unimplemented!()
    }
    fn verifying_key(&self, _handle: &HwKeyHandle) -> Result<[u8; 32], HwKeystoreError> {
        Ok(self.pubkey)
    }
}

#[tokio::test]
async fn initiate_device_transfer_propagates_sign_identity_failure_as_platform() {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test");
    let core = client.core();
    // verifying_key returns a deterministic pubkey distinct from new_device_pubkey.
    let approver_pk = [0xAA; 32];
    let mock = Arc::new(SignErrMock {
        pubkey: approver_pk,
    });
    let handle = HwKeyHandle::new("session-10f.sign-fail-mock".to_string());
    let new_device_pubkey = distinct_new_device_pubkey();
    assert_ne!(
        approver_pk, new_device_pubkey,
        "pubkeys must differ for this test"
    );

    let err = initiate_device_transfer(
        &core,
        mock,
        handle,
        new_device_pubkey,
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        VALID_POLICY_FLAGS,
    )
    .await
    .expect_err("sign_identity failure MUST propagate");

    assert!(
        matches!(&err, ClientError::Platform(msg) if msg.contains("sign_identity")),
        "expected Platform with sign_identity context, got: {err:?}"
    );
}

// ============================================================================
// 7. HW signature wrong length → Internal
// ============================================================================

/// Mock that returns a wrong-length signature (65 bytes instead of 64).
struct WrongLenSigMock {
    pubkey: [u8; 32],
}

impl PersistentKeyStoreCallback for WrongLenSigMock {
    fn generate_identity(&self, _label: String) -> Result<HwKeyHandle, HwKeystoreError> {
        unimplemented!()
    }
    fn sign_identity(
        &self,
        _handle: &HwKeyHandle,
        _data: &[u8],
    ) -> Result<Vec<u8>, HwKeystoreError> {
        Ok(vec![0u8; 65]) // 65 bytes — wrong length
    }
    fn wrap_secret(
        &self,
        _handle: &HwKeyHandle,
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, HwKeystoreError> {
        unimplemented!()
    }
    fn unwrap_secret(
        &self,
        _handle: &HwKeyHandle,
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, HwKeystoreError> {
        unimplemented!()
    }
    fn delete_identity(&self, _handle: &HwKeyHandle) -> Result<(), HwKeystoreError> {
        unimplemented!()
    }
    fn verifying_key(&self, _handle: &HwKeyHandle) -> Result<[u8; 32], HwKeystoreError> {
        Ok(self.pubkey)
    }
}

#[tokio::test]
async fn initiate_device_transfer_rejects_wrong_length_signature() {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test");
    let core = client.core();
    let approver_pk = [0xBB; 32];
    let mock = Arc::new(WrongLenSigMock {
        pubkey: approver_pk,
    });
    let handle = HwKeyHandle::new("session-10f.wrong-len-mock".to_string());
    let new_device_pubkey = distinct_new_device_pubkey();
    assert_ne!(approver_pk, new_device_pubkey);

    let err = initiate_device_transfer(
        &core,
        mock,
        handle,
        new_device_pubkey,
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        VALID_POLICY_FLAGS,
    )
    .await
    .expect_err("65-byte signature MUST be rejected");

    assert!(
        matches!(&err, ClientError::Internal(msg) if msg.contains("65 bytes, expected 64")),
        "expected Internal signature length error, got: {err:?}"
    );
}

// ============================================================================
// 8. Published wire frame's first byte is the 0x04 prefix (session 9c codec)
// ============================================================================

#[tokio::test]
async fn initiate_device_transfer_published_wire_starts_with_0x04_prefix() {
    let (client, mock, approver_handle, _approver_pk) = setup_initiate_rig().await;
    let core = client.core();
    let new_device_pubkey = distinct_new_device_pubkey();

    initiate_device_transfer(
        &core,
        mock,
        approver_handle,
        new_device_pubkey,
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        VALID_POLICY_FLAGS,
    )
    .await
    .expect("happy path");

    let frames = core.kt_transport().published_entries_snapshot();
    let wire = frames.last().expect("at least one published frame");
    assert_eq!(
        wire[0], KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_PREFIX,
        "first byte MUST equal KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_PREFIX (0x04)"
    );
    assert_eq!(
        wire[0], 0x04,
        "prefix constant must equal 0x04 per ADR-008 EntryType"
    );
}

// ============================================================================
// 9. Sequential initiates produce distinct wire frames
// ============================================================================

#[tokio::test]
async fn initiate_device_transfer_sequential_calls_publish_distinct_frames() {
    let (client, mock, approver_handle, _approver_pk) = setup_initiate_rig().await;
    let core = client.core();

    // Two distinct new devices.
    let mut new_pk_1 = distinct_new_device_pubkey();
    new_pk_1[0] = 0x10;
    let mut new_pk_2 = distinct_new_device_pubkey();
    new_pk_2[0] = 0x20;
    assert_ne!(new_pk_1, new_pk_2);

    let count_before = core.kt_transport().published_entry_count();

    initiate_device_transfer(
        &core,
        mock.clone(),
        approver_handle.clone(),
        new_pk_1,
        TEST_AUTHORIZED_SINCE,
        TEST_HISTORY_CUTOFF,
        VALID_POLICY_FLAGS,
    )
    .await
    .expect("first initiate");

    initiate_device_transfer(
        &core,
        mock,
        approver_handle,
        new_pk_2,
        TEST_AUTHORIZED_SINCE + 1, // different timestamp ensures different canonical input
        TEST_HISTORY_CUTOFF,
        VALID_POLICY_FLAGS,
    )
    .await
    .expect("second initiate");

    let count_after = core.kt_transport().published_entry_count();
    assert_eq!(
        count_after,
        count_before + 2,
        "two sequential initiates must increment counter by 2"
    );

    let frames = core.kt_transport().published_entries_snapshot();
    let last_two = &frames[frames.len() - 2..];
    assert_ne!(
        last_two[0], last_two[1],
        "two distinct (new_device, timestamp) inputs MUST produce distinct wire frames"
    );
    assert_eq!(last_two[0].len(), 147, "first frame 147 bytes");
    assert_eq!(last_two[1].len(), 147, "second frame 147 bytes");
}
