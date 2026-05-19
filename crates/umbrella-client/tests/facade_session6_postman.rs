//! F-CLIENT-FACADE-1 closure session 6 (2026-05-19): contract tests for
//! Welcome distribution через blind-postman-svc и `CloudChat::cloud_sync_history`
//! end-to-end через Cloud-wrap 3-of-5 unwrap fan-out + outer ChaCha20-Poly1305
//! decrypt.
//!
//! ## Coverage
//!
//! - **Welcome distribution**:
//!   - `add_member_publishes_welcome_into_recipient_postman_inbox`
//!   - `fetch_pending_welcomes_returns_published_welcome_bytes_in_order`
//!   - `fetch_pending_welcomes_drains_queue_second_call_returns_empty`
//!   - `bob_opens_chat_from_welcome_and_joins_alice_group_at_epoch_1`
//!
//! - **cloud_sync_history**:
//!   - `cloud_sync_history_returns_empty_when_no_entries_staged`
//!   - `cloud_sync_history_3_of_5_unwrap_recovers_plaintext_from_staged_entry`
//!   - `cloud_sync_history_fails_closed_with_only_2_of_5_shares_returned`
//!   - `cloud_sync_history_skips_entries_below_since_timestamp`
//!   - `cloud_sync_history_propagates_aead_decrypt_failed_on_tampered_ciphertext`
//!   - `cloud_sync_history_drains_multiple_entries_in_insertion_order`
//!
//! Эти тесты pin'ят session-6 contract: новое устройство получает Welcome
//! через postman + unwrap'ит pre-staged Cloud history через 3-of-5
//! Sealed Server fan-out + outer AEAD decrypt → plaintext.

use std::sync::Arc;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use rand_core::{OsRng, RngCore};
use umbrella_backup::cloud_wrap::aead::decompress_point;
use umbrella_backup::cloud_wrap::threshold::shamir_split_for_testing;
use umbrella_backup::cloud_wrap::wire::canonical_nonce;
use umbrella_backup::cloud_wrap::{
    wrap_message_key, CanonicalAad, ServerUnwrapShare, ThresholdConfig, WitnessIndex, WrappedKey,
    WrappingParams, DEFAULT_TOTAL, MESSAGE_KEY_LEN, POINT_LEN, PROTOCOL_VERSION,
};
use umbrella_client::core::CloudHistoryEntry;
use umbrella_client::facade::chat_common::{
    ChatSettings, PeerId, Timestamp, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
};
use umbrella_client::{ClientConfig, CloudChat, SecretChat, UmbrellaClient};
use umbrella_identity::{
    Clock, IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock,
};
use umbrella_mls::{build_device_key_package, UmbrellaCiphersuite, UmbrellaProvider};

/// Default Umbrella classical ciphersuite (RFC 9420 §17.1
/// `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`).
const TEST_CS: UmbrellaCiphersuite = UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519;
/// Stable anchor unix-time для tests.
const T0: u64 = 1_700_000_000;

#[allow(
    deprecated,
    reason = "test seed gen — same as facade_create_group_gateway.rs"
)]
fn test_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

/// Конструирует `ClientConfig` с custom `wrapping_params` для Cloud-wrap
/// tests. Главная отличие от facade_create_group_gateway::test_config —
/// здесь wrapping_params не stub'ы (zero pubkeys), а реальные
/// `Y = K·G` + 5 server_pubkeys `Y_i = k_i·G` derived из known Shamir
/// shares. Это позволяет тесту compute partial shares для
/// `StubUnwrapTransport::push_response`.
fn test_config_with_wrapping_params(params: WrappingParams) -> ClientConfig {
    ClientConfig {
        sealed_server_urls: (1..=5).map(|i| format!("http://stub-{i}:8080")).collect(),
        postman_url: "http://stub-postman:8080".into(),
        kt_url: "http://stub-kt:8080".into(),
        call_relay_url: "http://stub-call-relay:8080".into(),
        kt_monitor_interval_secs: 3600,
        wrapping_params: params,
        default_ciphersuite: UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
    }
}

/// Setup WrappingParams вокруг random Shamir scalar `K` (3-of-5).
/// Returns (params, shares) — params для ClientConfig, shares для
/// compute_partial_share при staging unwrap_transport responses.
fn setup_wrapping_params() -> (WrappingParams, Vec<(WitnessIndex, Scalar)>) {
    let config = ThresholdConfig::default();
    let k = Scalar::random(&mut OsRng);
    let shares = shamir_split_for_testing(k, config, &mut OsRng);
    let y = RISTRETTO_BASEPOINT_POINT * k;
    let mut server_pubkeys = [[0u8; POINT_LEN]; DEFAULT_TOTAL as usize];
    for (wi, k_i) in shares.iter() {
        let yi = RISTRETTO_BASEPOINT_POINT * *k_i;
        server_pubkeys[(wi.get() - 1) as usize] = yi.compress().to_bytes();
    }
    let params = WrappingParams {
        version: PROTOCOL_VERSION,
        main_pubkey: y.compress().to_bytes(),
        server_pubkeys,
        config,
    };
    (params, shares.iter().copied().collect())
}

/// Compute partial share `partial = k_i · R` для given (wi, k_i) и wrapped key.
/// Зеркалит helper в `crates/umbrella-tests/tests/stage5_milestone.rs:97`.
fn compute_partial_share(wi: WitnessIndex, k_i: Scalar, wrapped: &WrappedKey) -> ServerUnwrapShare {
    let r = decompress_point(&wrapped.ephemeral_r).unwrap();
    let partial = (k_i * r).compress().to_bytes();
    ServerUnwrapShare {
        witness_index: wi,
        partial,
    }
}

/// Tests-side at-rest message encrypt under random `message_key`. Mirrors
/// what production sender SHOULD do (session 7+ wire-up): pick random
/// 32-byte `message_key`, ChaCha20-Poly1305 encrypt plaintext under
/// `message_key` + deterministic nonce (`canonical_nonce(chat_id, msg_seq)`)
/// + canonical AAD, then wrap `message_key` via Cloud-wrap.
struct StagedEntry {
    entry: CloudHistoryEntry,
    /// Pre-computed shares ≥3 для stub dispatch (insertion order).
    /// Pre-computed partial shares (≥3) for staging the stub unwrap transport.
    partial_shares: Vec<ServerUnwrapShare>,
}

/// Stage a single Cloud-mode at-rest entry: wrap random `message_key`, encrypt
/// `plaintext` под `message_key`, compute partial shares for `share_count`
/// первых Sealed Servers. Returns assembled `StagedEntry` ready to be pushed
/// to `StubPostmanTransport.push_cloud_history` + shares to
/// `StubUnwrapTransport.push_response`.
fn stage_cloud_entry(
    params: &WrappingParams,
    shares: &[(WitnessIndex, Scalar)],
    sender_pk: [u8; 32],
    recipient_pk: [u8; 32],
    chat_id: [u8; 32],
    msg_seq: u64,
    sent_ts_ms: u64,
    plaintext: &[u8],
    share_count: usize,
) -> StagedEntry {
    // Random message_key.
    let mut message_key = [0u8; MESSAGE_KEY_LEN];
    OsRng.fill_bytes(&mut message_key);

    // CanonicalAad binds sender/recipient/chat_id/msg_seq.
    let aad = CanonicalAad {
        sender_identity_pubkey: sender_pk,
        recipient_device_pubkey: recipient_pk,
        chat_id,
        msg_seq,
    };

    // Cloud-wrap the message_key.
    let wrapped_key =
        wrap_message_key(params, &message_key, &aad, &mut OsRng).expect("wrap_message_key staging");

    // Outer ChaCha20-Poly1305 encrypt plaintext under message_key with
    // deterministic nonce + canonical AAD bytes (matches facade decrypt
    // path in cloud_sync_history_impl).
    let cipher = ChaCha20Poly1305::new((&message_key).into());
    let nonce_bytes = canonical_nonce(&chat_id, msg_seq);
    let aad_bytes = aad.canonical_bytes();
    let ciphertext_at_rest = cipher
        .encrypt(
            (&nonce_bytes).into(),
            Payload {
                msg: plaintext,
                aad: &aad_bytes,
            },
        )
        .expect("ChaCha20Poly1305 encrypt staging");

    // msg_id из 16 random bytes.
    let mut msg_id = [0u8; 16];
    OsRng.fill_bytes(&mut msg_id);

    let entry = CloudHistoryEntry {
        msg_id,
        sender: sender_pk,
        sent_ts_ms,
        msg_seq,
        ciphertext_at_rest,
        wrapped_key,
    };

    // Compute partial shares для `share_count` первых Sealed Servers.
    let partial_shares: Vec<ServerUnwrapShare> = shares
        .iter()
        .take(share_count)
        .map(|(wi, k_i)| compute_partial_share(*wi, *k_i, &wrapped_key))
        .collect();

    StagedEntry {
        entry,
        partial_shares,
    }
}

/// Sister non-facade MLS client (mirrors helper в facade_create_group_gateway).
struct SisterClient {
    ks: Arc<InMemoryKeyStore>,
    provider: UmbrellaProvider,
    device_index: u32,
}

impl SisterClient {
    fn new() -> Self {
        let seed = test_seed();
        let ks = InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>).unwrap();
        ks.add_device(0, None).unwrap();
        Self {
            ks: Arc::new(ks),
            provider: UmbrellaProvider::default(),
            device_index: 0,
        }
    }

    fn identity_pubkey_bytes(&self) -> [u8; 32] {
        self.ks.identity_public().to_bytes()
    }

    fn peer_id(&self) -> PeerId {
        PeerId(self.identity_pubkey_bytes())
    }

    fn publish_key_package_bytes(&self) -> Vec<u8> {
        let bundle =
            build_device_key_package(&self.provider, self.ks.as_ref(), self.device_index, TEST_CS)
                .expect("build_device_key_package");
        bundle
            .key_package()
            .tls_serialize_detached()
            .expect("KeyPackage tls_serialize")
    }
}

async fn bootstrap_client_with_default_config() -> Arc<UmbrellaClient> {
    let (params, _) = setup_wrapping_params();
    UmbrellaClient::bootstrap_for_test(test_config_with_wrapping_params(params), test_seed())
        .await
        .expect("bootstrap_for_test")
}

// ============================================================================
// Welcome distribution tests
// ============================================================================

#[tokio::test]
async fn add_member_publishes_welcome_into_recipient_postman_inbox() {
    let alice = bootstrap_client_with_default_config().await;
    let alice_chat = CloudChat::create(alice.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice create");

    let bob = SisterClient::new();
    let bob_kp_bytes = bob.publish_key_package_bytes();

    let welcome = alice_chat
        .add_member(bob.peer_id(), bob_kp_bytes)
        .await
        .expect("add_member");

    // Welcome should also exist in postman inbox keyed by Bob's identity.
    let pending = alice
        .core()
        .fetch_pending_welcomes(bob.identity_pubkey_bytes())
        .await;
    assert_eq!(
        pending.len(),
        1,
        "F-CLIENT-FACADE-1 session 6: add_member MUST auto-publish Welcome into postman"
    );
    assert_eq!(
        pending[0], welcome,
        "postman-inbox Welcome bytes MUST match add_member return value"
    );
}

#[tokio::test]
async fn fetch_pending_welcomes_returns_published_welcome_bytes_in_order() {
    let alice = bootstrap_client_with_default_config().await;
    let alice_chat = CloudChat::create(alice.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice create");

    let bob = SisterClient::new();
    let charlie = SisterClient::new();

    let w_bob = alice_chat
        .add_member(bob.peer_id(), bob.publish_key_package_bytes())
        .await
        .expect("add bob");
    let w_charlie = alice_chat
        .add_member(charlie.peer_id(), charlie.publish_key_package_bytes())
        .await
        .expect("add charlie");

    let bob_inbox = alice
        .core()
        .fetch_pending_welcomes(bob.identity_pubkey_bytes())
        .await;
    let charlie_inbox = alice
        .core()
        .fetch_pending_welcomes(charlie.identity_pubkey_bytes())
        .await;

    assert_eq!(bob_inbox.len(), 1, "Bob receives exactly one Welcome");
    assert_eq!(
        charlie_inbox.len(),
        1,
        "Charlie receives exactly one Welcome"
    );
    assert_eq!(bob_inbox[0], w_bob);
    assert_eq!(charlie_inbox[0], w_charlie);
}

#[tokio::test]
async fn fetch_pending_welcomes_drains_queue_second_call_returns_empty() {
    let alice = bootstrap_client_with_default_config().await;
    let alice_chat = CloudChat::create(alice.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice create");

    let bob = SisterClient::new();
    let _ = alice_chat
        .add_member(bob.peer_id(), bob.publish_key_package_bytes())
        .await
        .expect("add bob");

    let first = alice
        .core()
        .fetch_pending_welcomes(bob.identity_pubkey_bytes())
        .await;
    assert_eq!(first.len(), 1, "first drain returns the published Welcome");

    let second = alice
        .core()
        .fetch_pending_welcomes(bob.identity_pubkey_bytes())
        .await;
    assert!(
        second.is_empty(),
        "second drain MUST be empty — fetch is one-shot"
    );
}

#[tokio::test]
async fn bob_opens_chat_from_welcome_and_joins_alice_group_at_epoch_1() {
    // Setup: Alice's facade + Bob's facade (independent ClientCores). Alice
    // creates a chat and adds Bob via add_member (auto-publishes Welcome).
    // Bob's facade then fetches the pending Welcome from his own postman
    // inbox (a separate StubPostmanTransport instance) and calls
    // CloudChat::open_from_welcome — joining at epoch 1 + registering in
    // his ClientCore.groups.
    //
    // NB: because alice's and bob's `ClientCore.postman_transport` are
    // independent stubs, we have to manually relay the Welcome bytes from
    // Alice's postman to Bob's postman (production: blind-postman-svc is
    // a single shared service). For this test it suffices to verify that
    // open_from_welcome works against arbitrary Welcome bytes; the relay
    // step is the postman-service contract, not the facade contract.
    let alice = bootstrap_client_with_default_config().await;
    let bob = bootstrap_client_with_default_config().await;
    let bob_identity_pk = bob.core().mls_keystore().identity_public().to_bytes();

    let alice_chat = CloudChat::create(alice.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice create");

    // Build Bob's KeyPackage via his own keystore (not sister) so identity_pk
    // is real and matches what bob.core().mls_keystore().identity_public() returns.
    let bob_provider = bob.core().mls_provider();
    let bob_keystore = bob.core().mls_keystore();
    let bob_kp_bundle =
        build_device_key_package(bob_provider.as_ref(), bob_keystore.as_ref(), 0, TEST_CS)
            .expect("build bob KP");
    let bob_kp_bytes = bob_kp_bundle
        .key_package()
        .tls_serialize_detached()
        .unwrap();

    let welcome = alice_chat
        .add_member(PeerId(bob_identity_pk), bob_kp_bytes)
        .await
        .expect("add bob");

    // Production: postman-svc holds the Welcome; here we relay it manually
    // into Bob's stub postman so his fetch_pending_welcomes returns it.
    bob.core()
        .postman_transport()
        .push_welcome(bob_identity_pk, welcome.clone());
    let pending = bob.core().fetch_pending_welcomes(bob_identity_pk).await;
    assert_eq!(pending.len(), 1);

    // Bob opens chat from the fetched Welcome via the facade method.
    let bob_chat = CloudChat::open_from_welcome(bob.core(), &pending[0])
        .await
        .expect("CloudChat::open_from_welcome");

    assert_eq!(
        bob_chat.chat_id(),
        alice_chat.chat_id(),
        "Bob's chat_id MUST match Alice's — same MLS GroupId"
    );

    // Bob's facade now has the group registered; epoch=1 because add_member
    // commit was already merged on Alice's side and the Welcome carries the
    // post-commit GroupContext.
    let bob_group_arc = bob
        .core()
        .get_group(bob_chat.chat_id())
        .await
        .expect("Bob's group registered after open_from_welcome");
    let bob_group = bob_group_arc.lock().await;
    assert_eq!(
        bob_group.epoch(),
        1,
        "join_from_welcome puts Bob at epoch 1"
    );
    assert_eq!(bob_group.member_count(), 2, "Alice + Bob");
    assert_eq!(bob_group.ciphersuite(), TEST_CS);

    // SecretChat::open_from_welcome shares same code path — quick sanity smoke.
    let _ = SecretChat::open(bob.core(), bob_chat.chat_id())
        .await
        .expect("secret_chat open works against the same registered group_id");
}

// ============================================================================
// cloud_sync_history tests
// ============================================================================

#[tokio::test]
async fn cloud_sync_history_returns_empty_when_no_entries_staged() {
    let alice = bootstrap_client_with_default_config().await;
    let alice_chat = CloudChat::create(alice.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice create");

    let history = alice_chat
        .cloud_sync_history(None)
        .await
        .expect("cloud_sync_history with empty postman returns empty Vec");

    assert!(history.is_empty());
}

#[tokio::test]
async fn cloud_sync_history_3_of_5_unwrap_recovers_plaintext_from_staged_entry() {
    let (params, shares) = setup_wrapping_params();
    let config = test_config_with_wrapping_params(params.clone());
    let alice = UmbrellaClient::bootstrap_for_test(config, test_seed())
        .await
        .expect("bootstrap");
    let alice_chat = CloudChat::create(alice.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice create");

    // Recipient device pubkey = Alice's own MLS keystore identity (single-
    // device cloud_sync_history scenario; new-device join_from_welcome flow
    // is covered separately above).
    let recipient_pk = alice.core().mls_keystore().identity_public().to_bytes();
    let sender_pk = [0x11u8; 32];
    let plaintext = b"hello new device, this is the past";

    let staged = stage_cloud_entry(
        &params,
        &shares,
        sender_pk,
        recipient_pk,
        alice_chat.chat_id().0,
        /* msg_seq */ 0,
        /* sent_ts_ms */ T0 * 1000 + 100,
        plaintext,
        /* share_count */ 3,
    );

    alice
        .core()
        .postman_transport()
        .push_cloud_history(alice_chat.chat_id().0, staged.entry);
    alice
        .core()
        .stub_unwrap_transport()
        .expect("stub unwrap transport")
        .push_response(staged.partial_shares);

    let history = alice_chat
        .cloud_sync_history(None)
        .await
        .expect("cloud_sync_history with 3-of-5 unwrap succeeds");

    assert_eq!(history.len(), 1);
    let recovered = &history[0];
    assert_eq!(
        recovered.text.as_bytes(),
        plaintext,
        "recovered plaintext MUST match what sender encrypted"
    );
    assert_eq!(recovered.sender, PeerId(sender_pk));
    assert_eq!(recovered.timestamp, T0 * 1000 + 100);
    assert_eq!(recovered.chat_id, alice_chat.chat_id());
}

#[tokio::test]
async fn cloud_sync_history_fails_closed_with_only_2_of_5_shares_returned() {
    let (params, shares) = setup_wrapping_params();
    let config = test_config_with_wrapping_params(params.clone());
    let alice = UmbrellaClient::bootstrap_for_test(config, test_seed())
        .await
        .expect("bootstrap");
    let alice_chat = CloudChat::create(alice.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice create");

    let recipient_pk = alice.core().mls_keystore().identity_public().to_bytes();
    let staged = stage_cloud_entry(
        &params,
        &shares,
        [0x22u8; 32],
        recipient_pk,
        alice_chat.chat_id().0,
        0,
        T0 * 1000,
        b"unreachable plaintext",
        /* share_count */ 2,
    );

    alice
        .core()
        .postman_transport()
        .push_cloud_history(alice_chat.chat_id().0, staged.entry);
    alice
        .core()
        .stub_unwrap_transport()
        .unwrap()
        .push_response(staged.partial_shares);

    let result = alice_chat.cloud_sync_history(None).await;
    assert!(
        result.is_err(),
        "cloud_sync_history MUST fail closed with <3 shares (no silent fallback)"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("InsufficientUnwrapShares")
            || err_msg.contains("insufficient")
            || err_msg.contains("valid: 2"),
        "error must surface InsufficientUnwrapShares; got: {err_msg}"
    );
}

#[tokio::test]
async fn cloud_sync_history_skips_entries_below_since_timestamp() {
    let (params, shares) = setup_wrapping_params();
    let config = test_config_with_wrapping_params(params.clone());
    let alice = UmbrellaClient::bootstrap_for_test(config, test_seed())
        .await
        .expect("bootstrap");
    let alice_chat = CloudChat::create(alice.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice create");

    let recipient_pk = alice.core().mls_keystore().identity_public().to_bytes();
    let sender_pk = [0x33u8; 32];

    // Two staged entries: old (ts=100) and new (ts=300). Caller passes
    // since=200 — only new MUST be returned.
    let old = stage_cloud_entry(
        &params,
        &shares,
        sender_pk,
        recipient_pk,
        alice_chat.chat_id().0,
        0,
        100,
        b"old",
        3,
    );
    let new = stage_cloud_entry(
        &params,
        &shares,
        sender_pk,
        recipient_pk,
        alice_chat.chat_id().0,
        1,
        300,
        b"new",
        3,
    );

    alice
        .core()
        .postman_transport()
        .push_cloud_history(alice_chat.chat_id().0, old.entry);
    alice
        .core()
        .postman_transport()
        .push_cloud_history(alice_chat.chat_id().0, new.entry);
    // Only the new entry requires unwrap_transport response (old filtered out).
    alice
        .core()
        .stub_unwrap_transport()
        .unwrap()
        .push_response(new.partial_shares);

    let history = alice_chat
        .cloud_sync_history(Some(200 as Timestamp))
        .await
        .expect("sync with since=200");

    assert_eq!(history.len(), 1, "old entry filtered out by since=200");
    assert_eq!(history[0].text, "new");
    assert_eq!(history[0].timestamp, 300);
}

#[tokio::test]
async fn cloud_sync_history_propagates_aead_decrypt_failed_on_tampered_ciphertext() {
    let (params, shares) = setup_wrapping_params();
    let config = test_config_with_wrapping_params(params.clone());
    let alice = UmbrellaClient::bootstrap_for_test(config, test_seed())
        .await
        .expect("bootstrap");
    let alice_chat = CloudChat::create(alice.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice create");

    let recipient_pk = alice.core().mls_keystore().identity_public().to_bytes();
    let mut staged = stage_cloud_entry(
        &params,
        &shares,
        [0x44u8; 32],
        recipient_pk,
        alice_chat.chat_id().0,
        0,
        T0 * 1000,
        b"original plaintext bytes",
        3,
    );

    // Bit-flip a byte in the AEAD ciphertext_at_rest → Poly1305 tag check
    // must fail in the facade's outer ChaCha20-Poly1305 decrypt.
    if let Some(b) = staged.entry.ciphertext_at_rest.get_mut(0) {
        *b ^= 0xFFu8;
    }

    alice
        .core()
        .postman_transport()
        .push_cloud_history(alice_chat.chat_id().0, staged.entry);
    alice
        .core()
        .stub_unwrap_transport()
        .unwrap()
        .push_response(staged.partial_shares);

    let result = alice_chat.cloud_sync_history(None).await;
    assert!(result.is_err(), "tampered AEAD ciphertext MUST fail closed");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("AeadDecryptFailed")
            || err_msg.contains("aead")
            || err_msg.contains("decrypt"),
        "error must surface AEAD decrypt failure; got: {err_msg}"
    );
}

#[tokio::test]
async fn cloud_sync_history_drains_multiple_entries_in_insertion_order() {
    let (params, shares) = setup_wrapping_params();
    let config = test_config_with_wrapping_params(params.clone());
    let alice = UmbrellaClient::bootstrap_for_test(config, test_seed())
        .await
        .expect("bootstrap");
    let alice_chat = CloudChat::create(alice.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice create");

    let recipient_pk = alice.core().mls_keystore().identity_public().to_bytes();
    let sender_pk = [0x55u8; 32];

    let texts = [b"first".as_ref(), b"second", b"third"];
    for (i, text) in texts.iter().enumerate() {
        let staged = stage_cloud_entry(
            &params,
            &shares,
            sender_pk,
            recipient_pk,
            alice_chat.chat_id().0,
            i as u64,
            T0 * 1000 + (i as u64 * 100),
            text,
            3,
        );
        alice
            .core()
            .postman_transport()
            .push_cloud_history(alice_chat.chat_id().0, staged.entry);
        alice
            .core()
            .stub_unwrap_transport()
            .unwrap()
            .push_response(staged.partial_shares);
    }

    let history = alice_chat
        .cloud_sync_history(None)
        .await
        .expect("3-message sync");

    assert_eq!(history.len(), 3);
    assert_eq!(history[0].text, "first");
    assert_eq!(history[1].text, "second");
    assert_eq!(history[2].text, "third");
    assert!(history[0].timestamp < history[1].timestamp);
    assert!(history[1].timestamp < history[2].timestamp);
}

/// **Concrete-numbers benchmark** session 6 (analog session 5 helper).
/// Measures Cloud-wrap end-to-end recovery latency per message: stage +
/// dispatch + unwrap + AEAD decrypt. Stamp asserts < 1 second ceilings only;
/// purpose is reproducibility of numbers cited in session-6 commit message.
#[tokio::test]
async fn concrete_numbers_session_6_cloud_wrap_recovery_benchmark() {
    use std::time::Instant;

    let (params, shares) = setup_wrapping_params();
    let config = test_config_with_wrapping_params(params.clone());
    let alice = UmbrellaClient::bootstrap_for_test(config, test_seed())
        .await
        .expect("bootstrap");
    let alice_chat = CloudChat::create(alice.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("create");

    let recipient_pk = alice.core().mls_keystore().identity_public().to_bytes();
    let sender_pk = [0xAA; 32];
    let plaintext = b"session 6 benchmark: cloud-wrap recovery latency measurement";
    let plaintext_len = plaintext.len();

    let t0 = Instant::now();
    let staged = stage_cloud_entry(
        &params,
        &shares,
        sender_pk,
        recipient_pk,
        alice_chat.chat_id().0,
        0,
        T0 * 1000,
        plaintext,
        3,
    );
    let stage_us = t0.elapsed().as_micros();
    let ct_size = staged.entry.ciphertext_at_rest.len();

    alice
        .core()
        .postman_transport()
        .push_cloud_history(alice_chat.chat_id().0, staged.entry);
    alice
        .core()
        .stub_unwrap_transport()
        .unwrap()
        .push_response(staged.partial_shares);

    let t0 = Instant::now();
    let history = alice_chat.cloud_sync_history(None).await.expect("sync");
    let recover_us = t0.elapsed().as_micros();

    println!(
        "\n[session-6 concrete numbers — facade_session6_postman]\
         \n  plaintext: {plaintext_len} bytes\
         \n  ciphertext_at_rest: {ct_size} bytes (overhead {} bytes)\
         \n  stage_cloud_entry (wrap_message_key + AEAD encrypt): {stage_us} us\
         \n  cloud_sync_history (dispatch + unwrap + AEAD decrypt): {recover_us} us\n",
        ct_size - plaintext_len
    );

    assert_eq!(history.len(), 1);
    assert_eq!(history[0].text.as_bytes(), plaintext);
    assert!(stage_us < 1_000_000, "stage under 1 second");
    assert!(recover_us < 1_000_000, "recover under 1 second");
}
