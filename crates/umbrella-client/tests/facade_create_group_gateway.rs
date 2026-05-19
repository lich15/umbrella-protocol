//! F-CLIENT-FACADE-1 closure session 5 (2026-05-19): contract tests proving
//! that [`CloudChat::create`] / [`SecretChat::create`] construct real MLS
//! groups (RFC 9420 §10) via [`umbrella_mls::UmbrellaGroup::create_private`]
//! and register them in `ClientCore.groups`, and that [`CloudChat::add_member`]
//! runs a real MLS Add proposal + Commit producing a wire-format Welcome
//! that a sister client can join from.
//!
//! ## Coverage
//!
//! - `cloud_chat_create_returns_random_non_zero_chat_id` — sanity that
//!   `create` no longer returns the `ChatId([0u8; 32])` stub.
//! - `cloud_chat_create_registers_real_mls_group_state_in_core` —
//!   `get_group(chat_id)` returns `Some(...)` post-create with a real
//!   `UmbrellaGroup` (verified via `epoch() == 0` + `member_count() == 1`).
//! - `cloud_chat_create_two_calls_yield_distinct_chat_ids` — CSPRNG
//!   uniqueness across multiple creates.
//! - `secret_chat_create_returns_real_mls_group_id_and_registers_group` —
//!   SecretChat shares the same create path as CloudChat.
//! - `add_member_succeeds_and_returns_real_welcome_bytes` — happy path: Alice
//!   creates, Bob publishes KeyPackage, Alice runs `add_member` → returns
//!   non-trivial Welcome bytes, Bob joins from Welcome → both groups end up
//!   at epoch 1, member_count 2.
//! - `add_member_rejects_key_package_with_mismatched_credential_identity_pk` —
//!   anti-substitution guard: if the claimed `peer.0` differs from
//!   `key_package.credential.identity_pk`, the facade rejects.
//! - `add_member_fails_when_no_group_registered_for_chat_id` — invariant
//!   guard.
//! - `two_party_bob_encrypts_via_sister_group_alice_facade_fetch_inbox_decrypts_plaintext`
//!   — end-to-end real MLS encrypt (Bob's sister `UmbrellaGroup`) + Alice's
//!   facade fetches via mock gateway + decrypts via her own registered
//!   group state. Proves the receive path works against real MLS ciphertext
//!   (not the legacy UTF-8 lossy fallback path).
//!
//! These tests pin the F-CLIENT-FACADE-1 session 5 acceptance criteria from
//! `docs/audits/phd-b-pass5-remediation-2026-05-19.md`.

mod mock_gateway;

use std::sync::Arc;
use std::time::Duration;

use mock_gateway::{build_test_client_tls_config, MockBehavior, MockGateway, MockIncomingMessage};
use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use rand_core::OsRng;
use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_client::facade::chat_common::{
    ChatId, ChatSettings, PeerId, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
};
use umbrella_client::transport::{GatewayTransport, WebSocketTransport, WsConfig, WsTlsConfig};
use umbrella_client::{ClientConfig, CloudChat, SecretChat, UmbrellaClient};
use umbrella_identity::{
    Clock, IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock,
};
use umbrella_mls::{
    build_device_key_package, GroupPolicy, UmbrellaCiphersuite, UmbrellaGroup, UmbrellaProvider,
};

const TEST_HOST: &str = "localhost";
/// Default Umbrella classical ciphersuite (RFC 9420 §17.1
/// `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`). Mirrors
/// `UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT = 0x0003` at type level for
/// `UmbrellaGroup` / `build_device_key_package` callers in tests.
const TEST_CS: UmbrellaCiphersuite = UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519;
/// Stable unix-timestamp анchor для tests (2023-11-14 22:13:20 UTC). Совпадает с
/// `T0` в umbrella-mls/src/group.rs internal tests; используется в
/// `UmbrellaGroup::create_private` / `join_from_welcome` / `add_members`
/// lifetime + rekey timestamp arguments.
const T0: u64 = 1_700_000_000;

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
    reason = "test seed gen — same pattern as facade_integration.rs"
)]
fn test_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

async fn bootstrap_alice_facade() -> Arc<UmbrellaClient> {
    UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test")
}

async fn bootstrap_alice_with_ws_gateway(mock: &MockGateway) -> Arc<UmbrellaClient> {
    let client = bootstrap_alice_facade().await;
    let tls = build_test_client_tls_config(TEST_HOST, mock.spki_pin());
    let ws_cfg = WsConfig {
        url: mock.wss_url(),
        subprotocols: vec!["umx.pb.v1", "umx.v1"],
        tls: WsTlsConfig::Rustls(tls),
        connect_timeout: Duration::from_secs(5),
    };
    let ws_transport = WebSocketTransport::new(ws_cfg);
    let gateway_transport = GatewayTransport::new(None, ws_transport);
    let connection = gateway_transport.connect().await.expect("connect");
    connection
        .authenticate("test-token", b"device-slot-1".to_vec())
        .await
        .expect("authenticate");
    client.core().set_gateway(Arc::new(connection)).await;
    client
}

/// Sister non-facade client: own InMemoryKeyStore + UmbrellaProvider +
/// device-index 0. Mirrors the `Client` test helper in
/// `umbrella-mls/src/group.rs:786` so this test file can construct a real
/// MLS peer without spinning up a second `UmbrellaClient` (which would need
/// its own mock gateway, doubling test infra for no extra coverage).
struct SisterClient {
    ks: Arc<InMemoryKeyStore>,
    provider: UmbrellaProvider,
    device_index: u32,
}

impl SisterClient {
    fn new() -> Self {
        let seed = test_seed();
        let ks = InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>)
            .expect("InMemoryKeyStore::open");
        ks.add_device(0, None).expect("add_device(0)");
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

#[tokio::test]
async fn cloud_chat_create_returns_random_non_zero_chat_id() {
    let client = bootstrap_alice_facade().await;
    let chat = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("CloudChat::create (session 5: real MLS group)");

    assert_ne!(
        chat.chat_id(),
        ChatId([0u8; 32]),
        "session 5: CloudChat::create MUST generate a non-zero MLS group_id"
    );
}

#[tokio::test]
async fn cloud_chat_create_registers_real_mls_group_state_in_core() {
    let client = bootstrap_alice_facade().await;
    let chat = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("create");

    let group_arc =
        client.core().get_group(chat.chat_id()).await.expect(
            "session 5: ClientCore.groups MUST contain the chat_id after CloudChat::create",
        );

    let group = group_arc.lock().await;
    assert_eq!(group.epoch(), 0, "fresh group starts at epoch 0");
    assert_eq!(group.member_count(), 1, "creator is the sole member");
    assert_eq!(
        group.policy(),
        GroupPolicy::Private,
        "session 5: CloudChat creates a Private MLS group (no external ops)"
    );
    assert_eq!(group.own_leaf_index(), 0, "creator leaf index is 0");
}

#[tokio::test]
async fn cloud_chat_create_two_calls_yield_distinct_chat_ids() {
    let client = bootstrap_alice_facade().await;
    let first = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("create first");
    let second = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("create second");

    assert_ne!(
        first.chat_id(),
        second.chat_id(),
        "CSPRNG-generated chat_ids MUST be distinct (collision probability ≈ 2^-128 birthday over reasonable session counts)"
    );

    // Both groups MUST be independently registered in ClientCore.groups
    // (last-write-wins semantics on key collision do not erase the first).
    assert!(client.core().get_group(first.chat_id()).await.is_some());
    assert!(client.core().get_group(second.chat_id()).await.is_some());
}

#[tokio::test]
async fn secret_chat_create_returns_real_mls_group_id_and_registers_group() {
    let client = bootstrap_alice_facade().await;
    let secret = SecretChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("SecretChat::create");

    assert_ne!(secret.chat_id(), ChatId([0u8; 32]));

    let group_arc = client
        .core()
        .get_group(secret.chat_id())
        .await
        .expect("ClientCore.groups MUST contain SecretChat group");
    let group = group_arc.lock().await;
    assert_eq!(group.epoch(), 0);
    assert_eq!(group.member_count(), 1);
}

#[tokio::test]
async fn add_member_succeeds_and_returns_real_welcome_bytes() {
    let client = bootstrap_alice_facade().await;
    let alice_chat = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice create");

    let bob = SisterClient::new();
    let bob_kp_bytes = bob.publish_key_package_bytes();
    assert!(
        bob_kp_bytes.len() > 100,
        "canonical KeyPackage is ~300+ bytes (RFC 9420 §10.1)"
    );

    let welcome_bytes = alice_chat
        .add_member(bob.peer_id(), bob_kp_bytes)
        .await
        .expect("add_member returns Welcome bytes");
    assert!(
        welcome_bytes.len() > 100,
        "Welcome wire format is non-trivial (~hundreds of bytes including ratchet tree extension)"
    );

    // Alice's group advanced to epoch 1 (Add commit auto-merged).
    {
        let alice_group_arc = client
            .core()
            .get_group(alice_chat.chat_id())
            .await
            .expect("alice group registered");
        let alice_group = alice_group_arc.lock().await;
        assert_eq!(alice_group.epoch(), 1, "Add commit advances Alice's epoch");
        assert_eq!(alice_group.member_count(), 2, "Alice + Bob");
    }

    // Bob joins from the Welcome bytes Alice produced. join_from_welcome
    // verifies the Welcome's wire format + GroupPolicy::Private (no
    // ExternalPub extension) end-to-end — proves the Welcome bytes are
    // not a placeholder.
    let bob_group = UmbrellaGroup::join_from_welcome(
        &bob.provider,
        bob.ks.as_ref(),
        bob.device_index,
        &welcome_bytes,
        GroupPolicy::Private,
        T0 + 1,
    )
    .expect("bob join_from_welcome");
    assert_eq!(bob_group.epoch(), 1, "bob joins at epoch 1");
    assert_eq!(bob_group.member_count(), 2);
    assert_eq!(
        bob_group.ciphersuite(),
        TEST_CS,
        "bob's group inherits Alice's ciphersuite"
    );
}

#[tokio::test]
async fn add_member_rejects_key_package_with_mismatched_credential_identity_pk() {
    let client = bootstrap_alice_facade().await;
    let alice_chat = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice create");

    let bob = SisterClient::new();
    let bob_kp_bytes = bob.publish_key_package_bytes();

    // Adversary substitutes the claimed peer with a different identity
    // (Mallory's pubkey) while passing Bob's actual KeyPackage. Facade
    // anti-substitution check rejects because
    // KeyPackage.credential.identity_pk == bob's, not mallory's.
    let mallory_peer = PeerId([0xFFu8; 32]);
    let result = alice_chat.add_member(mallory_peer, bob_kp_bytes).await;

    assert!(
        result.is_err(),
        "add_member MUST reject KeyPackage whose credential.identity_pk != peer parameter"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("credential.identity_pk") || err_msg.contains("does not match peer"),
        "error must name the anti-substitution check; got: {err_msg}"
    );
}

#[tokio::test]
async fn add_member_fails_when_no_group_registered_for_chat_id() {
    let client = bootstrap_alice_facade().await;
    let alice_chat = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("create");
    // Drop the registered group out of band — simulates an invariant
    // violation (e.g. logout cleanup race or test wiring bug). add_member
    // must surface Mls error rather than silently succeed or panic.
    let _unregistered = client.core().unregister_group(alice_chat.chat_id()).await;

    let bob = SisterClient::new();
    let result = alice_chat
        .add_member(bob.peer_id(), bob.publish_key_package_bytes())
        .await;

    assert!(
        result.is_err(),
        "add_member without registered group MUST fail"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("no MLS group registered") || err_msg.contains("add_member"),
        "error must name the missing group; got: {err_msg}"
    );
}

/// **End-to-end real MLS receive path** (session 5 key acceptance criterion):
///
/// 1. Bob = sister UmbrellaGroup outside the facade (own ks + provider + KP)
/// 2. Alice = facade UmbrellaClient
/// 3. Alice creates CloudChat → her UmbrellaGroup A (epoch 0)
/// 4. Alice runs `add_member(bob_peer, bob_kp)` → Welcome bytes; her group at
///    epoch 1
/// 5. Bob joins from Welcome → his group B = identical state to A at epoch 1
/// 6. Bob encrypts "hello alice" via B → MLS ciphertext bytes (real wire
///    format)
/// 7. Mock gateway is spawned with PushInboxAfterAuth pushing Bob's ciphertext
///    as `IncomingMessage`
/// 8. Alice's facade connects to mock + calls `fetch_inbox()` → MLS decrypt
///    succeeds → returned plaintext == "hello alice"
///
/// Closes session 5 acceptance: real MLS encrypt → real MLS decrypt across
/// the facade boundary, no UTF-8 lossy fallback engaged on the decrypt path.
#[tokio::test]
async fn two_party_bob_encrypts_via_sister_group_alice_facade_fetch_inbox_decrypts_plaintext() {
    // Phase 1: stand up Bob (sister) BEFORE Alice — we need Bob's KP
    // before Alice's add_member call.
    let bob = SisterClient::new();
    let bob_peer = bob.peer_id();
    let bob_kp_bytes = bob.publish_key_package_bytes();

    // Phase 2: Alice facade WITHOUT gateway (we will attach later, after
    // Bob has already produced his ciphertext — the mock can only push
    // pre-baked messages after AuthOk).
    let client = bootstrap_alice_facade().await;
    let alice_chat = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice create CloudChat");

    // Phase 3: Alice add_member(bob) → Welcome bytes.
    let welcome_bytes = alice_chat
        .add_member(bob_peer, bob_kp_bytes)
        .await
        .expect("alice add_member(bob)");

    // Phase 4: Bob joins Alice's group from the Welcome.
    let mut bob_group = UmbrellaGroup::join_from_welcome(
        &bob.provider,
        bob.ks.as_ref(),
        bob.device_index,
        &welcome_bytes,
        GroupPolicy::Private,
        T0 + 1,
    )
    .expect("bob join_from_welcome");
    assert_eq!(bob_group.epoch(), 1);
    assert_eq!(bob_group.member_count(), 2);

    // Phase 5: Bob encrypts "hello alice" via his joined group state.
    let plaintext = b"hello alice".as_slice();
    let bob_ciphertext = bob_group
        .encrypt_application(&bob.provider, bob.ks.as_ref(), plaintext)
        .expect("bob encrypt_application");
    assert_ne!(
        bob_ciphertext.as_slice(),
        plaintext,
        "MLS ciphertext MUST differ from plaintext (real AEAD wrap)"
    );
    assert!(
        bob_ciphertext.len() > plaintext.len(),
        "MLS ciphertext is plaintext + AEAD overhead + framing — strictly larger"
    );

    // Phase 6: spawn mock with Bob's pre-baked ciphertext as IncomingMessage.
    let pushed = MockIncomingMessage {
        from_user_id: bob.identity_pubkey_bytes().to_vec(),
        ciphertext: bob_ciphertext,
        sent_ts_ms: 1_700_000_001_000,
        msg_id: format!("{:032x}", 0xBEEF_u64),
    };
    let mock = MockGateway::spawn(MockBehavior::PushInboxAfterAuth {
        accept_token: None,
        messages: vec![pushed],
    })
    .await;

    // Phase 7: attach mock gateway to Alice's facade.
    let tls = build_test_client_tls_config(TEST_HOST, mock.spki_pin());
    let ws_cfg = WsConfig {
        url: mock.wss_url(),
        subprotocols: vec!["umx.pb.v1"],
        tls: WsTlsConfig::Rustls(tls),
        connect_timeout: Duration::from_secs(5),
    };
    let ws_transport = WebSocketTransport::new(ws_cfg);
    let gateway_transport = GatewayTransport::new(None, ws_transport);
    let connection = gateway_transport.connect().await.expect("connect");
    connection
        .authenticate("token", b"alice-device".to_vec())
        .await
        .expect("auth");
    client.core().set_gateway(Arc::new(connection)).await;

    // Phase 8: Alice fetches the inbox → real MLS decrypt via her own group
    // state (registered at create), plaintext recovered.
    let drained = alice_chat.fetch_inbox().await.expect("alice fetch_inbox");
    assert_eq!(drained.len(), 1, "expected exactly 1 inbox message");

    let msg = &drained[0];
    assert_eq!(
        msg.text, "hello alice",
        "session 5: real MLS decrypt via alice's UmbrellaGroup, NOT UTF-8 lossy fallback"
    );
    assert_eq!(msg.sender, bob_peer, "sender preserved from from_user_id");
    assert_eq!(msg.chat_id, alice_chat.chat_id(), "chat_id mirrors alice's");
    assert_eq!(msg.timestamp, 1_700_000_001_000);

    // Alice's group must have advanced to epoch 1 (already after add_member).
    // After process_incoming(Application), epoch does NOT change (only commits
    // advance epoch); we already verified post-add_member assertions.
    let alice_group_arc = client
        .core()
        .get_group(alice_chat.chat_id())
        .await
        .expect("alice group registered");
    let alice_group = alice_group_arc.lock().await;
    assert_eq!(
        alice_group.epoch(),
        1,
        "Add commit set epoch=1; Application does not change epoch"
    );
    assert_eq!(alice_group.member_count(), 2);
}

/// **Concrete-numbers benchmark** (session 5 acceptance Q5 self-check):
/// prints encrypt/decrypt latency, ciphertext expansion factor, group
/// creation cost. Asserts only `< 1 second per primitive` ceilings (loose
/// upper bounds for CI hosts); main purpose is documentation reproducibility
/// of the numbers cited in the session 5 commit message.
///
/// Run with `cargo test -p umbrella-client --test facade_create_group_gateway
/// --offline -- --nocapture concrete_numbers` to see the printed values.
#[tokio::test]
async fn concrete_numbers_session_5_mls_primitives_benchmark() {
    use std::time::Instant;

    let bob = SisterClient::new();
    let bob_kp_bytes = bob.publish_key_package_bytes();
    let kp_size = bob_kp_bytes.len();

    let client = bootstrap_alice_facade().await;
    let t0 = Instant::now();
    let alice_chat = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice create");
    let create_us = t0.elapsed().as_micros();

    let t0 = Instant::now();
    let welcome = alice_chat
        .add_member(bob.peer_id(), bob_kp_bytes.clone())
        .await
        .expect("add_member");
    let add_us = t0.elapsed().as_micros();
    let welcome_size = welcome.len();

    let t0 = Instant::now();
    let mut bob_group = UmbrellaGroup::join_from_welcome(
        &bob.provider,
        bob.ks.as_ref(),
        bob.device_index,
        &welcome,
        GroupPolicy::Private,
        T0 + 1,
    )
    .expect("bob join");
    let join_us = t0.elapsed().as_micros();

    let plaintext = b"hello alice from session 5 - concrete numbers benchmark";
    let plaintext_len = plaintext.len();

    let t0 = Instant::now();
    let ct = bob_group
        .encrypt_application(&bob.provider, bob.ks.as_ref(), plaintext)
        .expect("bob encrypt");
    let encrypt_us = t0.elapsed().as_micros();
    let ct_size = ct.len();
    let expansion = ct_size as f64 / plaintext_len as f64;

    let alice_group_arc = client
        .core()
        .get_group(alice_chat.chat_id())
        .await
        .expect("alice group");
    let mut alice_group = alice_group_arc.lock().await;
    let t0 = Instant::now();
    let _ = alice_group
        .process_incoming(client.core().mls_provider().as_ref(), &ct)
        .expect("alice decrypt");
    let decrypt_us = t0.elapsed().as_micros();

    println!(
        "\n[session-5 concrete numbers — facade_create_group_gateway]\
         \n  KeyPackage size: {kp_size} bytes\
         \n  Welcome size: {welcome_size} bytes\
         \n  CloudChat::create (incl. MLS group_create_private): {create_us} us\
         \n  add_member (Add proposal + Commit + auto-merge): {add_us} us\
         \n  join_from_welcome: {join_us} us\
         \n  encrypt_application ({plaintext_len}-byte plaintext): {encrypt_us} us\
         \n    -> ciphertext: {ct_size} bytes (expansion {expansion:.2}x)\
         \n  process_incoming (decrypt): {decrypt_us} us\n"
    );

    assert!(create_us < 1_000_000, "create under 1 second");
    assert!(add_us < 1_000_000);
    assert!(join_us < 1_000_000);
    assert!(encrypt_us < 1_000_000);
    assert!(decrypt_us < 1_000_000);
}

/// **Backwards-compat regression guard:** if `fetch_inbox` runs against a
/// CloudChat whose chat_id has NO registered MLS group (e.g. opened via
/// stub `CloudChat::open(ChatId([0u8; 32]))`), the decrypt path falls back to
/// UTF-8 lossy. This preserves existing `facade_fetch_inbox_gateway.rs`
/// semantics where the mock pushes raw-bytes ciphertext.
///
/// Without this guard, session 5 wiring would break every test that
/// exercises fetch_inbox without a real MLS group setup.
#[tokio::test]
async fn fetch_inbox_falls_back_to_utf8_lossy_when_no_mls_group_registered() {
    let mock = MockGateway::spawn(MockBehavior::PushInboxAfterAuth {
        accept_token: None,
        messages: vec![MockIncomingMessage {
            from_user_id: vec![0x42; 32],
            ciphertext: b"plaintext-bytes-no-mls".to_vec(),
            sent_ts_ms: 100,
            msg_id: format!("{:032x}", 1u64),
        }],
    })
    .await;
    let client = bootstrap_alice_with_ws_gateway(&mock).await;

    // CloudChat::open does NOT register an MLS group; only create does. So
    // fetch_inbox here sees `get_group(zero_chat_id) == None` → UTF-8 lossy
    // fallback engages.
    let cloud = CloudChat::open(client.core(), ChatId([0u8; 32]))
        .await
        .expect("CloudChat::open (no MLS state)");

    let drained = cloud.fetch_inbox().await.expect("fetch_inbox");
    assert_eq!(drained.len(), 1);
    assert_eq!(
        drained[0].text, "plaintext-bytes-no-mls",
        "backwards-compat: without MLS group, fetch_inbox falls back to UTF-8 lossy"
    );
}
