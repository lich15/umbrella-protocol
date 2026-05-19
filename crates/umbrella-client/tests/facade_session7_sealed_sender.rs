//! F-CLIENT-FACADE-1 closure session 7 (2026-05-19): contract tests for
//! `SecretChat` sealed-sender envelope wrap (на send) и unwrap (на fetch_inbox).
//! Реализует Signal sealed-sender pattern (Lund et al. 2018) для UmbrellaX:
//! gateway / blind-postman видят только recipient routing (to_user_id), но не
//! sender — sender Ed25519 identity_pk зашифрован inside HPKE-style AEAD
//! envelope, recoverable только recipient'ом после ECDH key agreement.
//!
//! ## Coverage (12 tests)
//!
//! **Helper-level (direct `umbrella_sealed_sender::seal` / `unseal` API без
//! gateway dependency)** — pin wire-format invariants и cryptographic
//! roundtrip:
//!
//! 1. `helper_round_trip_seal_unseal_recovers_sender_and_message_with_real_mls_ciphertext`
//!    — Alice MLS-encrypt + seal → Bob unseal → MLS-decrypt → same plaintext;
//!    Bob receives Alice's identity_pk via inner signature.
//! 2. `helper_seal_wire_starts_with_v1_version_byte_0x01` — wire[0] == 0x01.
//! 3. `helper_seal_wire_does_not_contain_raw_sender_identity_pk_bytes` —
//!    32-byte sender identity_pk substring отсутствует на wire (sender
//!    anonymity invariant).
//! 4. `helper_seal_wire_ephemeral_x25519_differs_from_both_party_identity_x25519`
//!    — eph_pub фиксирует Forward Secrecy (compromise long-term не
//!    decrypt'ит past envelopes).
//! 5. `helper_unseal_rejects_envelope_with_tampered_aead_ciphertext` —
//!    bit-flip последнего байта → SealedSenderError (AEAD authentication
//!    failure).
//! 6. `helper_unseal_rejects_envelope_with_tampered_ephemeral_pubkey` —
//!    bit-flip eph_pub → DH desync → AEAD fail.
//! 7. `helper_unseal_rejects_envelope_sealed_for_different_recipient_keystore`
//!    — Eve (третья сторона) не может unseal envelope sealed для Bob'а
//!    (wrong-recipient invariant).
//!
//! **Facade-level (full `SecretChat` API через mock gateway)** — pin facade
//! wire-up correctness:
//!
//! 8.  `secret_chat_send_text_succeeds_when_peer_x25519_registered_for_2_member_group`
//!     — happy path: Alice creates group + adds Bob + registers Bob's X25519
//!     → send_text → mock acks с msg_id != stub.
//! 9.  `secret_chat_send_text_fails_closed_when_peer_x25519_not_registered_for_group_member`
//!     — постулат 14: missing X25519 directory entry → ClientError::SealedSender,
//!     никакого silent fallback на unsealed delivery.
//! 10. `secret_chat_send_text_returns_stub_msg_id_for_single_member_group_no_peers_to_seal_to`
//!     — group с только Alice → нет envelopes для seal → return stub MessageId.
//! 11. `secret_chat_fetch_inbox_unwraps_sealed_sender_envelope_recovering_sender_from_inner_signature`
//!     — Bob (sister) seal'ит envelope с realистичным MLS-encrypted payload,
//!     stages в mock через PushInboxAfterAuth; Alice's fetch_inbox unwrap'ит
//!     + MLS-decrypts → DecryptedMessage с sender recovered ИЗ inner sig
//!     (НЕ из gateway from_user_id, который mock устанавливает bogus
//!     `[0xFFu8; 32]` для демонстрации invariant'а).
//! 12. `cloud_chat_send_text_does_not_require_peer_x25519_directory_invariant_guard`
//!     — cross-mode invariant: CloudChat::send_text succeeds без peer_x25519
//!     registration (Cloud-режим не вызывает sealed-sender — trades sender
//!     anonymity для multi-device history per ADR-006 Вариант C).

mod mock_gateway;

use std::sync::Arc;
use std::time::Duration;

use mock_gateway::{build_test_client_tls_config, MockBehavior, MockGateway, MockIncomingMessage};
use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use rand::rngs::OsRng as RandOsRng;
use rand_core::OsRng;
use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_client::facade::chat_common::{
    ChatId, ChatSettings, PeerId, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
};
use umbrella_client::transport::{GatewayTransport, WebSocketTransport, WsConfig, WsTlsConfig};
use umbrella_client::{ClientConfig, ClientError, CloudChat, SecretChat, UmbrellaClient};
use umbrella_identity::{
    Clock, IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock,
};
use umbrella_mls::{
    build_device_key_package, GroupPolicy, IncomingMessage, UmbrellaCiphersuite, UmbrellaGroup,
    UmbrellaProvider,
};
use umbrella_sealed_sender::{seal, unseal, SealedSenderError, VERSION as SS_VERSION};

const TEST_HOST: &str = "localhost";
const TEST_CS: UmbrellaCiphersuite = UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519;
const T0: u64 = 1_700_000_000;

fn test_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut RandOsRng, MnemonicLanguage::English)
}

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

async fn bootstrap_client_no_gateway() -> Arc<UmbrellaClient> {
    UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test")
}

async fn bootstrap_client_with_ws_gateway(mock: &MockGateway) -> Arc<UmbrellaClient> {
    let client = bootstrap_client_no_gateway().await;
    let tls = build_test_client_tls_config(TEST_HOST, mock.spki_pin());
    let ws_cfg = WsConfig {
        url: mock.wss_url(),
        subprotocols: vec!["umx.pb.v1", "umx.v1"],
        tls: WsTlsConfig::Rustls(tls),
        connect_timeout: Duration::from_secs(5),
    };
    let ws = WebSocketTransport::new(ws_cfg);
    let gateway_transport = GatewayTransport::new(None, ws);
    let connection = gateway_transport.connect().await.expect("connect");
    connection
        .authenticate("test-token", b"device-slot-1".to_vec())
        .await
        .expect("authenticate");
    client.core().set_gateway(Arc::new(connection)).await;
    client
}

/// Non-facade MLS sister client. Used as Bob/Eve в multi-party tests:
/// holds own [`InMemoryKeyStore`] + [`UmbrellaProvider`] + optional joined
/// [`UmbrellaGroup`] state (set via [`SisterClient::join_group_from_welcome`]).
struct SisterClient {
    ks: Arc<InMemoryKeyStore>,
    provider: UmbrellaProvider,
    device_index: u32,
    group: Option<UmbrellaGroup>,
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
            group: None,
        }
    }

    fn identity_pk_bytes(&self) -> [u8; 32] {
        self.ks.identity_public().to_bytes()
    }

    fn identity_x25519_pubkey(&self) -> umbrella_identity::IdentityX25519KeyPublic {
        self.ks.identity_x25519_public()
    }

    fn peer_id(&self) -> PeerId {
        PeerId(self.identity_pk_bytes())
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

    fn join_group_from_welcome(&mut self, welcome_bytes: &[u8]) {
        let group = UmbrellaGroup::join_from_welcome(
            &self.provider,
            self.ks.as_ref(),
            self.device_index,
            welcome_bytes,
            GroupPolicy::Private,
            T0 + 10,
        )
        .expect("sister join_from_welcome");
        self.group = Some(group);
    }

    fn encrypt_application(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let group = self
            .group
            .as_mut()
            .expect("sister must call join_group_from_welcome before encrypt");
        group
            .encrypt_application(&self.provider, self.ks.as_ref(), plaintext)
            .expect("sister MLS encrypt")
    }
}

// ============================================================================
// Helper-level tests (direct umbrella_sealed_sender API; no gateway)
// ============================================================================

/// Set up Alice ClientCore + Bob sister + MLS group with both members, return
/// (alice_client, bob_sister, alice_chat). Bob joins from Welcome so both
/// share the same MLS epoch 1 — каждая сторона может encrypt/decrypt сообщения
/// другой через свой собственный group state.
async fn setup_two_party_alice_bob() -> (Arc<UmbrellaClient>, SisterClient, SecretChat) {
    let alice = bootstrap_client_no_gateway().await;
    let alice_chat = SecretChat::create(alice.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice SecretChat::create");

    let mut bob = SisterClient::new();
    let bob_kp_bytes = bob.publish_key_package_bytes();
    let welcome = alice_chat
        .add_member(bob.peer_id(), bob_kp_bytes)
        .await
        .expect("alice add_member(bob)");
    bob.join_group_from_welcome(&welcome);

    (alice, bob, alice_chat)
}

#[tokio::test]
async fn helper_round_trip_seal_unseal_recovers_sender_and_message_with_real_mls_ciphertext() {
    let (alice, mut bob, alice_chat) = setup_two_party_alice_bob().await;
    let alice_id_pk_bytes = alice.core().mls_keystore().identity_public().to_bytes();

    // 1. Alice MLS-encrypt "hello-bob" → mls_ciphertext (как делает
    //    SecretChat::send_text внутри `chat_common::send_secret_text`).
    let chat_id = alice_chat.chat_id();
    let alice_group_arc = alice.core().get_group(chat_id).await.expect("alice group");
    let mls_ciphertext = {
        let mut g = alice_group_arc.lock().await;
        g.encrypt_application(
            alice.core().mls_provider().as_ref(),
            alice.core().mls_keystore().as_ref(),
            b"hello-bob",
        )
        .expect("alice MLS encrypt")
    };

    // 2. Alice seal MLS ciphertext к Bob's X25519 identity (тот же путь что
    //    `chat_common::sealed_sender_seal_for_secret` вызывает internally).
    let mut rng = OsRng;
    let envelope_bytes = seal(
        alice.core().mls_keystore().as_ref(),
        &bob.identity_x25519_pubkey(),
        &mls_ciphertext,
        &mut rng,
    )
    .expect("alice seal envelope");

    // 3. Bob unseal envelope с his keystore.
    let opened = unseal(bob.ks.as_ref(), &envelope_bytes).expect("bob unseal envelope");

    // 4. Bob recovers Alice's MLS identity_pk через inner signature verification.
    assert_eq!(
        opened.sender_identity.to_bytes(),
        alice_id_pk_bytes,
        "Bob MUST recover Alice's MLS identity_pk from inner Ed25519 signature \
         (sealed-sender authenticates sender to recipient)"
    );

    // 5. Recovered MLS ciphertext bit-equal с тем что Alice encrypted.
    assert_eq!(
        opened.message.as_slice(),
        mls_ciphertext.as_slice(),
        "Bob's unseal MUST recover Alice's MLS ciphertext bit-exact"
    );

    // 6. Bob MLS-decrypt recovered ciphertext → "hello-bob".
    let bob_group = bob.group.as_mut().unwrap();
    let incoming = bob_group
        .process_incoming(&bob.provider, opened.message.as_slice())
        .expect("bob MLS decrypt");
    match incoming {
        IncomingMessage::Application { payload, .. } => {
            assert_eq!(
                payload.as_slice(),
                b"hello-bob",
                "Bob MUST recover Alice's original plaintext через end-to-end \
                 MLS-encrypt → sealed-sender-seal → sealed-sender-unseal → MLS-decrypt"
            );
        }
        other => panic!("expected IncomingMessage::Application, got {other:?}"),
    }
}

#[tokio::test]
async fn helper_seal_wire_starts_with_v1_version_byte_0x01() {
    let (_alice_client, bob, _alice_chat) = setup_two_party_alice_bob().await;
    let alice_again = bootstrap_client_no_gateway().await;

    let mut rng = OsRng;
    let envelope_bytes = seal(
        alice_again.core().mls_keystore().as_ref(),
        &bob.identity_x25519_pubkey(),
        b"payload-stub",
        &mut rng,
    )
    .expect("seal");

    assert_eq!(
        envelope_bytes[0], SS_VERSION,
        "sealed-sender V1 wire-format MUST start with version byte 0x{:02x}, got 0x{:02x}",
        SS_VERSION, envelope_bytes[0]
    );
    assert_eq!(SS_VERSION, 0x01, "documented invariant: V1 stamp = 0x01");
}

#[tokio::test]
async fn helper_seal_wire_does_not_contain_raw_sender_identity_pk_bytes() {
    let (_alice_client, bob, _alice_chat) = setup_two_party_alice_bob().await;
    let alice_again = bootstrap_client_no_gateway().await;
    let alice_id_pk_bytes = alice_again
        .core()
        .mls_keystore()
        .identity_public()
        .to_bytes();

    let mut rng = OsRng;
    let envelope_bytes = seal(
        alice_again.core().mls_keystore().as_ref(),
        &bob.identity_x25519_pubkey(),
        b"the-payload-content",
        &mut rng,
    )
    .expect("seal");

    // Sender anonymity invariant: 32-byte Alice's identity_pk substring
    // must NOT appear anywhere в wire bytes. Sender authenticated через
    // inner signature inside AEAD blob, не leaked на wire.
    let mut found_at: Option<usize> = None;
    if envelope_bytes.len() >= alice_id_pk_bytes.len() {
        for window_start in 0..=(envelope_bytes.len() - alice_id_pk_bytes.len()) {
            if &envelope_bytes[window_start..window_start + alice_id_pk_bytes.len()]
                == &alice_id_pk_bytes[..]
            {
                found_at = Some(window_start);
                break;
            }
        }
    }

    assert!(
        found_at.is_none(),
        "F-CLIENT-FACADE-1 session 7 sender anonymity invariant: Alice's MLS \
         identity_pk (32 bytes) MUST NOT appear на wire bytes; found at offset \
         {:?}. Sender authenticated через inner-AEAD-encrypted Ed25519 signature.",
        found_at
    );
}

#[tokio::test]
async fn helper_seal_wire_ephemeral_x25519_differs_from_both_party_identity_x25519() {
    let (_alice_client, bob, _alice_chat) = setup_two_party_alice_bob().await;
    let alice_again = bootstrap_client_no_gateway().await;

    let mut rng = OsRng;
    let envelope_bytes = seal(
        alice_again.core().mls_keystore().as_ref(),
        &bob.identity_x25519_pubkey(),
        b"x",
        &mut rng,
    )
    .expect("seal");

    // Wire layout (V1): [version(1) || eph_pub(32) || AEAD(...)].
    let eph_pub = &envelope_bytes[1..33];
    let alice_x25519_bytes = alice_again
        .core()
        .mls_keystore()
        .identity_x25519_public()
        .to_bytes();
    let bob_x25519_bytes = bob.identity_x25519_pubkey().to_bytes();

    assert_ne!(
        eph_pub,
        &alice_x25519_bytes[..],
        "Forward Secrecy invariant: ephemeral eph_pub MUST be distinct от Alice's \
         long-lived X25519 identity (compromise long-term не decrypt'ит past envelopes)"
    );
    assert_ne!(
        eph_pub,
        &bob_x25519_bytes[..],
        "ephemeral eph_pub MUST be distinct от Bob's X25519 identity"
    );
}

#[tokio::test]
async fn helper_unseal_rejects_envelope_with_tampered_aead_ciphertext() {
    let (_alice_client, bob, _alice_chat) = setup_two_party_alice_bob().await;
    let alice_again = bootstrap_client_no_gateway().await;

    let mut rng = OsRng;
    let mut envelope_bytes = seal(
        alice_again.core().mls_keystore().as_ref(),
        &bob.identity_x25519_pubkey(),
        b"payload",
        &mut rng,
    )
    .expect("seal");

    // Flip последний byte (внутри AEAD tag region) — Poly1305 MAC должен
    // отвергнуть tampered ciphertext через `SealedSenderError::Crypto`.
    let last_idx = envelope_bytes.len() - 1;
    envelope_bytes[last_idx] ^= 0x01;

    let result = unseal(bob.ks.as_ref(), &envelope_bytes);
    assert!(
        result.is_err(),
        "tampered AEAD ciphertext MUST reject через unseal — got {result:?}"
    );
    assert!(
        matches!(
            result,
            Err(SealedSenderError::Crypto(_))
                | Err(SealedSenderError::Padding(_))
                | Err(SealedSenderError::Malformed { .. })
        ),
        "expected SealedSenderError::Crypto / Padding / Malformed на bit-flip \
         AEAD ciphertext, got {result:?}"
    );
}

#[tokio::test]
async fn helper_unseal_rejects_envelope_with_tampered_ephemeral_pubkey() {
    let (_alice_client, bob, _alice_chat) = setup_two_party_alice_bob().await;
    let alice_again = bootstrap_client_no_gateway().await;

    let mut rng = OsRng;
    let mut envelope_bytes = seal(
        alice_again.core().mls_keystore().as_ref(),
        &bob.identity_x25519_pubkey(),
        b"payload",
        &mut rng,
    )
    .expect("seal");

    // Flip 1 байт inside eph_pub (offset 1..33). Bob's ECDH с tampered
    // eph_pub даст другой shared secret → AEAD-key MAC fail → unseal rejects.
    envelope_bytes[1] ^= 0x01;

    let result = unseal(bob.ks.as_ref(), &envelope_bytes);
    assert!(
        result.is_err(),
        "tampered ephemeral pubkey MUST reject через unseal — got {result:?}"
    );
}

#[tokio::test]
async fn helper_unseal_rejects_envelope_sealed_for_different_recipient_keystore() {
    let (_alice_client, bob, _alice_chat) = setup_two_party_alice_bob().await;
    let alice_again = bootstrap_client_no_gateway().await;
    let eve = SisterClient::new();

    let mut rng = OsRng;
    let envelope_bytes = seal(
        alice_again.core().mls_keystore().as_ref(),
        &bob.identity_x25519_pubkey(),
        b"for-bob-eyes-only",
        &mut rng,
    )
    .expect("seal к Bob");

    // Eve tries to unseal envelope encrypted к Bob's X25519 identity. Her
    // X25519-DH с eph_pub даст другой shared secret чем Bob'а → AEAD
    // decrypt fail (KCI variant — Eve has her own keystore с identity-x25519
    // secret, но recipient_x25519 в seal был Bob'а).
    let result = unseal(eve.ks.as_ref(), &envelope_bytes);
    assert!(
        result.is_err(),
        "Eve (wrong recipient) MUST NOT unseal envelope sealed for Bob — got {result:?}"
    );
}

// ============================================================================
// Facade-level tests (через mock gateway)
// ============================================================================

#[tokio::test]
async fn secret_chat_send_text_succeeds_when_peer_x25519_registered_for_2_member_group() {
    // Setup: real mock gateway + Alice facade + Bob sister + 2-member group.
    let mock = MockGateway::spawn(MockBehavior::standard_any_token()).await;
    let alice = bootstrap_client_with_ws_gateway(&mock).await;
    let alice_chat = SecretChat::create(alice.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice SecretChat::create");

    let mut bob = SisterClient::new();
    let welcome = alice_chat
        .add_member(bob.peer_id(), bob.publish_key_package_bytes())
        .await
        .expect("alice add_member(bob)");
    bob.join_group_from_welcome(&welcome);

    // Register Bob's X25519 identity в peer directory (production: KT lookup;
    // tests: explicit registration).
    alice
        .core()
        .register_peer_x25519(bob.identity_pk_bytes(), bob.identity_x25519_pubkey())
        .await;

    // Send text via facade → должен MLS-encrypt + seal envelope + send к gateway.
    let msg_id = alice_chat
        .send_text("hello-bob-via-facade".into())
        .await
        .expect("SecretChat::send_text успешно завершается");

    // Mock acks с real msg_id (не stub [0u8; 16]). Это подтверждает что
    // sealed-sender envelope ушёл на mock gateway, который ack'нул.
    assert_ne!(
        msg_id.0, [0u8; 16],
        "SecretChat::send_text MUST return real server-issued msg_id when gateway acks; \
         stub [0u8; 16] means no envelope was actually delivered"
    );
}

#[tokio::test]
async fn secret_chat_send_text_fails_closed_when_peer_x25519_not_registered_for_group_member() {
    // Same setup as test 8, но БЕЗ register_peer_x25519 call.
    let mock = MockGateway::spawn(MockBehavior::standard_any_token()).await;
    let alice = bootstrap_client_with_ws_gateway(&mock).await;
    let alice_chat = SecretChat::create(alice.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice SecretChat::create");

    let mut bob = SisterClient::new();
    let welcome = alice_chat
        .add_member(bob.peer_id(), bob.publish_key_package_bytes())
        .await
        .expect("alice add_member(bob)");
    bob.join_group_from_welcome(&welcome);

    // Deliberately skip register_peer_x25519. Send_text должен fail-closed
    // через ClientError::SealedSender (постулат 14 — никакого silent fallback
    // на unsealed delivery, который бы leak'нул sender identity_pk на wire).
    let result = alice_chat
        .send_text("no-peer-x25519-registered".into())
        .await;

    match result {
        Err(ClientError::SealedSender(SealedSenderError::Malformed { reason })) => {
            assert!(
                reason.contains("X25519 pubkey") && reason.contains("registered"),
                "expected diagnostic mentioning unregistered X25519, got: {reason}"
            );
        }
        other => panic!(
            "expected ClientError::SealedSender(Malformed) на missing peer X25519, got {other:?}"
        ),
    }
}

#[tokio::test]
async fn secret_chat_send_text_returns_stub_msg_id_for_single_member_group_no_peers_to_seal_to() {
    // Alice creates SecretChat без add_member — group имеет только Alice.
    // peers list (после filter self) пустой → нет envelopes для sealing.
    let mock = MockGateway::spawn(MockBehavior::standard_any_token()).await;
    let alice = bootstrap_client_with_ws_gateway(&mock).await;
    let alice_chat = SecretChat::create(alice.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice SecretChat::create");

    let msg_id = alice_chat
        .send_text("solo-message-no-peers".into())
        .await
        .expect("send_text на single-member group НЕ должен fail");

    // Без peers нет SendMessage frames — return stub MessageId([0u8; 16])
    // matching gateway-None convention.
    assert_eq!(
        msg_id.0, [0u8; 16],
        "single-member group (only self) MUST return stub MessageId([0u8; 16]) — \
         нет peers для sealed-sender envelope; got {msg_id:?}"
    );
}

#[tokio::test]
async fn secret_chat_fetch_inbox_unwraps_sealed_sender_envelope_recovering_sender_from_inner_signature(
) {
    // Multi-stage setup:
    //  Phase A: Alice creates SecretChat без gateway, adds Bob, Bob joins.
    //           Это даёт обе стороны MLS group state в epoch 1.
    //  Phase B: Bob (sister) MLS-encrypts "from-bob-via-inner-sig" → mls_ct.
    //           Bob seals envelope к Alice's X25519 → envelope_bytes.
    //  Phase C: Mock spawn с PushInboxAfterAuth(envelope_bytes) — bogus
    //           from_user_id `[0xFFu8; 32]` to prove sender comes из inner
    //           signature, NOT из gateway from_user_id.
    //  Phase D: Alice's SecretChat::fetch_inbox drains envelope → sealed-
    //           sender unseal → (bob_pk, mls_ct) → MLS decrypt → DecryptedMessage.

    // Phase A: no-gateway setup для MLS group + Welcome roundtrip.
    let (alice_no_gw, mut bob, alice_chat_no_gw) = setup_two_party_alice_bob().await;
    let chat_id = alice_chat_no_gw.chat_id();
    let alice_id_pk_bytes = alice_no_gw
        .core()
        .mls_keystore()
        .identity_public()
        .to_bytes();
    let alice_x25519 = alice_no_gw.core().mls_keystore().identity_x25519_public();
    let bob_id_pk_bytes = bob.identity_pk_bytes();

    // Phase B: Bob MLS-encrypts + seal'ит envelope к Alice's X25519.
    let bob_mls_ct = bob.encrypt_application(b"from-bob-via-inner-sig");
    let mut rng = OsRng;
    let envelope_bytes = seal(bob.ks.as_ref(), &alice_x25519, &bob_mls_ct, &mut rng)
        .expect("bob seal envelope к alice");

    // Phase C: Spawn fresh mock с pre-staged envelope в push-on-auth queue.
    // from_user_id = bogus [0xFFu8; 32] — proves sender recovery via inner sig.
    let staged = MockIncomingMessage {
        from_user_id: vec![0xFFu8; 32],
        ciphertext: envelope_bytes.clone(),
        sent_ts_ms: 1_700_000_500_000,
        msg_id: "abababababababababababababababab".to_string(),
    };
    let mock = MockGateway::spawn(MockBehavior::PushInboxAfterAuth {
        accept_token: None,
        messages: vec![staged],
    })
    .await;

    // Phase D: re-bootstrap Alice's facade using the SAME MLS keystore? No —
    // Alice's `bootstrap_for_test` generates new seed → new identity. Instead,
    // we use a different strategy: bootstrap alice2 + register her MLS group
    // via direct state transfer. That's complex.
    //
    // Simpler: bootstrap Alice's gateway-connected facade against a FRESH
    // group instance (Alice 2.0 with same identity_pk?). Hmm, but seed is
    // random — Alice's MLS identity won't match what Bob sealed to.
    //
    // Solution: skip Phase C/D fresh bootstrap. Instead, manually re-create
    // gateway connection on alice_no_gw using the new mock. Это same MLS
    // state, same X25519 identity, same group → Bob's envelope is valid
    // recipient.
    let tls = build_test_client_tls_config(TEST_HOST, mock.spki_pin());
    let ws_cfg = WsConfig {
        url: mock.wss_url(),
        subprotocols: vec!["umx.pb.v1", "umx.v1"],
        tls: WsTlsConfig::Rustls(tls),
        connect_timeout: Duration::from_secs(5),
    };
    let ws = WebSocketTransport::new(ws_cfg);
    let gateway_transport = GatewayTransport::new(None, ws);
    let connection = gateway_transport.connect().await.expect("connect");
    connection
        .authenticate("test-token", b"device-slot-1".to_vec())
        .await
        .expect("authenticate");
    alice_no_gw.core().set_gateway(Arc::new(connection)).await;

    // Phase D: Alice fetch_inbox через facade. SecretChat::fetch_inbox →
    // chat_common::fetch_secret_inbox → sealed-sender unseal → MLS decrypt.
    // Alice need to open the chat handle for fetch_inbox (chat_id alread known
    // from create earlier; alice_chat_no_gw still holds same chat_id).
    let alice_chat_via_gw = SecretChat::open(alice_no_gw.core(), chat_id)
        .await
        .expect("SecretChat::open");

    let messages = alice_chat_via_gw
        .fetch_inbox()
        .await
        .expect("SecretChat::fetch_inbox MUST unseal staged envelope");

    assert_eq!(
        messages.len(),
        1,
        "exactly one staged envelope should be drained, got {}",
        messages.len()
    );

    let msg = &messages[0];

    // Sender PeerId MUST be recovered from inner Ed25519 signature, NOT
    // from gateway routing from_user_id field (mock staged 0xFFu8 here).
    assert_eq!(
        msg.sender.0, bob_id_pk_bytes,
        "DecryptedMessage.sender MUST be Bob's MLS identity_pk (recovered \
         from inner-AEAD-encrypted signature), NOT bogus 0xFFu8 from_user_id"
    );
    assert_ne!(
        msg.sender.0, [0xFFu8; 32],
        "sender MUST NOT be the bogus 0xFFu8 transport routing metadata — \
         that bytes path is sender-anonymous in blind-postman model"
    );

    // Plaintext was MLS-decrypted correctly после sealed-sender unwrap.
    assert_eq!(
        msg.text, "from-bob-via-inner-sig",
        "MLS decrypt после sealed-sender unwrap MUST recover Bob's plaintext"
    );

    // chat_id propagated from caller (alice's facade), не из envelope.
    assert_eq!(msg.chat_id, chat_id);

    // Timestamp from gateway envelope (transport-level metadata, not signed).
    assert_eq!(msg.timestamp, 1_700_000_500_000);

    // Sanity guard: drop unused alice_id_pk_bytes warning.
    let _ = alice_id_pk_bytes;
}

#[tokio::test]
async fn cloud_chat_send_text_does_not_require_peer_x25519_directory_invariant_guard() {
    // Cross-mode invariant: CloudChat::send_text НЕ goes through sealed-sender
    // path (per ADR-006 Вариант C — Cloud trades sender anonymity для multi-
    // device history via Sealed Server wrap). Доказательство: send_text
    // succeeds на 2-member Cloud group БЕЗ peer_x25519 registration. Если бы
    // CloudChat шёл через sealed-sender, missing X25519 → fail-closed
    // (как в `secret_chat_send_text_fails_closed_when_peer_x25519_not_registered`).
    let mock = MockGateway::spawn(MockBehavior::standard_any_token()).await;
    let alice = bootstrap_client_with_ws_gateway(&mock).await;
    let cloud_chat = CloudChat::create(alice.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice CloudChat::create");

    let mut bob = SisterClient::new();
    let welcome = cloud_chat
        .add_member(bob.peer_id(), bob.publish_key_package_bytes())
        .await
        .expect("alice add_member(bob) на Cloud chat");
    bob.join_group_from_welcome(&welcome);

    // NB: Deliberately do NOT register_peer_x25519 для Bob. If CloudChat
    // tried sealed-sender wrapping, missing directory entry → fail-closed.
    let result = cloud_chat
        .send_text("cloud-mode-no-sealed-sender-needed".into())
        .await;

    assert!(
        result.is_ok(),
        "CloudChat::send_text MUST succeed без peer_x25519 registration — \
         Cloud mode не вызывает sealed-sender (ADR-006 Вариант C). \
         Если result.is_err(), значит CloudChat ошибочно requires \
         peer_x25519_directory, нарушая cross-mode invariant. got {result:?}"
    );
}

// === ChatId import guard (unused in tests but documents the type surface) ===
const _: fn() = || {
    let _: ChatId = ChatId([0u8; 32]);
};
