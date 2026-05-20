//! Task 6 max_ratchet v3 facade integration test (2026-05-20).
//!
//! Закрывает Task 6 carry-over из max-ratchet v3 spec 2026-05-20 §7.2: CloudChat /
//! SecretChat фасады теперь активируют max ratchet защиты (aggressive DH ratchet +
//! SPQR HMAC) для всех production пользователей через `MaxRatchetState` storage в
//! ClientCore + v3 envelope codec в `ClientPayload::SendMessage.ciphertext` field.
//!
//! Тестируем:
//! 1. `CloudChat::create` auto-registers `MaxRatchetState` parallel `UmbrellaGroup`.
//! 2. `unregister_group` также удаляет `MaxRatchetState`.
//! 3. Sender side: `encrypt_with_rekey_authenticated` advances epoch + sets counter
//!    + bundles в v3 wire format (marker `0xFF`).
//! 4. End-to-end Alice → Bob round-trip: Alice's facade produces v3 bundle, Bob
//!    (sister UmbrellaGroup outside facade) processes commit + decrypts ciphertext
//!    + verifies SPQR HMAC ⇒ plaintext recovered exactly.
//! 5. Negative SPQR: single bit flip в HMAC bytes → verify_hmac returns false
//!    (proves real cryptographic auth, не paperwork).
//!
//! Task 6 max_ratchet v3 facade integration test (2026-05-20). End-to-end proves
//! the facade activates aggressive DH ratchet + SPQR HMAC for all v3 users.

use std::sync::Arc;

use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use rand_core::OsRng;
use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_client::facade::chat_common::{
    ChatSettings, PeerId, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
};
use umbrella_client::facade::max_ratchet_envelope;
use umbrella_client::{ClientConfig, CloudChat, UmbrellaClient};
#[allow(deprecated)]
use umbrella_identity::IdentitySeed;
use umbrella_identity::{Clock, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock};
use umbrella_mls::max_ratchet::spqr;
use umbrella_mls::{
    build_device_key_package, GroupPolicy, IncomingMessage, UmbrellaCiphersuite, UmbrellaGroup,
    UmbrellaProvider,
};

const TEST_CS: UmbrellaCiphersuite = UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519;
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

/// Sister non-facade client для simulation Bob получающего v3 bundle от Alice.
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

// =============================================================================
// Test 1: MaxRatchetState auto-registered at CloudChat::create
// =============================================================================

#[tokio::test]
async fn cloud_chat_create_registers_max_ratchet_state_in_core() {
    let client = bootstrap_alice_facade().await;
    let chat = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("CloudChat::create");

    let state_arc = client
        .core()
        .get_ratchet_state(chat.chat_id())
        .await
        .expect("Task 6: MaxRatchetState MUST be auto-registered at CloudChat::create");

    let state = state_arc.lock().await;
    assert_eq!(
        state.commit_counter(),
        0,
        "fresh MaxRatchetState starts at counter 0"
    );
    let config = state.config();
    assert!(
        config.aggressive_dh_per_message,
        "default config MUST enable aggressive DH ratchet (Task 6: default-on for all v3 users)"
    );
    assert!(
        config.spqr_deniable_auth,
        "default config MUST enable SPQR HMAC (Task 6: default-on for all v3 users)"
    );
    assert_eq!(config.timer_rekey_seconds, 300, "5-minute timer default");
    assert_eq!(
        config.pq_ratchet_every_n_commits, 3,
        "PQ extension triggers every 3rd commit default"
    );
}

// =============================================================================
// Test 2: unregister_group also removes MaxRatchetState (consistency invariant)
// =============================================================================

#[tokio::test]
async fn unregister_group_also_removes_max_ratchet_state() {
    let client = bootstrap_alice_facade().await;
    let chat = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("create");

    // Sanity: both present before.
    assert!(client.core().get_group(chat.chat_id()).await.is_some());
    assert!(
        client
            .core()
            .get_ratchet_state(chat.chat_id())
            .await
            .is_some(),
        "Task 6: ratchet_state MUST be present after create"
    );

    let _dropped_group = client.core().unregister_group(chat.chat_id()).await;

    assert!(
        client.core().get_group(chat.chat_id()).await.is_none(),
        "group removed by unregister"
    );
    assert!(
        client
            .core()
            .get_ratchet_state(chat.chat_id())
            .await
            .is_none(),
        "Task 6: unregister_group MUST also drop MaxRatchetState (consistency)"
    );
}

// =============================================================================
// Test 3: encrypt_with_rekey_authenticated produces v3 bundle with correct shape
// =============================================================================

#[tokio::test]
async fn send_path_produces_v3_bundle_with_marker_commit_ciphertext_mac() {
    let client = bootstrap_alice_facade().await;
    let chat = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("create");

    let group_arc = client.core().get_group(chat.chat_id()).await.unwrap();
    let state_arc = client
        .core()
        .get_ratchet_state(chat.chat_id())
        .await
        .unwrap();

    let mut group = group_arc.lock().await;
    let mut state = state_arc.lock().await;
    let initial_epoch = group.epoch();
    let initial_counter = state.commit_counter();

    let outgoing = state
        .encrypt_with_rekey_authenticated(
            &mut group,
            client.core().mls_provider().as_ref(),
            client.core().mls_keystore().as_ref(),
            b"hello v3",
            T0 + 1,
        )
        .expect("encrypt_with_rekey_authenticated");

    // State invariants после send.
    assert_eq!(
        state.commit_counter(),
        initial_counter + 1,
        "counter must increment by 1"
    );
    assert_eq!(
        group.epoch(),
        initial_epoch + 1,
        "force_rekey must advance epoch by 1"
    );
    assert_eq!(outgoing.epoch_after_send, initial_epoch + 1);
    assert!(outgoing.commit_bytes.is_some(), "commit must be present");
    assert!(
        outgoing.spqr_mac.is_some(),
        "SPQR mac must be present (default-on)"
    );

    // Bundle in v3 format.
    let spqr_mac_arr: [u8; 32] = {
        let mut a = [0u8; 32];
        a.copy_from_slice(outgoing.spqr_mac.as_ref().unwrap());
        a
    };
    let bundle = max_ratchet_envelope::encode_v3(
        outgoing.commit_bytes.as_deref(),
        &outgoing.ciphertext_bytes,
        Some(&spqr_mac_arr),
    );

    assert_eq!(
        bundle[0],
        max_ratchet_envelope::V3_MARKER,
        "first byte must be v3 marker 0xFF"
    );
    assert_eq!(
        bundle[1],
        max_ratchet_envelope::V3_VERSION,
        "second byte must be version 0x03"
    );

    // Roundtrip decode succeeds.
    let decoded = max_ratchet_envelope::try_decode_v3(&bundle).expect("decode v3");
    assert!(
        decoded.commit_bytes.is_some(),
        "v3 bundle must include commit (force_rekey ran)"
    );
    assert!(
        !decoded.ciphertext_bytes.is_empty(),
        "ciphertext must be present"
    );
    assert_eq!(decoded.spqr_mac, spqr_mac_arr, "SPQR mac roundtrip");
}

// =============================================================================
// Test 4: End-to-end Alice → Bob round-trip with v3 bundle + real SPQR verify
// =============================================================================

#[tokio::test]
async fn end_to_end_alice_send_bob_decrypt_with_spqr_verify() {
    // Phase 1: Setup Bob first to publish KP.
    let bob = SisterClient::new();
    let bob_peer = bob.peer_id();
    let bob_kp_bytes = bob.publish_key_package_bytes();

    // Phase 2: Alice facade + create chat.
    let client = bootstrap_alice_facade().await;
    let alice_chat = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("alice create");

    // Phase 3: Alice add_member(bob).
    let welcome_bytes = alice_chat
        .add_member(bob_peer, bob_kp_bytes)
        .await
        .expect("alice add_member(bob)");

    // Phase 4: Bob joins from Welcome (epoch=1, members=2).
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

    // Phase 5: Alice produces v3 bundle via MaxRatchetState (aggressive DH +
    // SPQR HMAC). Manually invoke the same logic as send_mls_text.
    let alice_group_arc = client.core().get_group(alice_chat.chat_id()).await.unwrap();
    let alice_state_arc = client
        .core()
        .get_ratchet_state(alice_chat.chat_id())
        .await
        .unwrap();

    let mut alice_group = alice_group_arc.lock().await;
    let mut alice_state = alice_state_arc.lock().await;
    let outgoing = alice_state
        .encrypt_with_rekey_authenticated(
            &mut alice_group,
            client.core().mls_provider().as_ref(),
            client.core().mls_keystore().as_ref(),
            b"hello bob from alice v3",
            T0 + 2,
        )
        .expect("alice encrypt_with_rekey_authenticated");

    assert!(
        outgoing.commit_bytes.is_some(),
        "alice force_rekey must produce commit"
    );
    assert!(outgoing.spqr_mac.is_some(), "SPQR mac present");

    let commit_bytes = outgoing.commit_bytes.as_ref().unwrap().clone();
    let ciphertext_bytes = outgoing.ciphertext_bytes.clone();
    let spqr_mac_bytes = outgoing.spqr_mac.as_ref().unwrap().clone();

    // Release locks before bob processing — simulates wire transit.
    drop(alice_state);
    drop(alice_group);

    // Phase 6: Bob processes commit first (epoch advances).
    let commit_result = bob_group
        .process_incoming(&bob.provider, &commit_bytes)
        .expect("bob process_incoming(commit)");
    match commit_result {
        IncomingMessage::CommitApplied { .. } => {}
        other => panic!("expected CommitApplied from commit, got {other:?}"),
    }
    assert_eq!(
        bob_group.epoch(),
        2,
        "bob epoch advances 1 → 2 after merging Alice's force_rekey commit"
    );

    // Phase 7: Bob decrypts ciphertext at epoch 2.
    let app_result = bob_group
        .process_incoming(&bob.provider, &ciphertext_bytes)
        .expect("bob process_incoming(ciphertext)");
    let payload = match app_result {
        IncomingMessage::Application { payload, .. } => payload,
        other => panic!("expected Application, got {other:?}"),
    };
    assert_eq!(
        payload, b"hello bob from alice v3",
        "Bob decrypts Alice's payload correctly after force_rekey at new epoch"
    );

    // Phase 8: Bob verifies SPQR HMAC over ciphertext using current epoch exporter.
    let exporter = bob_group
        .exporter_secret(&bob.provider, "umbrellax-spqr-deniable-auth", b"", 32)
        .expect("bob exporter_secret");
    let epoch_secret = spqr::derive_epoch_secret_from_exporter(&exporter.expose()[..32])
        .expect("bob epoch_secret HKDF");

    let mac_arr: [u8; 32] = {
        let mut a = [0u8; 32];
        a.copy_from_slice(&spqr_mac_bytes);
        a
    };
    assert!(
        spqr::verify_hmac(&epoch_secret, &ciphertext_bytes, &mac_arr),
        "SPQR HMAC MUST verify on Bob side — proves end-to-end aggressive DH + SPQR delivery via facade"
    );

    // Phase 9: Negative — single bit flip в MAC bytes → verify rejects.
    let mut tampered_mac = mac_arr;
    tampered_mac[0] ^= 0xFF;
    assert!(
        !spqr::verify_hmac(&epoch_secret, &ciphertext_bytes, &tampered_mac),
        "tampered SPQR HMAC must fail verify (constant-time real auth)"
    );

    // Phase 10: Negative — ciphertext bit flip → original MAC fails.
    let mut tampered_ct = ciphertext_bytes.clone();
    tampered_ct[10] ^= 0xFF;
    assert!(
        !spqr::verify_hmac(&epoch_secret, &tampered_ct, &mac_arr),
        "tampered ciphertext must fail SPQR verify"
    );
}

// =============================================================================
// Test 5: Counter increments across multiple sends in same chat
// =============================================================================

#[tokio::test]
async fn counter_increments_on_each_send_authentication_path() {
    let client = bootstrap_alice_facade().await;
    let chat = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("create");

    let group_arc = client.core().get_group(chat.chat_id()).await.unwrap();
    let state_arc = client
        .core()
        .get_ratchet_state(chat.chat_id())
        .await
        .unwrap();

    for i in 1..=4u64 {
        let mut group = group_arc.lock().await;
        let mut state = state_arc.lock().await;
        let _ = state
            .encrypt_with_rekey_authenticated(
                &mut group,
                client.core().mls_provider().as_ref(),
                client.core().mls_keystore().as_ref(),
                format!("msg {}", i).as_bytes(),
                T0 + i,
            )
            .expect("send");
        assert_eq!(
            state.commit_counter(),
            i as u32,
            "counter must equal send number after each encrypt_with_rekey_authenticated"
        );
        assert_eq!(group.epoch(), i, "epoch must equal send number");
    }
}

// =============================================================================
// Active-mode security claim tests — Task 6 + max_ratchet v3 real evidence
// (per [[feedback-real-not-paperwork]] правило 2026-05-19)
// =============================================================================

/// **SPQR deniability — property test (real cryptographic evidence, not paperwork).**
///
/// Cryptographic claim: SPQR authentication uses HMAC-SHA256 keyed с epoch_secret,
/// который **shared симметрично** между sender и receiver через MLS exporter chain.
/// Любая сторона knowing epoch_secret может compute_hmac над arbitrary message →
/// MAC бесполезен как proof of authorship в court (third-party adversary cannot
/// distinguish который из двух сторон produced the MAC).
///
/// Это в contrast к signing (Ed25519 над session key) — signed messages have
/// non-repudiable authorship через verifiable signature. SPQR sacrifice'ит
/// non-repudiation за deniability — design goal per OTR (Borisov-Goldberg-Brewer 2004).
///
/// Test demonstrates property: given same epoch_secret + same message, MAC bit-equal
/// regardless of computing party. Forgery over fabricated message succeeds against
/// verify_hmac. Это **mathematical evidence** deniability claim в spec §3.4.
#[test]
fn spqr_deniability_either_party_can_forge_mac_over_arbitrary_payload() {
    // Симулируем shared epoch_secret — Alice и Bob оба derive один и тот же
    // 32-byte secret через exporter_secret из MLS group state. В тесте этот
    // factor reduces до literal: оба знают bytes.
    let shared_epoch_secret = [0xABu8; 32];

    // Authentic flow: Alice authors message, computes MAC. Bob verifies.
    let alice_authentic_payload = b"alice's real message";
    let mac_by_alice = spqr::compute_hmac(&shared_epoch_secret, alice_authentic_payload);
    assert!(
        spqr::verify_hmac(&shared_epoch_secret, alice_authentic_payload, &mac_by_alice),
        "Authentic MAC must verify"
    );

    // Deniability claim #1: identical MAC от Alice и от Bob (если бы Bob воспроизвёл
    // computation) over same message — НИКАКОГО distinguisher. HMAC deterministic.
    let mac_by_bob_replaying = spqr::compute_hmac(&shared_epoch_secret, alice_authentic_payload);
    assert_eq!(
        mac_by_alice, mac_by_bob_replaying,
        "Deniability property #1: HMAC deterministic from shared secret + message → MAC \
         bit-equal regardless of party. Third party cannot attribute authorship."
    );

    // Deniability claim #2: forgery property. Bob может fabricate compromising
    // payload + valid MAC. Court receiving (payload, mac) cannot distinguish
    // genuine Alice message from Bob's fabrication.
    let fabricated_compromising_payload = b"fabricated 'evidence' message ostensibly from Alice";
    let forgery_mac = spqr::compute_hmac(&shared_epoch_secret, fabricated_compromising_payload);
    assert!(
        spqr::verify_hmac(
            &shared_epoch_secret,
            fabricated_compromising_payload,
            &forgery_mac,
        ),
        "Deniability property #2: forgery accepts verify — no cryptographic distinguisher exists \
         between genuine Alice message and Bob's fabrication"
    );

    // Contrast: different secret → different MAC. SPQR HMAC is per-epoch fresh, so
    // forgeries don't transfer across epochs (forward-secret deniability).
    let next_epoch_secret = [0xCDu8; 32];
    let mac_next_epoch = spqr::compute_hmac(&next_epoch_secret, alice_authentic_payload);
    assert_ne!(
        mac_by_alice, mac_next_epoch,
        "Deniability property #3: per-epoch fresh — MAC tied to current epoch_secret, no \
         cross-epoch transfer"
    );
}

/// **V3 envelope decoder robustness — adversarial input fuzz-like test.**
///
/// Wire format codec MUST not panic on arbitrary attacker-controlled bytes. Decoder
/// strict-checks structure (marker, version, lengths consistent, no trailing); ALL
/// other inputs return `None` gracefully → caller falls back на legacy MLS path.
///
/// Crucially, no `panic!` / `unwrap` / arithmetic overflow possible. Tests cover:
/// truncation, wrong marker, wrong version, length-prefix inflation, trailing
/// junk, max-size values (u16::MAX commit_len with insufficient buffer).
#[test]
fn v3_envelope_decoder_robust_to_adversarial_inputs() {
    // 1. Empty blob.
    assert!(max_ratchet_envelope::try_decode_v3(&[]).is_none());

    // 2. Single byte 0xFF (marker only, no rest).
    assert!(max_ratchet_envelope::try_decode_v3(&[0xFF]).is_none());

    // 3. Marker + version + zero-everything truncated.
    assert!(max_ratchet_envelope::try_decode_v3(&[0xFF, 0x03]).is_none());

    // 4. Minimum-size shell (marker + version + zero-len fields + zero mac) — должен
    //    decode'ить как empty commit + empty ct + zero mac.
    let mut minimum = vec![0xFF, 0x03, 0x00, 0x00]; // marker, version, commit_len = 0
    minimum.extend_from_slice(&0u32.to_be_bytes()); // ct_len = 0
    minimum.extend_from_slice(&[0u8; 32]); // mac
    let decoded = max_ratchet_envelope::try_decode_v3(&minimum).expect("minimum decodes");
    assert!(decoded.commit_bytes.is_none());
    assert_eq!(decoded.ciphertext_bytes.len(), 0);
    assert_eq!(decoded.spqr_mac, [0u8; 32]);

    // 5. Inflated commit_len без backing bytes (u16::MAX = 65535).
    let mut inflated_commit = vec![0xFF, 0x03];
    inflated_commit.extend_from_slice(&u16::MAX.to_be_bytes());
    inflated_commit.resize(inflated_commit.len() + 10, 0); // only 10 bytes of "commit" available
    assert!(
        max_ratchet_envelope::try_decode_v3(&inflated_commit).is_none(),
        "decoder must reject inflated commit_len без backing bytes"
    );

    // 6. Random bytes starting with 0xFF — overwhelming majority should return None.
    // Generated по predictable pattern для test determinism.
    for i in 0..=255u8 {
        let mut blob = vec![0xFF, 0x03];
        // Vary commit_len and trailing data; most won't form valid structure.
        blob.extend_from_slice(&(i as u16).to_be_bytes());
        for j in 0..i {
            blob.push(j);
        }
        // ct_len + ct + mac slots intentionally missing для большинства i.
        let result = max_ratchet_envelope::try_decode_v3(&blob);
        // No panic — это главный invariant. Result либо None либо Some, both acceptable.
        let _ = result;
    }

    // 7. Bytes mimicking MLS message (ProtocolVersion 0x0100 BE first 2 bytes) — never v3.
    let mls_lookalike = vec![0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
    assert!(
        max_ratchet_envelope::try_decode_v3(&mls_lookalike).is_none(),
        "MLS message lookalike не должен decode'иться как v3"
    );

    // 8. Trailing byte after valid structure — must reject (strict equality).
    let mut valid_with_trailing = max_ratchet_envelope::encode_v3(
        Some(&[0xAA; 4]),
        &[0xBB; 8],
        Some(&[0xCC; max_ratchet_envelope::SPQR_MAC_LEN]),
    );
    valid_with_trailing.push(0xDE);
    assert!(
        max_ratchet_envelope::try_decode_v3(&valid_with_trailing).is_none(),
        "trailing byte must cause decode rejection (anti-trailing-data attack)"
    );
}

/// **V3 envelope boundary: large-size PQ commit (X-Wing) + medium ciphertext.**
///
/// Real-world PQ commit ~1100 bytes (X-Wing ML-KEM-768 ciphertext); ciphertext
/// может быть multi-KB для большого application payload. Test verifies codec
/// handles realistic upper bounds без overflow / panic.
#[test]
fn v3_envelope_large_pq_sized_commit_and_multi_kb_ciphertext_roundtrip() {
    // PQ commit ~1100 bytes (X-Wing realistic size).
    let pq_commit = vec![0x55; 1100];
    // Ciphertext 4096 bytes — представляет большой application message (~4KB plaintext).
    let large_ct = vec![0x77; 4096];
    let mac = [0xEEu8; max_ratchet_envelope::SPQR_MAC_LEN];

    let bundle = max_ratchet_envelope::encode_v3(Some(&pq_commit), &large_ct, Some(&mac));

    // Wire-size sanity: marker(1) + ver(1) + commit_len(2) + commit(1100) +
    // ct_len(4) + ct(4096) + mac(32) = 5236 bytes total.
    assert_eq!(
        bundle.len(),
        1 + 1 + 2 + 1100 + 4 + 4096 + 32,
        "v3 wire size accounting must match for PQ-sized inputs"
    );

    let decoded = max_ratchet_envelope::try_decode_v3(&bundle).expect("large bundle decodes");
    assert_eq!(decoded.commit_bytes.unwrap().len(), 1100);
    assert_eq!(decoded.ciphertext_bytes.len(), 4096);
    assert_eq!(decoded.spqr_mac, mac);
}

/// **Idle window attack defence — timer rekey end-to-end через MaxRatchetState.**
///
/// Scenario: Alice idle на чате > 5 минут. Adversary рассчитывает что symmetric
/// ratchet keys stale → window для side-channel extraction расширяется. Defence:
/// `check_timer_and_rekey` forces rekey при elapsed ≥ timer_rekey_seconds, что
/// advances epoch + invalidates все ранее-derived chain keys.
///
/// Test: setup chat с timer=60s, simulate 90s elapsed, verify check_timer_and_rekey
/// returns Some(commit_bytes) + epoch advances.
#[tokio::test]
async fn idle_window_attack_defence_timer_rekey_advances_epoch_after_pause() {
    use umbrella_mls::{MaxRatchetConfig, MaxRatchetState};

    let client = bootstrap_alice_facade().await;
    let chat = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("create");

    let group_arc = client.core().get_group(chat.chat_id()).await.unwrap();

    // Test-only config: timer 60s вместо production 300s чтобы test быстрый.
    // Заменяем auto-created state на test-config вариант.
    let test_state = Arc::new(tokio::sync::Mutex::new(MaxRatchetState::with_config(
        MaxRatchetConfig::with_overrides(true, 60, 3, true),
    )));

    let initial_epoch = {
        let group = group_arc.lock().await;
        group.epoch()
    };

    // Phase 1: первый send устанавливает last_rekey_at_unix = T0+1.
    {
        let mut group = group_arc.lock().await;
        let mut state = test_state.lock().await;
        let _ = state
            .encrypt_with_rekey_authenticated(
                &mut group,
                client.core().mls_provider().as_ref(),
                client.core().mls_keystore().as_ref(),
                b"first message",
                T0 + 1,
            )
            .expect("first send");
    }

    let epoch_after_first = {
        let group = group_arc.lock().await;
        group.epoch()
    };
    assert_eq!(
        epoch_after_first,
        initial_epoch + 1,
        "force_rekey advances epoch"
    );

    // Phase 2: idle period 90s. Timer (60s) должен trigger при check.
    {
        let mut group = group_arc.lock().await;
        let mut state = test_state.lock().await;
        let timer_commit = state
            .check_timer_and_rekey(
                &mut group,
                client.core().mls_provider().as_ref(),
                client.core().mls_keystore().as_ref(),
                T0 + 1 + 90, // 90 секунд после last rekey
            )
            .expect("check_timer_and_rekey");

        assert!(
            timer_commit.is_some(),
            "Idle window defence: timer (60s) MUST trigger force_rekey at elapsed 90s"
        );
        assert!(
            !timer_commit.unwrap().is_empty(),
            "Returned commit_bytes must be non-empty TLS-serialized MlsMessage"
        );
    }

    let epoch_after_timer = {
        let group = group_arc.lock().await;
        group.epoch()
    };
    assert_eq!(
        epoch_after_timer,
        epoch_after_first + 1,
        "Idle timer rekey advances epoch by 1 (chain key fully refreshed)"
    );

    // Phase 3: immediately re-check — should NOT trigger again (idempotent внутри window).
    {
        let mut group = group_arc.lock().await;
        let mut state = test_state.lock().await;
        let no_double_trigger = state
            .check_timer_and_rekey(
                &mut group,
                client.core().mls_provider().as_ref(),
                client.core().mls_keystore().as_ref(),
                T0 + 1 + 90 + 5, // 5s after timer rekey
            )
            .expect("second check");
        assert!(
            no_double_trigger.is_none(),
            "Timer не должен double-trigger в 5s после last rekey (idempotent)"
        );
    }
}

/// **Forward secrecy: aggressive DH per message — каждое сообщение в новом epoch'е.**
///
/// Scenario: adversary получает long-term identity key (R7 device capture). С
/// classical MLS только: forward secrecy сохраняется для прошлых сообщений
/// (chain keys deleted after use). С max_ratchet aggressive DH: даже compromised
/// process memory at epoch N не помогает decrypt messages at N+1 потому что
/// каждое сообщение это NEW epoch с full DH ratchet step.
///
/// Demonstrable property: epoch strictly monotonic, +1 per send (не +0 как в
/// vanilla MLS application messages которые stay в одном epoch).
#[tokio::test]
async fn forward_secrecy_aggressive_dh_each_send_in_new_epoch() {
    let client = bootstrap_alice_facade().await;
    let chat = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("create");

    let group_arc = client.core().get_group(chat.chat_id()).await.unwrap();
    let state_arc = client
        .core()
        .get_ratchet_state(chat.chat_id())
        .await
        .unwrap();

    let initial_epoch = {
        let group = group_arc.lock().await;
        group.epoch()
    };

    // Send 10 messages — verify каждое в новом epoch.
    let mut epochs_seen = Vec::with_capacity(10);
    for i in 1..=10u64 {
        let mut group = group_arc.lock().await;
        let mut state = state_arc.lock().await;
        let outgoing = state
            .encrypt_with_rekey_authenticated(
                &mut group,
                client.core().mls_provider().as_ref(),
                client.core().mls_keystore().as_ref(),
                format!("message {}", i).as_bytes(),
                T0 + i,
            )
            .expect("send");
        epochs_seen.push(outgoing.epoch_after_send);
    }

    // Strict monotonic +1 per send — это и есть aggressive DH defence.
    // В vanilla MLS multiple application messages в одном epoch имели бы equal epoch_after_send.
    for (i, epoch) in epochs_seen.iter().enumerate() {
        let expected = initial_epoch + (i as u64) + 1;
        assert_eq!(
            *epoch,
            expected,
            "Aggressive DH defence: send #{} must be in epoch {} (initial + {}), got {}",
            i + 1,
            expected,
            i + 1,
            epoch
        );
    }

    // Все epochs distinct (no replay window).
    let unique_count = epochs_seen
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    assert_eq!(
        unique_count,
        epochs_seen.len(),
        "Forward secrecy property: каждое сообщение в DISTINCT epoch (no two sends share epoch)"
    );
}
