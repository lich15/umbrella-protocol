//! F-CLIENT-FACADE-1 closure session 6c (2026-05-19): contract tests for
//! Cloud-mode at-rest send path. Session 6 wired the FETCH side
//! (`cloud_sync_history` 3-of-5 unwrap + AEAD decrypt) but left send-side
//! population of postman.cloud_history as a deferred. Session 6c closes the
//! gap: `CloudChat::send_text` теперь dual-writes — live MLS through gateway
//! plus at-rest entry through `cloud_publish_at_rest` into
//! `StubPostmanTransport.cloud_history`. Result: a Cloud-mode chat now
//! actually round-trips end-to-end через facade (send → at-rest →
//! cloud_sync_history → plaintext).
//!
//! ## Coverage
//!
//! - `cloud_chat_send_text_writes_at_rest_entry_to_postman_history`
//! - `cloud_chat_send_to_cloud_sync_history_round_trip_recovers_plaintext`
//!   (**THE KEY TEST**: full end-to-end Cloud send → recover)
//! - `cloud_chat_send_multiple_messages_assigns_strictly_monotonic_msg_seq`
//! - `secret_chat_send_text_does_not_write_at_rest_entry` (Secret-mode
//!   invariant: no Sealed Servers, no at-rest layer)
//! - `cloud_chat_send_text_without_gateway_does_not_write_at_rest_entry`
//!   (stub-msg_id path is excluded from at-rest write)
//!
//! Эти тесты pin'ят session-6c contract: Cloud-mode send DOES auto-publish
//! at-rest entry (когда gateway present), Secret-mode НЕ публикует, и
//! at-rest entries fully roundtrip через cloud_sync_history facade method.

mod mock_gateway;

use std::sync::Arc;
use std::time::Duration;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use mock_gateway::{build_test_client_tls_config, MockBehavior, MockGateway};
use rand_core::OsRng;
use umbrella_backup::cloud_wrap::aead::decompress_point;
use umbrella_backup::cloud_wrap::threshold::shamir_split_for_testing;
use umbrella_backup::cloud_wrap::ServerUnwrapShare as ShareAlias;
use umbrella_backup::cloud_wrap::{
    ServerUnwrapShare, ThresholdConfig, WitnessIndex, WrappedKey, WrappingParams, DEFAULT_TOTAL,
    POINT_LEN, PROTOCOL_VERSION,
};
use umbrella_client::facade::chat_common::{
    ChatId, ChatSettings, MessageId, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
};
use umbrella_client::transport::{GatewayTransport, WebSocketTransport, WsConfig, WsTlsConfig};
use umbrella_client::{ClientConfig, CloudChat, SecretChat, UmbrellaClient};
use umbrella_identity::{IdentitySeed, MnemonicLanguage};

const TEST_HOST: &str = "localhost";

#[allow(
    deprecated,
    reason = "test seed gen — same pattern as facade_session6_postman.rs"
)]
fn test_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

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

fn compute_partial_share(wi: WitnessIndex, k_i: Scalar, wrapped: &WrappedKey) -> ServerUnwrapShare {
    let r = decompress_point(&wrapped.ephemeral_r).unwrap();
    let partial = (k_i * r).compress().to_bytes();
    ShareAlias {
        witness_index: wi,
        partial,
    }
}

async fn bootstrap_client_with_ws_gateway_and_wrapping(
    mock: &MockGateway,
    params: WrappingParams,
) -> Arc<UmbrellaClient> {
    let client =
        UmbrellaClient::bootstrap_for_test(test_config_with_wrapping_params(params), test_seed())
            .await
            .expect("bootstrap");
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

#[tokio::test]
async fn cloud_chat_send_text_writes_at_rest_entry_to_postman_history() {
    let (params, _shares) = setup_wrapping_params();
    let mock = MockGateway::spawn(MockBehavior::standard_any_token()).await;
    let client = bootstrap_client_with_ws_gateway_and_wrapping(&mock, params).await;

    let cloud = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("create");

    let msg_id = cloud
        .send_text("session 6c at-rest send".to_string())
        .await
        .expect("send_text");
    assert_ne!(msg_id, MessageId([0u8; 16]), "gateway send must succeed");

    // Verify the at-rest entry exists on postman.cloud_history under this chat_id.
    // drain_cloud_history(since=0) returns entries with sent_ts_ms > 0;
    // unix_now_millis is far above 0 so the entry IS returned.
    let entries = client
        .core()
        .postman_transport()
        .drain_cloud_history(&cloud.chat_id().0, 0);
    assert_eq!(
        entries.len(),
        1,
        "F-CLIENT-FACADE-1 session 6c: CloudChat::send_text MUST write \
         exactly one at-rest entry to postman.cloud_history per successful \
         send"
    );

    let entry = &entries[0];
    assert_eq!(
        entry.msg_id, msg_id.0,
        "at-rest msg_id MUST match gateway ack"
    );
    assert_eq!(entry.msg_seq, 0, "first send to a chat allocates msg_seq=0");
    assert!(
        entry.ciphertext_at_rest.len() > "session 6c at-rest send".len(),
        "ciphertext_at_rest is plaintext + 16-byte Poly1305 tag — strictly larger than plaintext"
    );
    assert_eq!(
        entry.wrapped_key.version, PROTOCOL_VERSION,
        "WrappedKey MUST carry canonical version"
    );
}

#[tokio::test]
async fn cloud_chat_send_to_cloud_sync_history_round_trip_recovers_plaintext() {
    // **THE KEY SESSION-6C TEST**: full end-to-end Cloud-mode round-trip
    // через facade — send → at-rest write → drain (test side) → compute
    // partial shares → push back → cloud_sync_history → recover plaintext.
    let (params, shares) = setup_wrapping_params();
    let mock = MockGateway::spawn(MockBehavior::standard_any_token()).await;
    let client = bootstrap_client_with_ws_gateway_and_wrapping(&mock, params).await;

    let cloud = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("create");

    let plaintext = "Cloud-mode roundtrip session 6c — at-rest write integration";
    let _msg_id = cloud
        .send_text(plaintext.to_string())
        .await
        .expect("send_text");

    // Drain the at-rest entry to access its wrapped_key for share computation.
    // (Production: postman holds it indefinitely; here we drain + re-push.)
    let entries = client
        .core()
        .postman_transport()
        .drain_cloud_history(&cloud.chat_id().0, 0);
    assert_eq!(entries.len(), 1);
    let entry = entries[0].clone();

    // Compute 3 valid partial shares for the wrapped_key the sender produced.
    let partial_shares: Vec<ServerUnwrapShare> = shares
        .iter()
        .take(3)
        .map(|(wi, k_i)| compute_partial_share(*wi, *k_i, &entry.wrapped_key))
        .collect();

    // Re-push the entry (drain consumed it) and stage the shares.
    client
        .core()
        .postman_transport()
        .push_cloud_history(cloud.chat_id().0, entry);
    client
        .core()
        .stub_unwrap_transport()
        .expect("stub unwrap transport in test config")
        .push_response(partial_shares);

    // Facade sync_history runs the full Cloud-wrap unwrap pipeline +
    // ChaCha20-Poly1305 outer decrypt → recovered plaintext.
    let history = cloud
        .cloud_sync_history(None)
        .await
        .expect("cloud_sync_history full round-trip");

    assert_eq!(history.len(), 1, "exactly one recovered message");
    assert_eq!(
        history[0].text, plaintext,
        "F-CLIENT-FACADE-1 session 6c: Cloud-mode end-to-end MUST recover \
         the same plaintext bytes that the sender encrypted"
    );
}

#[tokio::test]
async fn cloud_chat_send_multiple_messages_assigns_strictly_monotonic_msg_seq() {
    let (params, _shares) = setup_wrapping_params();
    let mock = MockGateway::spawn(MockBehavior::standard_any_token()).await;
    let client = bootstrap_client_with_ws_gateway_and_wrapping(&mock, params).await;

    let cloud = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("create");

    for i in 0..5 {
        let _ = cloud
            .send_text(format!("msg-{i}"))
            .await
            .expect("send_text");
    }

    let entries = client
        .core()
        .postman_transport()
        .drain_cloud_history(&cloud.chat_id().0, 0);
    assert_eq!(entries.len(), 5, "5 sends → 5 at-rest entries");

    // Strict monotonic msg_seq: 0, 1, 2, 3, 4 — critical invariant for
    // ChaCha20-Poly1305 nonce reuse prevention.
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(
            entry.msg_seq, i as u64,
            "msg_seq MUST be strictly monotonic per chat — got {} at index {i}",
            entry.msg_seq
        );
    }
}

#[tokio::test]
async fn secret_chat_send_text_does_not_write_at_rest_entry() {
    // SecretChat по дизайну (ADR-006 Variant C) НЕ имеет Sealed Servers
    // backup — потеря всех devices = потеря history. send_text должен
    // НЕ публиковать at-rest entries. Invariant guard.
    //
    // F-CLIENT-FACADE-1 session 7 (2026-05-19) note: SecretChat::send_text
    // на single-member group (без add_member peers) теперь возвращает stub
    // `MessageId([0u8; 16])` — нет peers, нет sealed-sender envelopes, нет
    // gateway frames. Это OK для этого test'а — primary invariant («no
    // at-rest entries written») сохраняется regardless of msg_id outcome.
    // 2-party SecretChat send/fetch full round-trip coverage:
    // `tests/facade_session7_sealed_sender.rs`.
    let (params, _shares) = setup_wrapping_params();
    let mock = MockGateway::spawn(MockBehavior::standard_any_token()).await;
    let client = bootstrap_client_with_ws_gateway_and_wrapping(&mock, params).await;

    let secret = SecretChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("create secret");

    let msg_id = secret
        .send_text("secret message — no at-rest".to_string())
        .await
        .expect("send_text secret on single-member group MUST NOT fail");

    // Session 7: single-member SecretChat returns stub (no peers to seal).
    assert_eq!(
        msg_id,
        MessageId([0u8; 16]),
        "session 7 single-member SecretChat returns stub MessageId"
    );

    let entries = client
        .core()
        .postman_transport()
        .drain_cloud_history(&secret.chat_id().0, 0);
    assert!(
        entries.is_empty(),
        "ADR-006 Variant C: SecretChat::send_text MUST NOT write at-rest \
         entries (no Sealed Servers backup для Secret mode). Got {} entries.",
        entries.len()
    );
}

#[tokio::test]
async fn cloud_chat_send_text_without_gateway_does_not_write_at_rest_entry() {
    // No gateway → send_mls_text returns Ok(MessageId([0u8; 16])) stub.
    // Session 6c skips at-rest write in stub path (gateway-conditional
    // gate), иначе все stub-sends публиковали бы entries с duplicate
    // msg_id = [0u8; 16] — нарушая postman uniqueness invariant.
    let (params, _shares) = setup_wrapping_params();
    let client =
        UmbrellaClient::bootstrap_for_test(test_config_with_wrapping_params(params), test_seed())
            .await
            .expect("bootstrap without gateway");
    let cloud = CloudChat::create(client.core(), Vec::new(), ChatSettings::default())
        .await
        .expect("create");

    let msg_id = cloud
        .send_text("no gateway — stub path".to_string())
        .await
        .expect("stub send");
    assert_eq!(msg_id, MessageId([0u8; 16]), "stub returns zero msg_id");

    let entries = client
        .core()
        .postman_transport()
        .drain_cloud_history(&cloud.chat_id().0, 0);
    assert!(
        entries.is_empty(),
        "stub send (no gateway) MUST NOT write at-rest entry"
    );
}

#[tokio::test]
async fn next_cloud_msg_seq_strictly_monotonic_per_chat_and_independent_across_chats() {
    let client = UmbrellaClient::bootstrap_for_test(
        test_config_with_wrapping_params(setup_wrapping_params().0),
        test_seed(),
    )
    .await
    .expect("bootstrap");

    let chat_a = ChatId([0xAA; 32]);
    let chat_b = ChatId([0xBB; 32]);

    // Counter invariant: strictly monotonic per chat, independent across.
    assert_eq!(client.core().next_cloud_msg_seq(chat_a).await, 0);
    assert_eq!(client.core().next_cloud_msg_seq(chat_a).await, 1);
    assert_eq!(
        client.core().next_cloud_msg_seq(chat_b).await,
        0,
        "chat_b independent of chat_a"
    );
    assert_eq!(client.core().next_cloud_msg_seq(chat_a).await, 2);
    assert_eq!(client.core().next_cloud_msg_seq(chat_b).await, 1);
}
