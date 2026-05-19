//! F-CLIENT-FACADE-1 closure session 4 (2026-05-19): contract tests proving
//! that [`CloudChat::fetch_inbox`] and [`SecretChat::fetch_inbox`] drain
//! `IncomingMessage` envelopes from the active [`GatewayConnection`] and
//! translate them into [`DecryptedMessage`] values with placeholder
//! plaintext (real MLS decrypt is session-5+ scope).
//!
//! ## Coverage
//!
//! - Backwards-compat: no `set_gateway` → fetch_inbox returns empty `Vec`,
//!   so existing fixtures stay green.
//! - With WebSocket gateway + no pushed messages → fetch_inbox returns
//!   empty after the 100 ms drain budget elapses (no busy-loop, no panic).
//! - Mock pushes 1 / 3 / 5 IncomingMessage envelopes after AuthOk →
//!   fetch_inbox returns the same count, in the same order, with
//!   per-field correctness (sender PeerId, timestamp, text, msg_id).
//! - Second call to fetch_inbox after the first one drained the spool
//!   returns empty (confirms the helper consumed the envelopes rather
//!   than re-reading them).
//! - CloudChat + SecretChat both observe the same wire path.

mod mock_gateway;

use std::sync::Arc;
use std::time::Duration;

use mock_gateway::{
    build_test_client_tls_config, MockBehavior, MockGateway, MockIncomingMessage,
};
use rand::rngs::OsRng;
use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_client::facade::chat_common::{
    ChatSettings, PeerId, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
};
use umbrella_client::transport::{GatewayTransport, WebSocketTransport, WsConfig, WsTlsConfig};
use umbrella_client::{ClientConfig, CloudChat, SecretChat, UmbrellaClient};
use umbrella_identity::{IdentitySeed, MnemonicLanguage};

const TEST_HOST: &str = "localhost";

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
            config: ThresholdConfig::new(3, 5).expect("3-of-5 is a valid ThresholdConfig"),
        },
        default_ciphersuite: UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
    }
}

fn test_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

async fn bootstrap_client_with_ws_gateway(mock: &MockGateway) -> Arc<UmbrellaClient> {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test");
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

fn make_mock_message(byte: u8, ts: u64, hex: &str, body: &str) -> MockIncomingMessage {
    MockIncomingMessage {
        from_user_id: vec![byte; 32],
        ciphertext: body.as_bytes().to_vec(),
        sent_ts_ms: ts,
        msg_id: hex.to_string(),
    }
}

#[tokio::test]
async fn cloud_chat_fetch_inbox_without_gateway_returns_empty() {
    let client = UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test");
    let cloud = CloudChat::create(
        client.core(),
        vec![PeerId([2u8; 32])],
        ChatSettings::default(),
    )
    .await
    .expect("create CloudChat");

    let messages = cloud
        .fetch_inbox()
        .await
        .expect("fetch_inbox without gateway returns empty stub");

    assert!(
        messages.is_empty(),
        "no gateway → must return empty Vec (legacy stub); got {} messages",
        messages.len()
    );
}

#[tokio::test]
async fn cloud_chat_fetch_inbox_with_empty_gateway_returns_empty_after_timeout() {
    let mock = MockGateway::spawn(MockBehavior::standard_any_token()).await;
    let client = bootstrap_client_with_ws_gateway(&mock).await;
    let cloud = CloudChat::create(
        client.core(),
        vec![PeerId([2u8; 32])],
        ChatSettings::default(),
    )
    .await
    .expect("create CloudChat");

    let messages = cloud
        .fetch_inbox()
        .await
        .expect("fetch_inbox with empty inbox returns empty after drain timeout");

    assert!(messages.is_empty());
}

#[tokio::test]
async fn cloud_chat_fetch_inbox_drains_single_pushed_message() {
    let pushed = MockIncomingMessage {
        from_user_id: vec![0xAA; 32],
        ciphertext: b"hello session 4".to_vec(),
        sent_ts_ms: 1_700_000_000_123,
        msg_id: format!("{:032x}", 0xCAFEu64),
    };
    let mock = MockGateway::spawn(MockBehavior::PushInboxAfterAuth {
        accept_token: None,
        messages: vec![pushed.clone()],
    })
    .await;
    let client = bootstrap_client_with_ws_gateway(&mock).await;
    let cloud = CloudChat::create(
        client.core(),
        vec![PeerId([2u8; 32])],
        ChatSettings::default(),
    )
    .await
    .expect("create CloudChat");

    let messages = cloud
        .fetch_inbox()
        .await
        .expect("fetch_inbox with one pushed message returns one DecryptedMessage");

    assert_eq!(messages.len(), 1, "expected exactly 1 inbox message");
    let msg = &messages[0];
    assert_eq!(
        msg.sender,
        PeerId([0xAA; 32]),
        "sender PeerId must come from IncomingMessage.from_user_id"
    );
    assert_eq!(msg.timestamp, 1_700_000_000_123);
    assert_eq!(msg.text, "hello session 4");
    // chat_id field on DecryptedMessage must match the CloudChat instance
    // the caller invoked fetch_inbox on (stub Block-7.2 CloudChat::create
    // uses chat_id [0u8; 32]).
    assert_eq!(msg.chat_id.0, [0u8; 32]);
}

#[tokio::test]
async fn cloud_chat_fetch_inbox_drains_multiple_pushed_messages_in_order() {
    let messages = vec![
        make_mock_message(0x01, 100, &format!("{:032x}", 1), "first"),
        make_mock_message(0x02, 200, &format!("{:032x}", 2), "second"),
        make_mock_message(0x03, 300, &format!("{:032x}", 3), "third"),
        make_mock_message(0x04, 400, &format!("{:032x}", 4), "fourth"),
        make_mock_message(0x05, 500, &format!("{:032x}", 5), "fifth"),
    ];
    let mock = MockGateway::spawn(MockBehavior::PushInboxAfterAuth {
        accept_token: None,
        messages: messages.clone(),
    })
    .await;
    let client = bootstrap_client_with_ws_gateway(&mock).await;
    let cloud = CloudChat::create(
        client.core(),
        vec![PeerId([2u8; 32])],
        ChatSettings::default(),
    )
    .await
    .expect("create CloudChat");

    let drained = cloud
        .fetch_inbox()
        .await
        .expect("fetch_inbox drains 5 pushed messages");

    assert_eq!(drained.len(), 5);
    for (i, msg) in drained.iter().enumerate() {
        let expected = &messages[i];
        assert_eq!(msg.sender.0[0], expected.from_user_id[0]);
        assert_eq!(msg.timestamp, expected.sent_ts_ms);
        assert_eq!(msg.text, String::from_utf8_lossy(&expected.ciphertext));
    }
}

#[tokio::test]
async fn secret_chat_fetch_inbox_drains_pushed_messages() {
    let pushed = vec![
        make_mock_message(0xDE, 1000, &format!("{:032x}", 0xDEAD), "secret one"),
        make_mock_message(0xAD, 2000, &format!("{:032x}", 0xBEEF), "secret two"),
    ];
    let mock = MockGateway::spawn(MockBehavior::PushInboxAfterAuth {
        accept_token: None,
        messages: pushed,
    })
    .await;
    let client = bootstrap_client_with_ws_gateway(&mock).await;
    let secret = SecretChat::create(
        client.core(),
        vec![PeerId([3u8; 32])],
        ChatSettings::default(),
    )
    .await
    .expect("create SecretChat");

    let drained = secret
        .fetch_inbox()
        .await
        .expect("fetch_inbox via SecretChat works the same wire path as CloudChat");

    assert_eq!(drained.len(), 2);
    assert_eq!(drained[0].text, "secret one");
    assert_eq!(drained[1].text, "secret two");
}

#[tokio::test]
async fn cloud_chat_fetch_inbox_second_call_after_drain_returns_empty() {
    let pushed = vec![
        make_mock_message(0x01, 100, &format!("{:032x}", 1), "only message"),
    ];
    let mock = MockGateway::spawn(MockBehavior::PushInboxAfterAuth {
        accept_token: None,
        messages: pushed,
    })
    .await;
    let client = bootstrap_client_with_ws_gateway(&mock).await;
    let cloud = CloudChat::create(
        client.core(),
        vec![PeerId([2u8; 32])],
        ChatSettings::default(),
    )
    .await
    .expect("create CloudChat");

    let first = cloud
        .fetch_inbox()
        .await
        .expect("first fetch_inbox drains the single pushed message");
    assert_eq!(first.len(), 1);

    let second = cloud
        .fetch_inbox()
        .await
        .expect("second fetch_inbox returns empty — first consumed the envelope");
    assert!(
        second.is_empty(),
        "second drain must be empty; got {} messages (helper re-read consumed envelope)",
        second.len()
    );
}

#[tokio::test]
async fn cloud_chat_fetch_inbox_msg_id_correctly_decoded_from_hex() {
    let expected_msg_id_bytes = {
        let mut b = [0u8; 16];
        b[14..16].copy_from_slice(&0xBABEu16.to_be_bytes());
        b
    };
    let hex = hex::encode(expected_msg_id_bytes);
    assert_eq!(hex.len(), 32);

    let mock = MockGateway::spawn(MockBehavior::PushInboxAfterAuth {
        accept_token: None,
        messages: vec![MockIncomingMessage {
            from_user_id: vec![0x10; 32],
            ciphertext: b"id-test".to_vec(),
            sent_ts_ms: 42,
            msg_id: hex,
        }],
    })
    .await;
    let client = bootstrap_client_with_ws_gateway(&mock).await;
    let cloud = CloudChat::create(
        client.core(),
        vec![PeerId([2u8; 32])],
        ChatSettings::default(),
    )
    .await
    .expect("create CloudChat");

    let drained = cloud.fetch_inbox().await.expect("fetch_inbox");
    assert_eq!(drained.len(), 1);
    assert_eq!(
        drained[0].message_id.0, expected_msg_id_bytes,
        "msg_id must be hex-decoded byte-equal to the server-issued bytes"
    );
}
