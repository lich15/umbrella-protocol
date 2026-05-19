//! F-CLIENT-FACADE-1 closure session 2 (2026-05-19): contract tests for the
//! [`umbrella_client::transport::GatewayTransport`] auto-fallback wrapper.
//!
//! Pipeline:
//!
//! 1. Try QUIC if configured → on success return [`GatewayConnection::Quic`].
//! 2. Otherwise try WebSocket → on success return
//!    [`GatewayConnection::WebSocket`].
//! 3. If QUIC was tried and failed AND WebSocket fails, return
//!    [`GatewayTransportError::BothFailed`] with each wire's error.
//!
//! These tests pin the contract §2.3 obligation that the client prefers
//! QUIC when reachable and silently falls back to WebSocket when UDP is
//! blocked or the QUIC server is absent.

mod mock_gateway;

use std::time::Duration;

use mock_gateway::quic::{build_test_quic_client_tls, QuicMockBehavior, QuicMockGateway};
use mock_gateway::{build_test_client_tls_config, MockBehavior, MockGateway};
use umbrella_client::transport::{
    ClientPayload, GatewayTransport, GatewayTransportError, NegotiatedSubprotocol,
    NegotiatedTransport, QuicConfig, QuicTransport, ServerPayload, SpkiPin, WebSocketTransport,
    WsConfig, WsTlsConfig, SPKI_PIN_LEN,
};

const TEST_HOST: &str = "localhost";

fn ws_config_for(mock: &MockGateway) -> WsConfig {
    let tls = build_test_client_tls_config(TEST_HOST, mock.spki_pin());
    WsConfig {
        url: mock.wss_url(),
        subprotocols: vec!["umx.pb.v1", "umx.v1"],
        tls: WsTlsConfig::Rustls(tls),
        connect_timeout: Duration::from_secs(5),
    }
}

fn quic_config_for(mock: &QuicMockGateway) -> QuicConfig {
    let tls = build_test_quic_client_tls(mock.server_name(), mock.spki_pin());
    QuicConfig {
        server_addr: mock.addr(),
        server_name: mock.server_name().to_string(),
        tls,
        connect_timeout: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn gateway_picks_quic_when_both_transports_reachable() {
    let ws_mock = MockGateway::spawn(MockBehavior::standard_any_token()).await;
    let quic_mock = QuicMockGateway::spawn(QuicMockBehavior::standard_any_token()).await;

    let ws_transport = WebSocketTransport::new(ws_config_for(&ws_mock));
    let quic_transport =
        QuicTransport::new(quic_config_for(&quic_mock)).expect("quic transport builds");
    let gateway = GatewayTransport::new(Some(quic_transport), ws_transport);

    let conn = gateway.connect().await.expect("connect succeeds");
    assert!(conn.is_quic(), "QUIC reachable → must prefer QUIC");
    assert_eq!(conn.negotiated(), NegotiatedTransport::Quic);
    assert_eq!(conn.negotiated().metric_label(), "quic");
    let _ = conn.close().await;
}

#[tokio::test]
async fn gateway_falls_back_to_websocket_when_quic_unreachable() {
    let ws_mock = MockGateway::spawn(MockBehavior::standard_any_token()).await;

    // QUIC config points at a closed UDP port — handshake will time out.
    // We use a low timeout so the test doesn't drag.
    let dead_quic_addr = "127.0.0.1:1".parse().unwrap();
    let dead_quic_tls = build_test_quic_client_tls("localhost", random_pin());
    let dead_quic_cfg = QuicConfig {
        server_addr: dead_quic_addr,
        server_name: "localhost".to_string(),
        tls: dead_quic_tls,
        connect_timeout: Duration::from_millis(300),
    };
    let quic_transport = QuicTransport::new(dead_quic_cfg).expect("transport builds");
    let ws_transport = WebSocketTransport::new(ws_config_for(&ws_mock));
    let gateway = GatewayTransport::new(Some(quic_transport), ws_transport);

    let conn = gateway.connect().await.expect("WS fallback succeeds");
    assert!(!conn.is_quic(), "QUIC unreachable → must fall back to WS");
    assert_eq!(
        conn.negotiated(),
        NegotiatedTransport::WebSocket(NegotiatedSubprotocol::ProtobufV1)
    );
    assert_eq!(conn.negotiated().metric_label(), "ws-pb");
    let _ = conn.close().await;
}

#[tokio::test]
async fn gateway_returns_both_failed_when_quic_and_websocket_both_fail() {
    // Both transports point at closed ports / dead URLs.
    let dead_quic_addr = "127.0.0.1:1".parse().unwrap();
    let dead_quic_tls = build_test_quic_client_tls("localhost", random_pin());
    let dead_quic_cfg = QuicConfig {
        server_addr: dead_quic_addr,
        server_name: "localhost".to_string(),
        tls: dead_quic_tls,
        connect_timeout: Duration::from_millis(300),
    };
    let quic_transport = QuicTransport::new(dead_quic_cfg).expect("transport builds");

    let dead_ws_cfg = WsConfig {
        url: "wss://localhost:1/".to_string(),
        subprotocols: vec!["umx.pb.v1"],
        tls: WsTlsConfig::Rustls(build_test_client_tls_config(TEST_HOST, random_pin())),
        connect_timeout: Duration::from_millis(300),
    };
    let ws_transport = WebSocketTransport::new(dead_ws_cfg);
    let gateway = GatewayTransport::new(Some(quic_transport), ws_transport);

    let err = gateway
        .connect()
        .await
        .expect_err("both transports unreachable → BothFailed");

    match err {
        GatewayTransportError::BothFailed { .. } => {}
        other => panic!("expected BothFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn gateway_uses_websocket_only_when_quic_is_not_configured() {
    let ws_mock = MockGateway::spawn(MockBehavior::standard_any_token()).await;
    let ws_transport = WebSocketTransport::new(ws_config_for(&ws_mock));
    let gateway = GatewayTransport::new(None, ws_transport);

    let conn = gateway.connect().await.expect("WS-only connect succeeds");
    assert!(!conn.is_quic());
    assert_eq!(
        conn.negotiated(),
        NegotiatedTransport::WebSocket(NegotiatedSubprotocol::ProtobufV1)
    );
    let _ = conn.close().await;
}

#[tokio::test]
async fn gateway_send_recv_delegates_to_quic_when_chosen() {
    let ws_mock = MockGateway::spawn(MockBehavior::standard_any_token()).await;
    let quic_mock = QuicMockGateway::spawn(QuicMockBehavior::standard_any_token()).await;

    let ws_transport = WebSocketTransport::new(ws_config_for(&ws_mock));
    let quic_transport =
        QuicTransport::new(quic_config_for(&quic_mock)).expect("quic transport builds");
    let gateway = GatewayTransport::new(Some(quic_transport), ws_transport);

    let conn = gateway.connect().await.expect("connect");
    assert!(conn.is_quic());
    conn.authenticate("any", b"d".to_vec())
        .await
        .expect("auth via QUIC delegate");

    conn.send_envelope(ClientPayload::SendMessage {
        to_user_id: vec![1; 32],
        ciphertext: vec![0xCC; 8],
    })
    .await
    .expect("send via QUIC delegate");
    let frame = conn.recv_envelope().await.expect("recv via QUIC delegate");
    match frame.payload {
        ServerPayload::SendAck { msg_id } => assert_eq!(msg_id.len(), 32),
        other => panic!("expected SendAck, got {other:?}"),
    }
}

#[tokio::test]
async fn gateway_send_recv_delegates_to_websocket_when_quic_unavailable() {
    let ws_mock = MockGateway::spawn(MockBehavior::standard_any_token()).await;
    let ws_transport = WebSocketTransport::new(ws_config_for(&ws_mock));
    let gateway = GatewayTransport::new(None, ws_transport);

    let conn = gateway.connect().await.expect("connect");
    assert!(!conn.is_quic());
    conn.authenticate("any", b"d".to_vec())
        .await
        .expect("auth via WS delegate");
    conn.send_envelope(ClientPayload::Ping { client_ts_ms: 7 })
        .await
        .expect("send via WS delegate");
    let frame = conn.recv_envelope().await.expect("recv via WS delegate");
    match frame.payload {
        ServerPayload::Pong { client_ts_ms, .. } => assert_eq!(client_ts_ms, 7),
        other => panic!("expected Pong, got {other:?}"),
    }
}

#[tokio::test]
async fn gateway_metric_labels_partition_quic_and_websocket_observability() {
    let labels = [
        NegotiatedTransport::Quic.metric_label(),
        NegotiatedTransport::WebSocket(NegotiatedSubprotocol::ProtobufV1).metric_label(),
        NegotiatedTransport::WebSocket(NegotiatedSubprotocol::MessagePackV1).metric_label(),
    ];
    assert_eq!(labels, ["quic", "ws-pb", "ws-mpack"]);
}

fn random_pin() -> SpkiPin {
    SpkiPin::from_bytes([0xFEu8; SPKI_PIN_LEN])
}
