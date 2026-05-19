//! F-CLIENT-FACADE-1 closure session 2 (2026-05-19): consumer-driven
//! contract tests for the gateway-svc QUIC transport.
//!
//! Each test below targets one wire-format obligation described in
//! `docs/integration/gateway-svc-contract.md §2.1` and exercises it
//! end-to-end: real `quinn` client → real TLS 1.3 + QUIC handshake → real
//! ALPN `umx-quic-v1` negotiation → real length-delimited Protobuf envelope
//! round-trip → real [`umbrella_client::transport::QuicTransport`] surface.
//! The peer is the in-process quinn-based mock at
//! `tests/mock_gateway/quic.rs`, not a stub — it binds a real UDP socket,
//! performs a real QUIC handshake, and returns Protobuf-encoded
//! `ServerEnvelope` responses to client envelopes.

mod mock_gateway;

use std::sync::Arc;
use std::time::{Duration, Instant};

use mock_gateway::quic::{build_test_quic_client_tls, QuicMockBehavior, QuicMockGateway};
use umbrella_client::transport::{
    ClientPayload, QuicConfig, QuicTransport, QuicTransportError, ServerPayload, SpkiPin,
    ALPN_UMX_QUIC_V1, SPKI_PIN_LEN,
};

fn quic_config_for(mock: &QuicMockGateway) -> QuicConfig {
    let tls = build_test_quic_client_tls(mock.server_name(), mock.spki_pin());
    QuicConfig {
        server_addr: mock.addr(),
        server_name: mock.server_name().to_string(),
        tls,
        // Contract §2.3 production preset is 500 ms; contract tests use a
        // larger budget so a slow CI runner does not flake the latency
        // ceiling assertion.
        connect_timeout: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn quic_handshake_negotiates_alpn_umx_quic_v1() {
    let mock = QuicMockGateway::spawn(QuicMockBehavior::standard_any_token()).await;
    let cfg = quic_config_for(&mock);
    let transport = QuicTransport::new(cfg).expect("transport builds");

    let conn = transport
        .connect()
        .await
        .expect("QUIC handshake completes and ALPN negotiates");

    assert_eq!(conn.alpn(), ALPN_UMX_QUIC_V1);
    assert_eq!(conn.remote_addr(), mock.addr());
    let _ = conn.close().await;
}

#[tokio::test]
async fn quic_handshake_fails_when_server_offers_wrong_alpn() {
    let mock = QuicMockGateway::spawn(QuicMockBehavior::RejectAlpn).await;
    let cfg = quic_config_for(&mock);
    let transport = QuicTransport::new(cfg).expect("transport builds");

    let err = transport
        .connect()
        .await
        .expect_err("server offering wrong ALPN must abort the handshake");

    // The handshake either surfaces as a Handshake variant (rustls
    // alert "no_application_protocol") or as Tls — both are acceptable.
    match err {
        QuicTransportError::Handshake(_)
        | QuicTransportError::Tls(_)
        | QuicTransportError::AlpnRejected { .. } => {}
        other => panic!("expected Handshake/Tls/AlpnRejected, got {other:?}"),
    }
}

#[tokio::test]
async fn quic_auth_round_trip_succeeds_with_matching_token() {
    let mock = QuicMockGateway::spawn(QuicMockBehavior::Standard {
        accept_token: Some("real-jwt-token".to_string()),
    })
    .await;
    let cfg = quic_config_for(&mock);
    let conn = QuicTransport::new(cfg)
        .expect("transport builds")
        .connect()
        .await
        .expect("connect");

    conn.authenticate("real-jwt-token", b"device-slot-1".to_vec())
        .await
        .expect("auth round-trip succeeds");
    let _ = conn.close().await;
}

#[tokio::test]
async fn quic_auth_round_trip_fails_with_invalid_token() {
    let mock = QuicMockGateway::spawn(QuicMockBehavior::Standard {
        accept_token: Some("real-jwt-token".to_string()),
    })
    .await;
    let cfg = quic_config_for(&mock);
    let conn = QuicTransport::new(cfg)
        .expect("transport builds")
        .connect()
        .await
        .expect("connect");

    let err = conn
        .authenticate("forged-token", b"device-slot-1".to_vec())
        .await
        .expect_err("invalid token must be rejected");

    match err {
        QuicTransportError::AuthRejected { code } => assert_eq!(code, "auth.invalid"),
        other => panic!("expected AuthRejected, got {other:?}"),
    }
}

#[tokio::test]
async fn quic_send_message_round_trip_yields_ack_with_hex_msg_id() {
    let mock = QuicMockGateway::spawn(QuicMockBehavior::standard_any_token()).await;
    let cfg = quic_config_for(&mock);
    let conn = QuicTransport::new(cfg)
        .expect("transport builds")
        .connect()
        .await
        .expect("connect");
    conn.authenticate("any", b"d".to_vec()).await.unwrap();

    let payload = ClientPayload::SendMessage {
        to_user_id: vec![0xAB; 32],
        ciphertext: b"opaque-mls-envelope-bytes".to_vec(),
    };
    let sent_seq = conn.send_envelope(payload).await.unwrap();
    assert!(
        sent_seq >= 2,
        "auth used seq 1, send must be ≥ 2; got {sent_seq}"
    );

    let frame = conn.recv_envelope().await.expect("recv ack");
    match frame.payload {
        ServerPayload::SendAck { msg_id } => {
            assert_eq!(msg_id.len(), 32, "msg_id should be 32 hex chars (16 bytes)");
            assert!(
                msg_id.chars().all(|c| c.is_ascii_hexdigit()),
                "msg_id should be lowercase hex: {msg_id}"
            );
        }
        other => panic!("expected SendAck, got {other:?}"),
    }
}

#[tokio::test]
async fn quic_ping_pong_round_trip_returns_server_timestamp() {
    let mock = QuicMockGateway::spawn(QuicMockBehavior::standard_any_token()).await;
    let cfg = quic_config_for(&mock);
    let conn = QuicTransport::new(cfg)
        .expect("transport builds")
        .connect()
        .await
        .expect("connect");
    conn.authenticate("any", b"d".to_vec()).await.unwrap();

    let client_ts = 1_700_000_000_000;
    conn.send_envelope(ClientPayload::Ping {
        client_ts_ms: client_ts,
    })
    .await
    .unwrap();
    let frame = conn.recv_envelope().await.expect("recv pong");
    match frame.payload {
        ServerPayload::Pong {
            client_ts_ms,
            server_ts_ms,
        } => {
            assert_eq!(client_ts_ms, client_ts, "pong must echo client_ts_ms");
            assert!(server_ts_ms > 0, "server should stamp wall-clock time");
        }
        other => panic!("expected Pong, got {other:?}"),
    }
}

#[tokio::test]
async fn quic_tls_handshake_fails_on_spki_pin_mismatch() {
    let mock = QuicMockGateway::spawn(QuicMockBehavior::standard_any_token()).await;
    let wrong_pin = SpkiPin::from_bytes([0xFFu8; SPKI_PIN_LEN]);
    let wrong_tls = build_test_quic_client_tls(mock.server_name(), wrong_pin);
    let cfg = QuicConfig {
        server_addr: mock.addr(),
        server_name: mock.server_name().to_string(),
        tls: wrong_tls,
        connect_timeout: Duration::from_secs(5),
    };
    let transport = QuicTransport::new(cfg).expect("transport builds");

    let err = transport
        .connect()
        .await
        .expect_err("wrong SPKI pin must abort TLS+QUIC handshake");

    // SPKI pin mismatch surfaces as Handshake (transport layer carries the
    // TLS alert) or Tls — accept either.
    match err {
        QuicTransportError::Handshake(_) | QuicTransportError::Tls(_) => {}
        other => panic!("expected Handshake/Tls, got {other:?}"),
    }
}

#[tokio::test]
async fn quic_close_after_accept_observable_to_client() {
    let mock = QuicMockGateway::spawn(QuicMockBehavior::CloseAfterAccept).await;
    let cfg = quic_config_for(&mock);
    let transport = QuicTransport::new(cfg).expect("transport builds");

    let connect_result = transport.connect().await;
    match connect_result {
        Ok(conn) => {
            // Server may close after handshake but before we open bi-stream;
            // attempting any operation should surface a clean error rather
            // than a panic.
            let err = conn
                .authenticate("any", b"d".to_vec())
                .await
                .expect_err("server closed connection — auth must error");
            match err {
                QuicTransportError::Closed
                | QuicTransportError::Io(_)
                | QuicTransportError::Handshake(_) => {}
                other => panic!("expected Closed/Io/Handshake, got {other:?}"),
            }
        }
        Err(QuicTransportError::Handshake(_))
        | Err(QuicTransportError::Closed)
        | Err(QuicTransportError::Io(_)) => {
            // Acceptable — connect failed cleanly because the server closed.
        }
        Err(other) => panic!("unexpected connect error variant: {other:?}"),
    }
}

#[tokio::test]
async fn quic_handshake_latency_loopback_is_under_one_second_concrete_baseline() {
    // Loopback QUIC handshake observed ~5-15 ms on M-series arm64 dev
    // laptop (dominated by ring crypto + TLS 1.3 ClientHello). The 1-second
    // ceiling is a CI-safe sanity guard.
    let mock = QuicMockGateway::spawn(QuicMockBehavior::standard_any_token()).await;
    let cfg = quic_config_for(&mock);
    let transport = QuicTransport::new(cfg).expect("transport builds");

    let start = Instant::now();
    let conn = transport.connect().await.expect("handshake succeeds");
    let elapsed = start.elapsed();

    println!("quic handshake latency (loopback TLS 1.3 + QUIC 1-RTT): {elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(1),
        "loopback QUIC handshake should be << 1 s, took {elapsed:?}"
    );
    let _ = conn.close().await;
}

#[tokio::test]
async fn quic_concurrent_send_and_recv_do_not_deadlock_on_split_streams() {
    // QuicConnection holds the send and recv halves of the bidi stream
    // behind separate Mutexes — verified by firing send and recv on
    // independent tokio tasks. A single Mutex<(SendStream, RecvStream)>
    // would deadlock here.
    let mock = QuicMockGateway::spawn(QuicMockBehavior::standard_any_token()).await;
    let cfg = quic_config_for(&mock);
    let conn = Arc::new(
        QuicTransport::new(cfg)
            .expect("transport builds")
            .connect()
            .await
            .expect("connect"),
    );
    conn.authenticate("any", b"d".to_vec()).await.unwrap();

    let send_handle = {
        let conn = Arc::clone(&conn);
        tokio::spawn(async move {
            conn.send_envelope(ClientPayload::Ping { client_ts_ms: 42 })
                .await
        })
    };
    let recv_handle = {
        let conn = Arc::clone(&conn);
        tokio::spawn(async move { conn.recv_envelope().await })
    };

    let (send_res, recv_res) = tokio::join!(send_handle, recv_handle);
    let _seq = send_res.unwrap().expect("send completes without deadlock");
    let frame = recv_res.unwrap().expect("recv completes without deadlock");
    match frame.payload {
        ServerPayload::Pong { client_ts_ms, .. } => assert_eq!(client_ts_ms, 42),
        other => panic!("expected Pong, got {other:?}"),
    }
}
