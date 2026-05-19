//! F-CLIENT-FACADE-1 closure session 1 (2026-05-19): mock gateway harness for
//! the consumer-driven contract tests in
//! `tests/transport_websocket_contract.rs`. This is **client-side test
//! infrastructure** — it imitates the parts of `rust_1mlrd/crates/gateway-svc`
//! that are visible to the WebSocket client over the wire (RFC 6455 upgrade,
//! `umx.pb.v1` Protobuf envelope round-trip, TLS 1.3) so the client crate
//! stays buildable + testable in isolation. It is NOT a substitute for the
//! real backend — integration with the live `rust_1mlrd` cluster is a
//! separate milestone with its own deployment requirements.
//!
//! ## Design
//!
//! Each test spawns its own [`MockGateway`] on a kernel-assigned loopback
//! port. The mock generates a self-signed TLS certificate via `rcgen`,
//! advertises the cert's SPKI digest to the test (so the client can pin it),
//! and serves a fixed [`MockBehavior`] across all subsequent connections.
//! Per-connection state (sequence numbers, ack counters) lives in the
//! per-task closure; cross-connection state (e.g. "close the first N attempts
//! then behave normally") lives in shared `Arc<AtomicUsize>` counters.
//!
//! ## Test-side TLS plumbing
//!
//! Self-signed certs do not validate against the system root store, so the
//! client side needs a permissive inner verifier wrapped with the production
//! [`umbrella_client::transport::SpkiPinningVerifier`]. The wrapper preserves
//! the pin enforcement we actually care about (test 7 verifies wrong-pin
//! rejection) without dragging real trust-store plumbing into the test
//! harness. [`build_test_client_tls_config`] builds exactly this stack.
//!
//! ## Limitations
//!
//! - Only `umx.pb.v1` envelope handling is implemented. Receiving a
//!   `MessagePack` request would land in [`MockBehavior::EchoSubprotocol`]
//!   for negative tests but never produces a decodable response — the
//!   client does not consume MessagePack frames either.
//! - WebSocket close handshake is delegated to tungstenite defaults; we do
//!   not assert on specific close codes (tested in test 9 by absence of
//!   leaked panics, not by code).

#![allow(dead_code, reason = "test-only helpers; not every contract test uses every behavior variant")]
#![allow(clippy::result_large_err, reason = "tokio-tungstenite Callback trait fixes the Result<Response, ErrorResponse> signature; we cannot box the Err side")]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::ClientConfig as RustlsClientConfig;
use rustls::ServerConfig;
use rustls::SignatureScheme;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use umbrella_client::transport::proto_ws as proto;
use umbrella_client::transport::{extract_spki_pin_from_cert_der, PinningConfig, SpkiPin, SpkiPinningVerifier};

/// Behavioural knob for the mock gateway. Each test instantiates one variant
/// to exercise a specific contract obligation.
///
/// Behavioural knob for the mock gateway.
#[derive(Clone, Debug)]
pub enum MockBehavior {
    /// RFC 6455 negotiation + envelope round-trip. Auth is gated by
    /// `accept_token`: `Some(t)` accepts only when `ClientAuth.token == t`,
    /// `None` accepts any token (used by tests that do not exercise auth).
    ///
    /// Standard RFC 6455 + envelope round-trip with optional auth gating.
    Standard {
        /// `Some(t)` → accept only this token; `None` → accept any token.
        accept_token: Option<String>,
    },
    /// Reject HTTP Upgrade with `400 Bad Request` (e.g. subprotocol mismatch).
    /// Used by negative subprotocol-negotiation tests.
    ///
    /// Reject HTTP Upgrade with 400.
    RejectUpgrade,
    /// Echo a fixed subprotocol regardless of what the client offered. Used
    /// to drive the `SubprotocolRejected` arm when the server picks something
    /// the client did not actually request.
    ///
    /// Echo a fixed subprotocol regardless of client offer.
    EchoSubprotocol(&'static str),
    /// Close the first `fail_count` TCP connections immediately after accept,
    /// then behave per [`MockBehavior::Standard`] for subsequent attempts.
    /// Used by the reconnect test.
    ///
    /// Close the first N connections, then act as Standard.
    CloseFirstNThenStandard {
        /// Number of leading connections to drop immediately.
        fail_count: usize,
        /// Auth token gate for connections beyond `fail_count`.
        accept_token: Option<String>,
    },
}

impl MockBehavior {
    /// Permissive standard preset that accepts any auth token. Most contract
    /// tests use this baseline and override only the field they exercise.
    ///
    /// Permissive standard preset accepting any auth token.
    #[must_use]
    pub fn standard_any_token() -> Self {
        Self::Standard {
            accept_token: None,
        }
    }
}

/// Handle to a running mock gateway. Dropping the handle aborts the listener
/// task; the kernel returns the bound port to the ephemeral pool.
///
/// Handle to a running mock gateway.
pub struct MockGateway {
    bound: SocketAddr,
    server_cert_der: CertificateDer<'static>,
    task: JoinHandle<()>,
}

impl Drop for MockGateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockGateway {
    /// Spawn a TLS-terminating mock gateway on `127.0.0.1:0` (kernel-assigned
    /// port) and return a handle. The caller obtains the bound URL via
    /// [`Self::wss_url`] and the SPKI pin via [`Self::spki_pin`].
    ///
    /// Spawn a TLS-terminating mock gateway on a kernel-assigned port.
    pub async fn spawn(behavior: MockBehavior) -> Self {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("rcgen: generate self-signed cert for mock gateway");
        let cert_der: CertificateDer<'static> = cert.der().clone();
        let key_der_bytes = signing_key.serialize_der();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der_bytes));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("rustls server: TLS 1.3 supported")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("rustls server: single cert+key");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind 127.0.0.1:0");
        let bound = listener.local_addr().expect("local_addr");

        let attempt_counter = Arc::new(AtomicUsize::new(0));
        let behavior_for_task = behavior.clone();

        let task = tokio::spawn(async move {
            loop {
                let (tcp_stream, _peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let attempt = attempt_counter.fetch_add(1, Ordering::SeqCst);
                let behavior = behavior_for_task.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    handle_connection(tcp_stream, acceptor, behavior, attempt).await;
                });
            }
        });

        Self {
            bound,
            server_cert_der: cert_der,
            task,
        }
    }

    /// `wss://localhost:{port}/` URL — uses the loopback DNS name so the
    /// rustls server-name extension is exercised end-to-end (we want the
    /// pin lookup keyed on `"localhost"`, not on a raw IP).
    ///
    /// `wss://localhost:{port}/` URL.
    #[must_use]
    pub fn wss_url(&self) -> String {
        format!("wss://localhost:{}/", self.bound.port())
    }

    /// SPKI pin (SHA-256 over the cert's SubjectPublicKeyInfo) for the
    /// server's self-signed cert.
    ///
    /// SPKI pin for the mock cert.
    #[must_use]
    pub fn spki_pin(&self) -> SpkiPin {
        extract_spki_pin_from_cert_der(self.server_cert_der.as_ref())
            .expect("self-signed cert is valid DER")
    }
}

async fn handle_connection(
    tcp_stream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    behavior: MockBehavior,
    attempt: usize,
) {
    let tls_stream = match acceptor.accept(tcp_stream).await {
        Ok(s) => s,
        Err(_) => return,
    };

    // Drop the TLS connection right away when the test wants to simulate
    // transient failure for the reconnect path. The client side observes
    // either a TLS-half close or an EOF during HTTP upgrade — either maps to
    // `WsTransportError::Handshake` / `Io`, which is what the test asserts.
    if let MockBehavior::CloseFirstNThenStandard { fail_count, .. } = &behavior {
        if attempt < *fail_count {
            return;
        }
    }

    let upgrade_behavior = behavior.clone();
    let upgrade_callback = move |req: &Request, mut resp: Response| -> Result<Response, ErrorResponse> {
        let client_protos = req
            .headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let selected = match &upgrade_behavior {
            MockBehavior::RejectUpgrade => {
                let mut err = ErrorResponse::new(Some(
                    "mock gateway rejects upgrade per test policy".to_string(),
                ));
                *err.status_mut() = StatusCode::BAD_REQUEST;
                return Err(err);
            }
            MockBehavior::EchoSubprotocol(p) => p.to_string(),
            _ => match negotiate_first_supported(client_protos) {
                Some(p) => p.to_string(),
                None => {
                    let mut err = ErrorResponse::new(Some(format!(
                        "no supported subprotocol offered: {client_protos}"
                    )));
                    *err.status_mut() = StatusCode::BAD_REQUEST;
                    return Err(err);
                }
            },
        };
        let value = HeaderValue::from_str(&selected)
            .map_err(|_| ErrorResponse::new(Some("invalid subprotocol".to_string())))?;
        resp.headers_mut().insert("Sec-WebSocket-Protocol", value);
        Ok(resp)
    };

    let ws_stream = match accept_hdr_async(tls_stream, upgrade_callback).await {
        Ok(s) => s,
        Err(_) => return,
    };

    let (mut sink, mut stream) = ws_stream.split();
    let mut authenticated = matches!(&behavior, MockBehavior::EchoSubprotocol(_));
    let mut next_server_seq: u64 = 100;

    while let Some(item) = stream.next().await {
        let frame = match item {
            Ok(f) => f,
            Err(_) => return,
        };
        let bytes = match frame {
            WsMessage::Binary(b) => b,
            WsMessage::Close(_) => return,
            _ => continue,
        };
        let envelope = match proto::ClientEnvelope::decode(bytes.as_ref()) {
            Ok(e) => e,
            Err(_) => return,
        };
        let payload = match envelope.payload {
            Some(p) => p,
            None => continue,
        };
        let response = build_server_response(payload, &behavior, &mut authenticated, &mut next_server_seq);
        if let Some(resp_env) = response {
            let mut buf = Vec::with_capacity(resp_env.encoded_len());
            if resp_env.encode(&mut buf).is_err() {
                return;
            }
            if sink.send(WsMessage::Binary(buf.into())).await.is_err() {
                return;
            }
        }
    }
}

fn negotiate_first_supported(client_protos: &str) -> Option<&'static str> {
    for item in client_protos.split(',').map(str::trim) {
        if item.eq_ignore_ascii_case("umx.pb.v1") {
            return Some("umx.pb.v1");
        }
        if item.eq_ignore_ascii_case("umx.v1") {
            return Some("umx.v1");
        }
    }
    None
}

fn build_server_response(
    payload: proto::client_envelope::Payload,
    behavior: &MockBehavior,
    authenticated: &mut bool,
    next_seq: &mut u64,
) -> Option<proto::ServerEnvelope> {
    use proto::client_envelope::Payload as C;
    use proto::server_envelope::Payload as S;

    let seq = {
        let s = *next_seq;
        *next_seq = s.wrapping_add(1);
        s
    };

    let server_payload = match payload {
        C::Auth(a) => {
            let token_ok = match behavior_token_gate(behavior) {
                None => true,
                Some(expected) => a.token == expected,
            };
            if token_ok {
                *authenticated = true;
                S::AuthOk(proto::AuthOk {})
            } else {
                S::Error(proto::ErrorEnvelope {
                    code: "auth.invalid".to_string(),
                })
            }
        }
        C::Ping(p) => S::Pong(proto::ServerPong {
            client_ts_ms: p.client_ts_ms,
            server_ts_ms: now_unix_ms(),
        }),
        C::SendMessage(_) if !*authenticated => S::Error(proto::ErrorEnvelope {
            code: "auth.required".to_string(),
        }),
        C::SendMessage(_) => S::SendAck(proto::SendMessageAck {
            msg_id: format!("{:032x}", seq),
        }),
        C::DeliveryProbe(p) => S::DeliveryProbe(proto::DeliveryProbe {
            probe_id: p.probe_id,
            sent_ts_ms: p.sent_ts_ms,
        }),
        C::Presence(_) => return None,
        C::Close(_) => return None,
    };

    Some(proto::ServerEnvelope {
        seq,
        payload: Some(server_payload),
    })
}

fn behavior_token_gate(behavior: &MockBehavior) -> Option<&str> {
    match behavior {
        MockBehavior::Standard { accept_token } => accept_token.as_deref(),
        MockBehavior::CloseFirstNThenStandard { accept_token, .. } => accept_token.as_deref(),
        _ => None,
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build a rustls `ClientConfig` that:
///
/// - Speaks TLS 1.3 only.
/// - Wraps `expected_pin` with [`SpkiPinningVerifier`].
/// - Uses a permissive inner verifier (`AcceptAnyServerCert`) because the
///   mock cert is self-signed and would otherwise be rejected by the system
///   root store.
///
/// The pin enforcement still runs after the inner verifier returns success,
/// so tests that pass a wrong pin observe a rustls handshake failure exactly
/// like a production SPKI-mismatch event.
///
/// Build a rustls `ClientConfig` with the production SPKI pinning verifier
/// wrapped around a permissive inner verifier (self-signed cert acceptance).
#[must_use]
pub fn build_test_client_tls_config(
    server_host: &str,
    expected_pin: SpkiPin,
) -> Arc<RustlsClientConfig> {
    let mut pins = BTreeMap::new();
    pins.insert(server_host.to_string(), PinningConfig::single(expected_pin));
    let inner: Arc<dyn rustls::client::danger::ServerCertVerifier> =
        Arc::new(AcceptAnyServerCert);
    let pinning_verifier = SpkiPinningVerifier::new(inner, pins)
        .expect("SPKI pinning verifier accepts loopback host");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = RustlsClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 supported")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(pinning_verifier))
        .with_no_client_auth();
    Arc::new(cfg)
}

/// Permissive inner verifier — the SPKI-pin wrapper is the real gate; the
/// inner only needs to return success so the test cert (self-signed against
/// no root store) does not get rejected.
///
/// Permissive inner verifier — SPKI pinning is the real gate.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

/// Unused but typed import — the production `WebPkiClientVerifier` is the
/// real-world counterpart of [`AcceptAnyServerCert`] and lives here only so
/// future tests that need authenticated client certificates can refer to it
/// without searching the rustls crate. Marked `#[allow(dead_code)]` because
/// no current test wires client auth.
///
/// Unused typed reference to `WebPkiClientVerifier` for future client-auth
/// tests.
#[allow(dead_code)]
fn _client_verifier_phantom() -> Option<Arc<WebPkiClientVerifier>> {
    None
}
