// QUIC mock gateway test fixture. Carry-over к отдельной audit session.
// QUIC mock gateway test fixture. Carry-over to a dedicated audit session.
#![allow(unknown_lints)]
#![allow(require_dual_doc)]
//! quinn-based mock QUIC gateway, mirroring the shape of `mod.rs` (the
//! tokio-tungstenite WebSocket mock) for session 2 contract tests. Accepts
//! one QUIC connection at a time on a kernel-assigned loopback UDP port,
//! negotiates ALPN `umx-quic-v1`, and replies to length-delimited Protobuf
//! `ClientEnvelope`s on the first client-initiated bidirectional stream.
//!
//! ## Stream model
//!
//! The production backend uses **two** streams (control on stream 0, data on
//! stream 4) per
//! `rust_1mlrd/crates/gateway-svc/src/quic/stream_handler.rs:48`. This mock
//! accepts all envelope types on the **first** bidi stream it sees, which
//! matches the "stream-per-message backwards-compatibility fallback" mode
//! also implemented by the backend (`stream_handler.rs:11`). Session 3+
//! will split streams properly when facade methods route by payload
//! semantics; for now the simpler model exercises every wire-level
//! invariant we care about.
//!
//! ## Behaviours
//!
//! [`QuicMockBehavior`] mirrors the WebSocket [`super::MockBehavior`] enum
//! for symmetry — `Standard{accept_token}`, `RejectHandshake`,
//! `CloseAfterAccept`. The Reject variant aborts the connection with QUIC
//! transport error code 0x102 (CRYPTO_ERROR with TLS alert "internal_error"
//! per RFC 9001 §4.8); the Close variant lets the handshake complete and
//! then closes the connection cleanly, which the client observes as
//! [`QuicTransportError::Closed`].
//!
//! quinn-based mock QUIC gateway. Single bidi stream, ALPN `umx-quic-v1`,
//! length-delimited Protobuf envelopes.

#![allow(
    dead_code,
    reason = "test-only helpers; not every contract test uses every variant"
)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use prost::Message as ProstMessage;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig as RustlsClientConfig, ServerConfig as RustlsServerConfig, SignatureScheme,
};

use umbrella_client::transport::proto_ws as proto;
use umbrella_client::transport::{
    extract_spki_pin_from_cert_der, PinningConfig, SpkiPin, SpkiPinningVerifier, ALPN_UMX_QUIC_V1,
};

/// Behavioural knob mirroring [`super::MockBehavior`] for the QUIC mock.
///
/// Behavioural knob for the QUIC mock.
#[derive(Clone, Debug)]
pub enum QuicMockBehavior {
    /// ALPN negotiates `umx-quic-v1`, bidi stream accepts envelopes, auth
    /// gated by `accept_token`.
    /// Standard QUIC server.
    Standard {
        /// `Some(t)` accepts only token == t; `None` accepts any token.
        accept_token: Option<String>,
    },
    /// Server config offers ALPN `wrong-alpn-v1` so the client's
    /// `umx-quic-v1` is rejected during the TLS handshake.
    /// Server offers wrong ALPN — handshake fails.
    RejectAlpn,
    /// Server accepts ALPN, then immediately closes the connection with
    /// transport error code 0x0 (NO_ERROR per RFC 9000 §20.1) before any
    /// envelope round-trip. Used by the reconnect-after-failure test.
    /// Server accepts ALPN then drops the connection.
    CloseAfterAccept,
}

impl QuicMockBehavior {
    /// Permissive standard preset.
    ///
    /// Permissive standard preset.
    #[must_use]
    pub fn standard_any_token() -> Self {
        Self::Standard { accept_token: None }
    }
}

/// Handle to a running mock QUIC gateway. Dropping aborts the listener
/// task.
///
/// Handle to a running mock QUIC gateway.
pub struct QuicMockGateway {
    bound: SocketAddr,
    cert_der: CertificateDer<'static>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for QuicMockGateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl QuicMockGateway {
    /// Spawn a QUIC server on `127.0.0.1:0`. Self-signed cert is generated
    /// for `localhost`; SPKI is exposed via [`Self::spki_pin`].
    ///
    /// Spawn a QUIC server on a kernel-assigned loopback UDP port.
    pub async fn spawn(behavior: QuicMockBehavior) -> Self {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("rcgen self-signed cert for QUIC mock");
        let cert_der: CertificateDer<'static> = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

        let alpn_to_offer: Vec<Vec<u8>> = match &behavior {
            QuicMockBehavior::RejectAlpn => vec![b"wrong-alpn-v1".to_vec()],
            _ => vec![ALPN_UMX_QUIC_V1.to_vec()],
        };

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_cfg = RustlsServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("rustls TLS 1.3")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("server cert+key load");
        server_cfg.alpn_protocols = alpn_to_offer;

        let quic_server_cfg = quinn::crypto::rustls::QuicServerConfig::try_from(server_cfg)
            .expect("quinn server crypto");
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_cfg));

        let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
            .expect("quinn server bind");
        let bound = endpoint.local_addr().expect("quinn local_addr");

        let behavior_clone = behavior.clone();
        let task = tokio::spawn(async move {
            run_quic_server(endpoint, behavior_clone).await;
        });

        Self {
            bound,
            cert_der,
            task,
        }
    }

    /// UDP `SocketAddr` of the bound QUIC listener.
    ///
    /// UDP `SocketAddr` of the bound QUIC listener.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.bound
    }

    /// SNI hostname clients should pass (matches the cert's DNS SAN).
    ///
    /// SNI hostname clients should pass.
    #[must_use]
    pub fn server_name(&self) -> &'static str {
        "localhost"
    }

    /// SPKI pin for the mock cert (SHA-256 over SubjectPublicKeyInfo).
    ///
    /// SPKI pin for the mock cert.
    #[must_use]
    pub fn spki_pin(&self) -> SpkiPin {
        extract_spki_pin_from_cert_der(self.cert_der.as_ref())
            .expect("self-signed cert is valid DER")
    }
}

async fn run_quic_server(endpoint: quinn::Endpoint, behavior: QuicMockBehavior) {
    let attempt = Arc::new(AtomicUsize::new(0));
    while let Some(incoming) = endpoint.accept().await {
        let behavior = behavior.clone();
        let attempt = Arc::clone(&attempt);
        tokio::spawn(async move {
            let _n = attempt.fetch_add(1, Ordering::SeqCst);
            let connection = match incoming.await {
                Ok(c) => c,
                Err(_) => return,
            };

            if matches!(behavior, QuicMockBehavior::CloseAfterAccept) {
                connection.close(0u32.into(), b"mock close");
                return;
            }

            // Accept the first client-opened bidi stream and serve envelopes.
            let (send, recv) = match connection.accept_bi().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            serve_envelopes(send, recv, behavior).await;
        });
    }
}

async fn serve_envelopes(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    behavior: QuicMockBehavior,
) {
    let mut buf = BytesMut::with_capacity(4096);
    let mut authenticated = false;
    let mut next_server_seq: u64 = 100;

    loop {
        match recv.read_chunk(4096, true).await {
            Ok(Some(chunk)) => buf.extend_from_slice(&chunk.bytes),
            Ok(None) => return,
            Err(_) => return,
        }
        loop {
            let maybe_env = pop_length_delimited(&mut buf);
            match maybe_env {
                Some(Ok(envelope)) => {
                    let Some(payload) = envelope.payload else {
                        continue;
                    };
                    let seq = {
                        let s = next_server_seq;
                        next_server_seq = next_server_seq.wrapping_add(1);
                        s
                    };
                    let response =
                        build_server_response(payload, &behavior, &mut authenticated, seq);
                    if let Some(env) = response {
                        let mut out = Vec::with_capacity(env.encoded_len() + 10);
                        if env.encode_length_delimited(&mut out).is_err() {
                            return;
                        }
                        if send.write_all(&out).await.is_err() {
                            return;
                        }
                    }
                }
                Some(Err(())) => return,
                None => break,
            }
        }
    }
}

/// Returns `Some(Ok(env))` on a full frame, `Some(Err(()))` on a decode
/// failure (terminate connection), `None` if more bytes are needed.
fn pop_length_delimited(buf: &mut BytesMut) -> Option<Result<proto::ClientEnvelope, ()>> {
    let mut peek: &[u8] = buf.as_ref();
    let original_len = peek.len();
    let payload_len = match prost::encoding::decode_varint(&mut peek) {
        Ok(n) => n as usize,
        Err(_) => return None,
    };
    let prefix_len = original_len - peek.len();
    let total = prefix_len.checked_add(payload_len)?;
    if buf.len() < total {
        return None;
    }
    let payload = &buf[prefix_len..total];
    let envelope = match proto::ClientEnvelope::decode(payload) {
        Ok(e) => e,
        Err(_) => return Some(Err(())),
    };
    let _ = buf.split_to(total);
    Some(Ok(envelope))
}

fn build_server_response(
    payload: proto::client_envelope::Payload,
    behavior: &QuicMockBehavior,
    authenticated: &mut bool,
    seq: u64,
) -> Option<proto::ServerEnvelope> {
    use proto::client_envelope::Payload as C;
    use proto::server_envelope::Payload as S;

    let server_payload = match payload {
        C::Auth(a) => {
            let token_ok = match behavior {
                QuicMockBehavior::Standard { accept_token } => {
                    accept_token.as_deref().is_none_or(|t| a.token == t)
                }
                _ => true,
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
        C::Presence(_) | C::Close(_) => return None,
    };

    Some(proto::ServerEnvelope {
        seq,
        payload: Some(server_payload),
    })
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build a rustls `ClientConfig` for the QUIC contract tests — TLS 1.3 +
/// ALPN `umx-quic-v1` + `SpkiPinningVerifier` over a permissive inner
/// verifier (the mock cert is self-signed and would otherwise be rejected
/// by the system root store).
///
/// Build a rustls `ClientConfig` for QUIC contract tests with ALPN and
/// SPKI pinning around a permissive inner verifier.
#[must_use]
pub fn build_test_quic_client_tls(
    server_host: &str,
    expected_pin: SpkiPin,
) -> Arc<RustlsClientConfig> {
    let mut pins = std::collections::BTreeMap::new();
    pins.insert(server_host.to_string(), PinningConfig::single(expected_pin));
    let inner: Arc<dyn rustls::client::danger::ServerCertVerifier> = Arc::new(AcceptAnyServerCert);
    let pinning_verifier =
        SpkiPinningVerifier::new(inner, pins).expect("SPKI verifier for loopback");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = RustlsClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 supported")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(pinning_verifier))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN_UMX_QUIC_V1.to_vec()];
    Arc::new(cfg)
}

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
