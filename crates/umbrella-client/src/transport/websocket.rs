//! WebSocket transport to the gateway-svc `umx.pb.v1` real-time channel.
//!
//! ## Контракт (контракт со стороны бэкенда)
//!
//! Полная спецификация лежит в
//! `docs/integration/gateway-svc-contract.md` — здесь только инварианты,
//! которые транспорт обязан соблюдать на проводе.
//!
//! - **Протокол:** WebSocket 13 (RFC 6455) over TLS 1.3 (RFC 8446); plaintext
//!   `ws://` допускается только в локальных контракт-тестах.
//! - **Sub-protocol:** клиент ОБЯЗАН прислать
//!   `Sec-WebSocket-Protocol: umx.pb.v1, umx.v1` (либо подмножество).
//!   Сервер выбирает первое из списка, которое поддерживает; canary —
//!   `umx.pb.v1` (Protobuf), legacy — `umx.v1` (MessagePack). Этот клиент
//!   поддерживает только Protobuf; если сервер выбирает MessagePack —
//!   считается рассогласованием контракта.
//! - **Wire-формат envelope:** `umbrellax.gateway.v1.ClientEnvelope` /
//!   `ServerEnvelope`, сериализованные `prost`-ом. Один Protobuf message =
//!   один WebSocket binary frame (`tungstenite::Message::Binary`).
//! - **Auth flow:** после открытия канала клиент шлёт `ClientAuth` первым
//!   envelope; ответ — либо `AuthOk`, либо `ErrorEnvelope { code }`.
//! - **TLS:** `rustls::ClientConfig` передаётся как обязательная единица
//!   конфигурации; production callers собирают его через
//!   `transport::http2_client::build_production_http2_client` так, что в нём
//!   уже зашит `SpkiPinningVerifier` с production-пинами.
//!
//! ## Архитектура
//!
//! [`WebSocketTransport`] — фабрика подключений: хранит конфигурацию и не
//! владеет I/O state'ом. `connect()` поднимает один tokio-tungstenite-канал и
//! возвращает [`WebSocketConnection`], владеющую двумя половинами потока
//! (`Sink`/`Stream`) за отдельными `Mutex`-ами — это даёт concurrent
//! send/recv без блокировок одного на другом, что необходимо для facade-
//! сессий 3 — 9 (push-сообщения сервера приходят асинхронно к send_message).
//!
//! ## Что НЕ делает session 1
//!
//! - Не реализует `AsyncUnwrapTransport` / `PostmanTransport` / `KtTransport`
//!   — эти trait'ы обслуживают другой контракт (HTTP/2 к Sealed Servers /
//!   blind-postman / kt-svc), а не gateway WebSocket envelope.
//! - Не делает автоматический reconnect: caller (facade в сессиях 3 — 9) решает,
//!   когда переподключаться (мы возвращаем `WsTransportError::Closed` /
//!   `Reset`, а decision о retry — на стороне facade). Контракт-тест
//!   `ws_reconnect_after_transient_failure` проверяет ровно этот сценарий:
//!   первый `connect()` падает, второй — успешен.
//! - Не делает heartbeat / WS-level ping (по умолчанию tungstenite отвечает
//!   на server-initiated Ping автоматически Pong-ом; application-level
//!   `ClientPing` / `ServerPong` envelope — explicit caller responsibility).
//!
//! WebSocket transport to the gateway-svc `umx.pb.v1` real-time channel.
//! Full contract lives in `docs/integration/gateway-svc-contract.md`; this
//! file only enforces the on-the-wire invariants. `WebSocketTransport` is a
//! configuration factory; `connect()` returns a `WebSocketConnection` that
//! owns the two split halves of the stream behind separate `Mutex`es so that
//! concurrent send/receive does not deadlock. Session 1 does not implement
//! `AsyncUnwrapTransport` / `PostmanTransport` / `KtTransport` (different
//! services), auto-reconnect (facade owns retry), or app-level heartbeat
//! (callers send `ClientPing` envelopes themselves).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::sink::SinkExt;
use futures_util::stream::{SplitSink, SplitStream, StreamExt};
use prost::Message as ProstMessage;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use crate::transport::proto_ws as proto;

/// Internal alias for the tokio-tungstenite stream type the client owns
/// post-handshake.
///
/// Internal alias for the post-handshake tokio-tungstenite stream type.
type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Internal alias for the writable half after `.split()`.
///
/// Internal alias for the writable half after `.split()`.
type WsSink = SplitSink<WsStream, WsMessage>;

/// Internal alias for the readable half after `.split()`.
///
/// Internal alias for the readable half after `.split()`.
type WsRecv = SplitStream<WsStream>;

/// Subprotocol the server selected during the HTTP 101 Upgrade handshake.
/// The set is closed; mirrors `gateway-svc::ws::protocol::WebSocketProtocol`
/// 1:1 so wire-format identifiers stay in lockstep across the two repos.
///
/// Subprotocol the server selected during the HTTP 101 Upgrade handshake.
/// Mirrors `gateway-svc::ws::protocol::WebSocketProtocol` 1:1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiatedSubprotocol {
    /// `umx.pb.v1` — Protobuf wire format (canary, current preferred).
    ProtobufV1,
    /// `umx.v1` — MessagePack wire format (legacy fallback). This client does
    /// NOT decode MessagePack frames; receiving it from the server flags a
    /// contract mismatch.
    MessagePackV1,
}

impl NegotiatedSubprotocol {
    /// Canonical wire string (lowercase per RFC 6455 §1.9).
    ///
    /// Canonical wire string (lowercase per RFC 6455 §1.9).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtobufV1 => "umx.pb.v1",
            Self::MessagePackV1 => "umx.v1",
        }
    }

    /// Case-insensitive parse from a server-echoed `Sec-WebSocket-Protocol`
    /// value. Returns `None` for unrecognised tokens.
    ///
    /// Case-insensitive parse from a server-echoed `Sec-WebSocket-Protocol`
    /// value. Returns `None` for unrecognised tokens.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.eq_ignore_ascii_case("umx.pb.v1") {
            Some(Self::ProtobufV1)
        } else if trimmed.eq_ignore_ascii_case("umx.v1") {
            Some(Self::MessagePackV1)
        } else {
            None
        }
    }
}

/// TLS configuration for the WebSocket transport.
///
/// TLS configuration for the WebSocket transport.
#[derive(Clone)]
pub enum WsTlsConfig {
    /// No TLS — only valid against `ws://` URLs used by local contract tests.
    /// Production builds construct their `WsConfig` from
    /// `ProductionHttp2Config`-style helpers that reject the plaintext path.
    ///
    /// No TLS — only valid against `ws://` URLs used by local contract tests.
    Plaintext,
    /// rustls `ClientConfig` containing the SPKI-pinning certificate verifier.
    /// Production callers reuse the same `ClientConfig` built via
    /// `transport::http2_client::build_production_http2_client`.
    ///
    /// rustls `ClientConfig` with the SPKI-pinning certificate verifier;
    /// production callers reuse the `ClientConfig` from `http2_client`.
    Rustls(Arc<rustls::ClientConfig>),
}

impl std::fmt::Debug for WsTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plaintext => f.write_str("WsTlsConfig::Plaintext"),
            Self::Rustls(_) => f.write_str("WsTlsConfig::Rustls(<rustls::ClientConfig>)"),
        }
    }
}

/// Configuration for opening one WebSocket connection.
///
/// Configuration for opening one WebSocket connection.
#[derive(Debug, Clone)]
pub struct WsConfig {
    /// `wss://host:port/path` (production) or `ws://host:port/path` (tests).
    pub url: String,
    /// Subprotocols offered in the client's `Sec-WebSocket-Protocol` header,
    /// in preference order. The first server-supported entry is selected.
    pub subprotocols: Vec<&'static str>,
    /// TLS strategy (plaintext for contract tests, rustls for production).
    pub tls: WsTlsConfig,
    /// Maximum total time budget for the handshake (TCP + TLS + HTTP 101).
    pub connect_timeout: Duration,
}

impl WsConfig {
    /// Production preset: offer both subprotocols (preferring Protobuf) with a
    /// 10-second handshake budget that absorbs typical mobile 3G latency
    /// without parking forever on a stuck NAT hairpin.
    ///
    /// Production preset: offer both subprotocols (Protobuf preferred), 10 s
    /// handshake budget tuned for mobile networks.
    #[must_use]
    pub fn production(url: String, tls: Arc<rustls::ClientConfig>) -> Self {
        Self {
            url,
            subprotocols: vec!["umx.pb.v1", "umx.v1"],
            tls: WsTlsConfig::Rustls(tls),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// Errors raised by [`WebSocketTransport::connect`] and
/// [`WebSocketConnection`] methods.
///
/// Errors raised by `WebSocketTransport::connect` and `WebSocketConnection`
/// methods.
#[derive(Debug, Error)]
pub enum WsTransportError {
    /// Url is not parseable / missing scheme / missing host.
    /// Url is not parseable / missing scheme / missing host.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// rustls / tokio-rustls handshake error (cert chain rejected, SPKI pin
    /// mismatch, ALPN mismatch on the underlying TLS link).
    /// rustls / tokio-rustls handshake error.
    #[error("TLS handshake failed: {0}")]
    Tls(String),

    /// HTTP 101 Upgrade exchange failed: malformed response, wrong
    /// `Sec-WebSocket-Accept`, server rejected upgrade.
    /// HTTP 101 Upgrade exchange failed.
    #[error("WebSocket handshake failed: {0}")]
    Handshake(String),

    /// Server selected a subprotocol that the client did not offer or that
    /// the client cannot decode (e.g. MessagePack frames against this
    /// Protobuf-only client).
    /// Server selected an unsupported subprotocol.
    #[error("server selected an unsupported subprotocol (offered: {offered:?}, server returned: {server_selected:?})")]
    SubprotocolRejected {
        /// Subprotocols the client offered.
        /// Subprotocols the client offered.
        offered: Vec<&'static str>,
        /// Value the server returned in `Sec-WebSocket-Protocol` (or `None`
        /// if the server omitted the header entirely).
        /// Value the server returned in `Sec-WebSocket-Protocol`.
        server_selected: Option<String>,
    },

    /// Server responded to `ClientAuth` with an `ErrorEnvelope`.
    /// Server responded to `ClientAuth` with an `ErrorEnvelope`.
    #[error("authentication rejected by gateway: {code}")]
    AuthRejected {
        /// Server-supplied code (e.g. `"auth.expired"`, `"auth.invalid"`).
        /// Server-supplied code.
        code: String,
    },

    /// Server replied to `ClientAuth` with something other than `AuthOk` or
    /// `ErrorEnvelope` — contract violation.
    /// Server replied to `ClientAuth` with an unexpected envelope.
    #[error("authentication did not complete: expected AuthOk or ErrorEnvelope, got {0}")]
    UnexpectedAuthFrame(String),

    /// `recv_envelope` produced an envelope that did not match any known
    /// payload variant (server outpacing this client revision).
    /// Server sent an unknown envelope variant.
    #[error("server sent an unknown envelope variant")]
    UnknownServerPayload,

    /// Connection closed by peer mid-stream.
    /// Connection closed by peer mid-stream.
    #[error("connection closed by peer")]
    Closed,

    /// Underlying TCP / TLS I/O failure.
    /// Underlying TCP / TLS I/O failure.
    #[error("I/O error: {0}")]
    Io(String),

    /// Prost encode / decode error on a `ClientEnvelope` / `ServerEnvelope`.
    /// Prost encode / decode error.
    #[error("protobuf codec error: {0}")]
    Codec(String),

    /// `connect_timeout` exceeded before HTTP 101 completed.
    /// `connect_timeout` exceeded.
    #[error("connect timed out after {0:?}")]
    Timeout(Duration),
}

/// One outbound envelope payload — convenience wrapper over the prost-generated
/// `client_envelope::Payload` `oneof`. Keeping a hand-written enum here makes
/// the facade API ergonomic without leaking the generated symbols outside the
/// `transport` module.
///
/// Outbound envelope payload — hand-written wrapper over the prost-generated
/// `client_envelope::Payload` `oneof`.
#[derive(Debug, Clone)]
pub enum ClientPayload {
    /// `ClientPing { client_ts_ms }` — RTT probe.
    Ping {
        /// Millisecond timestamp recorded by the client at send time.
        client_ts_ms: u64,
    },
    /// `ClientAuth { token, device_id }` — first envelope after handshake.
    Auth {
        /// Access JWT from `AuthService.Login` / `AuthService.RefreshToken`.
        token: String,
        /// Device identifier (SPEC-11 §4 device-family slot).
        device_id: Vec<u8>,
    },
    /// `PresenceUpdate { online }` — coarse presence beacon.
    Presence {
        /// `true` while the user has the chat in the foreground.
        online: bool,
    },
    /// `SendMessageRequest { to_user_id, ciphertext }` — opaque ciphertext
    /// blob (MLS application message / sealed-sender envelope) — gateway
    /// routes by `to_user_id` without decrypting.
    SendMessage {
        /// Recipient UserId.
        to_user_id: Vec<u8>,
        /// Encrypted payload.
        ciphertext: Vec<u8>,
    },
    /// `DeliveryProbe { probe_id, sent_ts_ms }` — delivery-liveness probe
    /// (echoed back by the peer's gateway when the message lands).
    DeliveryProbe {
        /// Opaque probe identifier.
        probe_id: Vec<u8>,
        /// Send-side millisecond timestamp.
        sent_ts_ms: u64,
    },
    /// `ClientClose` — graceful shutdown indicator (followed by WS Close
    /// frame).
    Close,
}

/// One inbound envelope payload — hand-written wrapper over the prost-
/// generated `server_envelope::Payload` `oneof`.
///
/// Inbound envelope payload — hand-written wrapper over the prost-generated
/// `server_envelope::Payload` `oneof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerPayload {
    /// `ServerPong { client_ts_ms, server_ts_ms }` — RTT probe answer.
    Pong {
        /// Echo of the client's `client_ts_ms` (correlates the probe).
        client_ts_ms: u64,
        /// Server-side timestamp at pong time.
        server_ts_ms: u64,
    },
    /// `SendMessageAck { msg_id }` — server-issued 16-byte (hex) message id.
    SendAck {
        /// Hex-encoded 16-byte message id.
        msg_id: String,
    },
    /// `AuthOk {}` — `ClientAuth` accepted.
    AuthOk,
    /// `ErrorEnvelope { code }` — server-side rejection (e.g. `"auth.expired"`).
    Error {
        /// Server-supplied error code.
        code: String,
    },
    /// `DeliveryProbe { probe_id, sent_ts_ms }` — peer-side delivery beacon.
    DeliveryProbe {
        /// Opaque probe id.
        probe_id: Vec<u8>,
        /// Sender-side timestamp.
        sent_ts_ms: u64,
    },
}

/// Wrapper bundling the inbound payload with the server-issued sequence
/// number (`ServerEnvelope.seq`).
///
/// Wrapper bundling the inbound payload with the server-issued sequence
/// number (`ServerEnvelope.seq`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFrame {
    /// `ServerEnvelope.seq` — server-issued sequence number; opaque to the
    /// client (gateway uses it for ack correlation only).
    pub seq: u64,
    /// Decoded payload.
    pub payload: ServerPayload,
}

/// WebSocket transport factory — does not own I/O state.
///
/// WebSocket transport factory — owns configuration, not I/O state.
#[derive(Debug, Clone)]
pub struct WebSocketTransport {
    cfg: WsConfig,
}

impl WebSocketTransport {
    /// Construct a new transport factory from configuration.
    ///
    /// Construct a new transport factory from configuration.
    #[must_use]
    pub fn new(cfg: WsConfig) -> Self {
        Self { cfg }
    }

    /// Borrow the underlying configuration (used by tests / diagnostics).
    ///
    /// Borrow the underlying configuration.
    #[must_use]
    pub fn config(&self) -> &WsConfig {
        &self.cfg
    }

    /// Open one WebSocket connection: TCP → TLS (if configured) → HTTP 101
    /// Upgrade → subprotocol negotiation. Returns a [`WebSocketConnection`]
    /// owning the post-handshake stream halves. The transport itself stays
    /// stateless — call `connect()` again to obtain a fresh connection (e.g.
    /// after `Closed` / `Reset`).
    ///
    /// Open one WebSocket connection. The transport stays stateless: call
    /// `connect()` again to obtain a fresh connection after a failure.
    ///
    /// # Errors
    /// - [`WsTransportError::InvalidUrl`] on parse failure.
    /// - [`WsTransportError::Tls`] on rustls / handshake failure.
    /// - [`WsTransportError::Handshake`] on HTTP 101 failure.
    /// - [`WsTransportError::SubprotocolRejected`] if the server selects an
    ///   unsupported subprotocol.
    /// - [`WsTransportError::Timeout`] if the budget expires.
    pub async fn connect(&self) -> Result<WebSocketConnection, WsTransportError> {
        let connector = tls_connector_from_config(&self.cfg.tls);
        let request = build_client_request(&self.cfg.url, &self.cfg.subprotocols)?;

        let handshake = tokio_tungstenite::connect_async_tls_with_config(
            request,
            None,
            false,
            Some(connector),
        );

        let (stream, response) = timeout(self.cfg.connect_timeout, handshake)
            .await
            .map_err(|_| WsTransportError::Timeout(self.cfg.connect_timeout))?
            .map_err(map_tungstenite_handshake_error)?;

        let negotiated = parse_negotiated_subprotocol(&self.cfg.subprotocols, response.headers())?;
        let (sink, recv) = stream.split();

        Ok(WebSocketConnection {
            sink: Mutex::new(sink),
            recv: Mutex::new(recv),
            negotiated,
            next_seq: AtomicU64::new(1),
        })
    }
}

/// A live WebSocket connection. Owns both halves of the split tungstenite
/// stream behind separate `Mutex`-es so that one task can call `recv_envelope`
/// concurrently with another calling `send_envelope` without contention.
///
/// A live WebSocket connection. Holds the split stream halves behind separate
/// mutexes so send and receive do not contend.
pub struct WebSocketConnection {
    sink: Mutex<WsSink>,
    recv: Mutex<WsRecv>,
    negotiated: NegotiatedSubprotocol,
    next_seq: AtomicU64,
}

impl std::fmt::Debug for WebSocketConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketConnection")
            .field("negotiated", &self.negotiated)
            .field("next_seq", &self.next_seq.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl WebSocketConnection {
    /// Subprotocol the server selected during HTTP 101.
    ///
    /// Subprotocol the server selected during HTTP 101.
    #[must_use]
    pub fn negotiated(&self) -> NegotiatedSubprotocol {
        self.negotiated
    }

    /// Next outbound sequence number (1-based, monotonic).
    ///
    /// Next outbound sequence number (1-based, monotonic).
    #[must_use]
    pub fn peek_next_seq(&self) -> u64 {
        self.next_seq.load(Ordering::Relaxed)
    }

    /// Encode `payload` into a `ClientEnvelope`, allocate the next sequence
    /// number, and write the resulting binary WebSocket frame. Returns the
    /// `seq` actually used.
    ///
    /// Encode `payload` into a `ClientEnvelope`, allocate the next sequence
    /// number, write the binary WebSocket frame, and return the used `seq`.
    ///
    /// # Errors
    /// - [`WsTransportError::Codec`] if prost encoding fails (cannot happen
    ///   for the bounded types in this protocol — kept for completeness).
    /// - [`WsTransportError::Io`] / [`WsTransportError::Closed`] on
    ///   send-side I/O failure.
    pub async fn send_envelope(
        &self,
        payload: ClientPayload,
    ) -> Result<u64, WsTransportError> {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let envelope = build_client_envelope(seq, payload);
        let mut buf = Vec::with_capacity(envelope.encoded_len());
        envelope
            .encode(&mut buf)
            .map_err(|e| WsTransportError::Codec(format!("encode ClientEnvelope: {e}")))?;
        let frame = WsMessage::Binary(buf.into());

        let mut sink = self.sink.lock().await;
        sink.send(frame).await.map_err(map_tungstenite_io_error)?;
        Ok(seq)
    }

    /// Block until one `ServerEnvelope` arrives, decode and translate it into
    /// the high-level [`ServerFrame`]. WS-level control frames (Ping → auto
    /// Pong, Close, Pong) are filtered out and not surfaced to the caller;
    /// `recv_envelope` returns only application-level envelopes.
    ///
    /// Block until one `ServerEnvelope` arrives, decode and translate it.
    /// WS-level control frames are filtered out.
    ///
    /// # Errors
    /// - [`WsTransportError::Closed`] if the peer closed cleanly.
    /// - [`WsTransportError::Codec`] on prost decode failure.
    /// - [`WsTransportError::UnknownServerPayload`] if the envelope lacks
    ///   a known payload variant.
    /// - [`WsTransportError::Io`] on underlying transport failure.
    pub async fn recv_envelope(&self) -> Result<ServerFrame, WsTransportError> {
        let mut recv = self.recv.lock().await;
        loop {
            let frame = match recv.next().await {
                Some(Ok(frame)) => frame,
                Some(Err(e)) => return Err(map_tungstenite_io_error(e)),
                None => return Err(WsTransportError::Closed),
            };
            match frame {
                WsMessage::Binary(bytes) => {
                    let envelope = proto::ServerEnvelope::decode(bytes.as_ref())
                        .map_err(|e| WsTransportError::Codec(format!("decode ServerEnvelope: {e}")))?;
                    return decode_server_envelope(envelope);
                }
                WsMessage::Text(t) => {
                    return Err(WsTransportError::Codec(format!(
                        "expected binary Protobuf frame, got text frame: {t}"
                    )));
                }
                WsMessage::Close(_) => return Err(WsTransportError::Closed),
                WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Frame(_) => {
                    // tungstenite handles Ping/Pong control frames internally;
                    // raw Frame variant should not appear via the high-level
                    // stream API. Loop and read the next message.
                    continue;
                }
            }
        }
    }

    /// Run the gateway-svc authentication handshake: send `ClientAuth`, await
    /// the next `ServerEnvelope`, and require it to be `AuthOk`. Any other
    /// envelope is mapped to [`WsTransportError::AuthRejected`] (if
    /// `ErrorEnvelope`) or [`WsTransportError::UnexpectedAuthFrame`].
    ///
    /// Run the authentication handshake: send `ClientAuth`, await `AuthOk` or
    /// `ErrorEnvelope`.
    ///
    /// # Errors
    /// - [`WsTransportError::AuthRejected`] on `ErrorEnvelope`.
    /// - [`WsTransportError::UnexpectedAuthFrame`] on anything else.
    /// - Anything that `send_envelope` / `recv_envelope` may emit.
    pub async fn authenticate(
        &self,
        token: &str,
        device_id: Vec<u8>,
    ) -> Result<(), WsTransportError> {
        self.send_envelope(ClientPayload::Auth {
            token: token.to_string(),
            device_id,
        })
        .await?;
        let frame = self.recv_envelope().await?;
        match frame.payload {
            ServerPayload::AuthOk => Ok(()),
            ServerPayload::Error { code } => Err(WsTransportError::AuthRejected { code }),
            other => Err(WsTransportError::UnexpectedAuthFrame(format!("{other:?}"))),
        }
    }

    /// Send the WebSocket close frame and consume the connection. Subsequent
    /// `send_envelope` / `recv_envelope` calls on this same value would
    /// fail with `Closed`; we take `self` by value to make that statically
    /// impossible.
    ///
    /// Send the WebSocket close frame and consume the connection.
    ///
    /// # Errors
    /// [`WsTransportError::Io`] on send failure (the peer is already gone).
    pub async fn close(self) -> Result<(), WsTransportError> {
        let mut sink = self.sink.lock().await;
        sink.close().await.map_err(map_tungstenite_io_error)
    }
}

fn tls_connector_from_config(tls: &WsTlsConfig) -> Connector {
    match tls {
        WsTlsConfig::Plaintext => Connector::Plain,
        WsTlsConfig::Rustls(cfg) => Connector::Rustls(Arc::clone(cfg)),
    }
}

fn build_client_request(
    url: &str,
    subprotocols: &[&'static str],
) -> Result<tokio_tungstenite::tungstenite::handshake::client::Request, WsTransportError> {
    let mut request = url
        .into_client_request()
        .map_err(|e| WsTransportError::InvalidUrl(format!("{url}: {e}")))?;
    let header_value = subprotocols.join(", ");
    let value = HeaderValue::from_str(&header_value).map_err(|e| {
        WsTransportError::InvalidUrl(format!("invalid Sec-WebSocket-Protocol value: {e}"))
    })?;
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", value);
    Ok(request)
}

fn parse_negotiated_subprotocol(
    offered: &[&'static str],
    headers: &tokio_tungstenite::tungstenite::http::HeaderMap,
) -> Result<NegotiatedSubprotocol, WsTransportError> {
    let raw = headers
        .get("Sec-WebSocket-Protocol")
        .and_then(|v| v.to_str().ok());
    match raw.and_then(NegotiatedSubprotocol::parse) {
        Some(p) if offered.iter().any(|o| o.eq_ignore_ascii_case(p.as_str())) => Ok(p),
        Some(_) | None => Err(WsTransportError::SubprotocolRejected {
            offered: offered.to_vec(),
            server_selected: raw.map(str::to_string),
        }),
    }
}

fn build_client_envelope(seq: u64, payload: ClientPayload) -> proto::ClientEnvelope {
    use proto::client_envelope::Payload;
    let payload = Some(match payload {
        ClientPayload::Ping { client_ts_ms } => Payload::Ping(proto::ClientPing { client_ts_ms }),
        ClientPayload::Auth { token, device_id } => {
            Payload::Auth(proto::ClientAuth { token, device_id })
        }
        ClientPayload::Presence { online } => {
            Payload::Presence(proto::PresenceUpdate { online })
        }
        ClientPayload::SendMessage {
            to_user_id,
            ciphertext,
        } => Payload::SendMessage(proto::SendMessageRequest {
            to_user_id,
            ciphertext,
        }),
        ClientPayload::DeliveryProbe {
            probe_id,
            sent_ts_ms,
        } => Payload::DeliveryProbe(proto::DeliveryProbe {
            probe_id,
            sent_ts_ms,
        }),
        ClientPayload::Close => Payload::Close(proto::ClientClose {}),
    });
    proto::ClientEnvelope { seq, payload }
}

fn decode_server_envelope(env: proto::ServerEnvelope) -> Result<ServerFrame, WsTransportError> {
    use proto::server_envelope::Payload;
    let seq = env.seq;
    let payload = env.payload.ok_or(WsTransportError::UnknownServerPayload)?;
    let translated = match payload {
        Payload::Pong(p) => ServerPayload::Pong {
            client_ts_ms: p.client_ts_ms,
            server_ts_ms: p.server_ts_ms,
        },
        Payload::SendAck(a) => ServerPayload::SendAck { msg_id: a.msg_id },
        Payload::AuthOk(_) => ServerPayload::AuthOk,
        Payload::Error(e) => ServerPayload::Error { code: e.code },
        Payload::DeliveryProbe(p) => ServerPayload::DeliveryProbe {
            probe_id: p.probe_id,
            sent_ts_ms: p.sent_ts_ms,
        },
    };
    Ok(ServerFrame {
        seq,
        payload: translated,
    })
}

fn map_tungstenite_handshake_error(
    e: tokio_tungstenite::tungstenite::Error,
) -> WsTransportError {
    use tokio_tungstenite::tungstenite::Error as TE;
    match e {
        TE::Tls(t) => WsTransportError::Tls(format!("{t}")),
        TE::Url(u) => WsTransportError::InvalidUrl(format!("{u}")),
        TE::Http(resp) => WsTransportError::Handshake(format!(
            "server responded {} (expected 101)",
            resp.status()
        )),
        TE::HttpFormat(f) => WsTransportError::Handshake(format!("HTTP format: {f}")),
        TE::Protocol(p) => WsTransportError::Handshake(format!("protocol: {p}")),
        TE::Io(io) => WsTransportError::Io(format!("{io}")),
        other => WsTransportError::Handshake(format!("{other}")),
    }
}

fn map_tungstenite_io_error(e: tokio_tungstenite::tungstenite::Error) -> WsTransportError {
    use tokio_tungstenite::tungstenite::Error as TE;
    match e {
        TE::ConnectionClosed | TE::AlreadyClosed => WsTransportError::Closed,
        TE::Io(io) => WsTransportError::Io(format!("{io}")),
        TE::Tls(t) => WsTransportError::Tls(format!("{t}")),
        other => WsTransportError::Io(format!("{other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiated_subprotocol_as_str_matches_backend_wire_strings() {
        assert_eq!(NegotiatedSubprotocol::ProtobufV1.as_str(), "umx.pb.v1");
        assert_eq!(NegotiatedSubprotocol::MessagePackV1.as_str(), "umx.v1");
    }

    #[test]
    fn negotiated_subprotocol_parse_is_case_insensitive() {
        assert_eq!(
            NegotiatedSubprotocol::parse("UMX.PB.V1"),
            Some(NegotiatedSubprotocol::ProtobufV1)
        );
        assert_eq!(
            NegotiatedSubprotocol::parse("  umx.v1  "),
            Some(NegotiatedSubprotocol::MessagePackV1)
        );
        assert_eq!(NegotiatedSubprotocol::parse("legacy.v0"), None);
    }

    #[test]
    fn ws_config_production_uses_protobuf_first_and_10_s_timeout() {
        // Reuse the existing test ClientConfig builder pattern; the actual
        // values used here are dummy — we are only checking knob defaults.
        let dummy_tls = build_dummy_rustls_config();
        let cfg = WsConfig::production("wss://gw.example.com:8443/ws".into(), dummy_tls);
        assert_eq!(cfg.subprotocols, vec!["umx.pb.v1", "umx.v1"]);
        assert_eq!(cfg.connect_timeout, Duration::from_secs(10));
        assert!(matches!(cfg.tls, WsTlsConfig::Rustls(_)));
    }

    #[test]
    fn parse_negotiated_subprotocol_accepts_offered_protobuf() {
        let mut headers = tokio_tungstenite::tungstenite::http::HeaderMap::new();
        headers.insert("Sec-WebSocket-Protocol", HeaderValue::from_static("umx.pb.v1"));
        let offered = &["umx.pb.v1", "umx.v1"];
        let p = parse_negotiated_subprotocol(offered, &headers).unwrap();
        assert_eq!(p, NegotiatedSubprotocol::ProtobufV1);
    }

    #[test]
    fn parse_negotiated_subprotocol_rejects_not_offered() {
        let mut headers = tokio_tungstenite::tungstenite::http::HeaderMap::new();
        headers.insert("Sec-WebSocket-Protocol", HeaderValue::from_static("umx.v1"));
        // Client offered ONLY ProtobufV1; server picking umx.v1 violates RFC 6455 §4.2.2.
        let offered = &["umx.pb.v1"];
        let err = parse_negotiated_subprotocol(offered, &headers).unwrap_err();
        match err {
            WsTransportError::SubprotocolRejected { server_selected, .. } => {
                assert_eq!(server_selected, Some("umx.v1".to_string()));
            }
            other => panic!("expected SubprotocolRejected, got {other:?}"),
        }
    }

    #[test]
    fn parse_negotiated_subprotocol_rejects_missing_header() {
        let headers = tokio_tungstenite::tungstenite::http::HeaderMap::new();
        let offered = &["umx.pb.v1"];
        let err = parse_negotiated_subprotocol(offered, &headers).unwrap_err();
        match err {
            WsTransportError::SubprotocolRejected { server_selected, .. } => {
                assert_eq!(server_selected, None);
            }
            other => panic!("expected SubprotocolRejected, got {other:?}"),
        }
    }

    #[test]
    fn build_client_envelope_round_trips_through_prost_encode_decode() {
        let env = build_client_envelope(
            7,
            ClientPayload::SendMessage {
                to_user_id: vec![1, 2, 3, 4],
                ciphertext: vec![0xAA; 32],
            },
        );
        let mut buf = Vec::with_capacity(env.encoded_len());
        env.encode(&mut buf).unwrap();
        let back = proto::ClientEnvelope::decode(buf.as_slice()).unwrap();
        assert_eq!(back.seq, 7);
        match back.payload.unwrap() {
            proto::client_envelope::Payload::SendMessage(m) => {
                assert_eq!(m.to_user_id, vec![1, 2, 3, 4]);
                assert_eq!(m.ciphertext, vec![0xAA; 32]);
            }
            other => panic!("expected SendMessage, got {other:?}"),
        }
    }

    fn build_dummy_rustls_config() -> Arc<rustls::ClientConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        Arc::new(cfg)
    }
}
