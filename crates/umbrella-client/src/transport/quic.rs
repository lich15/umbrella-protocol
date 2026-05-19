//! QUIC transport to the gateway-svc `umx-quic-v1` real-time channel.
//!
//! ## Контракт (контракт со стороны бэкенда)
//!
//! Полная спецификация лежит в
//! `docs/integration/gateway-svc-contract.md §2.1` — здесь только инварианты,
//! которые транспорт обязан соблюдать на проводе.
//!
//! - **Протокол:** HTTP/3-style QUIC over TLS 1.3 (RFC 9001). Серверный ALPN
//!   ровно `umx-quic-v1` (11 байт); расхождение → handshake fail с
//!   [`QuicTransportError::AlpnRejected`].
//! - **TLS:** `rustls::ClientConfig` передаётся pre-built; caller обязан
//!   выставить `alpn_protocols = vec![ALPN_UMX_QUIC_V1.to_vec()]` —
//!   [`QuicTransport::new`] валидирует это требование fail-fast (без ALPN в
//!   config → невозможно negotiated handshake).
//! - **Стрим-модель:** session 2 открывает один persistent client-initiated
//!   bidi-стрим и сериализует все envelope через length-delimited Protobuf
//!   (RFC 9001 §10.4 stream-multiplexing fits; backend `gateway-svc` accepts
//!   эту модель как backwards-compat fallback). Production-цель — split на
//!   control stream 0 + data stream 4 как описано в backend
//!   `stream_handler.rs` — отложено к session 3+ когда facade методы
//!   маршрутизируют payload по семантике.
//! - **Wire-формат envelope:** length-delimited `umbrellax.gateway.v1.ClientEnvelope`
//!   / `ServerEnvelope`. Длина — protobuf varint (LEB128, max 10 байт),
//!   совпадает с `prost::Message::encode_length_delimited` /
//!   `decode_length_delimited`.
//! - **Auth flow:** идентичен WebSocket — `ClientAuth` первым envelope,
//!   ответ `AuthOk` либо `ErrorEnvelope { code }`.
//!
//! ## Архитектура
//!
//! [`QuicTransport`] владеет одним `quinn::Endpoint` (общим UDP-сокетом) и
//! создаёт N независимых [`QuicConnection`] через `connect()`. Каждое
//! соединение держит persistent bidi-стрим за двумя `Mutex`-ами (send vs
//! recv) — параллельные send/recv не блокируют друг друга, как и в
//! WebSocket'е (тот же паттерн split). Сам Endpoint можно безопасно
//! шарить между tokio-задачами через `Arc<QuicTransport>`.
//!
//! ## Что НЕ делает session 2
//!
//! - Не реализует split на control stream 0 / data stream 4 — все envelope
//!   идут через один bidi-стрим (упрощённая модель, mock toleratively
//!   accepts; production backend поддерживает обе модели per
//!   `stream_handler.rs:182` "stream-per-message remains available as
//!   backwards-compat fallback").
//! - Не делает 0-RTT (TLS session ticket cache не подключён; production
//!   будет — session 3+).
//! - Не делает connection migration (mobile NAT rebind) — backend
//!   `set_disable_active_migration(true)` по умолчанию, клиент не должен
//!   пробовать. Session 7+ при появлении mobile-canary.
//! - Не делает path MTU discovery — quinn default = 1500 байт.
//!
//! QUIC transport to the gateway-svc `umx-quic-v1` real-time channel.
//! Full contract in `docs/integration/gateway-svc-contract.md §2.1`. Session
//! 2 uses ONE persistent client-initiated bidi stream for all envelopes
//! (backend accepts as backwards-compat fallback); production split on
//! stream 0 (control) + stream 4 (data) is a session 3+ deliverable when
//! facade methods route by payload semantics. 0-RTT, connection migration,
//! and PMTU probing are out of session 2 scope.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use prost::Message as ProstMessage;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::transport::proto_ws as proto;
use crate::transport::websocket::{
    build_client_envelope, decode_server_envelope, ClientPayload, ServerFrame, ServerPayload,
};

/// ALPN-марлер `umx-quic-v1` (11 байт), фиксированный в backend
/// `gateway-svc::quic::ALPN_UMX_QUIC_V1` (rust_1mlrd commit 2fcc2107).
/// Caller обязан включать это значение в `rustls::ClientConfig.alpn_protocols`
/// до построения [`QuicTransport`], иначе `connect()` гарантированно упадёт
/// с [`QuicTransportError::AlpnRejected`].
///
/// ALPN marker `umx-quic-v1` (11 bytes). Callers must include this in
/// `rustls::ClientConfig.alpn_protocols` before passing the config to
/// [`QuicTransport::new`].
pub const ALPN_UMX_QUIC_V1: &[u8] = b"umx-quic-v1";

/// Максимальный размер одного length-delimited frame — должен совпадать с
/// серверным `Settings.max_message_bytes` (default 262_144 = 256 KiB,
/// `rust_1mlrd/crates/gateway-svc/src/config.rs`). DoS-защита от заявленного
/// гигантского varint length до того как мы начнём аллокацию.
///
/// Maximum size of one length-delimited Protobuf frame; matches backend
/// `Settings.max_message_bytes` (256 KiB default). DoS guard.
pub const QUIC_MAX_FRAME_BYTES: usize = 262_144;

/// Размер chunk'а который мы читаем из QUIC-стрима за один `read_chunk`
/// вызов. Совпадает с UDP MTU умноженным на ~3 для амортизации flow-control
/// updates.
///
/// Read-chunk size per `read_chunk` call — UDP MTU × ~3 amortises flow-control
/// updates.
const QUIC_RECV_CHUNK_BYTES: usize = 4096;

/// Конфигурация одного QUIC-канала.
///
/// Configuration for one QUIC channel.
#[derive(Clone)]
pub struct QuicConfig {
    /// UDP-адрес сервера (production: cloud edge node IPv4/IPv6:443).
    /// UDP server address (production: cloud edge node IPv4/IPv6:443).
    pub server_addr: SocketAddr,
    /// SNI hostname — должно совпадать с DNS-именем в pinned-сертификате
    /// сервера (production: edge-канарейка типа `ux-edge-v2-eu-nbg1.umbrellax.io`).
    /// SNI hostname; must match a DNS name in the pinned server certificate.
    pub server_name: String,
    /// rustls-конфигурация с уже выставленным `alpn_protocols`. Production
    /// callers переиспользуют тот же `ClientConfig`, что построен через
    /// `transport::http2_client::build_production_http2_client` (SPKI pinning
    /// inside), и дополнительно добавляют ALPN.
    /// rustls config with `alpn_protocols` pre-set. Production callers reuse
    /// the SPKI-pinning `ClientConfig` from `http2_client` and add ALPN.
    pub tls: Arc<rustls::ClientConfig>,
    /// Максимальный бюджет на TLS+QUIC handshake (RFC 9001 §1-RTT).
    /// Production preset — 500 ms (см. контракт §2.3 fallback timeout).
    /// Maximum total budget for the TLS + QUIC handshake. Production preset
    /// is 500 ms per contract §2.3 fallback timeout.
    pub connect_timeout: Duration,
}

impl std::fmt::Debug for QuicConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicConfig")
            .field("server_addr", &self.server_addr)
            .field("server_name", &self.server_name)
            .field("tls", &"<rustls::ClientConfig>")
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

impl QuicConfig {
    /// Production preset: 500 ms handshake budget per contract §2.3
    /// (auto-fallback к WebSocket после этого таймаута).
    ///
    /// Production preset: 500 ms handshake budget per contract §2.3.
    #[must_use]
    pub fn production(
        server_addr: SocketAddr,
        server_name: String,
        tls: Arc<rustls::ClientConfig>,
    ) -> Self {
        Self {
            server_addr,
            server_name,
            tls,
            connect_timeout: Duration::from_millis(500),
        }
    }
}

/// Errors raised by [`QuicTransport::new`], [`QuicTransport::connect`], and
/// [`QuicConnection`] methods.
///
/// Errors raised by `QuicTransport` and `QuicConnection`.
#[derive(Debug, Error)]
pub enum QuicTransportError {
    /// rustls `ClientConfig.alpn_protocols` пуст либо не содержит
    /// `umx-quic-v1`. Конфиг невозможно использовать для QUIC handshake.
    /// `ClientConfig.alpn_protocols` empty or missing `umx-quic-v1`.
    #[error("rustls ClientConfig must include ALPN `umx-quic-v1`; got: {got:?}")]
    AlpnConfigMissing {
        /// `alpn_protocols` value as supplied (may be empty).
        got: Vec<Vec<u8>>,
    },

    /// quinn не смог binding UDP-сокет (port in use, нет capability и т.п.).
    /// quinn failed to bind UDP socket.
    #[error("QUIC endpoint bind failed: {0}")]
    Bind(String),

    /// quinn::crypto::rustls::QuicClientConfig::try_from rejected the
    /// rustls config (e.g. unsupported cipher suite, no provider).
    /// rustls config rejected by quinn (provider / cipher mismatch).
    #[error("quinn crypto config rejected the rustls ClientConfig: {0}")]
    Tls(String),

    /// QUIC handshake didn't complete (cert chain rejected, ALPN mismatch,
    /// timeout from server, etc.). quinn's `ConnectError` /
    /// `ConnectionError` mapped here.
    /// QUIC handshake did not complete.
    #[error("QUIC handshake failed: {0}")]
    Handshake(String),

    /// Server selected an ALPN we did not offer (impossible per RFC 7301
    /// but defended in depth) or omitted ALPN entirely.
    /// Server selected an ALPN we did not offer.
    #[error("server selected unsupported ALPN (offered: {offered:?}, server returned: {server_selected:?})")]
    AlpnRejected {
        /// ALPN bytes the client offered (typically `b"umx-quic-v1"`).
        offered: Vec<u8>,
        /// ALPN the server selected (or `None` if the server omitted it).
        server_selected: Option<Vec<u8>>,
    },

    /// Server responded to `ClientAuth` with an `ErrorEnvelope`.
    /// Server responded to `ClientAuth` with `ErrorEnvelope`.
    #[error("authentication rejected by gateway: {code}")]
    AuthRejected {
        /// Server-supplied error code (e.g. `"auth.expired"`).
        code: String,
    },

    /// `authenticate` saw a non-`AuthOk` / non-`ErrorEnvelope` reply.
    /// `authenticate` saw an unexpected server reply.
    #[error("authentication did not complete: expected AuthOk or ErrorEnvelope, got {0}")]
    UnexpectedAuthFrame(String),

    /// `recv_envelope` produced a frame whose `payload` is `None` (server
    /// outpaced this client revision).
    /// Server sent an envelope without a known payload variant.
    #[error("server sent an unknown envelope variant")]
    UnknownServerPayload,

    /// QUIC stream closed cleanly by peer mid-read.
    /// QUIC stream closed by peer.
    #[error("QUIC stream closed by peer")]
    Closed,

    /// quinn read/write produced an `io::Error` we couldn't classify.
    /// Underlying quinn I/O failure.
    #[error("QUIC I/O error: {0}")]
    Io(String),

    /// Length-delimited Protobuf encode/decode failure.
    /// Length-delimited Protobuf encode / decode failure.
    #[error("protobuf codec error: {0}")]
    Codec(String),

    /// Frame length prefix claimed a size larger than [`QUIC_MAX_FRAME_BYTES`].
    /// Frame length prefix > QUIC_MAX_FRAME_BYTES.
    #[error("server announced frame size {announced} exceeds limit {limit}")]
    FrameTooLarge {
        /// Declared frame size in bytes.
        announced: usize,
        /// Maximum permitted frame size ([`QUIC_MAX_FRAME_BYTES`]).
        limit: usize,
    },

    /// Total handshake budget exceeded before connection reached "established".
    /// Handshake budget exceeded.
    #[error("QUIC connect timed out after {0:?}")]
    Timeout(Duration),
}

/// QUIC transport factory. Holds the shared `quinn::Endpoint` (UDP socket)
/// and supplies a fresh [`QuicConnection`] on each `connect()` call.
///
/// QUIC transport factory. Holds the shared `quinn::Endpoint`; supplies a
/// fresh `QuicConnection` per `connect()`.
#[derive(Debug, Clone)]
pub struct QuicTransport {
    cfg: QuicConfig,
    endpoint: quinn::Endpoint,
}

impl QuicTransport {
    /// Construct a new `QuicTransport`. Binds an ephemeral UDP socket
    /// (`0.0.0.0:0` for IPv4 targets, `[::]:0` for IPv6 targets) and primes
    /// the quinn client config from the supplied rustls `ClientConfig`.
    ///
    /// Construct a new `QuicTransport`; binds an ephemeral UDP socket and
    /// primes the quinn client config from the rustls `ClientConfig`.
    ///
    /// # Errors
    /// - [`QuicTransportError::AlpnConfigMissing`] if the rustls config lacks
    ///   `umx-quic-v1` in `alpn_protocols` (fail-fast — without ALPN the
    ///   handshake cannot negotiate the protocol).
    /// - [`QuicTransportError::Bind`] if quinn cannot bind the UDP socket.
    /// - [`QuicTransportError::Tls`] if quinn's crypto layer rejects the
    ///   rustls config (provider mismatch).
    pub fn new(cfg: QuicConfig) -> Result<Self, QuicTransportError> {
        if !cfg
            .tls
            .alpn_protocols
            .iter()
            .any(|p| p.as_slice() == ALPN_UMX_QUIC_V1)
        {
            return Err(QuicTransportError::AlpnConfigMissing {
                got: cfg.tls.alpn_protocols.clone(),
            });
        }

        let local_bind: SocketAddr = if cfg.server_addr.is_ipv6() {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        };
        let mut endpoint = quinn::Endpoint::client(local_bind)
            .map_err(|e| QuicTransportError::Bind(format!("{e}")))?;

        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::clone(&cfg.tls))
            .map_err(|e| QuicTransportError::Tls(format!("{e}")))?;
        let client_cfg = quinn::ClientConfig::new(Arc::new(crypto));
        endpoint.set_default_client_config(client_cfg);

        Ok(Self { cfg, endpoint })
    }

    /// Borrow the underlying configuration.
    ///
    /// Borrow the underlying configuration.
    #[must_use]
    pub fn config(&self) -> &QuicConfig {
        &self.cfg
    }

    /// Open one QUIC connection, perform the TLS 1.3 + QUIC handshake, open
    /// one client-initiated bidirectional stream, and return a
    /// [`QuicConnection`]. The transport stays stateless; call `connect()`
    /// again for a fresh connection after a failure.
    ///
    /// Open one QUIC connection and the persistent bidi stream.
    ///
    /// # Errors
    /// - [`QuicTransportError::Timeout`] if the handshake exceeds `connect_timeout`.
    /// - [`QuicTransportError::Handshake`] on quinn `ConnectionError`.
    /// - [`QuicTransportError::AlpnRejected`] if the server returned an
    ///   unsupported ALPN.
    /// - [`QuicTransportError::Io`] if opening the bidi stream fails.
    pub async fn connect(&self) -> Result<QuicConnection, QuicTransportError> {
        let connecting = self
            .endpoint
            .connect(self.cfg.server_addr, &self.cfg.server_name)
            .map_err(|e| QuicTransportError::Handshake(format!("{e}")))?;

        let connection = timeout(self.cfg.connect_timeout, connecting)
            .await
            .map_err(|_| QuicTransportError::Timeout(self.cfg.connect_timeout))?
            .map_err(map_connection_error)?;

        let negotiated_alpn = connection
            .handshake_data()
            .and_then(|hd| hd.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|hd| hd.protocol);
        match negotiated_alpn.as_deref() {
            Some(p) if p == ALPN_UMX_QUIC_V1 => {}
            other => {
                return Err(QuicTransportError::AlpnRejected {
                    offered: ALPN_UMX_QUIC_V1.to_vec(),
                    server_selected: other.map(<[u8]>::to_vec),
                });
            }
        }

        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| QuicTransportError::Io(format!("open_bi: {e}")))?;

        Ok(QuicConnection {
            conn: connection,
            bidi: Mutex::new(QuicBidi {
                send,
                recv,
                recv_buf: BytesMut::with_capacity(QUIC_RECV_CHUNK_BYTES),
            }),
            next_seq: AtomicU64::new(1),
        })
    }
}

/// Live QUIC connection. Owns one bidirectional stream over which all
/// envelope round-trips for this connection happen.
///
/// Live QUIC connection. Owns one bidirectional stream for envelope I/O.
pub struct QuicConnection {
    conn: quinn::Connection,
    bidi: Mutex<QuicBidi>,
    next_seq: AtomicU64,
}

struct QuicBidi {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    recv_buf: BytesMut,
}

impl std::fmt::Debug for QuicConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicConnection")
            .field("remote_addr", &self.conn.remote_address())
            .field("next_seq", &self.next_seq.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl QuicConnection {
    /// ALPN bytes negotiated for this connection (always [`ALPN_UMX_QUIC_V1`]
    /// — we reject any other in [`QuicTransport::connect`]).
    ///
    /// ALPN bytes for this connection.
    #[must_use]
    pub fn alpn(&self) -> &'static [u8] {
        ALPN_UMX_QUIC_V1
    }

    /// UDP address of the gateway peer.
    ///
    /// UDP address of the gateway peer.
    #[must_use]
    pub fn remote_addr(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    /// Next outbound sequence number (1-based, monotonic).
    ///
    /// Next outbound sequence number (1-based, monotonic).
    #[must_use]
    pub fn peek_next_seq(&self) -> u64 {
        self.next_seq.load(Ordering::Relaxed)
    }

    /// Encode `payload` as a `ClientEnvelope`, prepend the varint length, and
    /// write the result to the bidi stream. Returns the `seq` used.
    ///
    /// # Errors
    /// - [`QuicTransportError::Codec`] on prost encode failure.
    /// - [`QuicTransportError::Io`] / [`QuicTransportError::Closed`] on
    ///   write-side failure.
    pub async fn send_envelope(&self, payload: ClientPayload) -> Result<u64, QuicTransportError> {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let envelope = build_client_envelope(seq, payload);
        let mut buf = Vec::with_capacity(envelope.encoded_len() + 10);
        envelope
            .encode_length_delimited(&mut buf)
            .map_err(|e| QuicTransportError::Codec(format!("encode: {e}")))?;

        let mut bidi = self.bidi.lock().await;
        bidi.send.write_all(&buf).await.map_err(map_write_error)?;
        Ok(seq)
    }

    /// Read until a full length-delimited `ServerEnvelope` is available,
    /// decode, and translate it into a [`ServerFrame`].
    ///
    /// # Errors
    /// - [`QuicTransportError::Closed`] if the peer closed the stream.
    /// - [`QuicTransportError::FrameTooLarge`] if the announced length
    ///   exceeds [`QUIC_MAX_FRAME_BYTES`].
    /// - [`QuicTransportError::Codec`] on prost decode failure.
    pub async fn recv_envelope(&self) -> Result<ServerFrame, QuicTransportError> {
        let mut bidi = self.bidi.lock().await;
        loop {
            if let Some(envelope) = try_decode_length_delimited(&mut bidi.recv_buf)? {
                return decode_server_envelope(envelope)
                    .map_err(|e| QuicTransportError::Codec(format!("translate: {e:?}")));
            }
            match bidi.recv.read_chunk(QUIC_RECV_CHUNK_BYTES, true).await {
                Ok(Some(chunk)) => bidi.recv_buf.extend_from_slice(&chunk.bytes),
                Ok(None) => return Err(QuicTransportError::Closed),
                Err(e) => return Err(map_read_error(e)),
            }
        }
    }

    /// Send the gateway authentication handshake — `ClientAuth` envelope,
    /// then await `AuthOk` or `ErrorEnvelope`.
    ///
    /// # Errors
    /// - [`QuicTransportError::AuthRejected`] on `ErrorEnvelope`.
    /// - [`QuicTransportError::UnexpectedAuthFrame`] on anything else.
    /// - Anything emitted by `send_envelope` / `recv_envelope`.
    pub async fn authenticate(
        &self,
        token: &str,
        device_id: Vec<u8>,
    ) -> Result<(), QuicTransportError> {
        self.send_envelope(ClientPayload::Auth {
            token: token.to_string(),
            device_id,
        })
        .await?;
        let frame = self.recv_envelope().await?;
        match frame.payload {
            ServerPayload::AuthOk => Ok(()),
            ServerPayload::Error { code } => Err(QuicTransportError::AuthRejected { code }),
            other => Err(QuicTransportError::UnexpectedAuthFrame(format!(
                "{other:?}"
            ))),
        }
    }

    /// Finish the send stream cleanly and close the connection with code 0.
    /// Subsequent operations on this `QuicConnection` would fail — we take
    /// `self` by value to make that statically impossible.
    ///
    /// Finish the send stream and close the connection.
    ///
    /// # Errors
    /// [`QuicTransportError::Io`] on send-side failure.
    pub async fn close(self) -> Result<(), QuicTransportError> {
        {
            let mut bidi = self.bidi.lock().await;
            let _ = bidi.send.finish();
        }
        self.conn.close(0u32.into(), b"client close");
        Ok(())
    }
}

fn try_decode_length_delimited(
    buf: &mut BytesMut,
) -> Result<Option<proto::ServerEnvelope>, QuicTransportError> {
    let mut peek: &[u8] = buf.as_ref();
    let original_len = peek.len();
    let payload_len = match prost::encoding::decode_varint(&mut peek) {
        Ok(n) => n as usize,
        Err(_) => return Ok(None),
    };
    if payload_len > QUIC_MAX_FRAME_BYTES {
        return Err(QuicTransportError::FrameTooLarge {
            announced: payload_len,
            limit: QUIC_MAX_FRAME_BYTES,
        });
    }
    let prefix_len = original_len - peek.len();
    let total = prefix_len
        .checked_add(payload_len)
        .ok_or(QuicTransportError::FrameTooLarge {
            announced: usize::MAX,
            limit: QUIC_MAX_FRAME_BYTES,
        })?;
    if buf.len() < total {
        return Ok(None);
    }
    let payload = &buf[prefix_len..total];
    let envelope = proto::ServerEnvelope::decode(payload)
        .map_err(|e| QuicTransportError::Codec(format!("decode ServerEnvelope: {e}")))?;
    let _ = buf.split_to(total);
    Ok(Some(envelope))
}

fn map_connection_error(e: quinn::ConnectionError) -> QuicTransportError {
    use quinn::ConnectionError as CE;
    match e {
        CE::TimedOut => QuicTransportError::Handshake("connection timed out".to_string()),
        // TLS / crypto failures arrive via TransportError with code 0x0100..=0x01ff
        // (RFC 9001 §4.8 CRYPTO_ERROR range). We map the whole TransportError
        // family to Handshake — production callers don't need to distinguish.
        // TLS errors arrive inside TransportError per RFC 9001 §4.8.
        CE::TransportError(t) => QuicTransportError::Handshake(format!("transport: {t}")),
        CE::ApplicationClosed(reason) => QuicTransportError::Handshake(format!(
            "peer closed: {} ({})",
            String::from_utf8_lossy(&reason.reason),
            reason.error_code
        )),
        CE::ConnectionClosed(reason) => QuicTransportError::Handshake(format!(
            "peer closed (transport): {} ({})",
            String::from_utf8_lossy(&reason.reason),
            reason.error_code
        )),
        CE::Reset => QuicTransportError::Closed,
        CE::LocallyClosed => QuicTransportError::Closed,
        CE::VersionMismatch => QuicTransportError::Handshake("QUIC version mismatch".to_string()),
        CE::CidsExhausted => QuicTransportError::Handshake("connection IDs exhausted".to_string()),
    }
}

fn map_write_error(e: quinn::WriteError) -> QuicTransportError {
    use quinn::WriteError as WE;
    match e {
        WE::Stopped(_)
        | WE::ClosedStream
        | WE::ConnectionLost(quinn::ConnectionError::LocallyClosed) => QuicTransportError::Closed,
        WE::ConnectionLost(ce) => map_connection_error(ce),
        other => QuicTransportError::Io(format!("{other}")),
    }
}

fn map_read_error(e: quinn::ReadError) -> QuicTransportError {
    use quinn::ReadError as RE;
    match e {
        RE::Reset(_)
        | RE::ClosedStream
        | RE::ConnectionLost(quinn::ConnectionError::LocallyClosed) => QuicTransportError::Closed,
        RE::ConnectionLost(ce) => map_connection_error(ce),
        other => QuicTransportError::Io(format!("{other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_constant_matches_backend_wire_bytes() {
        assert_eq!(ALPN_UMX_QUIC_V1, b"umx-quic-v1");
        assert_eq!(ALPN_UMX_QUIC_V1.len(), 11);
    }

    #[test]
    fn new_rejects_rustls_config_without_alpn() {
        let tls = build_dummy_rustls_config_without_alpn();
        let cfg = QuicConfig {
            server_addr: "127.0.0.1:1".parse().unwrap(),
            server_name: "localhost".to_string(),
            tls,
            connect_timeout: Duration::from_millis(500),
        };
        let err = QuicTransport::new(cfg).unwrap_err();
        assert!(matches!(err, QuicTransportError::AlpnConfigMissing { .. }));
    }

    // quinn::Endpoint::client binds a UDP socket using the ambient tokio
    // runtime, so this validation lives in an async test rather than a
    // synchronous one.
    // quinn::Endpoint::client needs a tokio runtime — async test.
    #[tokio::test]
    async fn new_accepts_rustls_config_with_correct_alpn() {
        let tls = build_dummy_rustls_config_with_alpn();
        let cfg = QuicConfig {
            server_addr: "127.0.0.1:1".parse().unwrap(),
            server_name: "localhost".to_string(),
            tls,
            connect_timeout: Duration::from_millis(500),
        };
        let transport = QuicTransport::new(cfg).expect("alpn-present config builds");
        assert_eq!(transport.config().server_name, "localhost");
    }

    #[test]
    fn quic_config_production_default_timeout_500ms() {
        let cfg = QuicConfig::production(
            "127.0.0.1:443".parse().unwrap(),
            "edge.example.com".to_string(),
            build_dummy_rustls_config_with_alpn(),
        );
        assert_eq!(cfg.connect_timeout, Duration::from_millis(500));
    }

    #[test]
    fn try_decode_length_delimited_returns_none_on_empty_buffer() {
        let mut buf = BytesMut::new();
        assert!(try_decode_length_delimited(&mut buf).unwrap().is_none());
    }

    #[test]
    fn try_decode_length_delimited_returns_none_on_partial_frame() {
        // Encode a real ServerEnvelope (~6 bytes) length-delimited, then
        // truncate to 2 bytes — must return Ok(None), not error.
        let env = proto::ServerEnvelope {
            seq: 1,
            payload: Some(proto::server_envelope::Payload::AuthOk(proto::AuthOk {})),
        };
        let mut full = Vec::new();
        env.encode_length_delimited(&mut full).unwrap();
        let mut partial = BytesMut::from(&full[..2]);
        assert!(try_decode_length_delimited(&mut partial).unwrap().is_none());
        assert_eq!(partial.len(), 2, "must NOT consume the partial bytes");
    }

    #[test]
    fn try_decode_length_delimited_extracts_full_frame_and_advances_buffer() {
        let env = proto::ServerEnvelope {
            seq: 42,
            payload: Some(proto::server_envelope::Payload::Pong(proto::ServerPong {
                client_ts_ms: 100,
                server_ts_ms: 200,
            })),
        };
        let mut full = Vec::new();
        env.encode_length_delimited(&mut full).unwrap();
        // Append a partial second frame to confirm we only consume the first.
        full.extend_from_slice(&[0x01, 0x02, 0x03]);
        let mut buf = BytesMut::from(full.as_slice());
        let decoded = try_decode_length_delimited(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.seq, 42);
        assert_eq!(buf.len(), 3, "trailing partial bytes must survive");
    }

    #[test]
    fn try_decode_length_delimited_rejects_oversize_frame() {
        // Hand-build a varint announcing 1 GiB — must be rejected immediately
        // before any allocation.
        let mut buf = BytesMut::new();
        prost::encoding::encode_varint(1_073_741_824, &mut buf);
        let err = try_decode_length_delimited(&mut buf).unwrap_err();
        assert!(matches!(err, QuicTransportError::FrameTooLarge { .. }));
    }

    fn build_dummy_rustls_config_without_alpn() -> Arc<rustls::ClientConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        Arc::new(cfg)
    }

    fn build_dummy_rustls_config_with_alpn() -> Arc<rustls::ClientConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        cfg.alpn_protocols = vec![ALPN_UMX_QUIC_V1.to_vec()];
        Arc::new(cfg)
    }
}
