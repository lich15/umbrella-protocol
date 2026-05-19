//! Unified gateway transport that prefers QUIC (UDP 443, ALPN `umx-quic-v1`)
//! and falls back to WebSocket (TCP 8443, subprotocol `umx.pb.v1`).
//!
//! ## Зачем нужен auto-fallback
//!
//! Контракт §2.3 (`docs/integration/gateway-svc-contract.md`): «client SHOULD
//! attempt QUIC first, falling back to WebSocket when QUIC is blocked
//! (corporate firewalls, certain mobile carriers in restrictive
//! jurisdictions). Suggested fallback timeout: 500 ms». В странах с DPI на
//! UDP 443 (Россия / Китай / Иран) QUIC handshake надёжно фейлится; WebSocket
//! поверх TLS 1.3 на TCP 8443 проходит через те же DPI gates что HTTPS, и
//! даёт работающий fallback path. Логика выбора живёт здесь, в
//! [`GatewayTransport::connect`], а не на стороне facade — facade обращается
//! к единому [`GatewayConnection`] без знания про конкретный wire.
//!
//! ## Архитектура
//!
//! - [`GatewayTransport`] — фабрика подключений с двумя независимыми
//!   sub-транспортами. QUIC всегда опционален (mobile без QUIC support);
//!   WebSocket — обязательный fallback.
//! - [`GatewayConnection`] — enum-dispatch с двумя вариантами `Quic` и
//!   `WebSocket`. Public API (`send_envelope`, `recv_envelope`,
//!   `authenticate`, `close`) делегирует во внутреннюю реализацию.
//! - [`NegotiatedTransport`] возвращается caller'у через
//!   [`GatewayConnection::negotiated`] — facade использует это для
//!   диагностики и Prometheus-метки `transport=quic|ws`.
//! - [`GatewayTransportError`] — unified error enum; QUIC / WS варианты
//!   сохраняют оригинальную причину для логирования.
//!
//! ## Что НЕ делает session 2
//!
//! - Не делает Happy Eyeballs (parallel QUIC + WS handshake racing per
//!   RFC 8305). Session 2 — strict sequential: QUIC сначала, WS только при
//!   фейле. Parallel racing — оптимизация которая может прятать DPI
//!   detection (DPI может задерживать QUIC handshake ровно настолько, чтобы
//!   уровень pinged, а параллельный WS уже succeeded). Sequential — четкие
//!   границы failure-mode для logging.
//! - Не делает sticky transport selection (`last_good = quic` cache между
//!   соединениями). Каждый connect независим, фейл одного не отключает
//!   QUIC попытки на следующих. Session 7+ если будет mobile-canary с
//!   intermittent UDP-loss.
//!
//! Unified gateway transport — prefers QUIC, falls back to WebSocket. The
//! fallback decision lives in `GatewayTransport::connect`; facade callers
//! consume the enum-dispatch `GatewayConnection` agnostic of the wire choice.

use std::time::Duration;

use thiserror::Error;

use crate::transport::quic::{QuicConnection, QuicTransport, QuicTransportError};
use crate::transport::websocket::{
    ClientPayload, NegotiatedSubprotocol, ServerFrame, WebSocketConnection, WebSocketTransport,
    WsTransportError,
};

/// Selected transport for an established [`GatewayConnection`]. Returned by
/// [`GatewayConnection::negotiated`] — facade callers use this for metrics
/// label `transport=quic|ws` and for diagnostic logging.
///
/// Selected transport for an established `GatewayConnection`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiatedTransport {
    /// QUIC over UDP. ALPN was negotiated as `umx-quic-v1`.
    /// QUIC over UDP with ALPN `umx-quic-v1`.
    Quic,
    /// WebSocket over TLS over TCP, with the listed subprotocol.
    /// WebSocket over TLS over TCP with the listed subprotocol.
    WebSocket(NegotiatedSubprotocol),
}

impl NegotiatedTransport {
    /// Short metric label for Prometheus / OTel attribution
    /// (`"quic"` / `"ws-pb"` / `"ws-mpack"`).
    ///
    /// Short metric label for Prometheus / OTel attribution.
    #[must_use]
    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::Quic => "quic",
            Self::WebSocket(NegotiatedSubprotocol::ProtobufV1) => "ws-pb",
            Self::WebSocket(NegotiatedSubprotocol::MessagePackV1) => "ws-mpack",
        }
    }
}

/// Unified error type for the gateway transport. QUIC failures observed
/// during the fallback path are surfaced as
/// [`GatewayTransportError::BothFailed`] alongside the eventual WebSocket
/// failure so operators can attribute outages to one or both wires.
///
/// Unified gateway error type; preserves both wire-level errors when both
/// QUIC and WebSocket fail.
#[derive(Debug, Error)]
pub enum GatewayTransportError {
    /// QUIC-side failure (only surfaced for the variant where the QUIC arm
    /// failed and WebSocket was not attempted, e.g. operations on an already-
    /// connected QUIC GatewayConnection).
    /// QUIC failure on an already-connected QUIC connection.
    #[error("quic: {0}")]
    Quic(#[from] QuicTransportError),

    /// WebSocket-side failure on an already-connected WebSocket
    /// `GatewayConnection`, or the fallback case with no QUIC attempt
    /// configured.
    /// WebSocket failure on an already-connected WS connection or fallback.
    #[error("websocket: {0}")]
    WebSocket(#[from] WsTransportError),

    /// Both wires failed during a fallback `connect()`. Each side's
    /// underlying error is preserved so the operator can correlate outages
    /// (e.g. UDP block + TCP block both observed on the same path).
    /// Both QUIC and WebSocket failed during fallback connect.
    #[error("both transports failed; quic={quic}, websocket={websocket}")]
    BothFailed {
        /// QUIC-side failure observed before fallback.
        quic: QuicTransportError,
        /// WebSocket-side failure observed after fallback.
        websocket: WsTransportError,
    },
}

/// Unified gateway transport factory. Holds one optional [`QuicTransport`]
/// and one [`WebSocketTransport`]; `connect()` picks the wire per
/// `auto_fallback` policy.
///
/// Unified gateway transport factory: optional QUIC + WebSocket fallback.
#[derive(Clone, Debug)]
pub struct GatewayTransport {
    quic: Option<QuicTransport>,
    websocket: WebSocketTransport,
}

impl GatewayTransport {
    /// Build a gateway transport with QUIC preferred and WebSocket as
    /// fallback. When `quic` is `None`, `connect()` skips straight to the
    /// WebSocket path (useful for clients on platforms where UDP egress is
    /// permanently blocked).
    ///
    /// Build a gateway transport with optional QUIC preference + WebSocket
    /// fallback.
    #[must_use]
    pub fn new(quic: Option<QuicTransport>, websocket: WebSocketTransport) -> Self {
        Self { quic, websocket }
    }

    /// Borrow the underlying WebSocket transport (used by tests and by
    /// facades that need direct access to the WebSocket-specific config).
    ///
    /// Borrow the underlying WebSocket transport.
    #[must_use]
    pub fn websocket(&self) -> &WebSocketTransport {
        &self.websocket
    }

    /// Borrow the underlying QUIC transport, if any.
    ///
    /// Borrow the underlying QUIC transport, if any.
    #[must_use]
    pub fn quic(&self) -> Option<&QuicTransport> {
        self.quic.as_ref()
    }

    /// Open one gateway connection per the auto-fallback policy:
    ///
    /// 1. If `quic` is configured, attempt the QUIC handshake within its own
    ///    `QuicConfig.connect_timeout` budget (default 500 ms per contract
    ///    §2.3). On success — return [`GatewayConnection::Quic`].
    /// 2. Otherwise, attempt the WebSocket handshake within its own
    ///    `WsConfig.connect_timeout` budget. On success — return
    ///    [`GatewayConnection::WebSocket`].
    /// 3. If both fail, return [`GatewayTransportError::BothFailed`] with
    ///    each wire's error preserved.
    ///
    /// Open one gateway connection with QUIC-first fallback.
    ///
    /// # Errors
    /// - [`GatewayTransportError::BothFailed`] when QUIC and WS both fail.
    /// - [`GatewayTransportError::WebSocket`] when only WS is configured and
    ///   it fails.
    pub async fn connect(&self) -> Result<GatewayConnection, GatewayTransportError> {
        let quic_err = if let Some(quic) = &self.quic {
            match quic.connect().await {
                Ok(conn) => return Ok(GatewayConnection::Quic(conn)),
                Err(e) => Some(e),
            }
        } else {
            None
        };

        match self.websocket.connect().await {
            Ok(conn) => Ok(GatewayConnection::WebSocket(conn)),
            Err(ws_err) => match quic_err {
                Some(quic) => Err(GatewayTransportError::BothFailed {
                    quic,
                    websocket: ws_err,
                }),
                None => Err(GatewayTransportError::WebSocket(ws_err)),
            },
        }
    }
}

/// Live gateway connection — enum dispatch between the two underlying
/// transports. Public API mirrors the per-transport surface; facade callers
/// stay wire-agnostic.
///
/// Live gateway connection (enum-dispatch over QUIC / WebSocket).
#[derive(Debug)]
pub enum GatewayConnection {
    /// QUIC-backed connection. Holds the `quinn::Connection` + bidi stream.
    Quic(QuicConnection),
    /// WebSocket-backed connection. Holds the split tungstenite stream.
    WebSocket(WebSocketConnection),
}

impl GatewayConnection {
    /// Which transport this connection rides on top of.
    ///
    /// Which transport this connection rides on top of.
    #[must_use]
    pub fn negotiated(&self) -> NegotiatedTransport {
        match self {
            Self::Quic(_) => NegotiatedTransport::Quic,
            Self::WebSocket(conn) => NegotiatedTransport::WebSocket(conn.negotiated()),
        }
    }

    /// True iff the underlying transport is QUIC. Convenience for facade
    /// callers that just want a yes/no answer without unpacking the enum.
    ///
    /// True iff QUIC.
    #[must_use]
    pub const fn is_quic(&self) -> bool {
        matches!(self, Self::Quic(_))
    }

    /// Authenticate via the underlying transport.
    ///
    /// # Errors
    /// Whatever the underlying wire surfaces — wrapped in
    /// [`GatewayTransportError::Quic`] or
    /// [`GatewayTransportError::WebSocket`].
    pub async fn authenticate(
        &self,
        token: &str,
        device_id: Vec<u8>,
    ) -> Result<(), GatewayTransportError> {
        match self {
            Self::Quic(conn) => conn
                .authenticate(token, device_id)
                .await
                .map_err(Into::into),
            Self::WebSocket(conn) => conn
                .authenticate(token, device_id)
                .await
                .map_err(Into::into),
        }
    }

    /// Send one envelope.
    ///
    /// # Errors
    /// Wire-level send failure wrapped in [`GatewayTransportError::Quic`] or
    /// [`GatewayTransportError::WebSocket`].
    pub async fn send_envelope(
        &self,
        payload: ClientPayload,
    ) -> Result<u64, GatewayTransportError> {
        match self {
            Self::Quic(conn) => conn.send_envelope(payload).await.map_err(Into::into),
            Self::WebSocket(conn) => conn.send_envelope(payload).await.map_err(Into::into),
        }
    }

    /// Read one envelope.
    ///
    /// # Errors
    /// Wire-level recv failure wrapped in [`GatewayTransportError::Quic`] or
    /// [`GatewayTransportError::WebSocket`].
    pub async fn recv_envelope(&self) -> Result<ServerFrame, GatewayTransportError> {
        match self {
            Self::Quic(conn) => conn.recv_envelope().await.map_err(Into::into),
            Self::WebSocket(conn) => conn.recv_envelope().await.map_err(Into::into),
        }
    }

    /// Close the connection cleanly. Takes `self` by value because
    /// post-close operations would always fail.
    ///
    /// # Errors
    /// Wire-level close failure wrapped accordingly.
    pub async fn close(self) -> Result<(), GatewayTransportError> {
        match self {
            Self::Quic(conn) => conn.close().await.map_err(Into::into),
            Self::WebSocket(conn) => conn.close().await.map_err(Into::into),
        }
    }
}

/// Convenience builder for the QUIC handshake budget. Production callers
/// pass `Duration::from_millis(500)` per contract §2.3; tests typically
/// pass something larger to avoid CI flakes.
///
/// Convenience builder for the QUIC handshake budget.
#[must_use]
pub const fn default_quic_fallback_budget() -> Duration {
    Duration::from_millis(500)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_label_distinguishes_all_three_wires() {
        assert_eq!(NegotiatedTransport::Quic.metric_label(), "quic");
        assert_eq!(
            NegotiatedTransport::WebSocket(NegotiatedSubprotocol::ProtobufV1).metric_label(),
            "ws-pb"
        );
        assert_eq!(
            NegotiatedTransport::WebSocket(NegotiatedSubprotocol::MessagePackV1).metric_label(),
            "ws-mpack"
        );
    }

    #[test]
    fn default_quic_fallback_budget_matches_contract_500ms() {
        assert_eq!(default_quic_fallback_budget(), Duration::from_millis(500));
    }
}
