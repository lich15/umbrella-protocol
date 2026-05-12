//! Транспорт-слой: HTTP/2 клиенты к `Umbrella server implementation` сервисам (cloud-backup-svc,
//! blind-postman-svc, kt-svc, call-relay-svc). В Блоке 7.2 используются
//! in-memory stubs из [`stub`]; в Блоке 7.4 они замещаются реальными
//! `Http2*Transport` реализациями на reqwest + rustls (ADR-010 Решение 1).
//!
//! Transport layer: HTTP/2 clients for `Umbrella server implementation` services (cloud-backup-svc,
//! blind-postman-svc, kt-svc, call-relay-svc). Block 7.2 uses the in-memory
//! stubs from [`stub`]; Block 7.4 replaces them with real `Http2*Transport`
//! implementations on reqwest + rustls (ADR-010 Decision 1).

pub mod async_unwrap;
pub mod blind_postman;
pub mod call_relay;
pub mod cloud_backup;
pub mod http2_client;
pub mod kt_transport;
pub mod pinning;
pub mod retry;
pub mod stub;

pub use async_unwrap::AsyncUnwrapTransport;
pub use blind_postman::{Http2PostmanTransport, MESSAGE_ID_LEN};
pub use call_relay::{CallSecurityLevelWire, Http2CallRelayTransport, TurnAllocation, PEER_ID_LEN};
pub use cloud_backup::{Http2UnwrapTransport, EARLY_RETURN_THRESHOLD, SEALED_SERVER_COUNT};
pub use http2_client::{build_http2_client, Http2Config};
pub use kt_transport::{Http2KtTransport, ACCOUNT_ID_LEN};
pub use pinning::{PinningConfig, SpkiPin, SPKI_PIN_LEN};
pub use retry::{is_reqwest_retryable, retry_with_backoff, DEFAULT_MAX_ATTEMPTS};
