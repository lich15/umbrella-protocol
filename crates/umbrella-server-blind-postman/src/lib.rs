//! Слепой почтальон: парсит MLSMessage, маршрутизирует, защищает от replay; никогда не расшифровывает.
//! Blind postman: parses MLSMessage, routes, protects against replay; never decrypts.
//!
//! ## Принцип
//!
//! Серверная часть Umbrella Protocol обрабатывает зашифрованные пакеты без расшифровки — она
//! видит только wire-format: какого типа пакет, для какой группы/epoch, и байты (ciphertext).
//! Приватных ключей участников у сервера физически нет. Это обеспечивается на уровне
//! зависимостей: крейт НЕ зависит от `umbrella-identity` (приватные device/identity keys) и
//! НЕ зависит от `openmls_rust_crypto` (провайдер для криптооперационных процедур openmls).
//! Он использует только парсинг `openmls` wire-format и `sha2` для хэширования байт.
//!
//! ## Компоненты
//!
//! - [`envelope`] — структурная валидация MLSMessage без decrypt: парсим TLS wire-format,
//!   вынимаем маршрутизационные метаданные (тип, group_id, epoch для handshake),
//!   считаем SHA-256 хэш для anti-replay.
//! - [`replay`] — [`ReplayGuard`] с time-windowed HashSet message-hashes: отвергает дубликаты
//!   в окне `window_secs` (дефолт 60 секунд — превышает максимальный RTT между клиентом и
//!   DS-шард плюс retry-jitter, но короче чем ожидаемый интервал между уникальными
//!   сообщениями).
//! - [`ratelimit`] — trait [`RateLimiter`] с реализацией [`FixedWindow`] (скользящее окно по
//!   sender_id). Production backend — поверх Valkey/DragonflyDB через FFI обёртку в `Umbrella server implementation`.
//! - [`router`] — комбинирует парсер, replay-guard и rate-limiter в единое решение
//!   [`RoutingDecision`].
//!
//! ## Principle
//!
//! The server side of Umbrella Protocol handles encrypted packets without decrypting — it sees
//! only the wire format: packet type, target group/epoch, and ciphertext bytes. It physically
//! has no member private keys. This is enforced at the dependency level: the crate does NOT
//! depend on `umbrella-identity` (private device/identity keys) and does NOT depend on
//! `openmls_rust_crypto` (provider for openmls crypto ops). It uses only `openmls` wire-format
//! parsing and `sha2` for byte hashing.
//!
//! ## Components
//!
//! - [`envelope`] — structural MLSMessage validation without decrypt: parse TLS wire format,
//!   extract routing metadata (kind, group_id, epoch for handshake), compute SHA-256 hash for
//!   anti-replay.
//! - [`replay`] — [`ReplayGuard`] with time-windowed HashSet of message hashes: rejects
//!   duplicates in the `window_secs` window (default 60 seconds — exceeds the max client-DS
//!   RTT plus retry jitter, but shorter than the expected inter-unique-message interval).
//! - [`ratelimit`] — [`RateLimiter`] trait with a [`FixedWindow`] implementation (sliding
//!   window per sender_id). Production backend — on top of Valkey/DragonflyDB via FFI wrapper
//!   in `Umbrella server implementation`.
//! - [`router`] — combines the parser, replay guard and rate limiter into a single
//!   [`RoutingDecision`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod envelope;
pub mod ratelimit;
pub mod replay;
pub mod router;

pub use envelope::{
    parse_mls_envelope, EnvelopeError, EnvelopeKind, ParsedEnvelope, MLS_MESSAGE_MIN_BYTES,
};
pub use ratelimit::{AllowAll, FixedWindow, RateLimiter};
pub use replay::{ReplayDecision, ReplayGuard, DEFAULT_REPLAY_WINDOW_SECS};
pub use router::{Router, RoutingDecision};
