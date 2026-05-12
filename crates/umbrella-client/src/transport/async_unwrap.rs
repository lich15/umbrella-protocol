//! Async-версия `UnwrapTransport` для HTTP/2 реализаций.
//!
//! В `umbrella-backup` зафиксирован **синхронный** trait
//! [`umbrella_backup::cloud_wrap::transport::UnwrapTransport`] —
//! он используется `unwrap_message_key` и `MockUnwrapTransport` в unit-тестах
//! cloud_wrap, где dispatch — in-memory, без I/O. Пересечение границы с
//! real HTTP/2 транспортом (reqwest) требует `async fn` сигнатуры: HTTP ↔ await.
//!
//! Вместо того чтобы менять вышестоящий sync-контракт (breaking change для
//! всех unit-тестов cloud_wrap в umbrella-backup и integration-тестов в
//! umbrella-tests), вводим **дополнительный** async trait, живущий на стороне
//! umbrella-client. Он принимает те же типы (`SignedUnwrapRequest`,
//! `ServerUnwrapShare`, `BackupError`) и совпадает с контрактом SPEC-12 §A.7
//! (с явным `timeout`, который в sync trait отсутствует).
//!
//! Фасады `CloudChat` / `SecretChat` в блоке 7.7 держат
//! `Arc<dyn AsyncUnwrapTransport + Send + Sync>` — `StubUnwrapTransport`
//! coerce'ится в dyn через blanket impl в `stub.rs`, `Http2UnwrapTransport`
//! реализует trait напрямую.
//!
//! Async counterpart of `UnwrapTransport` for HTTP/2 implementations.
//!
//! `umbrella-backup` fixes a **synchronous**
//! [`umbrella_backup::cloud_wrap::transport::UnwrapTransport`] — it is used by
//! `unwrap_message_key` and `MockUnwrapTransport` in unit tests where dispatch
//! is in-memory. Crossing the boundary into real HTTP/2 (reqwest) needs
//! `async fn` — HTTP ↔ await.
//!
//! Rather than changing the upstream sync contract (breaking all cloud_wrap
//! unit tests plus umbrella-tests integration suites), we introduce an
//! **additional** async trait living in umbrella-client. It takes the same
//! types (`SignedUnwrapRequest`, `ServerUnwrapShare`, `BackupError`) and
//! matches SPEC-12 §A.7 (with the explicit `timeout` that the sync trait
//! lacks).
//!
//! `CloudChat` / `SecretChat` facades in Block 7.7 hold
//! `Arc<dyn AsyncUnwrapTransport + Send + Sync>`; `StubUnwrapTransport`
//! coerces into dyn via a blanket impl in `stub.rs`, while
//! `Http2UnwrapTransport` implements this trait natively.

use std::time::Duration;

use async_trait::async_trait;
use umbrella_backup::cloud_wrap::share::ServerUnwrapShare;
use umbrella_backup::cloud_wrap::signed_request::SignedUnwrapRequest;
use umbrella_backup::error::BackupError;

/// Async контракт disp-отправки unwrap-запроса к Sealed Servers
/// (fan-out 3-of-5, SPEC-12 §A.7).
///
/// Реализация — [`crate::transport::cloud_backup::Http2UnwrapTransport`] для
/// production и [`crate::transport::stub::StubUnwrapTransport`] для тестов
/// (через blanket adapter в `stub.rs`).
///
/// Async dispatcher contract for unwrap requests to Sealed Servers
/// (fan-out 3-of-5, SPEC-12 §A.7). Implemented by `Http2UnwrapTransport`
/// in production and by `StubUnwrapTransport` in tests (via a blanket adapter
/// in `stub.rs`).
#[async_trait]
pub trait AsyncUnwrapTransport: Send + Sync {
    /// Отправить запрос всем серверам (fan-out), вернуть до 5 валидных shares
    /// до `timeout`. Caller (threshold_combine) сам разбирается с ≥3 vs <3.
    ///
    /// Send the request to all servers (fan-out), return up to 5 valid shares
    /// within `timeout`. Caller (threshold_combine) decides whether ≥3 were
    /// collected.
    ///
    /// # Errors
    /// - [`BackupError`] по усмотрению реализации (сеть, парсинг, криптография).
    ///   Реализация может также вернуть `Ok(vec![])` при полном отсутствии
    ///   живых серверов — `threshold_combine` транслирует это в
    ///   [`BackupError::InsufficientUnwrapShares`].
    async fn dispatch(
        &self,
        request: &SignedUnwrapRequest,
        timeout: Duration,
    ) -> Result<Vec<ServerUnwrapShare>, BackupError>;
}
