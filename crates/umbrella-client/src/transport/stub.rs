//! In-memory stub транспорты для изолированного тестирования facade в Блоке 7.2.
//! Замещаются на `Http2*Transport` реализации в Блоке 7.4.
//!
//! `StubUnwrapTransport` реализует trait
//! [`umbrella_backup::cloud_wrap::transport::UnwrapTransport`]. Остальные
//! транспорты — структуры-заглушки без внешнего trait (в блоках 7.3–7.6 у них
//! появится сигнатура по мере роста call graph).
//!
//! In-memory stub transports for isolated facade testing in Block 7.2. Replaced
//! with real `Http2*Transport` implementations in Block 7.4.
//!
//! `StubUnwrapTransport` implements the
//! [`umbrella_backup::cloud_wrap::transport::UnwrapTransport`] trait. The other
//! transports are placeholder structs with no external trait (their signatures
//! grow in Blocks 7.3–7.6 as the call graph expands).
//!
//! ## Lint allow для `Mutex::lock().expect(...)`
//!
//! Stub module использует стандартный pattern `Mutex::lock().expect("poisoned")`
//! для in-memory shared state. Mutex poisoning означает багу в коде (panic в
//! другом потоке держащим lock), не runtime error от user input — `.expect`
//! здесь корректен. Real transports в Блоке 7.4+ заменят stub на async код
//! без shared mutex'ов.
//!
//! ## Lint allow для `Mutex::lock().expect(...)`
//!
//! The stub module uses the standard `Mutex::lock().expect("poisoned")` pattern
//! for in-memory shared state. Mutex poisoning indicates a bug (panic in another
//! thread that held the lock), not a runtime error from user input — `.expect`
//! is appropriate here. Real transports in Block 7.4+ replace stubs with async
//! code that has no shared mutex.

#![allow(
    unknown_lints,
    no_unwrap_in_lib,
    reason = "stub module — Mutex poisoning is a bug; replaced by real transport in Block 7.4+"
)]

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use umbrella_backup::cloud_wrap::share::ServerUnwrapShare;
use umbrella_backup::cloud_wrap::signed_request::SignedUnwrapRequest;
use umbrella_backup::cloud_wrap::transport::UnwrapTransport;
use umbrella_backup::error::BackupError;

use crate::transport::async_unwrap::AsyncUnwrapTransport;

/// Stub cloud-backup-svc. Возвращает предварительно-сконфигурированные
/// `ServerUnwrapShare`-ответы через [`StubUnwrapTransport::push_response`];
/// пустая очередь → возвращает пустой `Vec` (реальный
/// `threshold_combine` затем отдаст `BackupError::InsufficientUnwrapShares`).
///
/// Stub cloud-backup-svc. Returns pre-configured `ServerUnwrapShare` responses
/// queued via [`StubUnwrapTransport::push_response`]; an empty queue yields an
/// empty `Vec`, which `threshold_combine` surfaces as
/// `BackupError::InsufficientUnwrapShares`.
#[derive(Debug, Default)]
pub struct StubUnwrapTransport {
    responses: Mutex<VecDeque<Vec<ServerUnwrapShare>>>,
}

impl StubUnwrapTransport {
    /// Поставить в очередь ответ на следующий `dispatch` вызов.
    ///
    /// Enqueue a response for the next `dispatch` call.
    pub fn push_response(&self, shares: Vec<ServerUnwrapShare>) {
        self.responses
            .lock()
            .expect("StubUnwrapTransport mutex poisoned")
            .push_back(shares);
    }

    /// Количество ответов ещё в очереди.
    ///
    /// Number of queued responses remaining.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.responses
            .lock()
            .expect("StubUnwrapTransport mutex poisoned")
            .len()
    }
}

impl UnwrapTransport for StubUnwrapTransport {
    fn dispatch(
        &self,
        _request: &SignedUnwrapRequest,
    ) -> Result<Vec<ServerUnwrapShare>, BackupError> {
        let mut queue = self
            .responses
            .lock()
            .expect("StubUnwrapTransport mutex poisoned");
        Ok(queue.pop_front().unwrap_or_default())
    }
}

/// Async adapter над sync [`UnwrapTransport`] — делегирует синхронному
/// `dispatch` без blocking-wrapper'а, потому что stub полностью in-memory
/// (никаких I/O ожиданий). `timeout` игнорируется — stub возвращает
/// результат моментально.
///
/// Async adapter over the sync [`UnwrapTransport`] — delegates to the sync
/// `dispatch` without a blocking wrapper, since the stub is fully in-memory
/// (no I/O to wait for). `timeout` is ignored — the stub resolves instantly.
#[async_trait]
impl AsyncUnwrapTransport for StubUnwrapTransport {
    async fn dispatch(
        &self,
        request: &SignedUnwrapRequest,
        _timeout: Duration,
    ) -> Result<Vec<ServerUnwrapShare>, BackupError> {
        <Self as UnwrapTransport>::dispatch(self, request)
    }
}

/// Stub blind-postman-svc. Держит two VecDeque: один для исходящих
/// ciphertext'ов, второй для inbox'а (ответов сервера). Полный trait
/// появится в Блоке 7.4 когда будет `PostmanTransport`.
///
/// Stub blind-postman-svc. Holds two VecDeques: one for outbound ciphertexts,
/// another for inbox (server responses). Full trait emerges in Block 7.4 with
/// `PostmanTransport`.
#[derive(Debug, Default)]
pub struct StubPostmanTransport {
    /// Доставленные ciphertext'ы (snapshot исходящей очереди).
    /// Delivered ciphertexts (snapshot of the outbound queue).
    pub delivered: Mutex<Vec<Vec<u8>>>,
    /// Входящая очередь (серверные push'и).
    /// Inbound queue (server pushes).
    pub inbox: Mutex<VecDeque<Vec<u8>>>,
}

/// Stub kt-svc. В Блоке 7.5 появится trait `KtTransport` с методами
/// `fetch_epoch`, `publish_entry`, `query_proof`; здесь только счётчик
/// опубликованных записей для verification в тестах.
///
/// Stub kt-svc. Block 7.5 introduces a `KtTransport` trait with
/// `fetch_epoch`, `publish_entry`, `query_proof`; here we only count
/// published entries for assertion in tests.
#[derive(Debug, Default)]
pub struct StubKtTransport {
    /// Записи, «опубликованные» в stub log.
    /// Entries that were "published" to the stub log.
    pub published_entries: Mutex<Vec<Vec<u8>>>,
}

/// Stub call-relay-svc. Счётчик аллокаций TURN relay (SPEC-06 §3). Реальная
/// TURN allocation логика появится в Блоке 7.6 через `webrtc-ice`.
///
/// Stub call-relay-svc. Counter of TURN relay allocations (SPEC-06 §3). Real
/// allocation logic arrives in Block 7.6 via `webrtc-ice`.
#[derive(Debug, Default)]
pub struct StubCallRelayTransport {
    /// Количество успешных allocation вызовов.
    /// Count of successful allocation calls.
    pub allocations: Mutex<u32>,
}
