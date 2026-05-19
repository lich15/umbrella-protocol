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

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use umbrella_backup::cloud_wrap::share::ServerUnwrapShare;
use umbrella_backup::cloud_wrap::signed_request::SignedUnwrapRequest;
use umbrella_backup::cloud_wrap::transport::UnwrapTransport;
use umbrella_backup::cloud_wrap::wire::WrappedKey;
use umbrella_backup::error::BackupError;
use umbrella_kt::{KtEntry, SignedEpochRoot};

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

/// Stub blind-postman-svc. Держит four очередей: исходящие ciphertext'ы,
/// inbox-ответы сервера, per-`ChatId` Cloud history queue для
/// `cloud_sync_history` fetch, per-recipient Welcome queue для join-flow
/// сценариев. Полный trait появится в Блоке 7.4 как `PostmanTransport`.
///
/// Stub blind-postman-svc. Holds four queues: outbound ciphertexts, inbound
/// server pushes, per-`ChatId` Cloud history for `cloud_sync_history` fetch,
/// and per-recipient Welcome queue for join flow.
#[derive(Debug, Default)]
pub struct StubPostmanTransport {
    /// Доставленные ciphertext'ы (snapshot исходящей очереди).
    /// Delivered ciphertexts (snapshot of the outbound queue).
    pub delivered: Mutex<Vec<Vec<u8>>>,
    /// Входящая очередь (серверные push'и).
    /// Inbound queue (server pushes).
    pub inbox: Mutex<VecDeque<Vec<u8>>>,
    /// **F-CLIENT-FACADE-1 session 6 (2026-05-19):** Cloud-режим at-rest
    /// история. Ключ — 32-байтовый `chat_id` (используется напрямую как
    /// `[u8; 32]`, чтобы избежать зависимости stub'а от facade `ChatId`
    /// типа). Значение — упорядоченный список [`CloudHistoryEntry`]
    /// в order доставки на postman. `CloudChat::cloud_sync_history(since)`
    /// фильтрует по `sent_ts_ms > since` и unwrap'ит каждый.
    ///
    /// Cloud history queue indexed by chat_id (raw 32-byte key).
    /// `CloudChat::cloud_sync_history(since)` drains entries with
    /// `sent_ts_ms > since`.
    pub cloud_history: Mutex<HashMap<[u8; 32], Vec<CloudHistoryEntry>>>,
    /// **F-CLIENT-FACADE-1 session 6:** Welcome inbox per recipient device
    /// identity. Key — 32-байтовый Ed25519 identity pubkey получателя.
    /// `mls_add_member` при auto-publish push'ит TLS-serialized Welcome bytes
    /// в очередь; новое устройство при bootstrap дёргает
    /// `ClientCore::fetch_pending_welcomes(peer)`.
    ///
    /// Welcome inbox per recipient identity. `mls_add_member` auto-publishes
    /// here; `ClientCore::fetch_pending_welcomes(peer)` drains.
    pub welcome_inbox: Mutex<HashMap<[u8; 32], VecDeque<Vec<u8>>>>,
}

/// **F-CLIENT-FACADE-1 session 6 (2026-05-19):** запись в Cloud-режиме history
/// queue postman'а. Сочетает at-rest шифрование (AEAD под `message_key` через
/// ChaCha20-Poly1305) + Cloud-wrapped `WrappedKey` (81-байт threshold-HPKE
/// blob под `K = Y·G` Sealed Servers). Sender построит этот entry на send;
/// recipient на `cloud_sync_history` для каждого entry будет:
///
/// 1. Построить `SignedUnwrapRequest` из `wrapped_key.ephemeral_r`
/// 2. dispatch'ить через `AsyncUnwrapTransport` → ≥3 shares
/// 3. `unwrap_message_key` → 32-байт `message_key`
/// 4. AEAD-decrypt `ciphertext_at_rest` под `message_key` + `canonical_nonce(chat_id, msg_seq)`
/// 5. Получить plaintext UTF-8
///
/// `WrappedKey` (81 байт) хранит зашифрованный `message_key` под Sealed Server
/// threshold-HPKE; `ciphertext_at_rest` хранит зашифрованное plaintext
/// сообщения под `message_key`. Эта **двойная конструкция** требуется чтобы
/// новое устройство (которое не имеет MLS ratchet state) могло восстановить
/// chat history через cooperation Sealed Servers (Cloud-режим только;
/// SecretChat не имеет at-rest backup по дизайну).
///
/// One Cloud-mode at-rest history entry stored on postman. Sender writes
/// here on send; recipient drains via `cloud_sync_history`, fetches partial
/// shares from Sealed Servers, unwraps the `WrappedKey` to recover the
/// `message_key`, then AEAD-decrypts `ciphertext_at_rest` to recover the
/// plaintext.
#[derive(Clone)]
pub struct CloudHistoryEntry {
    /// 16-байт opaque message id (генерируется отправителем). Mirror'ит
    /// `MessageId` в facade::chat_common. Postman использует для dedup.
    pub msg_id: [u8; 16],
    /// 32-байт Ed25519 identity pubkey отправителя. Используется в
    /// `CanonicalAad.sender_identity_pubkey` для AEAD binding.
    pub sender: [u8; 32],
    /// Wall-clock millis отправителя на момент send. Используется для
    /// `since` filter в `cloud_sync_history` (recipient получает только
    /// сообщения после lastSeenTs).
    pub sent_ts_ms: u64,
    /// Monotonic per-chat sequence number. Используется в `canonical_nonce`
    /// derivation (deterministic AEAD nonce из (chat_id, msg_seq)) — sender
    /// и recipient приходят к одному nonce без передачи по сети. Replay
    /// инвариант: postman side enforces strict monotonicity per chat_id.
    pub msg_seq: u64,
    /// AEAD-encrypted plaintext под `message_key` с deterministic nonce
    /// `canonical_nonce(chat_id, msg_seq)`. Длина ≈ plaintext + 16 байт
    /// Poly1305 tag.
    pub ciphertext_at_rest: Vec<u8>,
    /// 81-байт wrapped `message_key` (threshold-HPKE под Sealed Server K).
    pub wrapped_key: WrappedKey,
}

/// `Debug` скрывает sensitive: sender pubkey + linkable timestamps оставляет,
/// ciphertext bytes redact — следует pattern остальных at-rest типов в
/// umbrella-backup.
impl core::fmt::Debug for CloudHistoryEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudHistoryEntry")
            .field("msg_id", &"<redacted>")
            .field("sender", &"<redacted>")
            .field("sent_ts_ms", &self.sent_ts_ms)
            .field("msg_seq", &self.msg_seq)
            .field("ciphertext_at_rest_len", &self.ciphertext_at_rest.len())
            .field("ciphertext_at_rest", &"<redacted>")
            .field("wrapped_key", &self.wrapped_key)
            .finish()
    }
}

impl StubPostmanTransport {
    /// **F-CLIENT-FACADE-1 session 6:** test helper — push a Cloud history
    /// entry for the given `chat_id`. Stages the entry for subsequent
    /// `CloudChat::cloud_sync_history` drain. Entries returned in insertion
    /// order.
    ///
    /// Test helper: push a Cloud history entry for the chat_id.
    pub fn push_cloud_history(&self, chat_id: [u8; 32], entry: CloudHistoryEntry) {
        self.cloud_history
            .lock()
            .expect("StubPostmanTransport.cloud_history mutex poisoned")
            .entry(chat_id)
            .or_default()
            .push(entry);
    }

    /// **F-CLIENT-FACADE-1 session 6:** drain Cloud history entries for the
    /// given `chat_id` whose `sent_ts_ms > since_ms`. Removes drained entries
    /// from the queue (one-shot fetch). Returns entries in insertion order.
    ///
    /// Drains entries with `sent_ts_ms > since_ms`; removes them.
    pub fn drain_cloud_history(&self, chat_id: &[u8; 32], since_ms: u64) -> Vec<CloudHistoryEntry> {
        let mut guard = self
            .cloud_history
            .lock()
            .expect("StubPostmanTransport.cloud_history mutex poisoned");
        let Some(entries) = guard.get_mut(chat_id) else {
            return Vec::new();
        };
        let mut keep = Vec::new();
        let mut drained = Vec::new();
        for entry in entries.drain(..) {
            if entry.sent_ts_ms > since_ms {
                drained.push(entry);
            } else {
                keep.push(entry);
            }
        }
        *entries = keep;
        drained
    }

    /// **F-CLIENT-FACADE-1 session 6:** publish a TLS-serialized Welcome
    /// message into the recipient device's Welcome inbox. Called by
    /// `mls_add_member` after generating Welcome bytes. New device drains
    /// via [`Self::drain_welcomes_for`].
    ///
    /// Publish a Welcome to the recipient device's inbox.
    pub fn push_welcome(&self, recipient_identity_pk: [u8; 32], welcome_bytes: Vec<u8>) {
        self.welcome_inbox
            .lock()
            .expect("StubPostmanTransport.welcome_inbox mutex poisoned")
            .entry(recipient_identity_pk)
            .or_default()
            .push_back(welcome_bytes);
    }

    /// **F-CLIENT-FACADE-1 session 6:** drain all Welcome bytes pending for
    /// the recipient device identity. Called by `ClientCore::fetch_pending_welcomes`.
    /// Returns Welcomes in insertion order; queue emptied on drain.
    ///
    /// Drain pending Welcomes for the recipient identity.
    pub fn drain_welcomes_for(&self, recipient_identity_pk: &[u8; 32]) -> Vec<Vec<u8>> {
        let mut guard = self
            .welcome_inbox
            .lock()
            .expect("StubPostmanTransport.welcome_inbox mutex poisoned");
        match guard.get_mut(recipient_identity_pk) {
            Some(queue) => queue.drain(..).collect(),
            None => Vec::new(),
        }
    }
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

    /// **F-CLIENT-FACADE-1 session 8a (2026-05-19):** typed staging для
    /// self-monitoring tests. Map `(account_id, epoch) → KtEntry`.
    /// Аналог `cloud_history` в [`StubPostmanTransport`] — test stages
    /// concrete entries которые facade self-monitor затем fetch'ит и
    /// сравнивает против `OwnExpectations`. Production:
    /// `Http2KtTransport::fetch_epoch` возвращает raw bytes, codec в
    /// `umbrella-kt` парсит → `KtEntry`; здесь codec обходится
    /// сохранением Rust value напрямую (canonical_encoding round-trip
    /// деferred до production wire-deserialization wiring в session 8c+).
    ///
    /// **F-CLIENT-FACADE-1 session 8a:** typed staging map
    /// `(account_id, epoch) → KtEntry` для facade self-monitor tests.
    /// Mirrors the `cloud_history` pattern in `StubPostmanTransport`.
    /// Production: HTTP/2 transport returns raw bytes and codec
    /// deserialises; here we skip the round-trip by storing Rust values.
    pub staged_entries: Mutex<HashMap<([u8; 32], u64), KtEntry>>,

    /// **F-CLIENT-FACADE-1 session 8b (2026-05-19):** typed staging map
    /// `epoch → SignedEpochRoot` для facade 3-of-5 witness-threshold tests.
    /// Один [`SignedEpochRoot`] per epoch уже несёт `signatures:
    /// Vec<WitnessSignature>` со всеми 5 подписями witness-ов (контейнер); тест
    /// stages один такой объект и facade helper верифицирует threshold через
    /// `umbrella_kt::witness::verify_signed_epoch`.
    ///
    /// Ключом служит **stub-side** `epoch_key: u64` — параметр запроса
    /// клиента. Поле `SignedEpochRoot.epoch` внутри — то значение, под которым
    /// witness-ы подписывали; production-server обязан возвращать запись где
    /// `signed.epoch == requested_epoch`. Stub позволяет тесту разойтись с
    /// этим инвариантом (stage SignedEpochRoot где `signed.epoch != epoch_key`),
    /// чтобы убедиться что facade helper детектирует attempted epoch
    /// substitution attack (см. session 8b test
    /// `verify_witness_signatures_detects_signed_epoch_field_substitution_attack`).
    ///
    /// **F-CLIENT-FACADE-1 session 8b:** typed staging map `epoch →
    /// SignedEpochRoot` for the facade 3-of-5 witness-threshold tests. Key is
    /// the **stub-side** `epoch_key` (the requested epoch); `SignedEpochRoot.epoch`
    /// is what the witnesses signed. A test can intentionally diverge these
    /// to exercise the facade's epoch-substitution defence.
    ///
    /// **Session 8c1 migration note**: pinned `WitnessSet` ранее жил в
    /// `staged_witness_set` поле здесь же; в session 8c1 переехал к
    /// `ClientCore::kt_witness_set` (single source of truth для facade
    /// helper'а + future Http2KtTransport wire-up). Здесь оставлено только
    /// signed-roots staging — это runtime data (per-epoch), не
    /// configuration.
    pub staged_signed_roots: Mutex<HashMap<u64, SignedEpochRoot>>,
}

impl StubKtTransport {
    /// **F-CLIENT-FACADE-1 session 8a (2026-05-19):** stage a `KtEntry` для
    /// последующего fetch'а через [`Self::fetch_staged_entry`]. Перезаписывает
    /// existing entry под тем же `(account_id, epoch)` key (last write wins;
    /// тесты ставят либо honest entry либо substituted entry для проверки
    /// `verify_own_entry` paths). Idempotent по `(account_id, epoch)`.
    ///
    /// **F-CLIENT-FACADE-1 session 8a:** stage a `KtEntry` for later fetch.
    /// Overwrites any existing entry under the same `(account_id, epoch)` key.
    pub fn push_staged_entry(&self, account_id: [u8; 32], epoch: u64, entry: KtEntry) {
        let mut guard = self.staged_entries.lock().expect("poisoned");
        guard.insert((account_id, epoch), entry);
    }

    /// **F-CLIENT-FACADE-1 session 8a (2026-05-19):** fetch staged entry для
    /// `(account_id, epoch)`. Returns `None` если ничего не staged — facade
    /// self-monitor maps это в `ClientError::Kt(KtError::SelfMonitoringMismatch
    /// { field: "no_entry_staged" })`-shaped diagnostic либо аналог.
    ///
    /// **F-CLIENT-FACADE-1 session 8a:** fetch a staged entry. Returns `None`
    /// when nothing was staged for that (account_id, epoch) key.
    #[must_use]
    pub fn fetch_staged_entry(&self, account_id: &[u8; 32], epoch: u64) -> Option<KtEntry> {
        let guard = self.staged_entries.lock().expect("poisoned");
        guard.get(&(*account_id, epoch)).cloned()
    }

    /// **F-CLIENT-FACADE-1 session 8b (2026-05-19):** stage `SignedEpochRoot`
    /// под `epoch_key`. Перезаписывает существующее значение под тем же
    /// ключом (last write wins; тесты могут stage'ить либо honest, либо
    /// substituted root для exercise разных paths). Idempotent по
    /// `epoch_key`. `signed.epoch` внутри **не обязан** совпадать с
    /// `epoch_key` — это позволяет тесту смоделировать epoch-substitution
    /// атаку сервера (см. session 8b test).
    ///
    /// **F-CLIENT-FACADE-1 session 8b:** stage a `SignedEpochRoot` under
    /// `epoch_key`. Overwrites any existing value. `signed.epoch` may
    /// intentionally differ from `epoch_key` to model an
    /// epoch-substitution attack by the server.
    pub fn push_staged_signed_root(&self, epoch_key: u64, signed: SignedEpochRoot) {
        let mut guard = self.staged_signed_roots.lock().expect("poisoned");
        guard.insert(epoch_key, signed);
    }

    /// **F-CLIENT-FACADE-1 session 8b (2026-05-19):** fetch staged
    /// `SignedEpochRoot` для `epoch_key`. Returns `None` если ничего не
    /// staged — facade helper maps это в
    /// `ClientError::Kt(KtError::InsufficientValidSignatures { valid: 0,
    /// required: threshold })` (fail-closed на полное отсутствие подписей).
    ///
    /// **F-CLIENT-FACADE-1 session 8b:** fetch a staged `SignedEpochRoot`.
    /// Returns `None` when nothing was staged for that `epoch_key`.
    #[must_use]
    pub fn fetch_staged_signed_root(&self, epoch_key: u64) -> Option<SignedEpochRoot> {
        let guard = self.staged_signed_roots.lock().expect("poisoned");
        guard.get(&epoch_key).cloned()
    }
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
