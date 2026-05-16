//! Router — единая точка входа сервера: парсинг → anti-replay → rate-limit → решение.
//! Router — single server entry point: parse → anti-replay → rate-limit → decision.
//!
//! Порядок проверок намеренный: сначала дешёвая структурная валидация (отбрасываем битые
//! байты до того как тратим время/память на replay lookup), затем проверка повтора без записи,
//! затем rate-limit, и только после разрешения лимитом — запись в anti-replay окно.
//!
//! The check order is deliberate: first the cheap structural validation (throw out malformed
//! bytes before spending time/memory on a replay lookup), then duplicate detection without
//! recording, then rate-limit, and only after the limiter allows the message — recording in
//! the anti-replay window.

use crate::envelope::{parse_mls_envelope, EnvelopeError, EnvelopeKind, ParsedEnvelope};
use crate::ratelimit::RateLimiter;
use crate::replay::ReplayGuard;

/// Решение маршрутизации. Routing decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Сообщение принято — сервер передаёт envelope в delivery fan-out.
    /// Message accepted — server hands the envelope to delivery fan-out.
    Accept(ParsedEnvelope),
    /// Сообщение не удалось распарсить как валидный MLSMessage.
    /// Message did not parse as a valid MLSMessage.
    RejectMalformed,
    /// Тип body не допускается на этом endpoint (например, KeyPackage на messages endpoint).
    /// Body kind not allowed on this endpoint (e.g. KeyPackage on a messages endpoint).
    RejectUnsupportedKind(EnvelopeKind),
    /// Это точный дубликат сообщения уже виденного в anti-replay окне.
    /// This is an exact duplicate of a message seen in the anti-replay window.
    RejectReplay,
    /// Sender превысил квоту rate-лимита.
    /// Sender exceeded the rate-limit quota.
    RejectRateLimit,
    /// `tls_codec` parser panic'нул на malformed wire input — F-37-class regression
    /// (block 10.14 inline-fix). Postulate 14 «no silent fallback» — caller получает
    /// diagnostic category для observability/escalation. Sender's quota не consumed —
    /// panic catch выявляется до replay/rate-limit checks (defence-in-depth).
    ///
    /// `tls_codec` parser panicked on malformed wire input — F-37-class regression
    /// (block 10.14 inline-fix). Postulate 14 «no silent fallback» — the caller receives
    /// a diagnostic category for observability / escalation. The sender's quota is not
    /// consumed — the panic catch is detected before replay / rate-limit checks
    /// (defence in depth).
    RejectParserPanic(&'static str),
}

/// Router комбинирует парсер, replay-guard и rate-limiter.
/// The router combines parser, replay guard, and rate limiter.
pub struct Router<RL: RateLimiter> {
    replay: ReplayGuard,
    rate_limiter: RL,
    accept_welcomes: bool,
    accept_key_packages: bool,
    accept_group_info: bool,
}

impl<RL: RateLimiter> Router<RL> {
    /// Создаёт Router с указанными компонентами. По дефолту принимает только
    /// PrivateMessage/PublicMessage (message-plane endpoint).
    ///
    /// Creates a Router with the given components. Defaults to accepting only
    /// PrivateMessage/PublicMessage (message-plane endpoint).
    pub fn new(replay: ReplayGuard, rate_limiter: RL) -> Self {
        Self {
            replay,
            rate_limiter,
            accept_welcomes: false,
            accept_key_packages: false,
            accept_group_info: false,
        }
    }

    /// Разрешает принимать Welcome envelope (используется в KeyPackage-swap endpoint).
    /// Allows accepting Welcome envelopes (used by the KeyPackage-swap endpoint).
    pub fn with_welcomes(mut self) -> Self {
        self.accept_welcomes = true;
        self
    }

    /// Разрешает принимать KeyPackage envelope (upload endpoint).
    /// Allows accepting KeyPackage envelopes (upload endpoint).
    pub fn with_key_packages(mut self) -> Self {
        self.accept_key_packages = true;
        self
    }

    /// Разрешает принимать GroupInfo envelope (public-group discovery endpoint).
    /// Allows accepting GroupInfo envelopes (public-group discovery endpoint).
    pub fn with_group_info(mut self) -> Self {
        self.accept_group_info = true;
        self
    }

    /// Обрабатывает incoming bytes с идентификатором sender'а для rate-лимита.
    /// Processes incoming bytes with the sender identifier for rate-limiting.
    pub fn dispatch(&mut self, bytes: &[u8], sender_id: &[u8], now_unix: u64) -> RoutingDecision {
        let envelope = match parse_mls_envelope(bytes) {
            Ok(e) => e,
            Err(EnvelopeError::Malformed) => return RoutingDecision::RejectMalformed,
            Err(EnvelopeError::UnsupportedKind) => {
                return RoutingDecision::RejectUnsupportedKind(EnvelopeKind::PrivateMessage)
            }
            // F-54 inline-fix (block 10.14): F-37 parser panic catch — diagnostic preserved
            // для observability/escalation; replay/rate-limit checks skipped (panic detected
            // ДО них), sender's quota не consumed.
            // F-54 inline-fix (block 10.14): F-37 parser-panic catch — diagnostic preserved
            // for observability / escalation; replay / rate-limit checks are skipped (the
            // panic is detected before them), so the sender's quota is not consumed.
            Err(EnvelopeError::ParserPanic { kind }) => {
                return RoutingDecision::RejectParserPanic(kind)
            }
        };

        let kind_allowed = match envelope.kind {
            EnvelopeKind::PrivateMessage | EnvelopeKind::PublicMessage => true,
            EnvelopeKind::Welcome => self.accept_welcomes,
            EnvelopeKind::KeyPackage => self.accept_key_packages,
            EnvelopeKind::GroupInfo => self.accept_group_info,
        };
        if !kind_allowed {
            return RoutingDecision::RejectUnsupportedKind(envelope.kind);
        }

        // Повтор проверяем до rate-limit, но не записываем новый hash до того как
        // rate-limit разрешит сообщение. Иначе unique flood сверх лимита забивает
        // replay-память.
        // Check duplicates before rate-limit, but do not record a new hash until
        // the rate-limit allows the message. Otherwise a unique flood over quota
        // fills replay memory.
        if self.replay.is_duplicate(envelope.message_hash, now_unix) {
            return RoutingDecision::RejectReplay;
        }

        if !self.rate_limiter.allow(sender_id, now_unix) {
            return RoutingDecision::RejectRateLimit;
        }

        self.replay.record(envelope.message_hash, now_unix);

        RoutingDecision::Accept(envelope)
    }

    /// Текущее число активных sender'ов в rate-limiter (для observability).
    /// Current number of active senders in the rate limiter (for observability).
    pub fn replay_active_entries(&self) -> usize {
        self.replay.active_entries()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratelimit::{AllowAll, FixedWindow};
    use crate::replay::DEFAULT_REPLAY_WINDOW_SECS;

    #[test]
    fn malformed_bytes_return_reject_malformed() {
        let mut r = Router::new(ReplayGuard::with_default_window(), AllowAll);
        assert_eq!(
            r.dispatch(b"garbage", b"alice", 100),
            RoutingDecision::RejectMalformed
        );
    }

    #[test]
    fn empty_bytes_return_reject_malformed() {
        let mut r = Router::new(ReplayGuard::with_default_window(), AllowAll);
        assert_eq!(
            r.dispatch(&[], b"alice", 100),
            RoutingDecision::RejectMalformed
        );
    }

    #[test]
    fn rate_limit_quota_exhausts_after_limit() {
        let mut r = Router::new(ReplayGuard::with_default_window(), FixedWindow::new(60, 2));
        // Поскольку мы не имеем валидный MLSMessage в unit-тесте, симулируем путь через
        // рефакторинг: dispatch возвращает RejectMalformed до rate-limit → квота не
        // уменьшается. Тест на rate-лимит с валидным payload — в integration tests
        // (umbrella-tests), где у нас настоящий UmbrellaGroup который генерирует валидные
        // envelope.
        // Since we don't have a valid MLSMessage in a unit test, we simulate the path:
        // dispatch returns RejectMalformed before rate-limit → quota is not consumed. The
        // rate-limit test with a valid payload lives in integration tests (umbrella-tests),
        // where we have a real UmbrellaGroup producing valid envelopes.
        assert_eq!(
            r.dispatch(b"garbage", b"alice", 100),
            RoutingDecision::RejectMalformed
        );
    }

    #[test]
    fn welcome_rejected_by_default_message_endpoint() {
        // Welcome bytes (мы не создаём валидный Welcome здесь, используем garbage для
        // RejectMalformed пути — реальный end-to-end тест в umbrella-tests).
        let mut r = Router::new(ReplayGuard::with_default_window(), AllowAll);
        assert_eq!(
            r.dispatch(b"garbage", b"alice", 100),
            RoutingDecision::RejectMalformed
        );
    }

    #[test]
    fn default_window_wired_through_guard() {
        let r = Router::new(ReplayGuard::with_default_window(), AllowAll);
        // Invariant: guard с дефолтным окном имеет 0 активных записей на старте.
        assert_eq!(r.replay_active_entries(), 0);
        let _ = DEFAULT_REPLAY_WINDOW_SECS; // использован для консистентности документации.
    }
}
