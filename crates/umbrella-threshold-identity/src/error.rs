//! Error types для threshold identity flow. Все ошибки typed и не утекают
//! секреты в `Display`.
//!
//! Error types for the threshold identity flow. Errors are typed and never
//! leak secrets via `Display`.

use thiserror::Error;

/// Top-level error для всех операций threshold identity.
///
/// Top-level error for all threshold identity operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ThresholdIdentityError {
    /// DKG-протокол сорван (например, недостаточно участников отвечают).
    #[error("DKG protocol aborted: {0}")]
    DkgAborted(&'static str),

    /// Неверный share от участника — Pedersen-VSS verification fail.
    #[error("invalid share from participant {0}")]
    InvalidShare(u16),

    /// Threshold signing failed — недостаточно подписей собрано.
    #[error("threshold sign failed: {0}")]
    SignFailed(&'static str),

    /// Серверная политика отказала операции (rate-limit, locked-out, etc).
    #[error("policy reject: {0}")]
    PolicyReject(PolicyRejection),

    /// PIN не прошёл проверку (после N попыток escalation).
    #[error("wrong PIN")]
    WrongPin,

    /// Аккаунт удалён (через duress либо после 5 неверных emergency).
    #[error("account permanently deleted")]
    AccountDeleted,

    /// Time-lock recovery ещё не завершён.
    #[error("time-lock not elapsed yet: {remaining_secs}s remaining")]
    TimeLockNotElapsed {
        /// Сколько секунд осталось до завершения time-lock.
        remaining_secs: u64,
    },

    /// Recovery отменён primary device через push notification.
    #[error("recovery cancelled by primary device")]
    RecoveryCancelled,

    /// Offline-ticket истёк (24h boundary прошёл).
    #[error("offline ticket expired")]
    OfflineTicketExpired,

    /// Argon2 PIN-KDF failure (alloc, parameters).
    #[error("PIN KDF failure: {0}")]
    PinKdfFailure(&'static str),

    /// FROST library error (wrapped).
    #[error("FROST error: {0}")]
    Frost(String),

    /// I/O failure on transport / serialization.
    #[error("I/O error: {0}")]
    Io(String),
}

/// Reasons почему policy reject'нул запрос.
///
/// Reasons for policy rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRejection {
    /// PIN attempts exhausted, escalate to 24-word recovery.
    PinAttemptsExhausted,
    /// 24-word recovery attempts exhausted, escalate to 12-word emergency.
    Recovery24Exhausted,
    /// 12-word emergency attempts exhausted, account permanently deleted.
    Emergency12Exhausted,
    /// Dead-man switch fired, account wiped.
    DeadManFired,
    /// Heartbeat missing, account temporarily suspicious.
    HeartbeatMissing,
}

impl core::fmt::Display for PolicyRejection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::PinAttemptsExhausted => "PIN attempts exhausted",
            Self::Recovery24Exhausted => "24-word recovery attempts exhausted",
            Self::Emergency12Exhausted => "12-word emergency attempts exhausted",
            Self::DeadManFired => "dead-man switch fired",
            Self::HeartbeatMissing => "heartbeat missing",
        };
        f.write_str(s)
    }
}

/// Алиас для `Result` с `ThresholdIdentityError` в качестве типа ошибки.
/// Result alias.
pub type ThresholdIdentityResult<T> = core::result::Result<T, ThresholdIdentityError>;

impl From<frost_ed25519::Error> for ThresholdIdentityError {
    fn from(e: frost_ed25519::Error) -> Self {
        Self::Frost(format!("{e}"))
    }
}
