//! Конфигурация максимального ratchet режима.
//!
//! Все защиты включены по умолчанию через [`MaxRatchetConfig::default()`]. Конструктор
//! [`MaxRatchetConfig::with_overrides`] используется только для тестов либо для
//! tier-aware конфигураций (например, временно отключить таймер при benchmark'е).
//!
//! Configuration for max ratchet mode.
//!
//! All defences are enabled by default via [`MaxRatchetConfig::default()`]. The
//! [`MaxRatchetConfig::with_overrides`] constructor is only for tests or tier-aware
//! configurations (e.g. temporarily disabling the timer for a benchmark).

/// Параметры максимального ratchet режима.
///
/// По умолчанию все защиты включены — это и есть «максимум для всех пользователей v3».
///
/// Max ratchet mode parameters. By default all defences are enabled — this is the
/// «maximum for all v3 users» setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxRatchetConfig {
    /// Делать DH-храповик через MLS commit перед каждой отправкой сообщения.
    /// Run a DH ratchet via MLS commit before every outgoing message.
    pub aggressive_dh_per_message: bool,
    /// Период таймера принудительного rekey в секундах (по умолчанию 300 = 5 минут).
    /// Forced rekey timer period in seconds (default 300 = 5 minutes).
    pub timer_rekey_seconds: u64,
    /// Каждый N-й commit дополнительно прогонять через X-Wing post-quantum combine.
    /// 0 = отключено.
    /// Run X-Wing post-quantum combine on every N-th commit; 0 = disabled.
    pub pq_ratchet_every_n_commits: u32,
    /// Добавлять SPQR HMAC к каждому application-сообщению (отрицаемая аутентификация).
    /// Attach an SPQR HMAC to every application message (deniable authentication).
    pub spqr_deniable_auth: bool,
}

impl Default for MaxRatchetConfig {
    /// Production default — все защиты включены. Не менять без явного приказа архитектора.
    ///
    /// Production default — all defences enabled. Do not change without explicit
    /// architect approval.
    fn default() -> Self {
        Self {
            aggressive_dh_per_message: true,
            timer_rekey_seconds: 300,
            pq_ratchet_every_n_commits: 3,
            spqr_deniable_auth: true,
        }
    }
}

impl MaxRatchetConfig {
    /// Конструктор только для тестов — позволяет переопределить отдельные параметры.
    /// Constructor for tests only — allows per-field overrides.
    pub fn with_overrides(
        aggressive_dh_per_message: bool,
        timer_rekey_seconds: u64,
        pq_ratchet_every_n_commits: u32,
        spqr_deniable_auth: bool,
    ) -> Self {
        Self {
            aggressive_dh_per_message,
            timer_rekey_seconds,
            pq_ratchet_every_n_commits,
            spqr_deniable_auth,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_enables_all_defences() {
        let cfg = MaxRatchetConfig::default();
        assert!(cfg.aggressive_dh_per_message);
        assert_eq!(cfg.timer_rekey_seconds, 300);
        assert_eq!(cfg.pq_ratchet_every_n_commits, 3);
        assert!(cfg.spqr_deniable_auth);
    }

    #[test]
    fn with_overrides_lets_tests_disable_individual_defences() {
        let cfg = MaxRatchetConfig::with_overrides(false, 60, 2, false);
        assert!(!cfg.aggressive_dh_per_message);
        assert_eq!(cfg.timer_rekey_seconds, 60);
        assert_eq!(cfg.pq_ratchet_every_n_commits, 2);
        assert!(!cfg.spqr_deniable_auth);
    }
}
