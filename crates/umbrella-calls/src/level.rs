//! [`CallSecurityLevel`] — уровень защиты звонка для UI индикатора.
//!
//! Крейт криптографически поддерживает только три E2E-варианта; четвёртый
//! [`CallSecurityLevel::NotE2eServerMixed`] экспортирован исключительно как
//! UI-индикатор для больших комнат, где сервер микширует plaintext audio
//! (это явное not-E2E обещание SPEC-06 §2).
//!
//! Display-impl форматирует двойной RU+EN лейбл — приложение получает
//! готовую строку и может использовать её напрямую в UI.
//!
//! [`CallSecurityLevel`] — call security level for UI indicators.
//!
//! The crate cryptographically supports only the three E2E variants; the
//! fourth [`CallSecurityLevel::NotE2eServerMixed`] is exported purely as a
//! UI indicator for large rooms where the server mixes plaintext audio
//! (the explicit not-E2E promise of SPEC-06 §2).
//!
//! The Display impl renders a dual RU+EN label — the application gets a
//! ready string it can put straight in the UI.

use core::fmt;

/// Четыре возможных уровня защиты звонка. Первые три — E2E (крейт реализует
/// криптографически), четвёртый — server-mixed NotE2E (крейт не участвует,
/// используется только как UI индикатор большой комнаты).
///
/// Four possible call security levels. The first three are E2E (realised
/// cryptographically by the crate); the fourth is server-mixed NotE2E
/// (the crate is not involved, used only as a UI indicator for large rooms).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallSecurityLevel {
    /// E2E через direct P2P (ICE/STUN). IP собеседника виден — opt-in только.
    /// E2E via direct P2P (ICE/STUN). Peer IP visible — opt-in only.
    E2eDirect,
    /// E2E через один TURN relay. Default при `CallPolicy::default()`.
    /// E2E via a single TURN relay. Default for `CallPolicy::default()`.
    E2eSingleRelay,
    /// E2E через два TURN relay в разных юрисдикциях. Sensitive-контакты / opt-in.
    /// E2E via two TURN relays in different jurisdictions. Sensitive contacts / opt-in.
    E2eDoubleRelay,
    /// Сервер микширует plaintext audio — **не E2E**. Только UI-индикатор
    /// для комнат ≥ 32 участников (SPEC-06 §2 третий класс).
    ///
    /// Server mixes plaintext audio — **not E2E**. UI indicator only for
    /// rooms of ≥ 32 participants (SPEC-06 §2 third class).
    NotE2eServerMixed,
}

impl CallSecurityLevel {
    /// `true` если звонок end-to-end шифрован (первые три варианта).
    /// `true` if the call is end-to-end encrypted (first three variants).
    pub fn is_e2e(&self) -> bool {
        !matches!(self, Self::NotE2eServerMixed)
    }

    /// `true` если IP собеседника скрыт от него (relay-режимы).
    /// `true` if peer IP is hidden from them (relay modes).
    pub fn hides_ip(&self) -> bool {
        matches!(self, Self::E2eSingleRelay | Self::E2eDoubleRelay)
    }
}

impl fmt::Display for CallSecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (ru, en) = match self {
            Self::E2eDirect => ("Прямое соединение", "Direct connection"),
            Self::E2eSingleRelay => ("Шифр через ретранслятор", "Encrypted via relay"),
            Self::E2eDoubleRelay => ("Через два ретранслятора", "Via two relays"),
            Self::NotE2eServerMixed => ("Не end-to-end", "Not end-to-end"),
        };
        write!(f, "{ru} / {en}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_ru_en_format_all_variants() {
        assert_eq!(
            format!("{}", CallSecurityLevel::E2eDirect),
            "Прямое соединение / Direct connection"
        );
        assert_eq!(
            format!("{}", CallSecurityLevel::E2eSingleRelay),
            "Шифр через ретранслятор / Encrypted via relay"
        );
        assert_eq!(
            format!("{}", CallSecurityLevel::E2eDoubleRelay),
            "Через два ретранслятора / Via two relays"
        );
        assert_eq!(
            format!("{}", CallSecurityLevel::NotE2eServerMixed),
            "Не end-to-end / Not end-to-end"
        );
    }

    #[test]
    fn is_e2e_correct() {
        assert!(CallSecurityLevel::E2eDirect.is_e2e());
        assert!(CallSecurityLevel::E2eSingleRelay.is_e2e());
        assert!(CallSecurityLevel::E2eDoubleRelay.is_e2e());
        assert!(!CallSecurityLevel::NotE2eServerMixed.is_e2e());
    }

    #[test]
    fn hides_ip_correct() {
        assert!(!CallSecurityLevel::E2eDirect.hides_ip());
        assert!(CallSecurityLevel::E2eSingleRelay.hides_ip());
        assert!(CallSecurityLevel::E2eDoubleRelay.hides_ip());
        assert!(!CallSecurityLevel::NotE2eServerMixed.hides_ip());
    }
}
