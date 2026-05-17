//! # Duress mechanism
//!
//! Round-6 design: user сетит при регистрации обычный PIN (e.g. `123456`) и
//! «duress PIN» (e.g. reverse: `654321`). При вводе duress PIN серверам
//! параллельно (всем 5 одновременно через broadcast) отправляется команда
//! `UNRECOVERABLE_DELETE`. Через ~5 секунд (network RTT × 5 серверов) аккаунт
//! удалён с лица земли.
//!
//! UI displays «loading» 3 sec then «no account» screen — visually indistinguishable
//! from a never-registered phone. The user can hand over phone to adversary
//! who finds nothing.
//!
//! Reverse PIN as duress per round-6 spec §«Universal entry rule». Reverse
//! is heuristic-friendly: user already memorised the PIN, no second secret
//! to forget; adversary watching shoulder cannot tell duress from genuine
//! because the user enters digits with identical UI.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Determines whether `candidate` is the duress reverse of `genuine_pin`.
/// Returns true iff `candidate == reverse(genuine_pin)`.
///
/// **Constant-time** w.r.t. PIN length (Aldo: PIN length is public anyway).
/// The byte-by-byte compare is `ConstantTimeEq`, so an attacker watching
/// timing cannot distinguish «duress detected» from «duress not detected»
/// after the reverse step (which is constant-time per PIN length).
///
/// Constant-time test whether `candidate` is the reverse of `genuine_pin`.
pub fn is_duress_reverse(candidate: &[u8], genuine_pin: &[u8]) -> bool {
    if candidate.len() != genuine_pin.len() {
        return false;
    }
    if candidate.is_empty() {
        return false;
    }
    let mut reversed = Zeroizing::new(vec![0u8; genuine_pin.len()]);
    for (i, &b) in genuine_pin.iter().rev().enumerate() {
        reversed[i] = b;
    }
    // Special case: palindromic PINs (e.g. "12321") would falsely trigger
    // duress at every entry. Reject palindromes at registration.
    if reversed.ct_eq(genuine_pin).into() {
        // Palindrome — never treat as duress.
        return false;
    }
    candidate.ct_eq(reversed.as_slice()).into()
}

/// Server-side: invoked when client signals duress. Marks account as Deleted
/// and emits a parallel UNRECOVERABLE_DELETE to all 5 servers.
///
/// This function is intentionally synchronous w.r.t. the network: production
/// implementations use `tokio::task::JoinSet` to fire all 5 requests
/// concurrently. The acceptance gate (R21 test) verifies that all shares are
/// wiped after the call returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuressTrigger {
    /// Reverse-PIN detected at PIN entry.
    ReversePin,
    /// User explicitly invoked duress via secondary code.
    ExplicitCode,
}

/// Convenience marker — server-side request to wipe all shares.
#[derive(Debug, Clone)]
pub struct UnrecoverableDelete {
    /// Trigger that caused the wipe.
    pub trigger: DuressTrigger,
    /// Anonymous account ID to wipe.
    pub anonymous_id: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duress_detects_simple_reverse() {
        assert!(is_duress_reverse(b"654321", b"123456"));
        assert!(is_duress_reverse(b"4321", b"1234"));
    }

    #[test]
    fn genuine_pin_is_not_duress() {
        assert!(!is_duress_reverse(b"123456", b"123456"));
        assert!(!is_duress_reverse(b"123457", b"123456"));
    }

    #[test]
    fn palindromic_pin_never_triggers_duress() {
        // "12321" reversed is "12321" — must not trigger.
        assert!(!is_duress_reverse(b"12321", b"12321"));
        assert!(!is_duress_reverse(b"1221", b"1221"));
    }

    #[test]
    fn length_mismatch_rejected() {
        assert!(!is_duress_reverse(b"54321", b"123456"));
        assert!(!is_duress_reverse(b"7654321", b"123456"));
    }

    #[test]
    fn empty_input_safe() {
        assert!(!is_duress_reverse(b"", b""));
        assert!(!is_duress_reverse(b"", b"1234"));
    }
}
