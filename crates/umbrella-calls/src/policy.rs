//! [`CallPolicy`] + [`RoutingMode`] + [`PeerId`] — пользовательская политика
//! маршрутизации звонков (ADR-2026-04-20-23 Вариант B++).
//!
//! **Крейт не выполняет routing.** Он только вычисляет `effective_routing` /
//! `effective_level` для конкретного peer'а — фактическое исполнение ICE/STUN
//! /TURN/SFU происходит в `umbrella-client` + native-bridges на Этапе 7.
//!
//! Стратегия:
//!
//! - Default `SingleRelay` — IP собеседника скрыт за TURN.
//! - Sensitive-контакты override-ятся в `DoubleRelay` (два relay в разных
//!   юрисдикциях) независимо от `default_routing`.
//! - `allow_p2p_global` — glob opt-in: даже если default P2P, без него
//!   fallback на SingleRelay.
//!
//! [`CallPolicy`] + [`RoutingMode`] + [`PeerId`] — user-level call-routing
//! policy (ADR-2026-04-20-23 Variant B++).
//!
//! **The crate does not execute routing.** It only computes
//! `effective_routing` / `effective_level` for a given peer — actual
//! ICE/STUN/TURN/SFU execution happens in `umbrella-client` + native bridges
//! at Stage 7.
//!
//! Strategy:
//!
//! - Default `SingleRelay` — peer IP hidden behind TURN.
//! - Sensitive contacts are overridden to `DoubleRelay` (two relays in
//!   different jurisdictions) regardless of `default_routing`.
//! - `allow_p2p_global` — global opt-in: even if default is P2P, without
//!   it we fall back to SingleRelay.

use std::collections::HashSet;

use crate::level::CallSecurityLevel;

/// Идентификатор контакта — 32-байтовый Ed25519 identity pubkey из KT.
///
/// Peer identifier — 32-byte Ed25519 identity pubkey from KT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    /// Bytes accessor для сравнения / логирования.
    /// Bytes accessor for comparison / logging.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Стратегия маршрутизации 1-1 звонка.
///
/// Routing mode for a 1-1 call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoutingMode {
    /// Прямой P2P через ICE/STUN. IP собеседника раскрывается — только opt-in.
    /// Direct P2P via ICE/STUN. Peer IP is exposed — opt-in only.
    DirectP2P,
    /// Один TURN relay — default (ADR-23).
    /// Single TURN relay — default (ADR-23).
    SingleRelay,
    /// Два TURN relay в разных юрисдикциях.
    /// Two TURN relays in different jurisdictions.
    DoubleRelay,
    /// Cloud-relay fallback для стран с deep packet inspection.
    /// Cloud-relay fallback for countries with deep packet inspection.
    CloudRelayFallback,
}

impl RoutingMode {
    /// Маппинг в [`CallSecurityLevel`] для UI.
    ///
    /// `CloudRelayFallback` → `E2eSingleRelay` — с точки зрения пользователя
    /// это один relay (просто другой серверный путь), один level UI индикатора.
    ///
    /// Maps to [`CallSecurityLevel`] for UI.
    ///
    /// `CloudRelayFallback` → `E2eSingleRelay` — from the user's perspective
    /// it is still one relay (different server path), same UI indicator.
    pub fn to_security_level(&self) -> CallSecurityLevel {
        match self {
            Self::DirectP2P => CallSecurityLevel::E2eDirect,
            Self::SingleRelay | Self::CloudRelayFallback => CallSecurityLevel::E2eSingleRelay,
            Self::DoubleRelay => CallSecurityLevel::E2eDoubleRelay,
        }
    }
}

/// Политика звонков пользователя. Крейт не выполняет routing — только
/// вычисляет `effective_mode` / `effective_level` для конкретного peer'а.
///
/// User's call policy. The crate does NOT execute routing — only computes
/// `effective_mode` / `effective_level` per peer.
#[derive(Clone)]
pub struct CallPolicy {
    /// Default routing для непомеченных контактов. По ADR-23 — `SingleRelay`.
    /// Default routing for unmarked contacts. Per ADR-23 — `SingleRelay`.
    pub default_routing: RoutingMode,

    /// Контакты, помеченные как «sensitive» — всегда `DoubleRelay` override.
    /// Contacts marked "sensitive" — always overridden to `DoubleRelay`.
    pub sensitive_contacts: HashSet<PeerId>,

    /// Разрешить direct P2P глобально (IP раскрывается). Default: `false`.
    /// Без `true` `DirectP2P` в `default_routing` fallback-ится на `SingleRelay`.
    ///
    /// Allow direct P2P globally (IP exposed). Default: `false`.
    /// Without `true`, `DirectP2P` in `default_routing` falls back to
    /// `SingleRelay`.
    pub allow_p2p_global: bool,
}

/// `Debug` не раскрывает список sensitive-контактов.
/// `Debug` does not reveal the sensitive-contact list.
impl core::fmt::Debug for CallPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CallPolicy")
            .field("default_routing", &self.default_routing)
            .field("sensitive_contacts_len", &self.sensitive_contacts.len())
            .field("sensitive_contacts", &"<redacted>")
            .field("allow_p2p_global", &self.allow_p2p_global)
            .finish()
    }
}

impl Default for CallPolicy {
    fn default() -> Self {
        Self {
            default_routing: RoutingMode::SingleRelay,
            sensitive_contacts: HashSet::new(),
            allow_p2p_global: false,
        }
    }
}

impl CallPolicy {
    /// Эффективный routing для указанного peer'а.
    ///
    /// Порядок приоритетов:
    /// 1. `peer ∈ sensitive_contacts` → `DoubleRelay` (sensitive всегда выигрывает).
    /// 2. `default_routing == DirectP2P ∧ !allow_p2p_global` → `SingleRelay`
    ///    (P2P глобально запрещён, fallback).
    /// 3. Иначе — `default_routing`.
    ///
    /// Effective routing for a given peer.
    ///
    /// Priority:
    /// 1. `peer ∈ sensitive_contacts` → `DoubleRelay` (sensitive always wins).
    /// 2. `default_routing == DirectP2P ∧ !allow_p2p_global` → `SingleRelay`
    ///    (P2P globally disallowed, fallback).
    /// 3. Otherwise — `default_routing`.
    pub fn effective_routing(&self, peer: &PeerId) -> RoutingMode {
        if self.sensitive_contacts.contains(peer) {
            return RoutingMode::DoubleRelay;
        }
        match self.default_routing {
            RoutingMode::DirectP2P if !self.allow_p2p_global => RoutingMode::SingleRelay,
            other => other,
        }
    }

    /// Security level для UI (через [`Self::effective_routing`]).
    ///
    /// Security level for UI (via [`Self::effective_routing`]).
    pub fn effective_level(&self, peer: &PeerId) -> CallSecurityLevel {
        self.effective_routing(peer).to_security_level()
    }

    /// Пометить контакт как sensitive.
    /// Возвращает `true` если контакт был добавлен (`false` если уже был).
    ///
    /// Mark a contact as sensitive.
    /// Returns `true` if the contact was newly inserted (`false` if already present).
    pub fn mark_sensitive(&mut self, peer: PeerId) -> bool {
        self.sensitive_contacts.insert(peer)
    }

    /// Снять пометку sensitive.
    /// Возвращает `true` если контакт был удалён (`false` если не был в списке).
    ///
    /// Unmark a sensitive contact.
    /// Returns `true` if the contact was removed (`false` if it was not in the set).
    pub fn unmark_sensitive(&mut self, peer: &PeerId) -> bool {
        self.sensitive_contacts.remove(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(byte: u8) -> PeerId {
        PeerId([byte; 32])
    }

    #[test]
    fn call_policy_debug_redacts_sensitive_contacts() {
        let mut p = CallPolicy::default();
        p.mark_sensitive(peer(0xAA));

        let debug = format!("{p:?}");

        assert!(
            !debug.contains("170, 170, 170"),
            "Debug output must not leak sensitive contact identifiers: {debug}"
        );
        assert!(
            debug.contains("sensitive_contacts_len"),
            "Debug output should keep sensitive-contact count for diagnostics: {debug}"
        );
    }

    #[test]
    fn default_policy_is_single_relay_no_p2p() {
        let p = CallPolicy::default();
        assert_eq!(p.default_routing, RoutingMode::SingleRelay);
        assert!(p.sensitive_contacts.is_empty());
        assert!(!p.allow_p2p_global);
    }

    #[test]
    fn unmarked_contact_uses_default() {
        let p = CallPolicy::default();
        assert_eq!(p.effective_routing(&peer(0x01)), RoutingMode::SingleRelay);
    }

    #[test]
    fn sensitive_contact_forces_double_relay() {
        let mut p = CallPolicy::default();
        p.mark_sensitive(peer(0xAA));
        assert_eq!(p.effective_routing(&peer(0xAA)), RoutingMode::DoubleRelay);
        assert_eq!(p.effective_routing(&peer(0xBB)), RoutingMode::SingleRelay);
    }

    #[test]
    fn sensitive_overrides_default_p2p() {
        let mut p = CallPolicy {
            default_routing: RoutingMode::DirectP2P,
            allow_p2p_global: true,
            ..Default::default()
        };
        p.mark_sensitive(peer(0xAA));
        // Sensitive приоритет даже при разрешённом P2P.
        // Sensitive wins even when P2P is allowed.
        assert_eq!(p.effective_routing(&peer(0xAA)), RoutingMode::DoubleRelay);
        assert_eq!(p.effective_routing(&peer(0xBB)), RoutingMode::DirectP2P);
    }

    #[test]
    fn allow_p2p_false_blocks_direct_p2p() {
        let p = CallPolicy {
            default_routing: RoutingMode::DirectP2P,
            allow_p2p_global: false,
            ..Default::default()
        };
        // P2P заблокирован → fallback SingleRelay.
        // P2P blocked → fallback to SingleRelay.
        assert_eq!(p.effective_routing(&peer(0xCC)), RoutingMode::SingleRelay);
    }

    #[test]
    fn allow_p2p_true_permits_direct_p2p() {
        let p = CallPolicy {
            default_routing: RoutingMode::DirectP2P,
            allow_p2p_global: true,
            ..Default::default()
        };
        assert_eq!(p.effective_routing(&peer(0xCC)), RoutingMode::DirectP2P);
    }

    #[test]
    fn effective_level_maps_correctly() {
        let mut p = CallPolicy::default();
        assert_eq!(
            p.effective_level(&peer(1)),
            CallSecurityLevel::E2eSingleRelay
        );
        p.mark_sensitive(peer(2));
        assert_eq!(
            p.effective_level(&peer(2)),
            CallSecurityLevel::E2eDoubleRelay
        );
    }

    #[test]
    fn routing_mode_to_level_mapping() {
        assert_eq!(
            RoutingMode::DirectP2P.to_security_level(),
            CallSecurityLevel::E2eDirect
        );
        assert_eq!(
            RoutingMode::SingleRelay.to_security_level(),
            CallSecurityLevel::E2eSingleRelay
        );
        assert_eq!(
            RoutingMode::DoubleRelay.to_security_level(),
            CallSecurityLevel::E2eDoubleRelay
        );
        assert_eq!(
            RoutingMode::CloudRelayFallback.to_security_level(),
            CallSecurityLevel::E2eSingleRelay
        );
    }

    #[test]
    fn mark_unmark_sensitive_returns_bool() {
        let mut p = CallPolicy::default();
        assert!(p.mark_sensitive(peer(1))); // newly inserted.
        assert!(!p.mark_sensitive(peer(1))); // уже есть.
        assert!(p.unmark_sensitive(&peer(1))); // existed.
        assert!(!p.unmark_sensitive(&peer(1))); // уже удалён.
    }

    #[test]
    fn hashset_dedup_sensitive() {
        let mut p = CallPolicy::default();
        p.mark_sensitive(peer(5));
        p.mark_sensitive(peer(5));
        p.mark_sensitive(peer(5));
        assert_eq!(p.sensitive_contacts.len(), 1);
    }

    #[test]
    fn cloud_relay_fallback_single_level() {
        let p = CallPolicy {
            default_routing: RoutingMode::CloudRelayFallback,
            ..Default::default()
        };
        assert_eq!(
            p.effective_routing(&peer(1)),
            RoutingMode::CloudRelayFallback
        );
        assert_eq!(
            p.effective_level(&peer(1)),
            CallSecurityLevel::E2eSingleRelay
        );
    }

    #[test]
    fn peer_id_hash_unique_per_pubkey() {
        let mut set = HashSet::new();
        set.insert(peer(1));
        set.insert(peer(1));
        set.insert(peer(2));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn peer_id_as_bytes_returns_inner() {
        let p = peer(0x77);
        assert_eq!(p.as_bytes(), &[0x77; 32]);
    }
}
