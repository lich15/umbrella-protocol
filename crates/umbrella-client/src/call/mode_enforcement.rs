//! `ModeEnforcement` — enforce mode-specific ограничений над user-provided
//! [`CallPolicy`]. CloudChat respect'ит user policy целиком; SecretChat
//! принудительно strip'ает direct P2P (SPEC-06 §3): `allow_p2p_global` →
//! `false`, `RoutingMode::DirectP2P` → `RoutingMode::SingleRelay`.
//!
//! Этот enforcement — вторая линия обороны поверх
//! [`ice_agent::IceAgent::new_no_p2p`](super::ice_agent::IceAgent::new_no_p2p):
//! даже если user передал aggressive policy, enforcement гарантирует что
//! `effective_policy` отражает мод чата, и ICE agent строится соответственно.
//! Физическая невозможность direct P2P обеспечивается `AgentConfig`
//! (только `CandidateType::Relay`), не логикой enforcement.
//!
//! `ModeEnforcement` enforces mode-specific restrictions on the
//! user-provided [`CallPolicy`]. CloudChat respects the user policy
//! verbatim; SecretChat strips direct P2P (SPEC-06 §3):
//! `allow_p2p_global` → `false`, `RoutingMode::DirectP2P` →
//! `RoutingMode::SingleRelay`.
//!
//! This enforcement is the second line of defense layered on
//! [`ice_agent::IceAgent::new_no_p2p`](super::ice_agent::IceAgent::new_no_p2p):
//! even if the user supplied an aggressive policy, enforcement guarantees
//! that `effective_policy` reflects the chat mode and the ICE agent is built
//! accordingly. The physical impossibility of direct P2P comes from
//! `AgentConfig` (only `CandidateType::Relay`), not from enforcement logic.

use umbrella_calls::{CallPolicy, RoutingMode};

/// Режим enforcement — по типу фасада.
///
/// Enforcement mode — keyed by the facade type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeEnforcement {
    /// CloudChat — user policy проходит без изменений.
    ///
    /// CloudChat — user policy passes through unchanged.
    CloudMode,
    /// SecretChat — force `allow_p2p_global = false` и strip `DirectP2P`
    /// из `default_routing`. `sensitive_contacts` сохраняется (он и так
    /// override'ит на `DoubleRelay`, более строгий чем `SingleRelay`).
    ///
    /// SecretChat — force `allow_p2p_global = false` and strip `DirectP2P`
    /// from `default_routing`. `sensitive_contacts` is preserved (it already
    /// overrides to `DoubleRelay`, stricter than `SingleRelay`).
    SecretMode,
}

impl ModeEnforcement {
    /// Применяет enforcement к user-provided policy.
    ///
    /// Applies enforcement to the user-provided policy.
    #[must_use]
    pub fn apply(&self, user_policy: CallPolicy) -> CallPolicy {
        match self {
            ModeEnforcement::CloudMode => user_policy,
            ModeEnforcement::SecretMode => CallPolicy {
                default_routing: strip_p2p(user_policy.default_routing),
                sensitive_contacts: user_policy.sensitive_contacts,
                allow_p2p_global: false,
            },
        }
    }
}

fn strip_p2p(routing: RoutingMode) -> RoutingMode {
    match routing {
        RoutingMode::DirectP2P => RoutingMode::SingleRelay,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use umbrella_calls::PeerId;

    fn aggressive_policy() -> CallPolicy {
        let mut sensitive = HashSet::new();
        sensitive.insert(PeerId([0xAA; 32]));
        CallPolicy {
            default_routing: RoutingMode::DirectP2P,
            sensitive_contacts: sensitive,
            allow_p2p_global: true,
        }
    }

    #[test]
    fn cloud_mode_passthrough() {
        let policy = aggressive_policy();
        let enforced = ModeEnforcement::CloudMode.apply(policy.clone());
        assert_eq!(enforced.default_routing, policy.default_routing);
        assert_eq!(enforced.allow_p2p_global, policy.allow_p2p_global);
        assert_eq!(enforced.sensitive_contacts, policy.sensitive_contacts);
    }

    #[test]
    fn secret_mode_forces_allow_p2p_false() {
        let enforced = ModeEnforcement::SecretMode.apply(aggressive_policy());
        assert!(!enforced.allow_p2p_global);
    }

    #[test]
    fn secret_mode_strips_direct_p2p_to_single_relay() {
        let enforced = ModeEnforcement::SecretMode.apply(aggressive_policy());
        assert_eq!(enforced.default_routing, RoutingMode::SingleRelay);
    }

    #[test]
    fn secret_mode_preserves_non_p2p_routing() {
        let p = CallPolicy {
            default_routing: RoutingMode::DoubleRelay,
            ..Default::default()
        };
        let enforced = ModeEnforcement::SecretMode.apply(p);
        assert_eq!(enforced.default_routing, RoutingMode::DoubleRelay);
    }

    #[test]
    fn secret_mode_preserves_cloud_relay_fallback() {
        let p = CallPolicy {
            default_routing: RoutingMode::CloudRelayFallback,
            ..Default::default()
        };
        let enforced = ModeEnforcement::SecretMode.apply(p);
        assert_eq!(enforced.default_routing, RoutingMode::CloudRelayFallback);
    }

    #[test]
    fn secret_mode_preserves_sensitive_contacts() {
        let enforced = ModeEnforcement::SecretMode.apply(aggressive_policy());
        assert!(enforced.sensitive_contacts.contains(&PeerId([0xAA; 32])));
    }

    #[test]
    fn secret_mode_effective_routing_for_sensitive_is_double_relay() {
        // После enforcement sensitive-контакт всё равно форсится в DoubleRelay
        // через CallPolicy::effective_routing — проверяем integration.
        //
        // After enforcement a sensitive contact is still promoted to
        // DoubleRelay via CallPolicy::effective_routing — integration check.
        let enforced = ModeEnforcement::SecretMode.apply(aggressive_policy());
        let peer = PeerId([0xAA; 32]);
        assert_eq!(enforced.effective_routing(&peer), RoutingMode::DoubleRelay);
    }

    #[test]
    fn secret_mode_effective_routing_for_unknown_peer_is_single_relay() {
        let enforced = ModeEnforcement::SecretMode.apply(aggressive_policy());
        let peer = PeerId([0xCC; 32]);
        assert_eq!(enforced.effective_routing(&peer), RoutingMode::SingleRelay);
    }

    #[test]
    fn cloud_mode_respects_allow_p2p_for_direct_routing() {
        let enforced = ModeEnforcement::CloudMode.apply(aggressive_policy());
        let peer = PeerId([0xCC; 32]);
        assert_eq!(enforced.effective_routing(&peer), RoutingMode::DirectP2P);
    }
}
