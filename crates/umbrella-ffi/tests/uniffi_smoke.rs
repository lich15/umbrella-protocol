//! Smoke-тесты FFI Records: roundtrip + length validation на FFI границе.
//! Проверяют что uniffi::Record types в [`umbrella_ffi::types`] корректно
//! конвертируются в Rust types через [`TryFrom`] / [`From`].
//!
//! Smoke tests for FFI Records: roundtrip + length validation at the FFI
//! boundary. Verify that uniffi::Record types in [`umbrella_ffi::types`]
//! convert to and from Rust types through [`TryFrom`] / [`From`].

use umbrella_calls::{CallPolicy, RoutingMode};
use umbrella_client::facade::chat_common::{ChatId, PeerId};
use umbrella_ffi::{CallPolicyFfi, ChatIdFfi, PeerIdFfi};

#[test]
fn chat_id_roundtrip() {
    let ffi = ChatIdFfi {
        bytes: vec![0x42; 32],
    };
    let rust: ChatId = ffi.clone().try_into().unwrap();
    assert_eq!(rust.0, [0x42u8; 32]);
    let back: ChatIdFfi = rust.into();
    assert_eq!(back.bytes, ffi.bytes);
}

#[test]
fn chat_id_too_short_errors() {
    let ffi = ChatIdFfi {
        bytes: vec![0x42; 10],
    };
    let result: Result<ChatId, _> = ffi.try_into();
    assert!(result.is_err());
}

#[test]
fn chat_id_too_long_errors() {
    let ffi = ChatIdFfi {
        bytes: vec![0x42; 64],
    };
    let result: Result<ChatId, _> = ffi.try_into();
    assert!(result.is_err());
}

#[test]
fn peer_id_roundtrip() {
    let ffi = PeerIdFfi {
        bytes: vec![0xAA; 32],
    };
    let rust: PeerId = ffi.clone().try_into().unwrap();
    assert_eq!(rust.0, [0xAAu8; 32]);
    let back: PeerIdFfi = rust.into();
    assert_eq!(back.bytes, ffi.bytes);
}

#[test]
fn peer_id_wrong_length_errors() {
    let ffi = PeerIdFfi {
        bytes: vec![0xAA; 5],
    };
    let result: Result<PeerId, _> = ffi.try_into();
    assert!(result.is_err());
}

#[test]
fn call_policy_default_routing_mapping() {
    for (idx, expected) in [
        (0u8, RoutingMode::DirectP2P),
        (1, RoutingMode::SingleRelay),
        (2, RoutingMode::DoubleRelay),
        (3, RoutingMode::CloudRelayFallback),
    ] {
        let ffi = CallPolicyFfi {
            default_routing: idx,
            sensitive_peers: vec![],
            allow_p2p_global: false,
        };
        let rust: CallPolicy = ffi.into();
        assert_eq!(rust.default_routing, expected, "idx={idx}");
    }
}

#[test]
fn call_policy_unknown_idx_falls_back_to_cloud_relay() {
    let ffi = CallPolicyFfi {
        default_routing: 99,
        sensitive_peers: vec![],
        allow_p2p_global: false,
    };
    let rust: CallPolicy = ffi.into();
    assert_eq!(rust.default_routing, RoutingMode::CloudRelayFallback);
}

#[test]
fn call_policy_sensitive_peers_correct_length_kept() {
    let ffi = CallPolicyFfi {
        default_routing: 1,
        sensitive_peers: vec![
            PeerIdFfi {
                bytes: vec![0x11; 32],
            },
            PeerIdFfi {
                bytes: vec![0x22; 32],
            },
        ],
        allow_p2p_global: false,
    };
    let rust: CallPolicy = ffi.into();
    assert_eq!(rust.sensitive_contacts.len(), 2);
}

#[test]
fn call_policy_wrong_length_peers_dropped() {
    let ffi = CallPolicyFfi {
        default_routing: 1,
        sensitive_peers: vec![
            PeerIdFfi {
                bytes: vec![0x11; 32],
            },
            PeerIdFfi {
                bytes: vec![0x22; 5], // wrong length — silent drop.
            },
        ],
        allow_p2p_global: false,
    };
    let rust: CallPolicy = ffi.into();
    assert_eq!(rust.sensitive_contacts.len(), 1);
}

#[test]
fn call_policy_allow_p2p_passthrough() {
    let ffi = CallPolicyFfi {
        default_routing: 0, // DirectP2P
        sensitive_peers: vec![],
        allow_p2p_global: true,
    };
    let rust: CallPolicy = ffi.into();
    assert!(rust.allow_p2p_global);
    assert_eq!(rust.default_routing, RoutingMode::DirectP2P);
}
