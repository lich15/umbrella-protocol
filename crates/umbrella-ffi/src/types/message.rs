//! `MessageFfi` + `CallPolicyFfi` — uniffi Records.
//!
//! `MessageFfi` + `CallPolicyFfi` — uniffi Records.

use std::collections::HashSet;

use umbrella_calls::{CallPolicy, PeerId as CallsPeerId, RoutingMode};

use crate::types::{ChatIdFfi, PeerIdFfi};

/// FFI представление расшифрованного сообщения.
///
/// FFI representation of a decrypted message.
#[derive(Clone, Debug, uniffi::Record)]
pub struct MessageFfi {
    /// 16-байтовый opaque message id.
    ///
    /// 16-byte opaque message id.
    pub message_id: Vec<u8>,
    /// Чат сообщения.
    ///
    /// Chat the message belongs to.
    pub chat_id: ChatIdFfi,
    /// Отправитель.
    ///
    /// Sender.
    pub sender: PeerIdFfi,
    /// Unix-timestamp в миллисекундах (по часам отправителя).
    ///
    /// Unix-epoch timestamp in milliseconds (sender clock).
    pub timestamp_unix_millis: u64,
    /// Plaintext текст. `None` — сообщение существует, но без текстового
    /// payload (media-only / system event в будущих блоках).
    ///
    /// Plaintext message body. `None` when the message exists but has no
    /// text payload (media-only / system event in future blocks).
    pub text: Option<String>,
}

/// FFI представление [`CallPolicy`].
///
/// FFI representation of [`CallPolicy`].
#[derive(Clone, Debug, uniffi::Record)]
pub struct CallPolicyFfi {
    /// 0 = `DirectP2P`, 1 = `SingleRelay`, 2 = `DoubleRelay`,
    /// 3+ = `CloudRelayFallback`.
    ///
    /// 0 = `DirectP2P`, 1 = `SingleRelay`, 2 = `DoubleRelay`,
    /// 3+ = `CloudRelayFallback`.
    pub default_routing: u8,
    /// Контакты помеченные «sensitive» — overrider'ятся в `DoubleRelay`.
    ///
    /// Contacts marked "sensitive" — overridden to `DoubleRelay`.
    pub sensitive_peers: Vec<PeerIdFfi>,
    /// Глобальный opt-in для direct P2P. SecretChat игнорирует
    /// (см. [`umbrella_client::call::ModeEnforcement::SecretMode`]).
    ///
    /// Global opt-in for direct P2P. SecretChat ignores this
    /// (see [`umbrella_client::call::ModeEnforcement::SecretMode`]).
    pub allow_p2p_global: bool,
}

impl From<CallPolicyFfi> for CallPolicy {
    fn from(v: CallPolicyFfi) -> Self {
        let default_routing = match v.default_routing {
            0 => RoutingMode::DirectP2P,
            1 => RoutingMode::SingleRelay,
            2 => RoutingMode::DoubleRelay,
            _ => RoutingMode::CloudRelayFallback,
        };
        // Игнорируем wrong-length peer'ов: на FFI границе невозможно вернуть
        // частичный валидный CallPolicy если part of input корректна — мы
        // вместо этого silent-drop'аем некорректные. Вызывающие FFI код
        // обязан валидировать длины предварительно.
        //
        // Wrong-length peers are dropped: the FFI boundary cannot return a
        // partial CallPolicy when only some inputs are valid. Callers are
        // expected to validate lengths upstream.
        let sensitive_contacts: HashSet<CallsPeerId> = v
            .sensitive_peers
            .into_iter()
            .filter_map(|p| {
                if p.bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&p.bytes);
                    Some(CallsPeerId(arr))
                } else {
                    None
                }
            })
            .collect();
        CallPolicy {
            default_routing,
            sensitive_contacts,
            allow_p2p_global: v.allow_p2p_global,
        }
    }
}
