//! `MessageFfi` + `CallPolicyFfi` — uniffi Records.
//!
//! `MessageFfi` + `CallPolicyFfi` — uniffi Records.

use std::collections::HashSet;

use umbrella_calls::{CallPolicy, PeerId as CallsPeerId, RoutingMode};

use crate::types::{ChatIdFfi, PeerIdFfi};

/// FFI представление расшифрованного сообщения.
///
/// FFI representation of a decrypted message.
#[derive(Clone, uniffi::Record)]
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

/// `Debug` на FFI-границе не печатает plaintext тела сообщения.
/// `Debug` at the FFI boundary never prints message-body plaintext.
impl core::fmt::Debug for MessageFfi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = self.text.as_ref().map(|_| "<redacted>");
        let text_len = self.text.as_ref().map(String::len);
        f.debug_struct("MessageFfi")
            .field("message_id", &self.message_id)
            .field("chat_id", &self.chat_id)
            .field("sender", &self.sender)
            .field("timestamp_unix_millis", &self.timestamp_unix_millis)
            .field("text_len", &text_len)
            .field("text", &text)
            .finish()
    }
}

/// FFI представление [`CallPolicy`].
///
/// FFI representation of [`CallPolicy`].
#[derive(Clone, uniffi::Record)]
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

/// `Debug` не раскрывает sensitive peers через мобильную FFI-границу.
/// `Debug` does not reveal sensitive peers across the mobile FFI boundary.
impl core::fmt::Debug for CallPolicyFfi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CallPolicyFfi")
            .field("default_routing", &self.default_routing)
            .field("sensitive_peers_len", &self.sensitive_peers.len())
            .field("sensitive_peers", &"<redacted>")
            .field("allow_p2p_global", &self.allow_p2p_global)
            .finish()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_ffi_debug_redacts_plaintext() {
        let msg = MessageFfi {
            message_id: vec![1u8; 16],
            chat_id: ChatIdFfi {
                bytes: vec![2u8; 32],
            },
            sender: PeerIdFfi {
                bytes: vec![3u8; 32],
            },
            timestamp_unix_millis: 1_700_000_000_000,
            text: Some("private-ffi-secret".to_string()),
        };

        let debug = format!("{msg:?}");

        assert!(
            !debug.contains("private-ffi-secret"),
            "Debug output must not leak FFI message plaintext: {debug}"
        );
        assert!(
            debug.contains("text_len"),
            "Debug output should keep text length metadata for diagnostics: {debug}"
        );
    }

    #[test]
    fn call_policy_ffi_debug_redacts_sensitive_peers() {
        let policy = CallPolicyFfi {
            default_routing: 2,
            sensitive_peers: vec![PeerIdFfi {
                bytes: vec![0xBB; 32],
            }],
            allow_p2p_global: false,
        };

        let debug = format!("{policy:?}");

        assert!(
            !debug.contains("187, 187, 187"),
            "Debug output must not leak sensitive peer identifiers: {debug}"
        );
        assert!(
            debug.contains("sensitive_peers_len"),
            "Debug output should keep sensitive-peer count for diagnostics: {debug}"
        );
    }
}
