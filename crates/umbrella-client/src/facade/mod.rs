//! Facade-слой — два type-safe типа [`CloudChat`] и [`SecretChat`] (ADR-006
//! Вариант C). Общие примитивы (ChatId, PeerId, MessageId, ChatSettings,
//! DecryptedMessage) выделены в [`chat_common`]; фасады экспонируют
//! полностью разные наборы методов: попытка вызвать Cloud-метод на
//! `SecretChat` — compile error.
//!
//! Facade layer — two type-safe types [`CloudChat`] and [`SecretChat`]
//! (ADR-006 Variant C). Shared primitives (ChatId, PeerId, MessageId,
//! ChatSettings, DecryptedMessage) live in [`chat_common`]; the facades expose
//! fully disjoint method sets: calling a Cloud method on `SecretChat` is a
//! compile error.

pub mod chat_common;
pub mod cloud_chat;
pub mod secret_chat;

/// Task 3 carry-over closure 2026-05-21: max_ratchet v3 wire-format codec живёт в
/// `umbrella_mls::max_ratchet::envelope` (sibling других max_ratchet модулей —
/// config/counter/spqr/state/timer/group). Re-export сохраняет downstream API
/// `umbrella_client::facade::max_ratchet_envelope::*` без breaking changes; перенос
/// нужен чтобы fuzz host crate `umbrella-fuzz` мог импортировать codec без
/// transitive pq-feature unification ошибки через umbrella-client::keystore::hw_backed.
///
/// Task 3 (2026-05-21): v3 envelope codec moved to `umbrella_mls::max_ratchet::envelope`
/// alongside the other max_ratchet modules; this is a re-export shim preserving the
/// existing `umbrella_client::facade::max_ratchet_envelope` API.
pub mod max_ratchet_envelope {
    pub use umbrella_mls::max_ratchet::envelope::*;
}

#[doc(inline)]
pub use cloud_chat::CloudChat;
#[doc(inline)]
pub use secret_chat::SecretChat;
