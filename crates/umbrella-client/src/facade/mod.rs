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
pub mod max_ratchet_envelope;
pub mod secret_chat;

#[doc(inline)]
pub use cloud_chat::CloudChat;
#[doc(inline)]
pub use secret_chat::SecretChat;
