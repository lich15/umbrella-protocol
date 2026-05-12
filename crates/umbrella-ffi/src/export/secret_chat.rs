//! `SecretChatHandle` — uniffi wrapper над [`umbrella_client::SecretChat`].
//!
//! **БЕЗ** `cloud_sync_history`, **БЕЗ** `add_bot` — ADR-006 Вариант C
//! type-safe enforcement на FFI уровне. Swift / Kotlin биндинги физически
//! не увидят этих методов; попытка вызвать → compile-error в их IDE.
//!
//! Compliance-gate `start_call` (SecretChat → only Relay candidates,
//! SPEC-06 §3) реализуется через [`umbrella_client::SecretChat::start_call`]
//! → [`umbrella_client::call::ModeEnforcement::SecretMode`]. FFI exposure
//! `start_call` появится в Блоке 7.10 milestone (требует `MediaSource` /
//! `MediaSink` callback interfaces — отдельный uniffi feature).
//!
//! `SecretChatHandle` — uniffi wrapper around [`umbrella_client::SecretChat`].
//!
//! **No** `cloud_sync_history`, **no** `add_bot` — ADR-006 Variant C
//! type-safe enforcement at the FFI layer. Swift / Kotlin bindings will
//! not see these methods at all; calls compile-error in their IDE.
//!
//! The `start_call` compliance-gate (SecretChat → only Relay candidates,
//! SPEC-06 §3) is enforced through
//! [`umbrella_client::SecretChat::start_call`] →
//! [`umbrella_client::call::ModeEnforcement::SecretMode`]. FFI exposure
//! of `start_call` arrives in the Block 7.10 milestone (requires
//! `MediaSource` / `MediaSink` callback interfaces — separate uniffi
//! feature).

use umbrella_client::SecretChat;

use crate::error::UmbrellaError;
use crate::types::{ChatIdFfi, MessageFfi, PeerIdFfi};

/// FFI handle над `SecretChat`. Создаётся через
/// [`super::client::UmbrellaClientHandle::open_secret_chat`].
///
/// FFI handle over `SecretChat`. Built via
/// [`super::client::UmbrellaClientHandle::open_secret_chat`].
#[derive(uniffi::Object)]
pub struct SecretChatHandle {
    inner: SecretChat,
}

impl SecretChatHandle {
    pub(crate) fn new(inner: SecretChat) -> Self {
        Self { inner }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl SecretChatHandle {
    /// Отправить текстовое сообщение.
    ///
    /// Send a text message.
    pub async fn send_text(&self, text: String) -> Result<Vec<u8>, UmbrellaError> {
        let id = self.inner.send_text(text).await?;
        Ok(id.0.to_vec())
    }

    /// Получить inbox.
    ///
    /// Fetch the inbox.
    pub async fn fetch_inbox(&self) -> Result<Vec<MessageFfi>, UmbrellaError> {
        let msgs = self.inner.fetch_inbox().await?;
        Ok(msgs.into_iter().map(decrypted_to_ffi).collect())
    }

    /// Добавить участника.
    ///
    /// Add a participant.
    pub async fn add_participant(&self, peer: PeerIdFfi) -> Result<(), UmbrellaError> {
        self.inner.add_participant(peer.try_into()?).await?;
        Ok(())
    }

    /// Удалить участника.
    ///
    /// Remove a participant.
    pub async fn remove_participant(&self, peer: PeerIdFfi) -> Result<(), UmbrellaError> {
        self.inner.remove_participant(peer.try_into()?).await?;
        Ok(())
    }

    /// Идентификатор чата.
    ///
    /// Chat identifier.
    pub fn chat_id(&self) -> ChatIdFfi {
        self.inner.chat_id().into()
    }

    // ADR-006 Вариант C — следующих методов намеренно НЕТ:
    //   cloud_sync_history(...)  — Cloud-only.
    //   add_bot(...)             — Cloud-only.
    // Swift / Kotlin биндинги их физически не увидят.
}

fn decrypted_to_ffi(m: umbrella_client::facade::chat_common::DecryptedMessage) -> MessageFfi {
    MessageFfi {
        message_id: m.message_id.0.to_vec(),
        chat_id: m.chat_id.into(),
        sender: m.sender.into(),
        timestamp_unix_millis: m.timestamp,
        text: Some(m.text),
    }
}
