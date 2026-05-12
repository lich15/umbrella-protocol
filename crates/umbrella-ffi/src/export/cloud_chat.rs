//! `CloudChatHandle` — uniffi wrapper над [`umbrella_client::CloudChat`].
//! Cloud-only методы (`cloud_sync_history`, `add_bot`) присутствуют только
//! здесь, не в [`super::secret_chat::SecretChatHandle`] — ADR-006 Вариант C
//! enforced на FFI уровне.
//!
//! `CloudChatHandle` — uniffi wrapper around [`umbrella_client::CloudChat`].
//! Cloud-only methods (`cloud_sync_history`, `add_bot`) live here only,
//! never on [`super::secret_chat::SecretChatHandle`] — ADR-006 Variant C
//! enforced at the FFI boundary.

use umbrella_client::CloudChat;

use crate::error::UmbrellaError;
use crate::types::{ChatIdFfi, MessageFfi, PeerIdFfi};

/// FFI handle над `CloudChat`. Создаётся через
/// [`super::client::UmbrellaClientHandle::open_cloud_chat`].
///
/// FFI handle over `CloudChat`. Built via
/// [`super::client::UmbrellaClientHandle::open_cloud_chat`].
#[derive(uniffi::Object)]
pub struct CloudChatHandle {
    inner: CloudChat,
}

impl CloudChatHandle {
    pub(crate) fn new(inner: CloudChat) -> Self {
        Self { inner }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl CloudChatHandle {
    /// Отправить текстовое сообщение. Возвращает 16-байтовый `MessageId`.
    ///
    /// Send a text message. Returns the 16-byte `MessageId` bytes.
    pub async fn send_text(&self, text: String) -> Result<Vec<u8>, UmbrellaError> {
        let id = self.inner.send_text(text).await?;
        Ok(id.0.to_vec())
    }

    /// Получить inbox с момента последнего вызова.
    ///
    /// Fetch the inbox since the previous call.
    pub async fn fetch_inbox(&self) -> Result<Vec<MessageFfi>, UmbrellaError> {
        let msgs = self.inner.fetch_inbox().await?;
        Ok(msgs.into_iter().map(decrypted_to_ffi).collect())
    }

    /// Cloud-only: синхронизация истории при bootstrap нового устройства.
    /// `since_unix_millis = None` → вся доступная история; `Some(ts)` →
    /// только сообщения после `ts`.
    ///
    /// Cloud-only: history sync at new-device bootstrap. `since_unix_millis
    /// = None` → fetch full history; `Some(ts)` → only messages after `ts`.
    pub async fn cloud_sync_history(
        &self,
        since_unix_millis: Option<u64>,
    ) -> Result<Vec<MessageFfi>, UmbrellaError> {
        let msgs = self.inner.cloud_sync_history(since_unix_millis).await?;
        Ok(msgs.into_iter().map(decrypted_to_ffi).collect())
    }

    /// Добавить участника в Cloud-чат.
    ///
    /// Add a participant to the Cloud chat.
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
