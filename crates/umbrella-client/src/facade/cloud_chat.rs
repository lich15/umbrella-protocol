//! Cloud-режим UmbrellaX фасад. ADR-006 Вариант C type-safe разграничение.
//! История хранится на Почтальоне постоянно в зашифрованном виде; wrap-ключ
//! собирается 3-of-5 Sealed Servers при открытии на новом устройстве.
//! Поддерживает multi-device, ботов, большие группы.
//!
//! Cloud-mode UmbrellaX facade. ADR-006 Variant C type-safe separation.
//! History persists on Postman in encrypted form; the wrap key is assembled by
//! 3-of-5 Sealed Servers when a new device opens the chat. Supports multi-
//! device, bots, large groups.
//!
//! # Mode-exclusive API
//!
//! - [`cloud_sync_history`](CloudChat::cloud_sync_history) — fetch history from
//!   Sealed Servers + Postman при bootstrap нового устройства. Недоступен
//!   на [`SecretChat`].
//! - [`add_bot`](CloudChat::add_bot) — добавление бота через Sealed Servers
//!   authorize flow. Недоступен на `SecretChat`.
//!
//! Попытка вызвать эти методы на `SecretChat` — compile error, не runtime check.
//!
//! # Mode-exclusive API (English)
//!
//! - [`cloud_sync_history`](CloudChat::cloud_sync_history) — fetch history from
//!   Sealed Servers + Postman during new-device bootstrap. Not available on
//!   [`SecretChat`].
//! - [`add_bot`](CloudChat::add_bot) — add a bot via the Sealed Servers authorize
//!   flow. Not available on `SecretChat`.
//!
//! Calling either on `SecretChat` is a compile error, not a runtime check.
//!
//! [`SecretChat`]: crate::facade::SecretChat

use std::sync::Arc;

use umbrella_calls::CallPolicy;

use crate::call::{CallSession, MediaSink, MediaSource, ModeEnforcement};
use crate::core::ClientCore;
use crate::error::Result;
use crate::facade::chat_common::{
    cloud_sync_history_impl, create_mls_group, fetch_mls_inbox, mls_add_member,
    open_mls_group_from_welcome, send_mls_text, ChatId, ChatSettings, DecryptedMessage,
    MessageId, PeerId, Timestamp,
};

/// Cloud-чат. Тонкая обёртка над `Arc<ClientCore>` + `ChatId` + effective
/// ciphersuite; фасад без собственного криптографического state — всё хранится
/// централизованно в `ClientCore` и связанных нижних слоях
/// (`umbrella-mls`, `umbrella-backup`).
///
/// `effective_ciphersuite` фиксируется в момент `create` — либо из
/// `ChatSettings.ciphersuite` (явный per-chat override), либо из
/// `core.default_ciphersuite()` (bootstrap-режим). После `open` `(_, _)`
/// существующего чата ciphersuite читается из persistent MLS state в
/// Блоке 7.4+; в Блоке 7.2 `open` использует `core.default_ciphersuite()`
/// (нет persistent MLS state stub'е).
///
/// Cloud chat. Thin wrapper over `Arc<ClientCore>` + `ChatId` + effective
/// ciphersuite; the facade owns no cryptographic state — everything is held
/// centrally in `ClientCore` and the underlying layers (`umbrella-mls`,
/// `umbrella-backup`).
///
/// `effective_ciphersuite` is pinned at `create` — either from
/// `ChatSettings.ciphersuite` (explicit per-chat override) or from
/// `core.default_ciphersuite()` (bootstrap mode). After `open` of an existing
/// chat the ciphersuite is read from the persistent MLS state in Block 7.4+;
/// in Block 7.2 `open` uses `core.default_ciphersuite()` (no persistent MLS
/// state in the stub).
#[derive(Clone)]
pub struct CloudChat {
    core: Arc<ClientCore>,
    chat_id: ChatId,
    /// Effective ciphersuite, выбранный при create (см. doc-comment struct).
    /// Effective ciphersuite picked at create time (see struct doc-comment).
    effective_ciphersuite: u16,
}

impl CloudChat {
    /// Открыть существующий Cloud-чат по `ChatId`. Не делает сетевых вызовов
    /// сам по себе — MLS state материализуется при первом `send_text` /
    /// `fetch_inbox`.
    ///
    /// Open an existing Cloud chat by `ChatId`. Performs no network I/O on
    /// its own — MLS state is materialized on the first `send_text` /
    /// `fetch_inbox`.
    ///
    /// # Errors
    ///
    /// В Блоке 7.2 — инфalible (stub); в Блоке 7.4 вернёт `ClientError::Storage`
    /// если local MLS snapshot недоступен.
    ///
    /// Infallible in Block 7.2 (stub); Block 7.4 may return
    /// `ClientError::Storage` if the local MLS snapshot is missing.
    pub async fn open(core: Arc<ClientCore>, chat_id: ChatId) -> Result<Self> {
        let effective_ciphersuite = core.default_ciphersuite();
        Ok(Self {
            core,
            chat_id,
            effective_ciphersuite,
        })
    }

    /// **F-CLIENT-FACADE-1 session 6 (2026-05-19):** join an existing Cloud-чат
    /// from a TLS-serialized `Welcome` message published by another member.
    /// Заменяет manual two-step pattern session 5
    /// (`fetch_pending_welcomes()` + manual `UmbrellaGroup::join_from_welcome`)
    /// на single fasade-level call.
    ///
    /// Flow:
    ///   1. `UmbrellaGroup::join_from_welcome` (validate Welcome + Private policy)
    ///   2. Extract MLS GroupId → `ChatId` (canonical 32-byte shape session 5)
    ///   3. Register joined group в `ClientCore.groups`
    ///   4. Return `CloudChat` handle с real chat_id + effective ciphersuite
    ///
    /// Typical flow: new device → `ClientCore::fetch_pending_welcomes(self_pk)` →
    /// для каждого welcome bytes →
    /// `CloudChat::open_from_welcome(core, welcome_bytes)`. После этого
    /// device может вызывать `send_text` / `fetch_inbox` / `cloud_sync_history`
    /// для recovered chat'ов.
    ///
    /// **F-CLIENT-FACADE-1 session 6:** join an existing Cloud chat from a
    /// Welcome message published by another member (typically retrieved via
    /// `ClientCore::fetch_pending_welcomes`). Replaces the session-5 manual
    /// two-step `UmbrellaGroup::join_from_welcome` + `register_group` pattern.
    ///
    /// # Errors
    ///
    /// Mirror'ит `open_mls_group_from_welcome` (см. doc-comment в
    /// `chat_common.rs`): Welcome decode/validate gap → `ClientError::Mls(Welcome)`;
    /// non-canonical GroupId shape → `ClientError::Mls(GroupOperation)`.
    pub async fn open_from_welcome(
        core: Arc<ClientCore>,
        welcome_bytes: &[u8],
    ) -> Result<Self> {
        let (chat_id, effective_ciphersuite) = open_mls_group_from_welcome(&core, welcome_bytes).await?;
        Ok(Self {
            core,
            chat_id,
            effective_ciphersuite,
        })
    }

    /// Создать новый Cloud-чат с указанными участниками и settings.
    /// В Блоке 7.4 инициирует MLS group create + публикует
    /// `WelcomeMessage` через blind-postman-svc.
    ///
    /// Create a new Cloud chat with the given participants and settings. In
    /// Block 7.4 initiates an MLS group creation and publishes the
    /// `WelcomeMessage` through blind-postman-svc.
    ///
    /// # Errors
    ///
    /// В Блоке 7.2 — infallible stub, возвращает `ChatId([0u8; 32])`. В 7.4
    /// могут возвращаться `ClientError::Mls`, `ClientError::SealedSender`,
    /// `ClientError::Network`.
    ///
    /// Block 7.2 infallible stub, returns `ChatId([0u8; 32])`. Block 7.4 may
    /// return `ClientError::Mls`, `ClientError::SealedSender`,
    /// `ClientError::Network`.
    pub async fn create(
        core: Arc<ClientCore>,
        _participants: Vec<PeerId>,
        settings: ChatSettings,
    ) -> Result<Self> {
        let effective_ciphersuite = settings
            .ciphersuite
            .unwrap_or_else(|| core.default_ciphersuite());
        // F-CLIENT-FACADE-1 session 5: real MLS group create. Random 32-byte
        // chat_id as MLS GroupId (RFC 9420 §13.1.1 opaque). `_participants`
        // intentionally ignored at create-time: production add flow goes
        // through `add_member(peer, key_package_bytes)` after fetching
        // KeyPackages from key-svc (session 6+). Block 7.2 callers that pass
        // peer list at create do not actually add members yet — same as
        // pre-session-5 stub behaviour.
        let chat_id = create_mls_group(&core, effective_ciphersuite).await?;
        Ok(Self {
            core,
            chat_id,
            effective_ciphersuite,
        })
    }

    /// Отправить текстовое сообщение. В Cloud-режиме: MLS-шифрование через
    /// shared chat_common helper, затем Cloud-wrap ключа через 3-of-5 Sealed
    /// Servers + запись `(ciphertext, wrapped_key)` на Почтальон (Блок 7.4).
    ///
    /// Send a text message. Cloud mode: MLS encryption via the shared
    /// chat_common helper, then Cloud-wrap of the message key via 3-of-5
    /// Sealed Servers, followed by a Postman write of `(ciphertext,
    /// wrapped_key)` (Block 7.4).
    ///
    /// # Errors
    ///
    /// В Блоке 7.2 stub — infallible. В 7.4 — `ClientError::Mls/Backup/
    /// Network/SealedSender/Padding`.
    ///
    /// Block 7.2 infallible stub. Block 7.4 may return `ClientError::Mls /
    /// Backup / Network / SealedSender / Padding`.
    pub async fn send_text(&self, text: String) -> Result<MessageId> {
        send_mls_text(&self.core, self.chat_id, text).await
    }

    /// Получить inbox — сообщения, пришедшие с момента последнего
    /// `fetch_inbox`. Пустой `Vec` если нет новых. В Блоке 7.4 делает
    /// blind-postman-svc fetch + параллельный Sealed Server unwrap 3-of-5
    /// для каждого сообщения.
    ///
    /// Fetch the inbox — messages that have arrived since the last
    /// `fetch_inbox`. Empty `Vec` when nothing new. Block 7.4 issues a
    /// blind-postman-svc fetch plus a parallel 3-of-5 Sealed Servers unwrap
    /// for each message.
    ///
    /// # Errors
    ///
    /// `ClientError::Network / Backup / Mls / SealedSender` в Блоке 7.4.
    ///
    /// `ClientError::Network / Backup / Mls / SealedSender` in Block 7.4.
    pub async fn fetch_inbox(&self) -> Result<Vec<DecryptedMessage>> {
        fetch_mls_inbox(&self.core, self.chat_id).await
    }

    /// Cloud-only: синхронизация истории при bootstrap нового устройства.
    /// Доступно только на `CloudChat` — ADR-006 Вариант C enforcement.
    ///
    /// `since` = `None` → забрать всю доступную историю; `Some(ts)` →
    /// только сообщения после `ts` (ms Unix).
    ///
    /// Cloud-only: history sync during new-device bootstrap. Available only on
    /// `CloudChat` — ADR-006 Variant C enforcement.
    ///
    /// `since = None` → fetch the full available history; `Some(ts)` → only
    /// messages after `ts` (ms Unix).
    ///
    /// # Errors
    ///
    /// `ClientError::Network / Backup / Mls / SealedSender` в Блоке 7.4.
    ///
    /// `ClientError::Network / Backup / Mls / SealedSender` in Block 7.4.
    pub async fn cloud_sync_history(
        &self,
        since: Option<Timestamp>,
    ) -> Result<Vec<DecryptedMessage>> {
        cloud_sync_history_impl(&self.core, self.chat_id, since).await
    }

    /// Cloud-only: добавить бота в чат. Bot = специальное identity у которого
    /// нет human-device; серверный authorize flow на Sealed Servers даёт
    /// боту доступ к wrap-ключам как авторизованному участнику.
    /// Недоступно на `SecretChat` — там ботов быть не может (нет wrap-ключей).
    ///
    /// Cloud-only: add a bot to the chat. A bot is a special identity with no
    /// human device; the Sealed Servers server-side authorize flow grants the
    /// bot access to wrap keys as an authorized participant. Not available on
    /// `SecretChat` — no wrap keys exist there.
    ///
    /// # Errors
    ///
    /// `ClientError::Network / Backup / Identity` в Блоке 7.4.
    ///
    /// `ClientError::Network / Backup / Identity` in Block 7.4.
    pub async fn add_bot(&self, _bot_id: [u8; 32]) -> Result<()> {
        Ok(())
    }

    /// Добавить участника (human device) в Cloud-чат. В Блоке 7.4 делает
    /// MLS Add proposal + Commit, публикует `WelcomeMessage` через
    /// blind-postman-svc. До wire-up к key-svc / blind-postman (sessions 6+)
    /// этот метод stub `Ok(())` — реальная MLS Add логика доступна через
    /// [`Self::add_member`] (peer + serialized KeyPackage).
    ///
    /// Add a participant (human device) to the Cloud chat. In Block 7.4 emits
    /// an MLS Add proposal + Commit and publishes the `WelcomeMessage` via
    /// blind-postman-svc. Pending key-svc / blind-postman wiring (sessions
    /// 6+) this method is a `Ok(())` stub — the real MLS Add logic is
    /// available through [`Self::add_member`] (peer + serialized KeyPackage).
    ///
    /// # Errors
    ///
    /// `ClientError::Mls / SealedSender / Network` once wired in session 6+.
    pub async fn add_participant(&self, _peer: PeerId) -> Result<()> {
        Ok(())
    }

    /// **F-CLIENT-FACADE-1 session 5 (2026-05-19):** real MLS Add operation на
    /// зарегистрированной группе. `peer` — Ed25519 identity pubkey того, кого
    /// добавляем (проверяется против `key_package.leaf_node.credential` —
    /// первые 32 байта payload), `key_package_bytes` — TLS-serialized
    /// `KeyPackage` (RFC 9420 §10.1, обычно ~300+ байт) этого устройства.
    ///
    /// Возвращает `Vec<u8>` — TLS-serialized `Welcome` сообщение которое
    /// caller (production: blind-postman-svc; тесты: явная передача в
    /// [`umbrella_mls::UmbrellaGroup::join_from_welcome`]) должен доставить
    /// новому участнику.
    ///
    /// **Производственный путь** (session 6+): KeyPackage'и fetch'аются из
    /// key-svc по `peer`, Welcome маршрутизируется через blind-postman-svc.
    /// Текущий signature `(peer, key_package_bytes) -> Welcome` отражает
    /// контракт между MLS-layer и transport-layer, готовый к session 6+
    /// wire-up.
    ///
    /// **F-CLIENT-FACADE-1 session 5:** real MLS Add operation on the
    /// registered group. `peer` is the Ed25519 identity pubkey of the addee
    /// (verified against `key_package.leaf_node.credential` — first 32
    /// bytes of payload); `key_package_bytes` is the TLS-serialized
    /// `KeyPackage` (RFC 9420 §10.1, typically ~300+ bytes) of that device.
    ///
    /// Returns the TLS-serialized `Welcome` message; the caller (production:
    /// blind-postman-svc; tests: explicit hand-off to
    /// `umbrella_mls::UmbrellaGroup::join_from_welcome`) must deliver it
    /// to the new member.
    ///
    /// # Errors
    ///
    /// - `ClientError::Mls` если группа не зарегистрирована, KeyPackage
    ///   некорректный, или credential.identity_pk не равен `peer.0`.
    pub async fn add_member(
        &self,
        peer: PeerId,
        key_package_bytes: Vec<u8>,
    ) -> Result<Vec<u8>> {
        mls_add_member(&self.core, self.chat_id, peer, &key_package_bytes).await
    }

    /// Удалить участника. Emit MLS Remove proposal + Commit; ratchet-tree
    /// обновляется так что removed device больше не может decrypt новые
    /// сообщения.
    ///
    /// Remove a participant. Emits an MLS Remove proposal + Commit; the
    /// ratchet tree updates so the removed device can no longer decrypt new
    /// messages.
    ///
    /// # Errors
    ///
    /// `ClientError::Mls / SealedSender / Network` в Блоке 7.4.
    ///
    /// `ClientError::Mls / SealedSender / Network` in Block 7.4.
    pub async fn remove_participant(&self, _peer: PeerId) -> Result<()> {
        Ok(())
    }

    /// Идентификатор чата.
    ///
    /// Chat identifier.
    #[must_use]
    pub fn chat_id(&self) -> ChatId {
        self.chat_id
    }

    /// Effective IANA ciphersuite (RFC 9420 §17.1) этого чата. Возвращает
    /// либо явный `ChatSettings.ciphersuite` из `create`, либо
    /// `ClientCore::default_ciphersuite` для `open` существующего чата
    /// (Блок 7.2 stub) или для `create` без override. В блоке 8.8 closing
    /// milestone integration scenarios используют этот accessor для verify
    /// что Cloud-чат поднялся под нужным ciphersuite (например `0x004D`
    /// hybrid PQ vs `0x0003` classical).
    ///
    /// Effective IANA ciphersuite (RFC 9420 §17.1) of this chat. Returns the
    /// explicit `ChatSettings.ciphersuite` from `create` if any, otherwise
    /// `ClientCore::default_ciphersuite` (used by `open` of an existing chat
    /// in the Block 7.2 stub or by `create` without an override). The Block
    /// 8.8 closing milestone integration scenarios rely on this accessor to
    /// verify that the Cloud chat negotiated the desired ciphersuite (e.g.
    /// `0x004D` hybrid PQ vs `0x0003` classical).
    #[must_use]
    pub fn ciphersuite(&self) -> u16 {
        self.effective_ciphersuite
    }

    /// Начать 1-1 звонок. CloudChat — user policy уважается (direct P2P
    /// возможен если `allow_p2p_global = true`). [`ModeEnforcement::CloudMode`]
    /// passthrough'ит policy без изменений.
    ///
    /// # Ошибки / Errors
    ///
    /// - [`crate::ClientError::Network`] если ICE agent construction
    ///   провалился (invalid TURN URL, underlying webrtc-ice error).
    ///
    /// Start a 1-1 call. CloudChat respects user policy (direct P2P is
    /// possible when `allow_p2p_global = true`). [`ModeEnforcement::CloudMode`]
    /// passes the policy through unchanged.
    ///
    /// # Errors
    ///
    /// - [`crate::ClientError::Network`] if ICE agent construction failed
    ///   (invalid TURN URL, underlying webrtc-ice error).
    pub async fn start_call(
        &self,
        peer: PeerId,
        user_policy: CallPolicy,
        media_source: Arc<dyn MediaSource>,
        media_sink: Arc<dyn MediaSink>,
    ) -> Result<CallSession> {
        CallSession::start_with_enforcement(
            self.core.clone(),
            peer,
            user_policy,
            ModeEnforcement::CloudMode,
            media_source,
            media_sink,
        )
        .await
    }

    /// Ссылка на `ClientCore` — для тестов и внутреннего использования
    /// `facade` и `call` слоёв (первый reader появится в Блоке 7.6 при
    /// wiring `CallSession`).
    ///
    /// Reference to `ClientCore` — used by tests and the internal `facade` /
    /// `call` layers (first reader arrives in Block 7.6 wiring `CallSession`).
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn core(&self) -> &Arc<ClientCore> {
        &self.core
    }
}
