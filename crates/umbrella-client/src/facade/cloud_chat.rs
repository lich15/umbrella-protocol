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
    cloud_publish_at_rest, cloud_sync_history_impl, create_mls_group, fetch_mls_inbox,
    mls_add_member, open_mls_group_from_welcome, send_mls_text, ChatId, ChatSettings,
    DecryptedMessage, MessageId, PeerId, Timestamp,
};

/// Cloud-чат. Тонкая обёртка над `Arc<ClientCore>` + `ChatId` + effective
/// ciphersuite; фасад без собственного криптографического state — всё хранится
/// централизованно в `ClientCore` и связанных нижних слоях
/// (`umbrella-mls`, `umbrella-backup`).
///
/// `effective_ciphersuite` фиксируется в момент `create` — либо из
/// `ChatSettings.ciphersuite` (явный per-chat override), либо из
/// `core.default_ciphersuite()` (bootstrap-режим). `open` по `ChatId`
/// использует `core.default_ciphersuite()` (persistent MLS state
/// материализуется lazily при первом `send_text` / `fetch_inbox`); для
/// recovery нового устройства правильный путь — [`Self::open_from_welcome`],
/// который вычитывает effective ciphersuite напрямую из Welcome.
///
/// Cloud chat. Thin wrapper over `Arc<ClientCore>` + `ChatId` + effective
/// ciphersuite; the facade owns no cryptographic state — everything is held
/// centrally in `ClientCore` and the underlying layers (`umbrella-mls`,
/// `umbrella-backup`).
///
/// `effective_ciphersuite` is pinned at `create` — either from
/// `ChatSettings.ciphersuite` (explicit per-chat override) or from
/// `core.default_ciphersuite()` (bootstrap mode). `open` by `ChatId` uses
/// `core.default_ciphersuite()` (persistent MLS state is materialised
/// lazily on the first `send_text` / `fetch_inbox`); for new-device
/// recovery the correct path is [`Self::open_from_welcome`], which reads
/// the effective ciphersuite directly from the Welcome.
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
    /// Infallible: возвращает handle с `effective_ciphersuite =
    /// core.default_ciphersuite()`. Если MLS state ещё не материализован
    /// для `chat_id`, ошибки surface'ятся позже в [`Self::send_text`] /
    /// [`Self::fetch_inbox`] / [`Self::cloud_sync_history`] как
    /// `ClientError::Mls` / `ClientError::Backup` / `ClientError::Network`.
    ///
    /// Infallible: returns a handle with `effective_ciphersuite =
    /// core.default_ciphersuite()`. If MLS state is not yet materialised
    /// for `chat_id`, errors surface later in [`Self::send_text`] /
    /// [`Self::fetch_inbox`] / [`Self::cloud_sync_history`] as
    /// `ClientError::Mls` / `ClientError::Backup` / `ClientError::Network`.
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
    pub async fn open_from_welcome(core: Arc<ClientCore>, welcome_bytes: &[u8]) -> Result<Self> {
        let (chat_id, effective_ciphersuite) =
            open_mls_group_from_welcome(&core, welcome_bytes).await?;
        Ok(Self {
            core,
            chat_id,
            effective_ciphersuite,
        })
    }

    /// Создать новый Cloud-чат с указанными участниками и settings.
    /// `UmbrellaGroup::create_private` инициализирует MLS group state с
    /// random 32-byte GroupId (RFC 9420 §13.1.1) и регистрирует его в
    /// `ClientCore.groups`. `_participants` на этом шаге игнорируется —
    /// production add flow идёт через [`Self::add_member`] после fetch
    /// `KeyPackage` из key-svc.
    ///
    /// Create a new Cloud chat with the given participants and settings.
    /// `UmbrellaGroup::create_private` initialises MLS group state with a
    /// random 32-byte GroupId (RFC 9420 §13.1.1) and registers it in
    /// `ClientCore.groups`. `_participants` is ignored at this step — the
    /// production add flow goes through [`Self::add_member`] after fetching
    /// `KeyPackage`s from key-svc.
    ///
    /// # Errors
    ///
    /// - `ClientError::Mls` — `UmbrellaGroup::create_private` failed
    ///   (unsupported ciphersuite через `UmbrellaCiphersuite::from_raw_id`,
    ///   provider не поддерживает X-Wing KEM под PQ, либо MLS keystore
    ///   write failure).
    ///
    /// - `ClientError::Mls` — `UmbrellaGroup::create_private` failed
    ///   (unsupported ciphersuite via `UmbrellaCiphersuite::from_raw_id`,
    ///   provider lacks X-Wing KEM under PQ, or MLS keystore write
    ///   failure).
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
        // KeyPackages from key-svc. Callers that pass a peer list at create
        // do not actually add members at this step — they must follow up
        // with `add_member` per peer.
        let chat_id = create_mls_group(&core, effective_ciphersuite).await?;
        Ok(Self {
            core,
            chat_id,
            effective_ciphersuite,
        })
    }

    /// Отправить текстовое сообщение. В Cloud-режиме: MLS-шифрование через
    /// shared chat_common helper (`send_mls_text` → MLS encrypt с
    /// max-ratchet aggressive DH rekey + SPQR HMAC + v3 wire envelope при
    /// зарегистрированной группе; raw text fallback для test fixtures без
    /// gateway), затем at-rest write — Cloud-wrap случайного message_key
    /// через 3-of-5 Sealed Servers HPKE + ChaCha20-Poly1305 encrypt
    /// plaintext + push `CloudHistoryEntry` в postman.cloud_history для
    /// будущего [`Self::cloud_sync_history`].
    ///
    /// Send a text message. Cloud mode: MLS encryption via the shared
    /// chat_common helper (`send_mls_text` → MLS encrypt with max-ratchet
    /// aggressive DH rekey + SPQR HMAC + v3 wire envelope when the group
    /// is registered; raw-text fallback for test fixtures without a
    /// gateway), then at-rest write — Cloud-wrap of a random message_key
    /// via 3-of-5 Sealed Servers HPKE + ChaCha20-Poly1305 encrypt of the
    /// plaintext + push of a `CloudHistoryEntry` into
    /// postman.cloud_history for future [`Self::cloud_sync_history`].
    ///
    /// # Errors
    ///
    /// - `ClientError::Network` — gateway send/recv I/O failed либо
    ///   неожиданный server payload.
    /// - `ClientError::Mls` — MLS encrypt failed (group evicted, ratchet
    ///   state corrupt, либо max-ratchet encrypt failure).
    /// - `ClientError::Backup` — `wrap_message_key` failed (invalid
    ///   wrapping_params, Sealed Server unwrap failure).
    /// - `ClientError::Internal` — ChaCha20-Poly1305 at-rest encrypt failed
    ///   (unusual; only AAD too large).
    ///
    /// At-rest write выполняется только когда live send succeeded с real
    /// gateway (`msg_id != [0u8; 16]` stub); пути без gateway не создают
    /// at-rest entry, чтобы избежать duplicate-msg_id violations postman
    /// invariant uniqueness.
    ///
    /// At-rest write runs only when the live send succeeded against a real
    /// gateway (`msg_id != [0u8; 16]` stub); paths without a gateway skip
    /// the at-rest entry to avoid duplicate-msg_id violations of the
    /// postman uniqueness invariant.
    pub async fn send_text(&self, text: String) -> Result<MessageId> {
        // F-CLIENT-FACADE-1 session 6c: dual-write path для Cloud-mode.
        // (1) Live MLS encrypt + send via gateway (session 5 path) — для
        //     online recipients с MLS group state.
        // (2) At-rest write to postman.cloud_history (session 6c) — для
        //     future new-device recovery через cloud_sync_history.
        //
        // At-rest write conditional: только когда live send succeeded с
        // real gateway (msg_id != zero stub). Stub path без gateway не
        // создаёт at-rest entry — иначе все entries имели бы duplicate
        // msg_id = [0u8; 16], нарушая postman invariant uniqueness.
        //
        // F-CLIENT-FACADE-1 session 6c: dual-write — MLS live (session 5)
        // + at-rest postman.cloud_history (session 6c). At-rest conditional
        // on gateway-success (msg_id != zero stub).
        let plaintext_bytes = text.as_bytes().to_vec();
        let msg_id = send_mls_text(&self.core, self.chat_id, text).await?;
        if msg_id != MessageId([0u8; 16]) {
            cloud_publish_at_rest(&self.core, self.chat_id, &plaintext_bytes, msg_id).await?;
        }
        Ok(msg_id)
    }

    /// Получить inbox — сообщения, пришедшие с момента последнего
    /// `fetch_inbox`. Пустой `Vec` если нет новых либо если gateway не
    /// сконфигурирован (test fixtures без networking). Drain loop читает
    /// `ServerPayload::IncomingMessage` с per-envelope timeout, конвертит
    /// каждое через MLS decrypt (если group зарегистрирован) либо UTF-8
    /// lossy fallback (legacy путь до session 5). SPQR HMAC failure
    /// fail-closed silently drop'ит message (warn-logged, без UI
    /// pollution).
    ///
    /// Fetch the inbox — messages that have arrived since the last
    /// `fetch_inbox`. Empty `Vec` when nothing new, or when the gateway
    /// is not configured (test fixtures without networking). The drain
    /// loop reads `ServerPayload::IncomingMessage` with a per-envelope
    /// timeout, decoding each via MLS decrypt (when a group is
    /// registered) or a UTF-8 lossy fallback (legacy pre-session-5 path).
    /// SPQR HMAC failure fail-closes by silently dropping the message
    /// (warn-logged, no UI pollution).
    ///
    /// # Errors
    ///
    /// - `ClientError::Network` — gateway recv I/O failure (timeout не
    ///   считается ошибкой — drain просто заканчивается).
    /// - `ClientError::Mls` — MLS decrypt failure (group epoch desync,
    ///   ratchet state corrupt).
    /// - `ClientError::Internal` — decoder failure при `decode_server_msg_id`
    ///   / `parse_peer_id_from_bytes`.
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
    /// - `ClientError::Backup(InsufficientUnwrapShares)` — менее 3 shares
    ///   returned для msg_id (нужны 3-of-5 Sealed Server unwraps).
    /// - `ClientError::Backup(AllSubsetsFailedUnwrap)` — все subset
    ///   combinations 3-of-N не дали валидный message_key.
    /// - `ClientError::Backup(AeadDecryptFailed)` — outer ciphertext_at_rest
    ///   AEAD verify не прошёл (corrupt/tampered postman entry).
    /// - `ClientError::Internal` — инвариант nарушен (ciphertext без
    ///   wrapped_key либо negative `since` cursor).
    ///
    /// - `ClientError::Backup(InsufficientUnwrapShares)` — fewer than 3
    ///   shares returned for a msg_id (3-of-5 Sealed Server unwraps
    ///   required).
    /// - `ClientError::Backup(AllSubsetsFailedUnwrap)` — every 3-of-N
    ///   subset combination failed to recover the message_key.
    /// - `ClientError::Backup(AeadDecryptFailed)` — outer
    ///   ciphertext_at_rest AEAD verify failed (corrupt/tampered postman
    ///   entry).
    /// - `ClientError::Internal` — invariant violation (ciphertext without
    ///   wrapped_key, negative `since` cursor).
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
    /// Текущая реализация — `Ok(())` (stub до wire-up Sealed Server
    /// bot-authorize flow + bot identity registry). Когда станет wired —
    /// будет возвращать `ClientError::Network / Backup / Identity`.
    ///
    /// Current implementation returns `Ok(())` (stub until the Sealed
    /// Server bot-authorize flow and bot identity registry are wired).
    /// Once wired it will return `ClientError::Network / Backup /
    /// Identity`.
    pub async fn add_bot(&self, _bot_id: [u8; 32]) -> Result<()> {
        Ok(())
    }

    /// Добавить участника (human device) в Cloud-чат. До wire-up к
    /// key-svc / blind-postman (KeyPackage fetch + Welcome fan-out)
    /// этот метод stub `Ok(())` — реальная MLS Add логика доступна через
    /// [`Self::add_member`] (peer + serialized KeyPackage), которая
    /// выполняет MLS Add proposal + Commit и возвращает Welcome bytes
    /// для distribution.
    ///
    /// Add a participant (human device) to the Cloud chat. Pending
    /// key-svc / blind-postman wiring (KeyPackage fetch + Welcome
    /// fan-out) this method is a `Ok(())` stub — the real MLS Add logic
    /// is available through [`Self::add_member`] (peer + serialized
    /// KeyPackage), which performs the MLS Add proposal + Commit and
    /// returns the Welcome bytes for distribution.
    ///
    /// # Errors
    ///
    /// Текущая реализация — `Ok(())`. Когда станет wired —
    /// `ClientError::Mls / SealedSender / Network`.
    ///
    /// Current implementation returns `Ok(())`. Once wired —
    /// `ClientError::Mls / SealedSender / Network`.
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
    pub async fn add_member(&self, peer: PeerId, key_package_bytes: Vec<u8>) -> Result<Vec<u8>> {
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
    /// Текущая реализация — `Ok(())` (stub до wire-up MLS Remove + Commit
    /// fan-out через blind-postman). Когда станет wired — будет возвращать
    /// `ClientError::Mls / SealedSender / Network`.
    ///
    /// Current implementation returns `Ok(())` (stub until MLS Remove +
    /// Commit fan-out is wired through blind-postman). Once wired it will
    /// return `ClientError::Mls / SealedSender / Network`.
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
    /// `ClientCore::default_ciphersuite` (для `open` по `ChatId` либо для
    /// `create` без override); `open_from_welcome` вычитывает effective
    /// ciphersuite напрямую из Welcome. Integration scenarios используют
    /// этот accessor для verify что Cloud-чат поднялся под нужным
    /// ciphersuite (например `0x004D` hybrid PQ vs `0x0003` classical).
    ///
    /// Effective IANA ciphersuite (RFC 9420 §17.1) of this chat. Returns
    /// the explicit `ChatSettings.ciphersuite` from `create` if any,
    /// otherwise `ClientCore::default_ciphersuite` (for `open` by
    /// `ChatId` or for `create` without an override); `open_from_welcome`
    /// reads the effective ciphersuite directly from the Welcome.
    /// Integration scenarios rely on this accessor to verify that the
    /// Cloud chat negotiated the desired ciphersuite (e.g. `0x004D`
    /// hybrid PQ vs `0x0003` classical).
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
    /// `facade` и `call` слоёв (`CallSession` wiring + integration
    /// scenarios).
    ///
    /// Reference to `ClientCore` — used by tests and the internal
    /// `facade` / `call` layers (`CallSession` wiring + integration
    /// scenarios).
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn core(&self) -> &Arc<ClientCore> {
        &self.core
    }
}
