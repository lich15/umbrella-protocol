//! Secret-режим UmbrellaX фасад. ADR-006 Вариант C type-safe разграничение.
//! Чистый MLS RFC 9420 без Sealed Servers: история живёт только на устройствах
//! участников. Потеря device без заранее настроенного второго = потеря
//! истории. Боты невозможны (нет Sealed Servers wrap).
//!
//! # Compliance-gate no-P2P (SPEC-06 §3)
//!
//! 1-1 звонки в Secret-режиме всегда идут через TURN relay (никогда не
//! напрямую). В Блоке 7.6 это принудительно enforced на уровне `IceAgent`
//! через `AgentConfig.candidate_types = [Relay]`. API `start_call` появится в
//! Блоке 7.6; в Блоке 7.2 только текстовый фасад.
//!
//! Secret-mode UmbrellaX facade. ADR-006 Variant C type-safe separation.
//! Pure MLS RFC 9420 without Sealed Servers: history lives only on participant
//! devices. Losing a device without a pre-paired second = history is lost.
//! Bots impossible (no Sealed Servers wrap).
//!
//! # Compliance-gate no-P2P (SPEC-06 §3)
//!
//! 1-1 calls in Secret mode always flow through a TURN relay (never direct).
//! Enforced in Block 7.6 at the `IceAgent` level via
//! `AgentConfig.candidate_types = [Relay]`. The `start_call` API arrives in
//! Block 7.6; Block 7.2 ships the text facade only.
//!
//! # Type-safety compile-fail tests (ADR-006 Вариант C enforcement)
//!
//! Следующие `compile_fail` doctests — механизм compile-time проверки того,
//! что `SecretChat` физически не имеет Cloud-exclusive методов. rustc должен
//! падать с `E0599` ("method not found on type"): атрибут
//! `compile_fail,E0599` гарантирует что test зачтётся именно на пропавшем
//! методе, а не на любой другой случайной ошибке компиляции.
//!
//! The following `compile_fail` doctests provide compile-time verification
//! that `SecretChat` physically lacks Cloud-exclusive methods. rustc must
//! fail with `E0599` ("method not found on type"); the `compile_fail,E0599`
//! attribute ensures the test passes specifically on the missing method, not
//! on some unrelated compile error.
//!
//! ## SecretChat не имеет `cloud_sync_history`
//!
//! ```compile_fail,E0599
//! use umbrella_client::SecretChat;
//!
//! fn must_not_compile(chat: &SecretChat) {
//!     // ERROR[E0599]: no method named `cloud_sync_history` found for
//!     // struct `SecretChat`. Cloud-only (ADR-006 Вариант C).
//!     let _ = chat.cloud_sync_history(None);
//! }
//! ```
//!
//! ## SecretChat не имеет `add_bot`
//!
//! ```compile_fail,E0599
//! use umbrella_client::SecretChat;
//!
//! fn must_not_compile(chat: &SecretChat) {
//!     // ERROR[E0599]: no method named `add_bot` found for struct
//!     // `SecretChat`. Bots требуют Sealed Servers wrap, которого в Secret
//!     // нет.
//!     let _ = chat.add_bot([0u8; 32]);
//! }
//! ```

use std::sync::Arc;

use umbrella_calls::CallPolicy;

use crate::call::{CallSession, MediaSink, MediaSource, ModeEnforcement};
use crate::core::ClientCore;
use crate::error::Result;
use crate::facade::chat_common::{
    fetch_mls_inbox, send_mls_text, ChatId, ChatSettings, DecryptedMessage, MessageId, PeerId,
};

/// Secret-чат. Зеркало [`CloudChat`] по shared методам, но **без**
/// `cloud_sync_history` и `add_bot`. Попытка вызвать их на `SecretChat` — не
/// runtime `Result::Err`, а **compile error** (метода нет в `impl`).
///
/// Хранит effective IANA ciphersuite по тем же правилам что [`CloudChat`]:
/// `create` берёт `ChatSettings.ciphersuite` либо `core.default_ciphersuite()`,
/// `open` использует `core.default_ciphersuite()` (Блок 7.2 stub без
/// persistent MLS state).
///
/// Secret chat. Mirrors [`CloudChat`] on shared methods, but **without**
/// `cloud_sync_history` and `add_bot`. Calling them on `SecretChat` is a
/// **compile error**, not a runtime `Result::Err` (the methods are absent
/// from the `impl` block).
///
/// Holds the effective IANA ciphersuite under the same rules as [`CloudChat`]:
/// `create` reads `ChatSettings.ciphersuite` or `core.default_ciphersuite()`;
/// `open` uses `core.default_ciphersuite()` (Block 7.2 stub without
/// persistent MLS state).
///
/// [`CloudChat`]: crate::facade::CloudChat
#[derive(Clone)]
pub struct SecretChat {
    core: Arc<ClientCore>,
    chat_id: ChatId,
    /// Effective ciphersuite, выбранный при create (см. doc-comment struct).
    /// Effective ciphersuite picked at create time (see struct doc-comment).
    effective_ciphersuite: u16,
}

impl SecretChat {
    /// Открыть существующий Secret-чат. MLS state берётся из локального
    /// snapshot — сервер его не хранит.
    ///
    /// Open an existing Secret chat. MLS state is read from the local
    /// snapshot — the server does not store it.
    ///
    /// # Errors
    ///
    /// В Блоке 7.2 — infallible stub; в 7.4 `ClientError::Storage` если
    /// MLS snapshot недоступен (device resync необходим через device-transfer,
    /// единственный путь для Secret).
    ///
    /// Infallible stub in Block 7.2; Block 7.4 may return
    /// `ClientError::Storage` if the MLS snapshot is missing (the device must
    /// resync via device-transfer — the only path in Secret mode).
    pub async fn open(core: Arc<ClientCore>, chat_id: ChatId) -> Result<Self> {
        let effective_ciphersuite = core.default_ciphersuite();
        Ok(Self {
            core,
            chat_id,
            effective_ciphersuite,
        })
    }

    /// Создать новый Secret-чат. MLS group create + прямая рассылка
    /// `WelcomeMessage` через blind-postman-svc участникам.
    ///
    /// Create a new Secret chat. MLS group create + direct delivery of the
    /// `WelcomeMessage` through blind-postman-svc to participants.
    ///
    /// # Errors
    ///
    /// В Блоке 7.2 — infallible stub. В 7.4 — `ClientError::Mls /
    /// SealedSender / Network`.
    ///
    /// Infallible stub in Block 7.2. Block 7.4 may return `ClientError::Mls /
    /// SealedSender / Network`.
    pub async fn create(
        core: Arc<ClientCore>,
        _participants: Vec<PeerId>,
        settings: ChatSettings,
    ) -> Result<Self> {
        let chat_id = ChatId([0u8; 32]);
        let effective_ciphersuite = settings
            .ciphersuite
            .unwrap_or_else(|| core.default_ciphersuite());
        Ok(Self {
            core,
            chat_id,
            effective_ciphersuite,
        })
    }

    /// Отправить текстовое сообщение. Secret-режим: MLS-шифрование через
    /// shared chat_common helper → sealed-sender envelope → blind-postman
    /// delivery. БЕЗ Cloud-wrap.
    ///
    /// Send a text message. Secret mode: MLS encryption via the shared
    /// chat_common helper → sealed-sender envelope → blind-postman delivery.
    /// No Cloud-wrap.
    ///
    /// # Errors
    ///
    /// В Блоке 7.2 — infallible stub. В 7.4 — `ClientError::Mls /
    /// SealedSender / Network / Padding`.
    ///
    /// Infallible stub in Block 7.2. Block 7.4 may return `ClientError::Mls /
    /// SealedSender / Network / Padding`.
    pub async fn send_text(&self, text: String) -> Result<MessageId> {
        send_mls_text(&self.core, self.chat_id, text).await
    }

    /// Получить inbox — сообщения из blind-postman-svc с момента последнего
    /// `fetch_inbox`. В отличие от Cloud — нет Sealed Server unwrap; каждое
    /// сообщение сразу MLS-расшифровывается локальным state.
    ///
    /// Fetch the inbox — messages from blind-postman-svc since the last
    /// `fetch_inbox`. Unlike Cloud, no Sealed Server unwrap; each message
    /// is MLS-decrypted immediately with local state.
    ///
    /// # Errors
    ///
    /// `ClientError::Network / Mls / SealedSender` в Блоке 7.4.
    ///
    /// `ClientError::Network / Mls / SealedSender` in Block 7.4.
    pub async fn fetch_inbox(&self) -> Result<Vec<DecryptedMessage>> {
        fetch_mls_inbox(&self.core, self.chat_id).await
    }

    /// Добавить участника в Secret-чат. MLS Add proposal + Commit,
    /// `WelcomeMessage` напрямую через blind-postman-svc.
    ///
    /// Add a participant to the Secret chat. MLS Add proposal + Commit;
    /// `WelcomeMessage` delivered directly via blind-postman-svc.
    ///
    /// # Errors
    ///
    /// `ClientError::Mls / SealedSender / Network` в Блоке 7.4.
    ///
    /// `ClientError::Mls / SealedSender / Network` in Block 7.4.
    pub async fn add_participant(&self, _peer: PeerId) -> Result<()> {
        Ok(())
    }

    /// Удалить участника. MLS Remove + Commit.
    ///
    /// Remove a participant. MLS Remove + Commit.
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

    /// Effective IANA ciphersuite этого Secret-чата. Поведение mirror'ит
    /// [`CloudChat::ciphersuite`] (см. doc-comment там).
    ///
    /// Effective IANA ciphersuite of this Secret chat. Mirrors
    /// [`CloudChat::ciphersuite`] (see doc-comment there).
    ///
    /// [`CloudChat::ciphersuite`]: crate::facade::CloudChat::ciphersuite
    #[must_use]
    pub fn ciphersuite(&self) -> u16 {
        self.effective_ciphersuite
    }

    /// Начать 1-1 звонок. SecretChat — direct P2P **принудительно запрещён**
    /// через [`ModeEnforcement::SecretMode`] (SPEC-06 §3 compliance-gate).
    /// Двойная защита:
    ///
    /// 1. `enforcement.apply` strip'ает `allow_p2p_global` / `DirectP2P` из
    ///    user policy.
    /// 2. `IceAgent::new_no_p2p` строит webrtc-ice agent с
    ///    `candidate_types = [Relay]`.
    ///
    /// Поведение тестируется property × 128 в `tests/call_no_p2p.rs`.
    ///
    /// # Ошибки / Errors
    ///
    /// - [`crate::ClientError::Network`] если ICE agent construction
    ///   провалился (invalid TURN URL, underlying webrtc-ice error).
    ///
    /// Start a 1-1 call. SecretChat — direct P2P is **physically forbidden**
    /// via [`ModeEnforcement::SecretMode`] (SPEC-06 §3 compliance-gate).
    /// Two-layer enforcement:
    ///
    /// 1. `enforcement.apply` strips `allow_p2p_global` / `DirectP2P` from
    ///    user policy.
    /// 2. `IceAgent::new_no_p2p` builds the webrtc-ice agent with
    ///    `candidate_types = [Relay]`.
    ///
    /// Verified by property × 128 in `tests/call_no_p2p.rs`.
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
            ModeEnforcement::SecretMode,
            media_source,
            media_sink,
        )
        .await
    }

    /// Ссылка на `ClientCore` — для внутреннего использования `call` слоя
    /// и тестов (первый reader появляется в Блоке 7.6 compliance-gate).
    ///
    /// Reference to `ClientCore` — used by the internal `call` layer and
    /// tests (first reader arrives in Block 7.6 compliance-gate).
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn core(&self) -> &Arc<ClientCore> {
        &self.core
    }

    // NB: ADR-006 Вариант C enforcement — следующих методов намеренно НЕТ:
    //   `cloud_sync_history(...)`  — доступен только на CloudChat.
    //   `add_bot(...)`             — доступен только на CloudChat.
    // Попытка вызвать их на `SecretChat` — compile error ("method not found"),
    // без runtime проверок. `tests/facade_type_safety.rs` verifies это через
    // два `compile_fail` doctest'а.
    //
    // ADR-006 Variant C enforcement — the following methods are deliberately
    // absent:
    //   `cloud_sync_history(...)`  — available on CloudChat only.
    //   `add_bot(...)`             — available on CloudChat only.
    // Calling either on `SecretChat` is a compile error ("method not found"),
    // with no runtime check. `tests/facade_type_safety.rs` verifies this via
    // two `compile_fail` doctests.
}
