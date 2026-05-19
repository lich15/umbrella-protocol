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
    create_mls_group, fetch_secret_inbox, mls_add_member, open_mls_group_from_welcome,
    send_secret_text, ChatId, ChatSettings, DecryptedMessage, MessageId, PeerId,
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

    /// **F-CLIENT-FACADE-1 session 6 (2026-05-19):** join existing Secret-чат
    /// из Welcome message. Зеркалирует
    /// [`crate::facade::CloudChat::open_from_welcome`] — shared MLS join
    /// path (`UmbrellaGroup::join_from_welcome` + register). Mode-specific
    /// divergence (sealed-sender envelope wrapping) — session 7+ scope.
    ///
    /// **F-CLIENT-FACADE-1 session 6:** join an existing Secret chat from a
    /// Welcome message. Mirrors
    /// [`crate::facade::CloudChat::open_from_welcome`].
    ///
    /// # Errors
    ///
    /// Same as [`crate::facade::CloudChat::open_from_welcome`].
    pub async fn open_from_welcome(core: Arc<ClientCore>, welcome_bytes: &[u8]) -> Result<Self> {
        let (chat_id, effective_ciphersuite) =
            open_mls_group_from_welcome(&core, welcome_bytes).await?;
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
        let effective_ciphersuite = settings
            .ciphersuite
            .unwrap_or_else(|| core.default_ciphersuite());
        // F-CLIENT-FACADE-1 session 5: real MLS group create (same code path as
        // CloudChat::create). Secret-mode-specific divergence (sealed-sender
        // envelope wrapping on send, no Sealed Servers wrap for keys) lives
        // in send_mls_text / fetch_mls_inbox session 7 + cloud_sync_history
        // session 6 — those are mode-aware while the group create primitive
        // itself is shared. ADR-006 Variant C type-safety is enforced via
        // method-presence asymmetry (cloud_sync_history / add_bot exist on
        // CloudChat only).
        let chat_id = create_mls_group(&core, effective_ciphersuite).await?;
        Ok(Self {
            core,
            chat_id,
            effective_ciphersuite,
        })
    }

    /// Отправить текстовое сообщение. Secret-режим: MLS encrypt через
    /// `UmbrellaGroup.encrypt_application` → sealed-sender V1 envelope
    /// wrap per recipient (`umbrella_sealed_sender::seal`) → per-peer
    /// gateway `SendMessage` frame с `to_user_id = peer_ed25519` и
    /// `ciphertext = envelope_bytes`. БЕЗ Cloud-wrap (ADR-006 Вариант C
    /// — Secret trade'ит multi-device history против sender anonymity на
    /// gateway / blind-postman).
    ///
    /// **F-CLIENT-FACADE-1 session 7 (2026-05-19):** wired end-to-end
    /// через [`crate::facade::chat_common::send_secret_text`]. До session 7
    /// SecretChat::send_text вызывал `send_mls_text` напрямую (raw MLS
    /// ciphertext через gateway, без envelope wrap) — это leak'ило sender
    /// MLS Ed25519 identity_pk на gateway через MLSCiphertext sender_index
    /// reconstruction. Session 7 закрыл этот gap полным sealed-sender V1
    /// wire-up (Signal Lund et al. 2018 design).
    ///
    /// **Recipient enumeration**: send path enumerate'ит non-self MLS
    /// group members через [`umbrella_mls::UmbrellaGroup::member_identities`]
    /// и для каждого looks up X25519 pubkey в
    /// [`crate::core::ClientCore::lookup_peer_x25519`]. Missing X25519 →
    /// fail-closed `ClientError::SealedSender` (постулат 14 — никакого
    /// silent fallback на unsealed delivery).
    ///
    /// **Sender anonymity invariant**: envelope wire bytes содержат только
    /// `0x01 || eph_pub(32) || AEAD(...)`. Никакого raw sender_pk на wire —
    /// sender Ed25519 identity_pk зашифрован inside AEAD blob, recoverable
    /// только recipient'ом после ECDH key agreement + inner-signature
    /// verify.
    ///
    /// Send a text message. Secret mode: MLS encrypt via
    /// `UmbrellaGroup.encrypt_application` → sealed-sender V1 envelope
    /// wrap per recipient → per-peer gateway `SendMessage`. No Cloud-wrap.
    /// **F-CLIENT-FACADE-1 session 7 (2026-05-19):** wired end-to-end via
    /// [`crate::facade::chat_common::send_secret_text`]; sender Ed25519
    /// identity_pk never appears on the wire.
    ///
    /// # Errors
    ///
    /// - `ClientError::SealedSender` — peer X25519 не зарегистрирован в
    ///   `ClientCore.peer_x25519_directory` (production: KT directory
    ///   lookup wiring session 8+; tests: explicit `register_peer_x25519`
    ///   call перед send_text).
    /// - `ClientError::Mls` — MLS encrypt failed (unusual; group evicted).
    /// - `ClientError::Network` — gateway send/recv I/O failed либо
    ///   unexpected server payload variant.
    pub async fn send_text(&self, text: String) -> Result<MessageId> {
        send_secret_text(&self.core, self.chat_id, text).await
    }

    /// Получить inbox — sealed-sender envelopes из blind-postman-svc с
    /// момента последнего `fetch_inbox`. Каждый envelope:
    /// `umbrella_sealed_sender::unseal` → `(sender PeerId recovered from
    /// inner Ed25519 signature, MLS ciphertext)` → MLS-decrypt через
    /// зарегистрированную [`umbrella_mls::UmbrellaGroup`] → plaintext.
    ///
    /// В отличие от Cloud — нет Sealed Server unwrap (нет at-rest history);
    /// каждое сообщение sealed-sender unseal'ится immediately локальной
    /// X25519 identity ключом.
    ///
    /// **F-CLIENT-FACADE-1 session 7 (2026-05-19):** wired end-to-end через
    /// [`crate::facade::chat_common::fetch_secret_inbox`]. До session 7
    /// fetch_inbox вызывал `fetch_mls_inbox` напрямую (decrypt'ило raw MLS
    /// ciphertext, sender брался из gateway `from_user_id` — sender-anonymous
    /// в blind-postman model был неработающим). Session 7 закрыл: sender
    /// PeerId теперь recovered из inner-signature, fail-closed на
    /// tampered/wrong-recipient envelope.
    ///
    /// **Sender anonymity invariant**: `DecryptedMessage.sender` ≠
    /// gateway routing `from_user_id`. Sender Ed25519 identity_pk recovered
    /// только через ECDH с recipient's X25519 + AEAD decrypt + inner
    /// signature verify — gateway / blind-postman не может ни forge'нуть
    /// sender, ни прочитать его.
    ///
    /// Fetch the inbox — sealed-sender envelopes from blind-postman-svc
    /// since the last `fetch_inbox`. Each envelope unsealed via
    /// `umbrella_sealed_sender::unseal` → `(sender PeerId recovered from
    /// inner Ed25519 signature, MLS ciphertext)` → MLS-decrypt → plaintext.
    /// Sender recovered from inner signature, NOT gateway routing metadata.
    ///
    /// **F-CLIENT-FACADE-1 session 7 (2026-05-19):** wired end-to-end via
    /// [`crate::facade::chat_common::fetch_secret_inbox`].
    ///
    /// # Errors
    ///
    /// - `ClientError::SealedSender` — first bad envelope (tampered,
    ///   wrong-recipient, bad inner signature) aborts drain; remainder of
    ///   inbox stays pending (caller retries fetch_inbox).
    /// - `ClientError::Network` — gateway recv I/O failed.
    /// - `ClientError::Mls` — MLS decrypt failure (group epoch desync).
    pub async fn fetch_inbox(&self) -> Result<Vec<DecryptedMessage>> {
        fetch_secret_inbox(&self.core, self.chat_id).await
    }

    /// Добавить участника в Secret-чат. См. doc-comment
    /// [`crate::facade::CloudChat::add_participant`] — поведение mirror'ит
    /// CloudChat: stub `Ok(())` до wire-up blind-postman session 6+, real
    /// MLS Add через [`Self::add_member`] (peer + serialized KeyPackage).
    ///
    /// Add a participant to the Secret chat. Same behaviour as
    /// [`crate::facade::CloudChat::add_participant`].
    ///
    /// # Errors
    ///
    /// `ClientError::Mls / SealedSender / Network` once wired in session 6+.
    pub async fn add_participant(&self, _peer: PeerId) -> Result<()> {
        Ok(())
    }

    /// **F-CLIENT-FACADE-1 session 5 (2026-05-19):** real MLS Add для Secret-чата.
    /// Identical в семантике с [`crate::facade::CloudChat::add_member`] (см.
    /// doc-comment там) — Secret-mode-specific divergence (Welcome через
    /// blind-postman вместо Sealed Servers fan-out) лежит в layered transport
    /// session 6+ scope.
    ///
    /// **F-CLIENT-FACADE-1 session 5:** real MLS Add for the Secret chat.
    /// Same semantics as [`crate::facade::CloudChat::add_member`].
    ///
    /// # Errors
    ///
    /// Same as [`crate::facade::CloudChat::add_member`].
    pub async fn add_member(&self, peer: PeerId, key_package_bytes: Vec<u8>) -> Result<Vec<u8>> {
        mls_add_member(&self.core, self.chat_id, peer, &key_package_bytes).await
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
