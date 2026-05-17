//! UmbrellaGroup — обёртка над `openmls::MlsGroup` с политикой Umbrella.
//! UmbrellaGroup — wrapper around `openmls::MlsGroup` with Umbrella policy.
//!
//! ## Гарантии
//!
//! - **Политика группы инвариантна на всём сроке жизни объекта.** Группа создаётся либо как
//!   `Private` (1-1, малая группа) через [`UmbrellaGroup::create_private`], либо принимается
//!   как приглашение с заявленной ожидаемой политикой через [`UmbrellaGroup::join_from_welcome`].
//!   Клиент, ожидающий `Private`, проверяет отсутствие `ExternalPub` extension в GroupInfo
//!   пришедшего Welcome и отвергает приглашение если расхождение — это защита от downgrade-атаки
//!   на политику.
//! - **External operations заблокированы по-умолчанию.** `create_private` не добавляет
//!   `ExternalPub` extension в group_context_extensions, поэтому external commits невозможны:
//!   openmls требует этот extension для `external_commit_builder`. Входящие external
//!   application / commit messages отвергаются с [`MlsError::ExternalOperationForbidden`].
//! - **Все подписи — через `KeyStore`.** Любая операция (Create, Add, Remove, self_update,
//!   application) подписывается через [`UmbrellaDeviceSigner`], а он делегирует в `KeyStore`.
//!   Приватный device-key не попадает в адресное пространство openmls.
//! - **Принудительный rekey каждые 24 часа.** `PRIVATE_GROUP_MAX_LIFETIME_SECS` — верхняя
//!   граница; клиент обязан вызвать [`UmbrellaGroup::force_rekey`] если `needs_rekey(now_unix)`
//!   возвращает `true`, иначе post-compromise security размывается.
//! - **Wire format = pure ciphertext.** Handshake messages зашифрованы (openmls default
//!   `PURE_CIPHERTEXT_WIRE_FORMAT_POLICY`).
//!
//! ## Guarantees
//!
//! - **Policy is invariant for the lifetime of the object.** A group is either created as
//!   `Private` (1-1, small group) via [`UmbrellaGroup::create_private`], or it accepts an
//!   invitation with an explicit expected-policy via [`UmbrellaGroup::join_from_welcome`]. A
//!   client expecting `Private` verifies the absence of the `ExternalPub` extension in the
//!   Welcome's GroupInfo and rejects the invitation on mismatch — a defence against
//!   policy-downgrade attacks.
//! - **External operations blocked by default.** `create_private` does not add the
//!   `ExternalPub` extension to group_context_extensions, so external commits are impossible:
//!   openmls requires that extension for `external_commit_builder`. Incoming external
//!   application / commit messages are rejected with [`MlsError::ExternalOperationForbidden`].
//! - **All signatures go through `KeyStore`.** Every operation (Create, Add, Remove,
//!   self_update, application) is signed via [`UmbrellaDeviceSigner`], which delegates to
//!   `KeyStore`. The private device key never enters the openmls address space.
//! - **Forced rekey every 24 hours.** `PRIVATE_GROUP_MAX_LIFETIME_SECS` is the upper bound;
//!   the client must call [`UmbrellaGroup::force_rekey`] when `needs_rekey(now_unix)` returns
//!   `true`, otherwise post-compromise security erodes.
//! - **Wire format = pure ciphertext.** Handshake messages are encrypted (openmls's default
//!   `PURE_CIPHERTEXT_WIRE_FORMAT_POLICY`).

use openmls::extensions::ExtensionType;
#[cfg(test)]
use openmls::framing::MlsMessageIn;
use openmls::framing::{MlsMessageBodyIn, ProcessedMessageContent, ProtocolMessage, Sender};
use openmls::group::{GroupId, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, StagedWelcome};
use openmls::key_packages::{KeyPackage, Lifetime};
#[cfg(test)]
use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use openmls::prelude::{LeafNodeIndex, LeafNodeParameters, ProcessMessageError};
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsProvider};
use umbrella_crypto_primitives::MlockedSecret;
use zeroize::Zeroize;

use umbrella_identity::KeyStore;

use crate::caps::umbrella_capabilities;
use crate::ciphersuite::UmbrellaCiphersuite;
use crate::credential::build_credential_for_device;
use crate::error::{MlsError, Result};
use crate::group_policy::{
    GroupPolicy, KEY_PACKAGE_LIFETIME_SECS, PRIVATE_GROUP_MAX_LIFETIME_SECS,
};
use crate::signer::UmbrellaDeviceSigner;

/// Результат модификации состава группы (add / remove).
/// Commit для рассылки всем существующим членам, опциональный Welcome для новых,
/// и новый epoch после merge.
///
/// Outcome of a group-membership change (add / remove).
/// Commit to be distributed to existing members, optional Welcome for newcomers,
/// and the new epoch after merge.
pub struct MemberChangeOutcome {
    /// TLS-сериализованный MlsMessage (commit). TLS-serialized MlsMessage (commit).
    pub commit: Vec<u8>,
    /// TLS-сериализованный Welcome (Some если добавили нового члена).
    /// TLS-serialized Welcome (Some if a new member was added).
    pub welcome: Option<Vec<u8>>,
    /// Epoch группы после применения commit. Group epoch after the commit is applied.
    pub epoch: u64,
}

/// `Debug` скрывает MLS wire payloads: commit/welcome не должны копироваться в логи.
/// `Debug` redacts MLS wire payloads: commit/welcome bytes must not be copied into logs.
impl core::fmt::Debug for MemberChangeOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let welcome_len = self.welcome.as_ref().map(Vec::len);
        f.debug_struct("MemberChangeOutcome")
            .field("commit_len", &self.commit.len())
            .field("commit", &"<redacted>")
            .field("welcome_len", &welcome_len)
            .field("welcome", &"<redacted>")
            .field("epoch", &self.epoch)
            .finish()
    }
}

/// Результат обработки входящего MLS-сообщения.
/// Outcome of processing an incoming MLS message.
pub enum IncomingMessage {
    /// Application-payload от участника; sender_index — индекс автора в ratchet tree.
    /// Application payload from a member; sender_index is the author's ratchet-tree leaf index.
    Application {
        /// Leaf index автора сообщения. Author leaf index.
        sender_index: u32,
        /// Сам payload (расшифрованное содержимое). The payload (decrypted content).
        payload: Vec<u8>,
    },
    /// Handshake commit был обработан и применён; epoch теперь новый.
    /// A handshake commit was processed and applied; the epoch has advanced.
    CommitApplied {
        /// Новый epoch группы после merge. New group epoch after merge.
        epoch: u64,
        /// Был ли данный клиент удалён этим commit'ом. Whether this client was removed by the commit.
        self_removed: bool,
    },
    /// Proposal поставлен в очередь (ожидает commit).
    /// A proposal was queued (awaiting commit).
    ProposalQueued,
}

/// `Debug` скрывает расшифрованный payload: журналы не должны становиться копией переписки.
/// `Debug` redacts decrypted payload: logs must not become a copy of private messages.
impl core::fmt::Debug for IncomingMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Application {
                sender_index,
                payload,
            } => f
                .debug_struct("Application")
                .field("sender_index", sender_index)
                .field("payload_len", &payload.len())
                .field("payload", &"<redacted>")
                .finish(),
            Self::CommitApplied {
                epoch,
                self_removed,
            } => f
                .debug_struct("CommitApplied")
                .field("epoch", epoch)
                .field("self_removed", self_removed)
                .finish(),
            Self::ProposalQueued => f.write_str("ProposalQueued"),
        }
    }
}

/// Группа MLS по политике Umbrella — обёртка над `openmls::MlsGroup` с enforce-политикой.
/// MLS group under Umbrella policy — wraps `openmls::MlsGroup` and enforces the policy.
pub struct UmbrellaGroup {
    inner: MlsGroup,
    policy: GroupPolicy,
    ciphersuite: UmbrellaCiphersuite,
    device_index: u32,
    last_rekey_at_unix: u64,
}

impl UmbrellaGroup {
    /// Создаёт новую Private-группу с creator = device_index в keystore.
    /// Creates a new Private group with creator = device_index in keystore.
    ///
    /// Группа инициализирована с canonical Umbrella capabilities (whitelist Ed25519/Ed448),
    /// `use_ratchet_tree_extension = true` (Welcome самодостаточен), без `ExternalPub`
    /// extension (external init невозможен).
    ///
    /// The group is initialised with canonical Umbrella capabilities (Ed25519/Ed448 whitelist),
    /// `use_ratchet_tree_extension = true` (self-contained Welcome), and no `ExternalPub`
    /// extension (external init is impossible).
    pub fn create_private(
        provider: &impl OpenMlsProvider,
        keystore: &dyn KeyStore,
        device_index: u32,
        ciphersuite: UmbrellaCiphersuite,
        group_id: GroupId,
        now_unix: u64,
    ) -> Result<Self> {
        // Pre-check: provider.crypto().supports(ciphersuite). Защита постулата 14 от misuse
        // (например, classical UmbrellaProvider + X-Wing ciphersuite → panic в
        // openmls_rust_crypto-0.5.1 unimplemented!() для HpkeKemType::XWingKemDraft6).
        // Pre-check: provider.crypto().supports(ciphersuite). Postulate-14 protection from
        // misuse (e.g., classical UmbrellaProvider + X-Wing ciphersuite → panic in
        // openmls_rust_crypto-0.5.1 unimplemented!() for HpkeKemType::XWingKemDraft6).
        provider
            .crypto()
            .supports(ciphersuite.to_openmls())
            .map_err(|_| MlsError::GroupOperation {
                kind: "provider does not support requested ciphersuite",
            })?;

        let signer = UmbrellaDeviceSigner::new(keystore, device_index)?;
        let credential = build_credential_for_device(keystore, device_index)?;

        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite.to_openmls())
            .capabilities(umbrella_capabilities())
            .lifetime(Lifetime::new(KEY_PACKAGE_LIFETIME_SECS))
            .use_ratchet_tree_extension(true)
            .build();

        let inner = MlsGroup::new_with_group_id(provider, &signer, &config, group_id, credential)
            .map_err(|_| MlsError::GroupOperation {
            kind: "MlsGroup::new_with_group_id failed",
        })?;

        Ok(Self {
            inner,
            policy: GroupPolicy::Private,
            ciphersuite,
            device_index,
            last_rekey_at_unix: now_unix,
        })
    }

    /// Присоединяется к существующей группе, декодируя Welcome-сообщение и проверяя
    /// `expected_policy` против observed GroupInfo (наличие/отсутствие `ExternalPub`
    /// extension). На любом mismatch отказ с [`MlsError::ExternalOperationForbidden`].
    ///
    /// Joins an existing group by decoding a Welcome message and verifying `expected_policy`
    /// against the observed GroupInfo (presence/absence of `ExternalPub` extension). Any
    /// mismatch rejects with [`MlsError::ExternalOperationForbidden`].
    pub fn join_from_welcome(
        provider: &impl OpenMlsProvider,
        keystore: &dyn KeyStore,
        device_index: u32,
        welcome_bytes: &[u8],
        expected_policy: GroupPolicy,
        now_unix: u64,
    ) -> Result<Self> {
        // Сам факт регистрации device_index — единственное что нужно от keystore на этом этапе.
        // Сигнирующий device-key попадёт в application / handshake messages позднее.
        // The only thing we need from keystore at this point is the device-index registration check.
        // The signing device key will be used on application / handshake messages later.
        if keystore.device_public(device_index).is_none() {
            return Err(MlsError::Identity(
                umbrella_identity::IdentityError::UnknownDevice {
                    index: device_index,
                },
            ));
        }

        // F-37 защита: bounds-check + std::panic::catch_unwind через parse_mls_message_safe.
        // tls_codec-0.4.2 panics на 5-байтовом malformed input `[0,0,0,1,192]` через
        // QUIC variable-length integer assertion; raw `tls_deserialize_exact` propagates panic
        // вверх по стеку. См. crate::parser + per-crate/umbrella-mls.md F-37 detailed analysis.
        // F-37 protection: bounds-check + std::panic::catch_unwind via parse_mls_message_safe.
        // tls_codec-0.4.2 panics on the 5-byte malformed input `[0,0,0,1,192]` via the QUIC
        // variable-length integer assertion; a raw `tls_deserialize_exact` propagates the panic
        // up the stack. See crate::parser + per-crate/umbrella-mls.md F-37 detailed analysis.
        let message =
            crate::parser::parse_mls_message_safe(welcome_bytes).map_err(|e| match e {
                MlsError::ParserPanic { kind } => MlsError::ParserPanic { kind },
                _ => MlsError::Codec {
                    kind: "welcome decode failed",
                },
            })?;
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => {
                return Err(MlsError::Welcome {
                    kind: "expected Welcome body, got another MLS message type",
                })
            }
        };

        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let staged = StagedWelcome::new_from_welcome(provider, &join_config, welcome, None)
            .map_err(|_| MlsError::Welcome {
                kind: "StagedWelcome::new_from_welcome failed",
            })?;

        // Ciphersuite берём из подтверждённого GroupContext: whitelist-проверка через наш
        // converter откажет в ECDSA даже если злоумышленник ухитрится поставить ECDSA-suite
        // в Welcome (что openmls уже отвергнет при валидации capabilities, но дублируем на
        // уровне типов).
        // Ciphersuite comes from the verified GroupContext: our whitelist converter rejects
        // ECDSA even if an attacker slipped an ECDSA suite into the Welcome (which openmls
        // would already reject via capabilities validation; we mirror it at the type level).
        let ciphersuite = UmbrellaCiphersuite::from_openmls(staged.group_context().ciphersuite())?;

        // Pre-check: provider.crypto().supports(ciphersuite). Защита постулата 14: classical
        // provider не должен попасть в `unimplemented!()` panic при попытке принять X-Wing
        // Welcome — лучше явный Err через supports(), чем `staged.into_group(provider)` panic.
        // Pre-check: provider.crypto().supports(ciphersuite). Postulate-14 protection: a
        // classical provider must not reach `unimplemented!()` panic when trying to accept an
        // X-Wing Welcome — a clean Err via supports() is preferable to a `staged.into_group`
        // panic.
        provider
            .crypto()
            .supports(ciphersuite.to_openmls())
            .map_err(|_| MlsError::Welcome {
                kind: "provider does not support Welcome's ciphersuite",
            })?;

        if expected_policy.is_private() {
            let has_external_pub = staged
                .group_context()
                .extensions()
                .iter()
                .any(|e| matches!(e.extension_type(), ExtensionType::ExternalPub));
            if has_external_pub {
                return Err(MlsError::ExternalOperationForbidden);
            }
        }

        let inner = staged.into_group(provider).map_err(|_| MlsError::Welcome {
            kind: "StagedWelcome::into_group failed",
        })?;

        Ok(Self {
            inner,
            policy: expected_policy,
            ciphersuite,
            device_index,
            last_rekey_at_unix: now_unix,
        })
    }

    /// Добавляет участников через их KeyPackages. Commit автоматически применяется (merge).
    /// Adds members by their KeyPackages. The commit is automatically merged.
    pub fn add_members(
        &mut self,
        provider: &impl OpenMlsProvider,
        keystore: &dyn KeyStore,
        key_packages: &[KeyPackage],
        now_unix: u64,
    ) -> Result<MemberChangeOutcome> {
        let signer = UmbrellaDeviceSigner::new(keystore, self.device_index)?;
        let (commit, welcome, _group_info) = self
            .inner
            .add_members(provider, &signer, key_packages)
            .map_err(|_| MlsError::GroupOperation {
                kind: "add_members failed",
            })?;

        self.inner
            .merge_pending_commit(provider)
            .map_err(|_| MlsError::GroupOperation {
                kind: "merge_pending_commit after add failed",
            })?;

        self.last_rekey_at_unix = now_unix;

        Ok(MemberChangeOutcome {
            commit: commit
                .tls_serialize_detached()
                .map_err(|_| MlsError::Codec {
                    kind: "commit serialize failed",
                })?,
            welcome: Some(
                welcome
                    .tls_serialize_detached()
                    .map_err(|_| MlsError::Codec {
                        kind: "welcome serialize failed",
                    })?,
            ),
            epoch: self.inner.epoch().as_u64(),
        })
    }

    /// Удаляет участников по их leaf-индексам. Commit автоматически применяется.
    /// Removes members by leaf index. The commit is automatically merged.
    pub fn remove_members(
        &mut self,
        provider: &impl OpenMlsProvider,
        keystore: &dyn KeyStore,
        member_indices: &[u32],
        now_unix: u64,
    ) -> Result<MemberChangeOutcome> {
        let signer = UmbrellaDeviceSigner::new(keystore, self.device_index)?;
        let indices: Vec<LeafNodeIndex> = member_indices
            .iter()
            .map(|&i| LeafNodeIndex::new(i))
            .collect();

        let (commit, welcome_opt, _group_info) = self
            .inner
            .remove_members(provider, &signer, &indices)
            .map_err(|_| MlsError::GroupOperation {
                kind: "remove_members failed",
            })?;

        self.inner
            .merge_pending_commit(provider)
            .map_err(|_| MlsError::GroupOperation {
                kind: "merge_pending_commit after remove failed",
            })?;

        self.last_rekey_at_unix = now_unix;

        let welcome = welcome_opt
            .map(|w| w.tls_serialize_detached())
            .transpose()
            .map_err(|_| MlsError::Codec {
                kind: "welcome serialize (after remove) failed",
            })?;

        Ok(MemberChangeOutcome {
            commit: commit
                .tls_serialize_detached()
                .map_err(|_| MlsError::Codec {
                    kind: "commit serialize (after remove) failed",
                })?,
            welcome,
            epoch: self.inner.epoch().as_u64(),
        })
    }

    /// Принудительное обновление group_secret без изменения состава (post-compromise security).
    /// Forced group_secret refresh without membership changes (post-compromise security).
    pub fn force_rekey(
        &mut self,
        provider: &impl OpenMlsProvider,
        keystore: &dyn KeyStore,
        now_unix: u64,
    ) -> Result<Vec<u8>> {
        let signer = UmbrellaDeviceSigner::new(keystore, self.device_index)?;
        let bundle = self
            .inner
            .self_update(provider, &signer, LeafNodeParameters::default())
            .map_err(|_| MlsError::GroupOperation {
                kind: "self_update (force_rekey) failed",
            })?;

        let commit_bytes =
            bundle
                .commit()
                .tls_serialize_detached()
                .map_err(|_| MlsError::Codec {
                    kind: "rekey commit serialize failed",
                })?;

        self.inner
            .merge_pending_commit(provider)
            .map_err(|_| MlsError::GroupOperation {
                kind: "merge_pending_commit after rekey failed",
            })?;

        self.last_rekey_at_unix = now_unix;
        Ok(commit_bytes)
    }

    /// Шифрует application-сообщение для рассылки всем членам группы.
    /// Encrypts an application message for delivery to all group members.
    pub fn encrypt_application(
        &mut self,
        provider: &impl OpenMlsProvider,
        keystore: &dyn KeyStore,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let signer = UmbrellaDeviceSigner::new(keystore, self.device_index)?;
        let msg = self
            .inner
            .create_message(provider, &signer, plaintext)
            .map_err(|_| MlsError::GroupOperation {
                kind: "create_message failed",
            })?;
        msg.tls_serialize_detached().map_err(|_| MlsError::Codec {
            kind: "application message serialize failed",
        })
    }

    /// Обрабатывает входящее MLS-сообщение (private или public).
    /// Для private/public message: запускает process_message, merge'ит commit если нужно.
    /// Welcome/KeyPackage/GroupInfo на входе отвергаются — эти типы не маршрутизируются как
    /// incoming в активную группу.
    ///
    /// Processes an incoming MLS message (private or public). For private/public: runs
    /// process_message, merges the commit if needed. Welcome/KeyPackage/GroupInfo are rejected
    /// on input — these types are not routed as incoming to an active group.
    pub fn process_incoming(
        &mut self,
        provider: &impl OpenMlsProvider,
        bytes: &[u8],
    ) -> Result<IncomingMessage> {
        // F-37 защита: bounds-check + std::panic::catch_unwind через parse_mls_message_safe.
        // F-37 protection: bounds-check + std::panic::catch_unwind via parse_mls_message_safe.
        let message = crate::parser::parse_mls_message_safe(bytes).map_err(|e| match e {
            MlsError::ParserPanic { kind } => MlsError::ParserPanic { kind },
            _ => MlsError::Codec {
                kind: "incoming MlsMessage decode failed",
            },
        })?;

        let protocol_message: ProtocolMessage = match message.extract() {
            MlsMessageBodyIn::PrivateMessage(m) => ProtocolMessage::from(m),
            MlsMessageBodyIn::PublicMessage(m) => ProtocolMessage::from(m),
            MlsMessageBodyIn::Welcome(_) => {
                return Err(MlsError::Welcome {
                    kind: "welcome arrived at process_incoming (not an active-group input)",
                })
            }
            MlsMessageBodyIn::KeyPackage(_) | MlsMessageBodyIn::GroupInfo(_) => {
                return Err(MlsError::Codec {
                    kind: "unexpected MlsMessage body on process_incoming",
                })
            }
        };

        // openmls 0.8.1 uses a debug assertion on some AEAD verification failures. Treat
        // dependency panics during adversarial message processing as explicit rejection instead
        // of letting malformed network input unwind through the client process.
        let processed = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.inner.process_message(provider, protocol_message)
        })) {
            Ok(Ok(processed)) => processed,
            Ok(Err(e)) => {
                return Err(match e {
                    ProcessMessageError::UnauthorizedExternalApplicationMessage
                    | ProcessMessageError::UnauthorizedExternalCommitMessage
                    | ProcessMessageError::UnsupportedProposalType => {
                        MlsError::ExternalOperationForbidden
                    }
                    _ => MlsError::GroupOperation {
                        kind: "process_message failed",
                    },
                })
            }
            Err(_) => {
                return Err(MlsError::ProcessingPanic {
                    kind: "MlsGroup::process_message panicked",
                })
            }
        };

        let sender = processed.sender().clone();
        let content = processed.into_content();

        match content {
            ProcessedMessageContent::ApplicationMessage(app) => {
                let sender_index = match sender {
                    Sender::Member(idx) => idx.u32(),
                    // RFC 9420: application messages from non-members are rejected at protocol
                    // level (openmls уже отдаёт UnauthorizedExternalApplicationMessage выше).
                    // Если попали сюда — это library-bug; возвращаем policy reject.
                    // RFC 9420: non-member application messages are rejected at protocol level
                    // (openmls would already return UnauthorizedExternalApplicationMessage above).
                    // If we reach here it's a library bug; surface as policy reject.
                    _ => return Err(MlsError::ExternalOperationForbidden),
                };
                Ok(IncomingMessage::Application {
                    sender_index,
                    payload: app.into_bytes(),
                })
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                // Для приватных групп отвергаем external commits явно.
                // Reject external commits explicitly for private groups.
                if self.policy.is_private() && matches!(sender, Sender::NewMemberCommit) {
                    return Err(MlsError::ExternalOperationForbidden);
                }

                let self_removed = staged.self_removed();
                self.inner
                    .merge_staged_commit(provider, *staged)
                    .map_err(|_| MlsError::GroupOperation {
                        kind: "merge_staged_commit failed",
                    })?;
                self.last_rekey_at_unix = 0; // caller обновит через mark_rekey_if_applicable.
                Ok(IncomingMessage::CommitApplied {
                    epoch: self.inner.epoch().as_u64(),
                    self_removed,
                })
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                // Для приватных групп external proposals уже отвергаются выше через
                // UnsupportedProposalType; здесь только member-proposals.
                // External proposals for private groups are already rejected via
                // UnsupportedProposalType above; only member proposals reach here.
                self.inner
                    .store_pending_proposal(provider.storage(), *proposal)
                    .map_err(|_| MlsError::GroupOperation {
                        kind: "store_pending_proposal failed",
                    })?;
                Ok(IncomingMessage::ProposalQueued)
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Err(MlsError::ExternalOperationForbidden)
            }
        }
    }

    /// Обновляет метку последнего rekey; следует вызвать после [`Self::process_incoming`] с
    /// `CommitApplied`, если вызывающий знает текущее unix-время (openmls не даёт его нам
    /// прямым путём при входящем commit).
    ///
    /// Updates the last-rekey timestamp; call after [`Self::process_incoming`] returns
    /// `CommitApplied` when the caller has a current unix time (openmls does not supply it on
    /// incoming commits).
    pub fn mark_rekey_observed(&mut self, now_unix: u64) {
        self.last_rekey_at_unix = now_unix;
    }

    /// True если с момента последнего rekey прошло >= `PRIVATE_GROUP_MAX_LIFETIME_SECS`.
    /// True if at least `PRIVATE_GROUP_MAX_LIFETIME_SECS` have elapsed since the last rekey.
    pub fn needs_rekey(&self, now_unix: u64) -> bool {
        now_unix.saturating_sub(self.last_rekey_at_unix) >= PRIVATE_GROUP_MAX_LIFETIME_SECS
    }

    /// Политика группы (invariant). Group policy (invariant).
    pub fn policy(&self) -> GroupPolicy {
        self.policy
    }

    /// Текущий ciphersuite. Current ciphersuite.
    pub fn ciphersuite(&self) -> UmbrellaCiphersuite {
        self.ciphersuite
    }

    /// Device index локального члена в ratchet tree.
    /// Device index of the local member in the ratchet tree.
    pub fn device_index(&self) -> u32 {
        self.device_index
    }

    /// Текущий epoch группы. Current group epoch.
    pub fn epoch(&self) -> u64 {
        self.inner.epoch().as_u64()
    }

    /// Leaf index локального члена в ratchet tree.
    /// Local member's leaf index in the ratchet tree.
    pub fn own_leaf_index(&self) -> u32 {
        self.inner.own_leaf_index().u32()
    }

    /// Количество активных членов группы. Number of active group members.
    pub fn member_count(&self) -> usize {
        self.inner.members().count()
    }

    /// Group ID (неизменяемый на всём сроке жизни группы).
    /// Group ID (immutable for the group's lifetime).
    pub fn group_id(&self) -> &GroupId {
        self.inner.group_id()
    }

    /// Unix-время последнего rekey, зафиксированного этим клиентом.
    /// Unix time of the last rekey observed by this client.
    pub fn last_rekey_at_unix(&self) -> u64 {
        self.last_rekey_at_unix
    }

    /// Экспортирует производный секрет из текущей MLS-эпохи (RFC 9420 §8.5).
    /// Используется в SFrame key derivation с label = `"SFrame 1.0 Base Key"`
    /// и context = `epoch_number_u64_be`; также доступен любым надстройкам,
    /// требующим group-scoped secret с domain separation через `label`.
    ///
    /// Exports a derived secret from the current MLS epoch (RFC 9420 §8.5).
    /// Used by SFrame key derivation with label = `"SFrame 1.0 Base Key"` and
    /// context = `epoch_number_u64_be`; also available to any extension that
    /// needs a group-scoped secret with label-based domain separation.
    ///
    /// Вывод оборачивается в [`MlockedSecret<[u8; MAX_EXPORTER_LEN]>`]:
    /// остаток буфера (при `len < MAX_EXPORTER_LEN`) заполнен нулями и
    /// будет zeroize'нут на drop. Round-5 device-capture closure
    /// F-PHD-DC-R11-1: MlockedSecret заменил `secrecy::SecretBox` чтобы
    /// добавить `libc::mlock` поверх baseline zeroize-on-drop. Caller
    /// должен использовать ровно первые `len` байт через `.expose()[..len]`.
    ///
    /// The output is wrapped in [`MlockedSecret<[u8; MAX_EXPORTER_LEN]>`]:
    /// the tail of the buffer (for `len < MAX_EXPORTER_LEN`) is zero-
    /// filled and will be zeroized on drop. Round-5 device-capture
    /// closure F-PHD-DC-R11-1: MlockedSecret replaced `secrecy::SecretBox`
    /// to add `libc::mlock` on top of baseline zeroize-on-drop. The
    /// caller must use exactly the first `len` bytes via
    /// `.expose()[..len]`.
    ///
    /// # Ошибки / Errors
    ///
    /// - `len == 0` или `len > MAX_EXPORTER_LEN` → [`MlsError::GroupOperation`].
    /// - Внутренний сбой `openmls::MlsGroup::export_secret` (группа evicted и
    ///   т.п.) → [`MlsError::GroupOperation`].
    ///
    /// - `len == 0` or `len > MAX_EXPORTER_LEN` → [`MlsError::GroupOperation`].
    /// - Inner `openmls::MlsGroup::export_secret` failure (group evicted, etc.)
    ///   → [`MlsError::GroupOperation`].
    pub fn exporter_secret(
        &self,
        provider: &impl OpenMlsProvider,
        label: &str,
        context: &[u8],
        len: usize,
    ) -> Result<MlockedSecret<[u8; MAX_EXPORTER_LEN]>> {
        if !(1..=MAX_EXPORTER_LEN).contains(&len) {
            return Err(MlsError::GroupOperation {
                kind: "exporter_secret length out of range (1..=64)",
            });
        }

        let mut raw = self
            .inner
            .export_secret(provider.crypto(), label, context, len)
            .map_err(|_| MlsError::GroupOperation {
                kind: "MlsGroup::export_secret failed",
            })?;

        let mut buf = [0u8; MAX_EXPORTER_LEN];
        buf[..len].copy_from_slice(&raw);
        raw.zeroize();
        let wrapped = MlockedSecret::new(buf);
        buf.zeroize();
        Ok(wrapped)
    }
}

/// Максимальная длина вывода [`UmbrellaGroup::exporter_secret`] — 64 байта
/// (достаточно для SHA-512 и покрывает Nh всех ciphersuites RFC 9420).
///
/// Maximum length of [`UmbrellaGroup::exporter_secret`] output — 64 bytes
/// (enough for SHA-512, covers Nh across all RFC 9420 ciphersuites).
pub const MAX_EXPORTER_LEN: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use openmls::framing::WireFormat;
    use openmls::group::GroupId;
    use openmls::key_packages::KeyPackage;
    use proptest::prelude::*;

    use umbrella_identity::{Clock, IdentitySeed, InMemoryKeyStore, MnemonicLanguage, SystemClock};

    use crate::{
        build_device_key_package, provider::UmbrellaProvider, GroupPolicy, UmbrellaCiphersuite,
        UMBRELLA_DEFAULT_CIPHERSUITE,
    };

    /// Ядро ciphersuite для большинства тестов (default по Umbrella). Быстрее на ARM-mobile,
    /// не требует AES-NI, PSK-совместим.
    const CS: UmbrellaCiphersuite = UMBRELLA_DEFAULT_CIPHERSUITE;

    /// Стандартный unix-timestamp для тестов (2023-11-14 22:13:20).
    const T0: u64 = 1_700_000_000;

    #[test]
    fn incoming_message_debug_redacts_application_payload() {
        let msg = IncomingMessage::Application {
            sender_index: 42,
            payload: b"private-mls-secret".to_vec(),
        };

        let debug = format!("{msg:?}");

        assert!(
            !debug.contains("112, 114, 105, 118, 97, 116, 101"),
            "Debug output must not leak decrypted MLS payload bytes: {debug}"
        );
        assert!(
            debug.contains("payload_len"),
            "Debug output should keep length metadata for diagnostics: {debug}"
        );
    }

    #[test]
    fn member_change_outcome_debug_redacts_wire_payloads() {
        let outcome = MemberChangeOutcome {
            commit: b"mls-commit-wire-payload".to_vec(),
            welcome: Some(b"mls-welcome-wire-payload".to_vec()),
            epoch: 77,
        };

        let debug = format!("{outcome:?}");

        assert!(
            !debug.contains("109, 108, 115, 45"),
            "Debug output must not leak MLS commit/welcome wire bytes: {debug}"
        );
        assert!(
            debug.contains("commit_len") && debug.contains("welcome_len"),
            "Debug output should keep wire length metadata: {debug}"
        );
    }

    /// Тестовый клиент: собственный keystore + собственный провайдер + device index.
    struct Client {
        ks: Arc<InMemoryKeyStore>,
        provider: UmbrellaProvider,
        device_index: u32,
    }

    impl Client {
        /// Создаёт свежий client с выставленным device_index.
        fn new(device_index: u32) -> Self {
            let mut rng = rand_core::OsRng;
            let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
            let ks =
                InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>).unwrap();
            ks.add_device(device_index, None).unwrap();
            Self {
                ks: Arc::new(ks),
                provider: UmbrellaProvider::default(),
                device_index,
            }
        }

        /// Публикует KeyPackage: строит bundle, сохраняет приватные части в собственном provider,
        /// возвращает публичный KeyPackage для рассылки.
        fn publish_key_package(&self, cs: UmbrellaCiphersuite) -> KeyPackage {
            build_device_key_package(&self.provider, self.ks.as_ref(), self.device_index, cs)
                .expect("build_device_key_package")
                .key_package()
                .clone()
        }
    }

    fn fresh_group_id(tag: u8) -> GroupId {
        GroupId::from_slice(&[tag; 16])
    }

    /// Создаёт dyadic группу: Alice создаёт, добавляет Bob по его KeyPackage, Bob join'ится из Welcome.
    fn make_dyadic_group() -> (Client, Client, UmbrellaGroup, UmbrellaGroup) {
        let alice = Client::new(0);
        let bob = Client::new(0);
        let bob_kp = bob.publish_key_package(CS);

        let mut alice_group = UmbrellaGroup::create_private(
            &alice.provider,
            alice.ks.as_ref(),
            alice.device_index,
            CS,
            fresh_group_id(0xA1),
            T0,
        )
        .expect("alice create_private");

        let outcome = alice_group
            .add_members(&alice.provider, alice.ks.as_ref(), &[bob_kp], T0 + 10)
            .expect("alice add_members(bob)");

        let welcome_bytes = outcome.welcome.expect("welcome must exist on add");

        let bob_group = UmbrellaGroup::join_from_welcome(
            &bob.provider,
            bob.ks.as_ref(),
            bob.device_index,
            &welcome_bytes,
            GroupPolicy::Private,
            T0 + 10,
        )
        .expect("bob join_from_welcome");

        (alice, bob, alice_group, bob_group)
    }

    /// Hi-level helper: Alice and Bob send `msg_alice` / `msg_bob` to each other, expect
    /// round-trip equality.
    fn exchange_two_way(
        alice: &Client,
        alice_g: &mut UmbrellaGroup,
        bob: &Client,
        bob_g: &mut UmbrellaGroup,
        msg_alice: &[u8],
        msg_bob: &[u8],
    ) {
        let a_to_b = alice_g
            .encrypt_application(&alice.provider, alice.ks.as_ref(), msg_alice)
            .expect("alice encrypt");
        match bob_g
            .process_incoming(&bob.provider, &a_to_b)
            .expect("bob process alice")
        {
            IncomingMessage::Application { payload, .. } => {
                assert_eq!(payload, msg_alice, "alice→bob payload must round-trip");
            }
            other => panic!("bob expected Application, got {other:?}"),
        }

        let b_to_a = bob_g
            .encrypt_application(&bob.provider, bob.ks.as_ref(), msg_bob)
            .expect("bob encrypt");
        match alice_g
            .process_incoming(&alice.provider, &b_to_a)
            .expect("alice process bob")
        {
            IncomingMessage::Application { payload, .. } => {
                assert_eq!(payload, msg_bob, "bob→alice payload must round-trip");
            }
            other => panic!("alice expected Application, got {other:?}"),
        }
    }

    // === Basic create/accessors ===

    #[test]
    fn create_private_sets_policy_ciphersuite_and_epoch() {
        let alice = Client::new(0);
        let g = UmbrellaGroup::create_private(
            &alice.provider,
            alice.ks.as_ref(),
            0,
            CS,
            fresh_group_id(1),
            T0,
        )
        .unwrap();
        assert_eq!(g.policy(), GroupPolicy::Private);
        assert_eq!(g.ciphersuite(), CS);
        assert_eq!(g.epoch(), 0);
        assert_eq!(g.last_rekey_at_unix(), T0);
    }

    #[test]
    fn create_private_member_count_is_one_and_own_leaf_zero() {
        let alice = Client::new(0);
        let g = UmbrellaGroup::create_private(
            &alice.provider,
            alice.ks.as_ref(),
            0,
            CS,
            fresh_group_id(2),
            T0,
        )
        .unwrap();
        assert_eq!(g.member_count(), 1, "creator is the only member");
        assert_eq!(g.own_leaf_index(), 0, "creator leaf index is 0");
    }

    #[test]
    fn create_private_group_id_matches_input() {
        let alice = Client::new(0);
        let gid = fresh_group_id(0xEE);
        let g = UmbrellaGroup::create_private(
            &alice.provider,
            alice.ks.as_ref(),
            0,
            CS,
            gid.clone(),
            T0,
        )
        .unwrap();
        assert_eq!(g.group_id(), &gid);
    }

    #[test]
    fn create_private_with_unknown_device_rejected() {
        let alice = Client::new(0);
        let result = UmbrellaGroup::create_private(
            &alice.provider,
            alice.ks.as_ref(),
            99, // not registered
            CS,
            fresh_group_id(3),
            T0,
        );
        assert!(matches!(
            result,
            Err(MlsError::Identity(
                umbrella_identity::IdentityError::UnknownDevice { index: 99 }
            ))
        ));
    }

    #[test]
    fn create_private_for_x25519_whitelisted_ciphersuites_succeeds() {
        // Текущий provider `openmls_rust_crypto` поддерживает X25519-based ciphersuites.
        // X448 и X-Wing требуют libcrux/separate backend — тесты для них будут активированы
        // когда мы подключим соответствующий provider в Этапе 8 (PQ hybrid).
        // Current provider `openmls_rust_crypto` supports X25519-based ciphersuites. X448 and
        // X-Wing require libcrux or a separate backend — tests for them activate when we wire
        // that provider in Stage 8 (PQ hybrid).
        for (tag, cs) in [
            (0x10u8, UmbrellaCiphersuite::Mls128X25519AesGcmSha256Ed25519),
            (0x11, UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519),
        ] {
            let alice = Client::new(0);
            let g = UmbrellaGroup::create_private(
                &alice.provider,
                alice.ks.as_ref(),
                0,
                cs,
                fresh_group_id(tag),
                T0,
            )
            .unwrap_or_else(|e| panic!("ciphersuite {cs:?} must work: {e:?}"));
            assert_eq!(g.ciphersuite(), cs);
        }
    }

    // === Two-party round-trip ===

    #[test]
    fn two_party_round_trip_alice_to_bob() {
        let (alice, bob, mut alice_g, mut bob_g) = make_dyadic_group();
        assert_eq!(alice_g.member_count(), 2);
        assert_eq!(bob_g.member_count(), 2);
        assert_eq!(alice_g.epoch(), 1, "epoch advances on add_members");
        assert_eq!(bob_g.epoch(), 1, "bob joins at epoch 1");

        let ct = alice_g
            .encrypt_application(&alice.provider, alice.ks.as_ref(), b"hello-bob")
            .unwrap();
        match bob_g.process_incoming(&bob.provider, &ct).unwrap() {
            IncomingMessage::Application {
                sender_index,
                payload,
            } => {
                assert_eq!(sender_index, 0);
                assert_eq!(payload, b"hello-bob");
            }
            other => panic!("expected Application, got {other:?}"),
        }
    }

    #[test]
    fn two_party_bidirectional_exchange() {
        let (alice, bob, mut ag, mut bg) = make_dyadic_group();
        exchange_two_way(&alice, &mut ag, &bob, &mut bg, b"alice-1", b"bob-1");
        exchange_two_way(&alice, &mut ag, &bob, &mut bg, b"alice-2", b"bob-2");
    }

    #[test]
    fn welcome_bytes_parse_as_welcome_body() {
        let alice = Client::new(0);
        let bob = Client::new(0);
        let bob_kp = bob.publish_key_package(CS);

        let mut ag = UmbrellaGroup::create_private(
            &alice.provider,
            alice.ks.as_ref(),
            0,
            CS,
            fresh_group_id(0x21),
            T0,
        )
        .unwrap();
        let outcome = ag
            .add_members(&alice.provider, alice.ks.as_ref(), &[bob_kp], T0)
            .unwrap();
        let welcome_bytes = outcome.welcome.unwrap();

        let parsed = MlsMessageIn::tls_deserialize_exact(&welcome_bytes).unwrap();
        assert!(matches!(parsed.extract(), MlsMessageBodyIn::Welcome(_)));
    }

    #[test]
    fn commit_bytes_wire_format_is_private_message() {
        let alice = Client::new(0);
        let bob = Client::new(0);
        let bob_kp = bob.publish_key_package(CS);

        let mut ag = UmbrellaGroup::create_private(
            &alice.provider,
            alice.ks.as_ref(),
            0,
            CS,
            fresh_group_id(0x22),
            T0,
        )
        .unwrap();
        let outcome = ag
            .add_members(&alice.provider, alice.ks.as_ref(), &[bob_kp], T0)
            .unwrap();

        let parsed = MlsMessageIn::tls_deserialize_exact(&outcome.commit).unwrap();
        assert_eq!(
            parsed.wire_format(),
            WireFormat::PrivateMessage,
            "private-group handshake must be encrypted (PURE_CIPHERTEXT policy)"
        );
    }

    // === Membership transitions ===

    #[test]
    fn add_third_party_all_three_members_exchange_messages() {
        let (alice, bob, mut ag, mut bg) = make_dyadic_group();
        let carol = Client::new(0);
        let carol_kp = carol.publish_key_package(CS);

        let outcome = ag
            .add_members(&alice.provider, alice.ks.as_ref(), &[carol_kp], T0 + 20)
            .unwrap();
        assert_eq!(ag.epoch(), 2);
        assert_eq!(ag.member_count(), 3);

        // Bob получает commit, применяет.
        match bg.process_incoming(&bob.provider, &outcome.commit).unwrap() {
            IncomingMessage::CommitApplied {
                epoch,
                self_removed,
            } => {
                assert_eq!(epoch, 2);
                assert!(!self_removed);
            }
            other => panic!("bob expected CommitApplied, got {other:?}"),
        }
        assert_eq!(bg.epoch(), 2);
        assert_eq!(bg.member_count(), 3);

        // Carol join'ится.
        let mut cg = UmbrellaGroup::join_from_welcome(
            &carol.provider,
            carol.ks.as_ref(),
            0,
            &outcome.welcome.unwrap(),
            GroupPolicy::Private,
            T0 + 20,
        )
        .unwrap();
        assert_eq!(cg.epoch(), 2);
        assert_eq!(cg.member_count(), 3);

        // Alice → Carol
        let ct = ag
            .encrypt_application(&alice.provider, alice.ks.as_ref(), b"hi-carol")
            .unwrap();
        match cg.process_incoming(&carol.provider, &ct).unwrap() {
            IncomingMessage::Application { payload, .. } => assert_eq!(payload, b"hi-carol"),
            other => panic!("carol expected Application, got {other:?}"),
        }
    }

    #[test]
    fn remove_member_advances_epoch_and_shrinks_membership() {
        let (alice, _bob, mut ag, mut bg) = make_dyadic_group();
        assert_eq!(ag.member_count(), 2);

        // Alice удаляет Bob (leaf_index=1).
        let outcome = ag
            .remove_members(&alice.provider, alice.ks.as_ref(), &[1], T0 + 30)
            .unwrap();
        assert_eq!(ag.epoch(), 2);
        assert_eq!(ag.member_count(), 1);

        // Bob получает commit и отмечает себя evicted.
        match bg
            .process_incoming(&_bob.provider, &outcome.commit)
            .unwrap()
        {
            IncomingMessage::CommitApplied { self_removed, .. } => {
                assert!(
                    self_removed,
                    "bob must observe self_removed=true after remove"
                );
            }
            other => panic!("bob expected CommitApplied, got {other:?}"),
        }
    }

    #[test]
    fn removed_member_cannot_decrypt_subsequent_messages() {
        // Forward secrecy after Remove: Bob удаляется, новое сообщение Alice — Bob не может читать.
        let (alice, bob, mut ag, mut bg) = make_dyadic_group();
        // Alice remove Bob.
        let outcome = ag
            .remove_members(&alice.provider, alice.ks.as_ref(), &[1], T0 + 40)
            .unwrap();
        // Bob применяет Remove commit — переходит в Inactive.
        bg.process_incoming(&bob.provider, &outcome.commit).unwrap();

        // Теперь Alice должна быть одна — create_message может не разрешиться если нет
        // других членов (openmls позволяет create_message для creator-only).
        let ct_result = ag.encrypt_application(&alice.provider, alice.ks.as_ref(), b"post-remove");
        // Даже если encrypt сработает (single-member групп разрешены), Bob не сможет process.
        if let Ok(ct) = ct_result {
            let bob_result = bg.process_incoming(&bob.provider, &ct);
            assert!(
                bob_result.is_err(),
                "removed Bob must not decrypt post-remove ciphertexts"
            );
        }
    }

    // === Force rekey / PCS ===

    #[test]
    fn force_rekey_advances_epoch_and_updates_timestamp() {
        let (alice, _, mut ag, _) = make_dyadic_group();
        let epoch_before = ag.epoch();
        let _commit = ag
            .force_rekey(&alice.provider, alice.ks.as_ref(), T0 + 3600)
            .unwrap();
        assert_eq!(ag.epoch(), epoch_before + 1);
        assert_eq!(ag.last_rekey_at_unix(), T0 + 3600);
    }

    #[test]
    fn force_rekey_commit_is_applied_by_peer_and_peer_can_decrypt() {
        let (alice, bob, mut ag, mut bg) = make_dyadic_group();

        let commit = ag
            .force_rekey(&alice.provider, alice.ks.as_ref(), T0 + 3600)
            .unwrap();
        match bg.process_incoming(&bob.provider, &commit).unwrap() {
            IncomingMessage::CommitApplied {
                epoch,
                self_removed,
            } => {
                assert_eq!(epoch, 2);
                assert!(!self_removed);
            }
            other => panic!("bob expected CommitApplied after rekey, got {other:?}"),
        }
        bg.mark_rekey_observed(T0 + 3600);

        // После rekey обмен продолжается на новом epoch.
        exchange_two_way(
            &alice,
            &mut ag,
            &bob,
            &mut bg,
            b"post-rekey-a",
            b"post-rekey-b",
        );
        assert_eq!(ag.epoch(), 2);
        assert_eq!(bg.epoch(), 2);
    }

    #[test]
    fn needs_rekey_false_right_after_creation() {
        let alice = Client::new(0);
        let g = UmbrellaGroup::create_private(
            &alice.provider,
            alice.ks.as_ref(),
            0,
            CS,
            fresh_group_id(0x30),
            T0,
        )
        .unwrap();
        assert!(!g.needs_rekey(T0));
        assert!(!g.needs_rekey(T0 + PRIVATE_GROUP_MAX_LIFETIME_SECS - 1));
    }

    #[test]
    fn needs_rekey_true_at_or_past_24h_boundary() {
        let alice = Client::new(0);
        let g = UmbrellaGroup::create_private(
            &alice.provider,
            alice.ks.as_ref(),
            0,
            CS,
            fresh_group_id(0x31),
            T0,
        )
        .unwrap();
        assert!(g.needs_rekey(T0 + PRIVATE_GROUP_MAX_LIFETIME_SECS));
        assert!(g.needs_rekey(T0 + PRIVATE_GROUP_MAX_LIFETIME_SECS + 1));
    }

    // === Adversarial inputs ===

    #[test]
    fn join_malformed_welcome_bytes_fails_with_codec_error() {
        let bob = Client::new(0);
        let result = UmbrellaGroup::join_from_welcome(
            &bob.provider,
            bob.ks.as_ref(),
            0,
            b"\x00\x01\x02garbage",
            GroupPolicy::Private,
            T0,
        );
        assert!(matches!(result, Err(MlsError::Codec { .. })));
    }

    #[test]
    fn join_with_unknown_device_rejected() {
        // Создаём валидный Welcome для Bob (device 0), пытаемся join'иться device 7.
        let (_, bob, _, _) = make_dyadic_group();
        // Берём любой welcome (делаем ещё одно приглашение).
        let _ = bob; // Bob уже поглощён, нам достаточно ещё одного client'а
        let alice2 = Client::new(0);
        let bob2 = Client::new(0);
        let bob2_kp = bob2.publish_key_package(CS);
        let mut ag = UmbrellaGroup::create_private(
            &alice2.provider,
            alice2.ks.as_ref(),
            0,
            CS,
            fresh_group_id(0x32),
            T0,
        )
        .unwrap();
        let outcome = ag
            .add_members(&alice2.provider, alice2.ks.as_ref(), &[bob2_kp], T0)
            .unwrap();
        let welcome = outcome.welcome.unwrap();

        let result = UmbrellaGroup::join_from_welcome(
            &bob2.provider,
            bob2.ks.as_ref(),
            7, // device 7 не зарегистрирован
            &welcome,
            GroupPolicy::Private,
            T0,
        );
        assert!(matches!(
            result,
            Err(MlsError::Identity(
                umbrella_identity::IdentityError::UnknownDevice { index: 7 }
            ))
        ));
    }

    #[test]
    fn process_incoming_garbage_bytes_fails_with_codec_error() {
        let alice = Client::new(0);
        let mut g = UmbrellaGroup::create_private(
            &alice.provider,
            alice.ks.as_ref(),
            0,
            CS,
            fresh_group_id(0x33),
            T0,
        )
        .unwrap();
        let result = g.process_incoming(&alice.provider, b"\xDE\xAD\xBE\xEF");
        assert!(matches!(result, Err(MlsError::Codec { .. })));
    }

    #[test]
    fn process_incoming_rejects_welcome_body() {
        let alice = Client::new(0);
        let bob = Client::new(0);
        let bob_kp = bob.publish_key_package(CS);
        let mut ag = UmbrellaGroup::create_private(
            &alice.provider,
            alice.ks.as_ref(),
            0,
            CS,
            fresh_group_id(0x34),
            T0,
        )
        .unwrap();
        let outcome = ag
            .add_members(&alice.provider, alice.ks.as_ref(), &[bob_kp], T0)
            .unwrap();
        let welcome_bytes = outcome.welcome.unwrap();

        // Пытаемся скормить Welcome в process_incoming второй группы.
        let mut other = UmbrellaGroup::create_private(
            &alice.provider,
            alice.ks.as_ref(),
            0,
            CS,
            fresh_group_id(0x35),
            T0,
        )
        .unwrap();
        let result = other.process_incoming(&alice.provider, &welcome_bytes);
        assert!(matches!(result, Err(MlsError::Welcome { .. })));
    }

    #[test]
    fn replay_same_ciphertext_fails_on_second_process() {
        let (alice, bob, mut ag, mut bg) = make_dyadic_group();
        let ct = ag
            .encrypt_application(&alice.provider, alice.ks.as_ref(), b"once")
            .unwrap();
        // Первый process — успех.
        bg.process_incoming(&bob.provider, &ct).unwrap();
        // Второй process того же ciphertext — должен упасть (sender ratchet state продвинулся).
        let result = bg.process_incoming(&bob.provider, &ct);
        assert!(
            result.is_err(),
            "replay of same ciphertext must be rejected"
        );
    }

    #[test]
    fn bit_flip_in_ciphertext_rejected() {
        // Известный квирк openmls 0.8.1: при AEAD verify failure decrypt_message может
        // panic'нуть в debug build. Production `process_incoming` должен преобразовать это в
        // explicit Err, а не требовать catch_unwind в вызывающем коде.
        // Known openmls 0.8.1 quirk: on AEAD verify failure decrypt_message panics rather
        // than returning Err in debug builds. Production `process_incoming` must convert that
        // into an explicit Err instead of requiring caller-side catch_unwind.

        let (alice, bob, mut ag, mut bg) = make_dyadic_group();
        let mut ct = ag
            .encrypt_application(&alice.provider, alice.ks.as_ref(), b"tamper-target")
            .unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        let outcome = bg.process_incoming(&bob.provider, &ct);
        assert!(
            matches!(
                outcome,
                Err(MlsError::ProcessingPanic { .. }) | Err(MlsError::GroupOperation { .. })
            ),
            "tampered ciphertext must be rejected as Err, got {outcome:?}"
        );
    }

    #[test]
    fn bit_flip_rejection_does_not_break_next_sender_generation() {
        let (alice, bob, mut ag, mut bg) = make_dyadic_group();
        let mut bad = ag
            .encrypt_application(&alice.provider, alice.ks.as_ref(), b"tamper-target")
            .unwrap();
        let good = ag
            .encrypt_application(&alice.provider, alice.ks.as_ref(), b"after-tamper")
            .unwrap();

        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(
            bg.process_incoming(&bob.provider, &bad).is_err(),
            "tampered ciphertext must be rejected"
        );

        match bg.process_incoming(&bob.provider, &good).unwrap() {
            IncomingMessage::Application { payload, .. } => assert_eq!(payload, b"after-tamper"),
            other => panic!("expected Application after tamper rejection, got {other:?}"),
        }
    }

    #[test]
    fn wrong_group_cannot_decrypt() {
        // Две независимые dyadic группы: Alice/Bob и Charlie/Dave.
        let (alice, _bob, mut ag, _bg) = make_dyadic_group();
        let (_charlie, dave, _cg, mut dg) = make_dyadic_group();

        let ct = ag
            .encrypt_application(&alice.provider, alice.ks.as_ref(), b"for-bob")
            .unwrap();
        let result = dg.process_incoming(&dave.provider, &ct);
        assert!(
            result.is_err(),
            "cross-group ciphertext must not decrypt (different group secrets)"
        );
    }

    // === Invariants through operations ===

    #[test]
    fn policy_invariant_through_rekey_and_add() {
        let (alice, bob, mut ag, _) = make_dyadic_group();
        assert_eq!(ag.policy(), GroupPolicy::Private);
        ag.force_rekey(&alice.provider, alice.ks.as_ref(), T0 + 100)
            .unwrap();
        assert_eq!(ag.policy(), GroupPolicy::Private);

        let carol = Client::new(0);
        let carol_kp = carol.publish_key_package(CS);
        ag.add_members(&alice.provider, alice.ks.as_ref(), &[carol_kp], T0 + 200)
            .unwrap();
        assert_eq!(ag.policy(), GroupPolicy::Private);
        let _ = bob;
    }

    #[test]
    fn ciphersuite_invariant_through_operations() {
        let (alice, _, mut ag, _) = make_dyadic_group();
        assert_eq!(ag.ciphersuite(), CS);
        ag.force_rekey(&alice.provider, alice.ks.as_ref(), T0 + 100)
            .unwrap();
        assert_eq!(ag.ciphersuite(), CS);
    }

    #[test]
    fn group_id_invariant_through_rekey_and_add() {
        let (alice, _, mut ag, _) = make_dyadic_group();
        let gid_before = ag.group_id().clone();
        ag.force_rekey(&alice.provider, alice.ks.as_ref(), T0 + 100)
            .unwrap();
        assert_eq!(ag.group_id(), &gid_before);
        let carol = Client::new(0);
        let carol_kp = carol.publish_key_package(CS);
        ag.add_members(&alice.provider, alice.ks.as_ref(), &[carol_kp], T0 + 200)
            .unwrap();
        assert_eq!(ag.group_id(), &gid_before);
    }

    #[test]
    fn device_index_invariant_through_operations() {
        let (alice, _, mut ag, _) = make_dyadic_group();
        assert_eq!(ag.device_index(), 0);
        ag.force_rekey(&alice.provider, alice.ks.as_ref(), T0 + 100)
            .unwrap();
        assert_eq!(ag.device_index(), 0);
    }

    #[test]
    fn last_rekey_updates_on_add_and_remove_and_force() {
        let alice = Client::new(0);
        let bob = Client::new(0);
        let bob_kp = bob.publish_key_package(CS);
        let mut ag = UmbrellaGroup::create_private(
            &alice.provider,
            alice.ks.as_ref(),
            0,
            CS,
            fresh_group_id(0x40),
            T0,
        )
        .unwrap();
        assert_eq!(ag.last_rekey_at_unix(), T0);

        ag.add_members(&alice.provider, alice.ks.as_ref(), &[bob_kp], T0 + 10)
            .unwrap();
        assert_eq!(ag.last_rekey_at_unix(), T0 + 10);

        ag.force_rekey(&alice.provider, alice.ks.as_ref(), T0 + 20)
            .unwrap();
        assert_eq!(ag.last_rekey_at_unix(), T0 + 20);

        ag.remove_members(&alice.provider, alice.ks.as_ref(), &[1], T0 + 30)
            .unwrap();
        assert_eq!(ag.last_rekey_at_unix(), T0 + 30);
    }

    // === Invariant: private group never publishes ExternalPub extension ===

    #[test]
    fn welcome_from_private_group_has_no_external_pub_extension() {
        let alice = Client::new(0);
        let bob = Client::new(0);
        let bob_kp = bob.publish_key_package(CS);
        let mut ag = UmbrellaGroup::create_private(
            &alice.provider,
            alice.ks.as_ref(),
            0,
            CS,
            fresh_group_id(0x50),
            T0,
        )
        .unwrap();
        let outcome = ag
            .add_members(&alice.provider, alice.ks.as_ref(), &[bob_kp], T0)
            .unwrap();
        let welcome_bytes = outcome.welcome.unwrap();

        // staged.group_context().extensions() — наблюдаемый публичный контекст Welcome.
        let message = MlsMessageIn::tls_deserialize_exact(&welcome_bytes).unwrap();
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => panic!("welcome expected"),
        };
        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged =
            StagedWelcome::new_from_welcome(&bob.provider, &join_config, welcome, None).unwrap();
        let has_external_pub = staged
            .group_context()
            .extensions()
            .iter()
            .any(|e| matches!(e.extension_type(), ExtensionType::ExternalPub));
        assert!(
            !has_external_pub,
            "Private group MUST NOT advertise ExternalPub extension"
        );
    }

    // === Property-based: application round-trip with random payloads ===

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn prop_application_round_trip_random_payloads(
            payload in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            let (alice, bob, mut ag, mut bg) = make_dyadic_group();
            let ct = ag.encrypt_application(&alice.provider, alice.ks.as_ref(), &payload).unwrap();
            let decoded = bg.process_incoming(&bob.provider, &ct).unwrap();
            match decoded {
                IncomingMessage::Application { payload: p, .. } => prop_assert_eq!(p, payload),
                other => prop_assert!(false, "expected Application, got {:?}", other),
            }
        }

        #[test]
        fn prop_random_message_sequence_round_trips(
            messages in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 1..128),
                1..8,
            ),
        ) {
            let (alice, bob, mut ag, mut bg) = make_dyadic_group();
            // Чередуем alice→bob и bob→alice.
            for (i, m) in messages.iter().enumerate() {
                if i % 2 == 0 {
                    let ct = ag.encrypt_application(&alice.provider, alice.ks.as_ref(), m).unwrap();
                    match bg.process_incoming(&bob.provider, &ct).unwrap() {
                        IncomingMessage::Application { payload, .. } => prop_assert_eq!(&payload, m),
                        other => prop_assert!(false, "alice→bob expected Application, got {:?}", other),
                    }
                } else {
                    let ct = bg.encrypt_application(&bob.provider, bob.ks.as_ref(), m).unwrap();
                    match ag.process_incoming(&alice.provider, &ct).unwrap() {
                        IncomingMessage::Application { payload, .. } => prop_assert_eq!(&payload, m),
                        other => prop_assert!(false, "bob→alice expected Application, got {:?}", other),
                    }
                }
            }
        }

        #[test]
        fn prop_random_group_ids_accepted(gid_bytes in proptest::collection::vec(any::<u8>(), 1..64)) {
            let alice = Client::new(0);
            let gid = GroupId::from_slice(&gid_bytes);
            let g = UmbrellaGroup::create_private(
                &alice.provider,
                alice.ks.as_ref(),
                0,
                CS,
                gid.clone(),
                T0,
            ).unwrap();
            prop_assert_eq!(g.group_id(), &gid);
        }
    }

    // === Bit-flip coverage across message positions (property-based adversarial) ===

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(40))]

        #[test]
        fn prop_any_bit_flip_in_ciphertext_rejected(
            plaintext in proptest::collection::vec(any::<u8>(), 1..64),
            position in 0usize..256,
            bit in 0u8..8,
        ) {
            let (alice, bob, mut ag, mut bg) = make_dyadic_group();
            let mut ct = ag.encrypt_application(&alice.provider, alice.ks.as_ref(), &plaintext).unwrap();
            let pos = position % ct.len();
            ct[pos] ^= 1u8 << bit;
            let outcome = bg.process_incoming(&bob.provider, &ct);
            if let Ok(IncomingMessage::Application { payload, .. }) = outcome {
                prop_assert_ne!(
                    &payload,
                    &plaintext,
                    "tampered ciphertext decoded to SAME plaintext — AEAD forgery!"
                );
            }
        }
    }

    // === RFC 9420 §8.5 exporter_secret ===
    //
    // Нормативная метка SFrame — "SFrame 1.0 Base Key" (draft-ietf-mls-sframe),
    // context = epoch_number_u64_be (8 байт). В тестах используем эту метку,
    // чтобы на практике проверять именно тот путь, который идёт в продакшене.
    //
    // SFrame normative label — "SFrame 1.0 Base Key" (draft-ietf-mls-sframe),
    // context = epoch_number_u64_be (8 bytes). The tests use this label to
    // exercise the exact code path used in production.

    const SFRAME_BASE_KEY_LABEL: &str = "SFrame 1.0 Base Key";

    #[test]
    fn exporter_secret_deterministic_same_group_state() {
        let (alice, _bob, alice_g, _bob_g) = make_dyadic_group();
        let ex1 = alice_g
            .exporter_secret(&alice.provider, SFRAME_BASE_KEY_LABEL, &[0u8; 8], 64)
            .expect("exporter call 1");
        let ex2 = alice_g
            .exporter_secret(&alice.provider, SFRAME_BASE_KEY_LABEL, &[0u8; 8], 64)
            .expect("exporter call 2");
        // Round-5 device-capture closure F-PHD-DC-R11-1: MlockedSecret<T>.expose().
        // Round-5 device-capture closure F-PHD-DC-R11-1: MlockedSecret<T>.expose().
        assert_eq!(ex1.expose(), ex2.expose());
        assert_eq!(ex1.expose().len(), 64);
    }

    #[test]
    fn exporter_secret_different_context_different_bytes() {
        let (alice, _bob, alice_g, _bob_g) = make_dyadic_group();
        let ex_ep0 = alice_g
            .exporter_secret(&alice.provider, SFRAME_BASE_KEY_LABEL, &[0u8; 8], 64)
            .unwrap();
        let mut ep1_bytes = [0u8; 8];
        ep1_bytes[7] = 1;
        let ex_ep1 = alice_g
            .exporter_secret(&alice.provider, SFRAME_BASE_KEY_LABEL, &ep1_bytes, 64)
            .unwrap();
        assert_ne!(ex_ep0.expose(), ex_ep1.expose());
    }

    #[test]
    fn exporter_secret_both_peers_agree() {
        let (alice, bob, alice_g, bob_g) = make_dyadic_group();
        let ex_a = alice_g
            .exporter_secret(&alice.provider, SFRAME_BASE_KEY_LABEL, &[0u8; 8], 64)
            .unwrap();
        let ex_b = bob_g
            .exporter_secret(&bob.provider, SFRAME_BASE_KEY_LABEL, &[0u8; 8], 64)
            .unwrap();
        assert_eq!(ex_a.expose(), ex_b.expose());
    }

    #[test]
    fn exporter_secret_different_label_different_bytes() {
        let (alice, _bob, alice_g, _bob_g) = make_dyadic_group();
        let ex_a = alice_g
            .exporter_secret(&alice.provider, SFRAME_BASE_KEY_LABEL, &[0u8; 8], 64)
            .unwrap();
        let ex_b = alice_g
            .exporter_secret(&alice.provider, "some-other-label-v1", &[0u8; 8], 64)
            .unwrap();
        assert_ne!(
            ex_a.expose(),
            ex_b.expose(),
            "domain separation: разные labels должны давать разные secrets"
        );
    }

    #[test]
    fn exporter_secret_rejects_zero_len() {
        let (alice, _bob, alice_g, _bob_g) = make_dyadic_group();
        let result = alice_g.exporter_secret(&alice.provider, SFRAME_BASE_KEY_LABEL, &[0u8; 8], 0);
        assert!(matches!(result, Err(MlsError::GroupOperation { .. })));
    }

    #[test]
    fn exporter_secret_rejects_over_max_len() {
        let (alice, _bob, alice_g, _bob_g) = make_dyadic_group();
        let result = alice_g.exporter_secret(&alice.provider, SFRAME_BASE_KEY_LABEL, &[0u8; 8], 65);
        assert!(matches!(result, Err(MlsError::GroupOperation { .. })));
    }

    #[test]
    fn exporter_secret_len_32_zero_tail() {
        let (alice, _bob, alice_g, _bob_g) = make_dyadic_group();
        let ex = alice_g
            .exporter_secret(&alice.provider, SFRAME_BASE_KEY_LABEL, &[0u8; 8], 32)
            .unwrap();
        let bytes = ex.expose();
        assert_eq!(bytes.len(), MAX_EXPORTER_LEN);
        for (i, &b) in bytes[32..].iter().enumerate() {
            assert_eq!(b, 0u8, "tail byte {i} must be zero after len=32 export");
        }
    }
}
