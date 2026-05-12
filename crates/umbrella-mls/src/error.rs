//! Типы ошибок крейта; конкретные ошибки openmls оборачиваются с потерей внутренних деталей,
//! чтобы сообщения не утекали в логах высоких слоёв.
//! Crate error types; specific openmls errors are wrapped with loss of internal detail
//! so messages do not leak through upper-layer logs.

use thiserror::Error;

/// Result alias для крейта.
/// Crate result alias.
pub type Result<T, E = MlsError> = core::result::Result<T, E>;

/// Ошибки уровня umbrella-mls; сообщения не содержат секретов.
/// umbrella-mls level errors; messages contain no secrets.
#[derive(Debug, Error)]
pub enum MlsError {
    /// Запрошена ciphersuite не входящая в whitelist (ECDSA-based отвергаются).
    /// Requested ciphersuite is not whitelisted (ECDSA-based variants are rejected).
    #[error("ciphersuite {raw_id:#06x} is not allowed by Umbrella policy (ECDSA disabled, only Ed25519/Ed448)")]
    DisallowedCiphersuite {
        /// Raw IANA-номер ciphersuite. IANA ciphersuite raw number.
        raw_id: u16,
    },

    /// Запрошена post-quantum ciphersuite (0x004D X-Wing), но крейт собран без feature `pq`.
    /// Без feature `pq` `UmbrellaXWingProvider` не доступен, и openmls_rust_crypto падает в
    /// `unimplemented!()` на `HpkeKemType::XWingKemDraft6`. Этот variant — runtime gate
    /// до наступления `unimplemented!()` (постулат 14: никаких panic в библиотечном коде).
    ///
    /// Requested a post-quantum ciphersuite (0x004D X-Wing), but the crate was built without
    /// feature `pq`. Without `pq`, `UmbrellaXWingProvider` is unavailable and
    /// openmls_rust_crypto traps `unimplemented!()` on `HpkeKemType::XWingKemDraft6`. This
    /// variant is a runtime gate before reaching `unimplemented!()` (postulate 14: no panic
    /// in library code).
    #[error("ciphersuite {raw_id:#06x} requires the 'pq' feature, which is not enabled")]
    CiphersuiteRequiresPqFeature {
        /// Raw IANA-номер ciphersuite. IANA ciphersuite raw number.
        raw_id: u16,
    },

    /// External operation попытка на приватной группе (требуется политика PublicBroadcast).
    /// External operation attempt on a private group (requires PublicBroadcast policy).
    #[error("external operation is forbidden by group policy")]
    ExternalOperationForbidden,

    /// Конфигурация группы не прошла валидацию: причина указана отдельно.
    /// Group configuration failed validation: reason supplied separately.
    #[error("invalid group configuration: {reason}")]
    InvalidGroupConfig {
        /// Человекочитаемая причина. Human-readable reason.
        reason: &'static str,
    },

    /// Ошибка при создании / обновлении / commit'е MLS-группы (детали обёрнуты).
    /// Error creating / updating / committing the MLS group (details wrapped).
    #[error("MLS group operation failed: {kind}")]
    GroupOperation {
        /// Категория операции для diagnostics. Operation category for diagnostics.
        kind: &'static str,
    },

    /// Ошибка обработки KeyPackage (валидация / парсинг).
    /// KeyPackage processing failure (validation / parsing).
    #[error("KeyPackage error: {kind}")]
    KeyPackage {
        /// Категория для diagnostics. Diagnostics category.
        kind: &'static str,
    },

    /// Ошибка обработки Welcome message при join.
    /// Welcome message processing failure during join.
    #[error("Welcome message error: {kind}")]
    Welcome {
        /// Категория для diagnostics. Diagnostics category.
        kind: &'static str,
    },

    /// Ошибка сериализации / десериализации wire format.
    /// Wire-format serialization / deserialization error.
    #[error("wire codec error: {kind}")]
    Codec {
        /// Категория для diagnostics. Diagnostics category.
        kind: &'static str,
    },

    /// Парсер MLS wire-format запаниковал на malformed input. Пакет признаётся отвергаемым,
    /// без silent fallback (постулат 14 — log + explicit Err). Защита от F-37 — `tls_codec-0.4.2`
    /// panic на 5-байтовом входе `[0,0,0,1,192]` через QUIC variable-length integer assertion
    /// `len_len_log <= MAX_LEN_LEN_LOG` в `tls_codec/src/quic_vec.rs:53`. См. `parser.rs`
    /// для bounds-check + `std::panic::catch_unwind` defensive wrappers.
    ///
    /// MLS wire-format parser panicked on malformed input. The packet is rejected explicitly,
    /// with no silent fallback (postulate 14 — log + explicit Err). Defence against F-37 —
    /// `tls_codec-0.4.2` panic on 5-byte input `[0,0,0,1,192]` via the QUIC variable-length
    /// integer assertion `len_len_log <= MAX_LEN_LEN_LOG` at `tls_codec/src/quic_vec.rs:53`.
    /// See `parser.rs` for the bounds-check + `std::panic::catch_unwind` defensive wrappers.
    #[error("MLS wire-format parser panicked: {kind}")]
    ParserPanic {
        /// Категория для diagnostics (e.g., "MlsMessageIn", "KeyPackageIn").
        /// Diagnostics category (e.g., "MlsMessageIn", "KeyPackageIn").
        kind: &'static str,
    },

    /// Нижележащая MLS-библиотека запаниковала во время обработки уже распарсенного сообщения
    /// (например, debug assertion на AEAD verify failure). Сообщение отвергается explicit Err,
    /// без проброса panic наружу к клиентскому процессу.
    ///
    /// The underlying MLS library panicked while processing an already parsed message
    /// (for example, a debug assertion on AEAD verification failure). The message is rejected as
    /// an explicit Err without propagating the panic to the client process.
    #[error("MLS message processing panicked: {kind}")]
    ProcessingPanic {
        /// Категория для diagnostics (e.g., "MlsGroup::process_message").
        /// Diagnostics category (e.g., "MlsGroup::process_message").
        kind: &'static str,
    },

    /// Ошибка нижележащего криптослоя.
    /// Underlying crypto-layer error.
    #[error("underlying crypto error: {0}")]
    Crypto(#[from] umbrella_crypto_primitives::CryptoError),

    /// Ошибка identity-слоя (BIP-39 / derive / attestation).
    /// Identity-layer error (BIP-39 / derive / attestation).
    #[error("identity error: {0}")]
    Identity(#[from] umbrella_identity::IdentityError),
}
