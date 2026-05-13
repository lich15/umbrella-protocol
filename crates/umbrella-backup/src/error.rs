//! Единый error enum крейта `umbrella-backup`.
//! Shared error enum for the `umbrella-backup` crate.
//!
//! Содержит варианты для обеих подсистем (Cloud-wrap и Secret device-transfer),
//! плюс общие парсер-ошибки. Выделение в единый enum упрощает FFI-сигнатуры
//! и перенос ошибок через границу крейта без лишнего маппинга.
//!
//! Unified enum for both subsystems (Cloud-wrap and Secret device-transfer) plus
//! shared parser errors. A single enum simplifies FFI signatures and avoids
//! mapping layers at the crate boundary.

use thiserror::Error;

/// Все ошибки крейта `umbrella-backup`.
/// All errors of the `umbrella-backup` crate.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BackupError {
    // ---------------------------------------------------------------
    // Общие / shared
    // ---------------------------------------------------------------
    /// Невалидный wire-format (длина, версия, кодирование).
    /// Invalid wire format (length, version, encoding).
    #[error("invalid wire format")]
    InvalidWireFormat,

    /// Байты не декодируются в валидную точку Ristretto255.
    /// Bytes do not decode to a valid Ristretto255 point.
    #[error("invalid Ristretto255 encoding")]
    InvalidRistrettoEncoding,

    /// Скаляр Ed25519/Ristretto — не в канонической форме.
    /// Ed25519/Ristretto scalar is not in canonical form.
    #[error("invalid scalar encoding")]
    InvalidScalarEncoding,

    /// Криптографическая подпись / MAC не проходит проверку.
    /// Cryptographic signature or MAC verification failed.
    #[error("crypto verification failed")]
    CryptoVerificationFailed,

    /// Ошибка из signer-callback (HSM/Secure Enclave недоступен, ...).
    /// Signer callback error (HSM/Secure Enclave unavailable, etc.).
    #[error("device signing failed: {0}")]
    DeviceSigning(&'static str),

    /// Невалидная форма платформенного attestation (пустой, слишком длинный).
    /// Invalid platform attestation shape (empty, too long).
    #[error("invalid attestation shape")]
    InvalidAttestationShape,

    /// Боевой проверяющий attestation для платформы ещё не подключён.
    /// Production attestation verifier for this platform is not wired yet.
    #[error("production attestation verifier unavailable for platform tag {platform_tag:#x}")]
    ProductionAttestationVerifierUnavailable {
        /// Тег платформы. Platform tag.
        platform_tag: u8,
    },

    /// Платформенная проверка закрыто отказала.
    /// Platform verification failed closed.
    #[error("production platform verification failed: {0}")]
    ProductionPlatformVerificationFailed(String),

    /// Тестовый платформенный проверяющий нельзя использовать в боевом контексте.
    /// Test-only platform verifier cannot be used in a production context.
    #[error("test-only attestation verifier rejected in production context")]
    ProductionTestVerifierRejected,

    /// Серверный вызов в запросе не совпал с выданным сервером вызовом.
    /// Request server nonce does not match the server-issued nonce.
    #[error("production server nonce mismatch")]
    ProductionServerNonceMismatch,

    /// Серверный вызов старше разрешённого окна свежести.
    /// Server-issued nonce is older than the allowed freshness window.
    #[error("production server nonce expired: age {age_millis} ms > max {max_age_millis} ms")]
    ProductionServerNonceExpired {
        /// Возраст вызова в миллисекундах. Nonce age in milliseconds.
        age_millis: u64,
        /// Максимальный возраст в миллисекундах. Maximum age in milliseconds.
        max_age_millis: u64,
    },

    /// Серверный вызов имеет время выдачи из будущего дальше допустимого перекоса.
    /// Server nonce issue time is too far in the future.
    #[error(
        "production server nonce issued in future: skew {skew_millis} ms > max {max_future_skew_millis} ms"
    )]
    ProductionServerNonceIssuedInFuture {
        /// Перекос в миллисекундах. Future skew in milliseconds.
        skew_millis: u64,
        /// Максимально допустимый перекос. Maximum allowed future skew.
        max_future_skew_millis: u64,
    },

    /// Время запроса из будущего дальше допустимого перекоса.
    /// Request timestamp is too far in the future.
    #[error(
        "production request timestamp in future: skew {skew_millis} ms > max {max_future_skew_millis} ms"
    )]
    ProductionRequestTimestampInFuture {
        /// Перекос в миллисекундах. Future skew in milliseconds.
        skew_millis: u64,
        /// Максимально допустимый перекос. Maximum allowed future skew.
        max_future_skew_millis: u64,
    },

    /// Устройство отсутствует в боевом снимке журнала ключей.
    /// Device is absent from the production key-transparency state snapshot.
    #[error("production device unknown")]
    ProductionDeviceUnknown,

    /// Устройство ещё не было разрешено в момент запроса.
    /// Device was not authorized yet at the request timestamp.
    #[error(
        "production device not active yet: authorized_since {authorized_since_unix_millis} > request {request_timestamp_unix_millis}"
    )]
    ProductionDeviceNotActiveYet {
        /// Когда устройство становится разрешённым. When the device becomes authorized.
        authorized_since_unix_millis: u64,
        /// Время запроса. Request timestamp.
        request_timestamp_unix_millis: u64,
    },

    // ---------------------------------------------------------------
    // Cloud-wrap (SPEC-12 §A)
    // ---------------------------------------------------------------
    /// `WrappedKey` короче ожидаемых 81 байт.
    /// `WrappedKey` is shorter than the expected 81 bytes.
    #[error("wrapped key truncated")]
    WrappedKeyTruncated,

    /// Версия `WrappedKey` не совпадает с ожидаемой протоколом.
    /// `WrappedKey` version mismatches the protocol-expected one.
    #[error("wrapped key version mismatch: expected {expected:#x}, found {found:#x}")]
    WrappedKeyVersionMismatch {
        /// Ожидаемая версия. Expected version byte.
        expected: u8,
        /// Полученная версия. Received version byte.
        found: u8,
    },

    /// `ServerUnwrapShare` короче ожидаемых 33 байт.
    /// `ServerUnwrapShare` shorter than the expected 33 bytes.
    #[error("unwrap share truncated")]
    UnwrapShareTruncated,

    /// Witness index вне диапазона 1..=total.
    /// Witness index outside 1..=total.
    #[error("unknown witness index {0}")]
    UnknownWitnessIndex(u8),

    /// Witness index повторяется в наборе shares.
    /// Witness index duplicated in the shares set.
    #[error("duplicate witness index {0}")]
    DuplicateWitnessIndex(u8),

    /// Недостаточно валидных shares для threshold reconstruction.
    /// Not enough valid shares for threshold reconstruction.
    #[error("insufficient unwrap shares: {valid}/{required}")]
    InsufficientUnwrapShares {
        /// Сколько валидных. Number valid.
        valid: usize,
        /// Сколько требуется. Number required.
        required: usize,
    },

    /// Все перепробованные подмножества 3-of-N дали AEAD-фейл — сигнал что
    /// ≥ 3 серверов malicious (catastrophic).
    ///
    /// All tried 3-of-N subsets failed AEAD — signals ≥ 3 malicious servers.
    #[error("all threshold subsets failed to unwrap (>= 3 malicious servers)")]
    AllSubsetsFailedUnwrap,

    /// AEAD-decrypt не прошёл: неверный ключ / подделан ciphertext / AAD.
    /// AEAD decrypt failed: wrong key / tampered ciphertext / AAD.
    #[error("AEAD decrypt failed")]
    AeadDecryptFailed,

    /// Внутренняя ошибка при сборке wire-буфера (overflow heapless Vec).
    /// Internal wire buffer assembly error (heapless Vec overflow).
    #[error("wire buffer overflow")]
    WireBufferOverflow,

    // ---------------------------------------------------------------
    // Device-transfer (SPEC-12 §B) — наполняются в под-этапе 5.3
    // ---------------------------------------------------------------
    /// QR-код с истёкшим сроком действия.
    /// Expired QR code.
    #[error("pairing QR expired")]
    QrExpired,

    /// Identity-signature на QR недействительна.
    /// Identity signature on QR is invalid.
    #[error("pairing QR signature invalid")]
    QrSignatureInvalid,

    /// QR payload короче ожидаемых 137 байт.
    /// QR payload shorter than the expected 137 bytes.
    #[error("pairing QR payload truncated")]
    QrPayloadTruncated,

    /// Версия QR не совпадает с ожидаемой.
    /// QR version mismatch.
    #[error("pairing QR version mismatch: expected {expected:#x}, found {found:#x}")]
    QrVersionMismatch {
        /// Ожидаемая версия. Expected version byte.
        expected: u8,
        /// Полученная версия. Received version byte.
        found: u8,
    },

    /// Ошибка Noise handshake.
    /// Noise handshake failure.
    #[error("device-transfer handshake failed: {0}")]
    HandshakeFailed(&'static str),

    /// Mismatch handshake hash между initiator и responder — подпись не
    /// привязана к handshake transcript, возможна подмена.
    ///
    /// Handshake hash mismatch between initiator and responder — signature
    /// not bound to handshake transcript, possible forking.
    #[error("handshake hash mismatch")]
    HandshakeHashMismatch,

    /// Frame в стриме больше лимита.
    /// Stream frame exceeds limit.
    #[error("stream frame too large: {actual} > {limit}")]
    StreamFrameTooLarge {
        /// Максимально допустимый размер (байт). Max allowed size (bytes).
        limit: usize,
        /// Фактический размер (байт). Actual size (bytes).
        actual: usize,
    },

    /// Поток завершился до полного snapshot'а.
    /// Stream ended before full snapshot.
    #[error("stream unexpected EOF")]
    StreamUnexpectedEof,

    /// Не удалось декодировать snapshot (внутренняя структура MLS/DB).
    /// Snapshot decoding failed (internal MLS/DB structure).
    #[error("snapshot decode failed")]
    SnapshotDecodeFailed,

    // ---------------------------------------------------------------
    // Authorization state (ADR-008, SPEC-12 §3 + §A.11)
    // ---------------------------------------------------------------
    /// Device-entry находится в состоянии `pending` и ещё не получил
    /// `DeviceAuthorizationApproval` от существующего active device.
    /// Sealed Server отказывает в partial unwrap shares. Клиент обязан
    /// ждать approval до повторной попытки.
    ///
    /// Device entry is in `pending` state and has not yet received a
    /// `DeviceAuthorizationApproval` from an existing active device. Sealed
    /// Server refuses partial unwrap shares. Client must wait for approval
    /// before retrying.
    #[error("device authorization pending — approval required")]
    DevicePendingAuthorization,

    /// Device-entry помечен `revoked` (terminal). Sealed Server отказывает
    /// навсегда; retry бессмыслен. Устройство должно быть заново
    /// зарегистрировано под новым device-key.
    ///
    /// Device entry is marked `revoked` (terminal). Sealed Server refuses
    /// forever; retries are pointless. The device must be re-registered
    /// under a new device-key.
    #[error("device revoked — permanent refusal")]
    DeviceRevoked,

    /// Envelope с `wrapped_key.timestamp < history_cutoff_timestamp`.
    /// Устройство было авторизовано c cutoff (режим повышенной безопасности
    /// или custom cutoff), envelope старее cutoff → Sealed Server отказывает.
    ///
    /// Envelope with `wrapped_key.timestamp < history_cutoff_timestamp`.
    /// The device was authorized with a cutoff (high-security mode or custom
    /// cutoff); envelope older than cutoff → Sealed Server refuses.
    #[error("history cutoff applies: envelope_timestamp {envelope_timestamp} < cutoff {cutoff}")]
    HistoryCutoffApplies {
        /// Timestamp envelope (unix millis) из запроса. Envelope unix-millis timestamp.
        envelope_timestamp: u64,
        /// Cutoff (unix millis) установленный в `DeviceAuthorizationApproval`. Cutoff unix-millis.
        cutoff: u64,
    },

    /// В KT опубликован `IdentityRotationRecord`, но запрос пришёл под
    /// устаревшим identity. Требуется retry под новым identity после
    /// publish нового device-entry под новым identity.
    ///
    /// An `IdentityRotationRecord` has been published in KT, but the request
    /// arrived under the stale identity. Client must retry under the new
    /// identity after publishing a fresh device-entry under the new identity.
    #[error("identity rotated — refusing requests under old identity")]
    IdentityRotatedRefuseOldRequests,

    // ---------------------------------------------------------------
    // Hybrid PQ wrap (V2, Этап 8 блок 8.7) — feature `pq`
    // Hybrid PQ wrap (V2, Stage 8 block 8.7) — feature `pq`
    // ---------------------------------------------------------------
    /// Wrapping ciphersuite версия не распознана (wire byte ≠ 0x01 и ≠ 0x02).
    /// Used as: caller-side dispatch peek `wire[0]` → `WrappingCiphersuite::try_from`.
    ///
    /// Unsupported wrapping ciphersuite (wire byte ≠ 0x01 and ≠ 0x02). Used by
    /// caller-side dispatch peek `wire[0]` → `WrappingCiphersuite::try_from`.
    #[error("unsupported wrapping ciphersuite: got {got:#x}")]
    UnsupportedWrappingCiphersuite {
        /// Полученный байт версии. Received version byte.
        got: u8,
    },

    /// V2 wire-format byte (0x02) встречен при сборке без feature `pq`.
    /// Indicates что client получил V2 wrapped key но не имеет PQ кода.
    /// Caller обязан upgrade'нуть до версии с feature `pq` или decline V2 path.
    ///
    /// V2 wire-format byte (0x02) encountered in a build without feature `pq`.
    /// Indicates that the client received a V2 wrapped key but lacks PQ code.
    /// Caller must upgrade to a feature-`pq` build or decline the V2 path.
    #[error("PQ feature required for wrapping ciphersuite version {version:#x}")]
    PqFeatureRequiredForCiphersuite {
        /// Версия wire-format byte. Wire-format version byte.
        version: u8,
    },

    /// V2 `WrappedKeyV2` короче ожидаемых 1218 байт либо empty.
    /// V2 `WrappedKeyV2` shorter than the expected 1218 bytes or empty.
    #[error("V2 wrapped key truncated (expected 1218 bytes)")]
    WrappedKeyV2Truncated,

    /// X-Wing encapsulation backend ошибка (invalid recipient pubkey, либо
    /// libcrux backend issue). Не должна возникать при валидном recipient
    /// pubkey + working RNG.
    ///
    /// X-Wing encapsulation backend error (invalid recipient pubkey or libcrux
    /// backend issue). Should not occur with a valid recipient pubkey + working RNG.
    #[error("X-Wing encapsulation failed")]
    XWingEncapsFailed,

    /// X-Wing decapsulation backend ошибка либо implicit-rejection (corrupted
    /// ciphertext, mismatch sk/pk pair). Returns generic ошибку чтобы не
    /// leak'ать distinction (постулат 4: privacy-preserving error reporting).
    ///
    /// X-Wing decapsulation backend error or implicit rejection (corrupted
    /// ciphertext, mismatched sk/pk pair). Returns a generic error to avoid
    /// leaking the distinction (postulate 4: privacy-preserving error reporting).
    #[error("X-Wing decapsulation failed")]
    XWingDecapsFailed,
}

/// Удобный псевдоним для Result с нашим error type.
/// Convenient Result type alias for our error.
pub type Result<T> = core::result::Result<T, BackupError>;
