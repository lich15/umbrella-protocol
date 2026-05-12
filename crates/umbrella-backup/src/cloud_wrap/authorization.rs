//! Записи авторизации устройств из ADR-008 (SPEC-12 §A.2, §A.5.1).
//! Device authorization records from ADR-008 (SPEC-12 §A.2, §A.5.1).
//!
//! Модуль реализует три wire-format типа публикуемых в KT (для approval и
//! revocation) либо в dedicated mailbox на Почтальоне (для request). Назначение
//! — двухфакторная авторизация новых устройств до выдачи Sealed Servers
//! partial unwrap shares: 24 слова BIP-39 дают derive identity-key, но
//! `DeviceAuthorizationApproval` от уже active существующего устройства
//! обязателен для перехода device-entry из `pending` в `active`. Это
//! закрывает угрозу утечки 24 слов (ADR-008 §1).
//!
//! This module implements three wire-format types published either to KT
//! (approval, revocation) or to a dedicated mailbox on the postman (request).
//! Their purpose is two-factor authorization of new devices before Sealed
//! Servers issue partial unwrap shares: BIP-39 24 words give you a derived
//! identity-key, but a `DeviceAuthorizationApproval` from an already-active
//! existing device is mandatory for transitioning the device-entry from
//! `pending` to `active`. This closes the 24-word leakage threat (ADR-008 §1).
//!
//! Все подписи — Ed25519 под явными domain separators. Canonical signing
//! input дословно соответствует SPEC-12 §A.5.1. Форматы wire-format
//! детерминистические (фиксированные offsets, big-endian для u64) для
//! reproducible сериализации и cross-client interop.
//!
//! All signatures are Ed25519 under explicit domain separators. Canonical
//! signing inputs match SPEC-12 §A.5.1 byte-for-byte. Wire formats are
//! deterministic (fixed offsets, big-endian for u64) so serialization is
//! reproducible and interop across clients works.

use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey as DalekVerifyingKey};
use heapless::String as HString;

use crate::error::BackupError;

use super::signed_request::{DEVICE_PUBKEY_LEN, DEVICE_SIG_LEN};

// ---------------------------------------------------------------------------
// Константы / Constants
// ---------------------------------------------------------------------------

/// Версия wire-format для всех трёх authorization-типов ADR-008 (v1).
/// Wire-format version for all three ADR-008 authorization types (v1).
pub const AUTHORIZATION_WIRE_VERSION: u8 = 0x01;

/// Длина challenge_nonce в `DeviceAuthorizationRequest` (32 байта CSPRNG).
/// Length of `challenge_nonce` in `DeviceAuthorizationRequest` (32 CSPRNG bytes).
pub const CHALLENGE_NONCE_LEN: usize = 32;

/// Максимальная длина `location_hint` UTF-8 payload в байтах.
/// Maximum length of `location_hint` UTF-8 payload in bytes.
pub const LOCATION_HINT_MAX: usize = 128;

/// Domain separator для canonical signing input `DeviceAuthorizationRequest`.
/// Точно 32 байта, фиксировано ADR-008.
///
/// Domain separator for the canonical signing input of
/// `DeviceAuthorizationRequest`. Exactly 32 bytes, fixed by ADR-008.
pub const DEVICE_AUTH_REQUEST_DOMAIN_SEPARATOR: &[u8] = b"umbrellax-device-auth-request-v1";

/// Domain separator для canonical signing input `DeviceAuthorizationApproval`.
/// Точно 33 байта, фиксировано ADR-008.
///
/// Domain separator for the canonical signing input of
/// `DeviceAuthorizationApproval`. Exactly 33 bytes, fixed by ADR-008.
pub const DEVICE_AUTH_APPROVAL_DOMAIN_SEPARATOR: &[u8] = b"umbrellax-device-auth-approval-v1";

/// Domain separator для canonical signing input `DeviceAuthorizationRevocation`.
/// Точно 31 байт, фиксировано ADR-008.
///
/// Domain separator for the canonical signing input of
/// `DeviceAuthorizationRevocation`. Exactly 31 bytes, fixed by ADR-008.
pub const DEVICE_AUTH_REVOKE_DOMAIN_SEPARATOR: &[u8] = b"umbrellax-device-auth-revoke-v1";

/// Минимальная длина wire-format `DeviceAuthorizationRequest` когда
/// `location_hint_len = 0` (138 байт).
///
/// Minimum wire-format length of `DeviceAuthorizationRequest` when
/// `location_hint_len = 0` (138 bytes).
pub const DEVICE_AUTH_REQUEST_BASE_LEN: usize = 1                 // version
    + DEVICE_PUBKEY_LEN                                            // new_device_pubkey
    + 8                                                            // request_timestamp
    + CHALLENGE_NONCE_LEN                                          // challenge_nonce
    + 1                                                            // location_hint_len
    + DEVICE_SIG_LEN; // identity_signature

/// Максимальная длина wire-format `DeviceAuthorizationRequest`
/// (`DEVICE_AUTH_REQUEST_BASE_LEN + LOCATION_HINT_MAX = 266 байт`).
///
/// Maximum wire-format length of `DeviceAuthorizationRequest`
/// (`DEVICE_AUTH_REQUEST_BASE_LEN + LOCATION_HINT_MAX = 266 bytes`).
pub const DEVICE_AUTH_REQUEST_MAX_LEN: usize = DEVICE_AUTH_REQUEST_BASE_LEN + LOCATION_HINT_MAX;

/// Фиксированная длина wire-format `DeviceAuthorizationApproval` (146 байт).
/// Fixed wire-format length of `DeviceAuthorizationApproval` (146 bytes).
pub const DEVICE_AUTH_APPROVAL_LEN: usize = 1                      // version
    + DEVICE_PUBKEY_LEN                                            // new_device_pubkey
    + DEVICE_PUBKEY_LEN                                            // approver_device_pubkey
    + 8                                                            // authorized_since_timestamp
    + 8                                                            // history_cutoff_timestamp
    + 1                                                            // policy_flags
    + DEVICE_SIG_LEN; // approver_signature

/// Фиксированная длина wire-format `DeviceAuthorizationRevocation` (137 байт).
/// Fixed wire-format length of `DeviceAuthorizationRevocation` (137 bytes).
pub const DEVICE_AUTH_REVOKE_LEN: usize = 1                        // version
    + DEVICE_PUBKEY_LEN                                            // revoked_device_pubkey
    + DEVICE_PUBKEY_LEN                                            // revoker_device_pubkey
    + 8                                                            // revocation_timestamp
    + DEVICE_SIG_LEN; // revoker_signature

/// Bit 0 флага `policy_flags`: повышенная безопасность (default history
/// cutoff = current timestamp, нет доступа к прошлой истории).
///
/// Bit 0 of `policy_flags`: high-security mode (default history cutoff =
/// current timestamp, no access to prior history).
pub const POLICY_FLAG_HIGH_SECURITY: u8 = 0x01;

/// Маска reserved bits `policy_flags` (bits 1..7 обязаны быть 0 в wire-v1).
/// Reserved-bits mask for `policy_flags` (bits 1..7 must be 0 in wire-v1).
pub const POLICY_FLAGS_RESERVED_MASK: u8 = 0xFE;

// ---------------------------------------------------------------------------
// DeviceAuthorizationRequest
// ---------------------------------------------------------------------------

/// Запрос авторизации нового устройства у уже существующего active device
/// того же identity. Публикуется новым устройством в dedicated mailbox на
/// Почтальоне после того как его device-key опубликован в KT с флагом
/// `pending`. Подписан `IdentityKey` (не device-key, потому что device-key
/// нового устройства ещё не active). Используется для push-уведомления
/// existing устройств; криптографической необходимости для approval нет
/// (approval может быть инициирован вручную).
///
/// Request for authorization of a new device from an existing active device
/// belonging to the same identity. Published by the new device to a
/// dedicated mailbox on the postman after its device-key has been published
/// in KT with the `pending` flag. Signed by `IdentityKey` (not device-key,
/// because the new device's key is not yet active). Used for push
/// notification to existing devices; not a cryptographic prerequisite for
/// approval (approval may be initiated manually).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthorizationRequest {
    /// Wire-version (= `AUTHORIZATION_WIRE_VERSION`). Wire-format version.
    pub version: u8,
    /// Ed25519 pubkey нового устройства (запросчика).
    /// Ed25519 public key of the new device (requester).
    pub new_device_pubkey: [u8; DEVICE_PUBKEY_LEN],
    /// Unix-millis timestamp отправки запроса.
    /// Unix-millis timestamp of request dispatch.
    pub request_timestamp: u64,
    /// CSPRNG challenge (anti-replay на уровне mailbox).
    /// CSPRNG challenge (anti-replay at the mailbox layer).
    pub challenge_nonce: [u8; CHALLENGE_NONCE_LEN],
    /// Опциональная подсказка местоположения (UTF-8, ≤ 128 байт).
    /// Optional location hint (UTF-8, ≤ 128 bytes).
    pub location_hint: HString<LOCATION_HINT_MAX>,
    /// Ed25519 подпись identity-key'а поверх canonical signing input.
    /// Ed25519 signature by the identity-key over the canonical signing input.
    pub identity_signature: [u8; DEVICE_SIG_LEN],
}

/// Canonical signing input для `DeviceAuthorizationRequest`.
///
/// Canonical signing input for `DeviceAuthorizationRequest`.
///
/// Формат / Format:
/// ```text
/// "umbrellax-device-auth-request-v1"      // 32 bytes domain separator
/// || [version]                             // 1 byte
/// || new_device_pubkey                     // 32 bytes (Ed25519 pub)
/// || request_timestamp_u64_be              // 8 bytes
/// || challenge_nonce                       // 32 bytes
/// || [location_hint_len]                   // 1 byte (u8, ≤ 128)
/// || location_hint                         // L bytes UTF-8
/// ```
#[must_use]
pub fn canonical_signing_input_request(
    version: u8,
    new_device_pubkey: &[u8; DEVICE_PUBKEY_LEN],
    request_timestamp: u64,
    challenge_nonce: &[u8; CHALLENGE_NONCE_LEN],
    location_hint: &str,
) -> Vec<u8> {
    let hint_bytes = location_hint.as_bytes();
    let capacity = DEVICE_AUTH_REQUEST_DOMAIN_SEPARATOR.len()
        + 1
        + DEVICE_PUBKEY_LEN
        + 8
        + CHALLENGE_NONCE_LEN
        + 1
        + hint_bytes.len();
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(DEVICE_AUTH_REQUEST_DOMAIN_SEPARATOR);
    out.push(version);
    out.extend_from_slice(new_device_pubkey);
    out.extend_from_slice(&request_timestamp.to_be_bytes());
    out.extend_from_slice(challenge_nonce);
    out.push(hint_bytes.len() as u8);
    out.extend_from_slice(hint_bytes);
    out
}

/// Построить и подписать `DeviceAuthorizationRequest` через identity signer
/// closure. Callers обычно оборачивают `KeyStore::sign_with_identity`.
///
/// Build and sign a `DeviceAuthorizationRequest` via an identity signer
/// closure. Callers typically wrap `KeyStore::sign_with_identity`.
///
/// # Errors
/// - [`BackupError::InvalidWireFormat`] если `location_hint` длиннее
///   `LOCATION_HINT_MAX` или не UTF-8 (статически проверено параметром `&str`).
/// - Любая ошибка из `identity_signer` (транслируется как есть).
pub fn seal_device_authorization_request<F>(
    new_device_pubkey: [u8; DEVICE_PUBKEY_LEN],
    request_timestamp: u64,
    challenge_nonce: [u8; CHALLENGE_NONCE_LEN],
    location_hint: &str,
    identity_signer: F,
) -> Result<DeviceAuthorizationRequest, BackupError>
where
    F: FnOnce(&[u8]) -> Result<[u8; DEVICE_SIG_LEN], BackupError>,
{
    if location_hint.len() > LOCATION_HINT_MAX {
        return Err(BackupError::InvalidWireFormat);
    }
    let mut hint_storage: HString<LOCATION_HINT_MAX> = HString::new();
    hint_storage
        .push_str(location_hint)
        .map_err(|_| BackupError::InvalidWireFormat)?;

    let canonical = canonical_signing_input_request(
        AUTHORIZATION_WIRE_VERSION,
        &new_device_pubkey,
        request_timestamp,
        &challenge_nonce,
        location_hint,
    );
    let identity_signature = identity_signer(&canonical)?;

    Ok(DeviceAuthorizationRequest {
        version: AUTHORIZATION_WIRE_VERSION,
        new_device_pubkey,
        request_timestamp,
        challenge_nonce,
        location_hint: hint_storage,
        identity_signature,
    })
}

impl DeviceAuthorizationRequest {
    /// Canonical signing input для текущего содержимого (то что подписано
    /// identity-key). Переиспользуется при verify.
    ///
    /// Canonical signing input for the current contents (what is signed by
    /// identity-key). Reused when verifying.
    #[must_use]
    pub fn canonical_signing_input(&self) -> Vec<u8> {
        canonical_signing_input_request(
            self.version,
            &self.new_device_pubkey,
            self.request_timestamp,
            &self.challenge_nonce,
            self.location_hint.as_str(),
        )
    }

    /// Сериализовать в wire-format (138 + L байт).
    ///
    /// Serialize to wire format (138 + L bytes).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let hint_bytes = self.location_hint.as_bytes();
        let mut out = Vec::with_capacity(DEVICE_AUTH_REQUEST_BASE_LEN + hint_bytes.len());
        out.push(self.version);
        out.extend_from_slice(&self.new_device_pubkey);
        out.extend_from_slice(&self.request_timestamp.to_be_bytes());
        out.extend_from_slice(&self.challenge_nonce);
        out.push(hint_bytes.len() as u8);
        out.extend_from_slice(hint_bytes);
        out.extend_from_slice(&self.identity_signature);
        out
    }

    /// Десериализовать из wire-format. Никогда не panic'ит на некорректных
    /// данных — возвращает `BackupError::InvalidWireFormat` либо
    /// `BackupError::WrappedKeyVersionMismatch`.
    ///
    /// Deserialize from wire format. Never panics on invalid data — returns
    /// `BackupError::InvalidWireFormat` or `BackupError::WrappedKeyVersionMismatch`.
    ///
    /// # Errors
    /// - [`BackupError::InvalidWireFormat`] если буфер короче `138` байт,
    ///   `location_hint_len > 128`, или объявленная длина не совпадает.
    /// - [`BackupError::WrappedKeyVersionMismatch`] если version != `0x01`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BackupError> {
        if bytes.len() < DEVICE_AUTH_REQUEST_BASE_LEN {
            return Err(BackupError::InvalidWireFormat);
        }
        let version = bytes[0];
        if version != AUTHORIZATION_WIRE_VERSION {
            return Err(BackupError::WrappedKeyVersionMismatch {
                expected: AUTHORIZATION_WIRE_VERSION,
                found: version,
            });
        }
        let new_device_pubkey: [u8; DEVICE_PUBKEY_LEN] = bytes[1..33]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        let request_timestamp = u64::from_be_bytes(
            bytes[33..41]
                .try_into()
                .map_err(|_| BackupError::InvalidWireFormat)?,
        );
        let challenge_nonce: [u8; CHALLENGE_NONCE_LEN] = bytes[41..73]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        let location_hint_len = bytes[73] as usize;
        if location_hint_len > LOCATION_HINT_MAX {
            return Err(BackupError::InvalidWireFormat);
        }
        let expected_total = DEVICE_AUTH_REQUEST_BASE_LEN + location_hint_len;
        if bytes.len() != expected_total {
            return Err(BackupError::InvalidWireFormat);
        }
        let hint_start = 74;
        let hint_end = hint_start + location_hint_len;
        let hint_slice = &bytes[hint_start..hint_end];
        let hint_str =
            core::str::from_utf8(hint_slice).map_err(|_| BackupError::InvalidWireFormat)?;
        let mut location_hint: HString<LOCATION_HINT_MAX> = HString::new();
        location_hint
            .push_str(hint_str)
            .map_err(|_| BackupError::InvalidWireFormat)?;

        let sig_start = hint_end;
        let sig_end = sig_start + DEVICE_SIG_LEN;
        let identity_signature: [u8; DEVICE_SIG_LEN] = bytes[sig_start..sig_end]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;

        Ok(Self {
            version,
            new_device_pubkey,
            request_timestamp,
            challenge_nonce,
            location_hint,
            identity_signature,
        })
    }

    /// Проверить `identity_signature` поверх canonical signing input под
    /// ожидаемым identity-pubkey.
    ///
    /// Verify `identity_signature` over canonical signing input against the
    /// expected identity-pubkey.
    ///
    /// # Errors
    /// - [`BackupError::InvalidRistrettoEncoding`] если `expected_identity_pubkey`
    ///   не декодируется в Ed25519 pubkey.
    /// - [`BackupError::CryptoVerificationFailed`] если подпись не проходит.
    pub fn verify(
        &self,
        expected_identity_pubkey: &[u8; DEVICE_PUBKEY_LEN],
    ) -> Result<(), BackupError> {
        let vk = DalekVerifyingKey::from_bytes(expected_identity_pubkey)
            .map_err(|_| BackupError::InvalidRistrettoEncoding)?;
        let sig = DalekSignature::from_bytes(&self.identity_signature);
        let canonical = self.canonical_signing_input();
        vk.verify(&canonical, &sig)
            .map_err(|_| BackupError::CryptoVerificationFailed)
    }
}

// ---------------------------------------------------------------------------
// DeviceAuthorizationApproval
// ---------------------------------------------------------------------------

/// Одобрение нового устройства существующим active device. Публикуется в KT
/// как update для new device entry; переводит флаг в `active`. Содержит
/// `history_cutoff_timestamp` — Sealed Servers отвергают unwrap-запросы для
/// envelope старше cutoff (SPEC-12 §A.11.3). Подписан active device-key
/// approver'а под domain separator `"umbrellax-device-auth-approval-v1"`.
///
/// Approval of a new device by an existing active device. Published to KT
/// as an update for the new device entry; transitions the flag to `active`.
/// Contains `history_cutoff_timestamp` — Sealed Servers refuse unwrap
/// requests for envelopes older than the cutoff (SPEC-12 §A.11.3). Signed
/// by the approver's active device-key under domain separator
/// `"umbrellax-device-auth-approval-v1"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthorizationApproval {
    /// Wire-version (= `AUTHORIZATION_WIRE_VERSION`). Wire-format version.
    pub version: u8,
    /// Ed25519 pubkey авторизуемого (нового) устройства.
    /// Ed25519 public key of the authorized (new) device.
    pub new_device_pubkey: [u8; DEVICE_PUBKEY_LEN],
    /// Ed25519 pubkey active approver-устройства.
    /// Ed25519 public key of the active approver device.
    pub approver_device_pubkey: [u8; DEVICE_PUBKEY_LEN],
    /// Unix-millis с которого устройство считается авторизованным.
    /// Unix-millis from which the device is considered authorized.
    pub authorized_since_timestamp: u64,
    /// Unix-millis cutoff: envelopes старше отвергаются Sealed Servers.
    /// `0` = доступ ко всей истории.
    ///
    /// Unix-millis cutoff: envelopes older than this are rejected by Sealed
    /// Servers. `0` = full history access.
    pub history_cutoff_timestamp: u64,
    /// Bitmap флагов политики: bit 0 = повышенная безопасность, bits 1..7 reserved.
    /// Policy flags bitmap: bit 0 = high-security mode, bits 1..7 reserved.
    pub policy_flags: u8,
    /// Ed25519 подпись approver-device-key'а поверх canonical signing input.
    /// Ed25519 signature by the approver device-key over the canonical signing input.
    pub approver_signature: [u8; DEVICE_SIG_LEN],
}

/// Canonical signing input для `DeviceAuthorizationApproval`.
///
/// Canonical signing input for `DeviceAuthorizationApproval`.
///
/// Формат / Format:
/// ```text
/// "umbrellax-device-auth-approval-v1"     // 33 bytes domain separator
/// || [version]                             // 1 byte
/// || new_device_pubkey                     // 32 bytes
/// || approver_device_pubkey                // 32 bytes
/// || authorized_since_timestamp_u64_be     // 8 bytes
/// || history_cutoff_timestamp_u64_be       // 8 bytes
/// || [policy_flags]                        // 1 byte
/// ```
#[must_use]
pub fn canonical_signing_input_approval(
    version: u8,
    new_device_pubkey: &[u8; DEVICE_PUBKEY_LEN],
    approver_device_pubkey: &[u8; DEVICE_PUBKEY_LEN],
    authorized_since_timestamp: u64,
    history_cutoff_timestamp: u64,
    policy_flags: u8,
) -> Vec<u8> {
    let capacity = DEVICE_AUTH_APPROVAL_DOMAIN_SEPARATOR.len()
        + 1
        + DEVICE_PUBKEY_LEN
        + DEVICE_PUBKEY_LEN
        + 8
        + 8
        + 1;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(DEVICE_AUTH_APPROVAL_DOMAIN_SEPARATOR);
    out.push(version);
    out.extend_from_slice(new_device_pubkey);
    out.extend_from_slice(approver_device_pubkey);
    out.extend_from_slice(&authorized_since_timestamp.to_be_bytes());
    out.extend_from_slice(&history_cutoff_timestamp.to_be_bytes());
    out.push(policy_flags);
    out
}

/// Построить и подписать `DeviceAuthorizationApproval` через device signer
/// closure. Обычно оборачивает `KeyStore::sign_with_device(approver_index, ...)`.
///
/// Build and sign a `DeviceAuthorizationApproval` via a device signer
/// closure. Typically wraps `KeyStore::sign_with_device(approver_index, ...)`.
///
/// # Errors
/// - [`BackupError::InvalidWireFormat`] если `policy_flags` содержит
///   установленные reserved bits (1..7).
/// - Любая ошибка из `device_signer`.
pub fn seal_device_authorization_approval<F>(
    new_device_pubkey: [u8; DEVICE_PUBKEY_LEN],
    approver_device_pubkey: [u8; DEVICE_PUBKEY_LEN],
    authorized_since_timestamp: u64,
    history_cutoff_timestamp: u64,
    policy_flags: u8,
    device_signer: F,
) -> Result<DeviceAuthorizationApproval, BackupError>
where
    F: FnOnce(&[u8]) -> Result<[u8; DEVICE_SIG_LEN], BackupError>,
{
    if policy_flags & POLICY_FLAGS_RESERVED_MASK != 0 {
        return Err(BackupError::InvalidWireFormat);
    }

    let canonical = canonical_signing_input_approval(
        AUTHORIZATION_WIRE_VERSION,
        &new_device_pubkey,
        &approver_device_pubkey,
        authorized_since_timestamp,
        history_cutoff_timestamp,
        policy_flags,
    );
    let approver_signature = device_signer(&canonical)?;

    Ok(DeviceAuthorizationApproval {
        version: AUTHORIZATION_WIRE_VERSION,
        new_device_pubkey,
        approver_device_pubkey,
        authorized_since_timestamp,
        history_cutoff_timestamp,
        policy_flags,
        approver_signature,
    })
}

impl DeviceAuthorizationApproval {
    /// Canonical signing input для текущего содержимого.
    /// Canonical signing input for the current contents.
    #[must_use]
    pub fn canonical_signing_input(&self) -> Vec<u8> {
        canonical_signing_input_approval(
            self.version,
            &self.new_device_pubkey,
            &self.approver_device_pubkey,
            self.authorized_since_timestamp,
            self.history_cutoff_timestamp,
            self.policy_flags,
        )
    }

    /// Сериализовать в wire-format (146 байт, fixed).
    /// Serialize to wire format (146 bytes, fixed).
    #[must_use]
    pub fn encode(&self) -> [u8; DEVICE_AUTH_APPROVAL_LEN] {
        let mut out = [0u8; DEVICE_AUTH_APPROVAL_LEN];
        out[0] = self.version;
        out[1..33].copy_from_slice(&self.new_device_pubkey);
        out[33..65].copy_from_slice(&self.approver_device_pubkey);
        out[65..73].copy_from_slice(&self.authorized_since_timestamp.to_be_bytes());
        out[73..81].copy_from_slice(&self.history_cutoff_timestamp.to_be_bytes());
        out[81] = self.policy_flags;
        out[82..146].copy_from_slice(&self.approver_signature);
        out
    }

    /// Десериализовать из wire-format (146 байт).
    ///
    /// Deserialize from wire format (146 bytes).
    ///
    /// # Errors
    /// - [`BackupError::InvalidWireFormat`] если длина ≠ 146 байт либо
    ///   `policy_flags` имеет set reserved bits.
    /// - [`BackupError::WrappedKeyVersionMismatch`] если version != `0x01`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BackupError> {
        if bytes.len() != DEVICE_AUTH_APPROVAL_LEN {
            return Err(BackupError::InvalidWireFormat);
        }
        let version = bytes[0];
        if version != AUTHORIZATION_WIRE_VERSION {
            return Err(BackupError::WrappedKeyVersionMismatch {
                expected: AUTHORIZATION_WIRE_VERSION,
                found: version,
            });
        }
        let new_device_pubkey: [u8; DEVICE_PUBKEY_LEN] = bytes[1..33]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        let approver_device_pubkey: [u8; DEVICE_PUBKEY_LEN] = bytes[33..65]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        let authorized_since_timestamp = u64::from_be_bytes(
            bytes[65..73]
                .try_into()
                .map_err(|_| BackupError::InvalidWireFormat)?,
        );
        let history_cutoff_timestamp = u64::from_be_bytes(
            bytes[73..81]
                .try_into()
                .map_err(|_| BackupError::InvalidWireFormat)?,
        );
        let policy_flags = bytes[81];
        if policy_flags & POLICY_FLAGS_RESERVED_MASK != 0 {
            return Err(BackupError::InvalidWireFormat);
        }
        let approver_signature: [u8; DEVICE_SIG_LEN] = bytes[82..146]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;

        Ok(Self {
            version,
            new_device_pubkey,
            approver_device_pubkey,
            authorized_since_timestamp,
            history_cutoff_timestamp,
            policy_flags,
            approver_signature,
        })
    }

    /// Проверить подпись approver'а под ожидаемым pubkey.
    /// Verify approver's signature against the expected pubkey.
    ///
    /// # Errors
    /// - [`BackupError::InvalidRistrettoEncoding`] если `expected_approver_pubkey`
    ///   не декодируется в Ed25519 pubkey.
    /// - [`BackupError::CryptoVerificationFailed`] если подпись не проходит.
    pub fn verify(
        &self,
        expected_approver_pubkey: &[u8; DEVICE_PUBKEY_LEN],
    ) -> Result<(), BackupError> {
        let vk = DalekVerifyingKey::from_bytes(expected_approver_pubkey)
            .map_err(|_| BackupError::InvalidRistrettoEncoding)?;
        let sig = DalekSignature::from_bytes(&self.approver_signature);
        let canonical = self.canonical_signing_input();
        vk.verify(&canonical, &sig)
            .map_err(|_| BackupError::CryptoVerificationFailed)
    }

    /// Проверить подпись против `approver_device_pubkey` из самого поля
    /// (self-consistency check). Полезно когда approver pubkey уже в entry.
    ///
    /// Verify signature against `approver_device_pubkey` taken from the entry
    /// itself (self-consistency check). Useful when the approver pubkey is
    /// already embedded in the entry.
    ///
    /// # Errors
    /// См. [`Self::verify`]. See [`Self::verify`].
    pub fn verify_self_consistent(&self) -> Result<(), BackupError> {
        self.verify(&self.approver_device_pubkey)
    }
}

// ---------------------------------------------------------------------------
// DeviceAuthorizationRevocation
// ---------------------------------------------------------------------------

/// Отзыв device-key существующим active device (включая self-revocation
/// где `revoked == revoker`). Публикуется в KT; переводит entry в
/// `revoked` terminal state. Подписан active device-key'ом revoker'а под
/// domain separator `"umbrellax-device-auth-revoke-v1"`.
///
/// Revocation of a device-key by an existing active device (including
/// self-revocation where `revoked == revoker`). Published to KT; moves
/// the entry to the `revoked` terminal state. Signed by the revoker's
/// active device-key under domain separator `"umbrellax-device-auth-revoke-v1"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthorizationRevocation {
    /// Wire-version (= `AUTHORIZATION_WIRE_VERSION`).
    pub version: u8,
    /// Ed25519 pubkey отзываемого устройства.
    /// Ed25519 public key of the revoked device.
    pub revoked_device_pubkey: [u8; DEVICE_PUBKEY_LEN],
    /// Ed25519 pubkey revoker'а (active device).
    /// Ed25519 public key of the revoker (active device).
    pub revoker_device_pubkey: [u8; DEVICE_PUBKEY_LEN],
    /// Unix-millis момент revocation. Unix-millis revocation moment.
    pub revocation_timestamp: u64,
    /// Ed25519 подпись revoker-device-key поверх canonical input.
    /// Ed25519 signature by the revoker device-key over the canonical input.
    pub revoker_signature: [u8; DEVICE_SIG_LEN],
}

/// Canonical signing input для `DeviceAuthorizationRevocation`.
///
/// Canonical signing input for `DeviceAuthorizationRevocation`.
///
/// Формат / Format:
/// ```text
/// "umbrellax-device-auth-revoke-v1"       // 31 bytes domain separator
/// || [version]                             // 1 byte
/// || revoked_device_pubkey                 // 32 bytes
/// || revoker_device_pubkey                 // 32 bytes
/// || revocation_timestamp_u64_be           // 8 bytes
/// ```
#[must_use]
pub fn canonical_signing_input_revocation(
    version: u8,
    revoked_device_pubkey: &[u8; DEVICE_PUBKEY_LEN],
    revoker_device_pubkey: &[u8; DEVICE_PUBKEY_LEN],
    revocation_timestamp: u64,
) -> Vec<u8> {
    let capacity =
        DEVICE_AUTH_REVOKE_DOMAIN_SEPARATOR.len() + 1 + DEVICE_PUBKEY_LEN + DEVICE_PUBKEY_LEN + 8;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(DEVICE_AUTH_REVOKE_DOMAIN_SEPARATOR);
    out.push(version);
    out.extend_from_slice(revoked_device_pubkey);
    out.extend_from_slice(revoker_device_pubkey);
    out.extend_from_slice(&revocation_timestamp.to_be_bytes());
    out
}

/// Построить и подписать `DeviceAuthorizationRevocation` через device signer.
///
/// Build and sign a `DeviceAuthorizationRevocation` via a device signer.
///
/// # Errors
/// Любая ошибка из `device_signer`.
pub fn seal_device_authorization_revocation<F>(
    revoked_device_pubkey: [u8; DEVICE_PUBKEY_LEN],
    revoker_device_pubkey: [u8; DEVICE_PUBKEY_LEN],
    revocation_timestamp: u64,
    device_signer: F,
) -> Result<DeviceAuthorizationRevocation, BackupError>
where
    F: FnOnce(&[u8]) -> Result<[u8; DEVICE_SIG_LEN], BackupError>,
{
    let canonical = canonical_signing_input_revocation(
        AUTHORIZATION_WIRE_VERSION,
        &revoked_device_pubkey,
        &revoker_device_pubkey,
        revocation_timestamp,
    );
    let revoker_signature = device_signer(&canonical)?;

    Ok(DeviceAuthorizationRevocation {
        version: AUTHORIZATION_WIRE_VERSION,
        revoked_device_pubkey,
        revoker_device_pubkey,
        revocation_timestamp,
        revoker_signature,
    })
}

impl DeviceAuthorizationRevocation {
    /// Canonical signing input для текущего содержимого.
    /// Canonical signing input for the current contents.
    #[must_use]
    pub fn canonical_signing_input(&self) -> Vec<u8> {
        canonical_signing_input_revocation(
            self.version,
            &self.revoked_device_pubkey,
            &self.revoker_device_pubkey,
            self.revocation_timestamp,
        )
    }

    /// Сериализовать в wire-format (137 байт, fixed).
    /// Serialize to wire format (137 bytes, fixed).
    #[must_use]
    pub fn encode(&self) -> [u8; DEVICE_AUTH_REVOKE_LEN] {
        let mut out = [0u8; DEVICE_AUTH_REVOKE_LEN];
        out[0] = self.version;
        out[1..33].copy_from_slice(&self.revoked_device_pubkey);
        out[33..65].copy_from_slice(&self.revoker_device_pubkey);
        out[65..73].copy_from_slice(&self.revocation_timestamp.to_be_bytes());
        out[73..137].copy_from_slice(&self.revoker_signature);
        out
    }

    /// Десериализовать из wire-format (137 байт).
    ///
    /// Deserialize from wire format (137 bytes).
    ///
    /// # Errors
    /// - [`BackupError::InvalidWireFormat`] если длина ≠ 137 байт.
    /// - [`BackupError::WrappedKeyVersionMismatch`] если version != `0x01`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BackupError> {
        if bytes.len() != DEVICE_AUTH_REVOKE_LEN {
            return Err(BackupError::InvalidWireFormat);
        }
        let version = bytes[0];
        if version != AUTHORIZATION_WIRE_VERSION {
            return Err(BackupError::WrappedKeyVersionMismatch {
                expected: AUTHORIZATION_WIRE_VERSION,
                found: version,
            });
        }
        let revoked_device_pubkey: [u8; DEVICE_PUBKEY_LEN] = bytes[1..33]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        let revoker_device_pubkey: [u8; DEVICE_PUBKEY_LEN] = bytes[33..65]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;
        let revocation_timestamp = u64::from_be_bytes(
            bytes[65..73]
                .try_into()
                .map_err(|_| BackupError::InvalidWireFormat)?,
        );
        let revoker_signature: [u8; DEVICE_SIG_LEN] = bytes[73..137]
            .try_into()
            .map_err(|_| BackupError::InvalidWireFormat)?;

        Ok(Self {
            version,
            revoked_device_pubkey,
            revoker_device_pubkey,
            revocation_timestamp,
            revoker_signature,
        })
    }

    /// Проверить подпись revoker'а под ожидаемым pubkey.
    /// Verify revoker's signature against the expected pubkey.
    ///
    /// # Errors
    /// - [`BackupError::InvalidRistrettoEncoding`] если pubkey некорректен.
    /// - [`BackupError::CryptoVerificationFailed`] если подпись не проходит.
    pub fn verify(
        &self,
        expected_revoker_pubkey: &[u8; DEVICE_PUBKEY_LEN],
    ) -> Result<(), BackupError> {
        let vk = DalekVerifyingKey::from_bytes(expected_revoker_pubkey)
            .map_err(|_| BackupError::InvalidRistrettoEncoding)?;
        let sig = DalekSignature::from_bytes(&self.revoker_signature);
        let canonical = self.canonical_signing_input();
        vk.verify(&canonical, &sig)
            .map_err(|_| BackupError::CryptoVerificationFailed)
    }

    /// Проверить подпись против `revoker_device_pubkey` из самого поля.
    /// Verify signature against `revoker_device_pubkey` from the entry itself.
    ///
    /// # Errors
    /// См. [`Self::verify`]. See [`Self::verify`].
    pub fn verify_self_consistent(&self) -> Result<(), BackupError> {
        self.verify(&self.revoker_device_pubkey)
    }

    /// `true` если revocation является self-revocation (revoked == revoker).
    /// `true` if the revocation is a self-revocation (revoked == revoker).
    #[must_use]
    pub fn is_self_revocation(&self) -> bool {
        self.revoked_device_pubkey == self.revoker_device_pubkey
    }
}

// ---------------------------------------------------------------------------
// Тесты / Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use proptest::prelude::*;
    use rand_core::{OsRng, RngCore};

    fn make_keypair() -> (SigningKey, [u8; 32]) {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let sk = SigningKey::from_bytes(&secret);
        let vk = sk.verifying_key().to_bytes();
        (sk, vk)
    }

    fn fresh_nonce() -> [u8; CHALLENGE_NONCE_LEN] {
        let mut n = [0u8; CHALLENGE_NONCE_LEN];
        OsRng.fill_bytes(&mut n);
        n
    }

    fn sign_with(
        sk: &SigningKey,
    ) -> impl FnOnce(&[u8]) -> Result<[u8; DEVICE_SIG_LEN], BackupError> + '_ {
        move |message: &[u8]| Ok(sk.sign(message).to_bytes())
    }

    // -------- Constants sanity --------

    #[test]
    fn domain_separator_request_is_32_bytes() {
        assert_eq!(DEVICE_AUTH_REQUEST_DOMAIN_SEPARATOR.len(), 32);
        assert_eq!(
            DEVICE_AUTH_REQUEST_DOMAIN_SEPARATOR,
            b"umbrellax-device-auth-request-v1"
        );
    }

    #[test]
    fn domain_separator_approval_is_33_bytes() {
        assert_eq!(DEVICE_AUTH_APPROVAL_DOMAIN_SEPARATOR.len(), 33);
        assert_eq!(
            DEVICE_AUTH_APPROVAL_DOMAIN_SEPARATOR,
            b"umbrellax-device-auth-approval-v1"
        );
    }

    #[test]
    fn domain_separator_revoke_is_31_bytes() {
        assert_eq!(DEVICE_AUTH_REVOKE_DOMAIN_SEPARATOR.len(), 31);
        assert_eq!(
            DEVICE_AUTH_REVOKE_DOMAIN_SEPARATOR,
            b"umbrellax-device-auth-revoke-v1"
        );
    }

    #[test]
    fn wire_format_lengths_match_spec() {
        assert_eq!(DEVICE_AUTH_REQUEST_BASE_LEN, 138);
        assert_eq!(DEVICE_AUTH_REQUEST_MAX_LEN, 266);
        assert_eq!(DEVICE_AUTH_APPROVAL_LEN, 146);
        assert_eq!(DEVICE_AUTH_REVOKE_LEN, 137);
    }

    // -------- DeviceAuthorizationRequest — unit --------

    #[test]
    fn request_seal_verify_happy_path() {
        let (identity_sk, identity_vk) = make_keypair();
        let (_device_sk, device_vk) = make_keypair();
        let req = seal_device_authorization_request(
            device_vk,
            1_700_000_000_000u64,
            fresh_nonce(),
            "Almaty",
            sign_with(&identity_sk),
        )
        .unwrap();
        req.verify(&identity_vk).expect("signature must verify");
    }

    #[test]
    fn request_canonical_layout() {
        let (identity_sk, _identity_vk) = make_keypair();
        let (_device_sk, device_vk) = make_keypair();
        let nonce = [0x77u8; CHALLENGE_NONCE_LEN];
        let ts = 0x0102_0304_0506_0708u64;
        let req = seal_device_authorization_request(
            device_vk,
            ts,
            nonce,
            "Unknown",
            sign_with(&identity_sk),
        )
        .unwrap();
        let canonical = req.canonical_signing_input();

        let mut off = 0;
        assert_eq!(
            &canonical[off..off + DEVICE_AUTH_REQUEST_DOMAIN_SEPARATOR.len()],
            DEVICE_AUTH_REQUEST_DOMAIN_SEPARATOR
        );
        off += DEVICE_AUTH_REQUEST_DOMAIN_SEPARATOR.len();
        assert_eq!(canonical[off], AUTHORIZATION_WIRE_VERSION);
        off += 1;
        assert_eq!(&canonical[off..off + DEVICE_PUBKEY_LEN], &device_vk);
        off += DEVICE_PUBKEY_LEN;
        assert_eq!(&canonical[off..off + 8], &ts.to_be_bytes());
        off += 8;
        assert_eq!(&canonical[off..off + CHALLENGE_NONCE_LEN], &nonce);
        off += CHALLENGE_NONCE_LEN;
        assert_eq!(canonical[off], b"Unknown".len() as u8);
        off += 1;
        assert_eq!(&canonical[off..off + b"Unknown".len()], b"Unknown");
        assert_eq!(off + b"Unknown".len(), canonical.len());
    }

    #[test]
    fn request_encode_decode_roundtrip_happy() {
        let (identity_sk, _identity_vk) = make_keypair();
        let (_device_sk, device_vk) = make_keypair();
        let req = seal_device_authorization_request(
            device_vk,
            1,
            fresh_nonce(),
            "Berlin",
            sign_with(&identity_sk),
        )
        .unwrap();
        let encoded = req.encode();
        assert_eq!(
            encoded.len(),
            DEVICE_AUTH_REQUEST_BASE_LEN + b"Berlin".len()
        );
        let decoded = DeviceAuthorizationRequest::from_bytes(&encoded).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn request_empty_location_hint_roundtrip() {
        let (identity_sk, _identity_vk) = make_keypair();
        let (_device_sk, device_vk) = make_keypair();
        let req = seal_device_authorization_request(
            device_vk,
            0,
            fresh_nonce(),
            "",
            sign_with(&identity_sk),
        )
        .unwrap();
        let encoded = req.encode();
        assert_eq!(encoded.len(), DEVICE_AUTH_REQUEST_BASE_LEN);
        let decoded = DeviceAuthorizationRequest::from_bytes(&encoded).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn request_max_location_hint_roundtrip() {
        let (identity_sk, identity_vk) = make_keypair();
        let (_device_sk, device_vk) = make_keypair();
        let hint = "a".repeat(LOCATION_HINT_MAX);
        let req = seal_device_authorization_request(
            device_vk,
            u64::MAX,
            fresh_nonce(),
            &hint,
            sign_with(&identity_sk),
        )
        .unwrap();
        let encoded = req.encode();
        assert_eq!(encoded.len(), DEVICE_AUTH_REQUEST_MAX_LEN);
        let decoded = DeviceAuthorizationRequest::from_bytes(&encoded).unwrap();
        assert_eq!(req, decoded);
        decoded.verify(&identity_vk).unwrap();
    }

    #[test]
    fn request_rejects_oversized_hint_at_seal() {
        let (identity_sk, _identity_vk) = make_keypair();
        let (_device_sk, device_vk) = make_keypair();
        let hint = "x".repeat(LOCATION_HINT_MAX + 1);
        let err = seal_device_authorization_request(
            device_vk,
            0,
            fresh_nonce(),
            &hint,
            sign_with(&identity_sk),
        )
        .unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn request_verify_rejects_tampered_signature() {
        let (identity_sk, identity_vk) = make_keypair();
        let (_device_sk, device_vk) = make_keypair();
        let mut req = seal_device_authorization_request(
            device_vk,
            5,
            fresh_nonce(),
            "Unknown",
            sign_with(&identity_sk),
        )
        .unwrap();
        req.identity_signature[0] ^= 1;
        let err = req.verify(&identity_vk).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn request_verify_rejects_tampered_field() {
        let (identity_sk, identity_vk) = make_keypair();
        let (_device_sk, device_vk) = make_keypair();
        let mut req = seal_device_authorization_request(
            device_vk,
            5,
            fresh_nonce(),
            "Unknown",
            sign_with(&identity_sk),
        )
        .unwrap();
        req.request_timestamp ^= 1;
        let err = req.verify(&identity_vk).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn request_verify_rejects_wrong_identity_pubkey() {
        let (identity_sk, _identity_vk_correct) = make_keypair();
        let (_other_sk, other_vk) = make_keypair();
        let (_device_sk, device_vk) = make_keypair();
        let req = seal_device_authorization_request(
            device_vk,
            5,
            fresh_nonce(),
            "Unknown",
            sign_with(&identity_sk),
        )
        .unwrap();
        let err = req.verify(&other_vk).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn request_from_bytes_rejects_bad_version() {
        let (identity_sk, _identity_vk) = make_keypair();
        let (_device_sk, device_vk) = make_keypair();
        let req = seal_device_authorization_request(
            device_vk,
            0,
            fresh_nonce(),
            "",
            sign_with(&identity_sk),
        )
        .unwrap();
        let mut encoded = req.encode();
        encoded[0] = 0x02;
        let err = DeviceAuthorizationRequest::from_bytes(&encoded).unwrap_err();
        assert!(matches!(
            err,
            BackupError::WrappedKeyVersionMismatch {
                expected: 0x01,
                found: 0x02
            }
        ));
    }

    #[test]
    fn request_from_bytes_rejects_truncated() {
        let short = vec![0u8; DEVICE_AUTH_REQUEST_BASE_LEN - 1];
        let err = DeviceAuthorizationRequest::from_bytes(&short).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn request_from_bytes_rejects_oversized_hint_len() {
        let (identity_sk, _identity_vk) = make_keypair();
        let (_device_sk, device_vk) = make_keypair();
        let req = seal_device_authorization_request(
            device_vk,
            0,
            fresh_nonce(),
            "",
            sign_with(&identity_sk),
        )
        .unwrap();
        let mut encoded = req.encode();
        encoded[73] = 200; // larger than LOCATION_HINT_MAX
        let err = DeviceAuthorizationRequest::from_bytes(&encoded).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn request_from_bytes_rejects_length_mismatch() {
        let (identity_sk, _identity_vk) = make_keypair();
        let (_device_sk, device_vk) = make_keypair();
        let req = seal_device_authorization_request(
            device_vk,
            0,
            fresh_nonce(),
            "AB",
            sign_with(&identity_sk),
        )
        .unwrap();
        let encoded = req.encode();
        // Declare length 10 but provide only 2 bytes of hint.
        let mut mutated = encoded.clone();
        mutated[73] = 10;
        let err = DeviceAuthorizationRequest::from_bytes(&mutated).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn request_signer_error_propagates() {
        let (_device_sk, device_vk) = make_keypair();
        let err = seal_device_authorization_request(device_vk, 0, fresh_nonce(), "", |_| {
            Err(BackupError::DeviceSigning("hw-unavailable"))
        })
        .unwrap_err();
        assert!(matches!(err, BackupError::DeviceSigning(_)));
    }

    // -------- DeviceAuthorizationApproval — unit --------

    #[test]
    fn approval_seal_verify_happy_path() {
        let (approver_sk, approver_vk) = make_keypair();
        let (_new_sk, new_vk) = make_keypair();
        let ap = seal_device_authorization_approval(
            new_vk,
            approver_vk,
            1_700_000_000_000u64,
            0,
            0,
            sign_with(&approver_sk),
        )
        .unwrap();
        ap.verify(&approver_vk).unwrap();
        ap.verify_self_consistent().unwrap();
    }

    #[test]
    fn approval_canonical_layout() {
        let (approver_sk, _approver_vk) = make_keypair();
        let new_vk = [0x11u8; DEVICE_PUBKEY_LEN];
        let approver_vk = [0x22u8; DEVICE_PUBKEY_LEN];
        let since = 0x0102_0304_0506_0708u64;
        let cutoff = 0x0807_0605_0403_0201u64;
        let flags = POLICY_FLAG_HIGH_SECURITY;
        let ap = DeviceAuthorizationApproval {
            version: AUTHORIZATION_WIRE_VERSION,
            new_device_pubkey: new_vk,
            approver_device_pubkey: approver_vk,
            authorized_since_timestamp: since,
            history_cutoff_timestamp: cutoff,
            policy_flags: flags,
            approver_signature: approver_sk
                .sign(&canonical_signing_input_approval(
                    AUTHORIZATION_WIRE_VERSION,
                    &new_vk,
                    &approver_vk,
                    since,
                    cutoff,
                    flags,
                ))
                .to_bytes(),
        };
        let canonical = ap.canonical_signing_input();

        let mut off = 0;
        assert_eq!(
            &canonical[off..off + DEVICE_AUTH_APPROVAL_DOMAIN_SEPARATOR.len()],
            DEVICE_AUTH_APPROVAL_DOMAIN_SEPARATOR
        );
        off += DEVICE_AUTH_APPROVAL_DOMAIN_SEPARATOR.len();
        assert_eq!(canonical[off], AUTHORIZATION_WIRE_VERSION);
        off += 1;
        assert_eq!(&canonical[off..off + DEVICE_PUBKEY_LEN], &new_vk);
        off += DEVICE_PUBKEY_LEN;
        assert_eq!(&canonical[off..off + DEVICE_PUBKEY_LEN], &approver_vk);
        off += DEVICE_PUBKEY_LEN;
        assert_eq!(&canonical[off..off + 8], &since.to_be_bytes());
        off += 8;
        assert_eq!(&canonical[off..off + 8], &cutoff.to_be_bytes());
        off += 8;
        assert_eq!(canonical[off], flags);
        assert_eq!(off + 1, canonical.len());
    }

    #[test]
    fn approval_encode_fixed_length() {
        let (approver_sk, approver_vk) = make_keypair();
        let (_new_sk, new_vk) = make_keypair();
        let ap = seal_device_authorization_approval(
            new_vk,
            approver_vk,
            1,
            0,
            0,
            sign_with(&approver_sk),
        )
        .unwrap();
        let bytes = ap.encode();
        assert_eq!(bytes.len(), DEVICE_AUTH_APPROVAL_LEN);
        let decoded = DeviceAuthorizationApproval::from_bytes(&bytes).unwrap();
        assert_eq!(ap, decoded);
    }

    #[test]
    fn approval_rejects_reserved_policy_bits_at_seal() {
        let (approver_sk, approver_vk) = make_keypair();
        let (_new_sk, new_vk) = make_keypair();
        let err = seal_device_authorization_approval(
            new_vk,
            approver_vk,
            1,
            0,
            0x02, // bit 1 reserved
            sign_with(&approver_sk),
        )
        .unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn approval_rejects_reserved_policy_bits_at_decode() {
        let (approver_sk, approver_vk) = make_keypair();
        let (_new_sk, new_vk) = make_keypair();
        let ap = seal_device_authorization_approval(
            new_vk,
            approver_vk,
            1,
            0,
            POLICY_FLAG_HIGH_SECURITY,
            sign_with(&approver_sk),
        )
        .unwrap();
        let mut bytes = ap.encode();
        bytes[81] = 0x80; // bit 7 reserved
        let err = DeviceAuthorizationApproval::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn approval_rejects_bad_version_at_decode() {
        let (approver_sk, approver_vk) = make_keypair();
        let (_new_sk, new_vk) = make_keypair();
        let ap = seal_device_authorization_approval(
            new_vk,
            approver_vk,
            1,
            0,
            0,
            sign_with(&approver_sk),
        )
        .unwrap();
        let mut bytes = ap.encode();
        bytes[0] = 0x7F;
        let err = DeviceAuthorizationApproval::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            BackupError::WrappedKeyVersionMismatch {
                expected: 0x01,
                found: 0x7F
            }
        ));
    }

    #[test]
    fn approval_rejects_wrong_length() {
        let short = vec![0u8; DEVICE_AUTH_APPROVAL_LEN - 1];
        let err = DeviceAuthorizationApproval::from_bytes(&short).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
        let long = vec![0u8; DEVICE_AUTH_APPROVAL_LEN + 1];
        let err = DeviceAuthorizationApproval::from_bytes(&long).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn approval_verify_rejects_tampered_history_cutoff() {
        let (approver_sk, approver_vk) = make_keypair();
        let (_new_sk, new_vk) = make_keypair();
        let mut ap = seal_device_authorization_approval(
            new_vk,
            approver_vk,
            1,
            100,
            0,
            sign_with(&approver_sk),
        )
        .unwrap();
        ap.history_cutoff_timestamp = 999;
        let err = ap.verify(&approver_vk).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn approval_verify_rejects_wrong_approver_pubkey() {
        let (approver_sk, approver_vk) = make_keypair();
        let (_other_sk, other_vk) = make_keypair();
        let (_new_sk, new_vk) = make_keypair();
        let ap = seal_device_authorization_approval(
            new_vk,
            approver_vk,
            1,
            0,
            0,
            sign_with(&approver_sk),
        )
        .unwrap();
        let err = ap.verify(&other_vk).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn approval_history_cutoff_max_works() {
        let (approver_sk, approver_vk) = make_keypair();
        let (_new_sk, new_vk) = make_keypair();
        let ap = seal_device_authorization_approval(
            new_vk,
            approver_vk,
            1,
            u64::MAX,
            0,
            sign_with(&approver_sk),
        )
        .unwrap();
        ap.verify(&approver_vk).unwrap();
        let encoded = ap.encode();
        let decoded = DeviceAuthorizationApproval::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.history_cutoff_timestamp, u64::MAX);
    }

    #[test]
    fn approval_signer_error_propagates() {
        let (_new_sk, new_vk) = make_keypair();
        let (_approver_sk, approver_vk) = make_keypair();
        let err = seal_device_authorization_approval(new_vk, approver_vk, 1, 0, 0, |_| {
            Err(BackupError::DeviceSigning("signer-offline"))
        })
        .unwrap_err();
        assert!(matches!(err, BackupError::DeviceSigning(_)));
    }

    // -------- DeviceAuthorizationRevocation — unit --------

    #[test]
    fn revocation_seal_verify_happy_path() {
        let (revoker_sk, revoker_vk) = make_keypair();
        let (_revoked_sk, revoked_vk) = make_keypair();
        let rv = seal_device_authorization_revocation(
            revoked_vk,
            revoker_vk,
            1_700_000_000_000u64,
            sign_with(&revoker_sk),
        )
        .unwrap();
        rv.verify(&revoker_vk).unwrap();
        rv.verify_self_consistent().unwrap();
        assert!(!rv.is_self_revocation());
    }

    #[test]
    fn revocation_self_revocation_flag() {
        let (revoker_sk, revoker_vk) = make_keypair();
        let rv = seal_device_authorization_revocation(
            revoker_vk, // revoked == revoker
            revoker_vk,
            1,
            sign_with(&revoker_sk),
        )
        .unwrap();
        assert!(rv.is_self_revocation());
        rv.verify(&revoker_vk).unwrap();
    }

    #[test]
    fn revocation_encode_fixed_length() {
        let (revoker_sk, revoker_vk) = make_keypair();
        let (_revoked_sk, revoked_vk) = make_keypair();
        let rv = seal_device_authorization_revocation(
            revoked_vk,
            revoker_vk,
            123,
            sign_with(&revoker_sk),
        )
        .unwrap();
        let bytes = rv.encode();
        assert_eq!(bytes.len(), DEVICE_AUTH_REVOKE_LEN);
        let decoded = DeviceAuthorizationRevocation::from_bytes(&bytes).unwrap();
        assert_eq!(rv, decoded);
    }

    #[test]
    fn revocation_canonical_layout() {
        let (revoker_sk, _revoker_vk) = make_keypair();
        let revoked_vk = [0x11u8; DEVICE_PUBKEY_LEN];
        let revoker_vk = [0x22u8; DEVICE_PUBKEY_LEN];
        let ts = 0x0F0E_0D0C_0B0A_0908u64;
        let rv = DeviceAuthorizationRevocation {
            version: AUTHORIZATION_WIRE_VERSION,
            revoked_device_pubkey: revoked_vk,
            revoker_device_pubkey: revoker_vk,
            revocation_timestamp: ts,
            revoker_signature: revoker_sk
                .sign(&canonical_signing_input_revocation(
                    AUTHORIZATION_WIRE_VERSION,
                    &revoked_vk,
                    &revoker_vk,
                    ts,
                ))
                .to_bytes(),
        };
        let canonical = rv.canonical_signing_input();

        let mut off = 0;
        assert_eq!(
            &canonical[off..off + DEVICE_AUTH_REVOKE_DOMAIN_SEPARATOR.len()],
            DEVICE_AUTH_REVOKE_DOMAIN_SEPARATOR
        );
        off += DEVICE_AUTH_REVOKE_DOMAIN_SEPARATOR.len();
        assert_eq!(canonical[off], AUTHORIZATION_WIRE_VERSION);
        off += 1;
        assert_eq!(&canonical[off..off + DEVICE_PUBKEY_LEN], &revoked_vk);
        off += DEVICE_PUBKEY_LEN;
        assert_eq!(&canonical[off..off + DEVICE_PUBKEY_LEN], &revoker_vk);
        off += DEVICE_PUBKEY_LEN;
        assert_eq!(&canonical[off..off + 8], &ts.to_be_bytes());
        assert_eq!(off + 8, canonical.len());
    }

    #[test]
    fn revocation_rejects_bad_version() {
        let (revoker_sk, revoker_vk) = make_keypair();
        let (_revoked_sk, revoked_vk) = make_keypair();
        let rv =
            seal_device_authorization_revocation(revoked_vk, revoker_vk, 1, sign_with(&revoker_sk))
                .unwrap();
        let mut bytes = rv.encode();
        bytes[0] = 0x99;
        let err = DeviceAuthorizationRevocation::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            BackupError::WrappedKeyVersionMismatch {
                expected: 0x01,
                found: 0x99
            }
        ));
    }

    #[test]
    fn revocation_rejects_wrong_length() {
        let short = vec![0u8; DEVICE_AUTH_REVOKE_LEN - 1];
        let err = DeviceAuthorizationRevocation::from_bytes(&short).unwrap_err();
        assert!(matches!(err, BackupError::InvalidWireFormat));
    }

    #[test]
    fn revocation_verify_rejects_tampered_timestamp() {
        let (revoker_sk, revoker_vk) = make_keypair();
        let (_revoked_sk, revoked_vk) = make_keypair();
        let mut rv = seal_device_authorization_revocation(
            revoked_vk,
            revoker_vk,
            100,
            sign_with(&revoker_sk),
        )
        .unwrap();
        rv.revocation_timestamp = 999;
        let err = rv.verify(&revoker_vk).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn revocation_verify_rejects_wrong_revoker_pubkey() {
        let (revoker_sk, revoker_vk) = make_keypair();
        let (_other_sk, other_vk) = make_keypair();
        let (_revoked_sk, revoked_vk) = make_keypair();
        let rv =
            seal_device_authorization_revocation(revoked_vk, revoker_vk, 1, sign_with(&revoker_sk))
                .unwrap();
        let err = rv.verify(&other_vk).unwrap_err();
        assert!(matches!(err, BackupError::CryptoVerificationFailed));
    }

    #[test]
    fn revocation_signer_error_propagates() {
        let (_revoker_sk, revoker_vk) = make_keypair();
        let (_revoked_sk, revoked_vk) = make_keypair();
        let err = seal_device_authorization_revocation(revoked_vk, revoker_vk, 1, |_| {
            Err(BackupError::DeviceSigning("hw-error"))
        })
        .unwrap_err();
        assert!(matches!(err, BackupError::DeviceSigning(_)));
    }

    // -------- Property-based tests --------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn proptest_request_roundtrip(
            timestamp in any::<u64>(),
            nonce in proptest::array::uniform32(any::<u8>()),
            new_device in proptest::array::uniform32(any::<u8>()),
            hint_len in 0usize..=LOCATION_HINT_MAX,
        ) {
            let (identity_sk, identity_vk) = make_keypair();
            let hint: String = "a".repeat(hint_len);
            let req = seal_device_authorization_request(
                new_device,
                timestamp,
                nonce,
                &hint,
                sign_with(&identity_sk),
            ).unwrap();
            let bytes = req.encode();
            prop_assert_eq!(bytes.len(), DEVICE_AUTH_REQUEST_BASE_LEN + hint_len);
            let decoded = DeviceAuthorizationRequest::from_bytes(&bytes).unwrap();
            prop_assert_eq!(&req, &decoded);
            decoded.verify(&identity_vk).unwrap();
        }

        #[test]
        fn proptest_approval_roundtrip(
            authorized_since in any::<u64>(),
            history_cutoff in any::<u64>(),
            policy_flag_high_sec in any::<bool>(),
            new_device in proptest::array::uniform32(any::<u8>()),
        ) {
            let (approver_sk, approver_vk) = make_keypair();
            let flags = if policy_flag_high_sec { POLICY_FLAG_HIGH_SECURITY } else { 0 };
            let ap = seal_device_authorization_approval(
                new_device,
                approver_vk,
                authorized_since,
                history_cutoff,
                flags,
                sign_with(&approver_sk),
            ).unwrap();
            let bytes = ap.encode();
            prop_assert_eq!(bytes.len(), DEVICE_AUTH_APPROVAL_LEN);
            let decoded = DeviceAuthorizationApproval::from_bytes(&bytes).unwrap();
            prop_assert_eq!(&ap, &decoded);
            decoded.verify(&approver_vk).unwrap();
        }

        #[test]
        fn proptest_revocation_roundtrip(
            timestamp in any::<u64>(),
            revoked_bytes in proptest::array::uniform32(any::<u8>()),
        ) {
            let (revoker_sk, revoker_vk) = make_keypair();
            let rv = seal_device_authorization_revocation(
                revoked_bytes,
                revoker_vk,
                timestamp,
                sign_with(&revoker_sk),
            ).unwrap();
            let bytes = rv.encode();
            prop_assert_eq!(bytes.len(), DEVICE_AUTH_REVOKE_LEN);
            let decoded = DeviceAuthorizationRevocation::from_bytes(&bytes).unwrap();
            prop_assert_eq!(&rv, &decoded);
            decoded.verify(&revoker_vk).unwrap();
        }

        #[test]
        fn proptest_request_tamper_any_canonical_byte_breaks_verify(
            byte_index in 0usize..(DEVICE_AUTH_REQUEST_BASE_LEN + 7),
        ) {
            let (identity_sk, identity_vk) = make_keypair();
            let (_device_sk, device_vk) = make_keypair();
            let req = seal_device_authorization_request(
                device_vk,
                1_700_000_000_000u64,
                [0xAAu8; CHALLENGE_NONCE_LEN],
                "Unknown",
                sign_with(&identity_sk),
            ).unwrap();
            let mut bytes = req.encode();
            // Wire-length = 138 (base) + 7 ("Unknown") = 145. Flipping any byte in
            // this region either (a) corrupts wire-format (parse fails), (b) corrupts
            // canonical-covered bytes (parse ok, verify fails), or (c) corrupts the
            // trailing signature (parse ok, verify fails). In all cases no bit-flip
            // produces an equivalent valid record.
            bytes[byte_index] ^= 1;
            if let Ok(parsed) = DeviceAuthorizationRequest::from_bytes(&bytes) {
                if parsed == req {
                    // Extremely unlikely but not impossible — degenerate case, skip.
                    return Ok(());
                }
                prop_assert!(parsed.verify(&identity_vk).is_err());
            }
        }

        #[test]
        fn proptest_approval_tamper_any_byte_breaks_verify(
            byte_index in 0usize..DEVICE_AUTH_APPROVAL_LEN,
        ) {
            let (approver_sk, approver_vk) = make_keypair();
            let (_new_sk, new_vk) = make_keypair();
            let ap = seal_device_authorization_approval(
                new_vk,
                approver_vk,
                1_700_000_000_000u64,
                0,
                0,
                sign_with(&approver_sk),
            ).unwrap();
            let mut bytes = ap.encode();
            bytes[byte_index] ^= 1;
            // Parse may or may not succeed — if succeeds, verify MUST fail.
            if let Ok(parsed) = DeviceAuthorizationApproval::from_bytes(&bytes) {
                if parsed == ap {
                    // Bit-flip accidentally landed in padding/unused space — skip.
                    return Ok(());
                }
                prop_assert!(parsed.verify(&approver_vk).is_err());
            }
        }

        #[test]
        fn proptest_revocation_tamper_any_byte_breaks_verify(
            byte_index in 0usize..DEVICE_AUTH_REVOKE_LEN,
        ) {
            let (revoker_sk, revoker_vk) = make_keypair();
            let (_revoked_sk, revoked_vk) = make_keypair();
            let rv = seal_device_authorization_revocation(
                revoked_vk,
                revoker_vk,
                1_700_000_000_000u64,
                sign_with(&revoker_sk),
            ).unwrap();
            let mut bytes = rv.encode();
            bytes[byte_index] ^= 1;
            if let Ok(parsed) = DeviceAuthorizationRevocation::from_bytes(&bytes) {
                if parsed == rv {
                    return Ok(());
                }
                prop_assert!(parsed.verify(&revoker_vk).is_err());
            }
        }

        #[test]
        fn proptest_from_bytes_never_panics_request(
            data in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            let _ = DeviceAuthorizationRequest::from_bytes(&data);
        }

        #[test]
        fn proptest_from_bytes_never_panics_approval(
            data in proptest::collection::vec(any::<u8>(), 0..200),
        ) {
            let _ = DeviceAuthorizationApproval::from_bytes(&data);
        }

        #[test]
        fn proptest_from_bytes_never_panics_revocation(
            data in proptest::collection::vec(any::<u8>(), 0..200),
        ) {
            let _ = DeviceAuthorizationRevocation::from_bytes(&data);
        }
    }
}
