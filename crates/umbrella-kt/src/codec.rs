//! Wire-format codec для типов `umbrella-kt` (на текущий момент —
//! [`SignedEpochRoot`]). Слой выше `Http2KtTransport` возвращает raw bytes
//! `Vec<u8>` от `kt-svc`; helpers facade (`verify_kt_witness_signatures_*`)
//! десериализуют их через [`decode_signed_epoch_root`] и валидируют через
//! `umbrella_kt::witness::verify_signed_epoch`.
//!
//! ## Wire format `SignedEpochRoot` (deterministic, fixed-layout)
//!
//! ```text
//! offset  length  field
//! ------  ------  -----
//! 0       1       version (`SIGNED_EPOCH_ROOT_WIRE_VERSION = 0x01`)
//! 1       8       epoch                 (u64 big-endian)
//! 9       32      root                  ([u8; NODE_HASH_LEN])
//! 41      8       log_size              (u64 big-endian)
//! 49      8       timestamp_unix_millis (u64 big-endian)
//! 57      1       signature_count       (u8, 0..=MAX_WITNESSES_PER_EPOCH=5)
//! 58      N × 96  signatures            (each = 32-byte witness_pubkey || 64-byte Ed25519 signature)
//! ```
//!
//! Header = 58 bytes. Per-signature payload = 32 + 64 = 96 bytes. Max wire
//! size (5 signatures) = 58 + 5 × 96 = 538 bytes. Zero signatures = 58 bytes
//! exactly. Wire format **не включает** `WITNESS_DOMAIN_SEP` — domain
//! separator живёт только внутри `canonical_sign_payload` (input для Ed25519
//! sign / verify), не на проводе.
//!
//! Wire-format codec for `umbrella-kt` types (currently `SignedEpochRoot`).
//! `Http2KtTransport` returns raw `Vec<u8>` from `kt-svc`; facade helpers
//! deserialise via `decode_signed_epoch_root` and validate via
//! `umbrella_kt::witness::verify_signed_epoch`.
//!
//! ## Wire format `SignedEpochRoot`
//!
//! Deterministic fixed-layout: version (1) || epoch_BE (8) || root (32) ||
//! log_size_BE (8) || timestamp_BE (8) || sig_count (1) || N × {pubkey (32) ||
//! signature (64)}. Header = 58 bytes, max wire (5 sigs) = 538 bytes.
//!
//! ## Defence-in-depth (постулат 14 fail-closed)
//!
//! `decode_signed_epoch_root` strict-rejects (returns
//! [`KtError::InvalidSignedEpochRootWire`]) any of:
//!
//! - input shorter than the 58-byte header (`"too_short"`);
//! - leading version byte ≠ `0x01` (`"unknown_version"`);
//! - `signature_count > MAX_WITNESSES_PER_EPOCH` (`"too_many_signatures"`);
//! - total length less than `58 + signature_count * 96` (`"truncated_signatures"`);
//! - any trailing bytes after the last signature (`"trailing_bytes"`).
//!
//! Strict rejection of trailing bytes blocks server-side smuggling of extra
//! payload past the documented field set — a passive adversary cannot append
//! out-of-band data that legitimate decoders would tolerate.

use crate::error::{KtError, Result};
use crate::merkle::NODE_HASH_LEN;
use crate::witness::{SignedEpochRoot, WitnessPublic, WitnessSignature};

use umbrella_crypto_primitives::sig::{PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// Версия wire-format `SignedEpochRoot`. Wire-format version byte.
pub const SIGNED_EPOCH_ROOT_WIRE_VERSION: u8 = 0x01;

/// SPEC-09 §6 invariant: не более 5 witness-подписей на эпоху.
/// SPEC-09 §6 invariant: at most 5 witness signatures per epoch.
pub const MAX_WITNESSES_PER_EPOCH: usize = 5;

/// Размер одной witness-signature на проводе: 32 + 64 = 96 байт.
/// On-wire size of one witness signature: 32 + 64 = 96 bytes.
pub const SIGNATURE_WIRE_LEN: usize = PUBLIC_KEY_LEN + SIGNATURE_LEN;

/// Размер header'а wire-format: 1 + 8 + 32 + 8 + 8 + 1 = 58 байт.
/// Wire-format header size: 1 + 8 + 32 + 8 + 8 + 1 = 58 bytes.
pub const SIGNED_EPOCH_ROOT_HEADER_LEN: usize = 1 + 8 + NODE_HASH_LEN + 8 + 8 + 1;

/// Размер wire-format при `signature_count` подписях.
/// Wire-format size for `signature_count` signatures.
#[must_use]
pub const fn signed_epoch_root_wire_len(signature_count: usize) -> usize {
    SIGNED_EPOCH_ROOT_HEADER_LEN + signature_count * SIGNATURE_WIRE_LEN
}

/// Serialise [`SignedEpochRoot`] в wire bytes (deterministic).
///
/// # Errors
///
/// - [`KtError::InvalidSignedEpochRootWire`] с tag `"too_many_signatures"`
///   если `signed.signatures.len() > MAX_WITNESSES_PER_EPOCH` (encoder
///   refuses to emit a frame the strict decoder would reject).
///
/// # Determinism
///
/// Деtermimistic byte-by-byte: same input → same output (no randomness, no
/// allocator dependency на content). Order of `signed.signatures` preserved
/// — Ed25519 signature verification is order-independent
/// ([`verify_signed_epoch`](crate::witness::verify_signed_epoch) dedupes by
/// witness pubkey), но кодек преданно zeros не вставляет.
pub fn encode_signed_epoch_root(signed: &SignedEpochRoot) -> Result<Vec<u8>> {
    if signed.signatures.len() > MAX_WITNESSES_PER_EPOCH {
        return Err(KtError::InvalidSignedEpochRootWire("too_many_signatures"));
    }

    let mut out = Vec::with_capacity(signed_epoch_root_wire_len(signed.signatures.len()));
    out.push(SIGNED_EPOCH_ROOT_WIRE_VERSION);
    out.extend_from_slice(&signed.epoch.to_be_bytes());
    out.extend_from_slice(&signed.root);
    out.extend_from_slice(&signed.log_size.to_be_bytes());
    out.extend_from_slice(&signed.timestamp_unix_millis.to_be_bytes());
    // Safe cast: bounded by MAX_WITNESSES_PER_EPOCH=5 < u8::MAX.
    out.push(signed.signatures.len() as u8);
    for sig in &signed.signatures {
        out.extend_from_slice(&sig.witness.to_bytes());
        out.extend_from_slice(&sig.signature);
    }
    debug_assert_eq!(
        out.len(),
        signed_epoch_root_wire_len(signed.signatures.len())
    );
    Ok(out)
}

/// Deserialise [`SignedEpochRoot`] из wire bytes (strict).
///
/// Любая нестандартная конфигурация — `Err(InvalidSignedEpochRootWire)` с
/// stable string tag. Это soft-fail в смысле «caller получает structured
/// reason», а не panic — но фактически передаётся как KT error к facade и
/// далее как `ClientError::Kt(...)` к caller (постулат 14).
///
/// # Errors
///
/// - [`KtError::InvalidSignedEpochRootWire`] с одним из тэгов:
///   - `"too_short"` — input короче 58-байт header'а.
///   - `"unknown_version"` — leading byte ≠ `0x01`.
///   - `"too_many_signatures"` — `signature_count > MAX_WITNESSES_PER_EPOCH`.
///   - `"truncated_signatures"` — длина < `58 + signature_count * 96`.
///   - `"trailing_bytes"` — длина > `58 + signature_count * 96`.
pub fn decode_signed_epoch_root(bytes: &[u8]) -> Result<SignedEpochRoot> {
    if bytes.len() < SIGNED_EPOCH_ROOT_HEADER_LEN {
        return Err(KtError::InvalidSignedEpochRootWire("too_short"));
    }
    if bytes[0] != SIGNED_EPOCH_ROOT_WIRE_VERSION {
        return Err(KtError::InvalidSignedEpochRootWire("unknown_version"));
    }

    // Header parse — все слайсы внутри [0, 58) гарантированно длины header.
    // Header parse — all slices within [0, 58) are guaranteed header-length.
    let mut cursor = 1usize;

    let epoch = u64::from_be_bytes(
        bytes[cursor..cursor + 8]
            .try_into()
            .map_err(|_| KtError::InvalidSignedEpochRootWire("header_slice_len"))?,
    );
    cursor += 8;

    let mut root = [0u8; NODE_HASH_LEN];
    root.copy_from_slice(&bytes[cursor..cursor + NODE_HASH_LEN]);
    cursor += NODE_HASH_LEN;

    let log_size = u64::from_be_bytes(
        bytes[cursor..cursor + 8]
            .try_into()
            .map_err(|_| KtError::InvalidSignedEpochRootWire("header_slice_len"))?,
    );
    cursor += 8;

    let timestamp_unix_millis = u64::from_be_bytes(
        bytes[cursor..cursor + 8]
            .try_into()
            .map_err(|_| KtError::InvalidSignedEpochRootWire("header_slice_len"))?,
    );
    cursor += 8;

    let signature_count = bytes[cursor] as usize;
    cursor += 1;
    debug_assert_eq!(cursor, SIGNED_EPOCH_ROOT_HEADER_LEN);

    if signature_count > MAX_WITNESSES_PER_EPOCH {
        return Err(KtError::InvalidSignedEpochRootWire("too_many_signatures"));
    }

    let expected_len = signed_epoch_root_wire_len(signature_count);
    if bytes.len() < expected_len {
        return Err(KtError::InvalidSignedEpochRootWire("truncated_signatures"));
    }
    if bytes.len() > expected_len {
        return Err(KtError::InvalidSignedEpochRootWire("trailing_bytes"));
    }

    let mut signatures = Vec::with_capacity(signature_count);
    for _ in 0..signature_count {
        let mut pk_bytes = [0u8; PUBLIC_KEY_LEN];
        pk_bytes.copy_from_slice(&bytes[cursor..cursor + PUBLIC_KEY_LEN]);
        cursor += PUBLIC_KEY_LEN;
        let mut sig_bytes = [0u8; SIGNATURE_LEN];
        sig_bytes.copy_from_slice(&bytes[cursor..cursor + SIGNATURE_LEN]);
        cursor += SIGNATURE_LEN;
        signatures.push(WitnessSignature {
            witness: WitnessPublic::from_bytes(pk_bytes),
            signature: sig_bytes,
        });
    }
    debug_assert_eq!(cursor, bytes.len());

    Ok(SignedEpochRoot {
        epoch,
        root,
        log_size,
        timestamp_unix_millis,
        signatures,
    })
}

// ============================================================================
// KT authorization-entry framing — IdentityRotation (ADR-008 EntryType 0x06)
// ============================================================================
//
// Wire layout (235 bytes, fixed):
//   1 byte    : EntryType prefix = 0x06 (IdentityRotationRecord)
//   234 bytes : IdentityRotationRecord::encode() body
//
// Body sub-layout (see umbrella_backup::cloud_wrap::identity_rotation):
//   1 byte    : version (AUTHORIZATION_WIRE_VERSION = 0x01)
//   32 bytes  : old_identity_pubkey (Ed25519)
//   32 bytes  : new_identity_pubkey (Ed25519)
//   8 bytes   : rotation_timestamp_u64_be
//   1 byte    : rotation_reason tag (0x01 / 0x02 / 0x03)
//   64 bytes  : old_identity_signature
//   64 bytes  : new_identity_signature
//   32 bytes  : code_recovery_public_half_proof (F-PHD-RETRO-3-E)
//
// Body verify (signatures + identical-pubkey rejection) lives in
// `IdentityRotationRecord::verify()`; the strict wire decoder here only
// guarantees structural / framing correctness. Cryptographic verification
// is a layer above (apply_identity_rotation в umbrella-kt::authorization_entries).

use umbrella_backup::cloud_wrap::{
    DeviceAuthorizationApproval, DeviceAuthorizationRevocation, IdentityRotationRecord,
    DEVICE_AUTH_APPROVAL_LEN, DEVICE_AUTH_REVOKE_LEN, IDENTITY_ROTATION_LEN,
};

use crate::authorization_entries::EntryType;

/// EntryType prefix byte для wire-framed KT entry, содержащей
/// `DeviceAuthorizationApproval` (ADR-008 §EntryType `0x04`).
///
/// EntryType prefix byte for the wire-framed KT entry carrying a
/// `DeviceAuthorizationApproval` (ADR-008 EntryType `0x04`).
pub const KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_PREFIX: u8 = 0x04;

/// Размер wire-format KT entry с `DeviceAuthorizationApproval` (1 byte prefix +
/// 146 bytes record = 147 bytes, fixed).
///
/// Wire-format size of a KT entry carrying a `DeviceAuthorizationApproval`
/// (1 byte prefix + 146 bytes record = 147 bytes, fixed).
pub const KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_WIRE_LEN: usize = 1 + DEVICE_AUTH_APPROVAL_LEN;

/// EntryType prefix byte для wire-framed KT entry, содержащей
/// `DeviceAuthorizationRevocation` (ADR-008 §EntryType `0x05`).
///
/// EntryType prefix byte for the wire-framed KT entry carrying a
/// `DeviceAuthorizationRevocation` (ADR-008 EntryType `0x05`).
pub const KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_PREFIX: u8 = 0x05;

/// Размер wire-format KT entry с `DeviceAuthorizationRevocation` (1 byte
/// prefix + 137 bytes record = 138 bytes, fixed).
///
/// Wire-format size of a KT entry carrying a `DeviceAuthorizationRevocation`
/// (1 byte prefix + 137 bytes record = 138 bytes, fixed).
pub const KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_WIRE_LEN: usize = 1 + DEVICE_AUTH_REVOKE_LEN;

/// EntryType prefix byte для wire-framed KT entry, содержащей
/// `IdentityRotationRecord` (ADR-008 §EntryType `0x06`).
///
/// EntryType prefix byte for the wire-framed KT entry carrying an
/// `IdentityRotationRecord` (ADR-008 EntryType `0x06`).
pub const KT_ENTRY_IDENTITY_ROTATION_PREFIX: u8 = 0x06;

/// Размер wire-format KT entry с `IdentityRotationRecord` (1 byte prefix +
/// 234 bytes record = 235 bytes, fixed).
///
/// Wire-format size of a KT entry carrying an `IdentityRotationRecord`
/// (1 byte prefix + 234 bytes record = 235 bytes, fixed).
pub const KT_ENTRY_IDENTITY_ROTATION_WIRE_LEN: usize = 1 + IDENTITY_ROTATION_LEN;

/// Wire-encode `IdentityRotationRecord` как KT entry с `0x06` префиксом.
/// Возвращает ровно 235 байт (deterministic, fixed-length).
///
/// # Determinism
///
/// Same input → same bytes. Никакой randomness, никакого аллокатор-зависимого
/// порядка полей. Длина гарантированно равна
/// [`KT_ENTRY_IDENTITY_ROTATION_WIRE_LEN`].
///
/// Wire-encode `IdentityRotationRecord` as a KT entry with a `0x06` prefix.
/// Returns exactly 235 bytes, deterministic.
#[must_use]
pub fn encode_kt_entry_identity_rotation(record: &IdentityRotationRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(KT_ENTRY_IDENTITY_ROTATION_WIRE_LEN);
    out.push(KT_ENTRY_IDENTITY_ROTATION_PREFIX);
    out.extend_from_slice(&record.encode());
    debug_assert_eq!(out.len(), KT_ENTRY_IDENTITY_ROTATION_WIRE_LEN);
    debug_assert_eq!(
        EntryType::IdentityRotationRecord as u8,
        KT_ENTRY_IDENTITY_ROTATION_PREFIX,
        "prefix const must match EntryType::IdentityRotationRecord tag"
    );
    out
}

/// Wire-decode `IdentityRotationRecord` из KT entry bytes с `0x06` префиксом.
/// Strict — отвергает любую malformed конфигурацию.
///
/// Defence-in-depth (постулат 14):
/// - input короче 1 байта → `"too_short"`
/// - первый байт ≠ `0x06` → `"wrong_prefix"` (KT entry содержит другой
///   EntryType либо corruption)
/// - длина ≠ 235 → `"wrong_length"` (truncated либо trailing bytes)
/// - body decode failure (identical pubkeys, unknown reason, version != 0x01,
///   и т.д.) — propagates через granular tag
///
/// # Errors
///
/// - [`KtError::InvalidAuthorizationEntryWire`] с одним из тэгов:
///   - `"too_short"` — input пустой.
///   - `"wrong_prefix"` — первый байт ≠ `KT_ENTRY_IDENTITY_ROTATION_PREFIX`.
///   - `"wrong_length"` — `bytes.len() != KT_ENTRY_IDENTITY_ROTATION_WIRE_LEN`.
///   - `"record_invalid_wire_format"` — body decode failed (identical
///     pubkeys, unknown reason tag, и т.д.).
///   - `"record_unknown_wire_version"` — body's leading version byte ≠ 0x01.
pub fn decode_kt_entry_identity_rotation(bytes: &[u8]) -> Result<IdentityRotationRecord> {
    use umbrella_backup::BackupError;

    if bytes.is_empty() {
        return Err(KtError::InvalidAuthorizationEntryWire("too_short"));
    }
    if bytes[0] != KT_ENTRY_IDENTITY_ROTATION_PREFIX {
        return Err(KtError::InvalidAuthorizationEntryWire("wrong_prefix"));
    }
    if bytes.len() != KT_ENTRY_IDENTITY_ROTATION_WIRE_LEN {
        return Err(KtError::InvalidAuthorizationEntryWire("wrong_length"));
    }
    IdentityRotationRecord::from_bytes(&bytes[1..]).map_err(|e| match e {
        BackupError::WrappedKeyVersionMismatch { .. } => {
            KtError::InvalidAuthorizationEntryWire("record_unknown_wire_version")
        }
        _ => KtError::InvalidAuthorizationEntryWire("record_invalid_wire_format"),
    })
}

// ============================================================================
// KT authorization-entry framing — DeviceAuthorizationApproval (0x04)
// ============================================================================
//
// Wire layout (147 bytes, fixed):
//   1 byte    : EntryType prefix = 0x04 (DeviceAuthorizationApproval)
//   146 bytes : DeviceAuthorizationApproval::encode() body
//
// Body sub-layout (см. umbrella_backup::cloud_wrap::authorization):
//   1 byte    : version (AUTHORIZATION_WIRE_VERSION = 0x01)
//   32 bytes  : new_device_pubkey (Ed25519)
//   32 bytes  : approver_device_pubkey (Ed25519)
//   8 bytes   : authorized_since_timestamp_u64_be
//   8 bytes   : history_cutoff_timestamp_u64_be (0 = full history)
//   1 byte    : policy_flags (bit 0 = high-security; bits 1..7 reserved)
//   64 bytes  : approver_signature

/// Wire-encode `DeviceAuthorizationApproval` как KT entry с `0x04` префиксом.
/// Возвращает ровно 147 байт (deterministic, fixed-length).
///
/// Wire-encode `DeviceAuthorizationApproval` as a KT entry with a `0x04`
/// prefix. Returns exactly 147 bytes, deterministic.
#[must_use]
pub fn encode_kt_entry_device_authorization_approval(
    record: &DeviceAuthorizationApproval,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_WIRE_LEN);
    out.push(KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_PREFIX);
    out.extend_from_slice(&record.encode());
    debug_assert_eq!(out.len(), KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_WIRE_LEN);
    debug_assert_eq!(
        EntryType::DeviceAuthorizationApproval as u8,
        KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_PREFIX,
        "prefix const must match EntryType::DeviceAuthorizationApproval tag"
    );
    out
}

/// Wire-decode `DeviceAuthorizationApproval` из KT entry bytes с `0x04`
/// префиксом. Strict — отвергает любую malformed конфигурацию.
///
/// # Errors
///
/// - [`KtError::InvalidAuthorizationEntryWire`] с теми же tags что и для
///   `decode_kt_entry_identity_rotation` (symmetric error model).
pub fn decode_kt_entry_device_authorization_approval(
    bytes: &[u8],
) -> Result<DeviceAuthorizationApproval> {
    use umbrella_backup::BackupError;

    if bytes.is_empty() {
        return Err(KtError::InvalidAuthorizationEntryWire("too_short"));
    }
    if bytes[0] != KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_PREFIX {
        return Err(KtError::InvalidAuthorizationEntryWire("wrong_prefix"));
    }
    if bytes.len() != KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_WIRE_LEN {
        return Err(KtError::InvalidAuthorizationEntryWire("wrong_length"));
    }
    DeviceAuthorizationApproval::from_bytes(&bytes[1..]).map_err(|e| match e {
        BackupError::WrappedKeyVersionMismatch { .. } => {
            KtError::InvalidAuthorizationEntryWire("record_unknown_wire_version")
        }
        _ => KtError::InvalidAuthorizationEntryWire("record_invalid_wire_format"),
    })
}

// ============================================================================
// KT authorization-entry framing — DeviceAuthorizationRevocation (0x05)
// ============================================================================
//
// Wire layout (138 bytes, fixed):
//   1 byte    : EntryType prefix = 0x05 (DeviceAuthorizationRevocation)
//   137 bytes : DeviceAuthorizationRevocation::encode() body
//
// Body sub-layout (см. umbrella_backup::cloud_wrap::authorization):
//   1 byte    : version (AUTHORIZATION_WIRE_VERSION = 0x01)
//   32 bytes  : revoked_device_pubkey (Ed25519)
//   32 bytes  : revoker_device_pubkey (Ed25519)
//   8 bytes   : revocation_timestamp_u64_be
//   64 bytes  : revoker_signature

/// Wire-encode `DeviceAuthorizationRevocation` как KT entry с `0x05`
/// префиксом. Возвращает ровно 138 байт (deterministic, fixed-length).
///
/// Wire-encode `DeviceAuthorizationRevocation` as a KT entry with a `0x05`
/// prefix. Returns exactly 138 bytes, deterministic.
#[must_use]
pub fn encode_kt_entry_device_authorization_revocation(
    record: &DeviceAuthorizationRevocation,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_WIRE_LEN);
    out.push(KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_PREFIX);
    out.extend_from_slice(&record.encode());
    debug_assert_eq!(out.len(), KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_WIRE_LEN);
    debug_assert_eq!(
        EntryType::DeviceAuthorizationRevocation as u8,
        KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_PREFIX,
        "prefix const must match EntryType::DeviceAuthorizationRevocation tag"
    );
    out
}

/// Wire-decode `DeviceAuthorizationRevocation` из KT entry bytes с `0x05`
/// префиксом. Strict — отвергает любую malformed конфигурацию.
///
/// # Errors
///
/// - [`KtError::InvalidAuthorizationEntryWire`] с теми же tags что и для
///   `decode_kt_entry_identity_rotation` (symmetric error model).
pub fn decode_kt_entry_device_authorization_revocation(
    bytes: &[u8],
) -> Result<DeviceAuthorizationRevocation> {
    use umbrella_backup::BackupError;

    if bytes.is_empty() {
        return Err(KtError::InvalidAuthorizationEntryWire("too_short"));
    }
    if bytes[0] != KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_PREFIX {
        return Err(KtError::InvalidAuthorizationEntryWire("wrong_prefix"));
    }
    if bytes.len() != KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_WIRE_LEN {
        return Err(KtError::InvalidAuthorizationEntryWire("wrong_length"));
    }
    DeviceAuthorizationRevocation::from_bytes(&bytes[1..]).map_err(|e| match e {
        BackupError::WrappedKeyVersionMismatch { .. } => {
            KtError::InvalidAuthorizationEntryWire("record_unknown_wire_version")
        }
        _ => KtError::InvalidAuthorizationEntryWire("record_invalid_wire_format"),
    })
}

// ============================================================================
// KT authorization-entry dispatcher — tag-routed decoding
// ============================================================================

/// Один из трёх ADR-008 wire-framed authorization-entry типов. Возвращается
/// dispatcher'ом [`decode_kt_authorization_entry`], который routes по первому
/// байту wire format'а.
///
/// One of the three ADR-008 wire-framed authorization-entry types. Returned
/// by the dispatcher [`decode_kt_authorization_entry`], which routes by the
/// first wire-format byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KtAuthorizationEntry {
    /// EntryType `0x04` — `DeviceAuthorizationApproval`.
    Approval(DeviceAuthorizationApproval),
    /// EntryType `0x05` — `DeviceAuthorizationRevocation`.
    Revocation(DeviceAuthorizationRevocation),
    /// EntryType `0x06` — `IdentityRotationRecord`.
    IdentityRotation(IdentityRotationRecord),
}

impl KtAuthorizationEntry {
    /// Возвращает соответствующий [`EntryType`] для текущего variant'а
    /// (i.e. `0x04`, `0x05`, либо `0x06` per ADR-008).
    ///
    /// Returns the corresponding [`EntryType`] for the current variant (i.e.
    /// `0x04`, `0x05`, or `0x06` per ADR-008).
    #[must_use]
    pub const fn entry_type(&self) -> EntryType {
        match self {
            Self::Approval(_) => EntryType::DeviceAuthorizationApproval,
            Self::Revocation(_) => EntryType::DeviceAuthorizationRevocation,
            Self::IdentityRotation(_) => EntryType::IdentityRotationRecord,
        }
    }
}

/// Высокоуровневый dispatcher: parse'ит wire-bytes и route'ит к
/// соответствующему per-type decoder'у на основе первого байта (EntryType
/// prefix). Возвращает [`KtAuthorizationEntry`] enum carrying decoded record.
///
/// **Defence-in-depth ordering**: empty input → `too_short` ДО prefix
/// dispatch'а; unknown prefix → `wrong_prefix`. Malformed body внутри
/// одного из known prefix'ов → tag из per-type decoder'а
/// (record_invalid_wire_format / record_unknown_wire_version / wrong_length).
///
/// High-level dispatcher: parses wire bytes and routes to the per-type
/// decoder based on the first byte (EntryType prefix). Returns a
/// [`KtAuthorizationEntry`] enum carrying the decoded record.
///
/// # Errors
///
/// - `KtError::InvalidAuthorizationEntryWire("too_short")` для empty input.
/// - `KtError::InvalidAuthorizationEntryWire("wrong_prefix")` для `byte[0]`
///   ∉ {0x04, 0x05, 0x06}.
/// - Per-type decoder errors propagate через `wrong_length` /
///   `record_invalid_wire_format` / `record_unknown_wire_version`.
pub fn decode_kt_authorization_entry(bytes: &[u8]) -> Result<KtAuthorizationEntry> {
    if bytes.is_empty() {
        return Err(KtError::InvalidAuthorizationEntryWire("too_short"));
    }
    match bytes[0] {
        KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_PREFIX => {
            decode_kt_entry_device_authorization_approval(bytes).map(KtAuthorizationEntry::Approval)
        }
        KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_PREFIX => {
            decode_kt_entry_device_authorization_revocation(bytes)
                .map(KtAuthorizationEntry::Revocation)
        }
        KT_ENTRY_IDENTITY_ROTATION_PREFIX => {
            decode_kt_entry_identity_rotation(bytes).map(KtAuthorizationEntry::IdentityRotation)
        }
        _ => Err(KtError::InvalidAuthorizationEntryWire("wrong_prefix")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::canonical_sign_payload;
    use rand_core::OsRng;
    use umbrella_crypto_primitives::sig::PrivateSigningKey;

    // ========================================================================
    // Test helpers
    // ========================================================================

    struct TestWitness {
        sk: PrivateSigningKey,
        pk: WitnessPublic,
    }

    fn fresh_witness() -> TestWitness {
        let sk = PrivateSigningKey::generate(&mut OsRng);
        let pk = WitnessPublic::from_bytes(sk.verifying_key().to_bytes());
        TestWitness { sk, pk }
    }

    fn sign_for(
        witness: &TestWitness,
        epoch: u64,
        root: &[u8; NODE_HASH_LEN],
        log_size: u64,
        ts_ms: u64,
    ) -> WitnessSignature {
        let payload = canonical_sign_payload(epoch, root, log_size, ts_ms);
        let sig = witness.sk.sign(&payload);
        WitnessSignature {
            witness: witness.pk,
            signature: sig.to_bytes(),
        }
    }

    fn fresh_signed_root(num_signatures: usize) -> SignedEpochRoot {
        let epoch = 42u64;
        let root: [u8; NODE_HASH_LEN] = [0xCD; NODE_HASH_LEN];
        let log_size = 1_000_000u64;
        let ts_ms = 1_715_000_000_000u64;
        let signatures: Vec<WitnessSignature> = (0..num_signatures)
            .map(|_| {
                let w = fresh_witness();
                sign_for(&w, epoch, &root, log_size, ts_ms)
            })
            .collect();
        SignedEpochRoot {
            epoch,
            root,
            log_size,
            timestamp_unix_millis: ts_ms,
            signatures,
        }
    }

    // ========================================================================
    // Constants invariants
    // ========================================================================

    #[test]
    fn header_constants_match_layout_documentation() {
        // 1 (version) + 8 (epoch) + 32 (root) + 8 (log_size) + 8 (timestamp) + 1 (sig_count) = 58
        assert_eq!(SIGNED_EPOCH_ROOT_HEADER_LEN, 58);
        assert_eq!(SIGNATURE_WIRE_LEN, 32 + 64);
        assert_eq!(SIGNATURE_WIRE_LEN, 96);
        assert_eq!(signed_epoch_root_wire_len(0), 58);
        assert_eq!(signed_epoch_root_wire_len(3), 58 + 3 * 96);
        assert_eq!(signed_epoch_root_wire_len(5), 58 + 5 * 96);
        assert_eq!(signed_epoch_root_wire_len(5), 538);
    }

    // ========================================================================
    // Round-trip preservation
    // ========================================================================

    #[test]
    fn encode_then_decode_round_trip_preserves_all_fields_with_five_signatures() {
        let original = fresh_signed_root(5);
        let bytes = encode_signed_epoch_root(&original).expect("encode 5 sigs");
        assert_eq!(bytes.len(), signed_epoch_root_wire_len(5));
        let decoded = decode_signed_epoch_root(&bytes).expect("decode 5 sigs");
        assert_eq!(decoded, original);
    }

    #[test]
    fn encode_then_decode_round_trip_preserves_all_fields_with_three_signatures() {
        let original = fresh_signed_root(3);
        let bytes = encode_signed_epoch_root(&original).expect("encode 3 sigs");
        assert_eq!(bytes.len(), signed_epoch_root_wire_len(3));
        let decoded = decode_signed_epoch_root(&bytes).expect("decode 3 sigs");
        assert_eq!(decoded, original);
    }

    #[test]
    fn encode_then_decode_round_trip_with_zero_signatures_produces_header_only_bytes() {
        let original = SignedEpochRoot {
            epoch: 0xDEAD_BEEF_CAFE_F00Du64,
            root: [0xAB; NODE_HASH_LEN],
            log_size: u64::MAX,
            timestamp_unix_millis: 1u64,
            signatures: vec![],
        };
        let bytes = encode_signed_epoch_root(&original).expect("encode 0 sigs");
        assert_eq!(bytes.len(), SIGNED_EPOCH_ROOT_HEADER_LEN);
        let decoded = decode_signed_epoch_root(&bytes).expect("decode 0 sigs");
        assert_eq!(decoded, original);
        assert!(decoded.signatures.is_empty());
    }

    #[test]
    fn encode_produces_deterministic_output_for_same_input() {
        let signed = fresh_signed_root(3);
        let a = encode_signed_epoch_root(&signed).expect("encode A");
        let b = encode_signed_epoch_root(&signed).expect("encode B");
        assert_eq!(
            a, b,
            "encoder MUST be byte-deterministic given identical input"
        );
    }

    #[test]
    fn decode_preserves_signature_order_under_round_trip() {
        let signed = fresh_signed_root(5);
        let pk_order_before: Vec<WitnessPublic> =
            signed.signatures.iter().map(|s| s.witness).collect();
        let bytes = encode_signed_epoch_root(&signed).expect("encode");
        let decoded = decode_signed_epoch_root(&bytes).expect("decode");
        let pk_order_after: Vec<WitnessPublic> =
            decoded.signatures.iter().map(|s| s.witness).collect();
        assert_eq!(
            pk_order_before, pk_order_after,
            "decoder MUST preserve insertion order of signatures"
        );
    }

    // ========================================================================
    // Wire-level reproducibility — explicit byte layout
    // ========================================================================

    #[test]
    fn encode_wire_layout_zero_signatures_explicit_bytes() {
        // Explicit byte-by-byte layout pin for header-only frame. Locks the
        // exact wire format so accidental field-order swap или endianness
        // regressions trip this test.
        let signed = SignedEpochRoot {
            epoch: 0x0102_0304_0506_0708u64,
            root: {
                let mut r = [0u8; NODE_HASH_LEN];
                for (i, b) in r.iter_mut().enumerate() {
                    *b = i as u8;
                }
                r
            },
            log_size: 0x1011_1213_1415_1617u64,
            timestamp_unix_millis: 0x2021_2223_2425_2627u64,
            signatures: vec![],
        };
        let bytes = encode_signed_epoch_root(&signed).expect("encode");
        let mut expected = Vec::with_capacity(58);
        expected.push(0x01); // version
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // epoch BE
        for i in 0..32u8 {
            expected.push(i);
        } // root 0..31
        expected.extend_from_slice(&[0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]); // log_size BE
        expected.extend_from_slice(&[0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27]); // timestamp BE
        expected.push(0x00); // signature_count = 0
        assert_eq!(bytes, expected);
    }

    // ========================================================================
    // Strict rejection — too_short
    // ========================================================================

    #[test]
    fn decode_rejects_empty_input_with_too_short_tag() {
        let err = decode_signed_epoch_root(&[]).expect_err("empty input must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("too_short")
        ));
    }

    #[test]
    fn decode_rejects_input_one_byte_below_header_length() {
        let signed = fresh_signed_root(0);
        let mut bytes = encode_signed_epoch_root(&signed).expect("encode");
        bytes.pop(); // 57 bytes — one byte short of header
        assert_eq!(bytes.len(), SIGNED_EPOCH_ROOT_HEADER_LEN - 1);
        let err = decode_signed_epoch_root(&bytes).expect_err("57-byte input must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("too_short")
        ));
    }

    #[test]
    fn decode_rejects_truncation_at_every_header_field_boundary() {
        // Take a header-only frame (58 bytes) and truncate at every length
        // in [0, 58) — each MUST be rejected with too_short. Boundary 58
        // is the minimum valid (zero-signature) frame which passes.
        let signed = fresh_signed_root(0);
        let full = encode_signed_epoch_root(&signed).expect("encode");
        assert_eq!(full.len(), 58);
        for truncate_at in 0..SIGNED_EPOCH_ROOT_HEADER_LEN {
            let truncated = &full[..truncate_at];
            match decode_signed_epoch_root(truncated) {
                Err(KtError::InvalidSignedEpochRootWire("too_short")) => {}
                other => panic!("truncate_at={truncate_at} expected too_short, got {other:?}"),
            }
        }
    }

    // ========================================================================
    // Strict rejection — unknown_version
    // ========================================================================

    #[test]
    fn decode_rejects_unknown_version_byte_0x00() {
        let signed = fresh_signed_root(0);
        let mut bytes = encode_signed_epoch_root(&signed).expect("encode");
        bytes[0] = 0x00;
        let err = decode_signed_epoch_root(&bytes).expect_err("version 0x00 must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("unknown_version")
        ));
    }

    #[test]
    fn decode_rejects_unknown_version_byte_0x02() {
        let signed = fresh_signed_root(0);
        let mut bytes = encode_signed_epoch_root(&signed).expect("encode");
        bytes[0] = 0x02;
        let err = decode_signed_epoch_root(&bytes).expect_err("version 0x02 must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("unknown_version")
        ));
    }

    #[test]
    fn decode_rejects_every_non_0x01_version_byte() {
        // Exhaustive enumeration of all 255 unknown version bytes.
        let signed = fresh_signed_root(0);
        let bytes_template = encode_signed_epoch_root(&signed).expect("encode");
        for bad_version in 0u8..=255u8 {
            if bad_version == SIGNED_EPOCH_ROOT_WIRE_VERSION {
                continue;
            }
            let mut bytes = bytes_template.clone();
            bytes[0] = bad_version;
            match decode_signed_epoch_root(&bytes) {
                Err(KtError::InvalidSignedEpochRootWire("unknown_version")) => {}
                other => panic!(
                    "bad_version=0x{bad_version:02x} expected unknown_version, got {other:?}"
                ),
            }
        }
    }

    // ========================================================================
    // Strict rejection — too_many_signatures
    // ========================================================================

    #[test]
    fn encode_rejects_input_with_six_signatures_via_too_many_signatures_tag() {
        // Encoder защищает adversary-controlled callers от формирования
        // frame'а который strict-decoder отверг бы — symmetry между
        // encode и decode.
        let mut signed = fresh_signed_root(5);
        let extra_witness = fresh_witness();
        let extra_sig = sign_for(
            &extra_witness,
            signed.epoch,
            &signed.root,
            signed.log_size,
            signed.timestamp_unix_millis,
        );
        signed.signatures.push(extra_sig);
        assert_eq!(signed.signatures.len(), 6);
        let err = encode_signed_epoch_root(&signed).expect_err("encode 6 sigs must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("too_many_signatures")
        ));
    }

    #[test]
    fn decode_rejects_wire_signature_count_byte_above_max_witnesses() {
        // Adversary вручную конструирует frame с signature_count=6 + 6 sigs.
        // Header parsed ok, signature_count > MAX → fail-closed before
        // attempting body parse.
        let signed = fresh_signed_root(5);
        let mut bytes = encode_signed_epoch_root(&signed).expect("encode 5");
        // Mutate signature_count byte at offset 57 to 6.
        bytes[57] = 0x06;
        // Append a fake 96-byte signature payload so length matches what
        // a non-strict decoder might expect for 6 sigs (58 + 6*96 = 634).
        bytes.extend_from_slice(&[0xFF; SIGNATURE_WIRE_LEN]);
        assert_eq!(bytes.len(), signed_epoch_root_wire_len(6));
        let err = decode_signed_epoch_root(&bytes).expect_err("count=6 must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("too_many_signatures")
        ));
    }

    #[test]
    fn decode_rejects_wire_signature_count_byte_0xff_extreme() {
        // Adversary устанавливает count=255 — should be rejected before
        // attempting allocation of 255 signatures.
        let signed = fresh_signed_root(0);
        let mut bytes = encode_signed_epoch_root(&signed).expect("encode 0");
        bytes[57] = 0xFF;
        let err = decode_signed_epoch_root(&bytes).expect_err("count=255 must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("too_many_signatures")
        ));
    }

    // ========================================================================
    // Strict rejection — truncated_signatures
    // ========================================================================

    #[test]
    fn decode_rejects_frame_where_payload_shorter_than_signature_count_implies() {
        // signature_count = 3 (header byte at 57), но в payload ровно 2
        // signatures (192 bytes after header) → expected 58 + 288 = 346,
        // actual = 58 + 192 = 250 → truncated_signatures.
        let signed_three = fresh_signed_root(3);
        let mut bytes = encode_signed_epoch_root(&signed_three).expect("encode 3");
        // Strip last 96-byte signature payload off the end (decoder sees
        // header claims 3 but only 2 signatures present).
        bytes.truncate(bytes.len() - SIGNATURE_WIRE_LEN);
        assert_eq!(
            bytes.len(),
            signed_epoch_root_wire_len(3) - SIGNATURE_WIRE_LEN
        );
        let err = decode_signed_epoch_root(&bytes).expect_err("truncated body must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("truncated_signatures")
        ));
    }

    #[test]
    fn decode_rejects_frame_truncated_one_byte_into_signature_payload() {
        // Header valid, signature_count = 1, but only 95 bytes of the 96-byte
        // signature follow — single missing byte must fail-close.
        let signed_one = fresh_signed_root(1);
        let mut bytes = encode_signed_epoch_root(&signed_one).expect("encode 1");
        bytes.pop(); // 58 + 95 = 153 bytes
        assert_eq!(bytes.len(), signed_epoch_root_wire_len(1) - 1);
        let err = decode_signed_epoch_root(&bytes).expect_err("153-byte input must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("truncated_signatures")
        ));
    }

    // ========================================================================
    // Strict rejection — trailing_bytes
    // ========================================================================

    #[test]
    fn decode_rejects_one_trailing_byte_appended_after_last_signature() {
        let signed = fresh_signed_root(3);
        let mut bytes = encode_signed_epoch_root(&signed).expect("encode");
        bytes.push(0x00); // one extra byte beyond expected layout
        let err = decode_signed_epoch_root(&bytes).expect_err("trailing byte must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("trailing_bytes")
        ));
    }

    #[test]
    fn decode_rejects_extra_signature_payload_size_chunk_appended() {
        // Adversary appends a full extra 96-byte signature payload but does
        // not bump the signature_count byte — strict decoder must reject.
        let signed = fresh_signed_root(3);
        let mut bytes = encode_signed_epoch_root(&signed).expect("encode");
        bytes.extend_from_slice(&[0xAA; SIGNATURE_WIRE_LEN]);
        let err =
            decode_signed_epoch_root(&bytes).expect_err("trailing signature payload must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("trailing_bytes")
        ));
    }

    #[test]
    fn decode_rejects_one_trailing_byte_after_zero_signature_header() {
        // Edge case: header-only frame + 1 trailing byte = 59 bytes.
        // Without the strict trailing check this would silently parse
        // as «valid zero-sig header» ignoring the dangling byte.
        let signed = fresh_signed_root(0);
        let mut bytes = encode_signed_epoch_root(&signed).expect("encode");
        bytes.push(0x42);
        let err = decode_signed_epoch_root(&bytes).expect_err("59-byte input must fail");
        assert!(matches!(
            err,
            KtError::InvalidSignedEpochRootWire("trailing_bytes")
        ));
    }

    // ========================================================================
    // Verify-compat — decoded frame passes verify_signed_epoch
    // ========================================================================

    #[test]
    fn decoded_signed_epoch_root_verifies_against_pinned_witness_set_threshold_three_of_five() {
        // Integration cross-check: encode honest 5-of-5, decode, then run
        // verify_signed_epoch — confirms wire layout matches what witness
        // verify expects (no field swap / endianness regression).
        use crate::witness::{verify_signed_epoch, WitnessSet};

        let witnesses: Vec<TestWitness> = (0..5).map(|_| fresh_witness()).collect();
        let epoch = 42u64;
        let root = [0xCD; NODE_HASH_LEN];
        let log_size = 1_000_000u64;
        let ts_ms = 1_715_000_000_000u64;
        let signatures: Vec<WitnessSignature> = witnesses
            .iter()
            .map(|w| sign_for(w, epoch, &root, log_size, ts_ms))
            .collect();
        let signed = SignedEpochRoot {
            epoch,
            root,
            log_size,
            timestamp_unix_millis: ts_ms,
            signatures,
        };

        let bytes = encode_signed_epoch_root(&signed).expect("encode");
        let decoded = decode_signed_epoch_root(&bytes).expect("decode");

        let mut witness_set = WitnessSet::new();
        for w in &witnesses {
            witness_set.add(w.pk);
        }
        verify_signed_epoch(&decoded, &witness_set, 3).expect(
            "decoded SignedEpochRoot MUST verify under pinned set with threshold 3 — \
             confirms wire layout binds to canonical_sign_payload correctly",
        );
    }

    // ========================================================================
    // KT entry IdentityRotation codec tests (session 9a)
    // ========================================================================

    mod kt_entry_identity_rotation_tests {
        use super::*;
        use umbrella_backup::cloud_wrap::RotationReason;

        /// Build a structurally-valid `IdentityRotationRecord` for wire-level
        /// testing. Signatures and proof are non-cryptographic placeholder
        /// bytes — these tests cover **wire framing**, not cryptographic
        /// verification (the latter lives in `IdentityRotationRecord::verify`
        /// + `apply_identity_rotation`).
        fn fresh_rotation_record() -> IdentityRotationRecord {
            IdentityRotationRecord {
                version: 0x01,
                old_identity_pubkey: [0xAA; 32],
                new_identity_pubkey: [0xBB; 32],
                rotation_timestamp: 1_715_000_000_000,
                rotation_reason: RotationReason::PlannedRotation,
                old_identity_signature: [0xCC; 64],
                new_identity_signature: [0xDD; 64],
                code_recovery_public_half_proof: [0xEE; 32],
            }
        }

        // --- Constants invariants ---

        #[test]
        fn wire_constants_match_layout_documentation() {
            // 1 byte prefix + 234 byte record = 235 bytes total.
            assert_eq!(KT_ENTRY_IDENTITY_ROTATION_PREFIX, 0x06);
            assert_eq!(KT_ENTRY_IDENTITY_ROTATION_WIRE_LEN, 235);
            assert_eq!(KT_ENTRY_IDENTITY_ROTATION_WIRE_LEN, 1 + 234);
            // Prefix const MUST equal the canonical EntryType tag.
            assert_eq!(
                KT_ENTRY_IDENTITY_ROTATION_PREFIX,
                EntryType::IdentityRotationRecord as u8
            );
        }

        // --- Round-trip ---

        #[test]
        fn encode_then_decode_round_trip_preserves_all_fields_for_kt_entry_identity_rotation() {
            let original = fresh_rotation_record();
            let bytes = encode_kt_entry_identity_rotation(&original);
            assert_eq!(bytes.len(), KT_ENTRY_IDENTITY_ROTATION_WIRE_LEN);
            let decoded =
                decode_kt_entry_identity_rotation(&bytes).expect("decode honest 235-byte frame");
            assert_eq!(decoded, original);
        }

        #[test]
        fn encode_produces_deterministic_output_for_same_record() {
            let record = fresh_rotation_record();
            let a = encode_kt_entry_identity_rotation(&record);
            let b = encode_kt_entry_identity_rotation(&record);
            assert_eq!(
                a, b,
                "encoder MUST be byte-deterministic given identical input"
            );
        }

        #[test]
        fn encoded_first_byte_is_kt_entry_identity_rotation_prefix_0x06() {
            let record = fresh_rotation_record();
            let bytes = encode_kt_entry_identity_rotation(&record);
            assert_eq!(bytes[0], KT_ENTRY_IDENTITY_ROTATION_PREFIX);
            assert_eq!(bytes[0], 0x06);
        }

        #[test]
        fn encoded_body_matches_record_encode_after_prefix() {
            // Wire layout: byte[0] = prefix, byte[1..235] = record.encode().
            let record = fresh_rotation_record();
            let wire = encode_kt_entry_identity_rotation(&record);
            let body_encoded = record.encode();
            assert_eq!(&wire[1..], &body_encoded[..]);
        }

        // --- Strict rejection: framing ---

        #[test]
        fn decode_rejects_empty_input_with_too_short_tag() {
            let err = decode_kt_entry_identity_rotation(&[]).expect_err("empty must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("too_short")
            ));
        }

        #[test]
        fn decode_rejects_only_prefix_byte_without_body_via_wrong_length() {
            // 1-byte input with correct prefix passes the "too_short" / "wrong_prefix"
            // gates but trips wrong_length (expected 235, got 1).
            let bytes = [KT_ENTRY_IDENTITY_ROTATION_PREFIX];
            let err = decode_kt_entry_identity_rotation(&bytes).expect_err("1-byte must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("wrong_length")
            ));
        }

        #[test]
        fn decode_rejects_input_one_byte_below_wire_length() {
            let record = fresh_rotation_record();
            let mut bytes = encode_kt_entry_identity_rotation(&record);
            bytes.pop();
            assert_eq!(bytes.len(), KT_ENTRY_IDENTITY_ROTATION_WIRE_LEN - 1);
            let err = decode_kt_entry_identity_rotation(&bytes).expect_err("234-byte must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("wrong_length")
            ));
        }

        #[test]
        fn decode_rejects_input_with_trailing_byte_above_wire_length() {
            let record = fresh_rotation_record();
            let mut bytes = encode_kt_entry_identity_rotation(&record);
            bytes.push(0x00);
            assert_eq!(bytes.len(), KT_ENTRY_IDENTITY_ROTATION_WIRE_LEN + 1);
            let err = decode_kt_entry_identity_rotation(&bytes).expect_err("236-byte must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("wrong_length")
            ));
        }

        // --- Strict rejection: prefix byte ---

        #[test]
        fn decode_rejects_prefix_byte_0x04_device_authorization_approval_tag() {
            // 0x04 is the canonical tag for DeviceAuthorizationApproval —
            // a different ADR-008 entry-type. KT entry shouldn't be
            // routed to identity-rotation decoder.
            let record = fresh_rotation_record();
            let mut bytes = encode_kt_entry_identity_rotation(&record);
            bytes[0] = 0x04;
            let err = decode_kt_entry_identity_rotation(&bytes).expect_err("prefix 0x04 must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("wrong_prefix")
            ));
        }

        #[test]
        fn decode_rejects_prefix_byte_0x05_device_authorization_revocation_tag() {
            // 0x05 is DeviceAuthorizationRevocation — different entry-type.
            let record = fresh_rotation_record();
            let mut bytes = encode_kt_entry_identity_rotation(&record);
            bytes[0] = 0x05;
            let err = decode_kt_entry_identity_rotation(&bytes).expect_err("prefix 0x05 must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("wrong_prefix")
            ));
        }

        #[test]
        fn decode_rejects_zero_prefix_byte() {
            let record = fresh_rotation_record();
            let mut bytes = encode_kt_entry_identity_rotation(&record);
            bytes[0] = 0x00;
            let err = decode_kt_entry_identity_rotation(&bytes).expect_err("prefix 0x00 must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("wrong_prefix")
            ));
        }

        #[test]
        fn decode_rejects_every_non_0x06_prefix_byte() {
            // Exhaustive enumeration of all 255 non-0x06 prefix bytes.
            let record = fresh_rotation_record();
            let template = encode_kt_entry_identity_rotation(&record);
            for bad_prefix in 0u8..=255u8 {
                if bad_prefix == KT_ENTRY_IDENTITY_ROTATION_PREFIX {
                    continue;
                }
                let mut bytes = template.clone();
                bytes[0] = bad_prefix;
                match decode_kt_entry_identity_rotation(&bytes) {
                    Err(KtError::InvalidAuthorizationEntryWire("wrong_prefix")) => {}
                    other => {
                        panic!("bad_prefix=0x{bad_prefix:02x} expected wrong_prefix, got {other:?}")
                    }
                }
            }
        }

        // --- Strict rejection: record body ---

        #[test]
        fn decode_rejects_body_with_identical_old_and_new_pubkeys() {
            // SPEC-09 §7.2 rule 3: identity rotation MUST change identity.
            // IdentityRotationRecord::from_bytes guards this — wire codec
            // surfaces as record_invalid_wire_format.
            let record = fresh_rotation_record();
            let mut bytes = encode_kt_entry_identity_rotation(&record);
            // Copy old_identity_pubkey (wire[2..34]) into new_identity_pubkey
            // (wire[34..66]) — now old_pk == new_pk.
            let old_pk: [u8; 32] = bytes[2..34].try_into().expect("32 bytes");
            bytes[34..66].copy_from_slice(&old_pk);
            let err =
                decode_kt_entry_identity_rotation(&bytes).expect_err("identical pubkeys must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("record_invalid_wire_format")
            ));
        }

        #[test]
        fn decode_rejects_body_with_unknown_rotation_reason_byte_0xff() {
            // rotation_reason at wire offset 1+73 = 74 (after prefix(1) +
            // version(1) + old_pk(32) + new_pk(32) + ts(8) = 74). Valid tags
            // are 0x01/0x02/0x03; 0xFF is unknown — `from_bytes` rejects via
            // `RotationReason::from_tag` returning None.
            let record = fresh_rotation_record();
            let mut bytes = encode_kt_entry_identity_rotation(&record);
            bytes[74] = 0xFF;
            let err = decode_kt_entry_identity_rotation(&bytes).expect_err("reason 0xFF must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("record_invalid_wire_format")
            ));
        }

        #[test]
        fn decode_rejects_body_with_unknown_wire_version_byte() {
            // version byte lives at wire offset 1 (immediately after prefix).
            // Valid value is AUTHORIZATION_WIRE_VERSION = 0x01. `from_bytes`
            // surfaces version mismatch as BackupError::WrappedKeyVersionMismatch
            // which we map to record_unknown_wire_version.
            let record = fresh_rotation_record();
            let mut bytes = encode_kt_entry_identity_rotation(&record);
            bytes[1] = 0xFF;
            let err =
                decode_kt_entry_identity_rotation(&bytes).expect_err("version 0xFF must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("record_unknown_wire_version")
            ));
        }
    }

    // ========================================================================
    // KT entry DeviceAuthorizationApproval codec tests (session 9a')
    // ========================================================================

    mod kt_entry_device_authorization_approval_tests {
        use super::*;

        fn fresh_approval_record() -> DeviceAuthorizationApproval {
            DeviceAuthorizationApproval {
                version: 0x01,
                new_device_pubkey: [0x11; 32],
                approver_device_pubkey: [0x22; 32],
                authorized_since_timestamp: 1_715_000_000_000,
                history_cutoff_timestamp: 0, // full history
                policy_flags: 0x00,
                approver_signature: [0x33; 64],
            }
        }

        #[test]
        fn wire_constants_match_layout_documentation() {
            assert_eq!(KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_PREFIX, 0x04);
            assert_eq!(KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_WIRE_LEN, 147);
            assert_eq!(KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_WIRE_LEN, 1 + 146);
            assert_eq!(
                KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_PREFIX,
                EntryType::DeviceAuthorizationApproval as u8
            );
        }

        #[test]
        fn encode_then_decode_round_trip_preserves_all_fields() {
            let original = fresh_approval_record();
            let bytes = encode_kt_entry_device_authorization_approval(&original);
            assert_eq!(bytes.len(), KT_ENTRY_DEVICE_AUTHORIZATION_APPROVAL_WIRE_LEN);
            let decoded = decode_kt_entry_device_authorization_approval(&bytes)
                .expect("decode honest 147-byte frame");
            assert_eq!(decoded, original);
        }

        #[test]
        fn encode_produces_deterministic_output_for_same_record() {
            let record = fresh_approval_record();
            let a = encode_kt_entry_device_authorization_approval(&record);
            let b = encode_kt_entry_device_authorization_approval(&record);
            assert_eq!(a, b);
        }

        #[test]
        fn encoded_first_byte_is_kt_entry_device_authorization_approval_prefix_0x04() {
            let bytes = encode_kt_entry_device_authorization_approval(&fresh_approval_record());
            assert_eq!(bytes[0], 0x04);
        }

        #[test]
        fn decode_rejects_empty_input_with_too_short_tag() {
            let err =
                decode_kt_entry_device_authorization_approval(&[]).expect_err("empty must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("too_short")
            ));
        }

        #[test]
        fn decode_rejects_wrong_prefix_byte_0x06_identity_rotation_tag() {
            // 0x06 = IdentityRotation. Routing approval decoder to a
            // rotation-prefixed frame must reject — guards against caller
            // dispatching to the wrong per-type decoder.
            let mut bytes = encode_kt_entry_device_authorization_approval(&fresh_approval_record());
            bytes[0] = 0x06;
            let err = decode_kt_entry_device_authorization_approval(&bytes)
                .expect_err("prefix 0x06 must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("wrong_prefix")
            ));
        }

        #[test]
        fn decode_rejects_input_below_wire_length() {
            let mut bytes = encode_kt_entry_device_authorization_approval(&fresh_approval_record());
            bytes.pop();
            let err = decode_kt_entry_device_authorization_approval(&bytes)
                .expect_err("146-byte must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("wrong_length")
            ));
        }

        #[test]
        fn decode_rejects_input_with_trailing_byte() {
            let mut bytes = encode_kt_entry_device_authorization_approval(&fresh_approval_record());
            bytes.push(0xAB);
            let err = decode_kt_entry_device_authorization_approval(&bytes)
                .expect_err("148-byte must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("wrong_length")
            ));
        }

        #[test]
        fn decode_rejects_body_with_unknown_wire_version_byte() {
            let mut bytes = encode_kt_entry_device_authorization_approval(&fresh_approval_record());
            bytes[1] = 0xFF; // body's version byte
            let err = decode_kt_entry_device_authorization_approval(&bytes)
                .expect_err("version 0xFF must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("record_unknown_wire_version")
            ));
        }
    }

    // ========================================================================
    // KT entry DeviceAuthorizationRevocation codec tests (session 9a')
    // ========================================================================

    mod kt_entry_device_authorization_revocation_tests {
        use super::*;

        fn fresh_revocation_record() -> DeviceAuthorizationRevocation {
            DeviceAuthorizationRevocation {
                version: 0x01,
                revoked_device_pubkey: [0x44; 32],
                revoker_device_pubkey: [0x55; 32],
                revocation_timestamp: 1_715_000_000_000,
                revoker_signature: [0x66; 64],
            }
        }

        #[test]
        fn wire_constants_match_layout_documentation() {
            assert_eq!(KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_PREFIX, 0x05);
            assert_eq!(KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_WIRE_LEN, 138);
            assert_eq!(KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_WIRE_LEN, 1 + 137);
            assert_eq!(
                KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_PREFIX,
                EntryType::DeviceAuthorizationRevocation as u8
            );
        }

        #[test]
        fn encode_then_decode_round_trip_preserves_all_fields() {
            let original = fresh_revocation_record();
            let bytes = encode_kt_entry_device_authorization_revocation(&original);
            assert_eq!(
                bytes.len(),
                KT_ENTRY_DEVICE_AUTHORIZATION_REVOCATION_WIRE_LEN
            );
            let decoded = decode_kt_entry_device_authorization_revocation(&bytes)
                .expect("decode honest 138-byte frame");
            assert_eq!(decoded, original);
        }

        #[test]
        fn encoded_first_byte_is_kt_entry_device_authorization_revocation_prefix_0x05() {
            let bytes = encode_kt_entry_device_authorization_revocation(&fresh_revocation_record());
            assert_eq!(bytes[0], 0x05);
        }

        #[test]
        fn decode_rejects_empty_input_with_too_short_tag() {
            let err =
                decode_kt_entry_device_authorization_revocation(&[]).expect_err("empty must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("too_short")
            ));
        }

        #[test]
        fn decode_rejects_wrong_prefix_byte_0x04_approval_tag() {
            // 0x04 = DeviceAuthorizationApproval. Routing revocation decoder
            // to an approval-prefixed frame must reject.
            let mut bytes =
                encode_kt_entry_device_authorization_revocation(&fresh_revocation_record());
            bytes[0] = 0x04;
            let err = decode_kt_entry_device_authorization_revocation(&bytes)
                .expect_err("prefix 0x04 must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("wrong_prefix")
            ));
        }

        #[test]
        fn decode_rejects_wrong_prefix_byte_0x06_identity_rotation_tag() {
            let mut bytes =
                encode_kt_entry_device_authorization_revocation(&fresh_revocation_record());
            bytes[0] = 0x06;
            let err = decode_kt_entry_device_authorization_revocation(&bytes)
                .expect_err("prefix 0x06 must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("wrong_prefix")
            ));
        }

        #[test]
        fn decode_rejects_input_below_wire_length() {
            let mut bytes =
                encode_kt_entry_device_authorization_revocation(&fresh_revocation_record());
            bytes.pop();
            let err = decode_kt_entry_device_authorization_revocation(&bytes)
                .expect_err("137-byte must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("wrong_length")
            ));
        }

        #[test]
        fn decode_rejects_input_with_trailing_byte() {
            let mut bytes =
                encode_kt_entry_device_authorization_revocation(&fresh_revocation_record());
            bytes.push(0x77);
            let err = decode_kt_entry_device_authorization_revocation(&bytes)
                .expect_err("139-byte must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("wrong_length")
            ));
        }

        #[test]
        fn decode_rejects_body_with_unknown_wire_version_byte() {
            let mut bytes =
                encode_kt_entry_device_authorization_revocation(&fresh_revocation_record());
            bytes[1] = 0xFF;
            let err = decode_kt_entry_device_authorization_revocation(&bytes)
                .expect_err("version 0xFF must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("record_unknown_wire_version")
            ));
        }
    }

    // ========================================================================
    // KT authorization-entry dispatcher tests (session 9a')
    // ========================================================================

    mod kt_authorization_entry_dispatcher_tests {
        use super::*;
        use umbrella_backup::cloud_wrap::RotationReason;

        fn fresh_approval() -> DeviceAuthorizationApproval {
            DeviceAuthorizationApproval {
                version: 0x01,
                new_device_pubkey: [0x11; 32],
                approver_device_pubkey: [0x22; 32],
                authorized_since_timestamp: 1_715_000_000_000,
                history_cutoff_timestamp: 0,
                policy_flags: 0x00,
                approver_signature: [0x33; 64],
            }
        }

        fn fresh_revocation() -> DeviceAuthorizationRevocation {
            DeviceAuthorizationRevocation {
                version: 0x01,
                revoked_device_pubkey: [0x44; 32],
                revoker_device_pubkey: [0x55; 32],
                revocation_timestamp: 1_715_000_000_000,
                revoker_signature: [0x66; 64],
            }
        }

        fn fresh_rotation() -> IdentityRotationRecord {
            IdentityRotationRecord {
                version: 0x01,
                old_identity_pubkey: [0xAA; 32],
                new_identity_pubkey: [0xBB; 32],
                rotation_timestamp: 1_715_000_000_000,
                rotation_reason: RotationReason::PlannedRotation,
                old_identity_signature: [0xCC; 64],
                new_identity_signature: [0xDD; 64],
                code_recovery_public_half_proof: [0xEE; 32],
            }
        }

        #[test]
        fn dispatch_routes_0x04_to_approval_decoder() {
            let original = fresh_approval();
            let bytes = encode_kt_entry_device_authorization_approval(&original);
            match decode_kt_authorization_entry(&bytes).expect("dispatch") {
                KtAuthorizationEntry::Approval(decoded) => assert_eq!(decoded, original),
                other => panic!("expected Approval variant, got {other:?}"),
            }
        }

        #[test]
        fn dispatch_routes_0x05_to_revocation_decoder() {
            let original = fresh_revocation();
            let bytes = encode_kt_entry_device_authorization_revocation(&original);
            match decode_kt_authorization_entry(&bytes).expect("dispatch") {
                KtAuthorizationEntry::Revocation(decoded) => assert_eq!(decoded, original),
                other => panic!("expected Revocation variant, got {other:?}"),
            }
        }

        #[test]
        fn dispatch_routes_0x06_to_identity_rotation_decoder() {
            let original = fresh_rotation();
            let bytes = encode_kt_entry_identity_rotation(&original);
            match decode_kt_authorization_entry(&bytes).expect("dispatch") {
                KtAuthorizationEntry::IdentityRotation(decoded) => assert_eq!(decoded, original),
                other => panic!("expected IdentityRotation variant, got {other:?}"),
            }
        }

        #[test]
        fn dispatch_rejects_empty_input_before_routing() {
            let err = decode_kt_authorization_entry(&[]).expect_err("empty must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("too_short")
            ));
        }

        #[test]
        fn dispatch_rejects_unknown_prefix_byte_0x00() {
            let bytes = [0x00u8; 200];
            let err = decode_kt_authorization_entry(&bytes).expect_err("prefix 0x00 must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("wrong_prefix")
            ));
        }

        #[test]
        fn dispatch_rejects_unknown_prefix_byte_0x01_identity_announce_legacy_tag() {
            // 0x01 = IdentityAnnounce (V1 EntryType, not framed). Dispatcher
            // covers ONLY the 3 ADR-008 framed types (0x04/0x05/0x06).
            let bytes = [0x01u8; 200];
            let err = decode_kt_authorization_entry(&bytes).expect_err("prefix 0x01 must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("wrong_prefix")
            ));
        }

        #[test]
        fn dispatch_propagates_per_decoder_wrong_length_for_truncated_approval() {
            // Valid 0x04 prefix but body truncated — dispatch routes to
            // approval decoder which then fails with wrong_length.
            let mut bytes = encode_kt_entry_device_authorization_approval(&fresh_approval());
            bytes.pop();
            let err = decode_kt_authorization_entry(&bytes).expect_err("truncated must fail");
            assert!(matches!(
                err,
                KtError::InvalidAuthorizationEntryWire("wrong_length")
            ));
        }

        #[test]
        fn entry_type_accessor_returns_correct_entry_type_for_each_variant() {
            let approval = KtAuthorizationEntry::Approval(fresh_approval());
            let revocation = KtAuthorizationEntry::Revocation(fresh_revocation());
            let rotation = KtAuthorizationEntry::IdentityRotation(fresh_rotation());
            assert_eq!(
                approval.entry_type(),
                EntryType::DeviceAuthorizationApproval
            );
            assert_eq!(
                revocation.entry_type(),
                EntryType::DeviceAuthorizationRevocation
            );
            assert_eq!(rotation.entry_type(), EntryType::IdentityRotationRecord);
        }

        #[test]
        fn dispatch_round_trips_all_three_entry_types_in_one_test() {
            // Single test exercising encode → dispatch decode for all three
            // entry types in sequence — confirms dispatcher symmetric coverage.
            for (entry_type, bytes) in [
                (
                    EntryType::DeviceAuthorizationApproval,
                    encode_kt_entry_device_authorization_approval(&fresh_approval()),
                ),
                (
                    EntryType::DeviceAuthorizationRevocation,
                    encode_kt_entry_device_authorization_revocation(&fresh_revocation()),
                ),
                (
                    EntryType::IdentityRotationRecord,
                    encode_kt_entry_identity_rotation(&fresh_rotation()),
                ),
            ] {
                let decoded = decode_kt_authorization_entry(&bytes)
                    .unwrap_or_else(|e| panic!("dispatch failed for {entry_type:?}: {e:?}"));
                assert_eq!(decoded.entry_type(), entry_type);
            }
        }
    }
}
