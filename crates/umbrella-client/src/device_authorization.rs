//! Facade-level device-authorization операции — публикация ADR-008
//! `DeviceAuthorizationApproval` (0x04) и `DeviceAuthorizationRevocation`
//! (0x05) записей в KT log (F-CLIENT-FACADE-1 session 9c, 2026-05-19).
//! Mirror'ит структуру `umbrella_client::identity` (session 9b) для парных
//! entry types: publish-only path, caller supplies все cryptographic
//! material, facade local-verifies + encodes + publishes.
//!
//! ## Two parallel methods
//!
//! - [`publish_device_authorization_approval`] — publish 147-byte
//!   0x04-prefixed entry. SPEC-11 §4 device add flow: existing active device
//!   («approver») authorizes a new device.
//! - [`publish_device_authorization_revocation`] — publish 138-byte
//!   0x05-prefixed entry. SPEC-11 §4 device revoke flow: active device
//!   («revoker») revokes another (or itself — self-revocation).
//!
//! Both are publish-only (Q1-independent layer), do NOT mutate
//! `core.mls_keystore`. Defence-in-depth chain identical to session 9b
//! (verify_self_consistent + policy-flags reserved check pre-publish for
//! approval).
//!
//! ## Why parallel methods, not a single `publish_authorization_entry`
//!
//! Approval (0x04) takes 7 parameters and has policy-flags semantics +
//! 147-byte wire layout. Revocation (0x05) takes 4 parameters and has no
//! flags + 138-byte wire layout. Folding both into one method either
//! requires a sum-type parameter (verbose ergonomic) или duplicates
//! validation logic. Parallel methods are cleaner.

use std::sync::Arc;

use umbrella_backup::cloud_wrap::{
    DeviceAuthorizationApproval, DeviceAuthorizationRevocation, AUTHORIZATION_WIRE_VERSION,
    POLICY_FLAGS_RESERVED_MASK,
};
use umbrella_kt::{
    encode_kt_entry_device_authorization_approval, encode_kt_entry_device_authorization_revocation,
    DEVICE_PUBKEY_LEN,
};

use crate::core::ClientCore;
use crate::error::{ClientError, Result};
use crate::identity::IDENTITY_SIGNATURE_LEN;

/// Outcome от successful publish'а одной из двух authorization entry types.
/// Returned by [`publish_device_authorization_approval`] и
/// [`publish_device_authorization_revocation`] после успешного push'а в
/// `kt_transport`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthorizationPublishOutcome {
    /// Размер опубликованного wire-frame (147 для approval, 138 для revocation).
    /// Size of the published wire frame (147 for approval, 138 for revocation).
    pub published_entry_size: usize,
    /// Timestamp указанный в record (approval: `authorized_since_timestamp`;
    /// revocation: `revocation_timestamp`).
    /// Timestamp in the record (approval's authorized_since OR revocation's ts).
    pub timestamp: u64,
}

/// **F-CLIENT-FACADE-1 session 9c (2026-05-19):** publish a device
/// authorization approval (ADR-008 EntryType 0x04) to the KT log.
/// Publish-only — caller supplies all crypto material. Defence-in-depth
/// chain:
///
/// 1. `policy_flags & POLICY_FLAGS_RESERVED_MASK != 0` → fail-closed
///    (`InvalidAuthorizationEntryWire("policy_flags_reserved_bits_set")`).
///    Matches `seal_device_authorization_approval` invariant exactly.
/// 2. Construct record.
/// 3. `record.verify_self_consistent()` — Ed25519 verify of
///    `approver_signature` against `approver_device_pubkey` over canonical
///    input. Catches caller signing errors before publish.
/// 4. Wire-encode via session 9a' codec (147 bytes fixed).
/// 5. Publish via `core.kt_transport().publish(wire)`.
///
/// **F-CLIENT-FACADE-1 session 9c:** publish a device authorization
/// approval to the KT log. Publish-only — caller supplies all crypto
/// material.
///
/// # Errors
///
/// - `ClientError::Kt(KtError::InvalidAuthorizationEntryWire("policy_flags_reserved_bits_set"))`
///   if `policy_flags & 0xFE != 0` (reserved bits 1..7 must be zero).
/// - `ClientError::Internal(...)` if `verify_self_consistent` fails
///   (signature mismatch — caller signing error).
#[allow(clippy::too_many_arguments)]
pub async fn publish_device_authorization_approval(
    core: &Arc<ClientCore>,
    new_device_pubkey: [u8; DEVICE_PUBKEY_LEN],
    approver_device_pubkey: [u8; DEVICE_PUBKEY_LEN],
    authorized_since_timestamp: u64,
    history_cutoff_timestamp: u64,
    policy_flags: u8,
    approver_signature: [u8; IDENTITY_SIGNATURE_LEN],
) -> Result<DeviceAuthorizationPublishOutcome> {
    if policy_flags & POLICY_FLAGS_RESERVED_MASK != 0 {
        return Err(ClientError::Kt(
            umbrella_kt::KtError::InvalidAuthorizationEntryWire("policy_flags_reserved_bits_set"),
        ));
    }

    let record = DeviceAuthorizationApproval {
        version: AUTHORIZATION_WIRE_VERSION,
        new_device_pubkey,
        approver_device_pubkey,
        authorized_since_timestamp,
        history_cutoff_timestamp,
        policy_flags,
        approver_signature,
    };

    record.verify_self_consistent().map_err(|backup_err| {
        ClientError::Internal(format!(
            "device authorization approval local verify failed pre-publish — \
             approver_signature does not validate against approver_device_pubkey \
             over canonical input (likely caller-side signing error): {backup_err}"
        ))
    })?;

    let wire = encode_kt_entry_device_authorization_approval(&record);
    let published_entry_size = wire.len();
    core.kt_transport().publish(wire);

    Ok(DeviceAuthorizationPublishOutcome {
        published_entry_size,
        timestamp: authorized_since_timestamp,
    })
}

/// **F-CLIENT-FACADE-1 session 9c (2026-05-19):** publish a device
/// authorization revocation (ADR-008 EntryType 0x05) to the KT log.
/// Publish-only — caller supplies all crypto material.
///
/// **Self-revocation explicitly allowed**: `revoked_device_pubkey ==
/// revoker_device_pubkey` is a legitimate flow per SPEC-11 §4 (device
/// retires itself). No early reject for this case.
///
/// **F-CLIENT-FACADE-1 session 9c:** publish a device authorization
/// revocation to the KT log. Self-revocation allowed.
///
/// # Errors
///
/// - `ClientError::Internal(...)` if `verify_self_consistent` fails
///   (signature mismatch — caller signing error).
pub async fn publish_device_authorization_revocation(
    core: &Arc<ClientCore>,
    revoked_device_pubkey: [u8; DEVICE_PUBKEY_LEN],
    revoker_device_pubkey: [u8; DEVICE_PUBKEY_LEN],
    revocation_timestamp: u64,
    revoker_signature: [u8; IDENTITY_SIGNATURE_LEN],
) -> Result<DeviceAuthorizationPublishOutcome> {
    let record = DeviceAuthorizationRevocation {
        version: AUTHORIZATION_WIRE_VERSION,
        revoked_device_pubkey,
        revoker_device_pubkey,
        revocation_timestamp,
        revoker_signature,
    };

    record.verify_self_consistent().map_err(|backup_err| {
        ClientError::Internal(format!(
            "device authorization revocation local verify failed pre-publish — \
             revoker_signature does not validate against revoker_device_pubkey \
             over canonical input (likely caller-side signing error): {backup_err}"
        ))
    })?;

    let wire = encode_kt_entry_device_authorization_revocation(&record);
    let published_entry_size = wire.len();
    core.kt_transport().publish(wire);

    Ok(DeviceAuthorizationPublishOutcome {
        published_entry_size,
        timestamp: revocation_timestamp,
    })
}
