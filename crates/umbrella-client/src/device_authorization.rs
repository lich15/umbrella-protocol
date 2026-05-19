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
    canonical_signing_input_approval, DeviceAuthorizationApproval, DeviceAuthorizationRevocation,
    AUTHORIZATION_WIRE_VERSION, POLICY_FLAGS_RESERVED_MASK,
};
use umbrella_kt::{
    encode_kt_entry_device_authorization_approval, encode_kt_entry_device_authorization_revocation,
    DEVICE_PUBKEY_LEN,
};

use crate::core::ClientCore;
use crate::error::{ClientError, Result};
use crate::identity::IDENTITY_SIGNATURE_LEN;
use crate::keystore::hw_callback::{HwKeyHandle, PersistentKeyStoreCallback};

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

/// **F-CLIENT-FACADE-1 session 10f (2026-05-19):** initiate a device-transfer
/// flow на existing («approver») device. Orchestrates HW signing of the
/// canonical approval input on the TEE-resident identity key + composes the
/// session 9c publish path. Caller supplies only `new_device_pubkey` (from
/// incoming-device side via QR / mutually-attested channel) + timestamps +
/// `policy_flags` — the approver's own pubkey is resolved from
/// `hw_callback.verifying_key(approver_handle)` (single source of truth).
///
/// SPEC-11 §4 device add flow: existing active device authorizes a new
/// device by publishing a `DeviceAuthorizationApproval` (ADR-008 EntryType
/// 0x04) record signed by the approver's identity key. The new device, once
/// online, observes the entry in KT and bootstraps its local state from the
/// approval metadata + cloud-wrap material.
///
/// ## Defence-in-depth (5 layers)
///
/// 1. **Policy-flags reserved bits** — `policy_flags & POLICY_FLAGS_RESERVED_MASK
///    != 0` → fail-closed before any HW round-trip. Matches the same
///    invariant in `seal_device_authorization_approval` /
///    [`publish_device_authorization_approval`] (defence-in-depth — caller,
///    facade, and seal helper all enforce).
/// 2. **HW pubkey resolution** — `hw_callback.verifying_key(approver_handle)`
///    fetches the approver pubkey directly from the TEE. Single source of
///    truth ensures the canonical input's `approver_device_pubkey` field
///    matches the key that will actually sign — no opportunity for a
///    caller-supplied stale pubkey to corrupt the record.
/// 3. **Self-approval rejection** — `new_device_pubkey ==
///    approver_device_pubkey` is rejected as a caller-side bug: device
///    transfer adds a **new** device. A device retiring its own identity
///    uses `rotate_identity_full` (session 9d), not this flow.
/// 4. **HW signature length** — `sign_identity` returns `Vec<u8>` per the
///    callback ABI; we strictly enforce the Ed25519 64-byte length so a
///    misbehaving native impl (or a mock returning wrong length) is caught
///    immediately rather than corrupting downstream wire frames.
/// 5. **Publish-side re-verify** — delegate to
///    [`publish_device_authorization_approval`] whose
///    `verify_self_consistent` step Ed25519-verifies the signature under
///    the embedded `approver_device_pubkey`. Catches HW key-handle
///    mismatch (signing key not paired with the resolved pubkey — would
///    indicate keystore corruption).
///
/// ## Why parametric `hw_callback` + `approver_handle`, not read from `core`
///
/// Mirrors `rotate_identity_full` (session 9d) rationale verbatim:
///
/// 1. **Test ergonomics** — `core.hw_callback` is `pub(crate)`; integration
///    tests can inject a `MockHwKeystore` directly.
/// 2. **Decoupling** — production callers (FFI layer) MAY wrap `core.hw_callback`
///    с telemetry или audit middleware before passing to this method.
/// 3. **Single-responsibility** — facade is pure orchestration; ClientCore
///    holds shared transport state but is not the source of truth for HW
///    callback wiring.
///
/// **F-CLIENT-FACADE-1 session 10f (2026-05-19):** initiate device-transfer
/// on existing approver device. HW signing + session 9c publish orchestration.
///
/// # Errors
///
/// - `ClientError::Kt(KtError::InvalidAuthorizationEntryWire("policy_flags_reserved_bits_set"))`
///   if `policy_flags & POLICY_FLAGS_RESERVED_MASK != 0`.
/// - `ClientError::Platform(...)` if `hw_callback.verifying_key(approver_handle)`
///   or `sign_identity` returns an error (TEE failure, key not found, etc.).
/// - `ClientError::Internal("...self-approval not allowed...")` if
///   `new_device_pubkey == approver_device_pubkey`.
/// - `ClientError::Internal("...HW signature length...")` if
///   `sign_identity` returns a `Vec<u8>` of length other than 64
///   (`IDENTITY_SIGNATURE_LEN`).
/// - Any error from [`publish_device_authorization_approval`] (Layer 5
///   self-consistency re-verify).
pub async fn initiate_device_transfer(
    core: &Arc<ClientCore>,
    hw_callback: Arc<dyn PersistentKeyStoreCallback>,
    approver_handle: HwKeyHandle,
    new_device_pubkey: [u8; DEVICE_PUBKEY_LEN],
    authorized_since_timestamp: u64,
    history_cutoff_timestamp: u64,
    policy_flags: u8,
) -> Result<DeviceAuthorizationPublishOutcome> {
    // Layer 1: policy_flags reserved bits guard. Fails closed before HW
    // round-trip to avoid wasting a TEE operation on a wire-frame that
    // would be rejected at publish time.
    if policy_flags & POLICY_FLAGS_RESERVED_MASK != 0 {
        return Err(ClientError::Kt(
            umbrella_kt::KtError::InvalidAuthorizationEntryWire("policy_flags_reserved_bits_set"),
        ));
    }

    // Layer 2: resolve approver pubkey from HW callback. Source of truth
    // is the TEE — never a caller-supplied parameter.
    let approver_device_pubkey = hw_callback.verifying_key(&approver_handle).map_err(|err| {
        ClientError::Platform(format!(
            "initiate_device_transfer: hw_callback.verifying_key(approver_handle) failed: {err}"
        ))
    })?;

    // Layer 3: self-approval rejection.
    if new_device_pubkey == approver_device_pubkey {
        return Err(ClientError::Internal(format!(
            "initiate_device_transfer: self-approval not allowed — new_device_pubkey \
             equals approver_device_pubkey ({}); device transfer requires a different \
             new device. For self-rotation use rotate_identity_full (session 9d)",
            hex_short_pk(&approver_device_pubkey),
        )));
    }

    // Layer 4: HW sign canonical approval input.
    let canonical = canonical_signing_input_approval(
        AUTHORIZATION_WIRE_VERSION,
        &new_device_pubkey,
        &approver_device_pubkey,
        authorized_since_timestamp,
        history_cutoff_timestamp,
        policy_flags,
    );
    let sig_vec = hw_callback
        .sign_identity(&approver_handle, &canonical)
        .map_err(|err| {
            ClientError::Platform(format!(
                "initiate_device_transfer: hw_callback.sign_identity over \
                 canonical_signing_input_approval failed: {err}"
            ))
        })?;
    let sig_len = sig_vec.len();
    let approver_signature: [u8; IDENTITY_SIGNATURE_LEN] =
        sig_vec.as_slice().try_into().map_err(|_| {
            ClientError::Internal(format!(
                "initiate_device_transfer: hw_callback.sign_identity returned {sig_len} bytes, \
                 expected {IDENTITY_SIGNATURE_LEN} (Ed25519 signature length)"
            ))
        })?;

    // Layer 5: publish via session 9c facade. publish_device_authorization_approval's
    // verify_self_consistent re-verifies signature → catches HW key-handle
    // mismatch (approver_handle paired with different identity key).
    publish_device_authorization_approval(
        core,
        new_device_pubkey,
        approver_device_pubkey,
        authorized_since_timestamp,
        history_cutoff_timestamp,
        policy_flags,
        approver_signature,
    )
    .await
}

/// Render the first 4 bytes of a 32-byte pubkey as hex with a trailing `...`
/// — used only in error messages so wallet inspectors can correlate a
/// failed approval to the device pubkey без leaking the full bytes into
/// logs. Same convention as `identity::hex_short`.
fn hex_short_pk(bytes: &[u8; DEVICE_PUBKEY_LEN]) -> String {
    let prefix: String = bytes.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("{prefix}...{}b", bytes.len())
}
