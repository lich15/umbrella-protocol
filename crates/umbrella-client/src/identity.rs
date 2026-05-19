//! Facade-level identity-management операции — публикация identity
//! rotation записи в KT log (F-CLIENT-FACADE-1 session 9b, 2026-05-19).
//! Closes the **rotation publish path** at the client side: вне-устройства
//! сгенерированные signatures (под HW-Keystore либо distributed signing
//! либо локальное вычисление, см. design spec Q1) комбинируются с
//! `core.mls_keystore.identity_public()` в полный
//! `IdentityRotationRecord`, локально verified (постулат 14 defence-in-depth),
//! wire-encoded через [`umbrella_kt::encode_kt_entry_identity_rotation`]
//! (session 9a) и published через `kt_transport.publish` (235-byte frame).
//!
//! ## Scope of session 9b (per design spec)
//!
//! - **In scope**: `rotate_identity_publish` — publish-only facade.
//!   Caller (UX layer либо HW callback либо distributed signing rig)
//!   provides all cryptographic material (new pubkey, both sigs, recovery
//!   proof) parameters. Facade does NOT generate new identity material,
//!   does NOT sign, does NOT mutate `core.mls_keystore`.
//! - **Deferred to session 9c+ (depends on user Q1 selection)**: HW
//!   callback path (`PersistentKeyStoreCallback::rotate_identity`
//!   trait extension), local identity material generation, distributed
//!   signing protocol, runtime `mls_keystore` swap.
//! - **Deferred to post-1.0.0 либо separate stage**: MLS group repair
//!   (rotation cascades device-entry revocation → all groups need
//!   leave/rejoin), SLH-DSA backup signature variant.
//!
//! ## Why publish-only first (architectural reasoning)
//!
//! Design spec `2026-05-19-f-client-facade-1-session-9-identity-rotation-design.md`
//! identifies five open architectural questions (Q1–Q5). The **signing
//! path** (Q1: local / distributed / HW Keystore) is fundamentally
//! orthogonal to the **publish path**: regardless of where signatures
//! come from, the resulting wire bytes go through the same publish API.
//! A publish-only facade is therefore Q1-independent foundation —
//! adding it now lets session 9c+ focus exclusively on the chosen
//! signing path without re-doing publish glue.
//!
//! ## Threat model coverage
//!
//! SPEC-09 §7.2 + SPEC-12 §A.5.1: rotation record protects against
//!
//! 1. **MITM substitution of new identity key** — dual signature gate
//!    (both old + new identity Ed25519 sigs over the same canonical
//!    input) blocks any single key substitution.
//! 2. **Replay across different (old, new) pairs** — canonical input
//!    binds to both pubkeys via 32+32=64 bytes inside the signed payload.
//! 3. **24-word leak hijack** (F-PHD-RETRO-3-E) — `code_recovery_public_half_proof`
//!    is bound into both signatures; without 12-word recovery entropy an
//!    adversary cannot recompute the proof, so signed records that
//!    substitute the proof break dual-sig verify.
//! 4. **Identical pubkey degenerate rotation** — early check rejects
//!    `old_pk == new_pk` before construction (matches SPEC-09 §7.2 rule 3).
//!
//! Facade-side `IdentityRotationRecord::verify()` call BEFORE publish
//! gives caller fast feedback (errored signatures don't burn a publish
//! attempt) and acts as defence-in-depth: a malicious / buggy caller
//! cannot accidentally publish a record that won't apply.

use std::sync::Arc;

use umbrella_backup::cloud_wrap::identity_rotation::CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN;
use umbrella_backup::cloud_wrap::{
    IdentityRotationRecord, RotationReason, AUTHORIZATION_WIRE_VERSION,
};
use umbrella_kt::{encode_kt_entry_identity_rotation, DEVICE_PUBKEY_LEN};

use crate::core::ClientCore;
use crate::error::{ClientError, Result};

/// Длина Ed25519 подписи в байтах (= `umbrella_backup::cloud_wrap::DEVICE_SIG_LEN`).
/// Length of an Ed25519 signature in bytes (= `umbrella_backup::cloud_wrap::DEVICE_SIG_LEN`).
pub const IDENTITY_SIGNATURE_LEN: usize = 64;

/// Successful identity rotation outcome — returned by
/// [`rotate_identity_publish`] after the wire-framed entry has been pushed
/// to the KT log.
///
/// Successful identity-rotation outcome returned by [`rotate_identity_publish`]
/// after the wire-framed entry has been pushed to the KT log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationOutcome {
    /// Старый identity pubkey, прочитанный из `core.mls_keystore.identity_public()`
    /// в начале операции. Old identity pubkey, read from
    /// `core.mls_keystore.identity_public()` at the start of the operation.
    pub old_identity_pubkey: [u8; DEVICE_PUBKEY_LEN],
    /// Новый identity pubkey — supplied caller'ом.
    /// New identity pubkey — supplied by the caller.
    pub new_identity_pubkey: [u8; DEVICE_PUBKEY_LEN],
    /// Unix-millis момент ротации (как был supplied caller'ом + zapis в record).
    /// Rotation timestamp in unix millis (as supplied by the caller and
    /// recorded in the published entry).
    pub rotation_timestamp: u64,
    /// Размер опубликованного wire-frame в байтах. Для `IdentityRotation`
    /// этот размер всегда = 235 (`KT_ENTRY_IDENTITY_ROTATION_WIRE_LEN`), но
    /// возвращаем как поле для удобства тестов / observability.
    /// Size of the published wire frame in bytes. Always 235
    /// (`KT_ENTRY_IDENTITY_ROTATION_WIRE_LEN`) for IdentityRotation; returned
    /// here for test / observability convenience.
    pub published_entry_size: usize,
}

/// **F-CLIENT-FACADE-1 session 9b (2026-05-19):** publish an identity
/// rotation record to the KT log. Publish-only path — all cryptographic
/// material (new pubkey, both Ed25519 signatures, code-recovery proof) is
/// supplied by the caller; facade reads only the *old* pubkey from the
/// local keystore, performs defence-in-depth local verification, and
/// publishes the 235-byte wire frame.
///
/// **Defence-in-depth chain** (постулат 14, fail-closed):
/// 1. `old_identity_pubkey == new_identity_pubkey` → `ClientError::Kt(...)`
///    via `KtError::InvalidAuthorizationEntryWire("old_and_new_identity_pubkeys_identical")`
///    — SPEC-09 §7.2 rule 3 enforced ahead of construction.
/// 2. Construct `IdentityRotationRecord`.
/// 3. `record.verify()` recomputes canonical signing input and validates
///    both Ed25519 signatures. Any failure → `ClientError::Internal` with
///    descriptive message (caller error: signatures don't match material).
/// 4. Wire-encode via session 9a codec (235 bytes fixed; encoder is
///    infallible at this stage — input shape already validated).
/// 5. Publish to `core.kt_transport().publish(wire)` — stub appends to
///    in-memory log; production-equivalent: HTTP/2 POST /kt/publish.
///
/// **Local state is NOT mutated.** `core.mls_keystore` continues to
/// return the old identity material. Caller (UX layer либо subsequent
/// session 9c facade method) responsible for triggering keystore swap +
/// MLS group repair after publish succeeds. This separation is intentional
/// per design spec Q1 deferral.
///
/// **F-CLIENT-FACADE-1 session 9b:** publish an identity rotation record
/// to the KT log. Publish-only — caller supplies all crypto material.
///
/// # Errors
///
/// - `ClientError::Kt(KtError::InvalidAuthorizationEntryWire("old_and_new_identity_pubkeys_identical"))`
///   if `new_identity_pubkey` equals the current identity pubkey.
/// - `ClientError::Internal(...)` if `record.verify()` fails (signatures
///   don't validate over canonical input — caller error).
pub async fn rotate_identity_publish(
    core: &Arc<ClientCore>,
    new_identity_pubkey: [u8; DEVICE_PUBKEY_LEN],
    rotation_reason: RotationReason,
    rotation_timestamp: u64,
    code_recovery_public_half_proof: [u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN],
    old_identity_signature: [u8; IDENTITY_SIGNATURE_LEN],
    new_identity_signature: [u8; IDENTITY_SIGNATURE_LEN],
) -> Result<RotationOutcome> {
    let old_identity_pubkey = core.mls_keystore.identity_public().to_bytes();

    if old_identity_pubkey == new_identity_pubkey {
        return Err(ClientError::Kt(
            umbrella_kt::KtError::InvalidAuthorizationEntryWire(
                "old_and_new_identity_pubkeys_identical",
            ),
        ));
    }

    let record = IdentityRotationRecord {
        version: AUTHORIZATION_WIRE_VERSION,
        old_identity_pubkey,
        new_identity_pubkey,
        rotation_timestamp,
        rotation_reason,
        old_identity_signature,
        new_identity_signature,
        code_recovery_public_half_proof,
    };

    // Defence-in-depth pre-publish verify (постулат 14): catches caller
    // errors (wrong signatures, mismatched canonical input) before they
    // burn a publish attempt and confuse downstream KT log state.
    record.verify().map_err(|backup_err| {
        ClientError::Internal(format!(
            "identity rotation record local verify failed pre-publish — \
             signatures do not validate over canonical input \
             (likely caller-side signing error): {backup_err}"
        ))
    })?;

    let wire = encode_kt_entry_identity_rotation(&record);
    let published_entry_size = wire.len();

    core.kt_transport().publish(wire);

    Ok(RotationOutcome {
        old_identity_pubkey,
        new_identity_pubkey,
        rotation_timestamp,
        published_entry_size,
    })
}
