//! Facade-level identity-management операции — публикация identity
//! rotation записи в KT log (F-CLIENT-FACADE-1 session 9b, 2026-05-19).
//! Closes the **rotation publish path** at the client side: вне-устройства
//! сгенерированные signatures (под HW-Keystore либо distributed signing
//! либо локальное вычисление, см. design spec Q1) комбинируются с
//! `core.mls_keystore().identity_public()` в полный
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
use crate::keystore::hw_callback::{HwKeyHandle, PersistentKeyStoreCallback};
use crate::keystore::HwBackedKeyStore;
use umbrella_identity::KeyStore;

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
    /// Старый identity pubkey, прочитанный из `core.mls_keystore().identity_public()`
    /// в начале операции. Old identity pubkey, read from
    /// `core.mls_keystore().identity_public()` at the start of the operation.
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
    let old_identity_pubkey = core.mls_keystore().identity_public().to_bytes();

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

/// **F-CLIENT-FACADE-1 session 9d (2026-05-19):** full identity rotation
/// orchestration. Drives the rotation through the HW-backed keystore
/// callback (`Q1 = Option C` per design spec), publishes the resulting
/// `IdentityRotationRecord` to KT, then swaps `core.mls_keystore` to a
/// fresh [`HwBackedKeyStore`] bound to the new HW handle. Returns
/// [`RotationOutcomeFull`] holding both the published outcome and the
/// new HW handle (so callers могут persist the alias / wire native UI).
///
/// **Layered defence-in-depth chain** (5 layers, постулат 14, all
/// fail-closed):
///
/// 1. **Pre-flight `old_pk` cross-check** — read `old_pk` from
///    `core.mls_keystore().identity_public()` AND from
///    `hw_callback.verifying_key(old_identity_handle)`. Refuse with
///    `ClientError::Internal` if they disagree — a state-machine bug
///    where the local keystore and the HW callback see different
///    identities, must be surfaced immediately rather than silently
///    rotating the wrong identity.
/// 2. **Atomic HW rotation** — single call to
///    [`PersistentKeyStoreCallback::rotate_identity`] which generates
///    new identity material in TEE, signs canonical input with old and
///    new keys, returns artifact. New seed never enters Rust heap.
/// 3. **Publish path defence** — delegate to [`rotate_identity_publish`]
///    (session 9b) which performs `record.verify()` over the canonical
///    input + wire-encodes + pushes 235 bytes via `kt_transport.publish`.
///    `verify()` catches any signing inconsistency between facade-built
///    canonical input and HW-callback-built canonical input (this is the
///    primary detection for native-side wire-format drift).
/// 4. **Post-publish keystore swap** — construct fresh
///    [`HwBackedKeyStore`] wrapping new HW handle + new pubkey, atomic
///    `core.swap_mls_keystore(new_keystore)` via the RwLock. After this
///    call `core.mls_keystore().identity_public()` returns the new
///    pubkey — verifies acceptance criterion #9 from design spec.
/// 5. **Outcome bundle** — return [`RotationOutcomeFull`] holding old +
///    new pubkeys + new handle + timestamp + published wire size. The
///    caller (UX layer / FFI) wires this back to native UI for handle
///    persistence + safety-number-changed banner trigger.
///
/// **What this facade DOES NOT do**:
///
/// - **MLS group repair** (design spec Q3 Option I): rotation cascades
///   device-entry revocation under old identity → all MLS groups under
///   that identity need leave/rejoin. Deferred to follow-up session
///   либо post-1.0.0.
/// - **SLH-DSA backup signature** (Q5 deferred): V2 entry coupling
///   deferred — only Ed25519 dual sigs covered.
/// - **`hw_callback` field swap** — `hw_callback` Arc reference stays
///   unchanged (it's the same callback impl that rotated identity;
///   the trait object is correct as-is). The Arc holds a single
///   trait object; rotation does not require a new callback impl.
///
/// **What this facade DOES (closure across sessions 9d + 9e + 9f)**:
///
/// - **Session 9d**: `mls_keystore` swap so
///   `core.mls_keystore().identity_public()` reflects new pubkey.
/// - **Session 9e**: `hw_identity_state` swap so
///   `core.hw_identity_handle()` / `core.identity_verifying_key()` /
///   `core.has_hw_identity()` reflect the new identity. Both fields
///   (`handle` + `verifying_key`) updated under one write-lock for
///   atomic-state semantics — readers never see a
///   `(new_handle, old_vk)` либо `(old_handle, new_vk)` transient.
/// - **Session 9f (NEW)**: `keystore` slot swap (F-IDENT-1 partition
///   invariant) — the canonical `Option<Arc<dyn KeyStore>>` slot also
///   refreshes to the new `HwBackedKeyStore`. The SAME `Arc<dyn
///   KeyStore>` pointer goes into both slots (`mls_keystore` and
///   `keystore`), so post-rotation
///   `Arc::ptr_eq(core.mls_keystore(), core.keystore().unwrap())` —
///   identity-equal references, no duplicate state. All three HW-
///   identity surfaces (`mls_keystore`, `hw_identity_state`,
///   `keystore`) atomic-swap together; the full `ClientCore` is
///   coherent post-rotation.
///
/// # Parameters
///
/// - `core` — target `ClientCore`. `core.mls_keystore()` must currently
///   return identity_public matching `hw_callback.verifying_key(old_handle)`;
///   facade verifies this invariant.
/// - `hw_callback` — the keystore callback. Production caller passes
///   `core.hw_callback.clone().expect("HW-bootstrapped")`; tests pass a
///   mock directly. Decoupling from `core.hw_callback` lets the test rig
///   construct a coherent state (mls_keystore = HwBackedKeyStore wrapping
///   the same mock) without needing a separate `ClientCore` constructor.
/// - `old_identity_handle` — handle to the currently-active HW identity.
///   Production: `core.hw_identity_handle.clone().expect(...)`. Tests:
///   the handle returned by `bootstrap_hw_identity`.
/// - `new_identity_label` — alias under which the native side stores the
///   new identity (e.g. `"xyz.umbrellax.identity.rotated.<ts>"`).
/// - `rotation_reason` — `CatastrophicRecovery` / `PlannedRotation` /
///   `IdentityCompromise` per `RotationReason`.
/// - `rotation_timestamp` — unix-millis moment of rotation. Caller
///   supplied to keep facade deterministic for tests.
/// - `code_recovery_public_half_proof` — 32-byte HKDF-SHA512 of the
///   12-word recovery mnemonic (F-PHD-RETRO-3-E binding). Caller
///   supplies; facade does not derive (12-word mnemonic «никогда на
///   устройстве» per Round-6).
///
/// # Errors
///
/// - `ClientError::Internal("rotation pre-flight: old_identity_pubkey
///   mismatch ...")` — local mls_keystore and HW callback disagree on
///   `old_pk` (layer 1).
/// - `ClientError::Platform(...)` — HW callback `rotate_identity` failed
///   (layer 2; mapped from `HwKeystoreError`).
/// - Any error from [`rotate_identity_publish`] (layer 3):
///   `ClientError::Kt(InvalidAuthorizationEntryWire("old_and_new_identity_pubkeys_identical"))`
///   либо `ClientError::Internal` for sig-verify failure.
/// - `ClientError::Internal("new HwBackedKeyStore construction failed
///   ...")` — new pubkey didn't decode as Ed25519 (layer 4; should not
///   happen for a healthy mock/native impl, but defended).
pub async fn rotate_identity_full(
    core: &Arc<ClientCore>,
    hw_callback: Arc<dyn PersistentKeyStoreCallback>,
    old_identity_handle: HwKeyHandle,
    new_identity_label: impl Into<String>,
    rotation_reason: RotationReason,
    rotation_timestamp: u64,
    code_recovery_public_half_proof: [u8; CODE_RECOVERY_PUBLIC_HALF_PROOF_LEN],
) -> Result<RotationOutcomeFull> {
    let new_identity_label = new_identity_label.into();

    // Layer 1: cross-check `old_pk` consistency between local mls_keystore
    // and HW callback's view of the same handle. Discrepancy here means
    // some prior code path corrupted the state (e.g. failed to swap
    // mls_keystore after a previous rotation, or hw_callback was wired
    // to a different identity than mls_keystore). Refusing prevents
    // signing a rotation record whose `old_identity_pubkey` field does
    // not match what the HW key actually is — which would otherwise
    // either pass verify (if HW happens to sign with matching key) and
    // publish a misleading record, or fail verify and leak the bug
    // through an obscure error path.
    let mls_old_pk = core.mls_keystore().identity_public().to_bytes();
    let hw_old_pk = hw_callback
        .verifying_key(&old_identity_handle)
        .map_err(|err| {
            ClientError::Platform(format!(
                "rotation pre-flight: hw_callback.verifying_key(old_handle) failed: {err}"
            ))
        })?;
    if mls_old_pk != hw_old_pk {
        return Err(ClientError::Internal(format!(
            "rotation pre-flight: old_identity_pubkey mismatch — \
             core.mls_keystore() reports {:?} but hw_callback.verifying_key(old_handle) reports {:?}; \
             refuse to rotate inconsistent state",
            hex_short(&mls_old_pk),
            hex_short(&hw_old_pk),
        )));
    }
    let old_identity_pubkey = mls_old_pk;

    // Layer 2: atomic HW rotation. Returns new handle + new pubkey + both
    // signatures. New seed material stays in TEE.
    let artifact = hw_callback
        .rotate_identity(
            &old_identity_handle,
            new_identity_label.clone(),
            old_identity_pubkey,
            rotation_timestamp,
            rotation_reason.tag(),
            code_recovery_public_half_proof,
        )
        .map_err(|err| {
            ClientError::Platform(format!(
                "hw_callback.rotate_identity failed: {err} — \
                 native side may be left in half-rotated state, \
                 client retry behaviour is up to the caller"
            ))
        })?;

    // Layer 3: delegate publish path to session 9b. record.verify() inside
    // catches any wire-format / canonical-input drift between this Rust
    // side and the native HW side (the strongest defence against
    // protocol divergence). Layer 3 also handles the identical-pubkey
    // check via session 9b's existing fail-closed guard.
    let publish_outcome = rotate_identity_publish(
        core,
        artifact.new_identity_pubkey,
        rotation_reason,
        rotation_timestamp,
        code_recovery_public_half_proof,
        artifact.old_identity_signature,
        artifact.new_identity_signature,
    )
    .await?;

    // Layer 4: construct new HwBackedKeyStore + atomic swap. The new
    // keystore returns `artifact.new_identity_pubkey` from
    // `identity_public()` and routes signing through `hw_callback` with
    // the new handle. account index preserved (Block 7.2 single-device
    // single-account assumption); future multi-account/multi-device
    // rotation will revisit this.
    //
    // **Why HwBackedKeyStore** (not a new InMemoryKeyStore): the new
    // identity SK lives in TEE; we have no seed material on the Rust
    // side from which to construct an InMemoryKeyStore. HwBackedKeyStore
    // is the canonical wrap of "identity in TEE, public material cached"
    // semantics. Limitations of HwBackedKeyStore (no device APIs, no
    // x25519, no PQ) are documented in the module-level docs of
    // `keystore/hw_backed.rs`; production callers must follow up with
    // device-key bootstrap separately (F-IDENT-DEVICE-1 v1.2.x scope).
    let account = core.mls_keystore().account();
    let new_hw_keystore = HwBackedKeyStore::new(
        account,
        hw_callback.clone(),
        artifact.new_identity_handle.clone(),
        artifact.new_identity_pubkey,
    )
    .map_err(|err| {
        ClientError::Internal(format!(
            "post-rotation HwBackedKeyStore construction failed — \
             new_identity_pubkey returned by HW callback did not decode as Ed25519: {err}"
        ))
    })?;
    let new_keystore: Arc<dyn KeyStore> = Arc::new(new_hw_keystore);
    core.swap_mls_keystore(new_keystore.clone());

    // **F-CLIENT-FACADE-1 session 9f (2026-05-19):** also refresh the
    // canonical `keystore` slot (F-IDENT-1 partition invariant) with
    // the SAME `Arc<dyn KeyStore>` reference. Without this the slot
    // would hold a stale `HwBackedKeyStore` bound to the pre-rotation
    // handle while `core.mls_keystore()` returns the post-rotation
    // keystore — split-state bug for any Block 7.4+ facade that reads
    // from `core.keystore()`. Re-uses the new Arc rather than building
    // a second HwBackedKeyStore instance so both accessors return
    // identity-equal (`Arc::ptr_eq`) pointers, simplifying future
    // refactor that merges the two slots.
    core.swap_keystore(Some(new_keystore));

    // **F-CLIENT-FACADE-1 session 9e (2026-05-19):** also refresh the
    // HW identity state atomically so subsequent
    // `core.hw_identity_handle()` / `core.identity_verifying_key()` /
    // `core.has_hw_identity()` reads reflect the new identity. This
    // closes the session-9d deferral («hw_callback / hw_identity_handle /
    // hw_verifying_key fields not mutated by this facade»). The swap
    // updates `handle` + `verifying_key` together under one write-lock —
    // no transient `(new_handle, old_vk)` либо `(old_handle, new_vk)`
    // observable by concurrent readers.
    //
    // Note: `core.hw_callback` field intentionally NOT swapped — the
    // callback impl is the same one that performed the rotation, so
    // the trait object reference is correct as-is. Re-assigning it
    // would require another RwLock wrap that has no protocol motivation.
    core.swap_hw_identity(
        artifact.new_identity_handle.clone(),
        artifact.new_identity_pubkey,
    );

    // Layer 5: build outcome bundle.
    Ok(RotationOutcomeFull {
        old_identity_pubkey,
        new_identity_pubkey: artifact.new_identity_pubkey,
        new_identity_handle: artifact.new_identity_handle,
        rotation_timestamp,
        published_entry_size: publish_outcome.published_entry_size,
    })
}

/// **F-CLIENT-FACADE-1 session 9d (2026-05-19):** result of a successful
/// [`rotate_identity_full`] call. Extends the publish-only
/// [`RotationOutcome`] (session 9b) with the new HW handle so that
/// callers (FFI / UX layer) can persist the native-side alias and wire
/// follow-up native UI (safety-number-changed banner, post-rotation
/// device-key bootstrap, etc.).
#[derive(Debug, Clone)]
pub struct RotationOutcomeFull {
    /// Old identity pubkey at the moment of rotation (read from local
    /// mls_keystore + cross-checked with HW callback verifying_key).
    pub old_identity_pubkey: [u8; DEVICE_PUBKEY_LEN],
    /// New identity pubkey returned by `hw_callback.rotate_identity` —
    /// also reflected in `core.mls_keystore().identity_public()` after
    /// the post-publish swap.
    pub new_identity_pubkey: [u8; DEVICE_PUBKEY_LEN],
    /// Opaque alias of the new TEE-resident identity. Caller persists
    /// this so subsequent app restarts re-bootstrap against the rotated
    /// identity (production: stored in app local settings; tests: held
    /// in scope для assertions).
    pub new_identity_handle: HwKeyHandle,
    /// Rotation timestamp echoed from the call site (unix millis).
    pub rotation_timestamp: u64,
    /// Size of the published wire frame (always `235` for
    /// `IdentityRotation` per ADR-008 EntryType 0x06; returned для
    /// observability / тест assertions).
    pub published_entry_size: usize,
}

/// Short-hex pretty-printer for error diagnostics. NOT for production
/// logging (full pubkeys are public-by-definition; this is only used in
/// error messages where space matters).
fn hex_short(bytes: &[u8; DEVICE_PUBKEY_LEN]) -> String {
    let prefix: String = bytes.iter().take(4).map(|b| format!("{b:02x}")).collect();
    let suffix: String = bytes
        .iter()
        .rev()
        .take(4)
        .rev()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{prefix}…{suffix}")
}
