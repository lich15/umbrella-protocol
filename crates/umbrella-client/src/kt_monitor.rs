//! Facade-level Key Transparency self-monitoring (F-CLIENT-FACADE-1 session
//! 8a, 2026-05-19). Closes the **ghost participant** attack (Levy & Robinson,
//! Lawfare 2018 — GCHQ "exceptional access" proposal) at the client side: the
//! client knows its own identity_pks + active device-keys, fetches what the
//! KT log claims for its account_id, and `verify_own_entry`-compares the two.
//! Any divergence → `ClientError::Kt(KtError::SelfMonitoringMismatch { field
//! })` with no silent acceptance (постулат 14).
//!
//! ## Scope of session 8a
//!
//! - **In scope**: on-demand `verify_own_kt_entry_for_epoch` against
//!   [`crate::transport::stub::StubKtTransport::fetch_staged_entry`] —
//!   typed-value path для facade integration tests. Construct
//!   `OwnExpectations` из `core.mls_keystore.identity_public()` +
//!   `identity_x25519_public()` + single device `(0, device_public(0))`
//!   (Block 7.2 single-device).
//! - **Deferred to session 8b**: 3-of-5 witness signature verification
//!   (`umbrella_kt::witness::verify_signed_epoch` + `StubKtTransport`
//!   signed-roots staging) — отдельный helper
//!   `verify_kt_witness_signatures_for_epoch`.
//! - **Deferred to session 8c**: periodic monitor tokio task (using
//!   `ClientConfig.kt_monitor_interval_secs = 3600`) + lifecycle management
//!   (cancel on `clear_gateway` / `Drop` of `ClientCore`) + production
//!   `Http2KtTransport` wire-up (replaces stub).
//! - **Deferred to session 8c+**: KT V2 hybrid-identity entry monitoring
//!   (`umbrella_kt::HybridOwnExpectations` + `verify_own_v2_entry` под
//!   feature `pq`) — PQ-режим monitor расширение.
//!
//! ## Threat model
//!
//! SPEC-09 §6 self-monitoring: client mirrors KT log of own account and
//! periodically (либо on-demand here) verifies the log entry matches what it
//! published. Three classes of attack are detected:
//!
//! 1. **Identity substitution**: log shows different `identity_ed25519_pub` /
//!    `identity_x25519_pub` than client published → ghost participant. MLS
//!    member with wrong identity_pk = adversary-controlled credential in
//!    group's ratchet tree.
//! 2. **Device substitution / injection**: log shows foreign `device_pub`
//!    либо missing one of client's devices → MitM via injected device-key.
//!    Adversary's device decrypts subsequent group messages.
//! 3. **account_id mismatch**: log shows different `account_id` for same
//!    `identity_ed25519_pub` → log corruption либо identity rotation
//!    inconsistency.
//!
//! Все три surface'ятся через `KtError::SelfMonitoringMismatch { field }`
//! где `field` указывает specifically какое поле mismatch'ed.

use std::sync::Arc;

use umbrella_kt::{verify_own_entry, KtEntry, KtError, OwnExpectations};

use crate::core::ClientCore;
use crate::error::{ClientError, Result};

/// **F-CLIENT-FACADE-1 session 8a (2026-05-19):** verify Alice's own KT entry
/// для epoch against локальных expectations. Alice знает свой
/// `identity_ed25519_pub` (через `core.mls_keystore`), `identity_x25519_pub`
/// (тот же keystore), и собственный список `device_index = 0` (Block 7.2
/// single-device). Fetch'ит entry из [`crate::transport::stub::StubKtTransport::fetch_staged_entry`]
/// под `(account_id = SHA-256(identity_ed25519_pub), epoch)`; если entry
/// staged — `verify_own_entry` сравнивает byte-by-byte; mismatch → fail-closed
/// `ClientError::Kt(KtError::SelfMonitoringMismatch { field })`.
///
/// **Fail-closed на отсутствие entry**: если stub не staged ничего под
/// `(account_id, epoch)`, helper возвращает `SelfMonitoringMismatch { field:
/// "entry_absent_from_log" }`. Production интерпретация: server cannot serve
/// Alice's published entry — либо censorship attack, либо Alice не публиковала
/// для этого epoch (UI distinction вне scope session 8a; surface как mismatch
/// и пусть caller treat'ает по своему usage pattern).
///
/// **Device list assumption**: Block 7.2 single-device (`device_index = 0`
/// только). Multi-device monitoring (`device_index` 0..15 per SPEC-11 §4)
/// добавляется в session 8c когда `core.mls_keystore` начнёт держать
/// multi-device state.
///
/// **F-CLIENT-FACADE-1 session 8a:** verify Alice's own KT entry for the
/// given epoch against expectations derived from `core.mls_keystore`.
/// Fail-closed on absence (`entry_absent_from_log`) or any field mismatch.
///
/// # Errors
///
/// - `ClientError::Kt(KtError::SelfMonitoringMismatch { field })` если:
///   - `field = "entry_absent_from_log"` — stub returned `None` for the
///     requested `(account_id, epoch)`.
///   - `field = "identity_ed25519_pub"` — entry's identity_ed25519_pub
///     differs from `core.mls_keystore.identity_public()`.
///   - `field = "identity_x25519_pub"` — analogous для X25519.
///   - `field = "account_id"` — entry's account_id ≠ derive_account_id(
///     identity_ed25519_pub).
///   - `field = "device_count" / "device_set_missing_expected" /
///     "device_set_unexpected_entry"` — device-set mismatch.
pub async fn verify_own_kt_entry_for_epoch(core: &Arc<ClientCore>, epoch: u64) -> Result<()> {
    let identity_ed25519 = core.mls_keystore.identity_public();
    let identity_x25519 = core.mls_keystore.identity_x25519_public();
    let account_id = KtEntry::derive_account_id(&identity_ed25519);

    let entry: KtEntry = core
        .kt_transport
        .fetch_staged_entry(&account_id, epoch)
        .ok_or(ClientError::Kt(KtError::SelfMonitoringMismatch {
            field: "entry_absent_from_log",
        }))?;

    // Block 7.2 single-device assumption: device_index = 0 only. KeyStore
    // trait returns `Option<DeviceKeyPublic>` для `device_public(index)`;
    // device 0 регистрируется в `ClientCore::new_for_test` через
    // `InMemoryKeyStore::add_device(0, None)`. Missing device_public(0)
    // here is an invariant violation (bootstrap broken), surfaced as
    // ClientError::Internal — НЕ KtError, потому что это локальная
    // bootstrap inconsistency, не KT log issue.
    //
    // Block 7.2 single-device: device_index 0 only. Missing device_public(0)
    // is a bootstrap invariant violation, not a KT log issue → Internal.
    let device_pub = core.mls_keystore.device_public(0).ok_or_else(|| {
        ClientError::Internal(
            "ClientCore bootstrap invariant violation: device_public(0) is None — \
                 KT self-monitoring requires at least the primary device registered \
                 in mls_keystore"
                .to_string(),
        )
    })?;

    let devices: [(u32, umbrella_identity::DeviceKeyPublic); 1] = [(0u32, device_pub)];
    let expected = OwnExpectations {
        identity_ed25519: &identity_ed25519,
        identity_x25519: &identity_x25519,
        devices: &devices,
    };

    verify_own_entry(&entry, &expected).map_err(ClientError::Kt)
}
