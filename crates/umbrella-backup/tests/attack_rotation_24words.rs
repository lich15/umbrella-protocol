//! F-PHD-RETRO-3-E regression-guard: identity rotation hijack via 24-words leak.
//!
//! Demonstrates that `IdentityRotationRecord::verify` accepts a rotation
//! signed with a **leaked** old identity_sk plus a **fresh** new identity_sk
//! generated locally by an adversary.
//!
//! Current state: this attack succeeds (vulnerability). After the
//! follow-up fix (binding 12-words commitment into `canonical_signing_input_rotation`
//! либо requiring active-device co-signature либо platform attestation
//! on rotation submit), this test should FAIL on the verify step — at
//! which point we re-purpose it as a regression-guard.
//!
//! See `docs/audits/security-hardening-audit-2026-05-17.md` §F-PHD-RETRO-3-E.

use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};

use umbrella_backup::cloud_wrap::{
    seal_identity_rotation_record, IdentityRotationRecord, RotationReason,
};
use umbrella_backup::BackupError;

const DEVICE_SIG_LEN: usize = 64;

fn fresh_signing_key() -> SigningKey {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    SigningKey::from_bytes(&secret)
}

fn sign_with(sk: &SigningKey) -> impl FnOnce(&[u8]) -> Result<[u8; DEVICE_SIG_LEN], BackupError> + '_ {
    move |message: &[u8]| Ok(sk.sign(message).to_bytes())
}

/// PRIMARY attack scenario: adversary получает 24-words утечкой (e.g.,
/// фото бумажки в облаке), генерирует **fresh** new identity локально, и
/// собирает rotation record. Сегодняшняя `verify()` принимает запись.
///
/// Severity: **High** (architectural abstraction gap).
///
/// Mitigation gap: rotation acceptance требует только two Ed25519
/// signatures. NO platform attestation, NO active-device co-signature,
/// NO 12-words binding в canonical signing input.
#[test]
fn attack_rotation_via_leaked_24_words_alone_currently_passes_verify() {
    // Victim's legitimate identity (the "leaked" key — adversary копия).
    let leaked_old_identity_sk = fresh_signing_key();
    let old_identity_pubkey = leaked_old_identity_sk.verifying_key().to_bytes();

    // Adversary локально генерирует FRESH new identity_sk — ничего не зная
    // про victim's 12-words code recovery либо active devices.
    let adversary_new_identity_sk = fresh_signing_key();
    let new_identity_pubkey = adversary_new_identity_sk.verifying_key().to_bytes();

    // Adversary builds rotation record using ТОЛЬКО:
    // 1. Leaked old_identity_sk (24-words derive)
    // 2. His own fresh adversary_new_identity_sk
    //
    // NO: active device sig, platform attestation, 12-words commitment.
    let rotation: IdentityRotationRecord = seal_identity_rotation_record(
        old_identity_pubkey,
        new_identity_pubkey,
        1_700_000_000_000, // arbitrary timestamp
        RotationReason::CatastrophicRecovery,
        sign_with(&leaked_old_identity_sk),
        sign_with(&adversary_new_identity_sk),
    )
    .expect("seal accepts adversary keys");

    // SECURITY-RELEVANT ASSERTION:
    // Current behavior — verify() PASSES. After the proposed fix (12-words
    // binding либо attestation либо active-device co-sign), this should
    // FAIL.
    let verify_result = rotation.verify();

    assert!(
        verify_result.is_ok(),
        "Current state: rotation hijack via leaked 24-words alone passes verify(). \
         If this assertion FAILS, the F-PHD-RETRO-3-E fix has landed and this \
         test should be re-purposed as a regression-guard for the fix."
    );

    // Document the gap explicitly for grep'ability в reviews:
    eprintln!(
        "F-PHD-RETRO-3-E reproduced: rotation hijack via leaked 24-words alone \
         passed verify() — old_pk={:02x?}, new_pk={:02x?}, reason=CatastrophicRecovery",
        &old_identity_pubkey[..4],
        &new_identity_pubkey[..4]
    );
}

/// Companion test: same attack pattern с reason=PlannedRotation должна
/// behave идентично (no rotation_reason gate на acceptance).
#[test]
fn attack_rotation_via_leaked_24_words_planned_rotation_also_passes() {
    let leaked_old_sk = fresh_signing_key();
    let adversary_new_sk = fresh_signing_key();

    let rotation: IdentityRotationRecord = seal_identity_rotation_record(
        leaked_old_sk.verifying_key().to_bytes(),
        adversary_new_sk.verifying_key().to_bytes(),
        1_700_000_001_000,
        RotationReason::PlannedRotation,
        sign_with(&leaked_old_sk),
        sign_with(&adversary_new_sk),
    )
    .expect("seal accepts adversary keys for any rotation_reason");

    assert!(
        rotation.verify().is_ok(),
        "PlannedRotation reason тоже не блокирует hijack — acceptance gate \
         не зависит от rotation_reason."
    );
}

/// Companion test: tampering любого из signatures блокирует. Это
/// проверяет что hijack действительно требует ОБА valid signatures
/// (adversary должен иметь оба ключа либо leaked oldsk + способность
/// generate fresh newsk).
#[test]
fn rotation_with_tampered_old_signature_fails() {
    let leaked_old_sk = fresh_signing_key();
    let adversary_new_sk = fresh_signing_key();

    let mut rotation: IdentityRotationRecord = seal_identity_rotation_record(
        leaked_old_sk.verifying_key().to_bytes(),
        adversary_new_sk.verifying_key().to_bytes(),
        1_700_000_002_000,
        RotationReason::CatastrophicRecovery,
        sign_with(&leaked_old_sk),
        sign_with(&adversary_new_sk),
    )
    .expect("seal");

    // Flip a bit in old signature.
    rotation.old_identity_signature[0] ^= 0x01;

    assert!(
        rotation.verify().is_err(),
        "tampered old_signature должна провалить verify"
    );
}

/// Companion: tampering new signature also fails.
#[test]
fn rotation_with_tampered_new_signature_fails() {
    let leaked_old_sk = fresh_signing_key();
    let adversary_new_sk = fresh_signing_key();

    let mut rotation: IdentityRotationRecord = seal_identity_rotation_record(
        leaked_old_sk.verifying_key().to_bytes(),
        adversary_new_sk.verifying_key().to_bytes(),
        1_700_000_003_000,
        RotationReason::CatastrophicRecovery,
        sign_with(&leaked_old_sk),
        sign_with(&adversary_new_sk),
    )
    .expect("seal");

    rotation.new_identity_signature[63] ^= 0xFF;

    assert!(
        rotation.verify().is_err(),
        "tampered new_signature должна провалить verify"
    );
}
