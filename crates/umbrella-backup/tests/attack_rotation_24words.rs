//! F-PHD-RETRO-3-E regression-guard: identity rotation hijack via 24-words leak.
//!
//! Historically (pre-fix) this test demonstrated that
//! `IdentityRotationRecord::verify` accepted a rotation signed with a
//! **leaked** old identity_sk plus a **fresh** new identity_sk generated
//! locally by an adversary, because the canonical signing input did not
//! cover any knowledge factor beyond the two identity keys themselves.
//!
//! Post-fix the canonical signing input includes
//! `code_recovery_public_half_proof` — a 32-byte HKDF-SHA512 derivation
//! from the 12-word recovery mnemonic (see
//! `CodeRecoveryMnemonic::public_half_proof`). An adversary with **only**
//! the 24 words cannot recompute this value, so any rotation record they
//! forge will carry a proof that differs from the one stored in KT at
//! bootstrap. The mock KT applier below checks bit-equality of the proof
//! against the stored value and rejects the rotation with
//! `KtError::CodeRecoveryProofMismatch`.
//!
//! See `docs/audits/security-hardening-audit-2026-05-17.md` §F-PHD-RETRO-3-E
//! and `docs/superpowers/specs/2026-05-18-fix-rotation-12words-binding.md`.

use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};

use umbrella_backup::cloud_wrap::{
    seal_identity_rotation_record, IdentityRotationRecord, RotationReason,
};
use umbrella_backup::BackupError;
use umbrella_identity::{CodeRecoveryMnemonic, MnemonicLanguage};

const DEVICE_SIG_LEN: usize = 64;

fn fresh_signing_key() -> SigningKey {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    SigningKey::from_bytes(&secret)
}

fn sign_with(
    sk: &SigningKey,
) -> impl FnOnce(&[u8]) -> Result<[u8; DEVICE_SIG_LEN], BackupError> + '_ {
    move |message: &[u8]| Ok(sk.sign(message).to_bytes())
}

fn fresh_code_recovery_mnemonic() -> CodeRecoveryMnemonic {
    let mut rng = OsRng;
    CodeRecoveryMnemonic::generate(&mut rng, MnemonicLanguage::English)
}

/// Mock KT-level acceptance check abstracted from the full `apply_identity_rotation`
/// pipeline. Matches the semantics of the production check: bit-equal compare
/// of the rotation record's `code_recovery_public_half_proof` against the
/// `expected_proof` recorded in KT at bootstrap. Returns `Ok(())` on match,
/// `Err(MockKtError::CodeRecoveryProofMismatch)` on mismatch.
#[derive(Debug, PartialEq, Eq)]
enum MockKtError {
    DualSignatureFailed,
    CodeRecoveryProofMismatch,
}

fn mock_apply_rotation(
    rotation: &IdentityRotationRecord,
    expected_proof: &[u8; 32],
) -> Result<(), MockKtError> {
    // First the dual-signature gate (identical to production `verify`).
    rotation
        .verify()
        .map_err(|_| MockKtError::DualSignatureFailed)?;

    // F-PHD-RETRO-3-E: bit-equal compare of the public_half_proof.
    if rotation.code_recovery_public_half_proof() != expected_proof {
        return Err(MockKtError::CodeRecoveryProofMismatch);
    }

    Ok(())
}

/// REGRESSION attack scenario (post-fix): adversary получает 24-words
/// утечкой (e.g., фото бумажки в облаке), генерирует **fresh** new
/// identity локально, собирает rotation record. **Без 12 слов** он не
/// может посчитать `code_recovery_public_half_proof`, поэтому подставляет
/// нули (либо любые adversary-controlled bytes). KT-уровневая проверка
/// блокирует: stored public_half_proof != adversary's zeros.
///
/// Severity: **High** (architectural abstraction gap closed by
/// F-PHD-RETRO-3-E fix).
///
/// Mitigation: `IdentityRotationRecord::code_recovery_public_half_proof`
/// поле + canonical signing input включает proof + KT applier сравнивает
/// proof с stored `public_half_proof` на bit-equal level.
#[test]
fn regression_attack_rotation_via_leaked_24_words_alone_now_blocked() {
    // Victim setup: legitimate 24-words identity + 12-words recovery code.
    let leaked_old_identity_sk = fresh_signing_key();
    let old_identity_pubkey = leaked_old_identity_sk.verifying_key().to_bytes();
    let victim_code_recovery = fresh_code_recovery_mnemonic();
    let account: u32 = 0;
    let victim_expected_proof = victim_code_recovery.public_half_proof(account);

    // Adversary локально генерирует FRESH new identity_sk — ничего не зная
    // про victim's 12-words code recovery либо active devices.
    let adversary_new_identity_sk = fresh_signing_key();
    let new_identity_pubkey = adversary_new_identity_sk.verifying_key().to_bytes();

    // Adversary builds rotation record using ТОЛЬКО:
    // 1. Leaked old_identity_sk (24-words derive)
    // 2. His own fresh adversary_new_identity_sk
    // 3. Adversary-chosen `code_recovery_public_half_proof` (zeros — он
    //    не знает 12 слов и не может посчитать правильный proof).
    let adversary_chosen_proof: [u8; 32] = [0u8; 32];
    let rotation: IdentityRotationRecord = seal_identity_rotation_record(
        old_identity_pubkey,
        new_identity_pubkey,
        1_700_000_000_000, // arbitrary timestamp
        RotationReason::CatastrophicRecovery,
        adversary_chosen_proof,
        sign_with(&leaked_old_identity_sk),
        sign_with(&adversary_new_identity_sk),
    )
    .expect("seal accepts adversary keys");

    // SECURITY-RELEVANT ASSERTION:
    // dual-signature gate alone still passes (adversary имеет обе подписи),
    // но stored public_half_proof проверка блокирует.
    rotation
        .verify()
        .expect("dual-signature gate passes — adversary has both keys");

    let result = mock_apply_rotation(&rotation, &victim_expected_proof);
    assert_eq!(
        result,
        Err(MockKtError::CodeRecoveryProofMismatch),
        "F-PHD-RETRO-3-E regression: rotation hijack via leaked 24-words alone \
         must now be blocked by code_recovery_public_half_proof mismatch. \
         Adversary cannot recompute the proof without 12 words."
    );

    eprintln!(
        "F-PHD-RETRO-3-E regression-guard PASSED: attack blocked at KT proof check — \
         stored proof={:02x?} adversary proof={:02x?}",
        &victim_expected_proof[..4],
        &adversary_chosen_proof[..4]
    );
}

/// Companion test: same attack pattern с reason=PlannedRotation также
/// блокируется. KT proof check не зависит от rotation_reason.
#[test]
fn regression_attack_rotation_via_leaked_24_words_planned_rotation_blocked() {
    let leaked_old_sk = fresh_signing_key();
    let adversary_new_sk = fresh_signing_key();
    let victim_code_recovery = fresh_code_recovery_mnemonic();
    let victim_expected_proof = victim_code_recovery.public_half_proof(0);

    let rotation: IdentityRotationRecord = seal_identity_rotation_record(
        leaked_old_sk.verifying_key().to_bytes(),
        adversary_new_sk.verifying_key().to_bytes(),
        1_700_000_001_000,
        RotationReason::PlannedRotation,
        [0u8; 32], // adversary не знает victim's 12 слов
        sign_with(&leaked_old_sk),
        sign_with(&adversary_new_sk),
    )
    .expect("seal accepts adversary keys for any rotation_reason");

    assert_eq!(
        mock_apply_rotation(&rotation, &victim_expected_proof),
        Err(MockKtError::CodeRecoveryProofMismatch),
        "PlannedRotation reason тоже блокируется через proof mismatch"
    );
}

/// Positive-path test: legitimate rotation с правильным
/// `code_recovery_public_half_proof` принимается. Это противоположный
/// случай — пользователь, реально владеющий 12 словами, может
/// корректно отротировать identity.
#[test]
fn legitimate_rotation_with_correct_proof_succeeds() {
    let old_sk = fresh_signing_key();
    let new_sk = fresh_signing_key();
    let code_recovery = fresh_code_recovery_mnemonic();
    let account: u32 = 0;
    let stored_proof = code_recovery.public_half_proof(account);

    // Пользователь имеет 12 слов, считает тот же proof, и собирает rotation.
    let user_computed_proof = code_recovery.public_half_proof(account);
    assert_eq!(
        user_computed_proof, stored_proof,
        "public_half_proof must be deterministic given the same code + account"
    );

    let rotation: IdentityRotationRecord = seal_identity_rotation_record(
        old_sk.verifying_key().to_bytes(),
        new_sk.verifying_key().to_bytes(),
        1_700_000_005_000,
        RotationReason::CatastrophicRecovery,
        user_computed_proof,
        sign_with(&old_sk),
        sign_with(&new_sk),
    )
    .expect("seal");

    mock_apply_rotation(&rotation, &stored_proof)
        .expect("legitimate rotation with correct proof must succeed");
}

/// Negative-path test: adversary имеет 24 слова **и** угадывает **неправильные**
/// 12 слов (e.g., свои собственные). Сервер блокирует: его `public_half_proof`
/// detеrministически отличается от victim's stored proof.
#[test]
fn attack_rotation_with_wrong_12_words_commitment_blocked() {
    let leaked_old_sk = fresh_signing_key();
    let adversary_new_sk = fresh_signing_key();
    let victim_code = fresh_code_recovery_mnemonic();
    let adversary_code = fresh_code_recovery_mnemonic();
    let account: u32 = 0;

    let stored_victim_proof = victim_code.public_half_proof(account);
    let adversary_computed_proof = adversary_code.public_half_proof(account);

    // Adversary using HIS OWN 12 words (different entropy) — produces a
    // valid-looking but mismatched proof.
    assert_ne!(
        stored_victim_proof, adversary_computed_proof,
        "different 12-words must produce different proofs"
    );

    let rotation: IdentityRotationRecord = seal_identity_rotation_record(
        leaked_old_sk.verifying_key().to_bytes(),
        adversary_new_sk.verifying_key().to_bytes(),
        1_700_000_006_000,
        RotationReason::CatastrophicRecovery,
        adversary_computed_proof,
        sign_with(&leaked_old_sk),
        sign_with(&adversary_new_sk),
    )
    .expect("seal");

    assert_eq!(
        mock_apply_rotation(&rotation, &stored_victim_proof),
        Err(MockKtError::CodeRecoveryProofMismatch),
        "rotation with WRONG 12-words commitment must be blocked"
    );
}

/// Companion test: tampering любого из signatures блокирует на dual-sig
/// gate, не доходя до KT proof check. Это проверяет defense-in-depth:
/// signatures cover the proof field, поэтому свободного выбора proof'a
/// у adversary'а нет.
#[test]
fn rotation_with_tampered_old_signature_fails() {
    let leaked_old_sk = fresh_signing_key();
    let adversary_new_sk = fresh_signing_key();
    let proof = fresh_code_recovery_mnemonic().public_half_proof(0);

    let mut rotation: IdentityRotationRecord = seal_identity_rotation_record(
        leaked_old_sk.verifying_key().to_bytes(),
        adversary_new_sk.verifying_key().to_bytes(),
        1_700_000_002_000,
        RotationReason::CatastrophicRecovery,
        proof,
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
    let proof = fresh_code_recovery_mnemonic().public_half_proof(0);

    let mut rotation: IdentityRotationRecord = seal_identity_rotation_record(
        leaked_old_sk.verifying_key().to_bytes(),
        adversary_new_sk.verifying_key().to_bytes(),
        1_700_000_003_000,
        RotationReason::CatastrophicRecovery,
        proof,
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

/// Defense-in-depth test: adversary пытается подменить proof уже
/// в собранной записи (после seal). Подписи покрывают proof через
/// canonical signing input — `verify` это ловит.
#[test]
fn attack_post_seal_proof_swap_breaks_signatures() {
    let leaked_old_sk = fresh_signing_key();
    let adversary_new_sk = fresh_signing_key();
    let original_proof = [0xAAu8; 32];

    let mut rotation: IdentityRotationRecord = seal_identity_rotation_record(
        leaked_old_sk.verifying_key().to_bytes(),
        adversary_new_sk.verifying_key().to_bytes(),
        1_700_000_004_000,
        RotationReason::CatastrophicRecovery,
        original_proof,
        sign_with(&leaked_old_sk),
        sign_with(&adversary_new_sk),
    )
    .expect("seal");

    // Adversary tries to replace the proof field with a freshly-chosen
    // value that would match the stored KT public_half_proof. The
    // signatures bind to the original proof through canonical signing
    // input — they break.
    rotation.code_recovery_public_half_proof = [0xBBu8; 32];

    assert!(
        rotation.verify().is_err(),
        "post-seal proof swap должна сломать обе подписи (canonical signing input binding)"
    );
}
