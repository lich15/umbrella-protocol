//! Block 10.9-active-retro PhD-level real cryptanalysis pass для umbrella-kt
//! (session #68 на дату 2026-05-08). Strategy B PhD level mandatory per memory
//! public high-assurance audit policy (session #65c) + formal-model review policy
//! (session #66) + real-attack naming policy (session #66).
//!
//! Block 10.9-active-retro PhD-level real cryptanalysis pass for umbrella-kt
//! (session #68 dated 2026-05-08). Strategy B PhD level mandatory per memory
//! public high-assurance audit policy (session #65c) + the two follow-up rules.
//!
//! ## Что отличает PhD level от A level в этом файле
//!
//! Каждый `attack_*` test содержит **explicit attack vector comment** с тремя
//! разделами: Setup (что adversary делает) + Hypothesis (что должно блокировать
//! атаку) + Defense (на каком SPEC / cryptographic reduction базируется
//! защита). Тесты атакуют production API напрямую через адверсариальные
//! последовательности вызовов; они не упрощают сценарий до boundary check.
//!
//! ## What separates PhD level from A level here
//!
//! Each `attack_*` test carries an **explicit attack vector comment** with
//! three sections: Setup (what the adversary does) + Hypothesis (what should
//! block the attack) + Defense (which SPEC / cryptographic reduction grounds
//! the protection). Tests exercise the production API directly through
//! adversarial call sequences; they do not collapse the scenario to a boundary
//! check.
//!
//! ## SPEC-01 § 4 угрозы applicable к umbrella-kt scope
//!
//! - **Row 3** «Ghost participant» — primary scope; KT log substitution detection.
//! - **Row 4** «Forking (split-view)» — primary scope; client A vs client B different epoch_root.
//! - Row 12 «KCI» — secondary scope; multi-witness threshold.
//! - Row 11 «Cold-boot/forensics» — N/A для umbrella-kt scope (witness keys в Sealed Servers,
//!   не в этом крейте; carry-over к block 10.13/10.14 retros).
//!
//! ## SPEC-01 § 4 threats applicable to umbrella-kt scope
//!
//! See above.

#![cfg(not(miri))] // Ed25519 verification на Curve25519 в miri очень медленный
                   // Ed25519 verification on Curve25519 is very slow under miri

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use umbrella_crypto_primitives::sig::PrivateSigningKey;
use umbrella_kt::{
    apply_authorization_approval, apply_authorization_revocation, apply_identity_rotation,
    canonical_sign_payload, leaf_hash, merkle_root, verify_inclusion, verify_signed_epoch, KtError,
    KtLogState, RotationReason, SignedEpochRoot, WitnessPublic, WitnessSet, WitnessSignature,
    NODE_HASH_LEN,
};

// ---------------------------------------------------------------------------
// Helper структура (test infrastructure)
// Helper structure (test infrastructure)
// ---------------------------------------------------------------------------

const WITNESS_THRESHOLD: usize = 3;
const EPOCH_BASELINE: u64 = 100;
const TIMESTAMP_BASELINE: u64 = 1_700_000_000;

struct Witness {
    sk: PrivateSigningKey,
    pk: WitnessPublic,
}

fn fresh_witness() -> Witness {
    let mut rng = OsRng;
    let sk = PrivateSigningKey::generate(&mut rng);
    let pk = WitnessPublic::from_bytes(sk.verifying_key().to_bytes());
    Witness { sk, pk }
}

fn build_witness_set(ws: &[&Witness]) -> WitnessSet {
    let mut set = WitnessSet::new();
    for w in ws {
        set.add(w.pk);
    }
    set
}

fn random_root() -> [u8; NODE_HASH_LEN] {
    let mut out = [0u8; NODE_HASH_LEN];
    OsRng.fill_bytes(&mut out);
    out
}

fn sign_epoch(witness: &Witness, epoch: u64, root: &[u8; NODE_HASH_LEN]) -> WitnessSignature {
    let payload = canonical_sign_payload(epoch, root, 1, 1_700_000_000_000);
    let sig = witness.sk.sign(&payload);
    WitnessSignature {
        witness: witness.pk,
        signature: sig.to_bytes(),
    }
}

// ---------------------------------------------------------------------------
// Attack 1 — ghost participant + 2-of-5 witness compromise
// ---------------------------------------------------------------------------
//
// PhD-level attack scenario per SPEC-01 § 4 row 3 «Ghost participant».
//
// Setup: Adversary имеет access к 2 of 5 multi-witness private keys (insider
// attack 1 jurisdiction + 1 compromised witness server organisation).
// Adversary cooperates с malicious key-svc operator чтобы:
// 1. Подделать ghost device entry с substituted device_pubkey
// 2. Sign forged epoch_root через 2 compromised witness keys
// 3. Construct SignedEpochRoot с двумя valid signatures + (попытка) добавить
//    3-ю forged signature от unknown / random witness key (не из witness_set)
// 4. Submit signed epoch к клиенту через malicious log delivery
//
// Hypothesis: 3-of-5 threshold блокирует. Без 3rd genuine signature от
// witness_set member, `verify_signed_epoch` returns
// `InsufficientValidSignatures { valid: 2, required: 3 }`. Random / unknown
// witness signatures fil'тuются на early-iteration check (witness_set.contains
// false → continue без count).
//
// Defense: SPEC-09 §5 multi-witness 3-of-5 threshold + Ed25519 SUF-CMA
// (Brendel-Cremers-Jackson-Zhao 2020 Theorem 2 — security advantage
// ε_SUF-CMA ≤ q_h · 2⁻¹²⁵ + q_s² · 2⁻²⁵⁶ под discrete-log hardness Curve25519
// и Random Oracle Model для SHA-512). Compromise 3rd jurisdiction requires
// coordinated pressure на independent organizations — cost prohibitive.
//
// Failure mode: если threshold counter incorrectly counts unknown-witness
// signatures либо если threshold modified к 2-of-5 на client side, defense
// breaks. Test verifies that:
// (a) 2 valid + 1 unknown_witness → reject
// (b) 2 valid + 1 duplicate → reject (dedup)
// (c) 2 valid + 1 tampered → reject (signature invalid)
// (d) Все 3 partial paths checked individually
//
// PhD-level attack per SPEC-01 § 4 row 3.

#[test]
fn attack_ghost_with_two_of_five_witness_compromise_blocked_by_threshold() {
    let witnesses: Vec<Witness> = (0..5).map(|_| fresh_witness()).collect();
    let unknown_witness = fresh_witness();
    let witness_set = build_witness_set(&witnesses.iter().collect::<Vec<_>>());
    let root = random_root();
    let epoch = EPOCH_BASELINE;

    // (a) Adversary имеет valid signatures от witness 0 + 1 (compromised),
    //     plus добавляет signature от unknown witness (вне witness_set).
    let sig_compromised_0 = sign_epoch(&witnesses[0], epoch, &root);
    let sig_compromised_1 = sign_epoch(&witnesses[1], epoch, &root);
    let sig_unknown_outside_set = sign_epoch(&unknown_witness, epoch, &root);

    let signed_a = SignedEpochRoot {
        epoch,
        root,
        log_size: 1,
        timestamp_unix_millis: 1_700_000_000_000,
        signatures: vec![
            sig_compromised_0,
            sig_compromised_1,
            sig_unknown_outside_set,
        ],
    };
    let result_a = verify_signed_epoch(&signed_a, &witness_set, WITNESS_THRESHOLD);
    assert!(matches!(
        result_a,
        Err(KtError::InsufficientValidSignatures {
            valid: 2,
            required: 3
        })
    ));

    // (b) Adversary дублирует одну valid signature чтобы накачать count.
    let signed_b = SignedEpochRoot {
        epoch,
        root,
        log_size: 1,
        timestamp_unix_millis: 1_700_000_000_000,
        signatures: vec![sig_compromised_0, sig_compromised_0, sig_compromised_1],
    };
    let result_b = verify_signed_epoch(&signed_b, &witness_set, WITNESS_THRESHOLD);
    assert!(matches!(
        result_b,
        Err(KtError::InsufficientValidSignatures {
            valid: 2,
            required: 3
        })
    ));

    // (c) Adversary добавляет 3rd signature но tampered — Ed25519 verify rejects.
    let mut sig_tampered = sign_epoch(&witnesses[2], epoch, &root);
    sig_tampered.signature[0] ^= 0x01;
    let signed_c = SignedEpochRoot {
        epoch,
        root,
        log_size: 1,
        timestamp_unix_millis: 1_700_000_000_000,
        signatures: vec![sig_compromised_0, sig_compromised_1, sig_tampered],
    };
    let result_c = verify_signed_epoch(&signed_c, &witness_set, WITNESS_THRESHOLD);
    assert!(matches!(
        result_c,
        Err(KtError::InsufficientValidSignatures {
            valid: 2,
            required: 3
        })
    ));

    // (d) Sanity: 3 valid signatures от distinct witness_set members → accept.
    let sig_ok_2 = sign_epoch(&witnesses[2], epoch, &root);
    let signed_d = SignedEpochRoot {
        epoch,
        root,
        log_size: 1,
        timestamp_unix_millis: 1_700_000_000_000,
        signatures: vec![sig_compromised_0, sig_compromised_1, sig_ok_2],
    };
    verify_signed_epoch(&signed_d, &witness_set, WITNESS_THRESHOLD)
        .expect("3 distinct valid signatures должны pass'нуть threshold");
}

// ---------------------------------------------------------------------------
// Attack 2 — split-view forking detection через distinct safety numbers
// ---------------------------------------------------------------------------
//
// PhD-level attack scenario per SPEC-01 § 4 row 4 «Forking (split-view)».
//
// Setup: Adversary controls KT log delivery service. Configures two distinct
// epoch_root values для SAME epoch_id=100:
// - epoch_root_A served к client Alice (содержит legitimate device entries)
// - epoch_root_B served к client Bob (содержит ghost device entry для Alice)
//
// Both signed by witness_set 3-of-5 threshold (adversary controls 3 jurisdictions
// либо each delivers signatures к different clients selectively). Alice and
// Bob each verify their own signed epoch — both pass `verify_signed_epoch`.
//
// Hypothesis: out-of-band fingerprint check (UI safety-number compare либо
// QR scan secondary channel) detects mismatch. SHA-256(epoch || root) дает
// distinct safety_numbers byte-for-byte для distinct roots.
//
// Defense: SPEC-09 §5.5 — split-view requires compromise 3 of 5 independent
// jurisdictions. Out-of-band channel (Signal-style safety number compare)
// catches forking even если все witnesses compromised. SHA-256 collision
// resistance ε ≤ 2⁻¹²⁸ (birthday bound NIST FIPS 180-4) гарантирует что
// distinct roots дают distinct safety_numbers.
//
// Failure mode: если safety_number derivation использует weak hash либо
// truncation бьёт под threshold collision birthday bound, защита breaks.
// Test verifies byte-distinct safety_numbers + collision rate over 1000
// random forked pairs.
//
// PhD-level attack per SPEC-01 § 4 row 4.

#[test]
fn attack_split_view_forking_distinct_safety_numbers_detect_mismatch() {
    fn safety_number(epoch: u64, root: &[u8; NODE_HASH_LEN]) -> [u8; 32] {
        // Reuse canonical_sign_payload format чтобы symmetric с witness signature
        // payload — оба binding одинаковые input domain.
        let payload = canonical_sign_payload(epoch, root, 1, 1_700_000_000_000);
        let mut digest = Sha256::new();
        digest.update(&payload);
        let out = digest.finalize();
        let mut safety = [0u8; 32];
        safety.copy_from_slice(&out);
        safety
    }

    let epoch = EPOCH_BASELINE;
    let root_alice = random_root();
    let root_bob = random_root();
    assert_ne!(root_alice, root_bob, "fresh roots должны быть distinct");

    let sn_alice = safety_number(epoch, &root_alice);
    let sn_bob = safety_number(epoch, &root_bob);

    // (a) Distinct roots → distinct safety_numbers byte-for-byte.
    assert_ne!(sn_alice, sn_bob);

    // (b) Same epoch + same root → identical safety_number (deterministic).
    let sn_alice_2 = safety_number(epoch, &root_alice);
    assert_eq!(sn_alice, sn_alice_2);

    // (c) Different epoch + same root → distinct safety_number (epoch binding).
    let sn_diff_epoch = safety_number(epoch + 1, &root_alice);
    assert_ne!(sn_alice, sn_diff_epoch);

    // (d) Statistical collision rate: 1000 random forked pairs, no collision
    //     expected (probability 2⁻¹²⁸ per pair × 1000 = 2⁻¹¹⁸ overall).
    for _ in 0..1000 {
        let r1 = random_root();
        let r2 = random_root();
        if r1 == r2 {
            continue; // skip identical (extremely rare ~2⁻²⁵⁶)
        }
        let s1 = safety_number(epoch, &r1);
        let s2 = safety_number(epoch, &r2);
        assert_ne!(
            s1, s2,
            "split-view safety_number collision (statistically infeasible)"
        );
    }
}

#[test]
fn threshold_compromised_views_can_verify_but_safety_numbers_diverge() {
    fn safety_number(epoch: u64, root: &[u8; NODE_HASH_LEN]) -> [u8; 32] {
        let payload = canonical_sign_payload(epoch, root, 1, 1_700_000_000_000);
        let mut digest = Sha256::new();
        digest.update(&payload);
        let out = digest.finalize();
        let mut safety = [0u8; 32];
        safety.copy_from_slice(&out);
        safety
    }

    let witnesses: Vec<Witness> = (0..5).map(|_| fresh_witness()).collect();
    let witness_set = build_witness_set(&witnesses.iter().collect::<Vec<_>>());
    let epoch = EPOCH_BASELINE + 7;
    let root_alice = random_root();
    let root_bob = random_root();
    assert_ne!(root_alice, root_bob);

    let signed_alice = SignedEpochRoot {
        epoch,
        root: root_alice,
        log_size: 1,
        timestamp_unix_millis: 1_700_000_000_000,
        signatures: vec![
            sign_epoch(&witnesses[0], epoch, &root_alice),
            sign_epoch(&witnesses[1], epoch, &root_alice),
            sign_epoch(&witnesses[2], epoch, &root_alice),
        ],
    };

    let signed_bob = SignedEpochRoot {
        epoch,
        root: root_bob,
        log_size: 1,
        timestamp_unix_millis: 1_700_000_000_000,
        signatures: vec![
            sign_epoch(&witnesses[0], epoch, &root_bob),
            sign_epoch(&witnesses[1], epoch, &root_bob),
            sign_epoch(&witnesses[2], epoch, &root_bob),
        ],
    };

    verify_signed_epoch(&signed_alice, &witness_set, WITNESS_THRESHOLD)
        .expect("threshold-signed Alice view verifies locally");
    verify_signed_epoch(&signed_bob, &witness_set, WITNESS_THRESHOLD)
        .expect("threshold-signed Bob view verifies locally");

    let alice_safety = safety_number(epoch, &signed_alice.root);
    let bob_safety = safety_number(epoch, &signed_bob.root);
    assert_ne!(
        alice_safety, bob_safety,
        "threshold-compromised split views require external comparison signal"
    );
}

// ---------------------------------------------------------------------------
// Attack 3 — append-only invariant break via Merkle recompute
// ---------------------------------------------------------------------------
//
// PhD-level attack scenario per SPEC-09 §4.4 «Append-only property».
//
// Setup: Adversary имеет write access к KT log storage (например через
// supply chain backdoor). Хочет:
// 1. Удалить старый entry (e.g., entry epoch_id=10 → empty)
// 2. Modify entry content (substitute leaf_hash в epoch_id=15)
// 3. Re-order entries (swap epoch_id=20 with epoch_id=21)
//
// All 3 mutations изменяют Merkle root; published root remains the same под
// witness signatures от honest pre-tamper epoch.
//
// Hypothesis: Merkle root invariant detects all 3 mutations. Recomputed root
// после adversary tampering должен mismatch published root. SHA-256 preimage
// resistance ε ≤ 2⁻²⁵⁶ (FIPS 180-4) гарантирует что adversary не может
// modify entry chain без changing root.
//
// Defense: RFC 6962 Merkle tree structure + SHA-256 collision resistance
// + leaf/inner domain separation (LEAF_PREFIX 0x00 vs INNER_PREFIX 0x01).
// adversary forced либо к (a) finding SHA-256 second preimage (infeasible)
// либо к (b) re-signing root через 3-of-5 witness threshold (cost-prohibitive).
//
// Failure mode: если Merkle layer has a bug в domain separation либо
// recursive split, adversary могла бы construct entries с identical leaf
// hashes. Test verifies all 3 mutations produce distinct roots.

#[test]
fn attack_append_only_break_via_recomputed_merkle_root_detected() {
    // Build legitimate log с 8 leaves (perfect binary tree).
    let leaves: Vec<[u8; 32]> = (0..8u8).map(|i| leaf_hash(&[i, 42])).collect();
    let honest_root = merkle_root(&leaves);

    // (a) Удаление entry — leaves[3] становится empty (zero hash).
    let mut tampered_a = leaves.clone();
    tampered_a[3] = [0u8; 32];
    let root_a = merkle_root(&tampered_a);
    assert_ne!(honest_root, root_a, "deletion должно изменить Merkle root");

    // (b) Modification entry — leaves[5] заменён на adversary's substituted hash.
    let mut tampered_b = leaves.clone();
    tampered_b[5] = leaf_hash(&[5, 99]); // attacker's payload
    let root_b = merkle_root(&tampered_b);
    assert_ne!(
        honest_root, root_b,
        "modification должно изменить Merkle root"
    );

    // (c) Re-ordering entries — swap leaves[2] ↔ leaves[3].
    let mut tampered_c = leaves.clone();
    tampered_c.swap(2, 3);
    let root_c = merkle_root(&tampered_c);
    assert_ne!(
        honest_root, root_c,
        "re-ordering должно изменить Merkle root"
    );

    // (d) Все 3 tampered roots distinct between themselves (атакер не может
    //     finding any two distinct mutations producing same root).
    assert_ne!(root_a, root_b);
    assert_ne!(root_b, root_c);
    assert_ne!(root_a, root_c);

    // (e) Inclusion proof для leaves[3] под honest_root → fails если recompute
    //     root уже tampered (любая из above mutations).
    use umbrella_kt::build_audit_path;
    let path = build_audit_path(&leaves, 3).unwrap();
    // Honest verify works.
    verify_inclusion(&leaves[3], 3, leaves.len() as u64, &path, &honest_root)
        .expect("honest inclusion verify");
    // Tampered root → reject.
    let result = verify_inclusion(&leaves[3], 3, leaves.len() as u64, &path, &root_a);
    assert!(matches!(result, Err(KtError::InclusionRootMismatch)));
}

// ---------------------------------------------------------------------------
// Attack 4 — inclusion proof forge для несуществующего entry
// ---------------------------------------------------------------------------
//
// PhD-level attack scenario per SPEC-09 §4.3 «AuditPath verify».
//
// Setup: Adversary хочет inject ghost device entry «post-hoc» — создать
// inclusion proof что выглядит valid но указывает на entry которого нет в
// actual log. Adversary controls log delivery service:
// 1. Constructs fake leaf_hash для ghost device entry
// 2. Forges audit path с siblings скопированными из legitimate proof для
//    другого index
// 3. Submits к клиенту: «вот proof что ghost device был в epoch_id=42»
//
// Hypothesis: verify_inclusion requires Merkle path к actual published root.
// Без access к full tree forge невозможен — adversary должен either find
// SHA-256 collision (ε ≤ 2⁻¹²⁸ birthday bound) либо partial preimage
// (ε ≤ 2⁻²⁵⁶ FIPS 180-4) для каждого sibling в пути.
//
// Defense: RFC 6962 Merkle tree + SHA-256 preimage resistance. inclusion
// proof verification recomputes root bottom-up через inner_hash; mismatch
// detected via byte-equality check `r != expected_root` → InclusionRootMismatch.
//
// Failure mode: если verify_inclusion имеет early-return bug либо truncation
// в hash compare, forge может pass. Test verifies forge всегда rejected.

#[test]
fn attack_inclusion_proof_forge_for_fake_leaf_rejected_by_root_match() {
    let leaves: Vec<[u8; 32]> = (0..8u8).map(|i| leaf_hash(&[i])).collect();
    let honest_root = merkle_root(&leaves);

    // (a) Adversary attempts forge: fake_leaf не в leaves.
    let fake_leaf = leaf_hash(b"ghost-device-pubkey-32-bytes-of-evil");

    // Adversary copies legitimate audit path для index=4 (хочет claim ghost
    // entry в slot 4).
    use umbrella_kt::build_audit_path;
    let stolen_path = build_audit_path(&leaves, 4).unwrap();

    // Verify должен reject — recomputed root ≠ honest_root.
    let result = verify_inclusion(
        &fake_leaf,
        4,
        leaves.len() as u64,
        &stolen_path,
        &honest_root,
    );
    assert!(matches!(result, Err(KtError::InclusionRootMismatch)));

    // (b) Adversary attempts modified path — siblings tampered.
    let mut tampered_path = stolen_path.clone();
    tampered_path.siblings[0][0] ^= 0x01;
    let result_2 = verify_inclusion(
        &leaves[4],
        4,
        leaves.len() as u64,
        &tampered_path,
        &honest_root,
    );
    assert!(matches!(result_2, Err(KtError::InclusionRootMismatch)));

    // (c) Adversary attempts wrong-length path для existing index.
    let mut wrong_length_path = stolen_path.clone();
    wrong_length_path.siblings.push([0u8; 32]);
    let result_3 = verify_inclusion(
        &leaves[4],
        4,
        leaves.len() as u64,
        &wrong_length_path,
        &honest_root,
    );
    assert!(matches!(result_3, Err(KtError::InvalidProofLength { .. })));

    // (d) Adversary tries index out-of-range claim.
    let result_4 = verify_inclusion(
        &fake_leaf,
        100,
        leaves.len() as u64,
        &stolen_path,
        &honest_root,
    );
    assert!(matches!(result_4, Err(KtError::LeafIndexOutOfRange { .. })));
}

// ---------------------------------------------------------------------------
// Attack 5 — replay old signed_epoch through monotonic gating
// ---------------------------------------------------------------------------
//
// PhD-level attack scenario per SPEC-09 §5 monotonic epoch invariant.
//
// Setup: Adversary capture'ит valid signed_epoch_root от epoch=10 (e.g., MITM
// against earlier session). Когда client уже на epoch=20, adversary replay'ит
// captured signed_epoch_root через apply_authorization_approval либо
// apply_authorization_revocation либо apply_identity_rotation. Цель: revert
// state changes сделанные между epoch=10 и epoch=20 (e.g., revoke ghost
// device added в epoch=15).
//
// Hypothesis: `verify_epoch_transition` enforces `signed.epoch >=
// log_state.last_verified_epoch`. Adversary's epoch=10 signed_epoch < client's
// last_verified=20 → InvalidEntry("epoch regression").
//
// Defense: SPEC-09 §5 monotonic non-decreasing epoch invariant. KtLogState
// sustains `last_verified_epoch` field между apply_* calls; rejection
// triggers via early-fast check внутри verify_epoch_transition (line 463-465
// authorization_entries.rs).
//
// Failure mode: если `last_verified_epoch` resettable либо apply_*
// мутирует state ДО verify_epoch_transition, replay могла бы pass. Test
// verifies that replay always rejected с stable error message.

#[test]
fn attack_replay_old_signed_epoch_blocked_by_monotonic_epoch_check() {
    use umbrella_backup::cloud_wrap::{
        seal_device_authorization_approval, seal_device_authorization_revocation,
    };
    use umbrella_backup::error::BackupError;

    let witnesses: Vec<Witness> = (0..5).map(|_| fresh_witness()).collect();
    let witness_set = build_witness_set(&witnesses.iter().collect::<Vec<_>>());

    // Helper: signed_epoch_with witness signatures.
    let signed_at = |epoch: u64| -> SignedEpochRoot {
        let root = random_root();
        let sigs = witnesses
            .iter()
            .take(3)
            .map(|w| sign_epoch(w, epoch, &root))
            .collect::<Vec<_>>();
        SignedEpochRoot {
            epoch,
            root,
            log_size: 1,
            timestamp_unix_millis: 1_700_000_000_000,
            signatures: sigs,
        }
    };

    // Setup: KtLogState с identity + bootstrap-active approver.
    let mut rng = OsRng;
    let approver_sk = PrivateSigningKey::generate(&mut rng);
    let approver_pk = approver_sk.verifying_key().to_bytes();
    let identity_sk = PrivateSigningKey::generate(&mut rng);
    let identity_pk = identity_sk.verifying_key().to_bytes();
    let mut log = KtLogState::with_identity(identity_pk);
    log.register_bootstrap_active(approver_pk, TIMESTAMP_BASELINE, identity_pk)
        .unwrap();

    // Step 1: client применил approval для new_device_pk_a в epoch=20.
    let new_device_a_sk = PrivateSigningKey::generate(&mut rng);
    let new_device_a_pk = new_device_a_sk.verifying_key().to_bytes();
    log.register_pending(new_device_a_pk, identity_pk).unwrap();

    fn signer(
        sk: &PrivateSigningKey,
    ) -> impl FnOnce(&[u8]) -> core::result::Result<[u8; 64], BackupError> + '_ {
        move |msg: &[u8]| Ok(sk.sign(msg).to_bytes())
    }

    let approval_a = seal_device_authorization_approval(
        new_device_a_pk,
        approver_pk,
        TIMESTAMP_BASELINE + 10,
        0,
        0,
        signer(&approver_sk),
    )
    .unwrap();
    let signed_20 = signed_at(20);
    apply_authorization_approval(
        &approval_a,
        &mut log,
        &witness_set,
        &signed_20,
        WITNESS_THRESHOLD,
    )
    .unwrap();
    assert_eq!(log.last_verified_epoch(), 20);

    // Step 2: Adversary replay captured signed_epoch_root от epoch=10
    //         с new approval for new_device_pk_b.
    let new_device_b_sk = PrivateSigningKey::generate(&mut rng);
    let new_device_b_pk = new_device_b_sk.verifying_key().to_bytes();
    log.register_pending(new_device_b_pk, identity_pk).unwrap();

    let approval_b = seal_device_authorization_approval(
        new_device_b_pk,
        approver_pk,
        TIMESTAMP_BASELINE + 5,
        0,
        0,
        signer(&approver_sk),
    )
    .unwrap();
    let signed_10 = signed_at(10);
    let result = apply_authorization_approval(
        &approval_b,
        &mut log,
        &witness_set,
        &signed_10,
        WITNESS_THRESHOLD,
    );
    assert!(matches!(
        result,
        Err(KtError::InvalidEntry(msg)) if msg == "epoch regression"
    ));

    // Step 3: state не должен mutate'ться — last_verified_epoch остался 20.
    assert_eq!(log.last_verified_epoch(), 20);

    // Step 4: Same replay attempt через apply_authorization_revocation.
    let revocation_b = seal_device_authorization_revocation(
        new_device_b_pk,
        approver_pk,
        TIMESTAMP_BASELINE + 7,
        signer(&approver_sk),
    )
    .unwrap();
    let result_2 = apply_authorization_revocation(
        &revocation_b,
        &mut log,
        &witness_set,
        &signed_10,
        WITNESS_THRESHOLD,
    );
    assert!(matches!(
        result_2,
        Err(KtError::InvalidEntry(msg)) if msg == "epoch regression"
    ));

    // Step 5: Replay через apply_identity_rotation.
    use umbrella_backup::cloud_wrap::seal_identity_rotation_record;
    let new_identity_sk = PrivateSigningKey::generate(&mut rng);
    let new_identity_pk = new_identity_sk.verifying_key().to_bytes();
    let rotation = seal_identity_rotation_record(
        identity_pk,
        new_identity_pk,
        TIMESTAMP_BASELINE + 8,
        RotationReason::PlannedRotation,
        signer(&identity_sk),
        signer(&new_identity_sk),
    )
    .unwrap();
    let result_3 = apply_identity_rotation(
        &rotation,
        &mut log,
        &witness_set,
        &signed_10,
        WITNESS_THRESHOLD,
    );
    assert!(matches!(
        result_3,
        Err(KtError::InvalidEntry(msg)) if msg == "epoch regression"
    ));
}

// ---------------------------------------------------------------------------
// Attack 6 — cross-epoch transcript chain break via parent_hash substitution
// ---------------------------------------------------------------------------
//
// PhD-level attack scenario для V2 entry chain (Stage 8 ADR-011 §6.5).
//
// Setup: Adversary хочет создать «alternative history» для V2 entry chain —
// два различных transcript chains starting от epoch_id=N + расходящиеся at
// epoch_id=N+5. Adversary controls KT log delivery + tries to:
// 1. Capture genuine V2 entry chain до epoch_id=5 (entries 1..5 with valid
//    parent_hash chain)
// 2. Construct alternative chain entries 6..10 с substituted parent_hash
//    pointing к forged predecessor (e.g., adversary's ghost entry)
// 3. Stitch alternative chain back в legit chain at epoch_id=11
//
// Hypothesis: каждый V2 entry binds parent_hash через canonical_encoding
// → leaf_hash → Merkle root. Adversary без collision SHA-256 не может branch
// chain без detection: recomputed Merkle root mismatches published root.
//
// Defense: SHA-256 collision resistance ε ≤ 2⁻¹²⁸ (birthday) + V2 entry
// canonical_encoding includes parent_hash field (entry_v2.rs:236) → leaf_hash
// (RFC 6962 LEAF_PREFIX 0x00) → Merkle leaf change → Merkle root change →
// detected by self-monitoring + multi-witness verification.
//
// Failure mode: если parent_hash не included в canonical_encoding либо
// Merkle leaf hash не binds parent_hash, branch attack возможен. Test
// verifies that distinct parent_hash values produce distinct Merkle leaves.

#[cfg(feature = "pq")]
#[test]
fn attack_cross_epoch_chain_break_via_parent_hash_substitution_detected() {
    use rand_core::OsRng;
    use umbrella_identity::{HybridIdentityKey, IdentitySeed, MnemonicLanguage};
    use umbrella_kt::KtEntryV2;

    let mut rng = OsRng;
    let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    let hybrid = HybridIdentityKey::derive(&seed, 0).unwrap();
    let pubkey = hybrid.public().clone();
    let ed25519_bytes = pubkey.ed25519_bytes();
    let account_id = KtEntryV2::derive_account_id(&ed25519_bytes);

    // (a) Honest chain: entries с sequential parent_hashes.
    let entry_n = KtEntryV2 {
        account_id,
        identity_hybrid_pubkey: pubkey.clone(),
        identity_slh_dsa_backup: None,
        timestamp_secs_unix: 1_700_000_000,
        sequence_number: 5,
        parent_hash: [0xAA; 32], // honest predecessor hash
    };

    // (b) Adversary's «forged» entry с substituted parent_hash.
    let entry_forged = KtEntryV2 {
        account_id,
        identity_hybrid_pubkey: pubkey.clone(),
        identity_slh_dsa_backup: None,
        timestamp_secs_unix: 1_700_000_000,
        sequence_number: 5,
        parent_hash: [0xFF; 32], // adversary's substituted hash
    };

    // (c) Distinct canonical_encoding produced.
    let enc_n = entry_n.canonical_encoding().unwrap();
    let enc_forged = entry_forged.canonical_encoding().unwrap();
    assert_ne!(enc_n, enc_forged);

    // (d) Distinct Merkle leaf hashes produced.
    let leaf_n = entry_n.merkle_leaf_hash().unwrap();
    let leaf_forged = entry_forged.merkle_leaf_hash().unwrap();
    assert_ne!(leaf_n, leaf_forged);

    // (e) Если Merkle root computed over chain включающий entry_n vs entry_forged
    //     → distinct roots (witness signatures от honest root reject forged tree).
    let leaves_honest = vec![[0u8; 32], leaf_n, [0xCC; 32]];
    let leaves_forged = vec![[0u8; 32], leaf_forged, [0xCC; 32]];
    let root_honest = merkle_root(&leaves_honest);
    let root_forged = merkle_root(&leaves_forged);
    assert_ne!(root_honest, root_forged);

    // (f) Statistical: adversary attempts 1000 random parent_hash substitutions
    //     ни один не дает collision с honest root.
    for _ in 0..1000 {
        let mut adversary_attempt = entry_n.clone();
        let mut random_parent = [0u8; 32];
        OsRng.fill_bytes(&mut random_parent);
        if random_parent == entry_n.parent_hash {
            continue; // skip identical (extremely rare)
        }
        adversary_attempt.parent_hash = random_parent;
        let enc_attempt = adversary_attempt.canonical_encoding().unwrap();
        assert_ne!(
            enc_n, enc_attempt,
            "different parent_hash → different canonical_encoding"
        );
    }
}

// ---------------------------------------------------------------------------
// Attack 7 — canonical_sign_payload binds log_size + timestamp (F-PHD-S68-1 closed)
// ---------------------------------------------------------------------------
//
// История теста (history of this test):
//
// 1. Session #68 (commit f54fd10): тест добавлен как **documentation finding**
//    F-PHD-S68-1 — production canonical_sign_payload производил 64 bytes,
//    SPEC-09 §5.3 normatively specified 80 bytes (с log_size + timestamp).
//    Assertion `payload.len() == 64` подтверждал divergence.
// 2. Session #68d (этот pass): SPEC-09 §5.3 alignment применён в production —
//    canonical_sign_payload теперь возвращает 80 bytes. SignedEpochRoot
//    extended с log_size + timestamp_unix_millis fields. Test переделан
//    в **regression test закрытия** F-PHD-S68-1: assertion `payload.len() == 80`
//    + cross-binding защита от replay-к-different-log-size demonstrated.
//
// Defense: per SPEC-09 §5.3, witness подписывает 80-byte canonical:
//     WITNESS_DOMAIN_SEP (23) || WITNESS_VERSION (1) || epoch_BE (8)
//   || root (32) || log_size_BE (8) || timestamp_BE (8)
//
// Если adversary captures signed_epoch_root для {epoch=N, root=X, log_size=1000}
// и пытается re-bind к log_size=2000 — signature НЕ verifies, потому что
// log_size теперь часть signed payload.

#[test]
fn attack_canonical_sign_payload_binds_log_size_post_fix_f_phd_s68_1() {
    let witness = fresh_witness();
    let epoch = EPOCH_BASELINE;
    let root = random_root();

    // Witness signs canonical_sign_payload(epoch, root, log_size=1000, ts=...).
    let log_size_genuine: u64 = 1000;
    let timestamp_ms: u64 = 1_700_000_000_000;
    let payload_genuine = canonical_sign_payload(epoch, &root, log_size_genuine, timestamp_ms);

    // SPEC-09 §5.3 alignment: canonical payload теперь = 80 bytes.
    assert_eq!(
        payload_genuine.len(),
        // WITNESS_DOMAIN_SEP (23) + VERSION (1) + epoch (8) + root (32)
        // + log_size (8) + timestamp (8) = 80
        23 + 1 + 8 + 32 + 8 + 8,
        "post-fix canonical_sign_payload должна быть 80 байт per SPEC-09 §5.3"
    );
    assert_eq!(payload_genuine.len(), 80);

    let signature_bytes = witness.sk.sign(&payload_genuine).to_bytes();
    let signature = WitnessSignature {
        witness: witness.pk,
        signature: signature_bytes,
    };

    // Honest path: signature verifies для подписанного {epoch, root, log_size=1000}.
    let witness_set = build_witness_set(&[&witness]);
    let signed_genuine = SignedEpochRoot {
        epoch,
        root,
        log_size: log_size_genuine,
        timestamp_unix_millis: timestamp_ms,
        signatures: vec![signature],
    };
    verify_signed_epoch(&signed_genuine, &witness_set, 1)
        .expect("signature на genuine {epoch, root, log_size=1000} verifies");

    // Adversarial path: adversary re-claims **тот же signature** но с
    // log_size=2000 (попытка cross-binding). Сигнатура должна reject —
    // log_size теперь часть signed payload.
    let signed_forged = SignedEpochRoot {
        epoch,
        root,
        log_size: 2000, // adversary claim
        timestamp_unix_millis: timestamp_ms,
        signatures: vec![signature],
    };
    let result = verify_signed_epoch(&signed_forged, &witness_set, 1);
    assert!(
        matches!(
            result,
            Err(KtError::InsufficientValidSignatures {
                valid: 0,
                required: 1
            })
        ),
        "F-PHD-S68-1 closure: signature должна reject при log_size mismatch; got {result:?}"
    );

    // Аналогично — adversary меняет timestamp.
    let signed_ts_forged = SignedEpochRoot {
        epoch,
        root,
        log_size: log_size_genuine,
        timestamp_unix_millis: timestamp_ms + 1, // adversary tampered
        signatures: vec![signature],
    };
    let result_ts = verify_signed_epoch(&signed_ts_forged, &witness_set, 1);
    assert!(
        matches!(
            result_ts,
            Err(KtError::InsufficientValidSignatures {
                valid: 0,
                required: 1
            })
        ),
        "F-PHD-S68-1 closure: signature должна reject при timestamp mismatch; got {result_ts:?}"
    );
}

// ---------------------------------------------------------------------------
// Attack 8 — concurrent self-monitoring race не corrupts log state
// ---------------------------------------------------------------------------
//
// PhD-level attack scenario per concurrency invariants.
//
// Setup: Adversary publishes ghost entry + immediately publishes legitimate
// entry с same account_id, hoping что concurrent self-monitor invocations
// race-condition между two reads — один thread видит ghost, другой видит
// legit, neither persists alarm state correctly.
//
// Hypothesis: KtLogState wrapped в Arc<Mutex<>> либо external lock
// preserves invariants. apply_* calls serialize through lock; concurrent
// modifications produce consistent state final.
//
// Defense: Rust's borrow checker + Mutex semantics. KtLogState не реализует
// Send/Sync без external wrapping; всё thread-safe access requires
// programmer explicit lock ordering.
//
// Failure mode: если внутренние invariants KtLogState нарушаются под
// concurrent mutate (e.g., HashMap iterator invalidation), state corruption.
// Test verifies that 4 threads × 100 iterations each preserve invariants.

#[test]
fn attack_concurrent_log_state_mutation_preserves_invariants() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let witnesses: Vec<Witness> = (0..5).map(|_| fresh_witness()).collect();
    let witness_set = Arc::new(build_witness_set(&witnesses.iter().collect::<Vec<_>>()));
    let log = Arc::new(Mutex::new(KtLogState::new()));

    // Pre-populate log с identity + bootstrap approver.
    let mut rng = OsRng;
    let approver_sk = PrivateSigningKey::generate(&mut rng);
    let approver_pk = approver_sk.verifying_key().to_bytes();
    let identity_sk = PrivateSigningKey::generate(&mut rng);
    let identity_pk = identity_sk.verifying_key().to_bytes();
    let _ = identity_sk;
    {
        let mut g = log.lock().unwrap();
        *g = KtLogState::with_identity(identity_pk);
        g.register_bootstrap_active(approver_pk, TIMESTAMP_BASELINE, identity_pk)
            .unwrap();
    }

    // Concurrent: 4 threads × 50 iterations каждое сделает register_pending +
    // lookup_device_entry. Используем same identity для всех чтобы test
    // serialized correctness.
    let mut handles = vec![];
    for thread_idx in 0..4u32 {
        let log_clone = Arc::clone(&log);
        let witness_set_clone = Arc::clone(&witness_set);
        let _ = witness_set_clone;
        handles.push(thread::spawn(move || {
            let mut local_rng = OsRng;
            for iter in 0..50u32 {
                let device_sk = PrivateSigningKey::generate(&mut local_rng);
                let device_pk = device_sk.verifying_key().to_bytes();
                {
                    let mut g = log_clone.lock().unwrap();
                    g.register_pending(device_pk, identity_pk).unwrap();
                }
                {
                    let g = log_clone.lock().unwrap();
                    let entry = umbrella_kt::lookup_device_entry(&g, &device_pk);
                    assert!(
                        entry.is_some(),
                        "thread {thread_idx} iter {iter} entry missing после register_pending"
                    );
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // Final invariant check: device_count == 200 (4 threads × 50 iter) + 1
    // bootstrap approver = 201.
    let g = log.lock().unwrap();
    assert_eq!(g.device_count(), 4 * 50 + 1);
    assert_eq!(
        g.active_count(),
        1,
        "только approver = active; rest pending"
    );
}

// ---------------------------------------------------------------------------
// Attack 9 — resource exhaustion: bulk pending entries
// ---------------------------------------------------------------------------
//
// PhD-level attack scenario per resource exhaustion invariants.
//
// Setup: Adversary publishes 10K ghost pending entries для legitimate user's
// account_id. Goal: либо (a) DoS клиент when self-monitoring iterates
// все entries, либо (b) hide ghost entry в bulk submission hoping client
// monitors only first N либо truncates.
//
// Hypothesis: KtLogState scaling на bulk entries:
// - register_pending O(1) per call (HashMap insert)
// - device_count() O(1)
// - active_count() O(N) — линейный обход
// - lookup_device_entry O(1) HashMap lookup
//
// Self-monitoring через verify_own_entry iterates ВСЕ entries unbounded —
// нет rate limit либо early-return optimization. Это actually intended
// behavior — iterating все entries detects ghost.
//
// Defense: SPEC-09 §6.1 — self-monitoring обязан iterate все entries;
// adversary не может hide ghost. Resource cost bounded by
// MAX_ENTRY_ENCODED_LEN (64 KiB per entry); 10K entries = 640 MB max.
// Practical bounds further limited by Sealed Server quotas.
//
// Failure mode: если monitor имеет early-return bug либо iteration limit,
// ghost entries past N invisible. Test verifies all 10K entries observable
// via iter_entries().

#[test]
fn attack_bulk_ghost_entries_all_observable_via_iteration() {
    let mut rng = OsRng;
    let identity_pk = PrivateSigningKey::generate(&mut rng)
        .verifying_key()
        .to_bytes();
    let mut log = KtLogState::with_identity(identity_pk);

    // Submit 10K pending entries (representing adversary's ghost devices).
    let target_count = 10_000usize;
    let mut all_pubkeys = Vec::with_capacity(target_count);
    for _ in 0..target_count {
        let pk = PrivateSigningKey::generate(&mut rng)
            .verifying_key()
            .to_bytes();
        log.register_pending(pk, identity_pk).unwrap();
        all_pubkeys.push(pk);
    }

    // (a) device_count returns full count.
    assert_eq!(log.device_count(), target_count);

    // (b) active_count = 0 (all pending, none active without approval).
    assert_eq!(log.active_count(), 0);

    // (c) iter_entries observes ВСЕ entries (включая «ghost» entries past N).
    let observed: Vec<_> = log.iter_entries().collect();
    assert_eq!(observed.len(), target_count);

    // (d) Каждый pubkey доступен через lookup_device_entry — нет truncation.
    for pk in &all_pubkeys {
        assert!(umbrella_kt::lookup_device_entry(&log, pk).is_some());
    }
}
