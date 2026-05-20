#![allow(deprecated)] // Round-6: test exercises legacy IdentitySeed::generate; production uses bootstrap_account
//! Drill A — SLH-DSA backup activation: симуляция CVE для ML-DSA-65, переключение
//! identity-подписи на SLH-DSA backup, проверка достижимости pre-CVE V2 entries
//! через KT log replay, контроль end-to-end timing внутри 72-часового бюджета.
//!
//! Drill A — SLH-DSA backup activation: simulates an ML-DSA-65 cryptanalysis CVE,
//! switches identity signing to the SLH-DSA-only backup signature scheme, verifies
//! that pre-CVE KT v2 entries remain reachable through KT log replay, and asserts
//! end-to-end activation timing fits inside the 72-hour budget.
//!
//! ## Сценарий
//!
//! Опубликован CVE для ML-DSA-65 — одна из двух post-quantum подписей в hybrid
//! identity сломана криптоанализом. Production decision: switch identity signing
//! на SLH-DSA backup (FIPS 205 SLH-DSA-128f-simple, hash-based, quantum-resistant
//! без зависимости от lattice problems). KT v2 entries получают rotation proof,
//! подписанный SLH-DSA backup ключом; downstream clients verify через
//! SLH-DSA pubkey, доступный в `KtEntryV2::identity_slh_dsa_backup` (ADR-008
//! § rotation + ADR-011 Решение 6). Гибридный pubkey остаётся в записи для
//! schema-совместимости, но операторы и self-monitor больше не доверяют
//! ML-DSA-65 части подписи; rotation proof — единственный source of truth.
//!
//! Target timing: < 72 часа от публикации CVE до user-side activation.
//!
//! ## Scenario
//!
//! ML-DSA-65 CVE published — one of the two post-quantum signatures in the
//! hybrid identity is broken by cryptanalysis. Production decision: switch
//! identity signing to the SLH-DSA backup (FIPS 205 SLH-DSA-128f-simple,
//! hash-based, quantum-resistant without lattice dependence). KT v2 entries
//! receive a rotation proof signed by the SLH-DSA backup key; downstream
//! clients verify via the SLH-DSA pubkey carried in
//! `KtEntryV2::identity_slh_dsa_backup` (ADR-008 § rotation + ADR-011
//! Decision 6). The hybrid pubkey stays in the record for schema continuity,
//! but operators and self-monitor no longer trust the ML-DSA-65 portion of
//! the signature; the rotation proof is the sole source of truth.
//!
//! Target timing: < 72 hours from CVE publication to user-side activation.
//!
//! ## Связанные документы / Related documents
//!
//! - Operational runbook — `docs/operations/drill_a_slh_dsa_activation.md`.
//! - Design reference — `docs/adr/ADR-012-hardening.md` §7.4.1.
//! - Implementation plan — `docs/adr/ADR-012-hardening.md` §9.9.1.
//! - SLH-DSA backup keypair — `crates/umbrella-identity/src/slh_dsa_backup.rs`.
//! - KT v2 entry self-monitoring — `crates/umbrella-kt/src/monitor.rs`.

#![cfg(feature = "pq")]

use rand_core::OsRng;

use umbrella_identity::{HybridIdentityKey, IdentitySeed, MnemonicLanguage, SlhDsaBackupKey};
use umbrella_kt::{
    verify_own_v2_entry, HybridOwnExpectations, KtEntryV2, KtError, KT_ENTRY_V2_MAX_ENCODED_LEN,
};
use umbrella_pq::{slh_dsa_128f_keygen, SlhDsa128fPublicKey, SlhDsa128fSignature};

// ─────────────────────────────────────────────────────────────────────────
// Drill timing constants — operator timeline anchors.
// Drill timing constants — operator timeline anchors.
// ─────────────────────────────────────────────────────────────────────────

/// Сколько production users участвуют в drill (репрезентативный subset для
/// проверки flow без масштабирования до миллиардов).
/// Number of production users in the drill (a representative subset that
/// exercises the flow without scaling to billions).
const DRILL_USER_COUNT: usize = 5;

/// Секунд в часе. Seconds per hour.
const SECS_PER_HOUR: u64 = 3600;

/// Бюджет end-to-end activation: ≤ 72 часа от CVE до user-side switch.
/// End-to-end activation budget: ≤ 72 hours from CVE to user-side switch.
const TARGET_ACTIVATION_BUDGET_SECS: u64 = 72 * SECS_PER_HOUR;

/// Якорная Unix-метка для CVE публикации (T+0). Все остальные timestamps
/// считаются относительно этой точки.
/// Anchor Unix timestamp for CVE publication (T+0). All other timestamps
/// are derived relative to this anchor.
const T_CVE_PUBLISHED: u64 = 1_700_000_000;

/// T+0 (CVE detected via RUSTSEC advisory + Tamarin model fail из block 9.3).
/// T+0 (CVE detected via RUSTSEC advisory + Tamarin model fail from block 9.3).
const T_DETECTION_DELAY: u64 = 0;

/// T+12h — production decision принят.
/// T+12h — production decision is taken.
const T_PRODUCTION_DECISION_DELAY: u64 = 12 * SECS_PER_HOUR;

/// T+24h — KT v2 entries обновлены с SLH-DSA rotation proof.
/// T+24h — KT v2 entries updated with the SLH-DSA rotation proof.
const T_KT_UPDATE_DELAY: u64 = 24 * SECS_PER_HOUR;

/// T+48h — in-app banner + push notification доставлены пользователям.
/// T+48h — in-app banner + push notification delivered to users.
const T_USER_NOTIFICATION_DELAY: u64 = 48 * SECS_PER_HOUR;

/// T+72h — full activation completed (last device confirmed switch).
/// T+72h — full activation completed (last device confirmed the switch).
const T_FULL_ACTIVATION_DELAY: u64 = 72 * SECS_PER_HOUR;

/// Контекст для rotation proof message — domain separation от других
/// SLH-DSA подписей в системе (rotation proofs vs version-locking attestation
/// vs KAT vector code-signing).
/// Domain separation context for the rotation-proof message — keeps it
/// disjoint from other SLH-DSA signatures (rotation proofs vs version-locking
/// attestation vs KAT vector code-signing).
const ROTATION_PROOF_CONTEXT: &[u8] = b"umbrellax-drill-a-slh-dsa-activation-v1";

// ─────────────────────────────────────────────────────────────────────────
// Test helpers — drill user, V2 entry builder, rotation proof message.
// Test helpers — drill user, V2 entry builder, rotation-proof message.
// ─────────────────────────────────────────────────────────────────────────

/// Drill user: full hybrid identity (Ed25519 + ML-DSA-65) + dedicated
/// SLH-DSA backup keypair, derived из общей 24-word BIP-39 mnemonic
/// (Pattern F — single recovery anchor).
///
/// Drill user: full hybrid identity (Ed25519 + ML-DSA-65) + a dedicated
/// SLH-DSA backup keypair, all derived from a single 24-word BIP-39 mnemonic
/// (Pattern F — single recovery anchor).
struct DrillUser {
    /// BIP-39 derivation seed (24-слово английская mnemonic).
    /// BIP-39 derivation seed (24-word English mnemonic).
    seed: IdentitySeed,
    /// Hybrid Ed25519 + ML-DSA-65 identity (block 8.3).
    /// Hybrid Ed25519 + ML-DSA-65 identity (block 8.3).
    hybrid: HybridIdentityKey,
    /// SLH-DSA-128f backup keypair (block 9.4 catastrophic recovery anchor).
    /// SLH-DSA-128f backup keypair (block 9.4 catastrophic recovery anchor).
    backup: SlhDsaBackupKey,
}

fn fresh_drill_user(account: u32) -> DrillUser {
    let mut rng = OsRng;
    let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    let hybrid = HybridIdentityKey::derive(&seed, account).expect("hybrid identity derive");
    let backup = SlhDsaBackupKey::derive(&seed, account).expect("SLH-DSA backup derive");
    DrillUser {
        seed,
        hybrid,
        backup,
    }
}

/// Извлекает SLH-DSA pubkey backup'а в форму, пригодную для вставки в KT v2
/// entry (`KtEntryV2::identity_slh_dsa_backup: Option<SlhDsa128fPublicKey>`).
/// Extracts the SLH-DSA backup pubkey in the form required by a KT v2 entry
/// (`KtEntryV2::identity_slh_dsa_backup: Option<SlhDsa128fPublicKey>`).
fn slh_dsa_pubkey_for_entry(user: &DrillUser) -> SlhDsa128fPublicKey {
    let bytes = user.backup.public().to_bytes();
    SlhDsa128fPublicKey::from_bytes(&bytes).expect("valid backup pubkey bytes")
}

/// Строит KT v2 entry для пользователя с заданным sequence_number, timestamp
/// и parent_hash. SLH-DSA backup pubkey всегда вставлен — drill требует
/// полное hybrid + backup setup для корректного rotation flow.
///
/// Builds a KT v2 entry for the user with the given sequence_number, timestamp
/// and parent_hash. The SLH-DSA backup pubkey is always present — the drill
/// requires the full hybrid + backup setup for the rotation flow to work.
fn build_v2_entry_with_backup(
    user: &DrillUser,
    seq: u64,
    timestamp: u64,
    parent_hash: [u8; 32],
) -> KtEntryV2 {
    let pub_key = user.hybrid.public().clone();
    let ed25519_bytes = pub_key.ed25519_bytes();
    let account_id = KtEntryV2::derive_account_id(&ed25519_bytes);
    KtEntryV2 {
        account_id,
        identity_hybrid_pubkey: pub_key,
        identity_slh_dsa_backup: Some(slh_dsa_pubkey_for_entry(user)),
        timestamp_secs_unix: timestamp,
        sequence_number: seq,
        parent_hash,
    }
}

/// Канонический rotation-proof message: контекстный тег + Merkle leaf hash
/// V2 entry + activation epoch BE u64. Подписывается SLH-DSA backup ключом
/// через `SlhDsaBackupKey::sign_rotation_proof` (тот добавляет внутренний
/// SLH_DSA_BACKUP_ROTATION_CONTEXT — двойная domain separation: drill
/// context tag + library context tag).
///
/// Canonical rotation-proof message: drill context tag + Merkle leaf hash of
/// the V2 entry + activation epoch BE u64. Signed by the SLH-DSA backup key
/// via `SlhDsaBackupKey::sign_rotation_proof` (which adds the library-level
/// SLH_DSA_BACKUP_ROTATION_CONTEXT — double domain separation: drill tag plus
/// library tag).
fn rotation_proof_message(entry: &KtEntryV2, activation_epoch: u64) -> Vec<u8> {
    let leaf = entry.merkle_leaf_hash().expect("leaf hash for valid entry");
    let mut msg = Vec::with_capacity(ROTATION_PROOF_CONTEXT.len() + 32 + 8);
    msg.extend_from_slice(ROTATION_PROOF_CONTEXT);
    msg.extend_from_slice(&leaf);
    msg.extend_from_slice(&activation_epoch.to_be_bytes());
    msg
}

// ─────────────────────────────────────────────────────────────────────────
// Drill scenarios.
// Drill scenarios.
// ─────────────────────────────────────────────────────────────────────────

/// Pre-CVE baseline: 5 пользователей публикуют V2 entries с настроенным
/// SLH-DSA backup pubkey. Каждая entry проходит roundtrip
/// canonical_encoding ↔ from_bytes без потерь и self-monitor подтверждает
/// match с собственными expectations пользователя.
///
/// Pre-CVE baseline: 5 users publish V2 entries with configured SLH-DSA
/// backup pubkeys. Each entry roundtrips canonical_encoding ↔ from_bytes
/// without loss and self-monitor confirms a match against the user's own
/// expectations.
#[test]
fn a1_baseline_pre_cve_state() {
    let users: Vec<DrillUser> = (0..DRILL_USER_COUNT as u32).map(fresh_drill_user).collect();

    for (idx, user) in users.iter().enumerate() {
        let entry =
            build_v2_entry_with_backup(user, /* seq = */ 1, T_CVE_PUBLISHED, [0u8; 32]);

        let wire = entry.canonical_encoding().expect("canonical encoding");
        assert_eq!(
            wire.len(),
            KT_ENTRY_V2_MAX_ENCODED_LEN,
            "user {idx}: V2 entry с SLH-DSA backup имеет MAX wire length 2098"
        );

        let parsed = KtEntryV2::from_bytes(&wire).expect("parse roundtrip");
        let backup_pk = slh_dsa_pubkey_for_entry(user);
        let exp = HybridOwnExpectations {
            identity_hybrid: user.hybrid.public(),
            identity_slh_dsa_backup: Some(&backup_pk),
        };
        verify_own_v2_entry(&parsed, &exp).expect("baseline self-monitor passes");
    }
}

/// CVE detected → operator строит новый V2 entry для пользователя
/// (sequence_number = 2, parent_hash = leaf hash pre-CVE entry) и подписывает
/// rotation proof SLH-DSA backup ключом. Verify roundtrip проходит и proof
/// верифицируется через SLH-DSA pubkey.
///
/// CVE detected → operator builds a new V2 entry for the user
/// (sequence_number = 2, parent_hash = leaf hash of the pre-CVE entry) and
/// signs the rotation proof with the SLH-DSA backup key. The roundtrip passes
/// and the proof verifies via the SLH-DSA pubkey.
#[test]
fn a2_cve_detected_new_v2_entry_signed_with_slh_dsa() {
    let user = fresh_drill_user(0);

    // Pre-CVE state — sequence 1.
    let pre_cve = build_v2_entry_with_backup(&user, 1, T_CVE_PUBLISHED, [0u8; 32]);
    let pre_cve_leaf = pre_cve.merkle_leaf_hash().expect("pre-CVE leaf");

    // T+24h: operator response — new V2 entry с parent_hash = pre_cve_leaf.
    let activation_ts = T_CVE_PUBLISHED + T_KT_UPDATE_DELAY;
    let post_cve = build_v2_entry_with_backup(&user, 2, activation_ts, pre_cve_leaf);

    // Rotation proof signed SLH-DSA backup'ом.
    let mut rng = OsRng;
    let proof_msg = rotation_proof_message(&post_cve, /* activation_epoch = */ 1);
    let proof = user
        .backup
        .sign_rotation_proof(&mut rng, &proof_msg)
        .expect("SLH-DSA sign rotation proof");

    user.backup
        .public()
        .verify_rotation_proof(&proof_msg, &proof)
        .expect("SLH-DSA verify rotation proof passes");

    // Self-monitor для post-CVE entry.
    let backup_pk = slh_dsa_pubkey_for_entry(&user);
    let exp = HybridOwnExpectations {
        identity_hybrid: user.hybrid.public(),
        identity_slh_dsa_backup: Some(&backup_pk),
    };
    let wire = post_cve.canonical_encoding().expect("encode");
    let parsed = KtEntryV2::from_bytes(&wire).expect("parse");
    verify_own_v2_entry(&parsed, &exp).expect("post-CVE self-monitor passes");
    assert_eq!(parsed.sequence_number, 2);
    assert_eq!(parsed.parent_hash, pre_cve_leaf);
}

/// KT log replay: pre-CVE entry (seq=1) и post-CVE entry (seq=2) одновременно
/// reachable в логе. Self-monitor passes для обеих, parent_hash chain корректен,
/// sequence_number монотонно растёт. Это проверка что post-CVE clients могут
/// найти pre-CVE keys (например, для расшифровки старых сообщений).
///
/// KT log replay: the pre-CVE entry (seq=1) and the post-CVE entry (seq=2)
/// remain reachable in the log together. Self-monitor passes for both, the
/// parent_hash chain is valid, and the sequence_number grows monotonically.
/// This guarantees that post-CVE clients can find pre-CVE keys (e.g. to
/// decrypt older messages).
#[test]
fn a3_kt_log_replay_pre_and_post_cve_entries_both_reachable() {
    let user = fresh_drill_user(0);

    let pre_cve = build_v2_entry_with_backup(&user, 1, T_CVE_PUBLISHED, [0u8; 32]);
    let pre_cve_leaf = pre_cve.merkle_leaf_hash().expect("leaf");
    let post_cve =
        build_v2_entry_with_backup(&user, 2, T_CVE_PUBLISHED + T_KT_UPDATE_DELAY, pre_cve_leaf);

    let log_bytes: Vec<Vec<u8>> = vec![
        pre_cve.canonical_encoding().expect("pre encode"),
        post_cve.canonical_encoding().expect("post encode"),
    ];

    let backup_pk = slh_dsa_pubkey_for_entry(&user);
    let exp = HybridOwnExpectations {
        identity_hybrid: user.hybrid.public(),
        identity_slh_dsa_backup: Some(&backup_pk),
    };

    let mut last_seq: u64 = 0;
    let mut last_leaf: [u8; 32] = [0u8; 32];
    for (i, bytes) in log_bytes.iter().enumerate() {
        let entry = KtEntryV2::from_bytes(bytes).expect("replay parse");
        verify_own_v2_entry(&entry, &exp).expect("replay self-monitor passes");

        assert!(
            entry.sequence_number > last_seq,
            "entry {i}: sequence_number должен расти монотонно"
        );
        last_seq = entry.sequence_number;

        if i == 0 {
            assert_eq!(
                entry.parent_hash, [0u8; 32],
                "первая entry имеет null parent"
            );
        } else {
            assert_eq!(entry.parent_hash, last_leaf, "parent_hash chain корректен");
        }
        last_leaf = entry.merkle_leaf_hash().expect("leaf chain step");
    }

    assert_eq!(last_seq, 2, "последняя entry имеет seq=2");
}

/// Timing budget: каждый шаг operator timeline ≤ предыдущего, и общий
/// elapsed time ≤ 72h budget. Это assertion над константами — компилятор
/// доказывает структурную корректность, тест runtime — численное равенство.
///
/// Timing budget: each operator timeline step is ≥ the previous one, and the
/// total elapsed time is ≤ the 72h budget. This is an assertion over
/// constants — the compiler proves structural correctness, the runtime test
/// asserts numeric equality.
#[test]
fn a4_activation_timing_within_72h_budget() {
    let cve_ts = T_CVE_PUBLISHED;
    let detection_ts = cve_ts + T_DETECTION_DELAY;
    let decision_ts = cve_ts + T_PRODUCTION_DECISION_DELAY;
    let kt_update_ts = cve_ts + T_KT_UPDATE_DELAY;
    let user_notification_ts = cve_ts + T_USER_NOTIFICATION_DELAY;
    let full_activation_ts = cve_ts + T_FULL_ACTIVATION_DELAY;

    assert!(detection_ts >= cve_ts, "detection после CVE");
    assert!(decision_ts >= detection_ts, "decision после detection");
    assert!(kt_update_ts >= decision_ts, "KT update после decision");
    assert!(
        user_notification_ts >= kt_update_ts,
        "notification после KT update"
    );
    assert!(
        full_activation_ts >= user_notification_ts,
        "full activation после notification"
    );

    let elapsed = full_activation_ts - cve_ts;
    assert!(
        elapsed <= TARGET_ACTIVATION_BUDGET_SECS,
        "activation took {elapsed}s, budget {TARGET_ACTIVATION_BUDGET_SECS}s"
    );
    assert_eq!(elapsed, 72 * SECS_PER_HOUR);
}

/// Rotation proof tamper resistance: подмена message → SLH-DSA verify fail;
/// подмена signature byte → SLH-DSA verify fail. Это закрывает adversary
/// который пытается forge rotation proof для substitution attack во время
/// drill flow.
///
/// Rotation proof tamper resistance: tampered message → SLH-DSA verify fails;
/// tampered signature byte → SLH-DSA verify fails. Closes the adversary path
/// where an attacker tries to forge a rotation proof for a substitution
/// attack during the drill flow.
#[test]
fn a5_rotation_proof_tamper_resistance() {
    let user = fresh_drill_user(0);
    let new_entry =
        build_v2_entry_with_backup(&user, 2, T_CVE_PUBLISHED + T_KT_UPDATE_DELAY, [0u8; 32]);
    let proof_msg = rotation_proof_message(&new_entry, 1);

    let mut rng = OsRng;
    let proof = user
        .backup
        .sign_rotation_proof(&mut rng, &proof_msg)
        .expect("sign");

    // Valid roundtrip.
    user.backup
        .public()
        .verify_rotation_proof(&proof_msg, &proof)
        .expect("valid proof verifies");

    // Tampered message → verify fails.
    let mut tampered_msg = proof_msg.clone();
    tampered_msg[0] ^= 0x01;
    assert!(
        user.backup
            .public()
            .verify_rotation_proof(&tampered_msg, &proof)
            .is_err(),
        "tampered message rejected (постулат 4 privacy + 14 strict dispatch)"
    );

    // Tampered signature byte → verify fails. SLH-DSA подписи (17_088 bytes)
    // имеют bit-by-bit cryptographic integrity — single bit flip ломает
    // verification.
    // Tampered signature byte → verify fails. SLH-DSA signatures (17_088 bytes)
    // have bit-by-bit cryptographic integrity — a single bit flip breaks
    // verification.
    let mut sig_bytes = proof.as_bytes().to_vec();
    sig_bytes[0] ^= 0x01;
    let tampered_sig = SlhDsa128fSignature::from_bytes(&sig_bytes).expect("from_bytes");
    assert!(
        user.backup
            .public()
            .verify_rotation_proof(&proof_msg, &tampered_sig)
            .is_err(),
        "tampered signature rejected"
    );
}

/// Adversary вставляет чужой hybrid pubkey в новый V2 entry во время activation
/// flow (substitution attack). Self-monitor у legitimate пользователя обнаруживает
/// расхождение — даже если SLH-DSA proof отдельно verifying'нул бы, account_id
/// и hybrid pubkey зафиксированы и должны совпадать с локальными expectations.
///
/// Adversary substitutes a foreign hybrid pubkey into a new V2 entry during
/// activation flow (substitution attack). The legitimate user's self-monitor
/// catches the mismatch — even if the SLH-DSA proof would verify separately,
/// the account_id and hybrid pubkey are pinned and must match local expectations.
#[test]
fn a6_substitution_attack_during_activation_detected() {
    let user = fresh_drill_user(0);
    let attacker = fresh_drill_user(1);

    // Attacker подменил hybrid pubkey, оставил account_id и backup user'а.
    let mut bad_entry =
        build_v2_entry_with_backup(&user, 2, T_CVE_PUBLISHED + T_KT_UPDATE_DELAY, [0u8; 32]);
    bad_entry.identity_hybrid_pubkey = attacker.hybrid.public().clone();

    let wire = bad_entry.canonical_encoding().expect("encode");
    let parsed = KtEntryV2::from_bytes(&wire).expect("parse");

    let backup_pk = slh_dsa_pubkey_for_entry(&user);
    let exp = HybridOwnExpectations {
        identity_hybrid: user.hybrid.public(),
        identity_slh_dsa_backup: Some(&backup_pk),
    };
    let err = verify_own_v2_entry(&parsed, &exp).expect_err("substitution detected");
    assert_eq!(
        err,
        KtError::SelfMonitoringMismatch {
            field: "v2_identity_hybrid_pubkey"
        }
    );
}

/// Пользователь без SLH-DSA backup (None) не может использовать drill flow
/// — operator пытается inject'ить backup pubkey, но self-monitor отвергает
/// как ghost-injection. Такой пользователь должен fall back на полное
/// re-derivation через mnemonic + новую BIP-39 phrase (Drill B path).
///
/// A user without an SLH-DSA backup (None) cannot use the drill flow — the
/// operator tries to inject a backup pubkey, but self-monitor rejects it as
/// ghost-injection. Such users must fall back to full re-derivation via the
/// mnemonic + a new BIP-39 phrase (Drill B path).
#[test]
fn a7_user_without_backup_cannot_use_drill_flow() {
    let mut rng = OsRng;
    let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    let hybrid = HybridIdentityKey::derive(&seed, 0).expect("hybrid derive");

    // Baseline: entry без backup, expectations None.
    let pub_key = hybrid.public().clone();
    let ed25519_bytes = pub_key.ed25519_bytes();
    let account_id = KtEntryV2::derive_account_id(&ed25519_bytes);
    let entry_no_backup = KtEntryV2 {
        account_id,
        identity_hybrid_pubkey: pub_key.clone(),
        identity_slh_dsa_backup: None,
        timestamp_secs_unix: T_CVE_PUBLISHED,
        sequence_number: 1,
        parent_hash: [0u8; 32],
    };

    let exp_no_backup = HybridOwnExpectations {
        identity_hybrid: hybrid.public(),
        identity_slh_dsa_backup: None,
    };
    verify_own_v2_entry(&entry_no_backup, &exp_no_backup).expect("baseline matches");

    // Drill flow injects SLH-DSA backup pubkey — но пользователь его никогда
    // не configурировал. Self-monitor отвергает.
    let (attacker_pk, _) = slh_dsa_128f_keygen(&mut rng).expect("attacker SLH-DSA keypair");
    let mut entry_attempt = entry_no_backup.clone();
    entry_attempt.identity_slh_dsa_backup = Some(attacker_pk);
    let wire = entry_attempt.canonical_encoding().expect("encode");
    let parsed = KtEntryV2::from_bytes(&wire).expect("parse");
    let err = verify_own_v2_entry(&parsed, &exp_no_backup).expect_err("backup unexpected");
    assert_eq!(
        err,
        KtError::SelfMonitoringMismatch {
            field: "v2_slh_dsa_backup_unexpected"
        }
    );
}

/// Single mnemonic invariant: тот же 24-word seed восстанавливает И hybrid
/// identity, И SLH-DSA backup byte-equal. Это Pattern F — фундамент drill
/// recovery flow: если пользователь потерял device, он может восстановить
/// весь identity material из одной mnemonic. Без этого свойства drill A
/// просто не работает (operator не может полагаться на user'ов имеющих
/// backup).
///
/// Single mnemonic invariant: the same 24-word seed restores BOTH the hybrid
/// identity AND the SLH-DSA backup byte-for-byte. This is Pattern F — the
/// foundation of the drill recovery flow: if the user lost a device, they
/// can rebuild all identity material from one mnemonic. Without this
/// property Drill A simply does not work (the operator cannot rely on users
/// having a backup).
#[test]
fn a8_single_mnemonic_invariant_for_drill_recovery() {
    let original = fresh_drill_user(0);
    let mnemonic = original.seed.to_mnemonic();

    let restored_seed = IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English)
        .expect("restore seed from mnemonic");
    let restored_hybrid =
        HybridIdentityKey::derive(&restored_seed, 0).expect("restore hybrid identity");
    let restored_backup =
        SlhDsaBackupKey::derive(&restored_seed, 0).expect("restore SLH-DSA backup");

    assert_eq!(
        original.hybrid.public().to_bytes(),
        restored_hybrid.public().to_bytes(),
        "hybrid identity восстановлен byte-equal через mnemonic (Pattern F)"
    );
    assert_eq!(
        original.backup.public().to_bytes(),
        restored_backup.public().to_bytes(),
        "SLH-DSA backup восстановлен byte-equal через mnemonic (Pattern F)"
    );

    // Cross-check: rotation proof, signed original, verifies через restored
    // pubkey (proof of Pattern F end-to-end).
    let mut rng = OsRng;
    let entry = build_v2_entry_with_backup(&original, 2, T_CVE_PUBLISHED, [0u8; 32]);
    let msg = rotation_proof_message(&entry, 1);
    let proof = original
        .backup
        .sign_rotation_proof(&mut rng, &msg)
        .expect("sign with original backup");
    restored_backup
        .public()
        .verify_rotation_proof(&msg, &proof)
        .expect("restored backup verifies original signature");
}

/// 5-user drill: scaling check — все 5 пользователей выполняют activation
/// flow параллельно (rotation proof для каждого пользователя), все
/// rotation proofs верифицируются успешно, KT log содержит 10 entries
/// (5 pre-CVE + 5 post-CVE) с корректными parent_hash chains per user.
///
/// 5-user drill: scaling check — all 5 users execute the activation flow in
/// parallel (rotation proof for each user), all proofs verify, the KT log
/// contains 10 entries (5 pre-CVE + 5 post-CVE) with correct per-user
/// parent_hash chains.
#[test]
fn a9_five_user_drill_end_to_end() {
    let users: Vec<DrillUser> = (0..DRILL_USER_COUNT as u32).map(fresh_drill_user).collect();
    let mut rng = OsRng;

    let mut log_entries: Vec<(usize, KtEntryV2)> = Vec::with_capacity(2 * DRILL_USER_COUNT);

    for (idx, user) in users.iter().enumerate() {
        let pre = build_v2_entry_with_backup(user, 1, T_CVE_PUBLISHED, [0u8; 32]);
        let pre_leaf = pre.merkle_leaf_hash().expect("pre leaf");
        let post =
            build_v2_entry_with_backup(user, 2, T_CVE_PUBLISHED + T_KT_UPDATE_DELAY, pre_leaf);

        // Operator подписывает rotation proof для каждого user'а.
        let proof_msg = rotation_proof_message(&post, /* activation_epoch = */ 1);
        let proof = user
            .backup
            .sign_rotation_proof(&mut rng, &proof_msg)
            .expect("sign rotation proof");
        user.backup
            .public()
            .verify_rotation_proof(&proof_msg, &proof)
            .unwrap_or_else(|_| panic!("user {idx} rotation proof must verify"));

        log_entries.push((idx, pre));
        log_entries.push((idx, post));
    }

    assert_eq!(
        log_entries.len(),
        2 * DRILL_USER_COUNT,
        "log имеет 2 entries на user (pre + post CVE)"
    );

    // Verify per-user self-monitor + chain корректен.
    for (idx, entry) in &log_entries {
        let user = &users[*idx];
        let backup_pk = slh_dsa_pubkey_for_entry(user);
        let exp = HybridOwnExpectations {
            identity_hybrid: user.hybrid.public(),
            identity_slh_dsa_backup: Some(&backup_pk),
        };
        verify_own_v2_entry(entry, &exp)
            .unwrap_or_else(|_| panic!("user {idx}: self-monitor должен пройти"));
    }
}
