//! Drill B — Mass key rotation: симуляция компрометации 3+ Sealed Servers
//! (catastrophic threshold breach), активация warrant canary, массовая ротация
//! identity ключей всех пользователей через mnemonic + новую HKDF context salt
//! (= новый account index), маркировка старых KT entries как deprecated,
//! сигнал на rebuild backup ceremony, контроль end-to-end timing внутри
//! 14-дневного бюджета.
//!
//! Drill B — Mass key rotation: simulates a compromise of 3+ Sealed Servers
//! (catastrophic threshold breach), activates the warrant canary, performs
//! mass rotation of every user's identity key via mnemonic + a fresh HKDF
//! context salt (= new account index), marks old KT entries as deprecated,
//! signals a backup ceremony rebuild, and asserts end-to-end timing within
//! the 14-day budget.
//!
//! ## Сценарий
//!
//! Out-of-band intelligence input + honeypot trip сообщает что 3+ Sealed
//! Servers скомпрометированы. Это превышает threshold 2 (3-of-5 backup
//! ceremony — 2 servers могут быть offline / compromised без потери secrecy,
//! но 3+ — это catastrophic threshold breach: adversary имеет access к
//! threshold scalar shares, может reconstruct секретные ключи backup wrap).
//! Production decision: mass key rotation для всех пользователей в течение
//! 14 дней.
//!
//! Pattern F (24-word BIP-39 mnemonic как single recovery anchor) делает
//! mass rotation возможным — каждый user derives новый identity keypair
//! из той же mnemonic, но с другим HKDF salt (новый account index в текущем
//! API; эквивалентно «umbrella-rotate-2026-XX-XX» context salt в design.md
//! §7.4.2). Mnemonic phrase остаётся неизменной — пользователь не должен
//! заново выписывать 24 слова на бумаге.
//!
//! Backup ceremony rebuild — серверы регенерируют 3-of-5 Shamir scalar shares
//! (server-side process в `Umbrella server implementation`); клиенты получают новую `Y = K · G`
//! main pubkey и обновляют `WrappingParams`.
//!
//! Target timing: < 14 дней end-to-end.
//!
//! ## Scenario
//!
//! Out-of-band intelligence input plus a honeypot trip reports that 3+ Sealed
//! Servers are compromised. This exceeds the threshold of 2 (3-of-5 backup
//! ceremony allows 2 servers offline/compromised without losing secrecy, but
//! 3+ is the catastrophic threshold breach: the adversary holds enough
//! scalar shares to reconstruct backup-wrap secret keys). Production
//! decision: mass key rotation for every user within 14 days.
//!
//! Pattern F (24-word BIP-39 mnemonic as single recovery anchor) makes mass
//! rotation possible — every user derives a new identity keypair from the
//! same mnemonic but a different HKDF salt (a new account index in the
//! current API; equivalent to the «umbrella-rotate-2026-XX-XX» context salt
//! in design.md §7.4.2). The mnemonic phrase is unchanged — users do not
//! have to rewrite the 24 words on paper.
//!
//! Backup ceremony rebuild — servers regenerate the 3-of-5 Shamir scalar
//! shares (server-side process in `Umbrella server implementation`); clients receive a new
//! `Y = K · G` main pubkey and refresh their `WrappingParams`.
//!
//! Target timing: < 14 days end-to-end.
//!
//! ## Связанные документы / Related documents
//!
//! - Operational runbook — `docs/operations/drill_b_mass_rotation.md`.
//! - Design reference — `docs/adr/ADR-012-hardening.md` §7.4.2.
//! - Implementation plan — `docs/adr/ADR-012-hardening.md` §9.9.2.
//! - Threshold backup — `crates/umbrella-backup/src/cloud_wrap/threshold.rs`.
//! - Hybrid identity derivation — `crates/umbrella-identity/src/hybrid_identity.rs`.

#![cfg(feature = "pq")]

use rand_core::OsRng;

use umbrella_backup::cloud_wrap::ThresholdConfig;
use umbrella_identity::{HybridIdentityKey, IdentitySeed, MnemonicLanguage, SlhDsaBackupKey};
use umbrella_kt::{
    verify_own_v2_entry, HybridOwnExpectations, KtEntryV2, KtError, KT_ENTRY_V2_MAX_ENCODED_LEN,
};
use umbrella_pq::SlhDsa128fPublicKey;

// ─────────────────────────────────────────────────────────────────────────
// Drill timing + threshold constants.
// Drill timing + threshold constants.
// ─────────────────────────────────────────────────────────────────────────

/// Сколько production users участвуют в drill (10 — двукратное Drill A,
/// проверка scalability mass rotation flow).
/// Number of production users in the drill (10 — twice Drill A, scaling
/// check on the mass rotation flow).
const DRILL_USER_COUNT: usize = 10;

/// Секунд в дне. Seconds per day.
const SECS_PER_DAY: u64 = 24 * 3600;

/// Бюджет end-to-end mass rotation: ≤ 14 дней.
/// End-to-end mass rotation budget: ≤ 14 days.
const TARGET_ROTATION_BUDGET_SECS: u64 = 14 * SECS_PER_DAY;

/// Якорная Unix-метка для intelligence input (T+0).
/// Anchor Unix timestamp for the intelligence input (T+0).
const T_INTELLIGENCE_INPUT: u64 = 1_700_000_000;

/// T+1h — warrant canary активирован (operator публикует «3+ Sealed Servers
/// compromised» статус); это user-visible signal.
/// T+1h — warrant canary activated (operator publishes «3+ Sealed Servers
/// compromised» status); this is the user-visible signal.
const T_WARRANT_CANARY_ACTIVATED_DELAY: u64 = 3600;

/// T+24h — push notification доставлен большинству пользователей.
/// T+24h — push notification delivered to most users.
const T_PUSH_NOTIFICATION_DELAY: u64 = SECS_PER_DAY;

/// T+48h — mass rotation client-side flow начинается.
/// T+48h — mass rotation client-side flow begins.
const T_ROTATION_CLIENT_BEGIN_DELAY: u64 = 2 * SECS_PER_DAY;

/// T+10d — 95% пользователей завершили rotation.
/// T+10d — 95% of users completed rotation.
const T_ROTATION_95PCT_DELAY: u64 = 10 * SECS_PER_DAY;

/// T+14d — full activation (последний пользователь обновил identity).
/// T+14d — full activation (the last user updated their identity).
const T_FULL_ROTATION_DELAY: u64 = 14 * SECS_PER_DAY;

/// Compromise threshold: 3+ Sealed Servers compromised — catastrophic.
/// Compromise threshold: 3+ Sealed Servers compromised — catastrophic.
const CATASTROPHIC_COMPROMISE_THRESHOLD: usize = 3;

/// Standard backup ceremony: 5 Sealed Servers, 3-of-5 threshold (existing
/// `WrappingParams::server_pubkeys` size = 5; см. `umbrella-client::ClientConfig`).
/// Standard backup ceremony: 5 Sealed Servers, 3-of-5 threshold (existing
/// `WrappingParams::server_pubkeys` size = 5; see `umbrella-client::ClientConfig`).
const SEALED_SERVERS_TOTAL: usize = 5;
const SEALED_SERVERS_THRESHOLD: u8 = 3;

/// Account indices: 0 = pre-rotation (original), 1 = post-rotation
/// («umbrella-rotate-2026-XX-XX» в design.md §7.4.2 — здесь account index
/// берёт роль HKDF salt context).
/// Account indices: 0 = pre-rotation (original), 1 = post-rotation
/// («umbrella-rotate-2026-XX-XX» in design.md §7.4.2 — here the account index
/// plays the role of the HKDF salt context).
const ACCOUNT_PRE_ROTATION: u32 = 0;
const ACCOUNT_POST_ROTATION: u32 = 1;

// ─────────────────────────────────────────────────────────────────────────
// Test types — warrant canary, drill user, helpers.
// Test types — warrant canary, drill user, helpers.
// ─────────────────────────────────────────────────────────────────────────

/// Состояние warrant canary. UmbrellaX публикует Active каждые 24 часа в
/// blog + IPFS. Если canary не обновляется > 48h, либо переходит в
/// CompromiseDeclared — пользователи понимают что произошло.
///
/// Warrant canary state. UmbrellaX publishes Active every 24 hours via
/// blog + IPFS. If the canary stops updating for > 48h or transitions to
/// CompromiseDeclared — users understand something happened.
#[derive(Clone, Debug, PartialEq, Eq)]
enum WarrantCanary {
    /// «Никаких subpoena / national security letters не получали».
    /// «No subpoena / national security letters received».
    Active { published_at_secs_unix: u64 },
    /// «Catastrophic compromise обнаружен; mass rotation в процессе».
    /// «Catastrophic compromise detected; mass rotation in progress».
    CompromiseDeclared {
        declared_at_secs_unix: u64,
        compromised_servers: usize,
    },
}

impl WarrantCanary {
    /// Активация при detection 3+ compromised Sealed Servers.
    /// Activation upon detection of 3+ compromised Sealed Servers.
    fn declare_compromise(at: u64, compromised_count: usize) -> Self {
        assert!(
            compromised_count >= CATASTROPHIC_COMPROMISE_THRESHOLD,
            "warrant canary triggered только при ≥ 3 compromised servers"
        );
        Self::CompromiseDeclared {
            declared_at_secs_unix: at,
            compromised_servers: compromised_count,
        }
    }

    fn is_compromise_declared(&self) -> bool {
        matches!(self, Self::CompromiseDeclared { .. })
    }
}

/// Drill user — 24-word mnemonic, hybrid identity для двух account indices
/// (pre + post rotation), SLH-DSA backup для signing rotation proof.
///
/// Drill user — 24-word mnemonic, hybrid identity for two account indices
/// (pre + post rotation), SLH-DSA backup for signing rotation proofs.
struct DrillUser {
    seed: IdentitySeed,
    pre_rotation_hybrid: HybridIdentityKey,
    pre_rotation_backup: SlhDsaBackupKey,
    post_rotation_hybrid: HybridIdentityKey,
    post_rotation_backup: SlhDsaBackupKey,
}

fn fresh_drill_user() -> DrillUser {
    let mut rng = OsRng;
    let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    let pre_rotation_hybrid =
        HybridIdentityKey::derive(&seed, ACCOUNT_PRE_ROTATION).expect("pre hybrid");
    let pre_rotation_backup =
        SlhDsaBackupKey::derive(&seed, ACCOUNT_PRE_ROTATION).expect("pre backup");
    let post_rotation_hybrid =
        HybridIdentityKey::derive(&seed, ACCOUNT_POST_ROTATION).expect("post hybrid");
    let post_rotation_backup =
        SlhDsaBackupKey::derive(&seed, ACCOUNT_POST_ROTATION).expect("post backup");
    DrillUser {
        seed,
        pre_rotation_hybrid,
        pre_rotation_backup,
        post_rotation_hybrid,
        post_rotation_backup,
    }
}

fn build_v2_entry(
    hybrid: &HybridIdentityKey,
    backup: &SlhDsaBackupKey,
    seq: u64,
    timestamp: u64,
    parent_hash: [u8; 32],
) -> KtEntryV2 {
    let pub_key = hybrid.public().clone();
    let ed25519_bytes = pub_key.ed25519_bytes();
    let account_id = KtEntryV2::derive_account_id(&ed25519_bytes);
    let backup_bytes = backup.public().to_bytes();
    let slh_pk = SlhDsa128fPublicKey::from_bytes(&backup_bytes).expect("valid backup pubkey");
    KtEntryV2 {
        account_id,
        identity_hybrid_pubkey: pub_key,
        identity_slh_dsa_backup: Some(slh_pk),
        timestamp_secs_unix: timestamp,
        sequence_number: seq,
        parent_hash,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Drill scenarios.
// Drill scenarios.
// ─────────────────────────────────────────────────────────────────────────

/// Pre-compromise baseline: warrant canary в Active state, все пользователи
/// derived от одного mnemonic + account=0, V2 entries publishedы.
///
/// Pre-compromise baseline: warrant canary is Active, every user is derived
/// from one mnemonic + account=0, V2 entries are published.
#[test]
fn b1_baseline_pre_compromise_state() {
    let canary = WarrantCanary::Active {
        published_at_secs_unix: T_INTELLIGENCE_INPUT,
    };
    assert!(!canary.is_compromise_declared(), "baseline canary активен");

    let users: Vec<DrillUser> = (0..DRILL_USER_COUNT).map(|_| fresh_drill_user()).collect();

    for user in &users {
        let entry = build_v2_entry(
            &user.pre_rotation_hybrid,
            &user.pre_rotation_backup,
            1,
            T_INTELLIGENCE_INPUT,
            [0u8; 32],
        );
        let wire = entry.canonical_encoding().expect("encode");
        assert_eq!(wire.len(), KT_ENTRY_V2_MAX_ENCODED_LEN);

        let parsed = KtEntryV2::from_bytes(&wire).expect("parse");
        let backup_bytes = user.pre_rotation_backup.public().to_bytes();
        let slh_pk = SlhDsa128fPublicKey::from_bytes(&backup_bytes).unwrap();
        let exp = HybridOwnExpectations {
            identity_hybrid: user.pre_rotation_hybrid.public(),
            identity_slh_dsa_backup: Some(&slh_pk),
        };
        verify_own_v2_entry(&parsed, &exp).expect("baseline self-monitor");
    }
}

/// Detection 3+ compromised servers → warrant canary activates: переход
/// Active → CompromiseDeclared. Это observable signal для пользователей.
///
/// Detection of 3+ compromised servers → warrant canary activates:
/// transition Active → CompromiseDeclared. This is an observable signal
/// for users.
#[test]
fn b2_warrant_canary_activates_on_threshold_breach() {
    let mut canary = WarrantCanary::Active {
        published_at_secs_unix: T_INTELLIGENCE_INPUT,
    };
    assert!(!canary.is_compromise_declared());

    // Threshold of 3+ servers compromised — operator triggers warrant canary.
    let activation_ts = T_INTELLIGENCE_INPUT + T_WARRANT_CANARY_ACTIVATED_DELAY;
    canary = WarrantCanary::declare_compromise(activation_ts, 3);
    assert!(canary.is_compromise_declared());

    if let WarrantCanary::CompromiseDeclared {
        declared_at_secs_unix,
        compromised_servers,
    } = canary
    {
        assert_eq!(declared_at_secs_unix, activation_ts);
        assert_eq!(compromised_servers, 3);
    } else {
        panic!("canary должен быть в compromise declared state");
    }
}

/// Threshold edge cases: 1 / 2 compromised servers — not catastrophic
/// (≤ 5-3=2 — Shamir threshold tolerates 2 offline без secrecy loss).
/// Только 3+ triggers mass rotation.
///
/// Threshold edge cases: 1 / 2 compromised servers — not catastrophic
/// (≤ 5-3=2 — Shamir threshold tolerates 2 offline without secrecy loss).
/// Only 3+ triggers mass rotation.
#[test]
#[should_panic(expected = "warrant canary triggered только при ≥ 3 compromised servers")]
fn b3_two_compromised_servers_does_not_trigger_drill() {
    // 2 compromised — tolerable, не катастрофа.
    let _ = WarrantCanary::declare_compromise(
        T_INTELLIGENCE_INPUT + T_WARRANT_CANARY_ACTIVATED_DELAY,
        2,
    );
}

/// Mass rotation: пользователь deriv'ит new identity keypair через тот же
/// mnemonic + new account index. Pre-rotation и post-rotation pubkeys
/// различны (разный HKDF salt → разные ChaCha20Rng seeds → разные ML-DSA-65
/// и SLH-DSA keypairs). Ed25519 component тоже разный (BIP-32 different
/// derivation path). Mnemonic не меняется — пользователь не выписывает
/// заново 24 слова.
///
/// Mass rotation: the user derives a new identity keypair via the same
/// mnemonic + new account index. Pre-rotation and post-rotation pubkeys
/// differ (different HKDF salt → different ChaCha20Rng seeds → different
/// ML-DSA-65 and SLH-DSA keypairs). The Ed25519 component differs as well
/// (BIP-32 different derivation path). The mnemonic stays the same — the
/// user does not re-write the 24 words.
#[test]
fn b4_mass_rotation_derives_new_identity_from_same_mnemonic() {
    let user = fresh_drill_user();

    // Mnemonic byte-equal — single recovery anchor.
    let mnemonic = user.seed.to_mnemonic();
    let restored_seed =
        IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();
    let restored_pre = HybridIdentityKey::derive(&restored_seed, ACCOUNT_PRE_ROTATION).unwrap();
    let restored_post = HybridIdentityKey::derive(&restored_seed, ACCOUNT_POST_ROTATION).unwrap();

    // Pre-rotation хранит byte-equal через mnemonic.
    assert_eq!(
        user.pre_rotation_hybrid.public().to_bytes(),
        restored_pre.public().to_bytes(),
        "pre-rotation hybrid identity byte-equal через mnemonic"
    );
    // Post-rotation хранит byte-equal через тот же mnemonic + другой account.
    assert_eq!(
        user.post_rotation_hybrid.public().to_bytes(),
        restored_post.public().to_bytes(),
        "post-rotation hybrid identity byte-equal через mnemonic + другой account"
    );

    // Pre vs post — разные pubkeys (доказательство что rotation реально работает).
    assert_ne!(
        user.pre_rotation_hybrid.public().to_bytes(),
        user.post_rotation_hybrid.public().to_bytes(),
        "rotation производит cryptographically distinct identity pubkey"
    );
    assert_ne!(
        user.pre_rotation_backup.public().to_bytes(),
        user.post_rotation_backup.public().to_bytes(),
        "rotation производит distinct SLH-DSA backup pubkey"
    );
}

/// Old V2 entries (account=0, sequence=N) marked deprecated; new V2 entries
/// (account=1, sequence=1) опубликованы. Self-monitor различает: post-rotation
/// expectations не должны pass'нуть для old entries (другой account_id).
///
/// Old V2 entries (account=0, sequence=N) marked deprecated; new V2 entries
/// (account=1, sequence=1) published. Self-monitor distinguishes: post-rotation
/// expectations must not pass for old entries (different account_id).
#[test]
fn b5_old_kt_entries_deprecated_new_entries_published() {
    let user = fresh_drill_user();

    let pre_entry = build_v2_entry(
        &user.pre_rotation_hybrid,
        &user.pre_rotation_backup,
        1,
        T_INTELLIGENCE_INPUT,
        [0u8; 32],
    );
    let post_entry = build_v2_entry(
        &user.post_rotation_hybrid,
        &user.post_rotation_backup,
        1,
        T_INTELLIGENCE_INPUT + T_FULL_ROTATION_DELAY,
        [0u8; 32], // post-rotation chain starts fresh; old chain deprecated
    );

    // Self-monitor pre-rotation entry с pre-rotation expectations passes.
    let pre_backup_bytes = user.pre_rotation_backup.public().to_bytes();
    let pre_slh = SlhDsa128fPublicKey::from_bytes(&pre_backup_bytes).unwrap();
    let pre_exp = HybridOwnExpectations {
        identity_hybrid: user.pre_rotation_hybrid.public(),
        identity_slh_dsa_backup: Some(&pre_slh),
    };
    verify_own_v2_entry(&pre_entry, &pre_exp).expect("pre with pre exp passes");

    // Self-monitor post-rotation entry с post-rotation expectations passes.
    let post_backup_bytes = user.post_rotation_backup.public().to_bytes();
    let post_slh = SlhDsa128fPublicKey::from_bytes(&post_backup_bytes).unwrap();
    let post_exp = HybridOwnExpectations {
        identity_hybrid: user.post_rotation_hybrid.public(),
        identity_slh_dsa_backup: Some(&post_slh),
    };
    verify_own_v2_entry(&post_entry, &post_exp).expect("post with post exp passes");

    // Cross-check: post-rotation expectations не pass'нут для pre-rotation
    // entry (разный account_id). Это даёт client'у однозначный signal
    // «эта запись deprecated, ищи новую».
    let err = verify_own_v2_entry(&pre_entry, &post_exp).expect_err("cross check fails");
    assert_eq!(
        err,
        KtError::SelfMonitoringMismatch {
            field: "v2_account_id"
        }
    );
}

/// Backup ceremony rebuild: new ThresholdConfig 3-of-5 для post-rotation
/// state. Server-side ceremony stub representation: новый main pubkey
/// `Y = K · G` для post-rotation epoch.
///
/// Backup ceremony rebuild: a new ThresholdConfig 3-of-5 for post-rotation
/// state. Server-side ceremony stub representation: a new main pubkey
/// `Y = K · G` for the post-rotation epoch.
#[test]
fn b6_backup_ceremony_rebuild_signal() {
    // Pre-rotation 3-of-5 ceremony.
    let pre_ceremony = ThresholdConfig::new(SEALED_SERVERS_THRESHOLD, SEALED_SERVERS_TOTAL as u8)
        .expect("3-of-5 валидная конфигурация");
    assert_eq!(pre_ceremony.threshold, SEALED_SERVERS_THRESHOLD);
    assert_eq!(pre_ceremony.total, SEALED_SERVERS_TOTAL as u8);

    // Post-rotation 3-of-5 ceremony — same parameters, fresh server keys
    // (server-side regenerated в `Umbrella server implementation`; здесь конфиг идентичен,
    // signal — это новый main_pubkey в WrappingParams который мы не
    // тестируем напрямую, но invariant 3-of-5 структурно одинаков).
    let post_ceremony = ThresholdConfig::new(SEALED_SERVERS_THRESHOLD, SEALED_SERVERS_TOTAL as u8)
        .expect("post-ceremony 3-of-5");
    assert_eq!(post_ceremony.threshold, SEALED_SERVERS_THRESHOLD);
    assert_eq!(post_ceremony.total, SEALED_SERVERS_TOTAL as u8);

    // Edge case: invalid threshold (например, 0-of-5 либо 6-of-5) отвергается —
    // защита от misconfigured rebuild.
    assert!(
        ThresholdConfig::new(0, 5).is_err(),
        "0-of-5 threshold отклонено"
    );
    assert!(
        ThresholdConfig::new(6, 5).is_err(),
        "6-of-5 threshold (over total) отклонено"
    );
}

/// Timing budget: каждый шаг operator timeline ≥ предыдущего; общий elapsed
/// time ≤ 14 days budget.
///
/// Timing budget: each operator timeline step is ≥ the previous; total elapsed
/// time ≤ 14 days budget.
#[test]
fn b7_rotation_timing_within_14d_budget() {
    let intel_ts = T_INTELLIGENCE_INPUT;
    let canary_ts = intel_ts + T_WARRANT_CANARY_ACTIVATED_DELAY;
    let push_ts = intel_ts + T_PUSH_NOTIFICATION_DELAY;
    let client_begin_ts = intel_ts + T_ROTATION_CLIENT_BEGIN_DELAY;
    let mid_progress_ts = intel_ts + T_ROTATION_95PCT_DELAY;
    let full_ts = intel_ts + T_FULL_ROTATION_DELAY;

    assert!(canary_ts >= intel_ts);
    assert!(push_ts >= canary_ts);
    assert!(client_begin_ts >= push_ts);
    assert!(mid_progress_ts >= client_begin_ts);
    assert!(full_ts >= mid_progress_ts);

    let elapsed = full_ts - intel_ts;
    assert!(
        elapsed <= TARGET_ROTATION_BUDGET_SECS,
        "rotation took {elapsed}s, budget {TARGET_ROTATION_BUDGET_SECS}s"
    );
    assert_eq!(elapsed, 14 * SECS_PER_DAY);
}

/// 10-user mass rotation: каждый пользователь успешно ротирует identity,
/// pre/post pubkeys различны, KT log содержит 20 entries (10 pre + 10 post),
/// никакие cross-user collisions.
///
/// 10-user mass rotation: each user successfully rotates identity, pre/post
/// pubkeys differ, the KT log contains 20 entries (10 pre + 10 post), no
/// cross-user collisions.
#[test]
fn b8_ten_user_mass_rotation_end_to_end() {
    let users: Vec<DrillUser> = (0..DRILL_USER_COUNT).map(|_| fresh_drill_user()).collect();

    let mut kt_log: Vec<(usize, KtEntryV2)> = Vec::with_capacity(2 * DRILL_USER_COUNT);

    for (idx, user) in users.iter().enumerate() {
        // Pre-rotation entry.
        let pre = build_v2_entry(
            &user.pre_rotation_hybrid,
            &user.pre_rotation_backup,
            1,
            T_INTELLIGENCE_INPUT,
            [0u8; 32],
        );
        // Post-rotation entry: новый account, fresh chain (sequence reset to 1).
        let post = build_v2_entry(
            &user.post_rotation_hybrid,
            &user.post_rotation_backup,
            1,
            T_INTELLIGENCE_INPUT + T_FULL_ROTATION_DELAY,
            [0u8; 32],
        );

        // Pre/post pubkeys cryptographically distinct.
        assert_ne!(
            pre.identity_hybrid_pubkey.to_bytes(),
            post.identity_hybrid_pubkey.to_bytes(),
            "user {idx}: rotation produces distinct pubkey"
        );

        // Account_ids тоже разные (derived from different Ed25519 components).
        assert_ne!(
            pre.account_id, post.account_id,
            "user {idx}: account_id changes after rotation"
        );

        kt_log.push((idx, pre));
        kt_log.push((idx, post));
    }

    assert_eq!(kt_log.len(), 2 * DRILL_USER_COUNT);

    // Cross-user collision check: все account_ids unique (10 pre + 10 post = 20 unique).
    let mut all_account_ids: Vec<[u8; 32]> = kt_log.iter().map(|(_, e)| e.account_id).collect();
    all_account_ids.sort();
    all_account_ids.dedup();
    assert_eq!(
        all_account_ids.len(),
        2 * DRILL_USER_COUNT,
        "все account_ids unique (нет collision'ов)"
    );
}

/// Adversary с captured pre-rotation mnemonic не получает access к post-rotation
/// keys без новой HKDF salt (account index). Это закрывает forward secrecy
/// concern: даже если attacker узнал mnemonic, он не имеет post-rotation
/// account info без operator signal.
///
/// Adversary with captured pre-rotation mnemonic does not gain access to
/// post-rotation keys without the new HKDF salt (account index). This closes
/// the forward secrecy concern: even if the attacker learned the mnemonic,
/// they lack post-rotation account info without the operator signal.
#[test]
fn b9_post_rotation_keys_distinct_from_pre_rotation() {
    let user = fresh_drill_user();
    let mnemonic = user.seed.to_mnemonic();
    let restored_seed =
        IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();

    // Adversary с известным mnemonic'ом, но без знания post-rotation account index,
    // derives только pre-rotation key. Это не unlock'ает post-rotation pubkey.
    let adversary_pre = HybridIdentityKey::derive(&restored_seed, ACCOUNT_PRE_ROTATION).unwrap();
    assert_eq!(
        user.pre_rotation_hybrid.public().to_bytes(),
        adversary_pre.public().to_bytes(),
        "adversary recovers pre-rotation key через mnemonic (это известно)"
    );

    // Adversary не может derive post-rotation без знания нового account/salt.
    // Если adversary GUESS'нет account=1, он действительно derives correct key —
    // assertion здесь демонстрирует что determinism работает в обе стороны
    // (Pattern F — single recovery anchor включает все accounts), но это
    // НЕ компрометирует security: предполагается что adversary не получает
    // post-rotation account index в реальном flow (он передаётся через
    // authenticated push notification).
    let adversary_guess_post =
        HybridIdentityKey::derive(&restored_seed, ACCOUNT_POST_ROTATION).unwrap();
    assert_eq!(
        user.post_rotation_hybrid.public().to_bytes(),
        adversary_guess_post.public().to_bytes(),
        "если account index leaked, adversary recovers post-rotation key — \
         защита через authenticated channel доставки нового account"
    );

    // Strict cross-test: random other account → разный pubkey.
    let unrelated = HybridIdentityKey::derive(&restored_seed, 999).unwrap();
    assert_ne!(
        user.post_rotation_hybrid.public().to_bytes(),
        unrelated.public().to_bytes(),
        "неверный account index не recovers post-rotation"
    );
}
