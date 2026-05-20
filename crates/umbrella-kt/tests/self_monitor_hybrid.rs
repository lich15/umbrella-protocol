#![allow(deprecated)] // Round-6: integration test exercises legacy IdentitySeed::generate fixture
//! Integration tests блока 8.5: end-to-end self-monitoring V2 entries через
//! wire-format roundtrip.
//! Integration tests for block 8.5: end-to-end self-monitoring of V2 entries
//! through wire-format roundtrip.
//!
//! Эти tests fixture'ят следующие end-to-end scenarios:
//! - Клиент опубликовал V2 entry с своим hybrid identity.
//! - Сервер вернул entry в wire-format bytes.
//! - Клиент парсит bytes → `KtEntryV2`.
//! - Клиент вызывает `verify_own_v2_entry` с собственными expectations.
//! - При match — Ok(()); при tampering — `SelfMonitoringMismatch { field }`
//!   с конкретным tag.
//!
//! Защита от ghost-participant атаки на PQ identity layer: server (или MITM)
//! не сможет подменить hybrid pubkey без detection через self-monitoring.
//!
//! These tests fixture the following end-to-end scenarios:
//! - The client published a V2 entry with its hybrid identity.
//! - The server returned the entry in wire-format bytes.
//! - The client parses the bytes → `KtEntryV2`.
//! - The client calls `verify_own_v2_entry` with its own expectations.
//! - On match — Ok(()); on tampering — `SelfMonitoringMismatch { field }`
//!   with a concrete tag.
//!
//! Protects against the ghost-participant attack at the PQ identity layer:
//! a server (or MITM) cannot substitute the hybrid pubkey without detection
//! via self-monitoring.

#![cfg(feature = "pq")]

use rand_core::OsRng;

use umbrella_identity::{HybridIdentityKey, IdentitySeed, MnemonicLanguage};
use umbrella_kt::{verify_own_v2_entry, HybridOwnExpectations, KtEntryV2, KtError};
use umbrella_pq::{slh_dsa_128f_keygen, SlhDsa128fPublicKey};

/// Создаёт fresh hybrid identity для tests.
/// Creates a fresh hybrid identity for tests.
fn fresh_hybrid(account: u32) -> HybridIdentityKey {
    let mut rng = OsRng;
    let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    HybridIdentityKey::derive(&seed, account).unwrap()
}

fn build_entry(
    hybrid: &HybridIdentityKey,
    backup: Option<SlhDsa128fPublicKey>,
    seq: u64,
) -> KtEntryV2 {
    let pub_key = hybrid.public().clone();
    let ed25519_bytes = pub_key.ed25519_bytes();
    let account_id = KtEntryV2::derive_account_id(&ed25519_bytes);
    KtEntryV2 {
        account_id,
        identity_hybrid_pubkey: pub_key,
        identity_slh_dsa_backup: backup,
        timestamp_secs_unix: 1_700_000_000,
        sequence_number: seq,
        parent_hash: [0u8; 32],
    }
}

/// Полный roundtrip: serialize → deserialize → verify_own_v2_entry passes.
/// Full roundtrip: serialize → deserialize → verify_own_v2_entry passes.
#[test]
fn end_to_end_roundtrip_no_backup_passes_self_monitor() {
    let hybrid = fresh_hybrid(0);
    let entry = build_entry(&hybrid, None, 1);
    let wire = entry.canonical_encoding().unwrap();

    // Server возвращает wire bytes; клиент парсит обратно.
    // Server returns wire bytes; client parses back.
    let parsed = KtEntryV2::from_bytes(&wire).unwrap();

    let exp = HybridOwnExpectations {
        identity_hybrid: hybrid.public(),
        identity_slh_dsa_backup: None,
    };
    verify_own_v2_entry(&parsed, &exp).unwrap();
}

#[test]
fn end_to_end_roundtrip_with_backup_passes_self_monitor() {
    let hybrid = fresh_hybrid(0);
    let mut rng = OsRng;
    let (slh_pk, _) = slh_dsa_128f_keygen(&mut rng).unwrap();
    let entry = build_entry(&hybrid, Some(slh_pk.clone()), 1);
    let wire = entry.canonical_encoding().unwrap();
    let parsed = KtEntryV2::from_bytes(&wire).unwrap();

    let exp = HybridOwnExpectations {
        identity_hybrid: hybrid.public(),
        identity_slh_dsa_backup: Some(&slh_pk),
    };
    verify_own_v2_entry(&parsed, &exp).unwrap();
}

/// Атакующий подменил Ed25519 component hybrid pubkey в wire-bytes (валидная
/// curve point из другого identity). После roundtrip — `verify_own_v2_entry`
/// детектит mismatch.
/// Attacker substituted the Ed25519 component of the hybrid pubkey in the
/// wire bytes (valid curve point from another identity). After roundtrip,
/// `verify_own_v2_entry` detects the mismatch.
#[test]
fn tampered_ed25519_in_wire_bytes_detected_after_roundtrip() {
    let hybrid_a = fresh_hybrid(0);
    let hybrid_b = fresh_hybrid(0);

    let entry = build_entry(&hybrid_a, None, 1);
    let mut wire = entry.canonical_encoding().unwrap();

    // Подменяем 32 байта Ed25519 component (offset 33: после version + account_id).
    // Replace 32 bytes of the Ed25519 component (offset 33: after version + account_id).
    let b_ed25519 = hybrid_b.public().ed25519_bytes();
    wire[33..33 + 32].copy_from_slice(&b_ed25519);

    // Server возвращает tampered bytes.
    // Server returns tampered bytes.
    let parsed = KtEntryV2::from_bytes(&wire).unwrap();

    // Клиент проверяет с original expectations — detection.
    // Client checks against original expectations — detection.
    let exp = HybridOwnExpectations {
        identity_hybrid: hybrid_a.public(),
        identity_slh_dsa_backup: None,
    };
    let err = verify_own_v2_entry(&parsed, &exp).unwrap_err();
    // Поскольку Ed25519 changed — hybrid pubkey bytes changed → mismatch detected.
    // account_id остался прежним (не пересчитан после подмены) — поэтому первая
    // проверка (account_id) проходит, а вторая (hybrid pubkey) падает.
    // Since Ed25519 changed — hybrid pubkey bytes changed → mismatch detected.
    // account_id stayed the same (not recomputed after substitution) — so the
    // first check (account_id) passes, and the second (hybrid pubkey) fails.
    assert_eq!(
        err,
        KtError::SelfMonitoringMismatch {
            field: "v2_identity_hybrid_pubkey"
        }
    );
}

/// Атакующий подменил account_id (но оставил hybrid pubkey клиента). Это
/// catches: account_id мismatch detected первым.
/// Attacker substituted account_id (but kept the client's hybrid pubkey).
/// Caught: account_id mismatch detected first.
#[test]
fn tampered_account_id_detected() {
    let hybrid = fresh_hybrid(0);
    let mut entry = build_entry(&hybrid, None, 1);
    entry.account_id[0] ^= 0xFF;
    let wire = entry.canonical_encoding().unwrap();
    let parsed = KtEntryV2::from_bytes(&wire).unwrap();

    let exp = HybridOwnExpectations {
        identity_hybrid: hybrid.public(),
        identity_slh_dsa_backup: None,
    };
    let err = verify_own_v2_entry(&parsed, &exp).unwrap_err();
    assert_eq!(
        err,
        KtError::SelfMonitoringMismatch {
            field: "v2_account_id"
        }
    );
}

/// Атакующий **добавил** SLH-DSA backup pubkey клиенту который его не
/// устанавливал. Это значит attacker'у удобно иметь backup-recovery путь к
/// аккаунту. Self-monitor отвергает.
/// Attacker **added** an SLH-DSA backup pubkey for a client that did not set
/// one. This gives the attacker a backup-recovery path. Self-monitor rejects.
#[test]
fn ghost_slh_dsa_backup_injection_detected() {
    let hybrid = fresh_hybrid(0);
    let mut rng = OsRng;
    let (attacker_pk, _) = slh_dsa_128f_keygen(&mut rng).unwrap();

    // Entry имеет attacker'ский backup pubkey.
    // Entry contains the attacker's backup pubkey.
    let entry = build_entry(&hybrid, Some(attacker_pk), 1);
    let wire = entry.canonical_encoding().unwrap();
    let parsed = KtEntryV2::from_bytes(&wire).unwrap();

    // Клиент не expects backup — он его никогда не configurал.
    // Client does not expect a backup — they never configured one.
    let exp = HybridOwnExpectations {
        identity_hybrid: hybrid.public(),
        identity_slh_dsa_backup: None,
    };
    let err = verify_own_v2_entry(&parsed, &exp).unwrap_err();
    assert_eq!(
        err,
        KtError::SelfMonitoringMismatch {
            field: "v2_slh_dsa_backup_unexpected"
        }
    );
}

/// Атакующий **удалил** SLH-DSA backup pubkey из entry (привычная attack:
/// client исключён от recovery path).
/// Attacker **stripped** the SLH-DSA backup pubkey from the entry (common
/// attack: client is locked out from recovery path).
#[test]
fn missing_slh_dsa_backup_detected() {
    let hybrid = fresh_hybrid(0);
    let mut rng = OsRng;
    let (slh_pk, _) = slh_dsa_128f_keygen(&mut rng).unwrap();

    // Server вернул entry без backup pubkey.
    // Server returned an entry without the backup pubkey.
    let entry = build_entry(&hybrid, None, 1);
    let wire = entry.canonical_encoding().unwrap();
    let parsed = KtEntryV2::from_bytes(&wire).unwrap();

    let exp = HybridOwnExpectations {
        identity_hybrid: hybrid.public(),
        identity_slh_dsa_backup: Some(&slh_pk),
    };
    let err = verify_own_v2_entry(&parsed, &exp).unwrap_err();
    assert_eq!(
        err,
        KtError::SelfMonitoringMismatch {
            field: "v2_slh_dsa_backup_missing"
        }
    );
}

/// Атакующий подменил SLH-DSA backup pubkey на свой (возможный takeover при
/// catastrophic recovery flow).
/// Attacker substituted the SLH-DSA backup pubkey with their own (possible
/// takeover during catastrophic recovery flow).
#[test]
fn substituted_slh_dsa_backup_detected() {
    let hybrid = fresh_hybrid(0);
    let mut rng = OsRng;
    let (real_pk, _) = slh_dsa_128f_keygen(&mut rng).unwrap();
    let (attacker_pk, _) = slh_dsa_128f_keygen(&mut rng).unwrap();

    let entry = build_entry(&hybrid, Some(attacker_pk), 1);
    let wire = entry.canonical_encoding().unwrap();
    let parsed = KtEntryV2::from_bytes(&wire).unwrap();

    let exp = HybridOwnExpectations {
        identity_hybrid: hybrid.public(),
        identity_slh_dsa_backup: Some(&real_pk),
    };
    let err = verify_own_v2_entry(&parsed, &exp).unwrap_err();
    assert_eq!(
        err,
        KtError::SelfMonitoringMismatch {
            field: "v2_slh_dsa_backup_pubkey"
        }
    );
}

/// Multiple entries для same client — все должны pass self-monitoring.
/// Multiple entries for the same client — all must pass self-monitoring.
#[test]
fn multiple_entries_same_identity_all_pass() {
    let hybrid = fresh_hybrid(0);
    let mut rng = OsRng;
    let (slh_pk, _) = slh_dsa_128f_keygen(&mut rng).unwrap();

    for seq in 1..=5u64 {
        let entry = build_entry(&hybrid, Some(slh_pk.clone()), seq);
        let wire = entry.canonical_encoding().unwrap();
        let parsed = KtEntryV2::from_bytes(&wire).unwrap();
        let exp = HybridOwnExpectations {
            identity_hybrid: hybrid.public(),
            identity_slh_dsa_backup: Some(&slh_pk),
        };
        verify_own_v2_entry(&parsed, &exp).unwrap();
        // sequence_number recovered корректно.
        // sequence_number recovered correctly.
        assert_eq!(parsed.sequence_number, seq);
    }
}

/// Cross-identity isolation: entry от identity A не должна passнуть как identity B.
/// Cross-identity isolation: an entry from identity A must not pass as identity B.
#[test]
fn entry_for_different_identity_rejected() {
    let hybrid_a = fresh_hybrid(0);
    let hybrid_b = fresh_hybrid(0);
    let entry_a = build_entry(&hybrid_a, None, 1);
    let wire = entry_a.canonical_encoding().unwrap();
    let parsed = KtEntryV2::from_bytes(&wire).unwrap();

    // Клиент B пытается self-monitor entry_a.
    // Client B tries to self-monitor entry_a.
    let exp_b = HybridOwnExpectations {
        identity_hybrid: hybrid_b.public(),
        identity_slh_dsa_backup: None,
    };
    let err = verify_own_v2_entry(&parsed, &exp_b).unwrap_err();
    // Account_id derived from B's Ed25519, entry account_id derived from A's.
    // Account_id derived from B's Ed25519, entry account_id derived from A's.
    assert_eq!(
        err,
        KtError::SelfMonitoringMismatch {
            field: "v2_account_id"
        }
    );
}
