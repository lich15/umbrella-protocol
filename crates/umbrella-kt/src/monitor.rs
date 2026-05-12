//! Self-monitoring: клиент сравнивает entry в KT-логе с ожидаемыми публичными ключами.
//! Self-monitoring: client compares the KT-log entry against expected public keys.
//!
//! ## Расширение блока 8.5 (Этап 8 PQ opt-in)
//!
//! Под `feature = "pq"` добавлены `HybridOwnExpectations` и `verify_own_v2_entry`,
//! которые проверяют hybrid identity (Ed25519 + ML-DSA-65 pubkey) + optional
//! SLH-DSA-128f backup pubkey в `KtEntryV2`. Та же доктрина что для V1: любое
//! расхождение возвращается как `KtError::SelfMonitoringMismatch { field }` без
//! silent acceptance (постулат 14).
//!
//! ## Block 8.5 extension (Stage 8 PQ opt-in)
//!
//! Under `feature = "pq"` we add `HybridOwnExpectations` and `verify_own_v2_entry`,
//! which check the hybrid identity (Ed25519 + ML-DSA-65 pubkey) plus the optional
//! SLH-DSA-128f backup pubkey in a `KtEntryV2`. Same doctrine as for V1: any
//! mismatch returns `KtError::SelfMonitoringMismatch { field }` with no silent
//! acceptance (postulate 14).
//!
//! Главная функция self-monitoring: клиент **знает** что должно быть в его записи (собственный
//! identity_ed25519, identity_x25519, список активных device-keys). Когда клиент получает KT
//! entry от лога, он проверяет что байт-в-байт совпадает. Любое расхождение — сигнал либо
//! atacked-log либо ghost-participant: атакующий вставил чужой device-key или подменил
//! identity-key. Клиент немедленно алертит пользователя.
//!
//! Main self-monitoring role: the client **knows** what its own entry should contain (own
//! identity_ed25519, identity_x25519, active device-keys). When it receives a KT entry from
//! the log, it checks byte-for-byte equality. Any mismatch signals either an attacked log or
//! ghost participant: attacker injected a foreign device-key or swapped identity. Client
//! alerts the user immediately.

use umbrella_identity::{DeviceKeyPublic, IdentityKeyPublic, IdentityX25519KeyPublic};

use crate::entry::{DeviceAttestationRef, KtEntry};
use crate::error::{KtError, Result};

/// Ожидания клиента о содержимом своей KT-записи.
/// Client expectations about its own KT entry contents.
#[derive(Clone, Debug)]
pub struct OwnExpectations<'a> {
    /// Ожидаемый Ed25519 identity-ключ (собственный). Expected Ed25519 identity (own).
    pub identity_ed25519: &'a IdentityKeyPublic,
    /// Ожидаемый X25519 identity-ключ (собственный). Expected X25519 identity (own).
    pub identity_x25519: &'a IdentityX25519KeyPublic,
    /// Ожидаемый набор активных device-keys (порядок значения не имеет).
    /// Expected active device-keys set (order does not matter).
    pub devices: &'a [(u32, DeviceKeyPublic)],
}

/// Проверяет что entry соответствует собственным ожиданиям клиента.
/// Verifies that the entry matches the client's own expectations.
///
/// Возвращает:
/// - `Ok(())` — все поля совпадают.
/// - `Err(SelfMonitoringMismatch { field })` — конкретное поле расходится.
///
/// Порядок проверок: identity_ed25519 → identity_x25519 → account_id → devices.
/// Каждое несоответствие — показание атаки, клиент должен алертить.
///
/// Returns:
/// - `Ok(())` — all fields match.
/// - `Err(SelfMonitoringMismatch { field })` — specific field mismatch.
///
/// Check order: identity_ed25519 → identity_x25519 → account_id → devices.
/// Every mismatch is evidence of attack; the client must alert.
pub fn verify_own_entry(entry: &KtEntry, expected: &OwnExpectations<'_>) -> Result<()> {
    if entry.identity_ed25519_pub.to_bytes() != expected.identity_ed25519.to_bytes() {
        return Err(KtError::SelfMonitoringMismatch {
            field: "identity_ed25519_pub",
        });
    }
    if entry.identity_x25519_pub.to_bytes() != expected.identity_x25519.to_bytes() {
        return Err(KtError::SelfMonitoringMismatch {
            field: "identity_x25519_pub",
        });
    }
    let derived = KtEntry::derive_account_id(expected.identity_ed25519);
    if entry.account_id != derived {
        return Err(KtError::SelfMonitoringMismatch {
            field: "account_id",
        });
    }

    // Сравниваем device-set как множество: одинаковое количество, каждый ожидаемый есть в entry.
    // Compare device-set as a set: same count, each expected is present in entry.
    if entry.devices.len() != expected.devices.len() {
        return Err(KtError::SelfMonitoringMismatch {
            field: "device_count",
        });
    }
    for (exp_idx, exp_pub) in expected.devices {
        let found = entry.devices.iter().any(|d: &DeviceAttestationRef| {
            d.device_index == *exp_idx && d.device_pub.to_bytes() == exp_pub.to_bytes()
        });
        if !found {
            return Err(KtError::SelfMonitoringMismatch {
                field: "device_set_missing_expected",
            });
        }
    }
    // Также: в entry не должно быть devices которых нет в expected.
    // Also: the entry must not contain devices missing from expected.
    for d in &entry.devices {
        let in_expected = expected.devices.iter().any(|(idx, pub_k)| {
            *idx == d.device_index && pub_k.to_bytes() == d.device_pub.to_bytes()
        });
        if !in_expected {
            return Err(KtError::SelfMonitoringMismatch {
                field: "device_set_unexpected_entry",
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// V2 self-monitoring (Этап 8, блок 8.5).
// V2 self-monitoring (Stage 8, block 8.5).
// ---------------------------------------------------------------------------

/// Ожидания клиента о содержимом своей V2 KT-записи. Включает hybrid identity
/// (Ed25519 + ML-DSA-65 pubkey, byte-level) и optional SLH-DSA-128f backup
/// pubkey. Если backup expected `None` — entry **обязана** иметь
/// `identity_slh_dsa_backup == None`; если backup expected `Some(_)` — entry
/// **обязана** содержать соответствующий byte-equal pubkey.
///
/// Ed25519 component берётся из hybrid pubkey (см. блок 8.3 invariant: hybrid
/// Ed25519 byte-exact == classical IdentityKey). ML-DSA-65 component derived
/// детерминистически из IdentitySeed (HKDF + ChaCha20Rng) — клиент знает свой
/// hybrid pubkey локально и сравнивает с entry.
///
/// Client expectations about its own V2 KT entry. Includes the hybrid identity
/// (Ed25519 + ML-DSA-65 pubkey, byte-level) plus the optional SLH-DSA-128f
/// backup pubkey. If backup is expected `None` — the entry **must** have
/// `identity_slh_dsa_backup == None`; if backup is expected `Some(_)` — the
/// entry **must** carry the corresponding byte-equal pubkey.
///
/// The Ed25519 component comes from the hybrid pubkey (see block 8.3
/// invariant: hybrid Ed25519 byte-exact == classical IdentityKey). The
/// ML-DSA-65 component is derived deterministically from the IdentitySeed
/// (HKDF + ChaCha20Rng) — the client knows its own hybrid pubkey locally and
/// compares against the entry.
#[cfg(feature = "pq")]
#[derive(Clone, Debug)]
pub struct HybridOwnExpectations<'a> {
    /// Ожидаемый hybrid pubkey (Ed25519 + ML-DSA-65). Сравнивается byte-в-байт
    /// через `to_bytes()`.
    /// Expected hybrid pubkey (Ed25519 + ML-DSA-65). Compared byte-for-byte
    /// via `to_bytes()`.
    pub identity_hybrid: &'a umbrella_identity::HybridIdentityKeyPublic,

    /// Ожидаемый SLH-DSA-128f backup pubkey:
    /// - `None` — клиент не имеет backup; entry **обязана** также его не иметь.
    /// - `Some(_)` — клиент имеет backup; entry **обязана** иметь byte-equal pubkey.
    ///
    /// Expected SLH-DSA-128f backup pubkey:
    /// - `None` — client has no backup; the entry **must** also have none.
    /// - `Some(_)` — client has a backup; the entry **must** carry a byte-equal pubkey.
    pub identity_slh_dsa_backup: Option<&'a umbrella_pq::SlhDsa128fPublicKey>,
}

/// Проверяет что V2 entry соответствует hybrid expectations клиента.
///
/// Порядок проверок (стабильный contract для caller'ов): account_id →
/// identity_hybrid_pubkey (через `to_bytes()` byte-equal) → SLH-DSA backup
/// (presence + byte-equal). Каждое расхождение даёт `SelfMonitoringMismatch
/// { field }` с конкретным field-tag для UX alert и для tests.
///
/// Field tags:
/// - `"v2_account_id"` — account_id mismatch.
/// - `"v2_identity_hybrid_pubkey"` — hybrid pubkey bytes mismatch.
/// - `"v2_slh_dsa_backup_unexpected"` — entry имеет backup, expected `None`.
/// - `"v2_slh_dsa_backup_missing"` — entry без backup, expected `Some(_)`.
/// - `"v2_slh_dsa_backup_pubkey"` — backup pubkey bytes mismatch.
///
/// Возвращает `Ok(())` при полном match всех полей.
///
/// Verifies that a V2 entry matches the client's hybrid expectations.
///
/// Check order (stable contract for callers): account_id →
/// identity_hybrid_pubkey (via `to_bytes()` byte-equal) → SLH-DSA backup
/// (presence + byte-equal). Each mismatch yields `SelfMonitoringMismatch
/// { field }` with a concrete field tag for UX alerts and for tests.
#[cfg(feature = "pq")]
pub fn verify_own_v2_entry(
    entry: &crate::entry_v2::KtEntryV2,
    expected: &HybridOwnExpectations<'_>,
) -> Result<()> {
    // 1. account_id derived from Ed25519 component — должен matchать.
    // 1. account_id is derived from the Ed25519 component — must match.
    let expected_ed25519 = expected.identity_hybrid.ed25519_bytes();
    let derived_account = crate::entry_v2::KtEntryV2::derive_account_id(&expected_ed25519);
    if entry.account_id != derived_account {
        return Err(KtError::SelfMonitoringMismatch {
            field: "v2_account_id",
        });
    }

    // 2. Hybrid pubkey byte-equal (Ed25519 32 + ML-DSA-65 1952).
    // 2. Hybrid pubkey byte-equal (Ed25519 32 + ML-DSA-65 1952).
    let entry_hybrid_bytes = entry.identity_hybrid_pubkey.to_bytes();
    let expected_hybrid_bytes = expected.identity_hybrid.to_bytes();
    if entry_hybrid_bytes != expected_hybrid_bytes {
        return Err(KtError::SelfMonitoringMismatch {
            field: "v2_identity_hybrid_pubkey",
        });
    }

    // 3. SLH-DSA backup: presence + bytes.
    // 3. SLH-DSA backup: presence + bytes.
    match (
        &entry.identity_slh_dsa_backup,
        expected.identity_slh_dsa_backup,
    ) {
        (None, None) => {}
        (Some(_), None) => {
            return Err(KtError::SelfMonitoringMismatch {
                field: "v2_slh_dsa_backup_unexpected",
            });
        }
        (None, Some(_)) => {
            return Err(KtError::SelfMonitoringMismatch {
                field: "v2_slh_dsa_backup_missing",
            });
        }
        (Some(entry_slh), Some(expected_slh)) => {
            if entry_slh.as_bytes() != expected_slh.as_bytes() {
                return Err(KtError::SelfMonitoringMismatch {
                    field: "v2_slh_dsa_backup_pubkey",
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use rand_core::OsRng;
    use umbrella_identity::{
        Clock, IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock,
    };

    use crate::entry::DeviceAttestationRef;

    fn fresh_keystore_with_devices(indices: &[u32]) -> Arc<InMemoryKeyStore> {
        let mut rng = OsRng;
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let ks = InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>).unwrap();
        for &i in indices {
            ks.add_device(i, None).unwrap();
        }
        Arc::new(ks)
    }

    fn entry_from(ks: &dyn KeyStore, indices: &[u32], epoch: u64) -> KtEntry {
        let identity_ed = ks.identity_public();
        let identity_x = ks.identity_x25519_public();
        let account_id = KtEntry::derive_account_id(&identity_ed);
        let devices = indices
            .iter()
            .map(|&i| DeviceAttestationRef {
                device_index: i,
                device_pub: ks.device_public(i).unwrap(),
                attestation_valid_until: u64::MAX,
            })
            .collect();
        KtEntry {
            account_id,
            epoch,
            identity_ed25519_pub: identity_ed,
            identity_x25519_pub: identity_x,
            devices,
        }
    }

    fn expectations_from<'a>(
        _ks: &'a dyn KeyStore,
        buffer: &'a mut Vec<(u32, DeviceKeyPublic)>,
        identity_ed: &'a IdentityKeyPublic,
        identity_x: &'a IdentityX25519KeyPublic,
    ) -> OwnExpectations<'a> {
        OwnExpectations {
            identity_ed25519: identity_ed,
            identity_x25519: identity_x,
            devices: buffer.as_slice(),
        }
    }

    #[test]
    fn matching_entry_passes() {
        let ks = fresh_keystore_with_devices(&[0, 1]);
        let entry = entry_from(ks.as_ref(), &[0, 1], 1);
        let identity_ed = ks.identity_public();
        let identity_x = ks.identity_x25519_public();
        let mut buf = vec![
            (0u32, ks.device_public(0).unwrap()),
            (1u32, ks.device_public(1).unwrap()),
        ];
        let exp = expectations_from(ks.as_ref(), &mut buf, &identity_ed, &identity_x);
        verify_own_entry(&entry, &exp).unwrap();
    }

    #[test]
    fn swapped_identity_ed25519_detected() {
        let ks_a = fresh_keystore_with_devices(&[0]);
        let ks_b = fresh_keystore_with_devices(&[0]);
        // Attacker подменил Alice's identity_ed25519 на Bob's.
        let mut tampered = entry_from(ks_a.as_ref(), &[0], 1);
        tampered.identity_ed25519_pub = ks_b.identity_public();
        // Alice ожидает свой identity.
        let identity_ed = ks_a.identity_public();
        let identity_x = ks_a.identity_x25519_public();
        let mut buf = vec![(0u32, ks_a.device_public(0).unwrap())];
        let exp = expectations_from(ks_a.as_ref(), &mut buf, &identity_ed, &identity_x);
        let result = verify_own_entry(&tampered, &exp);
        assert_eq!(
            result.unwrap_err(),
            KtError::SelfMonitoringMismatch {
                field: "identity_ed25519_pub"
            }
        );
    }

    #[test]
    fn swapped_identity_x25519_detected() {
        let ks_a = fresh_keystore_with_devices(&[0]);
        let ks_b = fresh_keystore_with_devices(&[0]);
        let mut tampered = entry_from(ks_a.as_ref(), &[0], 1);
        tampered.identity_x25519_pub = ks_b.identity_x25519_public();
        let identity_ed = ks_a.identity_public();
        let identity_x = ks_a.identity_x25519_public();
        let mut buf = vec![(0u32, ks_a.device_public(0).unwrap())];
        let exp = expectations_from(ks_a.as_ref(), &mut buf, &identity_ed, &identity_x);
        let result = verify_own_entry(&tampered, &exp);
        assert_eq!(
            result.unwrap_err(),
            KtError::SelfMonitoringMismatch {
                field: "identity_x25519_pub"
            }
        );
    }

    #[test]
    fn tampered_account_id_detected() {
        let ks = fresh_keystore_with_devices(&[0]);
        let mut tampered = entry_from(ks.as_ref(), &[0], 1);
        tampered.account_id[0] ^= 0x01;
        let identity_ed = ks.identity_public();
        let identity_x = ks.identity_x25519_public();
        let mut buf = vec![(0u32, ks.device_public(0).unwrap())];
        let exp = expectations_from(ks.as_ref(), &mut buf, &identity_ed, &identity_x);
        assert_eq!(
            verify_own_entry(&tampered, &exp).unwrap_err(),
            KtError::SelfMonitoringMismatch {
                field: "account_id"
            }
        );
    }

    #[test]
    fn phantom_device_injection_detected() {
        // Attacker добавил лишний device в Alice's entry (ghost participant).
        // Attacker injected an extra device into Alice's entry (ghost participant).
        let ks_a = fresh_keystore_with_devices(&[0]);
        let ks_attacker = fresh_keystore_with_devices(&[9]);
        let mut tampered = entry_from(ks_a.as_ref(), &[0], 1);
        tampered.devices.push(DeviceAttestationRef {
            device_index: 9,
            device_pub: ks_attacker.device_public(9).unwrap(),
            attestation_valid_until: u64::MAX,
        });
        let identity_ed = ks_a.identity_public();
        let identity_x = ks_a.identity_x25519_public();
        let mut buf = vec![(0u32, ks_a.device_public(0).unwrap())];
        let exp = expectations_from(ks_a.as_ref(), &mut buf, &identity_ed, &identity_x);
        let result = verify_own_entry(&tampered, &exp);
        assert_eq!(
            result.unwrap_err(),
            KtError::SelfMonitoringMismatch {
                field: "device_count"
            }
        );
    }

    #[test]
    fn device_removed_detected() {
        // Attacker удалил устройство из entry (попытка isolate клиент).
        let ks = fresh_keystore_with_devices(&[0, 1]);
        let mut tampered = entry_from(ks.as_ref(), &[0, 1], 1);
        tampered.devices.retain(|d| d.device_index != 1);
        let identity_ed = ks.identity_public();
        let identity_x = ks.identity_x25519_public();
        let mut buf = vec![
            (0u32, ks.device_public(0).unwrap()),
            (1u32, ks.device_public(1).unwrap()),
        ];
        let exp = expectations_from(ks.as_ref(), &mut buf, &identity_ed, &identity_x);
        assert_eq!(
            verify_own_entry(&tampered, &exp).unwrap_err(),
            KtError::SelfMonitoringMismatch {
                field: "device_count"
            }
        );
    }

    #[test]
    fn device_pub_replaced_same_count_detected() {
        // Attacker не добавляет лишних, но подменяет device_pub одного устройства на свой —
        // classic ghost participant. device_count тот же.
        let ks = fresh_keystore_with_devices(&[0]);
        let ks_attacker = fresh_keystore_with_devices(&[42]);
        let mut tampered = entry_from(ks.as_ref(), &[0], 1);
        tampered.devices[0].device_pub = ks_attacker.device_public(42).unwrap();
        let identity_ed = ks.identity_public();
        let identity_x = ks.identity_x25519_public();
        let mut buf = vec![(0u32, ks.device_public(0).unwrap())];
        let exp = expectations_from(ks.as_ref(), &mut buf, &identity_ed, &identity_x);
        let result = verify_own_entry(&tampered, &exp).unwrap_err();
        // Либо missing_expected (ожидаемый device_pub не найден), либо unexpected_entry
        // (в entry есть device_pub которого нет в expected). Оба — сигнал атаки.
        assert!(matches!(
            result,
            KtError::SelfMonitoringMismatch {
                field: "device_set_missing_expected"
            } | KtError::SelfMonitoringMismatch {
                field: "device_set_unexpected_entry"
            }
        ));
    }

    #[test]
    fn device_reorder_does_not_affect_monitoring() {
        // Порядок devices в Vec не значим для self-monitoring.
        let ks = fresh_keystore_with_devices(&[0, 1, 2]);
        let mut entry = entry_from(ks.as_ref(), &[0, 1, 2], 1);
        entry.devices.reverse();
        let identity_ed = ks.identity_public();
        let identity_x = ks.identity_x25519_public();
        let mut buf = vec![
            (0u32, ks.device_public(0).unwrap()),
            (1u32, ks.device_public(1).unwrap()),
            (2u32, ks.device_public(2).unwrap()),
        ];
        let exp = expectations_from(ks.as_ref(), &mut buf, &identity_ed, &identity_x);
        verify_own_entry(&entry, &exp).unwrap();
    }
}

#[cfg(all(test, feature = "pq"))]
mod tests_pq {
    use super::*;

    use rand_core::OsRng;
    use umbrella_identity::{HybridIdentityKey, IdentitySeed, MnemonicLanguage};
    use umbrella_pq::slh_dsa_128f_keygen;

    use crate::entry_v2::KtEntryV2;

    fn fresh_hybrid() -> HybridIdentityKey {
        let mut rng = OsRng;
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        HybridIdentityKey::derive(&seed, 0).unwrap()
    }

    fn entry_for(
        hybrid: &HybridIdentityKey,
        backup: Option<umbrella_pq::SlhDsa128fPublicKey>,
        sequence: u64,
    ) -> KtEntryV2 {
        let pub_key = hybrid.public().clone();
        let ed25519_bytes = pub_key.ed25519_bytes();
        let account_id = KtEntryV2::derive_account_id(&ed25519_bytes);
        KtEntryV2 {
            account_id,
            identity_hybrid_pubkey: pub_key,
            identity_slh_dsa_backup: backup,
            timestamp_secs_unix: 1_700_000_000,
            sequence_number: sequence,
            parent_hash: [0u8; 32],
        }
    }

    #[test]
    fn v2_matching_entry_passes() {
        let hybrid = fresh_hybrid();
        let entry = entry_for(&hybrid, None, 1);
        let exp = HybridOwnExpectations {
            identity_hybrid: hybrid.public(),
            identity_slh_dsa_backup: None,
        };
        verify_own_v2_entry(&entry, &exp).unwrap();
    }

    #[test]
    fn v2_matching_entry_with_backup_passes() {
        let hybrid = fresh_hybrid();
        let mut rng = OsRng;
        let (slh_pk, _) = slh_dsa_128f_keygen(&mut rng).unwrap();
        let entry = entry_for(&hybrid, Some(slh_pk.clone()), 1);
        let exp = HybridOwnExpectations {
            identity_hybrid: hybrid.public(),
            identity_slh_dsa_backup: Some(&slh_pk),
        };
        verify_own_v2_entry(&entry, &exp).unwrap();
    }

    #[test]
    fn v2_swapped_hybrid_pubkey_detected() {
        // Attacker подменил hybrid pubkey (account_id остаётся клиентский).
        // Attacker substituted hybrid pubkey (account_id stays client's).
        let hybrid_a = fresh_hybrid();
        let hybrid_b = fresh_hybrid();
        let mut entry = entry_for(&hybrid_a, None, 1);
        entry.identity_hybrid_pubkey = hybrid_b.public().clone();
        let exp = HybridOwnExpectations {
            identity_hybrid: hybrid_a.public(),
            identity_slh_dsa_backup: None,
        };
        // account_id derived from hybrid_a Ed25519, но entry hybrid pubkey = B —
        // самая ранняя проверка падает на account_id (consistency check), либо
        // на hybrid pubkey (если account_id случайно matches). Mы тестируем
        // что mismatch в любом случае ловится с одним из этих field tags.
        let err = verify_own_v2_entry(&entry, &exp).unwrap_err();
        assert!(matches!(
            err,
            KtError::SelfMonitoringMismatch {
                field: "v2_account_id"
            } | KtError::SelfMonitoringMismatch {
                field: "v2_identity_hybrid_pubkey"
            }
        ));
    }

    #[test]
    fn v2_tampered_account_id_detected() {
        let hybrid = fresh_hybrid();
        let mut entry = entry_for(&hybrid, None, 1);
        entry.account_id[0] ^= 0x01;
        let exp = HybridOwnExpectations {
            identity_hybrid: hybrid.public(),
            identity_slh_dsa_backup: None,
        };
        assert_eq!(
            verify_own_v2_entry(&entry, &exp).unwrap_err(),
            KtError::SelfMonitoringMismatch {
                field: "v2_account_id"
            }
        );
    }

    #[test]
    fn v2_unexpected_slh_dsa_backup_detected() {
        // Entry имеет backup, expected — нет. Ghost-injection of backup pubkey.
        let hybrid = fresh_hybrid();
        let mut rng = OsRng;
        let (slh_pk, _) = slh_dsa_128f_keygen(&mut rng).unwrap();
        let entry = entry_for(&hybrid, Some(slh_pk), 1);
        let exp = HybridOwnExpectations {
            identity_hybrid: hybrid.public(),
            identity_slh_dsa_backup: None,
        };
        assert_eq!(
            verify_own_v2_entry(&entry, &exp).unwrap_err(),
            KtError::SelfMonitoringMismatch {
                field: "v2_slh_dsa_backup_unexpected"
            }
        );
    }

    #[test]
    fn v2_missing_slh_dsa_backup_detected() {
        // Expected backup, entry без — entry приходит без backup, но клиент его
        // ожидает. Может означать что server урезал backup pubkey.
        let hybrid = fresh_hybrid();
        let mut rng = OsRng;
        let (slh_pk, _) = slh_dsa_128f_keygen(&mut rng).unwrap();
        let entry = entry_for(&hybrid, None, 1);
        let exp = HybridOwnExpectations {
            identity_hybrid: hybrid.public(),
            identity_slh_dsa_backup: Some(&slh_pk),
        };
        assert_eq!(
            verify_own_v2_entry(&entry, &exp).unwrap_err(),
            KtError::SelfMonitoringMismatch {
                field: "v2_slh_dsa_backup_missing"
            }
        );
    }

    #[test]
    fn v2_slh_dsa_backup_pubkey_mismatch_detected() {
        // Entry имеет backup B, expected backup A — attacker подменил backup.
        let hybrid = fresh_hybrid();
        let mut rng = OsRng;
        let (slh_pk_a, _) = slh_dsa_128f_keygen(&mut rng).unwrap();
        let (slh_pk_b, _) = slh_dsa_128f_keygen(&mut rng).unwrap();
        let entry = entry_for(&hybrid, Some(slh_pk_b), 1);
        let exp = HybridOwnExpectations {
            identity_hybrid: hybrid.public(),
            identity_slh_dsa_backup: Some(&slh_pk_a),
        };
        assert_eq!(
            verify_own_v2_entry(&entry, &exp).unwrap_err(),
            KtError::SelfMonitoringMismatch {
                field: "v2_slh_dsa_backup_pubkey"
            }
        );
    }
}
