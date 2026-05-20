//! KtEntry — канонический формат записи в Key Transparency логе.
//! KtEntry — canonical record format in the Key Transparency log.
//!
//! Одна запись содержит публичные ключи пользователя: Ed25519 identity, X25519 identity (для
//! Sealed Sender), список device-keys с attestation-ссылками, epoch и account_id. Хеш
//! записи (SHA-256 от канонического encoding) используется как leaf в Merkle tree.
//!
//! ## Канонический формат (детерминистический)
//!
//! ```text
//! account_id           : [u8; 32]        // hash identity_ed25519_pub
//! epoch                : u64 BE          // сквозной номер эпохи лога
//! identity_ed25519_pub : [u8; 32]
//! identity_x25519_pub  : [u8; 32]
//! device_count         : u16 BE
//! (per device:)
//!   device_index        : u32 BE
//!   device_pub          : [u8; 32]
//!   attestation_valid_until : u64 BE    // unix seconds
//! ```
//!
//! Любая подмена поля меняет хеш, Merkle root не сходится, self-monitoring выявляет расхождение.
//!
//! A single record holds the user's public keys (Ed25519 identity, X25519 identity for Sealed
//! Sender, device-keys with attestation refs), epoch, and account_id. The entry hash (SHA-256
//! of canonical encoding) is the Merkle leaf. Any tampered field changes the hash, breaks the
//! Merkle root, and self-monitoring flags the mismatch.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use umbrella_identity::{DeviceKeyPublic, IdentityKeyPublic, IdentityX25519KeyPublic};

use crate::error::{KtError, Result};
use crate::merkle::{leaf_hash, NODE_HASH_LEN};

/// Максимальный размер canonical encoding (resource exhaustion guard).
/// Maximum canonical encoding size (resource exhaustion guard).
pub const MAX_ENTRY_ENCODED_LEN: usize = 64 * 1024;

/// Ссылка на device-key внутри снапшот-записи `KtEntry`: индекс + публичный
/// ключ + срок действия attestation. Это **часть** identity/devices snapshot
/// (Этап 3.3). Не путать с SPEC-09 §3 `DeviceEntryRef` — последний живёт в
/// `authorization_entries.rs` и описывает client-side mirror device-entry
/// состояния (ADR-008) с флагом Pending/Active/Revoked/BootstrapActive.
///
/// Device-key reference inside a `KtEntry` snapshot: index + public key +
/// attestation expiry. This is **part** of the identity/devices snapshot
/// (Stage 3.3). Not to be confused with the SPEC-09 §3 `DeviceEntryRef` —
/// the latter lives in `authorization_entries.rs` and describes the
/// client-side mirror of a device-entry state (ADR-008) with a
/// Pending/Active/Revoked/BootstrapActive flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceAttestationRef {
    /// Индекс устройства в BIP-32 дереве. Device index in the BIP-32 tree.
    pub device_index: u32,
    /// Публичный device-key. Device public key.
    pub device_pub: DeviceKeyPublic,
    /// Unix-время истечения attestation (0xFFFF_FFFF_FFFF_FFFF = без срока).
    /// Attestation expiry unix time (0xFFFF_FFFF_FFFF_FFFF = perpetual).
    pub attestation_valid_until: u64,
}

/// KT запись: полный снапшот публичных ключей пользователя на эпоху.
/// KT entry: full snapshot of a user's public keys at a given epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KtEntry {
    /// 32-байтовый account_id (hash identity_ed25519_pub, стабилен на всё время аккаунта).
    /// 32-byte account_id (hash of identity_ed25519_pub, stable across account lifetime).
    pub account_id: [u8; 32],
    /// Номер эпохи (увеличивается монотонно при любой публикации).
    /// Epoch number (increases monotonically on any publication).
    pub epoch: u64,
    /// Публичный Ed25519 identity-ключ.
    /// Public Ed25519 identity key.
    pub identity_ed25519_pub: IdentityKeyPublic,
    /// Публичный X25519 identity-ключ для Sealed Sender.
    /// Public X25519 identity key for Sealed Sender.
    pub identity_x25519_pub: IdentityX25519KeyPublic,
    /// Устройства пользователя (порядок значим, сортируем по device_index).
    /// User's devices (order matters — sorted by device_index).
    pub devices: Vec<DeviceAttestationRef>,
}

impl KtEntry {
    /// Вычисляет account_id как SHA-256 от identity_ed25519_pub.
    /// Computes account_id as SHA-256 of identity_ed25519_pub.
    pub fn derive_account_id(identity: &IdentityKeyPublic) -> [u8; 32] {
        let digest = Sha256::digest(identity.to_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Возвращает canonical encoding (детерминистический, independent от порядка сбора).
    /// Returns the canonical encoding (deterministic, order-independent).
    pub fn canonical_encoding(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(32 + 8 + 32 + 32 + 2 + self.devices.len() * 44);
        out.extend_from_slice(&self.account_id);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.identity_ed25519_pub.to_bytes());
        out.extend_from_slice(&self.identity_x25519_pub.to_bytes());

        // Устройства сортируем по device_index перед сериализацией — защита от reorder-attack.
        // Sort devices by device_index before serialisation — defence against reorder attacks.
        let mut sorted = self.devices.clone();
        sorted.sort_by_key(|d| d.device_index);

        if sorted.len() > u16::MAX as usize {
            return Err(KtError::EntryTooLarge {
                got: sorted.len(),
                max: u16::MAX as usize,
            });
        }
        out.extend_from_slice(&(sorted.len() as u16).to_be_bytes());

        for d in &sorted {
            out.extend_from_slice(&d.device_index.to_be_bytes());
            out.extend_from_slice(&d.device_pub.to_bytes());
            out.extend_from_slice(&d.attestation_valid_until.to_be_bytes());
        }

        if out.len() > MAX_ENTRY_ENCODED_LEN {
            // Обнуляем buffer перед отказом (содержит pub bytes — не секрет, но из
            // предосторожности).
            // Zero the buffer before rejection (contains pub bytes — not secret, but prudent).
            out.zeroize();
            return Err(KtError::EntryTooLarge {
                got: out.len(),
                max: MAX_ENTRY_ENCODED_LEN,
            });
        }

        Ok(out)
    }

    /// Возвращает Merkle leaf-hash записи (SHA-256(0x00 || canonical_encoding)).
    /// Returns the entry's Merkle leaf hash (SHA-256(0x00 || canonical_encoding)).
    pub fn merkle_leaf_hash(&self) -> Result<[u8; NODE_HASH_LEN]> {
        let encoded = self.canonical_encoding()?;
        Ok(leaf_hash(&encoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use rand_core::OsRng;
    use umbrella_identity::{
        Clock, IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock,
    };

    fn fresh_keystore_with_devices(indices: &[u32]) -> Arc<InMemoryKeyStore> {
        let mut rng = OsRng;
        #[allow(deprecated)]
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let ks = InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>).unwrap();
        for &i in indices {
            ks.add_device(i, None).unwrap();
        }
        Arc::new(ks)
    }

    fn sample_entry(ks: &dyn KeyStore, device_indices: &[u32], epoch: u64) -> KtEntry {
        let identity_ed = ks.identity_public();
        let identity_x = ks.identity_x25519_public();
        let account_id = KtEntry::derive_account_id(&identity_ed);
        let devices = device_indices
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

    #[test]
    fn account_id_is_sha256_of_identity_pubkey() {
        let ks = fresh_keystore_with_devices(&[]);
        let id = ks.identity_public();
        let expected_digest = Sha256::digest(id.to_bytes());
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&expected_digest);
        assert_eq!(KtEntry::derive_account_id(&id), expected);
    }

    #[test]
    fn canonical_encoding_deterministic() {
        let ks = fresh_keystore_with_devices(&[0, 1, 2]);
        let e1 = sample_entry(ks.as_ref(), &[0, 1, 2], 1);
        let e2 = sample_entry(ks.as_ref(), &[0, 1, 2], 1);
        assert_eq!(
            e1.canonical_encoding().unwrap(),
            e2.canonical_encoding().unwrap()
        );
    }

    #[test]
    fn canonical_encoding_sorts_devices_by_index() {
        let ks = fresh_keystore_with_devices(&[0, 1, 2]);
        let mut in_order = sample_entry(ks.as_ref(), &[0, 1, 2], 5);
        let mut reversed = in_order.clone();
        reversed.devices.reverse();
        assert_ne!(in_order.devices, reversed.devices);
        assert_eq!(
            in_order.canonical_encoding().unwrap(),
            reversed.canonical_encoding().unwrap(),
            "encoding должен быть одинаковым независимо от порядка devices в vec"
        );
        // sanity
        in_order.devices.sort_by_key(|d| d.device_index);
        reversed.devices.sort_by_key(|d| d.device_index);
        assert_eq!(in_order, reversed);
    }

    #[test]
    fn canonical_encoding_has_expected_layout() {
        let ks = fresh_keystore_with_devices(&[7]);
        let e = sample_entry(ks.as_ref(), &[7], 42);
        let enc = e.canonical_encoding().unwrap();
        // 32 account_id + 8 epoch + 32 ed25519 + 32 x25519 + 2 count + 1 device * (4 + 32 + 8)
        // = 32 + 8 + 32 + 32 + 2 + 44 = 150
        assert_eq!(enc.len(), 150);
        // account_id префикс
        assert_eq!(&enc[..32], &e.account_id);
        // epoch BE
        assert_eq!(&enc[32..40], &42u64.to_be_bytes());
        // device_count = 1
        assert_eq!(&enc[104..106], &1u16.to_be_bytes());
        // device_index = 7
        assert_eq!(&enc[106..110], &7u32.to_be_bytes());
    }

    #[test]
    fn different_epoch_different_encoding() {
        let ks = fresh_keystore_with_devices(&[0]);
        let e1 = sample_entry(ks.as_ref(), &[0], 1);
        let e2 = sample_entry(ks.as_ref(), &[0], 2);
        assert_ne!(
            e1.canonical_encoding().unwrap(),
            e2.canonical_encoding().unwrap()
        );
    }

    #[test]
    fn different_device_set_different_encoding() {
        let ks = fresh_keystore_with_devices(&[0, 1]);
        let e1 = sample_entry(ks.as_ref(), &[0], 1);
        let e2 = sample_entry(ks.as_ref(), &[0, 1], 1);
        assert_ne!(
            e1.canonical_encoding().unwrap(),
            e2.canonical_encoding().unwrap()
        );
    }

    #[test]
    fn merkle_leaf_hash_is_sha256_zero_prefix_of_encoding() {
        let ks = fresh_keystore_with_devices(&[0]);
        let e = sample_entry(ks.as_ref(), &[0], 1);
        let enc = e.canonical_encoding().unwrap();
        let expected = leaf_hash(&enc);
        assert_eq!(e.merkle_leaf_hash().unwrap(), expected);
    }
}
