#![allow(deprecated)] // Round-6: legacy KT coexistence test exercises IdentitySeed::generate
//! Integration tests блока 8.5: V1 ↔ V2 wire-format coexistence в KT log mirror.
//! Integration tests for block 8.5: V1 ↔ V2 wire-format coexistence in the KT log mirror.
//!
//! Эти tests fixture'ят invariant'ы:
//! - V1 entries (existing 0.0.11 wire-format `KtEntry::canonical_encoding`) не
//!   имеют leading version byte; их Merkle leaf hash зависит только от
//!   account_id + epoch + identities + devices, **не** от version stamp.
//! - V2 entries (новый wire-format `KtEntryV2::canonical_encoding`) имеют
//!   leading byte 0x02; их Merkle leaf hash зависит от полной encoded byte
//!   sequence включая 0x02.
//! - V1 entry для seed S и V2 entry для того же seed S имеют тот же account_id
//!   (SHA-256 от Ed25519 component = SHA-256 от classical IdentityKey pubkey).
//! - V1 canonical_encoding **никогда** не парсится через `KtEntryV2::from_bytes`:
//!   первый байт V1 (`account_id[0]`) случайный, и `from_bytes` отвергает все
//!   значения кроме 0x02.
//! - Random byte sequences с first byte != 0x02 → `UnknownEntryVersion` без
//!   silent fallback (постулат 14).
//!
//! These tests pin down the invariants:
//! - V1 entries (existing 0.0.11 wire format `KtEntry::canonical_encoding`)
//!   have no leading version byte; their Merkle leaf hash depends only on
//!   account_id + epoch + identities + devices, **not** on a version stamp.
//! - V2 entries (new wire format `KtEntryV2::canonical_encoding`) carry a
//!   leading byte 0x02; their Merkle leaf hash depends on the full encoded
//!   byte sequence including 0x02.
//! - A V1 entry for seed S and a V2 entry for the same seed S share the same
//!   account_id (SHA-256 of the Ed25519 component = SHA-256 of the classical
//!   IdentityKey pubkey).
//! - The V1 canonical_encoding is **never** parsed through
//!   `KtEntryV2::from_bytes`: the first V1 byte (`account_id[0]`) is random,
//!   and `from_bytes` rejects every value except 0x02.
//! - Random byte sequences whose first byte != 0x02 → `UnknownEntryVersion`
//!   without silent fallback (postulate 14).

#![cfg(feature = "pq")]

use std::sync::Arc;

use rand_core::OsRng;

use umbrella_identity::{
    Clock, HybridIdentityKey, IdentityKey, IdentitySeed, InMemoryKeyStore, KeyStore,
    MnemonicLanguage, SystemClock,
};
use umbrella_kt::{
    DeviceAttestationRef, KtEntry, KtEntryV2, KtEntryVersion, KtError, KT_ENTRY_V2_MAX_ENCODED_LEN,
    KT_ENTRY_V2_MIN_ENCODED_LEN,
};
use umbrella_pq::slh_dsa_128f_keygen;

/// Создаёт fresh seed + classical IdentityKey + hybrid identity для same
/// account index. Helper для V1 ↔ V2 cross-checks.
/// Creates a fresh seed + classical IdentityKey + hybrid identity for the
/// same account index. Helper for V1 ↔ V2 cross-checks.
fn fresh_pair(account: u32) -> (IdentitySeed, IdentityKey, HybridIdentityKey) {
    let mut rng = OsRng;
    let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    let classical = IdentityKey::derive(&seed, account).unwrap();
    let hybrid = HybridIdentityKey::derive(&seed, account).unwrap();
    (seed, classical, hybrid)
}

fn fresh_keystore_with_devices(seed: IdentitySeed, indices: &[u32]) -> Arc<InMemoryKeyStore> {
    let ks = InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>).unwrap();
    for &i in indices {
        ks.add_device(i, None).unwrap();
    }
    Arc::new(ks)
}

fn build_v1_entry(ks: &dyn KeyStore, devices: &[u32], epoch: u64) -> KtEntry {
    let identity_ed = ks.identity_public();
    let identity_x = ks.identity_x25519_public();
    let account_id = KtEntry::derive_account_id(&identity_ed);
    let dev_refs = devices
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
        devices: dev_refs,
    }
}

fn build_v2_entry(hybrid: &HybridIdentityKey, sequence: u64) -> KtEntryV2 {
    let pubkey = hybrid.public().clone();
    let ed25519_bytes = pubkey.ed25519_bytes();
    let account_id = KtEntryV2::derive_account_id(&ed25519_bytes);
    KtEntryV2 {
        account_id,
        identity_hybrid_pubkey: pubkey,
        identity_slh_dsa_backup: None,
        timestamp_secs_unix: 1_700_000_000,
        sequence_number: sequence,
        parent_hash: [0u8; 32],
    }
}

/// V1 entry и V2 entry для same seed+account имеют совпадающий account_id.
/// Этот invariant позволяет mix V1 + V2 entries в одном log mirror под одним
/// account.
/// V1 entry and V2 entry for the same seed+account share account_id. This
/// invariant lets V1 + V2 entries coexist in the same log mirror under one
/// account.
#[test]
fn v1_and_v2_share_account_id_for_same_seed() {
    let (seed, classical, hybrid) = fresh_pair(0);
    let ks = fresh_keystore_with_devices(seed, &[0]);
    let v1 = build_v1_entry(ks.as_ref(), &[0], 1);
    let v2 = build_v2_entry(&hybrid, 1);

    let v1_account = KtEntry::derive_account_id(&classical.public());
    let v2_account = KtEntryV2::derive_account_id(&hybrid.public().ed25519_bytes());

    assert_eq!(v1.account_id, v1_account);
    assert_eq!(v2.account_id, v2_account);
    assert_eq!(v1.account_id, v2.account_id);
}

/// V1 wire-format не имеет leading version byte. Этот test регрессионный:
/// если кто-то добавит leading byte в `KtEntry::canonical_encoding`, все
/// existing Merkle leaves invalidate'ся.
/// V1 wire format has no leading version byte. This regression test pins it
/// down: if someone adds a leading byte to `KtEntry::canonical_encoding`,
/// every existing Merkle leaf is invalidated.
#[test]
fn v1_canonical_encoding_first_byte_is_account_id() {
    let (seed, _, _) = fresh_pair(0);
    let ks = fresh_keystore_with_devices(seed, &[0]);
    let v1 = build_v1_entry(ks.as_ref(), &[0], 7);
    let enc = v1.canonical_encoding().unwrap();
    // Первый байт V1 = account_id[0] (any of 0x00..0xFF из SHA-256 hash).
    // First V1 byte = account_id[0] (any of 0x00..0xFF from the SHA-256 hash).
    assert_eq!(enc[0], v1.account_id[0]);
    // V1 encoding **никогда** не начинается с явного version byte 0x01 / 0x02
    // как часть wire-format invariant — байты могут случайно совпасть, но это
    // совпадение, не намерение.
    // V1 encoding **never** starts with an explicit version byte 0x01 / 0x02
    // as part of the wire-format invariant — bytes may coincide, but that is
    // coincidence, not intent.
}

/// V2 canonical_encoding всегда начинается с 0x02.
/// V2 canonical_encoding always starts with 0x02.
#[test]
fn v2_canonical_encoding_first_byte_is_version_stamp() {
    let (_, _, hybrid) = fresh_pair(0);
    let v2 = build_v2_entry(&hybrid, 1);
    let enc = v2.canonical_encoding().unwrap();
    assert_eq!(enc[0], 0x02);
    assert_eq!(enc[0], KtEntryVersion::V2HybridPq.as_u8());
}

/// V1 canonical_encoding отвергается `KtEntryV2::from_bytes` (если только
/// случайно `account_id[0] == 0x02`, в этом случае length check отвергает).
/// Этот test guarantees: V1 entries никогда не silent'но parse'ятся как V2.
/// V1 canonical_encoding is rejected by `KtEntryV2::from_bytes` (and even if
/// `account_id[0] == 0x02` by chance, the length check rejects it). This test
/// guarantees: V1 entries are never silently parsed as V2.
#[test]
fn v1_encoding_never_parses_as_v2() {
    // Repeat для нескольких random seeds — статистически покрываем разные
    // первые-байты account_id.
    // Repeat for several random seeds — statistical coverage of different
    // first-byte account_id values.
    for _ in 0..16 {
        let (seed, _, _) = fresh_pair(0);
        let ks = fresh_keystore_with_devices(seed, &[0]);
        let v1 = build_v1_entry(ks.as_ref(), &[0], 1);
        let enc = v1.canonical_encoding().unwrap();
        let parsed = KtEntryV2::from_bytes(&enc);
        assert!(
            parsed.is_err(),
            "V1 encoding должно отвергаться V2 parser'ом, но parse прошёл"
        );
        // Возможные причины reject:
        // - UnknownEntryVersion (если account_id[0] != 0x02)
        // - InvalidV2Entry (length / structure mismatch если account_id[0] == 0x02)
        // Possible rejection reasons:
        // - UnknownEntryVersion (if account_id[0] != 0x02)
        // - InvalidV2Entry (length / structure mismatch if account_id[0] == 0x02)
        match parsed.unwrap_err() {
            KtError::UnknownEntryVersion { version } => {
                assert_eq!(version, enc[0]);
                assert_ne!(version, 0x02);
            }
            KtError::InvalidV2Entry(_) => {
                // First byte был случайно 0x02 — длина точно не совпадает с
                // V2 (V1 entry'ы намного короче 2066 bytes).
                // First byte happened to be 0x02 — length cannot match V2
                // (V1 entries are much shorter than 2066 bytes).
                assert_eq!(enc[0], 0x02);
                assert!(enc.len() < KT_ENTRY_V2_MIN_ENCODED_LEN);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

/// V2 entry roundtrip через canonical_encoding + from_bytes.
/// V2 entry roundtrip via canonical_encoding + from_bytes.
#[test]
fn v2_roundtrip_no_backup() {
    let (_, _, hybrid) = fresh_pair(0);
    let original = build_v2_entry(&hybrid, 42);
    let enc = original.canonical_encoding().unwrap();
    let decoded = KtEntryV2::from_bytes(&enc).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(enc.len(), KT_ENTRY_V2_MIN_ENCODED_LEN);
}

/// V2 entry roundtrip с SLH-DSA backup pubkey.
/// V2 entry roundtrip with SLH-DSA backup pubkey.
#[test]
fn v2_roundtrip_with_backup() {
    let (_, _, hybrid) = fresh_pair(0);
    let mut rng = OsRng;
    let (slh_pk, _) = slh_dsa_128f_keygen(&mut rng).unwrap();
    let mut entry = build_v2_entry(&hybrid, 100);
    entry.identity_slh_dsa_backup = Some(slh_pk);
    let enc = entry.canonical_encoding().unwrap();
    assert_eq!(enc.len(), KT_ENTRY_V2_MAX_ENCODED_LEN);
    let decoded = KtEntryV2::from_bytes(&enc).unwrap();
    assert_eq!(decoded, entry);
}

/// V1 Merkle leaf hash regression invariant: encoding не меняется относительно
/// блока 3.3 baseline. Если кто-то добавит leading byte в V1 — этот test упадёт.
/// V1 Merkle leaf hash regression invariant: encoding does not change vs the
/// block 3.3 baseline. If someone adds a leading byte to V1, this test fails.
#[test]
fn v1_canonical_encoding_length_unchanged() {
    let (seed, _, _) = fresh_pair(0);
    let ks = fresh_keystore_with_devices(seed, &[7]);
    let v1 = build_v1_entry(ks.as_ref(), &[7], 42);
    let enc = v1.canonical_encoding().unwrap();
    // V1 layout: 32 account_id + 8 epoch + 32 ed25519 + 32 x25519 + 2 device_count
    //          + 1 device * (4 device_index + 32 device_pub + 8 valid_until)
    //          = 32 + 8 + 32 + 32 + 2 + 44 = 150 bytes.
    // V1 layout: 32 account_id + 8 epoch + 32 ed25519 + 32 x25519 + 2 device_count
    //          + 1 device * (4 device_index + 32 device_pub + 8 valid_until)
    //          = 32 + 8 + 32 + 32 + 2 + 44 = 150 bytes.
    assert_eq!(enc.len(), 150);
}

/// V2 Merkle leaf hash зависит от leading version byte: same other-fields с
/// разными version stamps → разные leaf hashes. Это защита от cross-version
/// collision (атакующий не сможет manufacture V1 entry с тем же leaf hash как
/// V2 entry для same account).
/// V2 Merkle leaf hash depends on the leading version byte: same other-fields
/// with different version stamps → different leaf hashes. This protects against
/// cross-version collision (an attacker cannot manufacture a V1 entry with the
/// same leaf hash as a V2 entry for the same account).
#[test]
fn v2_leaf_hash_depends_on_version_byte() {
    let (_, _, hybrid) = fresh_pair(0);
    let v2 = build_v2_entry(&hybrid, 1);
    let enc = v2.canonical_encoding().unwrap();

    // Hash полного encoding (включая 0x02).
    // Hash full encoding (including 0x02).
    let h_full = umbrella_kt::leaf_hash(&enc);

    // Hash encoding **без** version byte.
    // Hash encoding **without** version byte.
    let h_without_version = umbrella_kt::leaf_hash(&enc[1..]);

    assert_ne!(h_full, h_without_version);
}

/// Random first bytes != 0x02 → UnknownEntryVersion. Все 254 invalid values
/// проверены.
/// Random first bytes != 0x02 → UnknownEntryVersion. All 254 invalid values
/// are checked.
#[test]
fn unknown_first_byte_rejected() {
    for v in 0u16..=255u16 {
        let v = v as u8;
        if v == 0x02 {
            continue;
        }
        let bytes = vec![v; KT_ENTRY_V2_MIN_ENCODED_LEN];
        let result = KtEntryV2::from_bytes(&bytes);
        match result {
            Err(KtError::UnknownEntryVersion { version }) => assert_eq!(version, v),
            other => panic!("byte 0x{v:02x} → expected UnknownEntryVersion, got {other:?}"),
        }
    }
}

/// Mixed log mirror: Vec<wire-bytes> содержит alternating V1 + V2 entries для
/// одного account_id. Простой dispatcher проверяет первый byte и dispatch'ит.
/// Этот pattern — что log mirror реализации используют для mixed processing.
/// Mixed log mirror: a `Vec<wire-bytes>` contains alternating V1 + V2 entries
/// under the same account_id. A simple dispatcher peeks at the first byte and
/// routes accordingly. This pattern is what log mirror implementations use for
/// mixed processing.
#[test]
fn mixed_v1_v2_log_processing_pattern() {
    let (seed, _, hybrid) = fresh_pair(0);
    let ks = fresh_keystore_with_devices(seed, &[0]);
    let v1 = build_v1_entry(ks.as_ref(), &[0], 1);
    let v2 = build_v2_entry(&hybrid, 2);

    let v1_bytes = v1.canonical_encoding().unwrap();
    let v2_bytes = v2.canonical_encoding().unwrap();

    // Dispatcher pattern: первый byte определяет path. KtEntryV2 box-ируется
    // в variant для компактного enum size (KtEntryV2 ~2 KB; clippy
    // `large_enum_variant`). Production caller'ы могут использовать тот же
    // паттерн при mixed log processing.
    // Dispatcher pattern: first byte determines the path. KtEntryV2 is boxed
    // in the variant to keep the enum size small (KtEntryV2 ~2 KB; clippy
    // `large_enum_variant`). Production callers can use the same pattern when
    // processing a mixed log.
    enum Parsed {
        V1Bytes(Vec<u8>), // V1 не парсится через wire bytes; mirror reconstructs из authorization records
        V2(Box<KtEntryV2>),
    }

    fn dispatch(bytes: &[u8]) -> Result<Parsed, KtError> {
        if bytes.is_empty() {
            return Err(KtError::EmptyEntry);
        }
        if bytes[0] == 0x02 {
            return KtEntryV2::from_bytes(bytes).map(|e| Parsed::V2(Box::new(e)));
        }
        // V1 path: returns raw bytes для downstream обработки.
        // V1 path: returns raw bytes for downstream processing.
        Ok(Parsed::V1Bytes(bytes.to_vec()))
    }

    let parsed_v1 = dispatch(&v1_bytes).unwrap();
    let parsed_v2 = dispatch(&v2_bytes).unwrap();

    match parsed_v1 {
        Parsed::V1Bytes(b) => assert_eq!(b, v1_bytes),
        Parsed::V2(_) => panic!("V1 wrongly parsed as V2"),
    }
    match parsed_v2 {
        Parsed::V2(decoded) => assert_eq!(*decoded, v2),
        Parsed::V1Bytes(_) => panic!("V2 wrongly classified as V1"),
    }
}

/// Empty bytes → EmptyEntry (не UnknownEntryVersion из-за out-of-bounds guard).
/// Empty bytes → EmptyEntry (not UnknownEntryVersion thanks to OOB guard).
#[test]
fn empty_bytes_rejected_with_empty_entry() {
    let result = KtEntryV2::from_bytes(&[]);
    assert_eq!(result.unwrap_err(), KtError::EmptyEntry);
}

/// Encoding determinism: same V2 entry даёт byte-byte одинаковый encoding (без
/// timestamps / RNG скачков).
/// Encoding determinism: same V2 entry yields byte-for-byte identical encoding
/// (no timestamps / RNG drift).
#[test]
fn v2_canonical_encoding_deterministic() {
    let (_, _, hybrid) = fresh_pair(0);
    let entry = build_v2_entry(&hybrid, 1);
    let a = entry.canonical_encoding().unwrap();
    let b = entry.canonical_encoding().unwrap();
    assert_eq!(a, b);
}

/// V1 encoding и V2 encoding для same seed дают **разные** byte sequences
/// (различные структуры, различные leading bytes).
/// V1 encoding and V2 encoding for the same seed yield **different** byte
/// sequences (different structures, different leading bytes).
#[test]
fn v1_and_v2_encodings_differ_byte_for_byte() {
    let (seed, _, hybrid) = fresh_pair(0);
    let ks = fresh_keystore_with_devices(seed, &[0]);
    let v1 = build_v1_entry(ks.as_ref(), &[0], 1);
    let v2 = build_v2_entry(&hybrid, 1);
    let v1_enc = v1.canonical_encoding().unwrap();
    let v2_enc = v2.canonical_encoding().unwrap();
    assert_ne!(v1_enc, v2_enc);
    // Длины тоже различные: V1 ~150 bytes vs V2 ~2066 bytes.
    // Lengths differ too: V1 ~150 bytes vs V2 ~2066 bytes.
    assert_ne!(v1_enc.len(), v2_enc.len());
}
