//! `KtEntryV2` — V2 wire-format identity-announcement entry (Этап 8, блок 8.5).
//! `KtEntryV2` — V2 wire-format identity-announcement entry (Stage 8, block 8.5).
//!
//! ## Назначение
//!
//! Closes ghost-participant атаку на уровне **post-quantum identity**: V2 entry
//! публикует hybrid identity (Ed25519 + ML-DSA-65 pubkey) для одного аккаунта,
//! плюс optional SLH-DSA-128f backup pubkey для catastrophic recovery (ADR-008
//! § rotation + ADR-011 Решение 5). Self-monitoring клиент сравнивает byte-в-байт
//! что V2 entry для собственного account_id содержит ожидаемые hybrid keys —
//! любая подмена детектится.
//!
//! V2 entry **complementary** к V1 device-snapshot entry: design §8.3 «mixed
//! V1+V2 entries в logе». Не replace — V1 device-snapshot продолжает publishить
//! список устройств, V2 announce identity layer (один account имеет обычно одну
//! V2 entry с hybrid identity и периодические V1 device-snapshot entries).
//!
//! ## Wire format (canonical encoding)
//!
//! ```text
//! Offset | Size | Field
//! -------+------+---------------------------------------------------------
//!     0  |   1  | version = 0x02
//!     1  |  32  | account_id  (= SHA-256(identity_ed25519_pubkey))
//!    33  |1984  | identity_hybrid_pubkey  (Ed25519 32 || ML-DSA-65 1952)
//!  2017  |   1  | has_slh_dsa_backup  (0x00 = absent, 0x01 = present)
//!  2018  |  32  | identity_slh_dsa_128f_pubkey  // только если flag == 0x01
//!  2018  |   8  | timestamp_secs_unix  (BE u64)        // если backup absent
//!  2026  |   8  | sequence_number      (BE u64)        // если backup absent
//!  2034  |  32  | parent_hash                          // если backup absent
//!  2050  |   8  | timestamp_secs_unix  (BE u64)        // если backup present
//!  2058  |   8  | sequence_number      (BE u64)        // если backup present
//!  2066  |  32  | parent_hash                          // если backup present
//! ```
//!
//! Total длина:
//! - **2066 bytes** без SLH-DSA backup
//! - **2098 bytes** с SLH-DSA backup
//!
//! ## Backward compat 0.0.11
//!
//! V1 wire-format (`KtEntry::canonical_encoding`) **не меняется** — Merkle leaf
//! hash invariant сохраняется. V2 entries имеют leading byte `0x02`,
//! existing 0.0.11 mirror видит unknown shape и отвергает entry через existing
//! pipeline (length / structural validation). Ни одна existing V1 leaf
//! не invalidate'ится.
//!
//! ## Purpose
//!
//! Closes the ghost-participant attack at the **post-quantum identity** layer:
//! a V2 entry publishes the hybrid identity (Ed25519 + ML-DSA-65 pubkey) for a
//! single account, plus an optional SLH-DSA-128f backup pubkey for catastrophic
//! recovery (ADR-008 § rotation + ADR-011 Decision 5). The self-monitoring
//! client checks byte-for-byte that the V2 entry for its own account_id
//! contains the expected hybrid keys — any substitution is detected.
//!
//! The V2 entry is **complementary** to the V1 device-snapshot entry: design
//! §8.3 «mixed V1+V2 entries in the log». Not a replacement — the V1
//! device-snapshot keeps publishing the device list, the V2 entry announces
//! the identity layer (one account typically has one V2 entry with the hybrid
//! identity and periodic V1 device-snapshot entries).
//!
//! ## 0.0.11 backward compat
//!
//! The V1 wire format (`KtEntry::canonical_encoding`) does **not** change —
//! the Merkle leaf hash invariant is preserved. V2 entries carry a leading
//! byte `0x02`; the existing 0.0.11 mirror sees an unknown shape and rejects
//! the entry via the existing pipeline (length / structural validation). No
//! existing V1 leaf is invalidated.

use sha2::{Digest, Sha256};

use umbrella_identity::{HybridIdentityKeyPublic, HYBRID_IDENTITY_PUBLIC_KEY_LEN};
use umbrella_pq::{SlhDsa128fPublicKey, SLH_DSA_128F_PUBLIC_KEY_LEN};

use crate::error::{KtError, Result};
use crate::merkle::{leaf_hash, NODE_HASH_LEN};
use crate::version::KtEntryVersion;

/// Длина account_id в KT entries (SHA-256 от identity_ed25519_pubkey).
/// Account_id length in KT entries (SHA-256 of identity_ed25519_pubkey).
const ACCOUNT_ID_LEN: usize = 32;

/// Длина parent_hash в V2 wire format.
/// parent_hash length in the V2 wire format.
const PARENT_HASH_LEN: usize = 32;

/// Длина BE u64 timestamp / sequence_number полей.
/// Length of the BE u64 timestamp / sequence_number fields.
const U64_BE_LEN: usize = 8;

/// Минимальная длина wire-format V2 entry (без SLH-DSA backup pubkey):
/// 1 (version) + 32 (account_id) + 1984 (hybrid pubkey) + 1 (slh_dsa flag)
/// + 8 (timestamp) + 8 (sequence_number) + 32 (parent_hash) = 2066.
///
/// Minimum wire-format length of a V2 entry (no SLH-DSA backup pubkey).
pub const KT_ENTRY_V2_MIN_ENCODED_LEN: usize = 1
    + ACCOUNT_ID_LEN
    + HYBRID_IDENTITY_PUBLIC_KEY_LEN
    + 1
    + U64_BE_LEN
    + U64_BE_LEN
    + PARENT_HASH_LEN;

/// Максимальная длина wire-format V2 entry (с SLH-DSA backup pubkey 32 bytes):
/// 2066 + 32 = 2098.
///
/// Maximum wire-format length of a V2 entry (with the 32-byte SLH-DSA backup
/// pubkey).
pub const KT_ENTRY_V2_MAX_ENCODED_LEN: usize =
    KT_ENTRY_V2_MIN_ENCODED_LEN + SLH_DSA_128F_PUBLIC_KEY_LEN;

/// V2 KT entry: identity-announcement запись с hybrid identity + optional
/// SLH-DSA-128f backup pubkey (Этап 8, ADR-011 Решение 6).
///
/// Поля:
/// - `account_id` — стабильный 32-байтовый идентификатор аккаунта (SHA-256
///   от Ed25519 component hybrid identity); тот же что и в V1 entries для
///   того же identity_seed (постулат 4 — privacy-friendly hash, не raw email).
/// - `identity_hybrid_pubkey` — Ed25519 + ML-DSA-65 pubkey (1984 bytes wire).
///   Ed25519 component byte-exact совпадает с classical `IdentityKey::derive`
///   для того же seed+account (см. блок 8.3 hybrid_identity.rs invariant).
/// - `identity_slh_dsa_backup` — optional SLH-DSA-128f public key (32 bytes)
///   для catastrophic recovery rotation (ADR-008 §rotation путь восстановления
///   через 12-словный код + SLH-DSA backup signing). `None` для аккаунтов без
///   backup, `Some(_)` для аккаунтов с явно отдельным SLH-DSA seed.
/// - `timestamp_secs_unix` — Unix-время публикации записи. Используется
///   self-monitoring для freshness checks (entry старее N дней — alert).
/// - `sequence_number` — per-account монотонный счётчик (semantically
///   equivalent to V1 `epoch`; design §8.3 «explicit sequence ordering через
///   sequence_number BE u64»).
/// - `parent_hash` — hash предыдущей entry для этого account_id в Merkle log;
///   chains V1 + V2 entries chronologically per account.
///
/// V2 KT entry: identity-announcement record carrying a hybrid identity plus
/// an optional SLH-DSA-128f backup pubkey (Stage 8, ADR-011 Decision 6).
///
/// Fields:
/// - `account_id` — stable 32-byte account identifier (SHA-256 of the Ed25519
///   component of the hybrid identity); same as in V1 entries for the same
///   identity_seed (postulate 4 — privacy-friendly hash, not raw email).
/// - `identity_hybrid_pubkey` — Ed25519 + ML-DSA-65 pubkey (1984 bytes wire).
///   The Ed25519 component byte-exactly matches classical `IdentityKey::derive`
///   for the same seed+account (see block 8.3 hybrid_identity.rs invariant).
/// - `identity_slh_dsa_backup` — optional SLH-DSA-128f public key (32 bytes)
///   for catastrophic recovery rotation (ADR-008 §rotation, recovery path via
///   the 12-word code + SLH-DSA backup signing). `None` for accounts without
///   backup, `Some(_)` for accounts with a dedicated SLH-DSA seed.
/// - `timestamp_secs_unix` — Unix time when the record was published. Used by
///   self-monitoring for freshness checks (entry older than N days → alert).
/// - `sequence_number` — per-account monotonic counter (semantically equivalent
///   to the V1 `epoch`; design §8.3 «explicit sequence ordering via
///   sequence_number BE u64»).
/// - `parent_hash` — hash of the previous entry for this account_id in the
///   Merkle log; chains V1 + V2 entries chronologically per account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KtEntryV2 {
    /// 32-байтовый account_id (SHA-256 от Ed25519 component hybrid identity).
    /// 32-byte account_id (SHA-256 of the Ed25519 component of the hybrid identity).
    pub account_id: [u8; ACCOUNT_ID_LEN],

    /// Hybrid identity public key (Ed25519 32 bytes || ML-DSA-65 1952 bytes).
    /// Hybrid identity public key (Ed25519 32 bytes || ML-DSA-65 1952 bytes).
    pub identity_hybrid_pubkey: HybridIdentityKeyPublic,

    /// Optional SLH-DSA-128f backup-recovery public key (32 bytes).
    /// Optional SLH-DSA-128f backup-recovery public key (32 bytes).
    pub identity_slh_dsa_backup: Option<SlhDsa128fPublicKey>,

    /// Unix-время публикации в секундах (BE u64 в wire-format).
    /// Unix publication time in seconds (BE u64 in wire format).
    pub timestamp_secs_unix: u64,

    /// Per-account монотонный sequence number (BE u64 в wire-format).
    /// Per-account monotonic sequence number (BE u64 in wire format).
    pub sequence_number: u64,

    /// Hash предыдущей entry для этого account_id в Merkle log.
    /// Hash of the previous entry for this account_id in the Merkle log.
    pub parent_hash: [u8; PARENT_HASH_LEN],
}

impl KtEntryV2 {
    /// Вычисляет account_id как SHA-256 от Ed25519 component hybrid identity.
    /// Используется для symmetry с V1 `KtEntry::derive_account_id` — один и
    /// тот же seed+account даёт одинаковый account_id в V1 и V2.
    ///
    /// Computes account_id as SHA-256 of the Ed25519 component of the hybrid
    /// identity. Used for symmetry with V1 `KtEntry::derive_account_id` — the
    /// same seed+account yields the same account_id in V1 and V2.
    pub fn derive_account_id(identity_ed25519_pubkey: &[u8; 32]) -> [u8; ACCOUNT_ID_LEN] {
        let digest = Sha256::digest(identity_ed25519_pubkey);
        let mut out = [0u8; ACCOUNT_ID_LEN];
        out.copy_from_slice(&digest);
        out
    }

    /// Возвращает canonical wire-format encoding с leading version byte 0x02.
    /// Detерминистический (одинаковые входы → одинаковые байты, byte-в-байт).
    ///
    /// Returns the canonical wire-format encoding with leading version byte
    /// 0x02. Deterministic (same input → same bytes, byte-for-byte).
    pub fn canonical_encoding(&self) -> Result<Vec<u8>> {
        let with_backup = self.identity_slh_dsa_backup.is_some();
        let total_len = if with_backup {
            KT_ENTRY_V2_MAX_ENCODED_LEN
        } else {
            KT_ENTRY_V2_MIN_ENCODED_LEN
        };
        let mut out = Vec::with_capacity(total_len);

        // version stamp = 0x02 (KtEntryVersion::V2HybridPq)
        out.push(KtEntryVersion::V2HybridPq.as_u8());

        // account_id [u8; 32]
        out.extend_from_slice(&self.account_id);

        // hybrid pubkey [u8; 1984]
        let hybrid_bytes = self.identity_hybrid_pubkey.to_bytes();
        debug_assert_eq!(hybrid_bytes.len(), HYBRID_IDENTITY_PUBLIC_KEY_LEN);
        out.extend_from_slice(&hybrid_bytes);

        // has_slh_dsa_backup flag (0x00 / 0x01)
        out.push(if with_backup { 0x01 } else { 0x00 });

        // optional slh_dsa_128f pubkey [u8; 32]
        if let Some(slh_dsa) = &self.identity_slh_dsa_backup {
            out.extend_from_slice(slh_dsa.as_bytes());
        }

        // timestamp_secs_unix BE u64
        out.extend_from_slice(&self.timestamp_secs_unix.to_be_bytes());

        // sequence_number BE u64
        out.extend_from_slice(&self.sequence_number.to_be_bytes());

        // parent_hash [u8; 32]
        out.extend_from_slice(&self.parent_hash);

        debug_assert_eq!(
            out.len(),
            total_len,
            "canonical encoding length matches expected"
        );
        Ok(out)
    }

    /// Парсит V2 entry из wire bytes. Strict V2-only dispatcher: первый байт
    /// **обязан** быть 0x02 (`KtEntryVersion::V2HybridPq`); любое другое значение
    /// возвращает `KtError::UnknownEntryVersion { version }` без silent fallback
    /// (постулат 14).
    ///
    /// Length validation: после parse'а flag `has_slh_dsa_backup` `bytes.len()`
    /// сверяется с expected total длиной (2066 без backup, 2098 с backup);
    /// trailing bytes отвергается с `KtError::InvalidV2Entry("trailing_bytes")`.
    ///
    /// Errors:
    /// - `KtError::EmptyEntry` — пустой slice.
    /// - `KtError::UnknownEntryVersion { version }` — первый байт не 0x02.
    /// - `KtError::InvalidV2Entry(tag)` — структурные ошибки с stable tag:
    ///     - `"too_short"` — длина меньше минимума.
    ///     - `"too_long"` — длина больше максимума.
    ///     - `"hybrid_pubkey_invalid"` — Ed25519 curve point invalid либо ML-DSA-65 pubkey invalid.
    ///     - `"slh_dsa_flag_invalid"` — флаг не 0x00 и не 0x01.
    ///     - `"slh_dsa_invalid"` — bytes SLH-DSA pubkey invalid.
    ///     - `"length_mismatch_for_flag"` — общая длина не соответствует flag (with vs without backup).
    ///     - `"trailing_bytes"` — лишние байты после parent_hash.
    ///
    /// Parses a V2 entry from wire bytes. Strict V2-only dispatcher: the first
    /// byte **must** be 0x02 (`KtEntryVersion::V2HybridPq`); any other value
    /// returns `KtError::UnknownEntryVersion { version }` with no silent
    /// fallback (postulate 14).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(KtError::EmptyEntry);
        }

        // Strict V2 dispatcher — only 0x02 accepted.
        let version = KtEntryVersion::try_from(bytes[0])?;
        if version != KtEntryVersion::V2HybridPq {
            // Reserved future versions (V1Classical = 0x01) тоже rejected
            // на этапе блока 8.5 — только V2 wire-format consumed.
            return Err(KtError::UnknownEntryVersion { version: bytes[0] });
        }

        if bytes.len() < KT_ENTRY_V2_MIN_ENCODED_LEN {
            return Err(KtError::InvalidV2Entry("too_short"));
        }
        if bytes.len() > KT_ENTRY_V2_MAX_ENCODED_LEN {
            return Err(KtError::InvalidV2Entry("too_long"));
        }

        // Cursor-based sequential parse.
        let mut cursor = 1usize; // skip version byte

        // account_id: [u8; 32]
        let mut account_id = [0u8; ACCOUNT_ID_LEN];
        account_id.copy_from_slice(&bytes[cursor..cursor + ACCOUNT_ID_LEN]);
        cursor += ACCOUNT_ID_LEN;

        // hybrid pubkey: [u8; 1984]
        let hybrid_pubkey_slice = &bytes[cursor..cursor + HYBRID_IDENTITY_PUBLIC_KEY_LEN];
        cursor += HYBRID_IDENTITY_PUBLIC_KEY_LEN;
        // account index в KT context не используется (см. version.rs docstring) —
        // передаём 0 как placeholder; pubkey verification полагается только на
        // cryptographic material, не на account index.
        // The account index is not used in the KT context (see version.rs
        // docstring) — passed 0 as a placeholder; pubkey verification depends
        // only on cryptographic material, not on the account index.
        let identity_hybrid_pubkey = HybridIdentityKeyPublic::from_bytes(hybrid_pubkey_slice, 0)
            .map_err(|_| KtError::InvalidV2Entry("hybrid_pubkey_invalid"))?;

        // has_slh_dsa_backup flag: u8
        let flag_byte = bytes[cursor];
        cursor += 1;
        let identity_slh_dsa_backup = match flag_byte {
            0x00 => None,
            0x01 => {
                // Гарантируем что в bytes есть место для 32-байтового SLH-DSA pubkey.
                // Guarantee that bytes has room for the 32-byte SLH-DSA pubkey.
                if cursor + SLH_DSA_128F_PUBLIC_KEY_LEN > bytes.len() {
                    return Err(KtError::InvalidV2Entry("slh_dsa_truncated"));
                }
                let slh_slice = &bytes[cursor..cursor + SLH_DSA_128F_PUBLIC_KEY_LEN];
                cursor += SLH_DSA_128F_PUBLIC_KEY_LEN;
                Some(
                    SlhDsa128fPublicKey::from_bytes(slh_slice)
                        .map_err(|_| KtError::InvalidV2Entry("slh_dsa_invalid"))?,
                )
            }
            _ => return Err(KtError::InvalidV2Entry("slh_dsa_flag_invalid")),
        };

        // Sanity check: общая длина соответствует flag.
        // Sanity check: total length matches the flag.
        let expected_total = if identity_slh_dsa_backup.is_some() {
            KT_ENTRY_V2_MAX_ENCODED_LEN
        } else {
            KT_ENTRY_V2_MIN_ENCODED_LEN
        };
        if bytes.len() != expected_total {
            return Err(KtError::InvalidV2Entry("length_mismatch_for_flag"));
        }

        // timestamp_secs_unix: BE u64
        let mut ts_buf = [0u8; U64_BE_LEN];
        ts_buf.copy_from_slice(&bytes[cursor..cursor + U64_BE_LEN]);
        cursor += U64_BE_LEN;
        let timestamp_secs_unix = u64::from_be_bytes(ts_buf);

        // sequence_number: BE u64
        let mut seq_buf = [0u8; U64_BE_LEN];
        seq_buf.copy_from_slice(&bytes[cursor..cursor + U64_BE_LEN]);
        cursor += U64_BE_LEN;
        let sequence_number = u64::from_be_bytes(seq_buf);

        // parent_hash: [u8; 32]
        let mut parent_hash = [0u8; PARENT_HASH_LEN];
        parent_hash.copy_from_slice(&bytes[cursor..cursor + PARENT_HASH_LEN]);
        cursor += PARENT_HASH_LEN;

        // Defensive: cursor должен достичь end of bytes.
        // Defensive: cursor must reach end of bytes.
        if cursor != bytes.len() {
            return Err(KtError::InvalidV2Entry("trailing_bytes"));
        }

        Ok(Self {
            account_id,
            identity_hybrid_pubkey,
            identity_slh_dsa_backup,
            timestamp_secs_unix,
            sequence_number,
            parent_hash,
        })
    }

    /// Возвращает Merkle leaf-hash V2 entry: SHA-256(0x00 || canonical_encoding).
    /// Domain separation byte 0x00 (LEAF_PREFIX) per RFC 6962 — общий с V1.
    ///
    /// Returns the V2 entry's Merkle leaf hash: SHA-256(0x00 || canonical_encoding).
    /// Domain separation byte 0x00 (LEAF_PREFIX) per RFC 6962 — same as for V1.
    pub fn merkle_leaf_hash(&self) -> Result<[u8; NODE_HASH_LEN]> {
        let encoded = self.canonical_encoding()?;
        Ok(leaf_hash(&encoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand_core::OsRng;
    use umbrella_identity::{HybridIdentityKey, IdentitySeed, MnemonicLanguage};
    use umbrella_pq::slh_dsa_128f_keygen;

    fn fresh_hybrid_identity(account: u32) -> HybridIdentityKey {
        let mut rng = OsRng;
        #[allow(deprecated)]
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        HybridIdentityKey::derive(&seed, account).unwrap()
    }

    fn sample_entry(with_backup: bool, sequence: u64) -> KtEntryV2 {
        let id = fresh_hybrid_identity(0);
        let identity_hybrid_pubkey = id.public().clone();
        let ed25519_bytes = identity_hybrid_pubkey.ed25519_bytes();
        let account_id = KtEntryV2::derive_account_id(&ed25519_bytes);
        let backup = if with_backup {
            let mut rng = OsRng;
            let (pk, _sk) = slh_dsa_128f_keygen(&mut rng).unwrap();
            Some(pk)
        } else {
            None
        };
        KtEntryV2 {
            account_id,
            identity_hybrid_pubkey,
            identity_slh_dsa_backup: backup,
            timestamp_secs_unix: 1_700_000_000,
            sequence_number: sequence,
            parent_hash: [0xAB; PARENT_HASH_LEN],
        }
    }

    #[test]
    fn encoded_length_no_backup_is_min_constant() {
        let e = sample_entry(false, 1);
        let enc = e.canonical_encoding().unwrap();
        assert_eq!(enc.len(), KT_ENTRY_V2_MIN_ENCODED_LEN);
        assert_eq!(KT_ENTRY_V2_MIN_ENCODED_LEN, 2066);
    }

    #[test]
    fn encoded_length_with_backup_is_max_constant() {
        let e = sample_entry(true, 1);
        let enc = e.canonical_encoding().unwrap();
        assert_eq!(enc.len(), KT_ENTRY_V2_MAX_ENCODED_LEN);
        assert_eq!(KT_ENTRY_V2_MAX_ENCODED_LEN, 2098);
    }

    #[test]
    fn canonical_encoding_starts_with_version_byte() {
        let e = sample_entry(false, 1);
        let enc = e.canonical_encoding().unwrap();
        assert_eq!(enc[0], 0x02);
        assert_eq!(enc[0], KtEntryVersion::V2HybridPq.as_u8());
    }

    #[test]
    fn canonical_encoding_layout_no_backup() {
        let e = sample_entry(false, 42);
        let enc = e.canonical_encoding().unwrap();
        // version
        assert_eq!(enc[0], 0x02);
        // account_id
        assert_eq!(&enc[1..33], &e.account_id);
        // hybrid pubkey 1984 bytes
        assert_eq!(
            &enc[33..2017],
            e.identity_hybrid_pubkey.to_bytes().as_slice()
        );
        // has_slh_dsa_backup flag
        assert_eq!(enc[2017], 0x00);
        // timestamp BE u64
        assert_eq!(&enc[2018..2026], &1_700_000_000u64.to_be_bytes());
        // sequence_number BE u64
        assert_eq!(&enc[2026..2034], &42u64.to_be_bytes());
        // parent_hash
        assert_eq!(&enc[2034..2066], &e.parent_hash);
    }

    #[test]
    fn canonical_encoding_layout_with_backup() {
        let e = sample_entry(true, 7);
        let enc = e.canonical_encoding().unwrap();
        assert_eq!(enc[0], 0x02);
        assert_eq!(&enc[1..33], &e.account_id);
        assert_eq!(
            &enc[33..2017],
            e.identity_hybrid_pubkey.to_bytes().as_slice()
        );
        // flag = 0x01
        assert_eq!(enc[2017], 0x01);
        // SLH-DSA pubkey 32 bytes
        let slh = e.identity_slh_dsa_backup.as_ref().unwrap();
        assert_eq!(&enc[2018..2050], slh.as_bytes().as_slice());
        // timestamp + sequence + parent_hash далее
        assert_eq!(&enc[2050..2058], &1_700_000_000u64.to_be_bytes());
        assert_eq!(&enc[2058..2066], &7u64.to_be_bytes());
        assert_eq!(&enc[2066..2098], &e.parent_hash);
    }

    #[test]
    fn canonical_encoding_deterministic() {
        let e = sample_entry(false, 1);
        let a = e.canonical_encoding().unwrap();
        let b = e.canonical_encoding().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn from_bytes_roundtrip_no_backup() {
        let e = sample_entry(false, 100);
        let enc = e.canonical_encoding().unwrap();
        let decoded = KtEntryV2::from_bytes(&enc).unwrap();
        assert_eq!(decoded, e);
    }

    #[test]
    fn from_bytes_roundtrip_with_backup() {
        let e = sample_entry(true, 200);
        let enc = e.canonical_encoding().unwrap();
        let decoded = KtEntryV2::from_bytes(&enc).unwrap();
        assert_eq!(decoded, e);
    }

    #[test]
    fn from_bytes_empty_rejected() {
        let result = KtEntryV2::from_bytes(&[]);
        assert_eq!(result.unwrap_err(), KtError::EmptyEntry);
    }

    #[test]
    fn from_bytes_v1_version_byte_rejected() {
        // 0x01 — зарезервированный V1Classical, но V2 parser его отвергает.
        let mut bytes = vec![0u8; KT_ENTRY_V2_MIN_ENCODED_LEN];
        bytes[0] = 0x01;
        let result = KtEntryV2::from_bytes(&bytes);
        assert_eq!(
            result.unwrap_err(),
            KtError::UnknownEntryVersion { version: 0x01 }
        );
    }

    #[test]
    fn from_bytes_unknown_version_rejected() {
        let mut bytes = vec![0u8; KT_ENTRY_V2_MIN_ENCODED_LEN];
        bytes[0] = 0xFF;
        let result = KtEntryV2::from_bytes(&bytes);
        assert_eq!(
            result.unwrap_err(),
            KtError::UnknownEntryVersion { version: 0xFF }
        );
    }

    #[test]
    fn from_bytes_too_short_rejected() {
        // Just the version byte — strict минимум 2066.
        let bytes = vec![0x02u8];
        assert_eq!(
            KtEntryV2::from_bytes(&bytes).unwrap_err(),
            KtError::InvalidV2Entry("too_short")
        );
    }

    #[test]
    fn from_bytes_too_long_rejected() {
        let mut bytes = vec![0x02u8; KT_ENTRY_V2_MAX_ENCODED_LEN + 1];
        bytes[0] = 0x02;
        assert_eq!(
            KtEntryV2::from_bytes(&bytes).unwrap_err(),
            KtError::InvalidV2Entry("too_long")
        );
    }

    #[test]
    fn from_bytes_trailing_bytes_rejected_via_length_mismatch() {
        // 2066 + 1 = 2067 bytes; flag = 0x00 (no backup) → expected 2066;
        // length check ловит первым.
        let e = sample_entry(false, 1);
        let mut enc = e.canonical_encoding().unwrap();
        enc.push(0xFF);
        // 2067 находится в [2066..=2098], так что too_short/too_long не сработает,
        // но length_mismatch_for_flag сработает.
        assert_eq!(
            KtEntryV2::from_bytes(&enc).unwrap_err(),
            KtError::InvalidV2Entry("length_mismatch_for_flag")
        );
    }

    #[test]
    fn from_bytes_invalid_slh_dsa_flag_rejected() {
        let e = sample_entry(false, 1);
        let mut enc = e.canonical_encoding().unwrap();
        enc[2017] = 0x02; // invalid flag value
        assert_eq!(
            KtEntryV2::from_bytes(&enc).unwrap_err(),
            KtError::InvalidV2Entry("slh_dsa_flag_invalid")
        );
    }

    // Note: validation hybrid pubkey bytes (Ed25519 curve point + ML-DSA-65 structural)
    // покрыто в `umbrella-identity::hybrid_identity` tests. `ed25519-dalek 2.x` имеет
    // lazy validation — большинство byte patterns accept'ятся как valid encoding (curve
    // point validity check'ится только при verify). Поэтому specific «invalid hybrid
    // pubkey bytes → hybrid_pubkey_invalid» путь надёжно проверяется в umbrella-identity,
    // не дублируется здесь. См. блок 8.3 `hybrid_pubkey_substituted_ed25519_yields_verify_failure`.
    //
    // Note: hybrid pubkey byte validation (Ed25519 curve point + ML-DSA-65 structural)
    // is covered by `umbrella-identity::hybrid_identity` tests. `ed25519-dalek 2.x` does
    // lazy validation — most byte patterns are accepted as valid encoding (curve point
    // validity is only enforced on verify). The specific «invalid hybrid pubkey bytes →
    // hybrid_pubkey_invalid» path is reliably exercised in umbrella-identity, not
    // duplicated here. See block 8.3 `hybrid_pubkey_substituted_ed25519_yields_verify_failure`.

    #[test]
    fn from_bytes_flag_with_backup_truncated_rejected() {
        // flag=0x01 указывает на backup, но в bytes только KT_ENTRY_V2_MIN_ENCODED_LEN
        // bytes (нет места для SLH-DSA + следующих полей).
        let e = sample_entry(false, 1);
        let mut enc = e.canonical_encoding().unwrap();
        enc[2017] = 0x01; // claim backup present
                          // Length теперь mismatch (нужен 2098, есть 2066).
        assert_eq!(
            KtEntryV2::from_bytes(&enc).unwrap_err(),
            KtError::InvalidV2Entry("length_mismatch_for_flag")
        );
    }

    #[test]
    fn merkle_leaf_hash_includes_version_byte() {
        // Если бы leaf hash считался без version byte, две разные V2 entry с
        // одинаковыми остальными полями но разными leading byte значениями дали
        // бы один и тот же hash. Поскольку version всегда 0x02 в V2, это checks
        // что leaf_hash зависит от полного encoded (включая byte 0x02).
        let e = sample_entry(false, 1);
        let enc = e.canonical_encoding().unwrap();
        let h_full = leaf_hash(&enc);
        let h_method = e.merkle_leaf_hash().unwrap();
        assert_eq!(h_full, h_method);
        // Sanity: убрать первый байт → разный hash.
        let h_truncated = leaf_hash(&enc[1..]);
        assert_ne!(h_full, h_truncated);
    }

    #[test]
    fn account_id_is_sha256_of_ed25519() {
        let id = fresh_hybrid_identity(0);
        let ed25519_bytes = id.public().ed25519_bytes();
        let derived = KtEntryV2::derive_account_id(&ed25519_bytes);
        let expected = Sha256::digest(ed25519_bytes);
        assert_eq!(&derived[..], expected.as_slice());
    }

    /// V2 entry для того же seed+account имеет тот же account_id что и V1 entry —
    /// invariant ADR-008/ADR-011: один account_id для всех записей одного аккаунта,
    /// независимо от entry type (device snapshot V1 vs identity announcement V2).
    /// V2 entry for the same seed+account has the same account_id as a V1 entry —
    /// invariant from ADR-008/ADR-011: one account_id for all records of a given
    /// account, regardless of entry type (V1 device snapshot vs V2 identity
    /// announcement).
    #[test]
    fn account_id_matches_v1_kt_entry() {
        use crate::entry::KtEntry;
        let mut rng = OsRng;
        #[allow(deprecated)]
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let hybrid = HybridIdentityKey::derive(&seed, 0).unwrap();
        let classical_pubkey = hybrid.public().ed25519_bytes();

        // V1 derive_account_id принимает IdentityKeyPublic; используем classical
        // identity для same seed+account.
        // V1 derive_account_id takes an IdentityKeyPublic; use the classical
        // identity for the same seed+account.
        use umbrella_identity::IdentityKey;
        let classical_id = IdentityKey::derive(&seed, 0).unwrap();
        let v1_account = KtEntry::derive_account_id(&classical_id.public());

        let v2_account = KtEntryV2::derive_account_id(&classical_pubkey);
        assert_eq!(
            v1_account, v2_account,
            "V1 и V2 account_id для same seed+account должны совпадать"
        );
    }
}
