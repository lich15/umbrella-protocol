//! KT entry version stamps — discriminator для wire-format dispatch (Этап 8, блок 8.5).
//! KT entry version stamps — discriminator for wire-format dispatch (Stage 8, block 8.5).
//!
//! ## Назначение
//!
//! `KtEntryVersion` — дискриминатор первого байта wire-format KT entry. Введён
//! в Этапе 8 (ADR-011 Решение 6) для co-existence существующих V1 device-snapshot
//! entries и новых V2 identity-announcement entries в одном append-only Merkle
//! log.
//!
//! ## Важная инвариант: V1 wire-format не имеет version stamp
//!
//! Существующая `KtEntry::canonical_encoding` (entry.rs) **не содержит** leading
//! version-байт — она начинается с `account_id` (32 random bytes из SHA-256).
//! Это invariant 0.0.11 wire-format'а: изменить = инвалидировать все existing
//! Merkle leaf hashes (постулат 1 «документы = источник правды» + Merkle log
//! append-only invariant).
//!
//! Поэтому V1 entries **никогда не парсятся** через `KtEntryVersion::try_from`.
//! V1 entries конструируются как Rust-структуры напрямую через authorization
//! records (см. `authorization_entries.rs`) — wire-bytes V1 entries никогда не
//! проходят через первый-байт dispatcher.
//!
//! V2 entries (новый wire-format, блок 8.5) **имеют** leading byte `0x02` как
//! часть `KtEntryV2::canonical_encoding`. `KtEntryV2::from_bytes` вызывает
//! `KtEntryVersion::try_from(bytes[0])` и принимает только `V2HybridPq`,
//! отвергая всё остальное с `KtError::UnknownEntryVersion`.
//!
//! ## Backward compatibility 0.0.11
//!
//! `V1Classical = 0x01` присутствует в enum как **зарезервированный** value на
//! случай будущей миграции V1 wire-format на versioned envelope (требует
//! breaking-change ADR + server-side shim). На дату блока 8.5 это value НЕ
//! используется — `KtEntryV2::from_bytes` отвергает `0x01` так же, как любое
//! другое не-`0x02` значение, через `UnknownEntryVersion`.
//!
//! Существующий 0.0.11 клиент, не имеющий feature `pq`, не понимает V2 entries.
//! Когда 0.0.11 mirror получает V2 entry (leading byte `0x02`) — wire-format
//! validation existing pipeline отвергает entry (length mismatch / unknown
//! shape) **без silent acceptance**. Это existing behaviour для unknown bytes
//! и не требует изменений в 0.0.11 коде.
//!
//! ## Purpose
//!
//! `KtEntryVersion` is the first-byte discriminator for KT entry wire formats.
//! Introduced in Stage 8 (ADR-011 Decision 6) to allow existing V1
//! device-snapshot entries and new V2 identity-announcement entries to coexist
//! in the same append-only Merkle log.
//!
//! ## Important invariant: V1 wire format has no version stamp
//!
//! The existing `KtEntry::canonical_encoding` (entry.rs) does **not** contain a
//! leading version byte — it starts with `account_id` (32 random bytes from
//! SHA-256). This is an invariant of the 0.0.11 wire format: changing it
//! invalidates every existing Merkle leaf hash (postulate 1 «documents are the
//! source of truth» plus the Merkle log append-only invariant).
//!
//! Therefore V1 entries **are never parsed** through `KtEntryVersion::try_from`.
//! V1 entries are constructed as Rust structs directly through authorization
//! records (see `authorization_entries.rs`) — V1 wire bytes never flow through
//! the first-byte dispatcher.
//!
//! V2 entries (the new wire format, block 8.5) **do** carry a leading byte
//! `0x02` as part of `KtEntryV2::canonical_encoding`. `KtEntryV2::from_bytes`
//! calls `KtEntryVersion::try_from(bytes[0])` and accepts only `V2HybridPq`,
//! rejecting everything else with `KtError::UnknownEntryVersion`.
//!
//! ## 0.0.11 backward compatibility
//!
//! `V1Classical = 0x01` is present in the enum as a **reserved** value for a
//! potential future migration of the V1 wire format to a versioned envelope
//! (which would require a breaking-change ADR and a server-side shim). As of
//! block 8.5 this value is NOT used — `KtEntryV2::from_bytes` rejects `0x01`
//! the same way as any other non-`0x02` value, via `UnknownEntryVersion`.
//!
//! An existing 0.0.11 client without feature `pq` does not understand V2
//! entries. When a 0.0.11 mirror receives a V2 entry (leading byte `0x02`),
//! the wire-format validation in the existing pipeline rejects the entry
//! (length mismatch / unknown shape) **without silent acceptance**. This is
//! existing behaviour for unknown bytes and requires no changes to 0.0.11
//! code.

use crate::error::{KtError, Result};

/// Дискриминатор версии KT log entry — первый байт wire-format представления
/// V2 entry. V1 entries не несут version stamp (см. module-level docstring),
/// поэтому variant `V1Classical = 0x01` — зарезервированный «никогда не
/// встречается на проводе на дату блока 8.5».
///
/// Repr `u8` фиксирован FIPS-style: значения 0x01 / 0x02 — wire-уровень,
/// смена requires ADR amendment + breaking-change rollout.
///
/// Discriminator for the version of a KT log entry — the first byte of the
/// wire-format V2 entry. V1 entries do not carry a version stamp (see the
/// module-level docstring), so the variant `V1Classical = 0x01` is reserved
/// «never seen on the wire as of block 8.5».
///
/// Repr `u8` is FIPS-style fixed: the values 0x01 / 0x02 are wire-level —
/// changing them requires an ADR amendment plus a breaking-change rollout.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KtEntryVersion {
    /// Зарезервированное значение для будущей миграции V1 wire-format на
    /// versioned envelope. На дату блока 8.5 не используется — V1 entries
    /// существуют только как Rust-структуры (без version-байта в
    /// canonical_encoding) и не проходят через `try_from`.
    ///
    /// Reserved value for a potential future migration of the V1 wire format
    /// to a versioned envelope. Not used as of block 8.5 — V1 entries exist
    /// only as Rust structs (no version byte in canonical_encoding) and never
    /// flow through `try_from`.
    V1Classical = 0x01,

    /// V2 hybrid PQ entry — first byte 0x02. Entry содержит hybrid identity
    /// (Ed25519 + ML-DSA-65 pubkey) + optional SLH-DSA-128f backup pubkey.
    /// Layout — см. `crate::entry_v2::KtEntryV2`.
    ///
    /// V2 hybrid PQ entry — first byte 0x02. The entry carries a hybrid
    /// identity (Ed25519 + ML-DSA-65 pubkey) plus an optional SLH-DSA-128f
    /// backup pubkey. Layout — see `crate::entry_v2::KtEntryV2`.
    V2HybridPq = 0x02,
}

impl KtEntryVersion {
    /// Возвращает byte-representation version stamp.
    /// Returns the byte representation of the version stamp.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for KtEntryVersion {
    type Error = KtError;

    /// Парсинг version stamp с строгим matching. Любое значение кроме 0x01 и
    /// 0x02 — `KtError::UnknownEntryVersion { version }` (постулат 14: никакого
    /// silent fallback).
    ///
    /// Strict version-stamp parsing. Any value other than 0x01 or 0x02 yields
    /// `KtError::UnknownEntryVersion { version }` (postulate 14: no silent
    /// fallback).
    fn try_from(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(Self::V1Classical),
            0x02 => Ok(Self::V2HybridPq),
            _ => Err(KtError::UnknownEntryVersion { version: b }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_v1_classical() {
        assert_eq!(
            KtEntryVersion::try_from(0x01u8).unwrap(),
            KtEntryVersion::V1Classical
        );
    }

    #[test]
    fn try_from_v2_hybrid_pq() {
        assert_eq!(
            KtEntryVersion::try_from(0x02u8).unwrap(),
            KtEntryVersion::V2HybridPq
        );
    }

    #[test]
    fn try_from_zero_rejected() {
        assert_eq!(
            KtEntryVersion::try_from(0x00u8).unwrap_err(),
            KtError::UnknownEntryVersion { version: 0x00 }
        );
    }

    #[test]
    fn try_from_three_rejected() {
        assert_eq!(
            KtEntryVersion::try_from(0x03u8).unwrap_err(),
            KtError::UnknownEntryVersion { version: 0x03 }
        );
    }

    #[test]
    fn try_from_high_byte_rejected() {
        assert_eq!(
            KtEntryVersion::try_from(0xFFu8).unwrap_err(),
            KtError::UnknownEntryVersion { version: 0xFF }
        );
    }

    #[test]
    fn as_u8_roundtrip_v1() {
        let v = KtEntryVersion::V1Classical;
        assert_eq!(v.as_u8(), 0x01);
        assert_eq!(KtEntryVersion::try_from(v.as_u8()).unwrap(), v);
    }

    #[test]
    fn as_u8_roundtrip_v2() {
        let v = KtEntryVersion::V2HybridPq;
        assert_eq!(v.as_u8(), 0x02);
        assert_eq!(KtEntryVersion::try_from(v.as_u8()).unwrap(), v);
    }

    /// Все байты кроме 0x01 и 0x02 должны давать `UnknownEntryVersion` с тем же
    /// байтом в payload — стабильный contract для caller'ов которые логируют
    /// rejection причину.
    /// All bytes except 0x01 and 0x02 must yield `UnknownEntryVersion` with the
    /// same byte in the payload — stable contract for callers that log the
    /// rejection cause.
    #[test]
    fn try_from_exhaustive_rejection_payload() {
        for b in 0u16..=255u16 {
            let b = b as u8;
            match b {
                0x01 | 0x02 => {} // accepted
                _ => {
                    let err = KtEntryVersion::try_from(b).unwrap_err();
                    assert_eq!(err, KtError::UnknownEntryVersion { version: b });
                }
            }
        }
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(KtEntryVersion::V1Classical, KtEntryVersion::V2HybridPq);
        assert_ne!(
            KtEntryVersion::V1Classical.as_u8(),
            KtEntryVersion::V2HybridPq.as_u8()
        );
    }
}
