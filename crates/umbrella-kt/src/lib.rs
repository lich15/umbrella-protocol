//! Key Transparency клиент: append-only log, self-monitoring, multi-witness (в блоке 3.4).
//! Key Transparency client: append-only log, self-monitoring, multi-witness (block 3.4).
//!
//! ## Назначение
//!
//! Закрывает **ghost participant** атаку (Levy & Robinson, Lawfare 2018 — GCHQ exceptional
//! access proposal). Без KT провайдер `key-svc` может подменить KeyPackage жертвы на
//! контролируемый сервером, и MLS примет ghost как легитимного члена группы. KT делает такие
//! подмены **публично наблюдаемыми**: все device-keys публикуются в append-only Merkle-лог,
//! клиенты **самостоятельно проверяют** что их собственная запись не подменена (self-monitoring),
//! а подписи log-корня независимыми witness-серверами (блок 3.4) повышают цену split-view
//! атаки. Обнаружение раздвоения одной эпохи требует сверки публичных наблюдений или номеров
//! безопасности; см. `observation` для проверяемого доказательства split-view.
//!
//! ## Что реализует текущий блок (3.3)
//!
//! - `merkle`: RFC 6962 Merkle tree (domain-separated leaf/inner hashes, audit path build,
//!   inclusion proof verify).
//! - `entry`: канонический формат `KtEntry` с детерминистическим encoding (байт-в-байт
//!   воспроизводимо для одинаковых входов).
//! - `monitor`: self-monitoring — клиент сравнивает получённую запись с собственными
//!   ожиданиями, любое расхождение возвращается как `SelfMonitoringMismatch { field }`.
//!
//! ## Что будет в блоке 3.4
//!
//! Multi-witness verification: 5 независимых witness-серверов подписывают root-hash каждой
//! эпохи, клиент принимает эпоху только при 3-of-5 валидных подписях. Non-equivocation check
//! через last-tree-hash консистентность между эпохами.
//!
//! ## Что добавил блок 8.5 (Этап 8 PQ opt-in, ADR-011 Решение 6)
//!
//! - `version` (всегда compiled): `KtEntryVersion` enum с дискриминатором первого байта
//!   wire-format V2 entry — основа для V1 ↔ V2 coexistence.
//! - `entry_v2` (под `feature = "pq"`): `KtEntryV2` — identity-announcement entry с hybrid
//!   identity (Ed25519 + ML-DSA-65 pubkey) и optional SLH-DSA-128f backup pubkey. Leading
//!   byte 0x02; canonical encoding ~2 KB. Complementary к V1 device-snapshot, не replace.
//! - `monitor` расширен (`feature = "pq"`): `HybridOwnExpectations` + `verify_own_v2_entry`
//!   проверяют hybrid identity в V2 entry — закрывают ghost-participant атаку для PQ
//!   identity layer.
//!
//! V1 wire-format (existing 0.0.11 `KtEntry::canonical_encoding`) **не меняется** — Merkle
//! leaf hash invariant сохраняется (постулат 1, ADR-011 Решение 6 backward compat).
//!
//! ## What block 8.5 adds (Stage 8 PQ opt-in, ADR-011 Decision 6)
//!
//! - `version` (always compiled): the `KtEntryVersion` enum — first-byte discriminator for
//!   the wire-format V2 entry; the basis for V1 ↔ V2 coexistence.
//! - `entry_v2` (under `feature = "pq"`): `KtEntryV2` — an identity-announcement entry with
//!   hybrid identity (Ed25519 + ML-DSA-65 pubkey) and an optional SLH-DSA-128f backup pubkey.
//!   Leading byte 0x02; canonical encoding ~2 KB. Complementary to the V1 device snapshot,
//!   not a replacement.
//! - `monitor` extended (`feature = "pq"`): `HybridOwnExpectations` plus `verify_own_v2_entry`
//!   check the hybrid identity in a V2 entry — closing the ghost-participant attack at the
//!   PQ identity layer.
//!
//! The V1 wire format (existing 0.0.11 `KtEntry::canonical_encoding`) does **not** change —
//! the Merkle leaf hash invariant is preserved (postulate 1, ADR-011 Decision 6 backward
//! compat).
//!
//! ## Purpose
//!
//! Closes the **ghost participant** attack (Levy & Robinson, Lawfare 2018 — GCHQ exceptional
//! access proposal). Without KT the `key-svc` provider can substitute a victim's KeyPackage
//! with a server-controlled one, and MLS accepts the ghost as a legitimate member. KT makes
//! such substitutions **publicly observable**: all device-keys go into an append-only Merkle
//! log, clients **self-monitor** that their own record is unchanged, and independent witness
//! signatures on the log root (block 3.4) raise the cost of split-view attacks. Same-epoch
//! fork detection requires comparing public observations or safety numbers; see
//! `observation` for verifiable split-view evidence.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod authorization_entries;
pub mod entry;
#[cfg(feature = "pq")]
pub mod entry_v2;
pub mod error;
pub mod merkle;
pub mod monitor;
pub mod observation;
pub mod version;
pub mod witness;

pub use authorization_entries::{
    apply_authorization_approval, apply_authorization_revocation, apply_identity_rotation,
    lookup_device_entry, DeviceAuthorizationApproval, DeviceAuthorizationRevocation,
    DeviceEntryRef, DeviceEntryState, DeviceEntryStateFlag, EntryType, IdentityRotationRecord,
    KtLogState, RotationReason, DEVICE_PUBKEY_LEN,
};
pub use entry::{DeviceAttestationRef, KtEntry, MAX_ENTRY_ENCODED_LEN};
#[cfg(feature = "pq")]
pub use entry_v2::{KtEntryV2, KT_ENTRY_V2_MAX_ENCODED_LEN, KT_ENTRY_V2_MIN_ENCODED_LEN};
pub use error::{KtError, Result};
pub use merkle::{
    audit_path_length, build_audit_path, empty_root, inner_hash, leaf_hash, merkle_root,
    verify_inclusion, AuditPath, INNER_PREFIX, LEAF_PREFIX, NODE_HASH_LEN,
};
pub use monitor::{verify_own_entry, OwnExpectations};
#[cfg(feature = "pq")]
pub use monitor::{verify_own_v2_entry, HybridOwnExpectations};
pub use observation::{
    compare_observations, EquivocationEvidence, KtLogId, KtObservation, KtTrustDecision,
    KT_OBSERVATION_VERSION, MAX_OBSERVATION_SIGNATURES,
};
pub use version::KtEntryVersion;
pub use witness::{
    canonical_sign_payload, sign_payload_digest, verify_signed_epoch, SignedEpochRoot,
    WitnessPublic, WitnessSet, WitnessSignature, WITNESS_DOMAIN_SEP, WITNESS_VERSION,
};
