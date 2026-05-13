//! Hybrid post-quantum primitives: ML-KEM-768, X-Wing, ML-DSA-65, SLH-DSA-128f-simple.
//! Hybrid post-quantum primitives: ML-KEM-768, X-Wing, ML-DSA-65, SLH-DSA-128f-simple.
//!
//! Все примитивы работают только в hybrid с classical (X25519, Ed25519) — никогда не отгружаем
//! pure-PQ в production. Урок KyberSlash 2024: если в lattice-based найдут side-channel,
//! classical companion защищает.
//!
//! All primitives operate only in hybrid mode with classical (X25519, Ed25519) — never
//! pure-PQ in production. KyberSlash 2024 lesson: if lattice-based reveals a side-channel,
//! the classical companion protects.
//!
//! # Бэкенды
//!
//! Бэкенды pinned exact; upstream assurance принимается только в scoped виде:
//!
//! - `libcrux-ml-kem 0.0.9` (mlkem768 feature) — ML-KEM-768 (FIPS 203).
//! - `libcrux-kem 0.0.8` — X-Wing combiner (upstream API name
//!   `Algorithm::XWingKemDraft06`, output checked against draft-10 KAT).
//! - `libcrux-ml-dsa 0.0.9` (mldsa65 feature) — ML-DSA-65 (FIPS 204).
//! - `fips205 0.4.1` (slh_dsa_sha2_128f feature) — SLH-DSA-SHA2-128f-simple (FIPS 205).
//!
//! libcrux-* используется через **derand API** (`generate_key_pair([u8; SEED])`,
//! `encapsulate_derand(&seed)`) потому что libcrux-kem 0.0.8 в её non-derand path
//! требует `rand_core 0.9` `CryptoRng`, несовместимый с workspace `rand_core 0.6`.
//! Наш API принимает `&mut R: RngCore + CryptoRng` от workspace `rand_core 0.6` и
//! наполняет нужный seed через `fill_bytes`.
//!
//! # Backends
//!
//! Backends are pinned exactly; upstream assurance is accepted only with
//! scoped boundaries:
//!
//! - `libcrux-ml-kem 0.0.9` (mlkem768 feature) — ML-KEM-768 (FIPS 203).
//! - `libcrux-kem 0.0.8` — X-Wing combiner (upstream API name
//!   `Algorithm::XWingKemDraft06`, output checked against draft-10 KAT).
//! - `libcrux-ml-dsa 0.0.9` (mldsa65 feature) — ML-DSA-65 (FIPS 204).
//! - `fips205 0.4.1` (slh_dsa_sha2_128f feature) — SLH-DSA-SHA2-128f-simple (FIPS 205).
//!
//! libcrux-* is used via the **derand API** (`generate_key_pair([u8; SEED])`,
//! `encapsulate_derand(&seed)`) because libcrux-kem 0.0.8's non-derand path requires
//! `rand_core 0.9` `CryptoRng`, incompatible with workspace `rand_core 0.6`. Our API
//! accepts `&mut R: RngCore + CryptoRng` from workspace `rand_core 0.6` and fills the
//! required seed via `fill_bytes`.
//!
//! # Подробности
//! # Details
//!
//! - private protocol notes — normative hybrid PQ specification.
//! - `docs/adr/ADR-011-hybrid-pq.md` — architecture rationale.
//! - `docs/audits/production-readiness-2026-05-09/real-world-attack-pass.md` — current
//!   production verification notes for real-world PQ bug classes.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod constants;
pub mod error;

#[cfg(feature = "ml-kem")]
pub mod ml_kem;
#[cfg(feature = "ml-kem")]
pub mod xwing;

#[cfg(feature = "ml-dsa")]
pub mod hybrid_signature;
#[cfg(feature = "ml-dsa")]
pub mod ml_dsa;

#[cfg(feature = "slh-dsa")]
pub mod slh_dsa;

pub use constants::*;
pub use error::{PqError, Result};

#[cfg(feature = "ml-kem")]
pub use ml_kem::{
    ml_kem_768_decaps, ml_kem_768_encaps, ml_kem_768_keygen, ml_kem_768_validate_public_key,
    MlKem768PublicKey, MlKem768SecretKey,
};

#[cfg(feature = "ml-kem")]
pub use xwing::{
    xwing_decaps, xwing_decaps_raw, xwing_encaps, xwing_encaps_derand, xwing_keygen,
    xwing_keygen_from_seed, XWingPublicKey, XWingSecretSeed,
};

#[cfg(feature = "ml-dsa")]
pub use ml_dsa::{
    ml_dsa_65_keygen, ml_dsa_65_sign, ml_dsa_65_verify, MlDsa65PublicKey, MlDsa65SecretKey,
    MlDsa65Signature,
};

#[cfg(feature = "ml-dsa")]
pub use hybrid_signature::{
    hybrid_keygen, hybrid_sign, hybrid_verify, HybridPublicKey, HybridSecretKey, HybridSignature,
};

#[cfg(feature = "slh-dsa")]
pub use slh_dsa::{
    slh_dsa_128f_keygen, slh_dsa_128f_sign, slh_dsa_128f_verify, SlhDsa128fPublicKey,
    SlhDsa128fSecretKey, SlhDsa128fSignature,
};

/// Маркер сборки. Используется для diagnostic output и unit-test sanity check.
/// Build marker. Used for diagnostic output and unit-test sanity check.
pub const BUILD_MARKER: &str = "umbrella-pq stage-8";
