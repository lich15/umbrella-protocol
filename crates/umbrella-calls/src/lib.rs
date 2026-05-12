//! E2E звонки UmbrellaX: DTLS-SRTP identity binding (1-1) и MLS + SFrame
//! RFC 9605 (групповые до 32). Серверная сторона (SFU / TURN) никогда не
//! расшифровывает медиа и видит только зашифрованные кадры + AAD-часть
//! SFrame header'а.
//!
//! Публичный API (по блокам Этапа 6):
//!
//! - [`error::CallError`] — единый enum ошибок (блок 6.2).
//! - [`sframe::ciphersuite`] — `SframeCiphersuite::Aes256GcmSha512` +
//!   константы длин (блок 6.2).
//! - [`sframe::derive`] — `SframeBaseKey::from_mls_exporter` / `from_group` /
//!   `from_ikm`, `derive_per_kid`, `PerKidKey` по RFC 9605 §4.4.2 (HKDF-Extract +
//!   HKDF-Expand-SHA512) (блоки 6.2 + 6.3).
//! - [`sframe::wire`] — `SframeHeader::parse` / `serialize` по RFC 9605 §4.1-4.3
//!   (блок 6.3).
//! - [`sframe::aead`] — crate-local AEAD wrapper (блок 6.3).
//! - [`sframe::replay`] — `ReplayWindow` sliding 64-bit bitmap (блок 6.3).
//! - [`sframe::frame`] — `SframeContext` / `encrypt_frame` / `decrypt_frame`
//!   (блок 6.3).
//! - `dtls::fingerprint` — DTLS identity binding для 1-1 звонков
//!   (блок 6.4; не в scope 6.3).
//! - `policy`, `level` — `CallPolicy`, `RoutingMode`,
//!   `CallSecurityLevel` (блок 6.5; не в scope 6.3).
//!
//! Интеграция с LiveKit SFU и реальный DTLS/ICE/STUN/TURN остаются вне
//! крейта. ADR-2026-04-20-23 Umbrella server implementation описывает default single-relay
//! и opt-in double-relay для IP privacy; исполнение routing — на уровне
//! `umbrella-client` и native bridges Этапа 7.
//!
//! E2E calls for UmbrellaX: DTLS-SRTP identity binding (1-1) and MLS +
//! SFrame RFC 9605 (group calls up to 32). The server side (SFU / TURN)
//! never decrypts media and sees only encrypted frames plus the AAD part
//! of the SFrame header.
//!
//! Public API (by Stage 6 blocks):
//!
//! - [`error::CallError`] — single error enum (block 6.2).
//! - [`sframe::ciphersuite`] — `SframeCiphersuite::Aes256GcmSha512` +
//!   length constants (block 6.2).
//! - [`sframe::derive`] — `SframeBaseKey::from_mls_exporter` / `from_group` /
//!   `from_ikm`, `derive_per_kid`, `PerKidKey` per RFC 9605 §4.4.2 (HKDF-Extract +
//!   HKDF-Expand-SHA512) (blocks 6.2 + 6.3).
//! - [`sframe::wire`] — `SframeHeader::parse` / `serialize` per RFC 9605
//!   §4.1-4.3 (block 6.3).
//! - [`sframe::aead`] — crate-local AEAD wrapper (block 6.3).
//! - [`sframe::replay`] — `ReplayWindow` sliding 64-bit bitmap (block 6.3).
//! - [`sframe::frame`] — `SframeContext` / `encrypt_frame` / `decrypt_frame`
//!   (block 6.3).
//! - `dtls::fingerprint` — DTLS identity binding for 1-1 calls
//!   (block 6.4; not in 6.3 scope).
//! - `policy`, `level` — `CallPolicy`, `RoutingMode`,
//!   `CallSecurityLevel` (block 6.5; not in 6.3 scope).
//!
//! LiveKit SFU integration and real DTLS/ICE/STUN/TURN stay outside the
//! crate. ADR-2026-04-20-23 in Umbrella server implementation describes default single-relay
//! and opt-in double-relay for IP privacy; routing execution belongs to
//! `umbrella-client` and the native bridges of Stage 7.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod dtls;
pub mod error;
pub mod level;
pub mod policy;
pub mod sframe;

pub use dtls::{
    compute_mutual_identity_binding, IdentityDtlsFingerprint, FINGERPRINT_LEN, IDENTITY_PUBKEY_LEN,
    SESSION_NONCE_LEN,
};
pub use error::{CallError, Result};
pub use level::CallSecurityLevel;
pub use policy::{CallPolicy, PeerId, RoutingMode};
pub use sframe::{
    compute_kid, parse_kid, DecryptedFrame, PerKidKey, ReplayWindow, SframeBaseKey,
    SframeCiphersuite, SframeContext, SframeHeader, AEAD_TAG_LEN, BASE_KEY_LEN, EPOCH_CACHE_SIZE,
    MAX_FRAME_PLAINTEXT_LEN, MAX_FRAME_WIRE_LEN, MAX_HEADER_LEN, MLS_EXPORTER_LABEL,
    REPLAY_WINDOW_WIDTH, SFRAME_KEY_LEN, SFRAME_SALT_LEN,
};

/// Build marker — видим в `nm`/binary inspection, указывает что блок
/// 6.5 Этапа Calls merged в main.
///
/// Build marker — visible in `nm`/binary inspection, indicates that
/// Stage 6 block 6.5 is merged into main.
pub const BUILD_MARKER: &str = "umbrella-calls stage-6.5 policy-level";
