//! SFrame RFC 9605 — end-to-end encrypted media frame protocol для
//! SFU-forwarded звонков (групповых до 32 участников). SFU видит только
//! зашифрованные кадры и AAD-часть SFrame header (CONFIG + KID + CTR);
//! plaintext и AEAD-ключи доступны только участникам MLS-группы через
//! derived `base_key`.
//!
//! ## Модули
//!
//! - [`mod@ciphersuite`] — `SframeCiphersuite::Aes256GcmSha512` (RFC 9605
//!   §4.5 ID `0x0005`) + константы длин `Nh/Nk/Nn/Nt`.
//! - [`mod@derive`] — `SframeBaseKey::from_mls_exporter` / `from_ikm` /
//!   `from_group` + `derive_per_kid` по RFC 9605 §4.4.2 (HKDF-Extract + Expand).
//! - [`mod@wire`] — `SframeHeader::parse` / `serialize` по RFC 9605 §4.1-4.3
//!   (layout `X K(3) Y C(3)`, minimum-encoding KID/CTR).
//! - [`mod@aead`] — AES-256-GCM invoke + per-frame `build_nonce`
//!   (RFC 9605 §4.4.3).
//! - [`mod@replay`] — `ReplayWindow` sliding 64-bit bitmap per-(sender, epoch)
//!   (SRTP RFC 3711 §3.3.2).
//! - [`mod@frame`] — `SframeContext` с 3-эпохальным VecDeque cache +
//!   per-KID derivation cache + per-(sender, epoch) replay windows +
//!   `encrypt_frame` / `decrypt_frame`.
//!
//! SFrame RFC 9605 — end-to-end encrypted media frame protocol for
//! SFU-forwarded calls (group calls up to 32 participants). The SFU only
//! sees encrypted frames and the AAD part of the SFrame header
//! (CONFIG, KID, CTR); plaintext and AEAD keys are accessible only to MLS
//! group members via the derived `base_key`.
//!
//! ## Modules
//!
//! - [`mod@ciphersuite`] — `SframeCiphersuite::Aes256GcmSha512` (RFC 9605
//!   §4.5 ID `0x0005`) + `Nh/Nk/Nn/Nt` length constants.
//! - [`mod@derive`] — `SframeBaseKey::from_mls_exporter` / `from_ikm` /
//!   `from_group` + `derive_per_kid` per RFC 9605 §4.4.2
//!   (HKDF-Extract + Expand).
//! - [`mod@wire`] — `SframeHeader::parse` / `serialize` per RFC 9605 §4.1-4.3
//!   (layout `X K(3) Y C(3)`, minimum-encoding KID/CTR).
//! - [`mod@aead`] — AES-256-GCM invoke + per-frame `build_nonce`
//!   (RFC 9605 §4.4.3).
//! - [`mod@replay`] — `ReplayWindow` sliding 64-bit bitmap per-(sender, epoch)
//!   (SRTP RFC 3711 §3.3.2).
//! - [`mod@frame`] — `SframeContext` with a 3-epoch VecDeque cache,
//!   per-KID derivation cache, per-(sender, epoch) replay windows, plus
//!   `encrypt_frame` / `decrypt_frame`.

pub mod aead;
pub mod ciphersuite;
pub mod derive;
pub mod frame;
pub mod replay;
pub mod wire;

pub use ciphersuite::{
    SframeCiphersuite, AEAD_TAG_LEN, BASE_KEY_LEN, SFRAME_KEY_LEN, SFRAME_SALT_LEN,
};
pub use derive::{PerKidKey, SframeBaseKey, MLS_EXPORTER_LABEL};
pub use frame::{
    compute_kid, parse_kid, DecryptedFrame, SframeContext, EPOCH_CACHE_SIZE,
    MAX_FRAME_PLAINTEXT_LEN, MAX_FRAME_WIRE_LEN,
};
pub use replay::{ReplayWindow, REPLAY_WINDOW_WIDTH};
pub use wire::{SframeHeader, MAX_HEADER_LEN};
