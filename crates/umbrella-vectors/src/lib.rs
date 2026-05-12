//! Генерация и валидация test vectors для Umbrella Protocol Extensions
//! (SFrame RFC 9605, KT, Sealed Sender, Backup envelope).
//!
//! Generation and validation of test vectors for Umbrella Protocol Extensions
//! (SFrame RFC 9605, KT, Sealed Sender, Backup envelope).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod nist_kat;
pub mod sframe;

pub use nist_kat::{
    decode_hex, decode_hex_opt, load_nist_kat_file, NistKatError, NistKatFile, NistKatVector,
};

/// Маркер сборки. Build marker.
pub const BUILD_MARKER: &str = "umbrella-vectors stage-8 nist-kat";
