//! Тонкая обёртка над крипто-примитивами с обязательным zeroize и constant-time API.
//! Thin wrappers around crypto primitives with mandatory zeroize and constant-time API.
//!
//! Этот крейт изолирует выбор бэкенда (RustCrypto, dalek-cryptography). Замена
//! одного бэкенда на другой не должна ломать downstream-крейты.
//!
//! This crate isolates the choice of backend (RustCrypto, dalek-cryptography).
//! Swapping one backend for another should not break downstream crates.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod aead;
pub mod dh;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod secret;
pub mod sig;

pub use error::{CryptoError, Result};
pub use secret::SecretBytes;
