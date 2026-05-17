//! Тонкая обёртка над крипто-примитивами с обязательным zeroize и constant-time API.
//! Thin wrappers around crypto primitives with mandatory zeroize and constant-time API.
//!
//! Этот крейт изолирует выбор бэкенда (RustCrypto, dalek-cryptography). Замена
//! одного бэкенда на другой не должна ломать downstream-крейты.
//!
//! This crate isolates the choice of backend (RustCrypto, dalek-cryptography).
//! Swapping one backend for another should not break downstream crates.
//!
//! # `unsafe` policy
//!
//! Все модули кроме `mlocked` имеют `#![forbid(unsafe_code)]` на уровне
//! модуля. `mlocked` использует `unsafe` для `libc::mlock` / `libc::munlock`
//! POSIX syscalls — единственный способ запретить ядру выгружать страницу
//! секретов в swap. Round-5 device-capture closure F-PHD-DC-R11-1.
//!
//! All modules except `mlocked` set `#![forbid(unsafe_code)]` at module
//! scope. `mlocked` uses `unsafe` for the `libc::mlock` / `libc::munlock`
//! POSIX syscalls — the only way to prevent the kernel from paging secret
//! pages out to swap. Round-5 device-capture closure F-PHD-DC-R11-1.

#![warn(missing_docs)]

pub mod aead;
pub mod dh;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod mlocked;
pub mod secret;
pub mod sig;

pub use error::{CryptoError, Result};
pub use mlocked::{MlockError, MlockedSecret};
pub use secret::SecretBytes;
