//! FFI-exposed data types — uniffi `Records`. ABI-stable (только
//! `Vec<u8>` / `String` / `u64` / `bool` / nested records).
//!
//! Все Records `#[derive(uniffi::Record)]` — генерирует Swift `struct`
//! и Kotlin `data class`. `TryFrom` validation длины байтовых полей
//! (32 для ChatId/PeerId) — при wrong size возвращается
//! `UmbrellaError::Internal`.
//!
//! FFI-exposed data types — uniffi `Records`. ABI-stable (only `Vec<u8>`
//! / `String` / `u64` / `bool` / nested records).
//!
//! Each record uses `#[derive(uniffi::Record)]` — generates a Swift
//! `struct` and Kotlin `data class`. `TryFrom` validates byte-field
//! lengths (32 for ChatId/PeerId); a mismatch returns
//! `UmbrellaError::Internal`.

/// FFI-обёртка для идентификатора чата.
/// FFI wrapper for the chat identifier.
pub mod chat_id;

/// FFI-обёртка для сообщения и связанных типов.
/// FFI wrapper for messages and related types.
pub mod message;

/// FFI-обёртка для идентификатора пира.
/// FFI wrapper for the peer identifier.
pub mod peer_id;

pub use chat_id::ChatIdFfi;
pub use message::{CallPolicyFfi, MessageFfi};
pub use peer_id::PeerIdFfi;
