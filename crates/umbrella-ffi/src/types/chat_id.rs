//! `ChatIdFfi` — 32-байтовый идентификатор чата для FFI.
//!
//! `ChatIdFfi` — 32-byte chat identifier for the FFI boundary.

use umbrella_client::facade::chat_common::ChatId;

use crate::error::UmbrellaError;

/// FFI представление [`ChatId`] — 32 байта в `Vec<u8>` (uniffi не поддерживает
/// fixed-length arrays). Validation длины — на конверсии в Rust-тип.
///
/// FFI representation of [`ChatId`] — 32 bytes in a `Vec<u8>` (uniffi does
/// not support fixed-length arrays). Length validation happens during
/// conversion into the Rust type.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ChatIdFfi {
    /// Ровно 32 байта identity-derived chat ID.
    ///
    /// Exactly 32 bytes of identity-derived chat ID.
    pub bytes: Vec<u8>,
}

impl TryFrom<ChatIdFfi> for ChatId {
    type Error = UmbrellaError;

    fn try_from(v: ChatIdFfi) -> Result<Self, Self::Error> {
        if v.bytes.len() != 32 {
            return Err(UmbrellaError::Internal(format!(
                "chat_id length {}, expected 32",
                v.bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v.bytes);
        Ok(ChatId(arr))
    }
}

impl From<ChatId> for ChatIdFfi {
    fn from(v: ChatId) -> Self {
        ChatIdFfi {
            bytes: v.0.to_vec(),
        }
    }
}
