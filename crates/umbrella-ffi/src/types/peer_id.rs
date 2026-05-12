//! `PeerIdFfi` — 32-байтовый Ed25519 identity pubkey для FFI.
//!
//! `PeerIdFfi` — 32-byte Ed25519 identity pubkey for the FFI boundary.

use umbrella_client::facade::chat_common::PeerId;

use crate::error::UmbrellaError;

/// FFI представление [`PeerId`] — 32 байта Ed25519 pubkey.
///
/// FFI representation of [`PeerId`] — 32 bytes of Ed25519 pubkey.
#[derive(Clone, Debug, uniffi::Record)]
pub struct PeerIdFfi {
    /// Ровно 32 байта Ed25519 pub.
    ///
    /// Exactly 32 bytes of Ed25519 pubkey.
    pub bytes: Vec<u8>,
}

impl TryFrom<PeerIdFfi> for PeerId {
    type Error = UmbrellaError;

    fn try_from(v: PeerIdFfi) -> Result<Self, Self::Error> {
        if v.bytes.len() != 32 {
            return Err(UmbrellaError::Internal(format!(
                "peer_id length {}, expected 32",
                v.bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v.bytes);
        Ok(PeerId(arr))
    }
}

impl From<PeerId> for PeerIdFfi {
    fn from(v: PeerId) -> Self {
        PeerIdFfi {
            bytes: v.0.to_vec(),
        }
    }
}
