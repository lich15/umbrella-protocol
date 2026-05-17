//! # Key re-derivation
//!
//! Round-6 design: на устройстве **нет** персистентных master_key / device_key.
//! Они **re-derived** на каждый unlock через HKDF-SHA256 из composition:
//!
//! ```text
//! IKM     = PIN_KDF_root || server_share || device_random
//! info    = transcript || label
//! HKDF    = SHA256_Expand(SHA256_Extract(IKM, salt), info, L)
//! ```
//!
//! - `PIN_KDF_root` — 32 bytes Argon2id output из user PIN.
//! - `server_share` — 32 bytes (или encrypted blob) от одного из 3-of-5 серверов
//!   через threshold unwrap. Возвращается только после successful PIN verification.
//! - `device_random` — 32 bytes from device-stored salt (in Secure Enclave / KeyStore
//!   wrapped key). Уникален per device, never leaves SE/StrongBox.
//! - `transcript` — round-6 specifies binding к session: account_id + epoch + key_type.
//!
//! Outputs:
//! - `device_key` (32 bytes) — per-device, rotated через threshold sign.
//! - `master_key` (32 bytes) — account-wide, used for cloud-chat encryption.
//!
//! Both wrapped в `MlockedSecret` для page-lock + zeroize-on-drop.
//!
//! Round-6 design: no persistent master_key/device_key on device. They are
//! **re-derived** on every unlock via HKDF-SHA256.

use hkdf::Hkdf;
use sha2::Sha256;
use umbrella_crypto_primitives::mlocked::MlockedSecret;

use crate::error::{ThresholdIdentityError, ThresholdIdentityResult};

/// Output length для device_key + master_key — 32 bytes (X25519/ChaCha20 root).
pub const KEY_LEN: usize = 32;

/// Domain separator: device_key derivation.
pub const DEVICE_KEY_LABEL: &[u8] = b"umbrella-r6/device-key/v1";

/// Domain separator: master_key derivation.
pub const MASTER_KEY_LABEL: &[u8] = b"umbrella-r6/master-key/v1";

/// Per-account local salt — 16 bytes stored alongside encrypted device-state.
/// Cannot derive master_key without it.
pub type AccountLocalSalt = [u8; 16];

/// Per-device random — 32 bytes stored inside Secure Enclave / StrongBox.
/// Never leaves hardware-backed keystore in cleartext.
pub type DeviceRandom = [u8; 32];

/// Server share — 32 bytes returned by threshold-3 servers after successful
/// PIN verification. Encrypted in transit via HPKE (X25519 + ChaCha20-Poly1305).
pub type ServerShare = [u8; 32];

/// Transcript: binds derivation to (account_id, epoch). Prevents downgrade
/// attacks where an attacker replays old server_share with newer PIN.
#[derive(Debug, Clone)]
pub struct DerivationTranscript {
    /// 32-byte account-anonymous-id from server.
    pub account_id: [u8; 32],
    /// Monotonic 64-bit epoch — incremented on every device-key rotate.
    pub epoch: u64,
}

impl DerivationTranscript {
    /// Serialise to canonical 40-byte form для HKDF info.
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.account_id);
        out[32..].copy_from_slice(&self.epoch.to_be_bytes());
        out
    }
}

/// Re-derives device_key. Caller MUST hold `pin_root` from `pin_kdf::derive_pin_root`.
///
/// `device_random` загружается из SE/StrongBox.
/// `server_share` получен от threshold-3 unwrap response.
///
/// Re-derives device_key. Inputs sourced as documented in module docs.
pub fn derive_device_key(
    pin_root: &[u8; 32],
    server_share: &ServerShare,
    device_random: &DeviceRandom,
    transcript: &DerivationTranscript,
) -> ThresholdIdentityResult<MlockedSecret<[u8; KEY_LEN]>> {
    // IKM = pin_root || server_share || device_random (3 × 32 = 96 bytes).
    let mut ikm = [0u8; 96];
    ikm[..32].copy_from_slice(pin_root);
    ikm[32..64].copy_from_slice(server_share);
    ikm[64..].copy_from_slice(device_random);

    let salt = transcript.to_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);

    let mut out = MlockedSecret::<[u8; KEY_LEN]>::new([0u8; KEY_LEN]);
    hkdf.expand(DEVICE_KEY_LABEL, out.expose_mut().as_mut())
        .map_err(|_| ThresholdIdentityError::PinKdfFailure("HKDF expand"))?;

    // Wipe IKM — it contained server_share which is a secret.
    use zeroize::Zeroize;
    ikm.zeroize();
    Ok(out)
}

/// Re-derives master_key. Account-wide; used for cloud-chat history wrapping.
///
/// `master_key` differs from `device_key` в info-label (HKDF domain separation),
/// и в том что НЕ зависит от `device_random` — master_key должен быть identical
/// на всех устройствах одного аккаунта.
///
/// Re-derives master_key. Differs from device_key in HKDF label + does not
/// bind to device_random (must be identical across all account devices).
pub fn derive_master_key(
    pin_root: &[u8; 32],
    server_share: &ServerShare,
    account_local_salt: &AccountLocalSalt,
    transcript: &DerivationTranscript,
) -> ThresholdIdentityResult<MlockedSecret<[u8; KEY_LEN]>> {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(pin_root);
    ikm[32..].copy_from_slice(server_share);

    // Salt = transcript || account_local_salt.
    let mut salt = [0u8; 40 + 16];
    salt[..40].copy_from_slice(&transcript.to_bytes());
    salt[40..].copy_from_slice(account_local_salt);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);

    let mut out = MlockedSecret::<[u8; KEY_LEN]>::new([0u8; KEY_LEN]);
    hkdf.expand(MASTER_KEY_LABEL, out.expose_mut().as_mut())
        .map_err(|_| ThresholdIdentityError::PinKdfFailure("HKDF expand"))?;

    use zeroize::Zeroize;
    ikm.zeroize();
    salt.zeroize();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_transcript() -> DerivationTranscript {
        DerivationTranscript {
            account_id: [0xAA; 32],
            epoch: 1,
        }
    }

    #[test]
    fn device_key_deterministic_for_same_inputs() {
        let pin = [1u8; 32];
        let share = [2u8; 32];
        let rand = [3u8; 32];
        let t = dummy_transcript();
        let a = derive_device_key(&pin, &share, &rand, &t).unwrap();
        let b = derive_device_key(&pin, &share, &rand, &t).unwrap();
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn device_key_differs_from_master_key_label_separation() {
        let pin = [1u8; 32];
        let share = [2u8; 32];
        let rand = [3u8; 32];
        let t = dummy_transcript();
        let dk = derive_device_key(&pin, &share, &rand, &t).unwrap();
        let mk = derive_master_key(&pin, &share, &[0x42; 16], &t).unwrap();
        // Domain separator must yield independent outputs.
        assert_ne!(dk.expose(), mk.expose());
    }

    #[test]
    fn master_key_changes_with_epoch() {
        let pin = [1u8; 32];
        let share = [2u8; 32];
        let salt = [3u8; 16];
        let t1 = DerivationTranscript {
            account_id: [9; 32],
            epoch: 1,
        };
        let t2 = DerivationTranscript {
            account_id: [9; 32],
            epoch: 2,
        };
        let a = derive_master_key(&pin, &share, &salt, &t1).unwrap();
        let b = derive_master_key(&pin, &share, &salt, &t2).unwrap();
        assert_ne!(a.expose(), b.expose(), "epoch rotation must invalidate");
    }

    #[test]
    fn device_key_depends_on_device_random() {
        let pin = [1u8; 32];
        let share = [2u8; 32];
        let t = dummy_transcript();
        let a = derive_device_key(&pin, &share, &[0xAA; 32], &t).unwrap();
        let b = derive_device_key(&pin, &share, &[0xBB; 32], &t).unwrap();
        assert_ne!(
            a.expose(),
            b.expose(),
            "device_random domain separates per-device"
        );
    }
}
