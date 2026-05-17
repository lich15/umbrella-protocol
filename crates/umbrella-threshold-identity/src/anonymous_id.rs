//! # Zero-knowledge account IDs
//!
//! Каждый из 5 серверов имеет **разный** anonymous ID для одного и того же
//! пользователя. ID derived через HKDF из `(master_key, server_id)` — без
//! master_key correlation между серверами невозможна.
//!
//! Без знания master_key (которое device не персистит — re-derive из PIN):
//! - Server A не может сказать что его `anon_id_A` относится к тому же
//!   аккаунту что Server B's `anon_id_B`.
//! - Subpoena к Server A раскрывает только `anon_id_A`, не сам аккаунт.
//! - Compromise всех 5 серверов **и** capture user device's PIN root всё равно
//!   не позволяет привязать к реальной personality (phone optional, used only
//!   once at registration for friend discovery).
//!
//! Zero-knowledge account IDs — per-server pseudonyms derived from
//! `(master_key, server_id)`, cross-server correlation impossible without
//! master_key (device-only via PIN re-derive).

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{ThresholdIdentityError, ThresholdIdentityResult};

/// Domain separator для anonymous-id derivation.
pub const ANON_ID_LABEL: &[u8] = b"umbrella-r6/anon-id/v1";

/// Number of bytes in an anonymous account ID.
pub const ANON_ID_LEN: usize = 32;

/// Derives the anonymous account ID for server `server_id` (1..=5) given the
/// account's `master_key`. Output is 32 bytes — cryptographically unique per
/// (master_key, server_id) pair.
///
/// Derives anonymous account ID = HKDF-SHA256(master_key, server_id, label).
pub fn derive_anonymous_id(
    master_key: &[u8; 32],
    server_id: u16,
) -> ThresholdIdentityResult<[u8; ANON_ID_LEN]> {
    if server_id == 0 {
        return Err(ThresholdIdentityError::Io(
            "server_id must be 1-indexed".into(),
        ));
    }

    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut info = [0u8; 2 + ANON_ID_LABEL.len()];
    info[..2].copy_from_slice(&server_id.to_be_bytes());
    info[2..].copy_from_slice(ANON_ID_LABEL);

    let mut out = [0u8; ANON_ID_LEN];
    hkdf.expand(&info, &mut out)
        .map_err(|_| ThresholdIdentityError::PinKdfFailure("HKDF expand anon-id"))?;
    Ok(out)
}

/// Derives all 5 per-server anonymous IDs from a single master_key. Useful
/// for client-side preparation (one master_key → 5 IDs to send to 5 servers).
pub fn derive_all_anonymous_ids(
    master_key: &[u8; 32],
) -> ThresholdIdentityResult<[[u8; ANON_ID_LEN]; 5]> {
    let mut out = [[0u8; ANON_ID_LEN]; 5];
    for (i, id) in out.iter_mut().enumerate() {
        *id = derive_anonymous_id(master_key, (i + 1) as u16)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_ids_differ_across_servers() {
        let mk = [0x33; 32];
        let id1 = derive_anonymous_id(&mk, 1).unwrap();
        let id2 = derive_anonymous_id(&mk, 2).unwrap();
        let id3 = derive_anonymous_id(&mk, 3).unwrap();
        // Cross-server correlation impossible.
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[test]
    fn different_master_keys_yield_different_ids() {
        let id_a = derive_anonymous_id(&[0xAA; 32], 1).unwrap();
        let id_b = derive_anonymous_id(&[0xBB; 32], 1).unwrap();
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let mk = [0x55; 32];
        let a = derive_anonymous_id(&mk, 3).unwrap();
        let b = derive_anonymous_id(&mk, 3).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn all_five_ids_pairwise_distinct() {
        let all = derive_all_anonymous_ids(&[0xAB; 32]).unwrap();
        for i in 0..5 {
            for j in (i + 1)..5 {
                assert_ne!(all[i], all[j], "server {i} == server {j}");
            }
        }
    }

    #[test]
    fn zero_server_id_rejected() {
        let r = derive_anonymous_id(&[0; 32], 0);
        assert!(r.is_err());
    }
}
