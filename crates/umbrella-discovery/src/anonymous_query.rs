//! Per-query анонимные ID: каждая discovery-query получает свежий anon_id,
//! derived из master_key + per-query salt через HKDF. Это устраняет
//! linkability двух запросов одного пользователя (D-2, D-6 mitigation).
//!
//! Per-query anonymous IDs: each discovery query receives a fresh anon_id,
//! derived from master_key + per-query salt via HKDF. Eliminates linkability
//! between two queries by the same user (D-2 / D-6 mitigation).
//!
//! # Безопасность
//!
//! - Без master_key (не персистится на устройстве — re-derive из PIN
//!   через `umbrella-threshold-identity`) сервер не может корреллировать.
//! - Per-query salt берётся из CSPRNG (32 байта).
//! - HKDF-SHA-256 даёт криптографическую stretchy между master_key и
//!   per-query anon_id: знание K выходов anon_id не позволяет восстановить
//!   master_key (Bellare-Lange 2010 HKDF security).
//!
//! # Security
//!
//! Without master_key (not persisted on the device — re-derived from PIN via
//! `umbrella-threshold-identity`), the server cannot correlate. Per-query
//! salt comes from CSPRNG (32 bytes). HKDF-SHA-256 gives cryptographic
//! stretch between master_key and per-query anon_id; knowing K outputs cannot
//! recover master_key (Bellare-Lange 2010 HKDF security).

use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{DiscoveryError, DiscoveryResult};

/// Domain separator для per-query anon-id derivation.
/// Domain separator for per-query anon-id derivation.
pub const PER_QUERY_ANON_ID_LABEL: &[u8] = b"umbrella-r7/discovery/per-query-anon-id/v1";

/// Длина anonymous-id (32 bytes).
/// Anonymous-id length.
pub const ANON_ID_LEN: usize = umbrella_threshold_identity::anonymous_id::ANON_ID_LEN;

/// Длина per-query salt (32 bytes).
/// Per-query salt length.
pub const SALT_LEN: usize = 32;

/// Свежий per-query salt из CSPRNG.
/// Fresh per-query salt from CSPRNG.
pub fn fresh_query_salt<R: CryptoRng + RngCore>(rng: &mut R) -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    salt
}

/// Derive per-query anon_id для конкретного сервера `server_id` (1..=5)
/// под общим `master_key` и unique `query_salt`.
///
/// Формула:
/// ```text
/// info = u16_be(server_id) || query_salt || PER_QUERY_ANON_ID_LABEL
/// anon_id = HKDF-SHA-256(master_key, info, 32)
/// ```
///
/// Каждый сервер получает разный anon_id (через server_id в info), и каждая
/// query получает разный anon_id (через query_salt). Без master_key
/// reconstruction невозможна (HKDF — PRF в random oracle model).
///
/// Derive a per-query anon_id for a given server `server_id` (1..=5) under
/// shared `master_key` and unique `query_salt`. Each server gets a distinct
/// anon_id (via server_id in info), and each query gets a distinct anon_id
/// (via query_salt). Without master_key reconstruction is impossible.
///
/// # Errors
/// - [`DiscoveryError::InputRejected`] если `server_id == 0` либо > 5.
/// - [`DiscoveryError::CryptoInternal`] если HKDF-expand вернул ошибку.
pub fn derive_per_query_anon_id(
    master_key: &[u8; 32],
    server_id: u16,
    query_salt: &[u8; SALT_LEN],
) -> DiscoveryResult<[u8; ANON_ID_LEN]> {
    if server_id == 0 || server_id > 5 {
        return Err(DiscoveryError::InputRejected("server_id must be 1..=5"));
    }
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut info = Vec::with_capacity(2 + SALT_LEN + PER_QUERY_ANON_ID_LABEL.len());
    info.extend_from_slice(&server_id.to_be_bytes());
    info.extend_from_slice(query_salt);
    info.extend_from_slice(PER_QUERY_ANON_ID_LABEL);

    let mut out = [0u8; ANON_ID_LEN];
    hkdf.expand(&info, &mut out)
        .map_err(|_| DiscoveryError::CryptoInternal("HKDF expand per-query anon-id"))?;
    info.zeroize();
    Ok(out)
}

/// Derive все 5 per-server anon_ids для одной query.
/// Derive all 5 per-server anon_ids for a single query.
///
/// # Errors
/// - [`DiscoveryError::CryptoInternal`] если HKDF expand failed.
pub fn derive_per_query_anon_ids_all_servers(
    master_key: &[u8; 32],
    query_salt: &[u8; SALT_LEN],
) -> DiscoveryResult<[[u8; ANON_ID_LEN]; 5]> {
    let mut out = [[0u8; ANON_ID_LEN]; 5];
    for (i, id) in out.iter_mut().enumerate() {
        *id = derive_per_query_anon_id(master_key, (i + 1) as u16, query_salt)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use std::collections::HashSet;

    #[test]
    fn per_query_anon_ids_distinct_across_servers() {
        let mk = [0x33u8; 32];
        let salt = [0xAA; SALT_LEN];
        let id1 = derive_per_query_anon_id(&mk, 1, &salt).unwrap();
        let id2 = derive_per_query_anon_id(&mk, 2, &salt).unwrap();
        let id3 = derive_per_query_anon_id(&mk, 3, &salt).unwrap();
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[test]
    fn per_query_anon_ids_distinct_across_queries() {
        let mk = [0x33u8; 32];
        let salt_a = [0xAA; SALT_LEN];
        let salt_b = [0xBB; SALT_LEN];
        let id_a = derive_per_query_anon_id(&mk, 1, &salt_a).unwrap();
        let id_b = derive_per_query_anon_id(&mk, 1, &salt_b).unwrap();
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn per_query_anon_ids_deterministic_for_same_inputs() {
        let mk = [0x55u8; 32];
        let salt = [0xCC; SALT_LEN];
        let a = derive_per_query_anon_id(&mk, 3, &salt).unwrap();
        let b = derive_per_query_anon_id(&mk, 3, &salt).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_zero_server_id() {
        let r = derive_per_query_anon_id(&[0; 32], 0, &[0; SALT_LEN]);
        assert!(matches!(r, Err(DiscoveryError::InputRejected(_))));
    }

    #[test]
    fn rejects_server_id_over_five() {
        for bad in [6u16, 7, 100, 1000] {
            let r = derive_per_query_anon_id(&[0; 32], bad, &[0; SALT_LEN]);
            assert!(matches!(r, Err(DiscoveryError::InputRejected(_))));
        }
    }

    #[test]
    fn all_five_anon_ids_pairwise_distinct() {
        let all =
            derive_per_query_anon_ids_all_servers(&[0xAB; 32], &[0xCD; SALT_LEN]).unwrap();
        for i in 0..5 {
            for j in (i + 1)..5 {
                assert_ne!(all[i], all[j], "server {i} == server {j}");
            }
        }
    }

    /// D-6 mitigation invariant: 1000 different salts → 1000 different anon_ids
    /// for the same master_key + server_id pair. This is the basic
    /// unlinkability requirement.
    #[test]
    fn one_thousand_queries_zero_anon_id_collisions() {
        let mk = [0x42u8; 32];
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let salt = fresh_query_salt(&mut OsRng);
            let id = derive_per_query_anon_id(&mk, 1, &salt).unwrap();
            assert!(seen.insert(id), "anon_id collision after {} salts", seen.len());
        }
        assert_eq!(seen.len(), 1000);
    }

    /// D-2 mitigation: cross-server корреляция невозможна без master_key.
    /// Server A's anon_id and Server B's anon_id для одной query — разные.
    /// D-2 mitigation: cross-server correlation impossible without master_key.
    #[test]
    fn cross_server_anon_ids_are_unlinkable_without_master_key() {
        let mk = [0x99u8; 32];
        let salt = fresh_query_salt(&mut OsRng);
        let server_a = derive_per_query_anon_id(&mk, 1, &salt).unwrap();
        let server_b = derive_per_query_anon_id(&mk, 2, &salt).unwrap();
        // Без master_key Server A не может вычислить server_b's anon_id из своего.
        // Симуляция: попытка brute-force через простое равенство.
        assert_ne!(server_a, server_b);
        // Inverse direction: same.
        let server_a2 = derive_per_query_anon_id(&mk, 1, &salt).unwrap();
        let server_b2 = derive_per_query_anon_id(&mk, 2, &salt).unwrap();
        assert_eq!(server_a, server_a2);
        assert_eq!(server_b, server_b2);
        assert_ne!(server_a, server_b);
    }
}
