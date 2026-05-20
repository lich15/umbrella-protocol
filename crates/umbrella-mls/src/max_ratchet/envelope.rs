//! Wire-format codec for max_ratchet v3 sealed envelopes.
//!
//! Task 6 carry-over из max-ratchet v3 spec 2026-05-20 §7.2. Bundles MLS commit +
//! application ciphertext + SPQR HMAC внутри single `ClientPayload::SendMessage.ciphertext`
//! field, сохраняя wire-level совместимость с существующим gateway protocol (no proto
//! changes required).
//!
//! ## Wire format
//!
//! ```text
//! [V3_MARKER: u8 = 0xFF]
//! [V3_VERSION: u8 = 0x03]
//! [commit_len: u16 BE]
//! [commit_bytes: commit_len bytes]
//! [ct_len: u32 BE]
//! [ciphertext_bytes: ct_len bytes]
//! [spqr_mac: 32 bytes]
//! ```
//!
//! ## Backward compatibility
//!
//! `V3_MARKER = 0xFF` collision-free с TLS-serialized MLS application messages: openmls
//! 0.8 serializes `ProtocolVersion::MLS_10 = 0x0100`, так что first byte любого MLS
//! message всегда `0x01` (high byte of u16 BE). Legacy v2 reader получив v3 message
//! пробует process_incoming → openmls returns `Codec` error (invalid ProtocolVersion) →
//! сообщение graceful'но отбрасывается, не crash. v3 reader проверяет marker первым и
//! routes accordingly; raw MLS bytes (legacy v2 path) идут через legacy code path.
//!
//! ## Task 6 closure note
//!
//! Это enables real activation max_ratchet защит (aggressive DH + SPQR HMAC) для ВСЕХ v3
//! пользователей через CloudChat / SecretChat — последний open carry-over из max ratchet
//! v3 spec acceptance criteria.

/// Magic byte marking v3 bundled envelope в первом байте of `ClientPayload.ciphertext`.
/// Collision-free с TLS-serialized MLS message (first byte всегда `0x01`).
pub const V3_MARKER: u8 = 0xFF;

/// Wire version inside v3 bundle. `0x03` corresponds к v3 release line. Future v4+
/// будет иметь other version byte after marker → forward-compat detection.
pub const V3_VERSION: u8 = 0x03;

/// SPQR HMAC длина (HMAC-SHA256 → 32 bytes). Matches
/// [`SPQR_HMAC_LEN`](super::spqr::SPQR_HMAC_LEN).
pub const SPQR_MAC_LEN: usize = 32;

/// Минимальный размер v3 bundle: marker(1) + version(1) + commit_len(2) + ct_len(4) + mac(32).
pub const V3_MIN_LEN: usize = 1 + 1 + 2 + 4 + SPQR_MAC_LEN;

/// Decoded view над v3 bundle bytes — zero-copy slices в исходный blob.
#[derive(Debug)]
pub struct V3Decoded<'a> {
    /// MLS commit bytes (Some если sender выполнил force_rekey; None если commit suppressed).
    pub commit_bytes: Option<&'a [u8]>,
    /// TLS-serialized MLS application message bytes.
    pub ciphertext_bytes: &'a [u8],
    /// SPQR HMAC over `ciphertext_bytes` (32 bytes). Zero-filled если sender не активировал
    /// SPQR.
    pub spqr_mac: [u8; SPQR_MAC_LEN],
}

/// Bundle v3 wire format: marker + version + commit + ciphertext + SPQR mac.
///
/// `commit_bytes = None` → empty commit slot (zero-length commit). `spqr_mac = None` →
/// zero-filled 32 bytes (sender disabled SPQR). Receiver интерпретирует zero mac как
/// "absent" only когда expected = None (config check).
pub fn encode_v3(
    commit_bytes: Option<&[u8]>,
    ciphertext_bytes: &[u8],
    spqr_mac: Option<&[u8; SPQR_MAC_LEN]>,
) -> Vec<u8> {
    let commit = commit_bytes.unwrap_or(&[]);
    assert!(
        commit.len() <= u16::MAX as usize,
        "commit bytes exceed wire format u16 length"
    );
    assert!(
        ciphertext_bytes.len() <= u32::MAX as usize,
        "ciphertext bytes exceed wire format u32 length"
    );
    let mac = spqr_mac.copied().unwrap_or([0u8; SPQR_MAC_LEN]);

    let mut out = Vec::with_capacity(V3_MIN_LEN + commit.len() + ciphertext_bytes.len());
    out.push(V3_MARKER);
    out.push(V3_VERSION);
    out.extend_from_slice(&(commit.len() as u16).to_be_bytes());
    out.extend_from_slice(commit);
    out.extend_from_slice(&(ciphertext_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(ciphertext_bytes);
    out.extend_from_slice(&mac);
    out
}

/// Detect + parse v3 bundle. Returns `None` если:
/// - `blob` короче `V3_MIN_LEN`
/// - первый байт `!= V3_MARKER`
/// - version байт `!= V3_VERSION`
/// - commit_len или ct_len indicates structure inconsistent (insufficient bytes)
/// - тотальный размер не точно `1+1+2+commit_len+4+ct_len+32`
///
/// `None` означает "not v3 либо malformed v3" — caller falls back на legacy path.
/// Strict equality check on total length protects от trailing data attacks
/// (malicious sender extra bytes which could be reinterpreted by other parsers).
pub fn try_decode_v3(blob: &[u8]) -> Option<V3Decoded<'_>> {
    if blob.len() < V3_MIN_LEN {
        return None;
    }
    if blob[0] != V3_MARKER {
        return None;
    }
    if blob[1] != V3_VERSION {
        return None;
    }
    let commit_len = u16::from_be_bytes([blob[2], blob[3]]) as usize;
    let after_commit_hdr = 4 + commit_len;
    if blob.len() < after_commit_hdr + 4 + SPQR_MAC_LEN {
        return None;
    }
    let ct_len_off = after_commit_hdr;
    let ct_len = u32::from_be_bytes([
        blob[ct_len_off],
        blob[ct_len_off + 1],
        blob[ct_len_off + 2],
        blob[ct_len_off + 3],
    ]) as usize;
    let ct_off = ct_len_off + 4;
    let mac_off = ct_off + ct_len;
    if blob.len() != mac_off + SPQR_MAC_LEN {
        // Strict equality: reject any trailing bytes.
        return None;
    }
    let commit_bytes = if commit_len > 0 {
        Some(&blob[4..after_commit_hdr])
    } else {
        None
    };
    let ciphertext_bytes = &blob[ct_off..mac_off];
    let mut spqr_mac = [0u8; SPQR_MAC_LEN];
    spqr_mac.copy_from_slice(&blob[mac_off..mac_off + SPQR_MAC_LEN]);
    Some(V3Decoded {
        commit_bytes,
        ciphertext_bytes,
        spqr_mac,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip_with_commit_and_mac() {
        let commit = vec![0xAA; 200];
        let ct = vec![0xBB; 64];
        let mac = [0xCC; SPQR_MAC_LEN];
        let blob = encode_v3(Some(&commit), &ct, Some(&mac));

        let decoded = try_decode_v3(&blob).expect("must decode");
        assert_eq!(decoded.commit_bytes, Some(&commit[..]));
        assert_eq!(decoded.ciphertext_bytes, &ct[..]);
        assert_eq!(decoded.spqr_mac, mac);
    }

    #[test]
    fn encode_decode_roundtrip_without_commit() {
        let ct = vec![0x42; 128];
        let mac = [0x11; SPQR_MAC_LEN];
        let blob = encode_v3(None, &ct, Some(&mac));

        let decoded = try_decode_v3(&blob).expect("must decode");
        assert!(decoded.commit_bytes.is_none());
        assert_eq!(decoded.ciphertext_bytes, &ct[..]);
        assert_eq!(decoded.spqr_mac, mac);
    }

    #[test]
    fn encode_decode_roundtrip_without_mac() {
        let ct = vec![0x77; 16];
        let blob = encode_v3(None, &ct, None);

        let decoded = try_decode_v3(&blob).expect("must decode");
        assert!(decoded.commit_bytes.is_none());
        assert_eq!(decoded.ciphertext_bytes, &ct[..]);
        assert_eq!(decoded.spqr_mac, [0u8; SPQR_MAC_LEN]);
    }

    #[test]
    fn reject_too_short_blob() {
        let blob = vec![0xFF; V3_MIN_LEN - 1];
        assert!(try_decode_v3(&blob).is_none());
    }

    #[test]
    fn reject_wrong_marker_legacy_mls_path() {
        // Legacy v2 raw MLS message starts с 0x01 (MLS ProtocolVersion 0x0100 BE).
        let mut blob = vec![0u8; V3_MIN_LEN];
        blob[0] = 0x01; // looks like MLS message
        assert!(try_decode_v3(&blob).is_none());
    }

    #[test]
    fn reject_wrong_version() {
        let mut blob = vec![0u8; V3_MIN_LEN];
        blob[0] = V3_MARKER;
        blob[1] = 0x02; // not V3_VERSION (= 0x03)
        assert!(try_decode_v3(&blob).is_none());
    }

    #[test]
    fn reject_inconsistent_commit_len() {
        let mut blob = encode_v3(Some(&[0; 4]), &[0; 16], Some(&[0; SPQR_MAC_LEN]));
        // Inflate commit_len header to be larger than actual buffer
        blob[2] = 0xFF;
        blob[3] = 0xFF;
        assert!(try_decode_v3(&blob).is_none());
    }

    #[test]
    fn reject_trailing_bytes() {
        let mut blob = encode_v3(None, &[0xCD; 8], Some(&[0xEE; SPQR_MAC_LEN]));
        blob.push(0xAB); // unauthorized trailing byte
        assert!(try_decode_v3(&blob).is_none());
    }

    #[test]
    fn marker_is_collision_free_with_mls_first_byte() {
        // Any TLS-serialized MLS message begins with ProtocolVersion::MLS_10 = 0x0100
        // big-endian → first byte always 0x01. V3_MARKER = 0xFF is invalid as
        // ProtocolVersion (RFC 9420 reserved 0xFF00..=0xFFFF) → guaranteed no collision.
        assert_ne!(V3_MARKER, 0x01);
        assert_eq!(V3_MARKER, 0xFF);
    }

    #[test]
    fn encode_decode_roundtrip_large_pq_sized_commit() {
        // X-Wing commit ~1100 bytes — ensure u16 commit_len handles it.
        let commit = vec![0x55; 1100];
        let ct = vec![0x66; 256];
        let mac = [0x77; SPQR_MAC_LEN];
        let blob = encode_v3(Some(&commit), &ct, Some(&mac));

        let decoded = try_decode_v3(&blob).expect("must decode large commit");
        assert_eq!(decoded.commit_bytes.as_ref().unwrap().len(), 1100);
        assert_eq!(decoded.ciphertext_bytes.len(), 256);
    }
}
