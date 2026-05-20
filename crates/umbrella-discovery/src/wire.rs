//! Wire-форматы discovery: PSI-запрос/ответ, username-запрос/ответ,
//! KT-bind структура. Все типы сериализуются в `Vec<u8>` через явные
//! big-endian encoders — никаких serde/bincode зависимостей чтобы избежать
//! schema drift (постулат «wire = детерминированный байтовый формат»).
//!
//! Wire formats for discovery: PSI request/response, username request/response,
//! KT-bind structure. All types serialize to `Vec<u8>` via explicit big-endian
//! encoders — no serde/bincode to avoid schema drift.
//!
//! ## Версионирование
//!
//! Первый байт каждого top-level wire object — `WIRE_VERSION` (0x01). Любая
//! несовместимость в будущих версиях должна привести к **отказу** decode'а;
//! не silent fallback (Postulate 1 «explicit version, no silent
//! downgrade»).
//!
//! ## Versioning
//!
//! The first byte of every top-level wire object is `WIRE_VERSION` (0x01). Any
//! future-incompatible change must cause decode to **fail** — no silent
//! fallback.

use umbrella_kt::AuditPath;

use crate::error::{DiscoveryError, DiscoveryResult};

/// Wire-версия discovery (`0x01`).
/// Discovery wire version (`0x01`).
pub const WIRE_VERSION: u8 = 0x01;

/// Длина OPRF blinded request / server evaluation (compressed Ristretto255).
/// Length of the OPRF blinded request / server evaluation.
pub const POINT_LEN: usize = umbrella_oprf::POINT_LEN;

/// Длина OPRF финальной метки.
/// OPRF final label length.
pub const LABEL_LEN: usize = umbrella_oprf::LABEL_LEN;

/// Длина anonymous-id (round 6 HKDF output).
/// Anonymous-id length (round-6 HKDF output).
pub const ANON_ID_LEN: usize = umbrella_threshold_identity::anonymous_id::ANON_ID_LEN;

/// Длина device_pubkey (Ed25519 public key, RFC 8032).
/// Device pubkey length.
pub const DEVICE_PUBKEY_LEN: usize = 32;

/// Длина server nonce (для replay rejection).
/// Server nonce length (for replay rejection).
pub const SERVER_NONCE_LEN: usize = 32;

/// Длина transcript binding (HMAC tag).
/// Transcript binding length (HMAC tag).
pub const TRANSCRIPT_TAG_LEN: usize = 32;

/// Длина SHA-256 хеша Merkle leaf/root.
/// SHA-256 hash length.
pub const NODE_HASH_LEN: usize = umbrella_kt::NODE_HASH_LEN;

/// Максимальный размер PSI-батча (контактов в одном запросе).
/// PSI batch maximum.
pub const MAX_PSI_BATCH: usize = 1024;

/// Максимальная длина handle / phone-input в байтах.
/// Handle/phone input max length.
pub const MAX_INPUT_BYTES: usize = umbrella_oprf::MAX_INPUT_BYTES;

/// Максимальная длина encrypted username record (AEAD ciphertext + tag).
/// Username encrypted-record max length.
pub const MAX_USERNAME_RECORD_LEN: usize = 256;

/// Одна запись PSI-batch: blinded request + per-query anonymous ID.
/// One PSI-batch entry: blinded request + per-query anonymous ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsiQueryEntry {
    /// Anonymous-id для этой query (per-query rotation, D-6 mitigation).
    /// Per-query anonymous-id (D-6 mitigation).
    pub anon_id: [u8; ANON_ID_LEN],

    /// Blinded compressed Ristretto255 point (от OPRF).
    /// Blinded compressed Ristretto255 point.
    pub blinded: [u8; POINT_LEN],
}

/// PSI-запрос: batch из N entries + server nonce (для replay), бинди тип.
/// PSI request: batch of N entries + server nonce (replay), version tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsiRequest {
    /// Wire version (всегда `WIRE_VERSION = 0x01`).
    /// Wire version (always `WIRE_VERSION = 0x01`).
    pub version: u8,

    /// Per-query записи.
    /// Per-query entries.
    pub entries: Vec<PsiQueryEntry>,

    /// Client-side nonce для transcript binding (replay rejection D-5).
    /// Client nonce for transcript binding (D-5).
    pub client_nonce: [u8; SERVER_NONCE_LEN],

    /// Witness index сервера (для каких 3 of 5 серверов клиент отправил).
    /// Witness index of the server (which of 3 of 5 the client targeted).
    pub witness_index: u8,
}

impl PsiRequest {
    /// Сериализовать в каноничный wire.
    /// Serialize to canonical wire.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            1 + 1 + 2 + self.entries.len() * (ANON_ID_LEN + POINT_LEN) + SERVER_NONCE_LEN,
        );
        out.push(self.version);
        out.push(self.witness_index);
        out.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.anon_id);
            out.extend_from_slice(&entry.blinded);
        }
        out.extend_from_slice(&self.client_nonce);
        out
    }

    /// Декодировать (с полной валидацией длин и version).
    /// Decode with full length+version validation.
    ///
    /// # Errors
    /// - [`DiscoveryError::WireDecode`] при любой несовместимости (version,
    ///   length, encoding).
    pub fn decode(bytes: &[u8]) -> DiscoveryResult<Self> {
        if bytes.len() < 1 + 1 + 2 + SERVER_NONCE_LEN {
            return Err(DiscoveryError::WireDecode {
                reason: "psi request bytes too short",
            });
        }
        let version = bytes[0];
        if version != WIRE_VERSION {
            return Err(DiscoveryError::WireDecode {
                reason: "psi request wire version mismatch",
            });
        }
        let witness_index = bytes[1];
        let n = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if n == 0 || n > MAX_PSI_BATCH {
            return Err(DiscoveryError::WireDecode {
                reason: "psi request batch size out of range",
            });
        }
        let body_len = n * (ANON_ID_LEN + POINT_LEN);
        let expected_len = 4 + body_len + SERVER_NONCE_LEN;
        if bytes.len() != expected_len {
            return Err(DiscoveryError::WireDecode {
                reason: "psi request length mismatch",
            });
        }
        let mut entries = Vec::with_capacity(n);
        let mut pos = 4;
        for _ in 0..n {
            let mut anon_id = [0u8; ANON_ID_LEN];
            anon_id.copy_from_slice(&bytes[pos..pos + ANON_ID_LEN]);
            pos += ANON_ID_LEN;
            let mut blinded = [0u8; POINT_LEN];
            blinded.copy_from_slice(&bytes[pos..pos + POINT_LEN]);
            pos += POINT_LEN;
            entries.push(PsiQueryEntry { anon_id, blinded });
        }
        let mut client_nonce = [0u8; SERVER_NONCE_LEN];
        client_nonce.copy_from_slice(&bytes[pos..pos + SERVER_NONCE_LEN]);
        Ok(Self {
            version,
            entries,
            client_nonce,
            witness_index,
        })
    }
}

/// Ответ PSI: одна запись на каждую entry в запросе (или ошибка серверная).
/// PSI response: one entry per request entry (or server error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsiResponseEntry {
    /// Anonymous-id (эхо запроса, для соотнесения position-by-position).
    /// Anonymous-id (echo for positional pairing).
    pub anon_id: [u8; ANON_ID_LEN],

    /// Server evaluation (compressed Ristretto255).
    /// Server evaluation (compressed Ristretto255).
    pub evaluation: [u8; POINT_LEN],
}

/// PSI ответ.
/// PSI response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsiResponse {
    /// Wire version.
    /// Wire version.
    pub version: u8,

    /// Ответы по позициям.
    /// Positional responses.
    pub entries: Vec<PsiResponseEntry>,

    /// Server nonce (echo для transcript binding + replay rejection).
    /// Server nonce (echo for transcript binding + replay rejection).
    pub server_nonce: [u8; SERVER_NONCE_LEN],

    /// Transcript HMAC (binds (client_nonce, server_nonce, entries)).
    /// Transcript HMAC over (client_nonce, server_nonce, entries).
    pub transcript_tag: [u8; TRANSCRIPT_TAG_LEN],
}

impl PsiResponse {
    /// Сериализовать в каноничный wire.
    /// Serialize to canonical wire.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            1 + 2
                + self.entries.len() * (ANON_ID_LEN + POINT_LEN)
                + SERVER_NONCE_LEN
                + TRANSCRIPT_TAG_LEN,
        );
        out.push(self.version);
        out.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.anon_id);
            out.extend_from_slice(&entry.evaluation);
        }
        out.extend_from_slice(&self.server_nonce);
        out.extend_from_slice(&self.transcript_tag);
        out
    }

    /// Декодировать (с полной валидацией).
    /// Decode with full validation.
    ///
    /// # Errors
    /// - [`DiscoveryError::WireDecode`] на любую неконсистентность.
    pub fn decode(bytes: &[u8]) -> DiscoveryResult<Self> {
        if bytes.len() < 1 + 2 + SERVER_NONCE_LEN + TRANSCRIPT_TAG_LEN {
            return Err(DiscoveryError::WireDecode {
                reason: "psi response bytes too short",
            });
        }
        let version = bytes[0];
        if version != WIRE_VERSION {
            return Err(DiscoveryError::WireDecode {
                reason: "psi response wire version mismatch",
            });
        }
        let n = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        if n == 0 || n > MAX_PSI_BATCH {
            return Err(DiscoveryError::WireDecode {
                reason: "psi response batch size out of range",
            });
        }
        let body_len = n * (ANON_ID_LEN + POINT_LEN);
        let expected = 3 + body_len + SERVER_NONCE_LEN + TRANSCRIPT_TAG_LEN;
        if bytes.len() != expected {
            return Err(DiscoveryError::WireDecode {
                reason: "psi response length mismatch",
            });
        }
        let mut entries = Vec::with_capacity(n);
        let mut pos = 3;
        for _ in 0..n {
            let mut anon_id = [0u8; ANON_ID_LEN];
            anon_id.copy_from_slice(&bytes[pos..pos + ANON_ID_LEN]);
            pos += ANON_ID_LEN;
            let mut eval = [0u8; POINT_LEN];
            eval.copy_from_slice(&bytes[pos..pos + POINT_LEN]);
            pos += POINT_LEN;
            entries.push(PsiResponseEntry {
                anon_id,
                evaluation: eval,
            });
        }
        let mut server_nonce = [0u8; SERVER_NONCE_LEN];
        server_nonce.copy_from_slice(&bytes[pos..pos + SERVER_NONCE_LEN]);
        pos += SERVER_NONCE_LEN;
        let mut transcript_tag = [0u8; TRANSCRIPT_TAG_LEN];
        transcript_tag.copy_from_slice(&bytes[pos..pos + TRANSCRIPT_TAG_LEN]);
        Ok(Self {
            version,
            entries,
            server_nonce,
            transcript_tag,
        })
    }
}

/// Wire-запрос username lookup: blinded handle + anon_id.
/// Username lookup wire request: blinded handle + anon_id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsernameRequest {
    /// Wire version.
    pub version: u8,
    /// Witness index 1..=5.
    pub witness_index: u8,
    /// Per-query anon-id.
    pub anon_id: [u8; ANON_ID_LEN],
    /// Blinded compressed Ristretto255.
    pub blinded: [u8; POINT_LEN],
    /// Client nonce.
    pub client_nonce: [u8; SERVER_NONCE_LEN],
}

impl UsernameRequest {
    /// Сериализовать.
    /// Serialize.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 1 + ANON_ID_LEN + POINT_LEN + SERVER_NONCE_LEN);
        out.push(self.version);
        out.push(self.witness_index);
        out.extend_from_slice(&self.anon_id);
        out.extend_from_slice(&self.blinded);
        out.extend_from_slice(&self.client_nonce);
        out
    }

    /// Декодировать.
    /// Decode.
    ///
    /// # Errors
    /// - [`DiscoveryError::WireDecode`] на любую несовместимость.
    pub fn decode(bytes: &[u8]) -> DiscoveryResult<Self> {
        let expected = 1 + 1 + ANON_ID_LEN + POINT_LEN + SERVER_NONCE_LEN;
        if bytes.len() != expected {
            return Err(DiscoveryError::WireDecode {
                reason: "username request length mismatch",
            });
        }
        if bytes[0] != WIRE_VERSION {
            return Err(DiscoveryError::WireDecode {
                reason: "username request wire version mismatch",
            });
        }
        let witness_index = bytes[1];
        let mut anon_id = [0u8; ANON_ID_LEN];
        anon_id.copy_from_slice(&bytes[2..2 + ANON_ID_LEN]);
        let mut blinded = [0u8; POINT_LEN];
        let off = 2 + ANON_ID_LEN;
        blinded.copy_from_slice(&bytes[off..off + POINT_LEN]);
        let mut client_nonce = [0u8; SERVER_NONCE_LEN];
        client_nonce.copy_from_slice(&bytes[off + POINT_LEN..off + POINT_LEN + SERVER_NONCE_LEN]);
        Ok(Self {
            version: WIRE_VERSION,
            witness_index,
            anon_id,
            blinded,
            client_nonce,
        })
    }
}

/// KT inclusion proof для discovery answer (binds handle → device_pubkey
/// к KT log epoch root).
/// KT inclusion proof for discovery answer (binds handle → device_pubkey
/// to a KT log epoch root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KtInclusionProof {
    /// Ожидаемый Merkle root для эпохи (32 bytes SHA-256).
    /// Expected Merkle root for the epoch (32 bytes SHA-256).
    pub epoch_root: [u8; NODE_HASH_LEN],

    /// Размер дерева (количество leaves в эпохе).
    /// Tree size (number of leaves in the epoch).
    pub tree_size: u64,

    /// Индекс leaf в дереве.
    /// Leaf index in the tree.
    pub leaf_index: u64,

    /// Canonical leaf bytes (что input в leaf_hash на стороне клиента).
    /// Canonical leaf bytes (input to leaf_hash on the client).
    pub leaf_payload: Vec<u8>,

    /// Sibling-хеши снизу вверх для верификации (audit path).
    /// Sibling hashes bottom-up for verification (audit path).
    pub siblings: Vec<[u8; NODE_HASH_LEN]>,
}

impl KtInclusionProof {
    /// Преобразовать siblings в [`AuditPath`] для verify_inclusion.
    /// Convert siblings to [`AuditPath`] for verify_inclusion.
    pub fn as_audit_path(&self) -> AuditPath {
        AuditPath {
            siblings: self.siblings.clone(),
        }
    }
}

/// Wire-ответ username lookup.
/// Username lookup wire response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsernameResponse {
    /// Wire version.
    pub version: u8,
    /// Эхо anon_id для соотнесения.
    pub anon_id: [u8; ANON_ID_LEN],
    /// Server evaluation (compressed Ristretto255).
    pub evaluation: [u8; POINT_LEN],
    /// Encrypted record (ChaCha20-Poly1305 ciphertext, ключ derived через
    /// OPRF unblind output). HasMap rows can store this verbatim.
    /// Encrypted record (ChaCha20-Poly1305 ciphertext, key derived from the
    /// OPRF unblind output).
    pub encrypted_record: Vec<u8>,
    /// KT inclusion proof (binds device_pubkey).
    /// KT inclusion proof (binds device_pubkey).
    pub kt_proof: KtInclusionProof,
    /// Server nonce + transcript tag.
    /// Server nonce + transcript tag.
    pub server_nonce: [u8; SERVER_NONCE_LEN],
    /// Transcript binding tag.
    /// Transcript binding tag.
    pub transcript_tag: [u8; TRANSCRIPT_TAG_LEN],
}

impl UsernameResponse {
    /// Сериализовать в canonical wire.
    /// Serialize to canonical wire.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        out.extend_from_slice(&self.anon_id);
        out.extend_from_slice(&self.evaluation);
        out.extend_from_slice(&(self.encrypted_record.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.encrypted_record);
        out.extend_from_slice(&self.kt_proof.epoch_root);
        out.extend_from_slice(&self.kt_proof.tree_size.to_be_bytes());
        out.extend_from_slice(&self.kt_proof.leaf_index.to_be_bytes());
        out.extend_from_slice(&(self.kt_proof.leaf_payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.kt_proof.leaf_payload);
        out.extend_from_slice(&(self.kt_proof.siblings.len() as u16).to_be_bytes());
        for s in &self.kt_proof.siblings {
            out.extend_from_slice(s);
        }
        out.extend_from_slice(&self.server_nonce);
        out.extend_from_slice(&self.transcript_tag);
        out
    }

    /// Декодировать (полная валидация).
    /// Decode with full validation.
    ///
    /// # Errors
    /// - [`DiscoveryError::WireDecode`] на любую неконсистентность.
    pub fn decode(bytes: &[u8]) -> DiscoveryResult<Self> {
        if bytes.is_empty() {
            return Err(DiscoveryError::WireDecode {
                reason: "username response empty",
            });
        }
        if bytes[0] != WIRE_VERSION {
            return Err(DiscoveryError::WireDecode {
                reason: "username response wire version mismatch",
            });
        }
        let mut pos = 1usize;
        let need = |p: usize, n: usize, src: &[u8]| -> DiscoveryResult<()> {
            if p + n > src.len() {
                Err(DiscoveryError::WireDecode {
                    reason: "username response truncated",
                })
            } else {
                Ok(())
            }
        };
        need(pos, ANON_ID_LEN, bytes)?;
        let mut anon_id = [0u8; ANON_ID_LEN];
        anon_id.copy_from_slice(&bytes[pos..pos + ANON_ID_LEN]);
        pos += ANON_ID_LEN;
        need(pos, POINT_LEN, bytes)?;
        let mut eval = [0u8; POINT_LEN];
        eval.copy_from_slice(&bytes[pos..pos + POINT_LEN]);
        pos += POINT_LEN;
        need(pos, 2, bytes)?;
        let rec_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        if rec_len > MAX_USERNAME_RECORD_LEN {
            return Err(DiscoveryError::WireDecode {
                reason: "username record too large",
            });
        }
        need(pos, rec_len, bytes)?;
        let encrypted_record = bytes[pos..pos + rec_len].to_vec();
        pos += rec_len;
        need(pos, NODE_HASH_LEN, bytes)?;
        let mut epoch_root = [0u8; NODE_HASH_LEN];
        epoch_root.copy_from_slice(&bytes[pos..pos + NODE_HASH_LEN]);
        pos += NODE_HASH_LEN;
        need(pos, 8, bytes)?;
        let tree_size = u64::from_be_bytes(bytes[pos..pos + 8].try_into().map_err(|_| {
            DiscoveryError::WireDecode {
                reason: "tree_size decode",
            }
        })?);
        pos += 8;
        need(pos, 8, bytes)?;
        let leaf_index = u64::from_be_bytes(bytes[pos..pos + 8].try_into().map_err(|_| {
            DiscoveryError::WireDecode {
                reason: "leaf_index decode",
            }
        })?);
        pos += 8;
        need(pos, 2, bytes)?;
        let leaf_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        need(pos, leaf_len, bytes)?;
        let leaf_payload = bytes[pos..pos + leaf_len].to_vec();
        pos += leaf_len;
        need(pos, 2, bytes)?;
        let sib_count = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        if sib_count > 64 {
            return Err(DiscoveryError::WireDecode {
                reason: "too many KT proof siblings",
            });
        }
        need(pos, sib_count * NODE_HASH_LEN, bytes)?;
        let mut siblings = Vec::with_capacity(sib_count);
        for _ in 0..sib_count {
            let mut s = [0u8; NODE_HASH_LEN];
            s.copy_from_slice(&bytes[pos..pos + NODE_HASH_LEN]);
            siblings.push(s);
            pos += NODE_HASH_LEN;
        }
        need(pos, SERVER_NONCE_LEN, bytes)?;
        let mut server_nonce = [0u8; SERVER_NONCE_LEN];
        server_nonce.copy_from_slice(&bytes[pos..pos + SERVER_NONCE_LEN]);
        pos += SERVER_NONCE_LEN;
        need(pos, TRANSCRIPT_TAG_LEN, bytes)?;
        let mut transcript_tag = [0u8; TRANSCRIPT_TAG_LEN];
        transcript_tag.copy_from_slice(&bytes[pos..pos + TRANSCRIPT_TAG_LEN]);
        pos += TRANSCRIPT_TAG_LEN;
        if pos != bytes.len() {
            return Err(DiscoveryError::WireDecode {
                reason: "username response trailing bytes",
            });
        }
        Ok(Self {
            version: WIRE_VERSION,
            anon_id,
            evaluation: eval,
            encrypted_record,
            kt_proof: KtInclusionProof {
                epoch_root,
                tree_size,
                leaf_index,
                leaf_payload,
                siblings,
            },
            server_nonce,
            transcript_tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(seed: u8) -> PsiQueryEntry {
        let mut anon = [0u8; ANON_ID_LEN];
        for (i, b) in anon.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        let mut blind = [0u8; POINT_LEN];
        for (i, b) in blind.iter_mut().enumerate() {
            *b = seed.wrapping_mul(i as u8 + 1);
        }
        PsiQueryEntry {
            anon_id: anon,
            blinded: blind,
        }
    }

    fn sample_request(n: usize) -> PsiRequest {
        PsiRequest {
            version: WIRE_VERSION,
            entries: (0..n).map(|i| sample_entry(i as u8)).collect(),
            client_nonce: [0xAA; SERVER_NONCE_LEN],
            witness_index: 2,
        }
    }

    #[test]
    fn psi_request_roundtrip_single() {
        let r = sample_request(1);
        let wire = r.encode();
        let r2 = PsiRequest::decode(&wire).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn psi_request_roundtrip_max_batch() {
        let r = sample_request(MAX_PSI_BATCH);
        let wire = r.encode();
        let r2 = PsiRequest::decode(&wire).unwrap();
        assert_eq!(r, r2);
        assert_eq!(r2.entries.len(), MAX_PSI_BATCH);
    }

    #[test]
    fn psi_request_rejects_zero_batch() {
        // Manually craft request with 0 entries.
        let mut wire = vec![WIRE_VERSION, 1, 0, 0];
        wire.extend_from_slice(&[0u8; SERVER_NONCE_LEN]);
        let err = PsiRequest::decode(&wire).unwrap_err();
        assert!(matches!(err, DiscoveryError::WireDecode { .. }));
    }

    #[test]
    fn psi_request_rejects_wrong_version() {
        let mut wire = sample_request(1).encode();
        wire[0] = 0xFF;
        let err = PsiRequest::decode(&wire).unwrap_err();
        assert!(matches!(err, DiscoveryError::WireDecode { .. }));
    }

    #[test]
    fn psi_request_rejects_truncated() {
        let wire = sample_request(2).encode();
        let err = PsiRequest::decode(&wire[..wire.len() - 1]).unwrap_err();
        assert!(matches!(err, DiscoveryError::WireDecode { .. }));
    }

    #[test]
    fn psi_response_roundtrip() {
        let resp = PsiResponse {
            version: WIRE_VERSION,
            entries: vec![PsiResponseEntry {
                anon_id: [1; ANON_ID_LEN],
                evaluation: [2; POINT_LEN],
            }],
            server_nonce: [3; SERVER_NONCE_LEN],
            transcript_tag: [4; TRANSCRIPT_TAG_LEN],
        };
        let wire = resp.encode();
        let resp2 = PsiResponse::decode(&wire).unwrap();
        assert_eq!(resp, resp2);
    }

    #[test]
    fn username_request_roundtrip() {
        let req = UsernameRequest {
            version: WIRE_VERSION,
            witness_index: 3,
            anon_id: [9; ANON_ID_LEN],
            blinded: [8; POINT_LEN],
            client_nonce: [7; SERVER_NONCE_LEN],
        };
        let wire = req.encode();
        let req2 = UsernameRequest::decode(&wire).unwrap();
        assert_eq!(req, req2);
    }

    #[test]
    fn username_response_roundtrip() {
        let resp = UsernameResponse {
            version: WIRE_VERSION,
            anon_id: [1; ANON_ID_LEN],
            evaluation: [2; POINT_LEN],
            encrypted_record: vec![0xFE; 64],
            kt_proof: KtInclusionProof {
                epoch_root: [3; NODE_HASH_LEN],
                tree_size: 100,
                leaf_index: 42,
                leaf_payload: vec![0xAB; 32],
                siblings: vec![[4u8; NODE_HASH_LEN], [5u8; NODE_HASH_LEN]],
            },
            server_nonce: [6; SERVER_NONCE_LEN],
            transcript_tag: [7; TRANSCRIPT_TAG_LEN],
        };
        let wire = resp.encode();
        let resp2 = UsernameResponse::decode(&wire).unwrap();
        assert_eq!(resp, resp2);
    }

    #[test]
    fn username_response_decode_rejects_truncated() {
        let resp = UsernameResponse {
            version: WIRE_VERSION,
            anon_id: [1; ANON_ID_LEN],
            evaluation: [2; POINT_LEN],
            encrypted_record: vec![0xAA; 32],
            kt_proof: KtInclusionProof {
                epoch_root: [3; NODE_HASH_LEN],
                tree_size: 10,
                leaf_index: 4,
                leaf_payload: vec![0xCD; 16],
                siblings: vec![[4u8; NODE_HASH_LEN]],
            },
            server_nonce: [6; SERVER_NONCE_LEN],
            transcript_tag: [7; TRANSCRIPT_TAG_LEN],
        };
        let wire = resp.encode();
        let err = UsernameResponse::decode(&wire[..wire.len() - 5]).unwrap_err();
        assert!(matches!(err, DiscoveryError::WireDecode { .. }));
    }

    #[test]
    fn username_response_rejects_oversized_record() {
        // Manually craft response with record len > MAX_USERNAME_RECORD_LEN.
        let mut wire = vec![WIRE_VERSION];
        wire.extend_from_slice(&[0u8; ANON_ID_LEN]);
        wire.extend_from_slice(&[0u8; POINT_LEN]);
        wire.extend_from_slice(&((MAX_USERNAME_RECORD_LEN + 1) as u16).to_be_bytes());
        wire.extend_from_slice(&vec![0u8; MAX_USERNAME_RECORD_LEN + 1]);
        // Rest of fields won't be parsed because record length check fails first.
        let err = UsernameResponse::decode(&wire).unwrap_err();
        assert!(matches!(err, DiscoveryError::WireDecode { .. }));
    }

    #[test]
    fn psi_request_rejects_too_many_entries() {
        // n = MAX_PSI_BATCH + 1.
        let n = MAX_PSI_BATCH + 1;
        let mut wire = vec![WIRE_VERSION, 1];
        wire.extend_from_slice(&(n as u16).to_be_bytes());
        wire.extend_from_slice(&vec![0u8; n * (ANON_ID_LEN + POINT_LEN)]);
        wire.extend_from_slice(&[0u8; SERVER_NONCE_LEN]);
        let err = PsiRequest::decode(&wire).unwrap_err();
        assert!(matches!(err, DiscoveryError::WireDecode { .. }));
    }
}
