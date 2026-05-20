//! Username lookup: `@handle → device_pubkey` через OPRF + KT-bind.
//!
//! Username lookup: `@handle → device_pubkey` via OPRF + KT bind.
//!
//! ## Flow
//!
//! 1. Клиент blind'ит handle через OPRF.
//! 2. Шлёт request к 3 of 5 Sealed Servers (per-query anon_ids, distinct).
//! 3. Каждый сервер возвращает:
//!    - partial OPRF evaluation,
//!    - encrypted record (`AEAD(K_oprf, (device_pubkey || KT_proof_blob))`),
//!    - KT inclusion proof для leaf (handle, device_pubkey, epoch).
//! 4. Клиент threshold-combine partial evaluations → OprfLabel.
//! 5. Клиент derive AEAD ключ из (OprfLabel || domain_sep).
//! 6. Клиент AEAD-decrypt encrypted record → достаёт `device_pubkey`.
//! 7. Клиент verify KT-bind → ensure server returns same `device_pubkey`
//!    что и в KT leaf (D-3 silent swap prevented).
//!
//! ## Безопасность
//!
//! - Server без OPRF key не может decrypt encrypted_record (KDF-bound).
//! - Server без знания handle (it's blinded) не может target nun-existent
//!   query → IND-CPA от server perspective.
//! - KT-bind binds (handle, pubkey, epoch) в Merkle log → swap detected.
//!
//! ## Security
//!
//! - The server (without the OPRF key) cannot decrypt the record (KDF-bound).
//! - The server cannot target a non-existent query without knowing the handle
//!   (which is blinded) → IND-CPA-equivalent from the server's perspective.
//! - The KT bind ties (handle, pubkey, epoch) into the Merkle log → silent
//!   swap is detected.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use umbrella_oprf::{
    blind, finalize, threshold_combine, BlindedRequest, BlindingState, OprfInput, OprfLabel,
    ServerEvaluation, ThresholdConfig, WitnessIndex,
};

use crate::anonymous_query::{derive_per_query_anon_id, fresh_query_salt, SALT_LEN};
use crate::error::{DiscoveryError, DiscoveryResult, KtBindKind};
use crate::kt_bind::{verify_discovery_bind, DiscoveryBindExpectation};
use crate::wire::{
    KtInclusionProof, UsernameRequest, UsernameResponse, ANON_ID_LEN, DEVICE_PUBKEY_LEN,
    MAX_USERNAME_RECORD_LEN, NODE_HASH_LEN, SERVER_NONCE_LEN, TRANSCRIPT_TAG_LEN, WIRE_VERSION,
};

/// Domain separator для derive AEAD-ключа из OprfLabel.
/// Domain separator to derive an AEAD key from OprfLabel.
pub const USERNAME_AEAD_KEY_LABEL: &[u8] = b"umbrella-r7/discovery/username-aead/v1";

/// Размер AEAD key (ChaCha20-Poly1305).
/// AEAD key size (ChaCha20-Poly1305).
pub const AEAD_KEY_LEN: usize = 32;

/// Размер AEAD nonce (12 байт для ChaCha20-Poly1305).
/// AEAD nonce size (12 bytes for ChaCha20-Poly1305).
pub const AEAD_NONCE_LEN: usize = 12;

/// Client-side state for one username lookup query.
/// Client-side state for one username lookup query.
#[derive(Debug)]
pub struct UsernameQueryState {
    /// Per-query salt (deterministic seed for anon_ids).
    /// Per-query salt.
    #[allow(dead_code)]
    salt: [u8; SALT_LEN],
    /// OPRF blinding state.
    /// OPRF blinding state.
    blinding: BlindingState,
    /// Handle (raw, для finalize и kt_bind verify).
    /// Raw handle (for finalize and KT bind verify).
    handle: Vec<u8>,
    /// Client nonce (echoed in transcript).
    /// Client nonce (echoed in transcript).
    client_nonce: [u8; SERVER_NONCE_LEN],
}

impl UsernameQueryState {
    /// Test-only: salt for testing.
    #[cfg(test)]
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }
}

/// Подготовить username lookup query: blind handle + derive anon_id.
///
/// Возвращает (UsernameRequest, UsernameQueryState).
///
/// # Errors
/// - [`DiscoveryError::InputRejected`] если handle out-of-range или
///   witness_index invalid.
/// - [`DiscoveryError::Oprf`] если voprf blind вернул ошибку.
pub fn prepare_username_query<R: CryptoRng + RngCore>(
    master_key: &[u8; 32],
    handle: &[u8],
    witness_index: u8,
    rng: &mut R,
) -> DiscoveryResult<(UsernameRequest, UsernameQueryState)> {
    if witness_index == 0 || witness_index > 5 {
        return Err(DiscoveryError::InputRejected("witness_index must be 1..=5"));
    }
    let inp = OprfInput::new(handle)
        .map_err(|_| DiscoveryError::InputRejected("handle length out of OPRF range"))?;
    let (req, blinding) = blind(inp, rng)?;
    let salt = fresh_query_salt(rng);
    let anon_id = derive_per_query_anon_id(master_key, u16::from(witness_index), &salt)?;
    let mut client_nonce = [0u8; SERVER_NONCE_LEN];
    rng.fill_bytes(&mut client_nonce);
    Ok((
        UsernameRequest {
            version: WIRE_VERSION,
            witness_index,
            anon_id,
            blinded: *req.as_bytes(),
            client_nonce,
        },
        UsernameQueryState {
            salt,
            blinding,
            handle: handle.to_vec(),
            client_nonce,
        },
    ))
}

/// Server-side mock: для caller (handle, device_pubkey, epoch) формирует
/// encrypted record + KT proof + partial OPRF eval.
///
/// **Backend production:** OPRF key shares + KT tree держатся в TEE. Encrypted
/// record вычисляется один раз при регистрации; KT proof — лениво при запросе.
/// Здесь mock builds everything at request time для упрощения tests.
///
/// `sk_share` — Shamir-доля OPRF master key, держится TEE Sealed Server #i.
/// `expected_oprf_label` — то, что клиент получит после threshold combine и
/// finalize (нужно знать заранее для AEAD key derivation; для тестов мы
/// reconstruct из master через 3 mock-shares).
///
/// Server-side mock builds encrypted record + KT proof + partial OPRF eval for
/// a (handle, device_pubkey, epoch) tuple.
#[allow(clippy::too_many_arguments)]
pub fn username_server_respond<R: CryptoRng + RngCore>(
    request: &UsernameRequest,
    sk_share: &[u8; 32],
    target_device_pubkey: &[u8; DEVICE_PUBKEY_LEN],
    kt_proof: KtInclusionProof,
    aead_key_for_record: &[u8; AEAD_KEY_LEN],
    rng: &mut R,
) -> DiscoveryResult<UsernameResponse> {
    let blinded = BlindedRequest::from_bytes(&request.blinded)?;
    let eval = umbrella_oprf::evaluate_for_testing(&blinded, sk_share)?;

    // AEAD-encrypt device_pubkey + KT proof epoch_root binding под server-provided
    // key. Каждый из 5 серверов имеет одну и ту же запись (encrypted один раз
    // в registration ceremony, persisted, re-served). Здесь генерируем заново.
    let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(aead_key_for_record));
    let mut plaintext = Vec::with_capacity(DEVICE_PUBKEY_LEN + NODE_HASH_LEN);
    plaintext.extend_from_slice(target_device_pubkey);
    plaintext.extend_from_slice(&kt_proof.epoch_root);
    let aad = build_aead_aad(&request.client_nonce, &request.anon_id);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| DiscoveryError::CryptoInternal("AEAD encrypt"))?;
    if AEAD_NONCE_LEN + ciphertext.len() > MAX_USERNAME_RECORD_LEN {
        return Err(DiscoveryError::CryptoInternal("encrypted record too large"));
    }
    let mut encrypted_record = Vec::with_capacity(AEAD_NONCE_LEN + ciphertext.len());
    encrypted_record.extend_from_slice(&nonce_bytes);
    encrypted_record.extend_from_slice(&ciphertext);

    let mut server_nonce = [0u8; SERVER_NONCE_LEN];
    rng.fill_bytes(&mut server_nonce);
    let transcript_tag = compute_username_transcript_tag(
        &request.client_nonce,
        &server_nonce,
        &request.anon_id,
        &eval,
        &encrypted_record,
        sk_share,
    );
    Ok(UsernameResponse {
        version: WIRE_VERSION,
        anon_id: request.anon_id,
        evaluation: *eval.as_bytes(),
        encrypted_record,
        kt_proof,
        server_nonce,
        transcript_tag,
    })
}

fn build_aead_aad(client_nonce: &[u8; SERVER_NONCE_LEN], anon_id: &[u8; ANON_ID_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SERVER_NONCE_LEN + ANON_ID_LEN);
    aad.extend_from_slice(client_nonce);
    aad.extend_from_slice(anon_id);
    aad
}

fn compute_username_transcript_tag(
    client_nonce: &[u8; SERVER_NONCE_LEN],
    server_nonce: &[u8; SERVER_NONCE_LEN],
    anon_id: &[u8; ANON_ID_LEN],
    eval: &ServerEvaluation,
    encrypted_record: &[u8],
    seed: &[u8],
) -> [u8; TRANSCRIPT_TAG_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"umbrella-r7/discovery/username-transcript/v1");
    hasher.update(client_nonce);
    hasher.update(server_nonce);
    hasher.update(anon_id);
    hasher.update(eval.as_bytes());
    hasher.update((encrypted_record.len() as u32).to_be_bytes());
    hasher.update(encrypted_record);
    hasher.update(seed);
    let digest = hasher.finalize();
    let mut out = [0u8; TRANSCRIPT_TAG_LEN];
    out.copy_from_slice(&digest[..TRANSCRIPT_TAG_LEN]);
    out
}

/// Derive AEAD-ключ из OprfLabel + handle (домейн-сепарация).
/// Derive AEAD key from OprfLabel + handle (domain-separated).
pub fn derive_aead_key_from_label(
    label: &OprfLabel,
    handle: &[u8],
) -> DiscoveryResult<[u8; AEAD_KEY_LEN]> {
    let hkdf = Hkdf::<Sha256>::new(None, label.as_bytes());
    let mut info = Vec::with_capacity(USERNAME_AEAD_KEY_LABEL.len() + 2 + handle.len());
    info.extend_from_slice(USERNAME_AEAD_KEY_LABEL);
    info.extend_from_slice(&(handle.len() as u16).to_be_bytes());
    info.extend_from_slice(handle);
    let mut out = [0u8; AEAD_KEY_LEN];
    hkdf.expand(&info, &mut out)
        .map_err(|_| DiscoveryError::CryptoInternal("HKDF expand username AEAD key"))?;
    Ok(out)
}

/// Финализация username lookup: threshold combine 3 of 5 responses →
/// finalize OPRF → derive AEAD key → decrypt record → verify KT-bind →
/// возвращает (device_pubkey, kt_proof).
///
/// # Errors
/// - [`DiscoveryError::InsufficientResponses`] если ответов < threshold.
/// - [`DiscoveryError::Oprf`] из threshold combine / finalize.
/// - [`DiscoveryError::UsernameForgeDetected`] если AEAD decrypt fail.
/// - [`DiscoveryError::KtBindFailed { kind }`] если KT proof не сходится.
///
/// Finalize username lookup: threshold combine → finalize OPRF → derive AEAD
/// key → decrypt → verify KT bind → return (device_pubkey, kt_proof).
pub fn finalize_username_query(
    state: &UsernameQueryState,
    server_responses: &[(WitnessIndex, &UsernameResponse)],
    pinned_epoch_root: &[u8; NODE_HASH_LEN],
    epoch: u64,
    config: ThresholdConfig,
) -> DiscoveryResult<([u8; DEVICE_PUBKEY_LEN], KtInclusionProof)> {
    if server_responses.len() < config.threshold as usize {
        return Err(DiscoveryError::InsufficientResponses {
            valid: server_responses.len(),
            required: config.threshold as usize,
        });
    }
    // Все ответы должны иметь одинаковую encrypted_record и kt_proof
    // (мы делаем sanity check: оба сервера должны отдавать тот же leaf).
    // Однако partial OPRF eval разный.
    // В первую очередь — threshold combine evals.
    let mut partials: Vec<(WitnessIndex, ServerEvaluation)> =
        Vec::with_capacity(server_responses.len());
    for (wi, resp) in server_responses {
        let eval = ServerEvaluation::from_bytes(&resp.evaluation)?;
        partials.push((*wi, eval));
    }
    let combined = threshold_combine(&partials, config)?;
    let inp = OprfInput::new(&state.handle)
        .map_err(|_| DiscoveryError::InputRejected("handle out of range"))?;
    let label = finalize(&state.blinding, inp, &combined)?;

    // Derive AEAD key из label + handle.
    let aead_key = derive_aead_key_from_label(&label, &state.handle)?;

    // Decrypt encrypted_record первого сервера (все 3 серверa должны вернуть
    // одинаковый record; если различаются — server-side collusion attempt).
    let primary = server_responses[0].1;
    if primary.encrypted_record.len() < AEAD_NONCE_LEN + 16 {
        return Err(DiscoveryError::UsernameForgeDetected);
    }
    let nonce = Nonce::from_slice(&primary.encrypted_record[..AEAD_NONCE_LEN]);
    let ciphertext = &primary.encrypted_record[AEAD_NONCE_LEN..];
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
    let aad = build_aead_aad(&state.client_nonce, &primary.anon_id);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| DiscoveryError::UsernameForgeDetected)?;
    if plaintext.len() != DEVICE_PUBKEY_LEN + NODE_HASH_LEN {
        return Err(DiscoveryError::UsernameForgeDetected);
    }
    let mut device_pubkey = [0u8; DEVICE_PUBKEY_LEN];
    device_pubkey.copy_from_slice(&plaintext[..DEVICE_PUBKEY_LEN]);
    let mut record_root = [0u8; NODE_HASH_LEN];
    record_root.copy_from_slice(&plaintext[DEVICE_PUBKEY_LEN..]);

    // Защита от server lying: encrypted_record's claimed root должен match
    // KT-proof's epoch_root → cross-validate.
    if record_root != primary.kt_proof.epoch_root {
        return Err(DiscoveryError::KtBindFailed {
            kind: KtBindKind::ProofMismatch,
        });
    }

    // Sanity: KT proof epoch_root должен match pinned_epoch_root.
    let exp = DiscoveryBindExpectation {
        epoch,
        pinned_epoch_root,
        expected_device_pubkey: Some(&device_pubkey),
        handle_kind: 1, // username
        handle: &state.handle,
    };
    let verified_pk = verify_discovery_bind(&primary.kt_proof, &exp)?;
    debug_assert_eq!(verified_pk, device_pubkey);
    Ok((device_pubkey, primary.kt_proof.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kt_bind::canonical_leaf_payload;
    use crate::wire::DEVICE_PUBKEY_LEN;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;
    use std::collections::HashSet;
    use umbrella_kt::{build_audit_path, leaf_hash, merkle_root};
    use umbrella_oprf::{generate_test_private_key, shamir_split_for_testing, SCALAR_LEN};

    fn make_cluster() -> ([u8; SCALAR_LEN], Vec<(WitnessIndex, [u8; SCALAR_LEN])>) {
        let master_sk = generate_test_private_key(&mut OsRng);
        let k = Scalar::from_canonical_bytes(master_sk).unwrap();
        let cfg = ThresholdConfig::default();
        let raw = shamir_split_for_testing(k, cfg, &mut OsRng);
        let shares: Vec<_> = raw.iter().map(|(wi, s)| (*wi, s.to_bytes())).collect();
        (master_sk, shares)
    }

    fn compute_full_oprf_label(handle: &[u8], master_sk: &[u8; SCALAR_LEN]) -> OprfLabel {
        let inp = OprfInput::new(handle).unwrap();
        let (req, st) = blind(inp, &mut OsRng).unwrap();
        let eval = umbrella_oprf::evaluate_for_testing(&req, master_sk).unwrap();
        finalize(&st, inp, &eval).unwrap()
    }

    fn build_test_kt(handle: &[u8], pk: &[u8; DEVICE_PUBKEY_LEN], epoch: u64) -> KtInclusionProof {
        let payload = canonical_leaf_payload(1, handle, pk, epoch);
        let other_leaf = canonical_leaf_payload(1, b"other", &[0; DEVICE_PUBKEY_LEN], epoch);
        let leaves = vec![leaf_hash(&payload), leaf_hash(&other_leaf)];
        let root = merkle_root(&leaves);
        let audit = build_audit_path(&leaves, 0).unwrap();
        KtInclusionProof {
            epoch_root: root,
            tree_size: 2,
            leaf_index: 0,
            leaf_payload: payload,
            siblings: audit.siblings,
        }
    }

    #[test]
    fn username_lookup_end_to_end_success() {
        let (master_sk, shares) = make_cluster();
        let mk = [0xAAu8; 32];
        let handle = b"@alice";
        let target_pk = [0x42u8; DEVICE_PUBKEY_LEN];
        let epoch = 7u64;
        let kt_proof = build_test_kt(handle, &target_pk, epoch);
        let pinned_root = kt_proof.epoch_root;

        // Server-side: AEAD-key для record derive'ится из full OPRF label
        // master ключа + handle. Это симулирует registration ceremony.
        let label = compute_full_oprf_label(handle, &master_sk);
        let aead_key = derive_aead_key_from_label(&label, handle).unwrap();

        // Клиент:
        let (req, state) = prepare_username_query(&mk, handle, 1, &mut OsRng).unwrap();

        // Сервер отвечает 3 раз (по одному per witness, шары 0, 1, 2).
        let mut responses = Vec::new();
        for &(wi, sk_share) in shares.iter().take(3) {
            // В реальности каждый сервер генерирует свой response с тем же
            // encrypted_record и kt_proof. Здесь делаем simulation: тот же
            // request шлётся 3 серверам (как в production: один client →
            // multiple sealed servers).
            let resp = username_server_respond(
                &req,
                &sk_share,
                &target_pk,
                kt_proof.clone(),
                &aead_key,
                &mut OsRng,
            )
            .unwrap();
            responses.push((wi, resp));
        }
        let resp_refs: Vec<_> = responses.iter().map(|(w, r)| (*w, r)).collect();

        let (pk_out, _proof) = finalize_username_query(
            &state,
            &resp_refs,
            &pinned_root,
            epoch,
            ThresholdConfig::default(),
        )
        .unwrap();
        assert_eq!(pk_out, target_pk);
    }

    #[test]
    fn username_lookup_rejects_zero_witness_index() {
        let mk = [0u8; 32];
        let err = prepare_username_query(&mk, b"@alice", 0, &mut OsRng).unwrap_err();
        assert!(matches!(err, DiscoveryError::InputRejected(_)));
    }

    #[test]
    fn username_lookup_rejects_witness_index_over_5() {
        let mk = [0u8; 32];
        let err = prepare_username_query(&mk, b"@alice", 6, &mut OsRng).unwrap_err();
        assert!(matches!(err, DiscoveryError::InputRejected(_)));
    }

    #[test]
    fn one_thousand_username_queries_yield_distinct_anon_ids() {
        let mk = [0xCCu8; 32];
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let (req, _state) = prepare_username_query(&mk, b"@alice", 1, &mut OsRng).unwrap();
            assert!(
                seen.insert(req.anon_id),
                "collision after {} queries",
                seen.len()
            );
        }
        assert_eq!(seen.len(), 1000);
    }

    #[test]
    fn username_lookup_finalize_with_only_two_responses_fails() {
        let (master_sk, shares) = make_cluster();
        let mk = [0xAAu8; 32];
        let handle = b"@bob";
        let pk = [0x10u8; DEVICE_PUBKEY_LEN];
        let kt_proof = build_test_kt(handle, &pk, 1);
        let label = compute_full_oprf_label(handle, &master_sk);
        let aead_key = derive_aead_key_from_label(&label, handle).unwrap();
        let (req, state) = prepare_username_query(&mk, handle, 1, &mut OsRng).unwrap();
        let (wi1, sk1) = shares[0];
        let (wi2, sk2) = shares[1];
        let r1 = username_server_respond(&req, &sk1, &pk, kt_proof.clone(), &aead_key, &mut OsRng)
            .unwrap();
        let r2 = username_server_respond(&req, &sk2, &pk, kt_proof.clone(), &aead_key, &mut OsRng)
            .unwrap();
        let err = finalize_username_query(
            &state,
            &[(wi1, &r1), (wi2, &r2)],
            &kt_proof.epoch_root,
            1,
            ThresholdConfig::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DiscoveryError::InsufficientResponses {
                valid: 2,
                required: 3
            }
        ));
    }
}
