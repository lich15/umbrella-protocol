//! KT-bind для discovery answer: проверяет Merkle inclusion proof в текущей
//! KT-эпохе, чтобы сервер не мог silently swap `(handle → device_pubkey)`.
//! Это D-3 mitigation.
//!
//! KT bind for discovery answer: verifies Merkle inclusion proof in the
//! current KT epoch so the server cannot silently swap `(handle →
//! device_pubkey)`. D-3 mitigation.
//!
//! ## Алгоритм
//!
//! 1. Сервер строит canonical leaf-payload (handle || device_pubkey || meta).
//! 2. Клиент знает ожидаемый `epoch_root` (из предыдущего KT observation либо
//!    из witness-signature 3-of-5 верификации; за это отвечает `umbrella-kt`).
//! 3. Discovery-ответ содержит `KtInclusionProof` с (leaf_payload, leaf_index,
//!    tree_size, siblings, claimed_epoch_root).
//! 4. Клиент:
//!    a. Проверяет, что `claimed_epoch_root == pinned_epoch_root` (D-3 forge
//!       блокируется без необходимости пересчитывать).
//!    b. Вычисляет `leaf_hash(leaf_payload)` через RFC 6962.
//!    c. Запускает `umbrella_kt::verify_inclusion(leaf_hash, leaf_index,
//!       tree_size, audit_path, &expected_root)`.
//!    d. Проверяет, что `device_pubkey` в leaf_payload совпадает с ожидаемым
//!       (то, что клиент собирается использовать для Sealed Sender V2).
//! 5. Любое расхождение → `DiscoveryError::KtBindFailed { kind }` (fail-stop).
//!
//! ## Algorithm
//!
//! 1. Server builds canonical leaf payload (handle || device_pubkey || meta).
//! 2. Client knows expected `epoch_root` (from prior KT observation or
//!    witness-signature 3-of-5 verification handled by `umbrella-kt`).
//! 3. Discovery response carries `KtInclusionProof` with (leaf_payload,
//!    leaf_index, tree_size, siblings, claimed_epoch_root).
//! 4. Client verifies all components; any mismatch → fail-stop.
//!
//! ## Note
//!
//! Эта реализация — клиентская сторона. Серверная (генерация proof) — в
//! `umbrella-kt::build_audit_path` + leaf composition в backend (см.
//! `docs/spec/discovery-backend-spec.md` Round 7).
//!
//! This is the client-side verifier. The server side (generating proof) lives
//! in `umbrella-kt::build_audit_path` + leaf composition in the backend (see
//! the round-7 backend-spec document).

use subtle::ConstantTimeEq;
use umbrella_kt::{leaf_hash, verify_inclusion, KtError, NODE_HASH_LEN};

use crate::error::{DiscoveryError, DiscoveryResult, KtBindKind};
use crate::wire::{KtInclusionProof, DEVICE_PUBKEY_LEN};

/// Domain separator для discovery leaf-payload.
/// Domain separator for discovery leaf payload.
pub const DISCOVERY_LEAF_DOMAIN: &[u8] = b"umbrella-r7/discovery/kt-leaf/v1";

/// Canonical leaf payload encoding:
/// ```text
/// DOMAIN || u8(handle_kind) || u16_be(handle_len) || handle ||
///   device_pubkey(32) || u64_be(epoch)
/// ```
///
/// `handle_kind = 0` для phone-number, `1` для @username. `epoch` — KT epoch
/// number в котором leaf published.
///
/// Canonical leaf payload encoding (see code).
pub fn canonical_leaf_payload(
    handle_kind: u8,
    handle: &[u8],
    device_pubkey: &[u8; DEVICE_PUBKEY_LEN],
    epoch: u64,
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(DISCOVERY_LEAF_DOMAIN.len() + 1 + 2 + handle.len() + DEVICE_PUBKEY_LEN + 8);
    out.extend_from_slice(DISCOVERY_LEAF_DOMAIN);
    out.push(handle_kind);
    out.extend_from_slice(&(handle.len() as u16).to_be_bytes());
    out.extend_from_slice(handle);
    out.extend_from_slice(device_pubkey);
    out.extend_from_slice(&epoch.to_be_bytes());
    out
}

/// Что клиент ожидает от discovery-bind.
///
/// `pinned_epoch_root` — root который клиент уже зафиксировал для эпохи
/// `epoch` (через KT observation либо witness signatures 3-of-5).
/// `expected_device_pubkey` — `None` если клиент готов принять любой
/// device_pubkey (первая discovery), иначе обязан совпасть.
///
/// What the client expects from a discovery bind: pinned epoch root for the
/// epoch plus optionally an expected device_pubkey.
#[derive(Debug, Clone, Copy)]
pub struct DiscoveryBindExpectation<'a> {
    /// Какая эпоха KT log используется.
    /// KT log epoch number.
    pub epoch: u64,
    /// Pinned root для этой эпохи (из предыдущего observation).
    /// Pinned root for the epoch (from prior observation).
    pub pinned_epoch_root: &'a [u8; NODE_HASH_LEN],
    /// Optional expected device_pubkey. `None` = первая discovery, любая ок.
    /// Optional expected device pubkey. `None` = first discovery.
    pub expected_device_pubkey: Option<&'a [u8; DEVICE_PUBKEY_LEN]>,
    /// Handle kind (0 = phone, 1 = username).
    /// Handle kind (0 = phone, 1 = username).
    pub handle_kind: u8,
    /// Handle bytes для проверки совпадения с leaf payload.
    /// Handle bytes to match against the leaf payload.
    pub handle: &'a [u8],
}

/// Проверить KT-bind discovery-ответа.
///
/// Возвращает `Ok(device_pubkey)` если все проверки прошли (extracted из
/// leaf_payload). Иначе — `DiscoveryError::KtBindFailed { kind }`.
///
/// # Errors
/// Все варианты [`KtBindKind`] — см. модуль `error`.
///
/// Verify a discovery answer's KT bind. Returns the device_pubkey extracted
/// from the leaf payload on success.
pub fn verify_discovery_bind(
    proof: &KtInclusionProof,
    expectation: &DiscoveryBindExpectation<'_>,
) -> DiscoveryResult<[u8; DEVICE_PUBKEY_LEN]> {
    // 1. Pinned root match (D-3 silent swap: forge с другим root отвергнут).
    if proof.epoch_root.ct_eq(expectation.pinned_epoch_root).unwrap_u8() == 0 {
        return Err(DiscoveryError::KtBindFailed {
            kind: KtBindKind::RootForked,
        });
    }

    // 2. Leaf payload parse + match для handle, epoch.
    let expected_payload = canonical_leaf_payload(
        expectation.handle_kind,
        expectation.handle,
        // Реально ожидаемый device_pubkey известен (или нет; см. ниже).
        // Если expectation.expected_device_pubkey Some — мы можем сразу
        // сравнить весь payload. Если None — мы парсим payload и достаём
        // device_pubkey из него (потому что это первая discovery).
        expectation
            .expected_device_pubkey
            .unwrap_or(&[0u8; DEVICE_PUBKEY_LEN]),
        expectation.epoch,
    );

    // Стуктурная проверка длины leaf_payload:
    let min_expected_len = DISCOVERY_LEAF_DOMAIN.len() + 1 + 2 + expectation.handle.len()
        + DEVICE_PUBKEY_LEN
        + 8;
    if proof.leaf_payload.len() != min_expected_len {
        return Err(DiscoveryError::KtBindFailed {
            kind: KtBindKind::LeafPayloadMismatch,
        });
    }

    // Извлекаем device_pubkey из leaf_payload:
    let pk_off = DISCOVERY_LEAF_DOMAIN.len() + 1 + 2 + expectation.handle.len();
    let mut extracted_pk = [0u8; DEVICE_PUBKEY_LEN];
    extracted_pk.copy_from_slice(&proof.leaf_payload[pk_off..pk_off + DEVICE_PUBKEY_LEN]);

    // Если expected_pubkey задан — должен совпасть (constant-time).
    if let Some(expected_pk) = expectation.expected_device_pubkey {
        if extracted_pk.ct_eq(expected_pk).unwrap_u8() == 0 {
            return Err(DiscoveryError::KtBindFailed {
                kind: KtBindKind::LeafPayloadMismatch,
            });
        }
    }

    // Validate the rest of the payload structure (domain, handle_kind, handle,
    // epoch) by reconstructing it with the *extracted* pk and comparing.
    let reconstructed = canonical_leaf_payload(
        expectation.handle_kind,
        expectation.handle,
        &extracted_pk,
        expectation.epoch,
    );
    if reconstructed != proof.leaf_payload {
        return Err(DiscoveryError::KtBindFailed {
            kind: KtBindKind::LeafPayloadMismatch,
        });
    }
    // Sanity check: expected_payload (с zero-pk если не задан pk) хотя бы
    // длиной совпал; иначе у нас баг кодирования.
    debug_assert_eq!(expected_payload.len(), proof.leaf_payload.len());

    // 3. Verify inclusion via RFC 6962 audit path.
    let leaf = leaf_hash(&proof.leaf_payload);
    let audit_path = proof.as_audit_path();
    match verify_inclusion(
        &leaf,
        proof.leaf_index,
        proof.tree_size,
        &audit_path,
        &proof.epoch_root,
    ) {
        Ok(()) => Ok(extracted_pk),
        Err(KtError::InclusionRootMismatch) => Err(DiscoveryError::KtBindFailed {
            kind: KtBindKind::ProofMismatch,
        }),
        Err(KtError::InvalidProofLength { .. })
        | Err(KtError::LeafIndexOutOfRange { .. })
        | Err(KtError::EmptyTree) => Err(DiscoveryError::KtBindFailed {
            kind: KtBindKind::ProofShapeInvalid,
        }),
        Err(_) => Err(DiscoveryError::KtBindFailed {
            kind: KtBindKind::ProofMismatch,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbrella_kt::{build_audit_path, merkle_root};

    fn make_proof_for(
        handle_kind: u8,
        handle: &[u8],
        pk: &[u8; DEVICE_PUBKEY_LEN],
        epoch: u64,
        leaf_index: usize,
        other_leaves: &[Vec<u8>],
    ) -> (KtInclusionProof, [u8; NODE_HASH_LEN]) {
        let target_payload = canonical_leaf_payload(handle_kind, handle, pk, epoch);
        let mut all_leaves_raw = other_leaves.to_vec();
        all_leaves_raw.insert(leaf_index, target_payload.clone());
        let leaves: Vec<[u8; NODE_HASH_LEN]> =
            all_leaves_raw.iter().map(|p| leaf_hash(p)).collect();
        let root = merkle_root(&leaves);
        let audit = build_audit_path(&leaves, leaf_index).unwrap();
        (
            KtInclusionProof {
                epoch_root: root,
                tree_size: leaves.len() as u64,
                leaf_index: leaf_index as u64,
                leaf_payload: target_payload,
                siblings: audit.siblings,
            },
            root,
        )
    }

    fn dummy_other_leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| canonical_leaf_payload(1, &[i as u8, 0xCC], &[i as u8; DEVICE_PUBKEY_LEN], 0))
            .collect()
    }

    #[test]
    fn valid_proof_accepted_and_pk_extracted() {
        let pk = [0xABu8; DEVICE_PUBKEY_LEN];
        let handle = b"alice";
        let others = dummy_other_leaves(7);
        let (proof, root) = make_proof_for(1, handle, &pk, 100, 3, &others);

        let exp = DiscoveryBindExpectation {
            epoch: 100,
            pinned_epoch_root: &root,
            expected_device_pubkey: None,
            handle_kind: 1,
            handle,
        };
        let out = verify_discovery_bind(&proof, &exp).unwrap();
        assert_eq!(out, pk);
    }

    #[test]
    fn pk_mismatch_rejected_when_expected_pinned() {
        let pk_a = [0xAA; DEVICE_PUBKEY_LEN];
        let pk_b = [0xBB; DEVICE_PUBKEY_LEN];
        let handle = b"alice";
        let others = dummy_other_leaves(7);
        let (proof, root) = make_proof_for(1, handle, &pk_a, 100, 2, &others);

        let exp = DiscoveryBindExpectation {
            epoch: 100,
            pinned_epoch_root: &root,
            expected_device_pubkey: Some(&pk_b),
            handle_kind: 1,
            handle,
        };
        let err = verify_discovery_bind(&proof, &exp).unwrap_err();
        assert!(matches!(
            err,
            DiscoveryError::KtBindFailed {
                kind: KtBindKind::LeafPayloadMismatch
            }
        ));
    }

    #[test]
    fn forged_root_rejected() {
        let pk = [0xAA; DEVICE_PUBKEY_LEN];
        let handle = b"bob";
        let others = dummy_other_leaves(3);
        let (proof, _real_root) = make_proof_for(1, handle, &pk, 5, 0, &others);

        let forged = [0xFFu8; NODE_HASH_LEN];
        let exp = DiscoveryBindExpectation {
            epoch: 5,
            pinned_epoch_root: &forged,
            expected_device_pubkey: None,
            handle_kind: 1,
            handle,
        };
        let err = verify_discovery_bind(&proof, &exp).unwrap_err();
        assert!(matches!(
            err,
            DiscoveryError::KtBindFailed {
                kind: KtBindKind::RootForked
            }
        ));
    }

    #[test]
    fn tampered_proof_mismatch_rejected() {
        let pk = [0xAA; DEVICE_PUBKEY_LEN];
        let handle = b"bob";
        let others = dummy_other_leaves(7);
        let (mut proof, root) = make_proof_for(1, handle, &pk, 5, 4, &others);

        // Tamper with leaf_payload: flip a single bit in device_pubkey.
        let pk_off = DISCOVERY_LEAF_DOMAIN.len() + 1 + 2 + handle.len();
        proof.leaf_payload[pk_off] ^= 0x01;

        let exp = DiscoveryBindExpectation {
            epoch: 5,
            pinned_epoch_root: &root,
            expected_device_pubkey: None,
            handle_kind: 1,
            handle,
        };
        let err = verify_discovery_bind(&proof, &exp).unwrap_err();
        // Tampered leaf_payload — leaf_hash изменится, audit path не сойдётся.
        assert!(matches!(
            err,
            DiscoveryError::KtBindFailed {
                kind: KtBindKind::ProofMismatch
            }
        ));
    }

    #[test]
    fn wrong_leaf_payload_length_rejected() {
        let pk = [0xAA; DEVICE_PUBKEY_LEN];
        let handle = b"bob";
        let others = dummy_other_leaves(3);
        let (mut proof, root) = make_proof_for(1, handle, &pk, 5, 0, &others);
        proof.leaf_payload.push(0xFF);
        let exp = DiscoveryBindExpectation {
            epoch: 5,
            pinned_epoch_root: &root,
            expected_device_pubkey: None,
            handle_kind: 1,
            handle,
        };
        let err = verify_discovery_bind(&proof, &exp).unwrap_err();
        assert!(matches!(
            err,
            DiscoveryError::KtBindFailed {
                kind: KtBindKind::LeafPayloadMismatch
            }
        ));
    }

    #[test]
    fn wrong_handle_in_payload_rejected() {
        let pk = [0xAA; DEVICE_PUBKEY_LEN];
        let handle = b"bob";
        let others = dummy_other_leaves(3);
        let (proof, root) = make_proof_for(1, handle, &pk, 5, 0, &others);
        let exp = DiscoveryBindExpectation {
            epoch: 5,
            pinned_epoch_root: &root,
            expected_device_pubkey: None,
            handle_kind: 1,
            handle: b"car",
        };
        let err = verify_discovery_bind(&proof, &exp).unwrap_err();
        // Length match но bytes mismatch → LeafPayloadMismatch.
        assert!(matches!(
            err,
            DiscoveryError::KtBindFailed {
                kind: KtBindKind::LeafPayloadMismatch
            }
        ));
    }

    #[test]
    fn invalid_proof_shape_rejected() {
        let pk = [0xAA; DEVICE_PUBKEY_LEN];
        let handle = b"bob";
        let others = dummy_other_leaves(7);
        let (mut proof, root) = make_proof_for(1, handle, &pk, 5, 0, &others);
        proof.siblings.clear();
        let exp = DiscoveryBindExpectation {
            epoch: 5,
            pinned_epoch_root: &root,
            expected_device_pubkey: None,
            handle_kind: 1,
            handle,
        };
        let err = verify_discovery_bind(&proof, &exp).unwrap_err();
        assert!(matches!(
            err,
            DiscoveryError::KtBindFailed {
                kind: KtBindKind::ProofShapeInvalid
            }
        ));
    }
}
