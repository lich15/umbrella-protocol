//! D-3 regression: malicious server returns a fake `device_pubkey` for a
//! queried handle; client's KT-bind verifier MUST reject it.
//!
//! D-3 атака: вредоносный сервер возвращает fake `device_pubkey` для
//! запрашиваемого handle; KT-bind клиента ДОЛЖЕН его отвергнуть.
//!
//! ## Attack model
//!
//! Server controls 3 of 5 (threshold reached). Goal: client queries
//! `@alice`; server returns Mallory's `device_pubkey` instead of Alice's.
//! Without KT-bind, client believes Mallory's pubkey is Alice's. С KT-bind,
//! server must include inclusion proof for (alice, mallory_pk, epoch) →
//! that leaf doesn't exist in the real KT log; reconstruction fails.
//!
//! ## Defense
//!
//! `verify_discovery_bind` recomputes `leaf_hash(handle, claimed_pk, epoch)`
//! и проверяет, что это leaf reconstructs to `pinned_root` via audit path.
//! Forged claimed_pk → leaf_hash differs → reconstructed root ≠ pinned_root
//! → `KtBindFailed { kind: ProofMismatch }`.

use rand_core::OsRng;
use umbrella_discovery::{
    canonical_leaf_payload, verify_discovery_bind, DiscoveryBindExpectation, DiscoveryError,
    KtBindKind, KtInclusionProof, DEVICE_PUBKEY_LEN, NODE_HASH_LEN,
};
use umbrella_kt::{build_audit_path, leaf_hash, merkle_root};

fn make_real_kt(handle: &[u8], real_pk: &[u8; DEVICE_PUBKEY_LEN], epoch: u64) -> KtInclusionProof {
    let payload = canonical_leaf_payload(1, handle, real_pk, epoch);
    // Несколько других leaves для realism.
    let others = (0..7)
        .map(|i| canonical_leaf_payload(1, &[i as u8, 0xFF], &[i as u8; DEVICE_PUBKEY_LEN], epoch))
        .collect::<Vec<_>>();
    let mut leaves = others.clone();
    leaves.insert(3, payload.clone());
    let leaf_hashes: Vec<[u8; NODE_HASH_LEN]> = leaves.iter().map(|p| leaf_hash(p)).collect();
    let root = merkle_root(&leaf_hashes);
    let audit = build_audit_path(&leaf_hashes, 3).unwrap();
    KtInclusionProof {
        epoch_root: root,
        tree_size: leaves.len() as u64,
        leaf_index: 3,
        leaf_payload: payload,
        siblings: audit.siblings,
    }
}

#[test]
fn d3_attack_forged_pubkey_rejected_by_kt_bind() {
    // Сервер хочет вернуть Mallory's PK вместо Alice's.
    let handle = b"@alice";
    let alice_pk = [0xAAu8; DEVICE_PUBKEY_LEN];
    let mallory_pk = [0xBAu8; DEVICE_PUBKEY_LEN];
    let epoch = 42;

    // Реальный KT log содержит (alice, alice_pk, epoch).
    let real_proof = make_real_kt(handle, &alice_pk, epoch);
    let real_root = real_proof.epoch_root;

    // Атакующий пытается отдать клиенту "alice → mallory_pk" с подменённым
    // leaf_payload — но root становится другой.
    let mut forged_proof = real_proof.clone();
    let pk_off = umbrella_discovery::DISCOVERY_LEAF_DOMAIN.len() + 1 + 2 + handle.len();
    forged_proof.leaf_payload[pk_off..pk_off + DEVICE_PUBKEY_LEN].copy_from_slice(&mallory_pk);
    // Sigling он оставляет — но это уже sufficient: leaf_hash changes.

    // Клиент проверяет:
    let exp = DiscoveryBindExpectation {
        epoch,
        pinned_epoch_root: &real_root,
        expected_device_pubkey: None,
        handle_kind: 1,
        handle,
    };
    let err = verify_discovery_bind(&forged_proof, &exp).unwrap_err();
    // Восстановленный root от подменённого leaf не совпадает с real root.
    assert!(
        matches!(
            err,
            DiscoveryError::KtBindFailed {
                kind: KtBindKind::ProofMismatch
            }
        ),
        "expected KtBindFailed::ProofMismatch, got {err:?}"
    );
    let _ = OsRng;
}

#[test]
fn d3_attack_forged_epoch_root_rejected() {
    // Атакующий полностью fakes root.
    let handle = b"@bob";
    let real_pk = [0xCCu8; DEVICE_PUBKEY_LEN];
    let real_proof = make_real_kt(handle, &real_pk, 1);

    let forged_root = [0xFFu8; NODE_HASH_LEN];
    let exp = DiscoveryBindExpectation {
        epoch: 1,
        pinned_epoch_root: &forged_root,
        expected_device_pubkey: None,
        handle_kind: 1,
        handle,
    };
    let err = verify_discovery_bind(&real_proof, &exp).unwrap_err();
    assert!(matches!(
        err,
        DiscoveryError::KtBindFailed {
            kind: KtBindKind::RootForked
        }
    ));
}

#[test]
fn d3_attack_pinned_pubkey_swap_blocked() {
    // Атака на second contact: клиент expects конкретный pubkey, но
    // сервер возвращает другой. Even если proof valid для нового, expected
    // mismatch блокирует.
    let handle = b"@charlie";
    let pk_real = [0x11u8; DEVICE_PUBKEY_LEN];
    let pk_expected = [0x22u8; DEVICE_PUBKEY_LEN]; // client knows pk_expected
    let proof = make_real_kt(handle, &pk_real, 5);

    let exp = DiscoveryBindExpectation {
        epoch: 5,
        pinned_epoch_root: &proof.epoch_root,
        expected_device_pubkey: Some(&pk_expected),
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
fn d3_attack_valid_proof_accepted_baseline() {
    // Negative-positive control: legitimate proof passes.
    let handle = b"@dave";
    let pk = [0x33u8; DEVICE_PUBKEY_LEN];
    let proof = make_real_kt(handle, &pk, 7);
    let exp = DiscoveryBindExpectation {
        epoch: 7,
        pinned_epoch_root: &proof.epoch_root,
        expected_device_pubkey: Some(&pk),
        handle_kind: 1,
        handle,
    };
    let returned = verify_discovery_bind(&proof, &exp).unwrap();
    assert_eq!(returned, pk);
}
