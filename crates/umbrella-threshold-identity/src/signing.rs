//! # Threshold signing — FROST-Ed25519 sign protocol
//!
//! Реализует 2-round threshold sign: round-1 commitments, round-2 share + agg.
//! Совместимо с Ed25519 verification (single signature output, любой клиент
//! проверяет через `VerifyingKey::verify`).
//!
//! 2-round threshold sign: round-1 commitments, round-2 signature shares +
//! aggregation. Output is Ed25519-compatible (any client verifies via
//! `VerifyingKey::verify`).

use std::collections::BTreeMap;

use frost_ed25519::{
    keys::{KeyPackage, PublicKeyPackage},
    round1::{self, SigningCommitments, SigningNonces},
    round2::{self, SignatureShare},
    Identifier, Signature, SigningPackage,
};
use rand_core::{CryptoRng, RngCore};

use crate::error::{ThresholdIdentityError, ThresholdIdentityResult};

/// Output одного сервера-участника на round-1 signing: nonces (локально) +
/// commitments (broadcast).
///
/// One server participant's round-1 signing output.
pub struct Round1SigningOutput {
    /// Local secret nonces — **никогда** не покидает сервер.
    pub nonces: SigningNonces,
    /// Broadcast commitments — рассылается всем участникам через coordinator.
    pub commitments: SigningCommitments,
}

/// Производит round-1 signing commitments для одного участника.
///
/// Produces round-1 signing commitments for one participant.
pub fn sign_round1<R: CryptoRng + RngCore>(
    key_package: &KeyPackage,
    rng: &mut R,
) -> Round1SigningOutput {
    let (nonces, commitments) = round1::commit(key_package.signing_share(), rng);
    Round1SigningOutput {
        nonces,
        commitments,
    }
}

/// Производит round-2 signature share одного участника.
///
/// `signing_package` собирается coordinator-ом из всех round-1 commitments
/// (+message) и рассылается всем подписантам.
///
/// Produces a round-2 signature share for one participant. `signing_package`
/// is assembled by a coordinator from all round-1 commitments (+message) and
/// distributed to every signer.
pub fn sign_round2(
    key_package: &KeyPackage,
    nonces: &SigningNonces,
    signing_package: &SigningPackage,
) -> ThresholdIdentityResult<SignatureShare> {
    let share = round2::sign(signing_package, nonces, key_package)?;
    Ok(share)
}

/// Coordinator: собирает round-1 commitments + message → `SigningPackage`.
///
/// Coordinator: assembles round-1 commitments + message → `SigningPackage`.
pub fn assemble_signing_package(
    commitments: BTreeMap<Identifier, SigningCommitments>,
    message: &[u8],
) -> SigningPackage {
    SigningPackage::new(commitments, message)
}

/// Coordinator: aggregates все `SignatureShare`s в финальную Ed25519-
/// compatible подпись. Возвращает ошибку если хотя бы одна share не валидна
/// (cheater detection).
///
/// Coordinator: aggregates all signature shares into a final Ed25519-
/// compatible signature. Returns an error if any share is invalid (cheater
/// detection per Komlo-Goldberg 2020 §5).
pub fn aggregate(
    signing_package: &SigningPackage,
    signature_shares: &BTreeMap<Identifier, SignatureShare>,
    public_key_package: &PublicKeyPackage,
) -> ThresholdIdentityResult<Signature> {
    frost_ed25519::aggregate(signing_package, signature_shares, public_key_package)
        .map_err(Into::into)
}

/// Полностью симулирует threshold sign end-to-end: участники с индексами в
/// `signer_indices` подписывают `message` под общим `public_key_package`,
/// каждый используя свой `KeyPackage` из `all_key_packages`.
///
/// Threshold sign simulation: participants in `signer_indices` sign `message`
/// using their `KeyPackage` from `all_key_packages`. Returns the aggregated
/// Ed25519-compatible signature.
///
/// **Internal use only** — production deployment runs each participant on a
/// separate server with serialised messages.
pub fn run_in_process_sign<R: CryptoRng + RngCore>(
    all_key_packages: &[KeyPackage],
    public_key_package: &PublicKeyPackage,
    signer_indices: &[usize],
    message: &[u8],
    rng: &mut R,
) -> ThresholdIdentityResult<Signature> {
    if signer_indices.is_empty() {
        return Err(ThresholdIdentityError::SignFailed(
            "no signers specified",
        ));
    }
    // Round 1: each signer commits.
    let mut all_commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
    let mut all_nonces: BTreeMap<Identifier, SigningNonces> = BTreeMap::new();
    let mut signer_key_packages: BTreeMap<Identifier, KeyPackage> = BTreeMap::new();

    for &idx in signer_indices {
        let kp = all_key_packages.get(idx).ok_or(
            ThresholdIdentityError::SignFailed("signer index out of range"),
        )?;
        let ident = *kp.identifier();
        let out = sign_round1(kp, rng);
        all_commitments.insert(ident, out.commitments);
        all_nonces.insert(ident, out.nonces);
        signer_key_packages.insert(ident, kp.clone());
    }

    // Coordinator assembles SigningPackage.
    let signing_package = assemble_signing_package(all_commitments, message);

    // Round 2: each signer produces share.
    let mut shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
    for (ident, kp) in &signer_key_packages {
        let nonces = all_nonces
            .get(ident)
            .ok_or(ThresholdIdentityError::SignFailed("missing nonces"))?;
        let share = sign_round2(kp, nonces, &signing_package)?;
        shares.insert(*ident, share);
    }

    aggregate(&signing_package, &shares, public_key_package)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::run_in_process_dkg;
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn threshold_3_of_5_signs_and_verifies_against_ed25519() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xC0DECAFE_u64);
        let (key_packages, pubkey_package) = run_in_process_dkg(5, 3, &mut rng).unwrap();

        let message = b"R6 acceptance: threshold sign produces valid Ed25519 sig";

        // Sign with subset {0, 1, 2} (3 of 5).
        let signature =
            run_in_process_sign(&key_packages, &pubkey_package, &[0, 1, 2], message, &mut rng)
                .expect("3-of-5 should sign");

        // Verify via FROST's own VerifyingKey path.
        pubkey_package
            .verifying_key()
            .verify(message, &signature)
            .expect("FROST verify");

        // Verify via dalek Ed25519 (cross-check that output is a valid Ed25519 sig).
        let pk_bytes = pubkey_package
            .verifying_key()
            .serialize()
            .expect("pk bytes");
        let sig_bytes = signature.serialize().expect("sig bytes");
        assert_eq!(pk_bytes.len(), 32);
        assert_eq!(sig_bytes.len(), 64);
        let dalek_pk =
            ed25519_dalek::VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap())
                .expect("dalek pk parse");
        let dalek_sig =
            ed25519_dalek::Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
        dalek_pk
            .verify_strict(message, &dalek_sig)
            .expect("dalek strict verify");
    }

    #[test]
    fn threshold_below_min_signers_fails() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let (key_packages, pubkey_package) = run_in_process_dkg(5, 3, &mut rng).unwrap();
        let message = b"with only 2 of 5 we cannot make a valid sig";

        // 2 of 5 — below threshold; FROST returns IncorrectNumberOfShares.
        let r = run_in_process_sign(&key_packages, &pubkey_package, &[0, 1], message, &mut rng);
        assert!(r.is_err(), "below threshold must fail");
    }

    #[test]
    fn different_quorum_subsets_produce_valid_signatures() {
        let mut rng = ChaCha20Rng::seed_from_u64(99);
        let (key_packages, pubkey_package) = run_in_process_dkg(5, 3, &mut rng).unwrap();
        let message = b"any quorum of 3 yields valid sig";

        for subset in [&[0usize, 1, 2][..], &[1, 3, 4][..], &[0, 2, 4][..]] {
            let sig = run_in_process_sign(&key_packages, &pubkey_package, subset, message, &mut rng)
                .unwrap_or_else(|e| panic!("subset {:?} sign: {e:?}", subset));
            pubkey_package
                .verifying_key()
                .verify(message, &sig)
                .unwrap_or_else(|e| panic!("subset {:?} verify: {e:?}", subset));
        }
    }
}
