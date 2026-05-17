//! # Distributed Key Generation (DKG) — Pedersen-VSS via FROST-Ed25519
//!
//! Реализует 3-round Pedersen-VSS DKG между 5 серверами. Каждый сервер
//! получает на выходе `KeyPackage` (свою долю secret-а + verifying keys всех
//! остальных), и общий `PublicKeyPackage` (= identity_pk, наблюдается клиентом).
//! Никто не имеет full secret. Любые 3-of-5 могут восстановить либо подписать.
//!
//! 3-round Pedersen-VSS DKG between 5 servers using `frost-ed25519`. Each
//! server outputs a `KeyPackage` (its share + everyone's verifying keys), and
//! a shared `PublicKeyPackage` (= identity_pk, observable by client). No one
//! holds the full secret. Any 3-of-5 can reconstruct or sign.
//!
//! ## References
//!
//! - Pedersen 1991, «Non-Interactive and Information-Theoretic Secure
//!   Verifiable Secret Sharing», CRYPTO '91.
//! - Komlo, Goldberg 2020, «FROST: Flexible Round-Optimized Schnorr Threshold
//!   Signatures», SAC 2020.
//! - Zcash Foundation `frost-ed25519` crate v3.0.0, formal audit by NCC Group
//!   2024 (covering frost-core ≥ 2.0).

use std::collections::BTreeMap;

use frost_ed25519::{
    keys::{
        dkg::{part1, part2, part3, round1, round2},
        KeyPackage, PublicKeyPackage,
    },
    Identifier,
};
use rand_core::{CryptoRng, RngCore};

use crate::error::{ThresholdIdentityError, ThresholdIdentityResult};

/// State одного сервера-участника между раундами DKG. Round-1: hold secret
/// commitments; Round-2: hold round-2 secret package; Round-3: produce
/// `KeyPackage`.
///
/// One server participant's state between DKG rounds.
#[derive(Debug, Clone)]
pub struct DkgParticipant {
    /// Идентификатор участника (1..=5 для нашего кластера).
    pub identifier: Identifier,
    /// Общее число участников (фиксировано 5).
    pub max_signers: u16,
    /// Threshold (фиксировано 3).
    pub min_signers: u16,
}

impl DkgParticipant {
    /// Конструирует participant state с заданным `index` (1..=5).
    ///
    /// Errors:
    /// - `ThresholdIdentityError::DkgAborted` если `index == 0` или
    ///   `index > max_signers`.
    pub fn new(index: u16, max_signers: u16, min_signers: u16) -> ThresholdIdentityResult<Self> {
        if index == 0 || index > max_signers {
            return Err(ThresholdIdentityError::DkgAborted(
                "identifier index out of range",
            ));
        }
        if min_signers == 0 || min_signers > max_signers {
            return Err(ThresholdIdentityError::DkgAborted(
                "threshold out of range",
            ));
        }
        let identifier = Identifier::try_from(index)?;
        Ok(Self {
            identifier,
            max_signers,
            min_signers,
        })
    }
}

/// Round-1 output: SecretPackage держится сервером локально, Package
/// рассылается всем остальным участникам через broadcast channel.
///
/// Round-1 output: SecretPackage held locally, Package broadcast to others.
pub struct Round1Output {
    /// Secret material, **никогда** не покидает сервер.
    pub secret: round1::SecretPackage,
    /// Public commitment, рассылается всем (включая полиномные коэффициенты
    /// + proof-of-knowledge подпись).
    pub broadcast: round1::Package,
}

/// Round-2 output: SecretPackage держится сервером, broadcast — это `BTreeMap`
/// где каждому Identifier соответствует direct-message share (point-to-point).
///
/// Round-2 output: SecretPackage local, broadcast is a BTreeMap of P2P share
/// packages — server i has the share encrypted-for-server-j.
#[derive(Debug)]
pub struct Round2Output {
    /// Secret material, **никогда** не покидает сервер.
    pub secret: round2::SecretPackage,
    /// `BTreeMap<recipient_id, point-to-point share>`. Каждый share передаётся
    /// строго одному recipient через secure channel.
    pub point_to_point: BTreeMap<Identifier, round2::Package>,
}

/// Round-3 output: final `KeyPackage` (доля + verifying keys) и
/// `PublicKeyPackage` (общий identity pk + verifying shares всех).
///
/// Round-3 output: final KeyPackage + shared PublicKeyPackage.
pub struct Round3Output {
    /// Локальная доля + verifying material. Stays on server.
    pub key_package: KeyPackage,
    /// Identity public key + verifying shares of all participants. Observable
    /// by anyone (returned to client as identity_pk).
    pub public_key_package: PublicKeyPackage,
}

impl DkgParticipant {
    /// Запускает round-1 DKG. Принимает `rng` (для генерации полиномных
    /// коэффициентов + proof-of-knowledge nonce).
    ///
    /// Runs DKG round 1. Requires a CSPRNG.
    pub fn round1<R: CryptoRng + RngCore>(&self, rng: R) -> ThresholdIdentityResult<Round1Output> {
        let (secret, broadcast) = part1(self.identifier, self.max_signers, self.min_signers, rng)?;
        Ok(Round1Output { secret, broadcast })
    }

    /// Запускает round-2 DKG. Принимает свой `round1_secret` и broadcast
    /// packages от всех остальных участников (без своего собственного).
    ///
    /// `round1_packages` ДОЛЖНА содержать пакеты от всех других участников
    /// и НЕ содержать пакет самого `self.identifier` (per `frost-ed25519`
    /// API contract).
    ///
    /// Runs DKG round 2. `round1_packages` must contain broadcasts from all
    /// other participants, NOT from self.
    pub fn round2(
        &self,
        round1_secret: round1::SecretPackage,
        round1_packages: &BTreeMap<Identifier, round1::Package>,
    ) -> ThresholdIdentityResult<Round2Output> {
        // Defensive check: our own identifier MUST NOT appear in incoming
        // round1_packages. If it does, abort — that's a protocol violation
        // (somebody crafted a malicious broadcast claiming to be us).
        if round1_packages.contains_key(&self.identifier) {
            return Err(ThresholdIdentityError::DkgAborted(
                "round1_packages contains self identifier",
            ));
        }
        // Expect exactly max_signers - 1 packages from other participants.
        if round1_packages.len() != (self.max_signers as usize - 1) {
            return Err(ThresholdIdentityError::DkgAborted(
                "round1_packages cardinality mismatch",
            ));
        }
        let (secret, point_to_point) = part2(round1_secret, round1_packages)?;
        Ok(Round2Output {
            secret,
            point_to_point,
        })
    }

    /// Запускает round-3 DKG. Принимает round-2 secret и broadcast от всех
    /// остальных (round-1 broadcasts ещё раз нужны для verification + round-2
    /// P2P shares адресованные именно нам).
    ///
    /// Runs DKG round 3. Inputs:
    /// - `round2_secret` — own round-2 secret.
    /// - `round1_packages` — broadcasts from all others (verification).
    /// - `round2_packages` — P2P shares addressed to self by all others.
    pub fn round3(
        &self,
        round2_secret: &round2::SecretPackage,
        round1_packages: &BTreeMap<Identifier, round1::Package>,
        round2_packages: &BTreeMap<Identifier, round2::Package>,
    ) -> ThresholdIdentityResult<Round3Output> {
        if round1_packages.contains_key(&self.identifier) {
            return Err(ThresholdIdentityError::DkgAborted(
                "round1_packages contains self identifier",
            ));
        }
        if round2_packages.contains_key(&self.identifier) {
            return Err(ThresholdIdentityError::DkgAborted(
                "round2_packages contains self identifier",
            ));
        }
        let (key_package, public_key_package) =
            part3(round2_secret, round1_packages, round2_packages)?;
        Ok(Round3Output {
            key_package,
            public_key_package,
        })
    }
}

/// Полностью симулирует DKG end-to-end между `n` participants с threshold `t`,
/// все в одном process — для тестов + reference implementation.
///
/// Возвращает `Vec<KeyPackage>` (по одному на каждого) и общий
/// `PublicKeyPackage`.
///
/// Simulates an in-process DKG between `n` participants with threshold `t`.
/// Returns one `KeyPackage` per participant and the shared `PublicKeyPackage`.
///
/// **Internal use only**: real deployment runs each participant on a separate
/// server with serialised messages over secure channels. This helper exists
/// for tests + round-6 acceptance gate.
pub fn run_in_process_dkg<R: CryptoRng + RngCore>(
    n: u16,
    t: u16,
    rng: &mut R,
) -> ThresholdIdentityResult<(Vec<KeyPackage>, PublicKeyPackage)> {
    if n == 0 || t == 0 || t > n {
        return Err(ThresholdIdentityError::DkgAborted(
            "invalid n/t parameters",
        ));
    }

    let participants: Vec<DkgParticipant> = (1..=n)
        .map(|i| DkgParticipant::new(i, n, t))
        .collect::<ThresholdIdentityResult<_>>()?;

    // Round 1: each participant broadcasts.
    let mut round1_secrets: BTreeMap<Identifier, round1::SecretPackage> = BTreeMap::new();
    let mut round1_broadcasts: BTreeMap<Identifier, round1::Package> = BTreeMap::new();
    for p in &participants {
        let mut local_rng = derive_subrng(rng)?;
        let out = p.round1(&mut local_rng)?;
        round1_secrets.insert(p.identifier, out.secret);
        round1_broadcasts.insert(p.identifier, out.broadcast);
    }

    // Round 2: each participant receives all others' round1 broadcasts and
    // emits a per-recipient P2P share map.
    let mut round2_secrets: BTreeMap<Identifier, round2::SecretPackage> = BTreeMap::new();
    // Inverse map: for each recipient j, a BTreeMap<sender_id, package addressed to j>.
    let mut p2p_inbox: BTreeMap<Identifier, BTreeMap<Identifier, round2::Package>> =
        BTreeMap::new();
    for p in &participants {
        let mut their_round1_packages = round1_broadcasts.clone();
        their_round1_packages.remove(&p.identifier);
        let secret = round1_secrets
            .remove(&p.identifier)
            .ok_or(ThresholdIdentityError::DkgAborted("missing round1 secret"))?;
        let out = p.round2(secret, &their_round1_packages)?;
        round2_secrets.insert(p.identifier, out.secret);
        for (recipient, pkg) in out.point_to_point {
            p2p_inbox
                .entry(recipient)
                .or_default()
                .insert(p.identifier, pkg);
        }
    }

    // Round 3: each participant collects their inbox + verifies + produces
    // KeyPackage and PublicKeyPackage.
    let mut key_packages: Vec<KeyPackage> = Vec::with_capacity(participants.len());
    let mut shared_pubkey_package: Option<PublicKeyPackage> = None;

    for p in &participants {
        let mut their_round1_packages = round1_broadcasts.clone();
        their_round1_packages.remove(&p.identifier);
        let their_round2_packages = p2p_inbox
            .get(&p.identifier)
            .cloned()
            .unwrap_or_default();
        let secret = round2_secrets
            .get(&p.identifier)
            .ok_or(ThresholdIdentityError::DkgAborted("missing round2 secret"))?;
        let out = p.round3(secret, &their_round1_packages, &their_round2_packages)?;
        key_packages.push(out.key_package);

        match &shared_pubkey_package {
            None => shared_pubkey_package = Some(out.public_key_package),
            Some(prev) => {
                // All participants must converge on identical PublicKeyPackage.
                if prev.verifying_key() != out.public_key_package.verifying_key() {
                    return Err(ThresholdIdentityError::DkgAborted(
                        "PublicKeyPackage divergence between participants",
                    ));
                }
            }
        }
    }

    let public_key_package = shared_pubkey_package
        .ok_or(ThresholdIdentityError::DkgAborted("no PublicKeyPackage"))?;

    Ok((key_packages, public_key_package))
}

/// Derives a child CSPRNG from a parent one without consuming the parent's
/// owned position. Used to give each participant its own sub-rng in the
/// in-process simulation (so the test is deterministic given a seeded parent).
fn derive_subrng<R: CryptoRng + RngCore>(parent: &mut R) -> ThresholdIdentityResult<impl CryptoRng + RngCore> {
    let mut seed = [0u8; 32];
    parent.fill_bytes(&mut seed);
    Ok(rand_chacha::ChaCha20Rng::from_seed(seed))
}

use rand_chacha::rand_core::SeedableRng;

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn dkg_5of3_completes_and_converges() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x_DEAD_BEEF_DEAD_BEEF_u64);
        let (key_packages, public_key_package) =
            run_in_process_dkg(5, 3, &mut rng).expect("DKG should succeed");

        // 5 KeyPackages output, one per participant.
        assert_eq!(key_packages.len(), 5);

        // Identity public key bytes are 32 bytes (Ed25519).
        let pk_bytes = public_key_package
            .verifying_key()
            .serialize()
            .expect("Ed25519 pk serialisation");
        assert_eq!(pk_bytes.len(), 32);

        // Every KeyPackage agrees on the same verifying_key.
        for kp in &key_packages {
            assert_eq!(kp.verifying_key(), public_key_package.verifying_key());
        }
    }

    #[test]
    fn dkg_self_inclusion_in_round1_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p = DkgParticipant::new(1, 5, 3).unwrap();
        let r1 = p.round1(&mut rng).unwrap();
        let mut bad_packages = BTreeMap::new();
        bad_packages.insert(p.identifier, r1.broadcast);
        // Round-2 call with self in inbox must reject.
        let err = p.round2(r1.secret, &bad_packages).unwrap_err();
        assert!(matches!(
            err,
            ThresholdIdentityError::DkgAborted("round1_packages contains self identifier")
        ));
    }

    #[test]
    fn dkg_invalid_threshold_rejected() {
        // t > n
        let r = DkgParticipant::new(1, 3, 5);
        assert!(matches!(
            r,
            Err(ThresholdIdentityError::DkgAborted("threshold out of range"))
        ));
        // index = 0
        let r = DkgParticipant::new(0, 5, 3);
        assert!(matches!(
            r,
            Err(ThresholdIdentityError::DkgAborted("identifier index out of range"))
        ));
    }
}
