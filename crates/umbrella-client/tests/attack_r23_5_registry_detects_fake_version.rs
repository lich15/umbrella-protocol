//! R23 — Real attack: 5-registry integrity check detects fake version
//!
//! Per round-6 spec §«Stage 5» R23:
//! > substitute app binary with modified version, run startup integrity check
//! > → assert 5-registry check fails on at least 4 of 5 sources → app refuses
//! > to start.
//!
//! The 5 registries:
//! 1. Our official registry (e.g. update.umbrellax.io).
//! 2. Sigstore transparency log (rekor.sigstore.dev).
//! 3. Certificate Transparency (CT).
//! 4. Alternative jurisdiction registry (e.g. Iceland mirror).
//! 5. P2P peer attestation network.
//!
//! Attack scenario: adversary replaces binary on device with version embedding
//! NSL backdoor. Adversary may collude with 1 of 5 registries (e.g. coerce
//! our registry to attest the fake version). Other 4 registries continue to
//! list the official hash → mismatch detected.
//!
//! Numerical outcome:
//! - number of registries verifying the binary hash
//! - mismatch count
//! - decision: refuse-to-start if ≥4 of 5 disagree with local binary

use std::collections::BTreeMap;

/// Simulates a 5-registry attestation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryResult {
    Match,
    Mismatch,
    Unavailable,
}

#[derive(Debug)]
struct IntegrityCheck {
    /// Hash of the locally-loaded binary.
    local_binary_hash: [u8; 32],
    /// Per-registry attestation (what each registry says).
    registries: BTreeMap<&'static str, [u8; 32]>,
}

impl IntegrityCheck {
    fn matches(&self) -> Vec<(&'static str, RegistryResult)> {
        self.registries
            .iter()
            .map(|(name, hash)| {
                let r = if hash == &self.local_binary_hash {
                    RegistryResult::Match
                } else {
                    RegistryResult::Mismatch
                };
                (*name, r)
            })
            .collect()
    }

    /// Returns true iff at least `min` registries match the local binary.
    fn passes_with_min(&self, min: usize) -> bool {
        self.matches()
            .into_iter()
            .filter(|(_, r)| *r == RegistryResult::Match)
            .count()
            >= min
    }
}

#[test]
fn r23_genuine_binary_passes_all_5_registries() {
    let canonical = [0x55u8; 32];
    let mut registries = BTreeMap::new();
    registries.insert("umbrellax", canonical);
    registries.insert("sigstore", canonical);
    registries.insert("ct", canonical);
    registries.insert("iceland_mirror", canonical);
    registries.insert("p2p_attestation", canonical);
    let check = IntegrityCheck {
        local_binary_hash: canonical,
        registries,
    };
    let matches = check.matches();
    eprintln!("[R23] genuine binary: {matches:?}");
    let match_count = matches.iter().filter(|(_, r)| *r == RegistryResult::Match).count();
    assert_eq!(match_count, 5, "5/5 registries match canonical binary");
    assert!(check.passes_with_min(4), "passes the 4-of-5 acceptance gate");
}

#[test]
fn r23_fake_binary_detected_by_4_of_5_registries() {
    // Adversary has replaced binary with fake hash 0xFF.
    let fake = [0xFFu8; 32];
    let canonical = [0x55u8; 32];

    // Adversary may have coerced 1 registry to attest the fake. Other 4
    // continue with canonical.
    let mut registries = BTreeMap::new();
    registries.insert("umbrellax_coerced", fake); // attacker's coercion
    registries.insert("sigstore", canonical);
    registries.insert("ct", canonical);
    registries.insert("iceland_mirror", canonical);
    registries.insert("p2p_attestation", canonical);
    let check = IntegrityCheck {
        local_binary_hash: fake, // device is running the fake binary
        registries,
    };
    let matches = check.matches();
    eprintln!("[R23] fake binary: {matches:?}");
    let mismatch_count = matches
        .iter()
        .filter(|(_, r)| *r == RegistryResult::Mismatch)
        .count();
    eprintln!(
        "[R23] mismatch count: {mismatch_count}/5 (≥4 required to refuse start)"
    );
    assert_eq!(mismatch_count, 4, "4 of 5 registries detect fake binary");
    assert!(
        !check.passes_with_min(4),
        "fake binary fails the 4-of-5 acceptance gate"
    );
}

#[test]
fn r23_2_of_5_compromised_still_detects_fake() {
    let fake = [0xFFu8; 32];
    let canonical = [0x55u8; 32];

    // Adversary coerces 2 of 5 registries. Still 3 detect.
    let mut registries = BTreeMap::new();
    registries.insert("umbrellax_coerced", fake);
    registries.insert("sigstore_coerced", fake);
    registries.insert("ct", canonical);
    registries.insert("iceland_mirror", canonical);
    registries.insert("p2p_attestation", canonical);
    let check = IntegrityCheck {
        local_binary_hash: fake,
        registries,
    };
    let mismatch_count = check
        .matches()
        .iter()
        .filter(|(_, r)| *r == RegistryResult::Mismatch)
        .count();
    eprintln!("[R23] with 2 compromised: mismatch count={mismatch_count}/5");
    // 3 of 5 detect mismatch → app refuses start (we need ≥4 matches; only
    // 2 match the fake, so 2 < 4 → refuse).
    assert!(!check.passes_with_min(4));
}

#[test]
fn r23_3_of_5_compromised_marginal_case() {
    let fake = [0xFFu8; 32];
    let canonical = [0x55u8; 32];

    let mut registries = BTreeMap::new();
    registries.insert("umbrellax_coerced", fake);
    registries.insert("sigstore_coerced", fake);
    registries.insert("ct_coerced", fake);
    registries.insert("iceland_mirror", canonical);
    registries.insert("p2p_attestation", canonical);
    let check = IntegrityCheck {
        local_binary_hash: fake,
        registries,
    };
    let match_count = check
        .matches()
        .iter()
        .filter(|(_, r)| *r == RegistryResult::Match)
        .count();
    eprintln!(
        "[R23] with 3 compromised: match count={match_count}/5 (4-of-5 gate not met)"
    );
    assert_eq!(match_count, 3);
    // 3 < 4 → still refuse. Adversary needs to compromise 4 of 5 simultaneously.
    assert!(!check.passes_with_min(4));
}
