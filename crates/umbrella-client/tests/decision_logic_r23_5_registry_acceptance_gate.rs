//! # R23 5-registry acceptance gate — decision-logic model (NOT a real attack regression)
//!
//! **F-3 closure (PhD-B Pass 1 CRITICAL → Pass 5 remediation 2026-05-18).**
//!
//! This file was previously named `attack_r23_5_registry_detects_fake_version.rs`,
//! claiming it regressed a real supply-chain attack. PhD-B Pass 1 audit
//! (`docs/audits/phd-b-full-sweep-pass1-2026-05-18.md` F-3) identified the
//! mis-naming as CRITICAL severity: the file contained pure
//! `BTreeMap<&str, [u8; 32]>` arithmetic and **never** invoked Sigstore
//! Rekor, Certificate Transparency, cosign, mirror probes, or any real
//! registry. Calling it «attack regression» over-promised the
//! supply-chain defense posture.
//!
//! ## What this file IS
//!
//! A **decision-logic model** for the proposed 4-of-5 registry acceptance
//! gate. It validates that **once the real registry integration ships**,
//! the gate semantics are sound: 4 of 5 registries must independently
//! attest the local binary hash before the app starts; 2-of-5 coerced
//! adversary still fails the gate; 3-of-5 coerced is the marginal case
//! that the gate correctly rejects.
//!
//! ## What this file IS NOT
//!
//! A real supply-chain attack regression. The 5 registries below are
//! **simulated** with hardcoded `[u8; 32]` arrays. Production integration
//! requires:
//!
//! 1. **Sigstore Rekor REST client** — query `rekor.sigstore.dev/api/v1/log/entries`
//!    for the official binary hash, verify Rekor inclusion proof, check
//!    SET (Signed Entry Timestamp) signature against Rekor's public key.
//! 2. **Certificate Transparency log lookup** — query a public CT log
//!    (Google Argon / Cloudflare Nimbus / etc) for the build certificate
//!    used to sign the binary, verify SCT (Signed Certificate Timestamp).
//! 3. **Alternative jurisdiction mirror** — hosted in a separate legal
//!    jurisdiction (e.g. Iceland, Switzerland), running independent
//!    cosign verification of the same binary hash.
//! 4. **P2P attestation network** — pull binary hash attestations from
//!    other devices on the network via the secure transport.
//! 5. **Local cosign verification** — verify the bundled signature
//!    against the official build public key (currently partially shipped
//!    in v1.0.0 via `cosign sign-blob` on release artifacts).
//!
//! Items 1-4 are **not** in the v1.0.0 codebase. They are tracked as a
//! v1.1.x supply-chain hardening milestone (see PhD-B Pass 5 final
//! consolidation §6 Track A item 4). F-3 is shipped as «decision-logic
//! model + cosign-only» rather than removed entirely, because the gate
//! logic itself is sound and the design intent should be documented.
//!
//! ## Honest current security posture (v1.0.0)
//!
//! - Cosign signed releases — real
//! - Reproducible build for desktop targets — partial (Linux deterministic,
//!   macOS / Win not yet)
//! - Sigstore Rekor inclusion — planned v1.1.x
//! - Certificate Transparency lookup — planned v1.1.x
//! - Alternative jurisdiction mirror — planned v1.1.x (requires deployment)
//! - P2P attestation network — planned v1.1.x (requires umbrella-discovery
//!   Round 7 + P2P attestation protocol design)
//!
//! Readers of the tests below MUST NOT conclude that Umbrella has a
//! 4-of-5 supply-chain defense in production today. They should conclude
//! that the **decision logic** is implemented correctly so that when the
//! 4 missing integrations land in v1.1.x, the acceptance gate behaves as
//! intended.
//!
//! Per round-6 spec §«Stage 5» R23 design intent (not yet shipped):
//! > substitute app binary with modified version, run startup integrity check
//! > → assert 5-registry check fails on at least 4 of 5 sources → app refuses
//! > to start.
//!
//! The 5 registries (design — NOT YET integrated in v1.0.0):
//! 1. Our official registry (e.g. update.umbrellax.io).
//! 2. Sigstore transparency log (rekor.sigstore.dev).
//! 3. Certificate Transparency (CT).
//! 4. Alternative jurisdiction registry (e.g. Iceland mirror).
//! 5. P2P peer attestation network.
//!
//! Numerical outcome of the decision-logic model:
//! - number of registries verifying the binary hash (simulated)
//! - mismatch count (simulated)
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

/// **Decision-logic only** — simulates a genuine release scenario.
///
/// All 5 simulated registries return the canonical hash; the device runs
/// the canonical binary; the 4-of-5 acceptance gate passes.
///
/// Does NOT exercise any real registry integration — see module-level
/// F-3 closure disclaimer.
#[test]
fn r23_decision_logic_genuine_binary_passes_all_5_simulated_registries() {
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

/// **Decision-logic only** — simulates fake binary + 1 coerced registry.
///
/// 4 of 5 simulated registries detect mismatch; the gate refuses to start.
/// Validates the gate semantics, not a real supply-chain regression.
#[test]
fn r23_decision_logic_fake_binary_detected_by_4_of_5_simulated_registries() {
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

/// **Decision-logic only** — simulates 2-of-5 coerced adversary.
///
/// Validates the gate threshold: 2 of 5 compromised registries still
/// fail the 4-of-5 acceptance threshold (only 2 match the fake).
#[test]
fn r23_decision_logic_2_of_5_compromised_still_fails_gate() {
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

/// **Decision-logic only** — simulates 3-of-5 coerced (marginal case).
///
/// Validates the gate threshold: 3 of 5 compromised registries still
/// fall short of the 4-of-5 acceptance threshold; adversary would need
/// 4-of-5 simultaneous coercion to bypass the gate (assuming all 5
/// registries are actually independent in production).
#[test]
fn r23_decision_logic_3_of_5_compromised_marginal_case() {
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
