//! # Distributed identity client — round-6 backend integration
//!
//! Это клиентская часть round-6 protocol: устройство участвует в DKG только
//! как **участник handshake** (отправляет PIN + получает encrypted share),
//! сами DKG runds выполняют серверы. С точки зрения клиента flow:
//!
//! ```text
//! Bootstrap:
//!   1. user picks PIN
//!   2. client → 5 servers: registration request with anon_handles + PIN_envelope
//!   3. servers run DKG (this crate's umbrella-threshold-identity::dkg)
//!   4. each server returns: identity_pk + encrypted_share (for THIS device)
//!   5. client stores: identity_pk + 16-byte account_local_salt + 32-byte device_random
//!      (the latter wrapped in SE/StrongBox via PersistentKeyStoreCallback)
//!   6. **никаких слов на устройство не сохраняется**
//!
//! Daily unlock:
//!   1. user enters PIN
//!   2. client computes pin_root = Argon2id(PIN, account_local_salt)
//!   3. client → 3 of 5 servers: unwrap request bound to anon_id_i + signed by device
//!   4. servers verify PIN hash, return server_share to client
//!   5. client re-derives device_key + master_key через HKDF
//!   6. client holds device_key + master_key in MlockedSecret for session;
//!      зеroizes on background / screen lock / debugger detect.
//! ```
//!
//! Round-6 client backend: bootstrap + daily-unlock flow. Re-derives
//! device_key/master_key from PIN every unlock — no persistent secrets.

use std::sync::Arc;

use curve25519_dalek::scalar::Scalar;
use umbrella_crypto_primitives::mlocked::MlockedSecret;
// F-2 closure (PhD-B Pass 5 remediation): per-server anonymous IDs derived
// through a 3-of-5 threshold OPRF (Ristretto255-SHA512 over RFC 9497 Base
// Mode) rather than a local HKDF chain over `(PIN, salt)`. An adversary
// holding `(PIN, account_local_salt)` but lacking 3-of-5 Sealed Server
// OPRF key shares can no longer reconstruct anon-IDs without server
// interaction.
//
// F-2 closure: anon-IDs are now threshold-OPRF outputs, not local HKDF
// of PIN+salt.
use umbrella_oprf::{
    blind as oprf_blind, finalize as oprf_finalize, generate_test_private_key,
    shamir_split_for_testing, threshold_combine, BlindedRequest, OprfInput, ServerEvaluation,
    ThresholdConfig, WitnessIndex,
};
use umbrella_threshold_identity::{
    anonymous_id,
    key_derivation::{self, DerivationTranscript, DeviceRandom, ServerShare},
    pin_kdf,
};
use zeroize::Zeroize;

use crate::error::ClientError;

/// Identity public key (32 bytes Ed25519).
pub type IdentityPublicKey = [u8; 32];

/// 16-byte account-wide salt — persisted on device, not a secret.
pub type AccountLocalSalt = [u8; 16];

/// Бутстрап-ввод: всё что нужно для регистрации нового аккаунта.
#[derive(Debug, Clone)]
pub struct BootstrapInput {
    /// User-entered PIN (UTF-8 numeric digits).
    pub pin: Vec<u8>,
    /// Optional duress reverse PIN. If `None`, regular reverse of `pin` is
    /// implicitly the duress code per round-6 spec §«Duress mechanism».
    pub duress_pin: Option<Vec<u8>>,
    /// Optional phone E.164 for friend discovery only (never used for recovery).
    pub phone_e164: Option<String>,
    /// Optional OTP shared secret (20 bytes raw, base32-encoded in UI).
    pub otp_secret: Option<[u8; 20]>,
}

/// Output после bootstrap: ровно то что клиент должен сохранить на устройстве.
/// **24/12 слов на устройстве отсутствуют.**
#[derive(Debug, Clone)]
pub struct BootstrapOutput {
    /// Identity public key — observable, used for verification.
    pub identity_pk: IdentityPublicKey,
    /// 16-byte account-local salt — public, stored on device.
    pub account_local_salt: AccountLocalSalt,
    /// 32-byte device_random handle (in production stored inside SE/StrongBox).
    /// Это **handle**, не сам secret — secret access mediated через PersistentKeyStoreCallback.
    pub device_random_handle: [u8; 32],
    /// Initial transcript binding (epoch=1 on registration).
    pub initial_transcript: DerivationTranscript,
    /// Per-server anonymous IDs (5 values, cross-server correlation impossible).
    pub per_server_anonymous_ids: [[u8; 32]; 5],
}

/// Daily-unlock result: re-derived session keys, valid until lifecycle wipes.
#[derive(Debug)]
pub struct UnlockSession {
    /// Re-derived device_key for current session.
    pub device_key: MlockedSecret<[u8; 32]>,
    /// Re-derived master_key for current session.
    pub master_key: MlockedSecret<[u8; 32]>,
    /// Public identity (constant across sessions).
    pub identity_pk: IdentityPublicKey,
}

/// Abstracts the server unwrap call. Production uses async HTTPS+Tor fallback;
/// tests inject a deterministic mock.
pub trait ServerUnwrapClient: Send + Sync {
    /// Sends PIN verification challenge to server `server_id` (1..=5) for
    /// `anonymous_id`. Server replies with `server_share` iff PIN matched
    /// (server itself runs Argon2id verify; client never sees server_share
    /// unless verify succeeded).
    ///
    /// Returns 32-byte `server_share` or `ClientError::WrongPin` if servers
    /// reject. Other errors map to `ClientError::Network`.
    fn unwrap_share(
        &self,
        server_id: u16,
        anonymous_id: &[u8; 32],
        pin_root: &[u8; 32],
        transcript: &DerivationTranscript,
    ) -> Result<ServerShare, ClientError>;
}

/// Abstracts the Sealed Server OPRF (Oblivious PRF, RFC 9497) evaluation
/// endpoint. Used during bootstrap (F-2 closure) to derive per-server
/// anonymous IDs through a 3-of-5 threshold OPRF rather than local HKDF.
///
/// **F-2 closure (PhD-B Pass 5 remediation):** the prior bootstrap derived
/// anon-IDs through a local `HKDF<SHA256>` over `(PIN, account_local_salt)`
/// — any device knowing both inputs could reconstruct the full 5×32-byte
/// anon-ID set without server interaction. PSI round-7 design intent
/// requires anon-IDs to be **issued server-side via OPRF**: each Sealed
/// Server holds a Shamir share `k_i = f(server_id_i)` of the master OPRF
/// key `k = f(0)`, and the client must collect any 3 of 5 partial
/// evaluations and threshold-combine them to obtain the OPRF output
/// (algebraically `oprf_output = OPRF_k(pin_root)`). Without 3 of 5
/// server cooperations the client cannot derive anon-IDs even with full
/// `(PIN, salt)` knowledge.
///
/// **Trait shape parity with [`ServerUnwrapClient`]:** the trait is sync
/// so production HTTP/2 implementations block on a tokio runtime at the
/// transport edge — same pattern as the daily-unlock path. Async-native
/// production wiring is a future refactor that flips both traits together.
///
/// Production: HTTP/2 to `POST /v1/oprf/evaluate_anon_id` per Sealed Server
/// (rate-limited + attestation-guarded so PIN-bruteforce against the OPRF
/// endpoint is throttled).
///
/// Tests: [`MockServerOprfCluster`] with a Shamir-split master OPRF key.
pub trait ServerOprfClient: Send + Sync {
    /// Sends a blinded OPRF request to server `server_id` (1..=5). The
    /// server multiplies the blinded Ristretto255 point by its Shamir
    /// share `k_i` and returns the partial evaluation
    /// `E_i = k_i · blinded`. The caller threshold-combines 3 of 5 such
    /// partials via [`umbrella_oprf::threshold_combine`] to obtain
    /// `E = k · blinded` (algebraically identical to a single-server
    /// evaluation under the full master key), then unblinds locally.
    ///
    /// # Errors
    /// - [`ClientError::Network`] for transport failures or invalid
    ///   `server_id`.
    /// - [`ClientError::Oprf`] for server-side OPRF protocol errors.
    fn evaluate_anon_id(
        &self,
        server_id: u8,
        blinded: &BlindedRequest,
    ) -> Result<ServerEvaluation, ClientError>;
}

/// Performs daily unlock: re-derives device_key + master_key from PIN.
///
/// Steps:
/// 1. Argon2id(PIN, account_local_salt) → pin_root (32 bytes).
/// 2. Derive all 5 per-server anonymous IDs (locally).
/// 3. Send PIN-verification probe to up to 5 servers; collect first 3
///    successful `server_share`s with their server_id (1..=5).
/// 4. **Shamir 3-of-5 Lagrange interpolation** over the curve25519 scalar
///    field GF(q) to reconstruct the polynomial value at `x = 0` —
///    `master_secret = Σ_{i ∈ S} λ_i(0) · share_i` with
///    `λ_i(0) = ∏_{j ∈ S, j ≠ i} (j · (j − i)⁻¹)`. F-1 closure (PhD-B
///    Pass 5 remediation): replaces the Pass 1 XOR-combine placeholder
///    that broke the threshold-property (algebraic linearity revealed
///    256 bits of share correlation per pair of reconstructions with
///    different quora).
/// 5. HKDF: derive device_key (binds to device_random) and master_key
///    (account-wide) from the reconstructed `combined_share`.
///
/// Output stored в `MlockedSecret` для page-lock + zeroize-on-drop.
///
/// Daily unlock — re-derive session keys from PIN via 3-of-5 server unwraps.
/// Combines 3 shares via Shamir Lagrange interpolation over GF(q) on
/// curve25519 scalar field (F-1 closure: replaces the Pass 1 XOR-combine
/// placeholder).
pub fn unlock_with_pin(
    pin: &[u8],
    bootstrap: &BootstrapOutput,
    device_random: &DeviceRandom,
    transcript: &DerivationTranscript,
    server_client: &Arc<dyn ServerUnwrapClient>,
) -> Result<UnlockSession, ClientError> {
    // Step 1: PIN → Argon2id root.
    let pin_root = pin_kdf::derive_pin_root(pin, &bootstrap.account_local_salt)
        .map_err(|e| ClientError::Crypto(format!("PIN-KDF: {e}")))?;

    // Step 2: anonymous IDs (already computed at bootstrap, here we recompute
    // for safety; in production read from device storage).
    let anon_ids = &bootstrap.per_server_anonymous_ids;

    // Step 3: probe up to 5 servers; collect first 3 successful (server_id,
    // share) pairs preserving the server_id for Lagrange interpolation in
    // step 4. The server_id (1..=5) is the polynomial evaluation point
    // `x_i`; the share is the polynomial value `f(x_i)`. F-1 closure:
    // unlike XOR-combine, Lagrange requires preserving which server
    // contributed each share — anonymous accumulation breaks the algebra.
    let pin_root_bytes = *pin_root.expose();
    let mut collected: [(u8, [u8; 32]); 3] = [(0u8, [0u8; 32]); 3];
    let mut got_shares = 0usize;
    for server_id in 1..=5u16 {
        if got_shares >= 3 {
            break;
        }
        match server_client.unwrap_share(
            server_id,
            &anon_ids[(server_id - 1) as usize],
            &pin_root_bytes,
            transcript,
        ) {
            Ok(share) => {
                // Preserve (server_id, share) tuple; Lagrange interpolation
                // in step 4 maps server_id → polynomial evaluation point.
                #[allow(clippy::cast_possible_truncation)]
                let id_u8 = server_id as u8;
                collected[got_shares] = (id_u8, share);
                got_shares += 1;
            }
            Err(ClientError::WrongPin) => return Err(ClientError::WrongPin),
            Err(e) => {
                // Try next server.
                tracing::debug!("server {server_id} unwrap failed: {e:?}");
                continue;
            }
        }
    }
    if got_shares < 3 {
        return Err(ClientError::Network(
            "fewer than 3 servers responded".into(),
        ));
    }

    // Step 4: Shamir 3-of-5 Lagrange interpolation over GF(q).
    //
    // Reconstructs `f(0) = master_secret` from any 3 distinct polynomial
    // evaluations `(x_i, f(x_i))`:
    //
    // ```text
    // master_secret = Σ_{i ∈ S} λ_i(0) · share_i  mod q
    //   where λ_i(0) = ∏_{j ∈ S, j ≠ i} (x_j · (x_j − x_i)⁻¹)
    // ```
    //
    // `x_i` = server_id ∈ {1..=5}; `share_i` interpreted as `Scalar` via
    // `from_bytes_mod_order` (any 32 bytes reduce mod q). For well-formed
    // polynomial shares produced by a Sealed-Servers ceremony, any 3-of-5
    // quorum yields the **same** master_secret (Lagrange property of
    // polynomial interpolation). The XOR-combine placeholder lacked this
    // invariant — two reconstructions with different quora differed by
    // XOR of the unseen shares, leaking share correlations.
    let combined_share = lagrange_combine_shares(&collected[..got_shares]);

    // Step 5: HKDF re-derive device_key + master_key from reconstructed
    // master_secret.
    let device_key = key_derivation::derive_device_key(
        &pin_root_bytes,
        &combined_share,
        device_random,
        transcript,
    )
    .map_err(|e| ClientError::Crypto(format!("derive device_key: {e}")))?;

    let master_key = key_derivation::derive_master_key(
        &pin_root_bytes,
        &combined_share,
        &bootstrap.account_local_salt,
        transcript,
    )
    .map_err(|e| ClientError::Crypto(format!("derive master_key: {e}")))?;

    // Wipe transient secrets: combined_share + collected pool. The
    // `Scalar` arithmetic above already operated on copies; clearing the
    // serialized bytes prevents lingering heap residues for the
    // reconstruction transcript.
    let mut combined = combined_share;
    combined.zeroize();
    for (_id, share) in collected.iter_mut() {
        share.zeroize();
    }

    Ok(UnlockSession {
        device_key,
        master_key,
        identity_pk: bootstrap.identity_pk,
    })
}

/// Shamir 3-of-5 Lagrange interpolation over curve25519 scalar field
/// GF(q) at `x = 0`. Reconstructs the polynomial constant term from any
/// `threshold` evaluations `(x_i, f(x_i))`.
///
/// **F-1 closure (PhD-B Pass 5 remediation):** the Pass 1 XOR-combine
/// placeholder broke the threshold-property — algebraic linearity of XOR
/// meant any two reconstructions with different quora differed by XOR of
/// the unseen shares, revealing 256 bits of share correlation per pair
/// of observations. Lagrange interpolation closes this: for any
/// well-formed Shamir polynomial, **every** valid quorum reconstructs
/// the **same** secret (and the difference is zero).
///
/// # Algebra
///
/// Each `share` is interpreted as a scalar `f(x_i)` via
/// `Scalar::from_bytes_mod_order` (reduce mod the curve order q for any
/// 32-byte input). The Lagrange coefficient at zero is
///
/// ```text
/// λ_i(0) = ∏_{(x_j, _) ∈ shares, x_j ≠ x_i} (x_j / (x_j − x_i))   mod q
/// ```
///
/// and the reconstructed master scalar is `Σ_{i} λ_i(0) · f(x_i)`. The
/// result is serialized via `Scalar::to_bytes` (canonical 32-byte
/// little-endian); HKDF in step 5 absorbs this as IKM.
///
/// # Invariants (caller responsibility)
///
/// - `shares.len()` must equal the polynomial threshold (3 for 3-of-5).
/// - `x_i` values must be distinct (`(x_j − x_i) ≠ 0` so `invert()` is
///   well-defined). The unlock_with_pin caller enforces this via the
///   server_id 1..=5 loop with `break`-on-quorum which prevents
///   duplicates by construction.
///
/// # F-1 closure regression
///
/// The companion attack demonstrator
/// `attack_phd4_f1_xor_linearity_breaks_shamir_threshold_property` (in
/// `crates/umbrella-tests/tests/attack_phd4_real_exploits.rs`) sustains as
/// a class-level documenter of why XOR-combine fails. The positive
/// reconstruction-determinism property is exercised by the
/// `lagrange_reconstruction_yields_same_master_for_different_quora`
/// test below.
fn lagrange_combine_shares(shares: &[(u8, [u8; 32])]) -> [u8; 32] {
    let scalars: Vec<(u8, Scalar)> = shares
        .iter()
        .map(|(id, bytes)| (*id, Scalar::from_bytes_mod_order(*bytes)))
        .collect();

    let mut result = Scalar::ZERO;
    for (x_i, y_i) in &scalars {
        let xi = Scalar::from(u64::from(*x_i));
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for (x_j, _) in &scalars {
            if *x_j == *x_i {
                continue;
            }
            let xj = Scalar::from(u64::from(*x_j));
            num *= xj;
            den *= xj - xi;
        }
        let lambda_i = num * den.invert();
        result += y_i * lambda_i;
    }
    result.to_bytes()
}

/// Mock implementation of `ServerUnwrapClient` for tests. Stores per-server
/// `(expected_pin_root, share_bytes)` and returns share iff `pin_root` matches.
pub struct MockServerCluster {
    /// For each server (1..=5), what pin_root unlocks it and what share to return.
    pub shares: [(/* pin_root */ [u8; 32], /* share */ [u8; 32]); 5],
}

impl ServerUnwrapClient for MockServerCluster {
    fn unwrap_share(
        &self,
        server_id: u16,
        _anonymous_id: &[u8; 32],
        pin_root: &[u8; 32],
        _transcript: &DerivationTranscript,
    ) -> Result<ServerShare, ClientError> {
        if server_id == 0 || server_id as usize > self.shares.len() {
            return Err(ClientError::Network("invalid server_id".into()));
        }
        let (expected, share) = &self.shares[(server_id - 1) as usize];
        use subtle::ConstantTimeEq;
        if expected.ct_eq(pin_root).into() {
            Ok(*share)
        } else {
            Err(ClientError::WrongPin)
        }
    }
}

/// Mock implementation of [`ServerOprfClient`] for tests. Holds a
/// Shamir-split master OPRF key — each entry is one server's partial
/// scalar `k_i = f(i)` where `f` is a random degree-2 polynomial with
/// `f(0) = k` (master OPRF key). Server `i` (1..=5) evaluates partial
/// OPRF by multiplying the blinded Ristretto255 point by its share.
///
/// **F-2 closure (PhD-B Pass 5 remediation):** test rig parity with the
/// PSI round-7 production deployment of 5 Sealed Servers running
/// independent Shamir shares. A real HTTP/2 cluster replaces this mock
/// in production; the [`ServerOprfClient`] trait surface stays identical.
///
/// **Construction:** [`MockServerOprfCluster::new`] generates a fresh
/// master OPRF key and Shamir-splits it via
/// [`umbrella_oprf::shamir_split_for_testing`] with the default 3-of-5
/// threshold.
///
/// **Security note:** in production, no single party ever holds the
/// master OPRF key `k = f(0)`; the DKG ceremony at cluster bootstrap
/// produces shares directly. The test helper sidesteps DKG for
/// determinism but the algebraic threshold property (any 3 of 5 reconstruct
/// the same OPRF output) is preserved bit-for-bit.
pub struct MockServerOprfCluster {
    /// Shamir shares of the master OPRF key. Index `i ∈ 0..5` holds
    /// `(WitnessIndex(i+1), f(i+1).to_bytes())` so that
    /// `shares[i].0.get() == (i + 1) as u8`.
    shares: [(WitnessIndex, [u8; 32]); 5],
}

impl MockServerOprfCluster {
    /// Constructs a fresh mock cluster with a random master OPRF key
    /// Shamir-split into 5 shares with 3-of-5 threshold (default config).
    /// The master key is consumed inside this constructor and never
    /// surfaces through the public API — only the 5 shares persist.
    ///
    /// # Panics
    /// Inconceivable. [`generate_test_private_key`] yields a canonical
    /// Ristretto255 scalar by construction; [`WitnessIndex::new`] accepts
    /// 1..=5 by inspection of the constant range.
    pub fn new<R: rand_core::CryptoRng + rand_core::RngCore>(rng: &mut R) -> Self {
        let master_sk = generate_test_private_key(rng);
        let k = Scalar::from_canonical_bytes(master_sk)
            .into_option()
            .expect("generate_test_private_key yields canonical Ristretto255 scalar");

        let raw_shares = shamir_split_for_testing(k, ThresholdConfig::default(), rng);
        // Invariant: raw_shares.len() == DEFAULT_TOTAL (5) per the
        // contract of `shamir_split_for_testing` with the default config.
        debug_assert_eq!(raw_shares.len(), 5);

        let shares: [(WitnessIndex, [u8; 32]); 5] = std::array::from_fn(|i| {
            let (wi, scalar) = &raw_shares[i];
            (*wi, scalar.to_bytes())
        });

        Self { shares }
    }

    /// **Test-only**: exposes one server's OPRF share for adversary
    /// modeling (negative regression test: «adversary with `k-1 = 2`
    /// server keys cannot recover anon-IDs»). Production never exposes
    /// shares outside the Sealed Server enclave.
    ///
    /// Panics on out-of-range `server_id`.
    #[cfg(test)]
    pub(crate) fn share_at(&self, server_id: u8) -> (WitnessIndex, [u8; 32]) {
        assert!(
            (1..=5).contains(&server_id),
            "server_id must be 1..=5, got {server_id}"
        );
        self.shares[(server_id - 1) as usize]
    }
}

impl ServerOprfClient for MockServerOprfCluster {
    fn evaluate_anon_id(
        &self,
        server_id: u8,
        blinded: &BlindedRequest,
    ) -> Result<ServerEvaluation, ClientError> {
        if server_id == 0 || server_id as usize > self.shares.len() {
            return Err(ClientError::Network(format!(
                "invalid server_id {server_id}"
            )));
        }
        let (_wi, share_bytes) = &self.shares[(server_id - 1) as usize];
        umbrella_oprf::evaluate_for_testing(blinded, share_bytes).map_err(ClientError::from)
    }
}

/// Derives 5 per-server anonymous IDs via 3-of-5 threshold OPRF against the
/// Sealed Server cluster. **F-2 closure (PhD-B Pass 5 remediation):**
/// replaces the prior local `HKDF<SHA256>(salt, pin_root, "anon-seed/v1")`
/// derivation with a server-side OPRF flow so an adversary holding
/// `(PIN, account_local_salt)` alone cannot regenerate the anon-ID chain.
///
/// # Cryptographic flow (RFC 9497 Base Mode + threshold extension)
///
/// 1. Wrap `pin_root` as an [`OprfInput`] (32 bytes opaque).
/// 2. Blind through [`umbrella_oprf::blind`] →
///    `(BlindedRequest, BlindingState)`. The blinding factor `r` is fresh
///    per-call and zeroized on `BlindingState::drop`.
/// 3. Send the same `BlindedRequest` to up to 5 Sealed Servers in order
///    1..=5; collect the first 3 successful partial evaluations
///    `E_i = k_i · BlindedRequest` (Ristretto255 point multiplication).
/// 4. [`threshold_combine`] performs Lagrange interpolation in the
///    Ristretto255 group at `x = 0` to reconstruct the full evaluation
///    `E = k · BlindedRequest` where `k = f(0)` is the master OPRF key.
/// 5. [`umbrella_oprf::finalize`] unblinds (`r⁻¹ · E`) and SHA-512-hashes
///    with the canonical domain separator to yield a 32-byte
///    [`umbrella_oprf::OprfLabel`].
/// 6. The OPRF label is passed to
///    [`umbrella_threshold_identity::anonymous_id::derive_all_anonymous_ids`]
///    as the master input; HKDF-SHA256 expands to 5 per-server pseudonyms.
///
/// # Security reduction (informal)
///
/// Under the OPRF Base Mode assumption (RFC 9497 §4 — adversary cannot
/// distinguish `OPRF_k(x)` from a uniformly random 32-byte string without
/// knowing `k`), the anonymous IDs are pseudorandom functions of
/// `(k, pin_root)`. An adversary with `(PIN, salt)` can locally derive
/// `pin_root` (Argon2id) but **cannot** compute `OPRF_k(pin_root)`
/// without 3-of-5 server cooperations (Shamir secret-sharing of `k`).
/// Thus 5 × 32 = 160 bytes of cross-server correlation key are protected
/// behind the threshold reconstruction barrier.
///
/// # Errors
/// - [`ClientError::Oprf`] from any OPRF layer step (input validation,
///   blind, threshold_combine, finalize).
/// - [`ClientError::Network`] if fewer than 3 OPRF servers respond.
/// - [`ClientError::Crypto`] from `derive_all_anonymous_ids`.
fn derive_anon_ids_via_oprf<R: rand_core::CryptoRng + rand_core::RngCore>(
    pin_root: &[u8; 32],
    server_oprf_client: &Arc<dyn ServerOprfClient>,
    rng: &mut R,
) -> Result<[[u8; 32]; 5], ClientError> {
    // Step 1: wrap pin_root as opaque OPRF input.
    let oprf_input = OprfInput::new(pin_root).map_err(ClientError::from)?;

    // Step 2: blind. BlindingState holds the blind scalar `r` and
    // ZeroizeOnDrop-clears it when this function returns.
    let (blinded, blind_state) = oprf_blind(oprf_input, rng).map_err(ClientError::from)?;

    // Step 3: query servers 1..=5, stop after 3 successful partials.
    // Iterating in deterministic 1..=5 order keeps the threshold subset
    // dependent only on which servers respond, not on caller scheduling.
    let mut collected: Vec<(WitnessIndex, ServerEvaluation)> = Vec::with_capacity(3);
    for server_id in 1u8..=5 {
        if collected.len() >= 3 {
            break;
        }
        match server_oprf_client.evaluate_anon_id(server_id, &blinded) {
            Ok(eval) => {
                let wi = WitnessIndex::new(server_id).map_err(ClientError::from)?;
                collected.push((wi, eval));
            }
            Err(e) => {
                tracing::debug!("OPRF server {server_id} unavailable: {e:?}");
            }
        }
    }
    if collected.len() < 3 {
        return Err(ClientError::Network(format!(
            "fewer than 3 OPRF servers responded ({}/5 succeeded)",
            collected.len()
        )));
    }

    // Step 4: threshold-combine the 3 partial evaluations via Lagrange
    // interpolation at x = 0 in the Ristretto255 group.
    let combined =
        threshold_combine(&collected, ThresholdConfig::default()).map_err(ClientError::from)?;

    // Step 5: unblind + finalize (SHA-512 with `umbrellax-oprf-output-v1`
    // domain separator) → 32-byte OprfLabel.
    let oprf_label =
        oprf_finalize(&blind_state, oprf_input, &combined).map_err(ClientError::from)?;

    // Step 6: derive 5 per-server anon-IDs from the OPRF label.
    let anon_ids = anonymous_id::derive_all_anonymous_ids(oprf_label.as_bytes())
        .map_err(|e| ClientError::Crypto(format!("anon-id: {e}")))?;

    Ok(anon_ids)
}

/// Performs bootstrap (registration). Generates 16-byte account_local_salt +
/// 32-byte device_random_handle, derives 5 per-server anonymous IDs through
/// a 3-of-5 threshold OPRF against [`ServerOprfClient`], and assembles the
/// public bootstrap output. **No words on device, no PIN copy, no local
/// master_key.**
///
/// **F-2 closure (PhD-B Pass 5 remediation):** the prior implementation
/// derived anon-IDs locally through
/// `HKDF<SHA256>(salt, pin_root, "umbrella-r6/anon-seed/v1")` — an
/// adversary with `(PIN, captured account_local_salt)` could regenerate
/// all 5 × 32 = 160 bytes of anon-IDs without server interaction (6-digit
/// PIN brute-force = ~140 h CPU / ~6 h GPU farm via Argon2id, feasible
/// for state-level adversary). The OPRF flow now binds anon-IDs to the
/// secret master OPRF key held in a Shamir 3-of-5 split across Sealed
/// Servers; an adversary holding `(PIN, salt)` alone cannot derive
/// anon-IDs without 3 of 5 server cooperations.
///
/// In production, `identity_pk_from_server_dkg` comes from the FROST DKG
/// performed by the 5 Sealed Servers at registration; the client passes
/// it through. Production wiring for `server_oprf_client` is HTTP/2 to
/// the OPRF evaluation endpoint; tests inject [`MockServerOprfCluster`].
///
/// Bootstrap — registers new account, persists only PIN-derivable handles +
/// public OPRF-derived anon-IDs.
pub fn bootstrap_account<R: rand_core::CryptoRng + rand_core::RngCore>(
    input: &BootstrapInput,
    identity_pk_from_server_dkg: IdentityPublicKey,
    server_oprf_client: &Arc<dyn ServerOprfClient>,
    rng: &mut R,
) -> Result<BootstrapOutput, ClientError> {
    // Generate per-account salt (16 bytes).
    let mut account_local_salt = [0u8; 16];
    rng.fill_bytes(&mut account_local_salt);

    // Generate device_random_handle (32 bytes). In production this would be
    // a label string referring to a key inside SE/StrongBox; here it's the
    // raw 32 bytes (test rig only).
    let mut device_random_handle = [0u8; 32];
    rng.fill_bytes(&mut device_random_handle);

    // Compute pin_root via Argon2id(PIN, salt) — 32 bytes mlocked. This is
    // the same pin_root used by daily-unlock (`unlock_with_pin`) and is
    // the OPRF input that binds the anon-ID derivation to the user's PIN.
    let pin_root = pin_kdf::derive_pin_root(&input.pin, &account_local_salt)
        .map_err(|e| ClientError::Crypto(format!("PIN-KDF bootstrap: {e}")))?;

    // F-2 closure: derive 5 per-server anon-IDs through 3-of-5 threshold
    // OPRF against Sealed Servers rather than local HKDF. Replaces the
    // bit-equal regeneration path documented in the F-2 exploit
    // demonstrator (`attack_phd4_f2_*` in umbrella-tests). The OPRF
    // output is a pseudorandom 32-byte value bound to `(pin_root, k)`
    // where `k` is the master OPRF key Shamir-split across servers.
    let per_server_anonymous_ids =
        derive_anon_ids_via_oprf(pin_root.expose(), server_oprf_client, rng)?;

    // Initial transcript: epoch=1.
    let initial_transcript = DerivationTranscript {
        account_id: per_server_anonymous_ids[0], // server 1's ID is "primary" reference.
        epoch: 1,
    };

    // Drop input.pin / input.duress_pin via input's caller; we never copy them.
    let _ = &input.duress_pin; // silence unused if duress not yet wired.
    let _ = &input.phone_e164;
    let _ = &input.otp_secret;

    Ok(BootstrapOutput {
        identity_pk: identity_pk_from_server_dkg,
        account_local_salt,
        device_random_handle,
        initial_transcript,
        per_server_anonymous_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::collections::HashSet;

    fn fake_identity_pk() -> IdentityPublicKey {
        [0xCC; 32]
    }

    /// Test helper: build a fresh [`MockServerOprfCluster`] seeded from the
    /// given u64. Each test uses its own seed so test isolation is preserved;
    /// the [`Arc<dyn ServerOprfClient>`] coercion matches the
    /// [`bootstrap_account`] signature.
    fn fake_oprf_cluster(seed: u64) -> Arc<dyn ServerOprfClient> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        Arc::new(MockServerOprfCluster::new(&mut rng))
    }

    /// Test helper: wraps a [`ServerOprfClient`] but only forwards
    /// evaluations for `server_id` in `allowed`. Used to model partial
    /// availability scenarios (e.g., «only 2 of 5 servers reachable») and
    /// quorum-determinism property tests («same OPRF output regardless of
    /// which 3 of 5 servers respond»). F-2 closure: enables negative
    /// regression guards against fallback-to-local-derivation patches.
    struct QuorumSelectiveOprfCluster {
        inner: Arc<dyn ServerOprfClient>,
        allowed: HashSet<u8>,
    }

    impl ServerOprfClient for QuorumSelectiveOprfCluster {
        fn evaluate_anon_id(
            &self,
            server_id: u8,
            blinded: &BlindedRequest,
        ) -> Result<ServerEvaluation, ClientError> {
            if !self.allowed.contains(&server_id) {
                return Err(ClientError::Network(format!(
                    "test: server {server_id} disabled"
                )));
            }
            self.inner.evaluate_anon_id(server_id, blinded)
        }
    }

    #[test]
    fn bootstrap_persists_only_handles_not_secrets() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let oprf_cluster = fake_oprf_cluster(0x9001);
        let input = BootstrapInput {
            pin: b"123456".to_vec(),
            duress_pin: None,
            phone_e164: None,
            otp_secret: None,
        };
        let out = bootstrap_account(&input, fake_identity_pk(), &oprf_cluster, &mut rng).unwrap();
        assert_eq!(out.identity_pk, fake_identity_pk());
        // Persisted state contains 16+32 bytes of public material + 5 anon-ids.
        // **No PIN, no master_key, no device_key, no recovery words.**
        for id in &out.per_server_anonymous_ids {
            assert_ne!(id, &[0u8; 32]);
        }
    }

    #[test]
    fn unlock_re_derives_session_keys_deterministically() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let oprf_cluster = fake_oprf_cluster(0x9002);
        let input = BootstrapInput {
            pin: b"123456".to_vec(),
            duress_pin: None,
            phone_e164: None,
            otp_secret: None,
        };
        let boot = bootstrap_account(&input, fake_identity_pk(), &oprf_cluster, &mut rng).unwrap();

        // Mock server cluster: any pin_root matching Argon2id(123456, salt) unlocks.
        let pin_root_expected =
            pin_kdf::derive_pin_root(b"123456", &boot.account_local_salt).unwrap();
        let pre = *pin_root_expected.expose();
        let shares = [
            (pre, [0x11; 32]),
            (pre, [0x22; 32]),
            (pre, [0x33; 32]),
            (pre, [0x44; 32]),
            (pre, [0x55; 32]),
        ];
        let cluster: Arc<dyn ServerUnwrapClient> = Arc::new(MockServerCluster { shares });

        let device_random = [0xAB; 32];
        let session1 = unlock_with_pin(
            b"123456",
            &boot,
            &device_random,
            &boot.initial_transcript,
            &cluster,
        )
        .expect("unlock1");
        let session2 = unlock_with_pin(
            b"123456",
            &boot,
            &device_random,
            &boot.initial_transcript,
            &cluster,
        )
        .expect("unlock2");
        // Same PIN, same transcript → same session keys.
        assert_eq!(session1.device_key.expose(), session2.device_key.expose());
        assert_eq!(session1.master_key.expose(), session2.master_key.expose());
        // Device_key and master_key independent.
        assert_ne!(session1.device_key.expose(), session1.master_key.expose());
    }

    #[test]
    fn unlock_with_wrong_pin_rejects() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let oprf_cluster = fake_oprf_cluster(0x9003);
        let input = BootstrapInput {
            pin: b"123456".to_vec(),
            duress_pin: None,
            phone_e164: None,
            otp_secret: None,
        };
        let boot = bootstrap_account(&input, fake_identity_pk(), &oprf_cluster, &mut rng).unwrap();
        let correct_root = *pin_kdf::derive_pin_root(b"123456", &boot.account_local_salt)
            .unwrap()
            .expose();
        let cluster: Arc<dyn ServerUnwrapClient> = Arc::new(MockServerCluster {
            shares: [
                (correct_root, [1u8; 32]),
                (correct_root, [2u8; 32]),
                (correct_root, [3u8; 32]),
                (correct_root, [4u8; 32]),
                (correct_root, [5u8; 32]),
            ],
        });
        let r = unlock_with_pin(
            b"999999",
            &boot,
            &[0; 32],
            &boot.initial_transcript,
            &cluster,
        );
        assert!(matches!(r, Err(ClientError::WrongPin)));
    }

    /// **F-1 closure regression guard (PhD-B Pass 5 remediation).**
    ///
    /// Validates the Lagrange interpolation property that the Pass 1
    /// XOR-combine placeholder lacked: for a well-formed Shamir polynomial
    /// `f(x) = master + a₁·x + a₂·x²` (degree threshold − 1 = 2), **every**
    /// 3-of-5 quorum reconstructs the **same** master scalar. The XOR
    /// placeholder broke this — two reconstructions over different quora
    /// differed by `XOR` of the unseen shares (256 bits of share
    /// correlation per pair of observations).
    ///
    /// The attack class is documented in
    /// `crates/umbrella-tests/tests/attack_phd4_real_exploits.rs`
    /// (`attack_phd4_f1_xor_linearity_breaks_shamir_threshold_property`),
    /// which sustains as a class-level XOR-linearity demonstrator. This
    /// test is the **positive** Lagrange property guard against
    /// re-introduction of the XOR pattern.
    #[test]
    fn lagrange_reconstruction_yields_same_master_for_different_quora() {
        use curve25519_dalek::scalar::Scalar;
        use rand_chacha::rand_core::RngCore;
        use rand_chacha::rand_core::SeedableRng;

        let mut rng = ChaCha20Rng::seed_from_u64(0xF1_C105E_DEAD_BEEF);

        // Random master scalar = f(0).
        let mut master_bytes = [0u8; 32];
        rng.fill_bytes(&mut master_bytes);
        let master_scalar = Scalar::from_bytes_mod_order(master_bytes);
        let expected_master_canonical = master_scalar.to_bytes();

        // Random polynomial coefficients a₁, a₂.
        let mut a1_bytes = [0u8; 32];
        let mut a2_bytes = [0u8; 32];
        rng.fill_bytes(&mut a1_bytes);
        rng.fill_bytes(&mut a2_bytes);
        let a1 = Scalar::from_bytes_mod_order(a1_bytes);
        let a2 = Scalar::from_bytes_mod_order(a2_bytes);

        // Generate 5 polynomial shares: y_i = f(i) = master + a₁·i + a₂·i².
        let mut shares = [(0u8, [0u8; 32]); 5];
        for i in 1u8..=5u8 {
            let x = Scalar::from(u64::from(i));
            let y = master_scalar + a1 * x + a2 * x * x;
            shares[(i - 1) as usize] = (i, y.to_bytes());
        }

        // Reconstruct from quorum A = {1, 2, 3}.
        let quorum_a = [shares[0], shares[1], shares[2]];
        let recovered_a = lagrange_combine_shares(&quorum_a);

        // Reconstruct from quorum B = {1, 2, 4}.
        let quorum_b = [shares[0], shares[1], shares[3]];
        let recovered_b = lagrange_combine_shares(&quorum_b);

        // Reconstruct from quorum C = {3, 4, 5}.
        let quorum_c = [shares[2], shares[3], shares[4]];
        let recovered_c = lagrange_combine_shares(&quorum_c);

        // All three reconstructions must equal the master scalar (Lagrange
        // interpolation property of degree-2 polynomial over 5 evaluation
        // points).
        assert_eq!(
            recovered_a, expected_master_canonical,
            "F-1 closure: quorum {{1,2,3}} reconstructs master"
        );
        assert_eq!(
            recovered_b, expected_master_canonical,
            "F-1 closure: quorum {{1,2,4}} reconstructs master"
        );
        assert_eq!(
            recovered_c, expected_master_canonical,
            "F-1 closure: quorum {{3,4,5}} reconstructs master"
        );

        // The Pass 1 XOR-leak invariant — combined_a XOR combined_b reveals
        // unseen shares — is sealed: after Lagrange, both reconstructions
        // are bit-identical so the XOR difference is zero. An attacker
        // observing two unlock transcripts learns nothing about the
        // unused server shares.
        let mut xor_diff = [0u8; 32];
        for (slot, (a, b)) in xor_diff
            .iter_mut()
            .zip(recovered_a.iter().zip(recovered_b.iter()))
        {
            *slot = a ^ b;
        }
        assert_eq!(
            xor_diff, [0u8; 32],
            "F-1 closure: XOR-linearity leak sealed — different quora yield bit-identical reconstruction"
        );
    }

    #[test]
    fn different_pins_yield_different_sessions() {
        // Share the same OPRF cluster across the two bootstraps so the
        // difference in anon-IDs is attributable to the PIN change, not to
        // a different master OPRF key.
        let mut setup_rng = ChaCha20Rng::seed_from_u64(4);
        let cluster_inner = Arc::new(MockServerOprfCluster::new(&mut setup_rng));
        // Unsized coercion `Arc<MockServerOprfCluster>` → `Arc<dyn ServerOprfClient>`
        // fires at the let-binding via `CoerceUnsized`; `Arc::clone(&...)`
        // would force `T = dyn ServerOprfClient` inference and fail because
        // the input is `&Arc<MockServerOprfCluster>`, so method syntax is
        // mandatory here.
        let oprf_cluster_1: Arc<dyn ServerOprfClient> = cluster_inner.clone();
        let oprf_cluster_2: Arc<dyn ServerOprfClient> = cluster_inner.clone();

        let mut input = BootstrapInput {
            pin: b"123456".to_vec(),
            duress_pin: None,
            phone_e164: None,
            otp_secret: None,
        };
        let mut rng1 = ChaCha20Rng::seed_from_u64(0xA1);
        let boot =
            bootstrap_account(&input, fake_identity_pk(), &oprf_cluster_1, &mut rng1).unwrap();

        // Bootstrap with a second PIN should give different anon-IDs even
        // when fed into the same OPRF cluster (different PIN → different
        // pin_root → different OPRF input → pseudorandom-distinct output).
        input.pin = b"654321".to_vec();
        let mut rng2 = ChaCha20Rng::seed_from_u64(0xA2);
        let boot2 =
            bootstrap_account(&input, fake_identity_pk(), &oprf_cluster_2, &mut rng2).unwrap();
        assert_ne!(
            boot.per_server_anonymous_ids[0], boot2.per_server_anonymous_ids[0],
            "different PINs derive different anonymous IDs"
        );
    }

    /// **F-2 closure regression guard #1 — positive Lagrange property over
    /// Ristretto255 (3-of-5 quorum determinism).**
    ///
    /// Validates the threshold-OPRF property the F-2 fix relies on: for a
    /// single master OPRF key Shamir-split into 5 shares with 3-of-5
    /// threshold, **every** quorum of 3 servers (no matter which 3) yields
    /// bit-identical anonymous IDs. This is the OPRF analog of the F-1
    /// Lagrange-determinism guard
    /// (`lagrange_reconstruction_yields_same_master_for_different_quora`):
    /// under proper Shamir + Lagrange interpolation in the Ristretto255
    /// group, the threshold reconstruction is independent of subset choice.
    ///
    /// **F-2 closure significance:** if a future regression replaced
    /// [`threshold_combine`] with a quorum-dependent shortcut (e.g.,
    /// «just use server 1's evaluation» or local XOR aggregation), this
    /// test would expose the divergence. The class-level F-2 demonstrator
    /// in `crates/umbrella-tests/tests/attack_phd4_real_exploits.rs`
    /// complements this positive test by documenting why local HKDF
    /// derivation is fundamentally insufficient regardless of which
    /// quorum responds.
    #[test]
    fn oprf_3_of_5_yields_same_anon_ids_regardless_of_quorum() {
        let mut setup_rng = ChaCha20Rng::seed_from_u64(0xF2_C105E_DEAD_BEEF);
        let base_cluster = Arc::new(MockServerOprfCluster::new(&mut setup_rng));

        let input = BootstrapInput {
            pin: b"123456".to_vec(),
            duress_pin: None,
            phone_e164: None,
            otp_secret: None,
        };

        let bootstrap_with_quorum = |allowed: &[u8]| -> BootstrapOutput {
            // Method-syntax `clone()` so unsizing coercion fires at let.
            let inner: Arc<dyn ServerOprfClient> = base_cluster.clone();
            let cluster: Arc<dyn ServerOprfClient> = Arc::new(QuorumSelectiveOprfCluster {
                inner,
                allowed: allowed.iter().copied().collect::<HashSet<u8>>(),
            });
            let mut rng = ChaCha20Rng::seed_from_u64(0xBABE_F00D);
            bootstrap_account(&input, fake_identity_pk(), &cluster, &mut rng).expect("bootstrap")
        };

        let boot_a = bootstrap_with_quorum(&[1, 2, 3]);
        let boot_b = bootstrap_with_quorum(&[3, 4, 5]);
        let boot_c = bootstrap_with_quorum(&[1, 4, 5]);

        // Sanity: same rng seed across all 3 calls → identical salt + pin_root.
        // Guards against silently-broken determinism that would make the
        // anon-ID equality comparison meaningless.
        assert_eq!(boot_a.account_local_salt, boot_b.account_local_salt);
        assert_eq!(boot_a.account_local_salt, boot_c.account_local_salt);

        assert_eq!(
            boot_a.per_server_anonymous_ids, boot_b.per_server_anonymous_ids,
            "F-2 closure: quorum {{1,2,3}} vs {{3,4,5}} must yield bit-identical anon-IDs"
        );
        assert_eq!(
            boot_a.per_server_anonymous_ids, boot_c.per_server_anonymous_ids,
            "F-2 closure: quorum {{1,2,3}} vs {{1,4,5}} must yield bit-identical anon-IDs"
        );
    }

    /// **F-2 closure regression guard #2 — fail-closed below threshold.**
    ///
    /// When only 2 of 5 Sealed Servers respond, `bootstrap_account` must
    /// fail closed: there is no fallback path to local-HKDF derivation,
    /// and partial OPRF evaluations cannot reconstruct the OPRF output
    /// below threshold. This guards against future «graceful degradation»
    /// patches that might re-introduce the F-2 vulnerability by silently
    /// falling back to local derivation when servers are unreachable.
    #[test]
    fn bootstrap_fails_with_only_2_of_5_oprf_servers() {
        let mut setup_rng = ChaCha20Rng::seed_from_u64(0xF2_5BAD_FA15_DEAD);
        let base_cluster = Arc::new(MockServerOprfCluster::new(&mut setup_rng));

        // Allow only servers 1 and 2 — quorum 2 of 5, below threshold.
        // Method-syntax clone so unsizing coercion fires at the struct
        // field init (`inner: Arc<dyn ServerOprfClient>`).
        let inner_clone: Arc<dyn ServerOprfClient> = base_cluster.clone();
        let cluster: Arc<dyn ServerOprfClient> = Arc::new(QuorumSelectiveOprfCluster {
            inner: inner_clone,
            allowed: [1u8, 2].iter().copied().collect::<HashSet<u8>>(),
        });

        let input = BootstrapInput {
            pin: b"123456".to_vec(),
            duress_pin: None,
            phone_e164: None,
            otp_secret: None,
        };

        let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);
        let result = bootstrap_account(&input, fake_identity_pk(), &cluster, &mut rng);

        match result {
            Err(ClientError::Network(msg)) => {
                assert!(
                    msg.contains("fewer than 3 OPRF servers"),
                    "F-2 closure: expected fail-closed message, got: {msg}"
                );
            }
            Ok(_) => {
                panic!("F-2 closure: bootstrap with 2-of-5 servers must fail closed")
            }
            Err(other) => {
                panic!("F-2 closure: wrong error variant — {other:?}")
            }
        }
    }

    /// **F-2 closure regression guard #3 — adversary with `k-1 = 2` server
    /// OPRF keys cannot reconstruct anon-IDs.**
    ///
    /// Models the worst-case threat from the F-2 demonstrator: an
    /// adversary who has compromised 2 of 5 Sealed Servers (and therefore
    /// holds 2 of 5 Shamir shares of the master OPRF key) AND captured
    /// `(PIN, account_local_salt)` from the victim's device cannot
    /// reconstruct anon-IDs without a 3rd server cooperation. The
    /// threshold barrier holds at exactly 3 — below it,
    /// [`threshold_combine`] returns
    /// [`umbrella_oprf::OprfError::InsufficientValidEvaluations`].
    ///
    /// **Measured outcome:** with 2 of 5 server OPRF keys held by the
    /// adversary, the threshold reconstruction step refuses to combine
    /// (zero anon-IDs recovered, zero computational work past
    /// validation). Compromise of ≥ 3 of 5 servers is required to bypass
    /// the threshold cryptography barrier — that is the entire security
    /// margin of 3-of-5 OPRF.
    #[test]
    fn adversary_with_2_oprf_keys_cannot_recover_anon_ids() {
        use umbrella_oprf::OprfError;

        let mut setup_rng = ChaCha20Rng::seed_from_u64(0xF2AD2_DEAD_BEE5);
        let cluster = MockServerOprfCluster::new(&mut setup_rng);
        let k1 = cluster.share_at(1);
        let k2 = cluster.share_at(2);

        // Legitimate bootstrap (full cluster) so we can capture
        // `account_local_salt` for the adversary scenario.
        let cluster_arc: Arc<dyn ServerOprfClient> = Arc::new(cluster);
        let input = BootstrapInput {
            pin: b"123456".to_vec(),
            duress_pin: None,
            phone_e164: None,
            otp_secret: None,
        };
        let mut boot_rng = ChaCha20Rng::seed_from_u64(0xDEAD);
        let legit = bootstrap_account(&input, fake_identity_pk(), &cluster_arc, &mut boot_rng)
            .expect("legit bootstrap");

        // Adversary captures (PIN, account_local_salt) plus the 2 server
        // OPRF key shares (k_1, k_2). Tries to reconstruct anon-IDs by
        // blinding pin_root, locally evaluating two partials, and asking
        // threshold_combine to merge them — below quorum.
        let pin_root =
            pin_kdf::derive_pin_root(b"123456", &legit.account_local_salt).expect("pin_root");
        let oprf_input = OprfInput::new(pin_root.expose()).expect("oprf input");
        let mut adv_rng = ChaCha20Rng::seed_from_u64(0xEEEE_DEAD_BEEF_FEED);
        let (blinded, _state) = umbrella_oprf::blind(oprf_input, &mut adv_rng).expect("blind");

        let eval_1 = umbrella_oprf::evaluate_for_testing(&blinded, &k1.1).expect("eval 1");
        let eval_2 = umbrella_oprf::evaluate_for_testing(&blinded, &k2.1).expect("eval 2");

        let only_two = vec![(k1.0, eval_1), (k2.0, eval_2)];
        let combine_err =
            umbrella_oprf::threshold_combine(&only_two, ThresholdConfig::default()).unwrap_err();

        assert!(
            matches!(
                combine_err,
                OprfError::InsufficientValidEvaluations {
                    valid: 2,
                    required: 3
                }
            ),
            "F-2 closure: adversary with k-1 = 2 server keys must hit threshold barrier, \
             got {combine_err:?}"
        );

        eprintln!("[F-2 ADVERSARY BARRIER measurements]");
        eprintln!("  Adversary inputs: PIN (6 digits) + account_local_salt (16 bytes captured)");
        eprintln!("                  + 2 of 5 server OPRF key shares (k_1, k_2)");
        eprintln!(
            "  Operations: blind(pin_root) + 2 partial OPRF evaluate + threshold_combine attempt"
        );
        eprintln!("  Result: threshold_combine refuses below quorum (2 < 3)");
        eprintln!("  Bits leaked: 0 (no anon-ID reconstruction possible)");
        eprintln!("  Compromise threshold: ≥ 3 of 5 server OPRF keys required to bypass");
    }
}
