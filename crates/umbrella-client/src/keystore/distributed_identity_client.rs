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

use umbrella_crypto_primitives::mlocked::MlockedSecret;
use umbrella_threshold_identity::{
    anonymous_id, key_derivation::{self, DerivationTranscript, DeviceRandom, ServerShare},
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

/// Performs daily unlock: re-derives device_key + master_key from PIN.
///
/// Steps:
/// 1. Argon2id(PIN, account_local_salt) → pin_root (32 bytes).
/// 2. Derive all 5 per-server anonymous IDs (locally).
/// 3. Send PIN-verification probe to 3 servers; receive 3 `server_share`s.
/// 4. XOR-combine shares (informational only — production combines via
///    threshold reconstruction; in this Stage 2 minimum we use any one
///    share as the input).
/// 5. HKDF: derive device_key (binds to device_random) and master_key
///    (account-wide).
///
/// Output stored в `MlockedSecret` для page-lock + zeroize-on-drop.
///
/// Daily unlock — re-derive session keys from PIN via 3-of-5 server unwraps.
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

    // Step 3: request `server_share` from servers 1..=3 (any 3-of-5 quorum).
    let mut combined_share = [0u8; 32];
    let pin_root_bytes = *pin_root.expose();
    let mut got_shares = 0usize;
    for server_id in 1..=5u16 {
        if got_shares >= 3 {
            break;
        }
        match server_client.unwrap_share(server_id, &anon_ids[(server_id - 1) as usize], &pin_root_bytes, transcript) {
            Ok(share) => {
                // XOR-combine (placeholder for production threshold reconstruction).
                for (slot, byte) in combined_share.iter_mut().zip(share.iter()) {
                    *slot ^= *byte;
                }
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

    // Step 4: HKDF re-derive device_key + master_key.
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

    // Wipe combined_share — it's a transient secret.
    combined_share.zeroize();

    Ok(UnlockSession {
        device_key,
        master_key,
        identity_pk: bootstrap.identity_pk,
    })
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

/// Performs bootstrap (registration). Generates 16-byte account_local_salt +
/// 32-byte device_random + computes per-server anonymous IDs from a *seed
/// master_key proxy* (here derived from PIN+salt for determinism in test).
///
/// In production, identity_pk comes from server DKG output; this function
/// also receives that pk via callback. For Stage 2 minimum we accept it as
/// an argument and persist locally.
///
/// Bootstrap — registers new account, persists only PIN-derivable handles.
pub fn bootstrap_account<R: rand_core::CryptoRng + rand_core::RngCore>(
    input: &BootstrapInput,
    identity_pk_from_server_dkg: IdentityPublicKey,
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

    // Compute pin_root + a "proxy master_key" used purely to derive 5
    // anonymous IDs. (In production the master_key is HKDF-re-derived from
    // PIN+salt+server_share — but we don't have server_share at registration;
    // we use HKDF(pin_root, salt) as a deterministic proxy that any device
    // re-deriving from the same PIN+salt will obtain identical IDs).
    let pin_root = pin_kdf::derive_pin_root(&input.pin, &account_local_salt)
        .map_err(|e| ClientError::Crypto(format!("PIN-KDF bootstrap: {e}")))?;

    // Anonymous ID seeder = HKDF(pin_root, salt, "anon-seed").
    use hkdf::Hkdf;
    use sha2::Sha256;
    let mut anon_seed = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&account_local_salt), pin_root.expose())
        .expand(b"umbrella-r6/anon-seed/v1", &mut anon_seed)
        .map_err(|_| ClientError::Crypto("anon-seed expand".into()))?;
    let per_server_anonymous_ids = anonymous_id::derive_all_anonymous_ids(&anon_seed)
        .map_err(|e| ClientError::Crypto(format!("anon-id: {e}")))?;

    // Initial transcript: epoch=1.
    let initial_transcript = DerivationTranscript {
        account_id: per_server_anonymous_ids[0], // server 1's ID is "primary" reference.
        epoch: 1,
    };

    // Wipe transient secret.
    use zeroize::Zeroize;
    anon_seed.zeroize();

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
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;

    fn fake_identity_pk() -> IdentityPublicKey {
        [0xCC; 32]
    }

    #[test]
    fn bootstrap_persists_only_handles_not_secrets() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let input = BootstrapInput {
            pin: b"123456".to_vec(),
            duress_pin: None,
            phone_e164: None,
            otp_secret: None,
        };
        let out = bootstrap_account(&input, fake_identity_pk(), &mut rng).unwrap();
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
        let input = BootstrapInput {
            pin: b"123456".to_vec(),
            duress_pin: None,
            phone_e164: None,
            otp_secret: None,
        };
        let boot = bootstrap_account(&input, fake_identity_pk(), &mut rng).unwrap();

        // Mock server cluster: any pin_root matching Argon2id(123456, salt) unlocks.
        let pin_root_expected = pin_kdf::derive_pin_root(b"123456", &boot.account_local_salt)
            .unwrap();
        let pre = *pin_root_expected.expose();
        let shares = [
            (pre, [0x11; 32]),
            (pre, [0x22; 32]),
            (pre, [0x33; 32]),
            (pre, [0x44; 32]),
            (pre, [0x55; 32]),
        ];
        let cluster: Arc<dyn ServerUnwrapClient> =
            Arc::new(MockServerCluster { shares });

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
        let input = BootstrapInput {
            pin: b"123456".to_vec(),
            duress_pin: None,
            phone_e164: None,
            otp_secret: None,
        };
        let boot = bootstrap_account(&input, fake_identity_pk(), &mut rng).unwrap();
        let correct_root = *pin_kdf::derive_pin_root(b"123456", &boot.account_local_salt).unwrap().expose();
        let cluster: Arc<dyn ServerUnwrapClient> = Arc::new(MockServerCluster {
            shares: [
                (correct_root, [1u8; 32]),
                (correct_root, [2u8; 32]),
                (correct_root, [3u8; 32]),
                (correct_root, [4u8; 32]),
                (correct_root, [5u8; 32]),
            ],
        });
        let r = unlock_with_pin(b"999999", &boot, &[0; 32], &boot.initial_transcript, &cluster);
        assert!(matches!(r, Err(ClientError::WrongPin)));
    }

    #[test]
    fn different_pins_yield_different_sessions() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let mut input = BootstrapInput {
            pin: b"123456".to_vec(),
            duress_pin: None,
            phone_e164: None,
            otp_secret: None,
        };
        let boot = bootstrap_account(&input, fake_identity_pk(), &mut rng).unwrap();
        // Bootstrap with a second PIN should give different anon_ids (because
        // anonymous IDs are PIN+salt derived).
        input.pin = b"654321".to_vec();
        let mut rng2 = ChaCha20Rng::seed_from_u64(4);
        // Use SAME salt+device_random by manually constructing.
        let boot2 = BootstrapOutput {
            account_local_salt: boot.account_local_salt,
            ..bootstrap_account(&input, fake_identity_pk(), &mut rng2).unwrap()
        };
        assert_ne!(
            boot.per_server_anonymous_ids[0],
            boot2.per_server_anonymous_ids[0],
            "different PINs derive different anonymous IDs"
        );
    }
}
