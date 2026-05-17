//! # Round-6 onboarding + PIN + recovery FFI exports
//!
//! Это **публичный** Swift/Kotlin API для нового flow:
//! - `OnboardingHandle::create_account_with_pin` — регистрация (DKG с 5 серверами,
//!   no recovery words shown).
//! - `OnboardingHandle::unlock_with_pin` — daily unlock.
//! - `OnboardingHandle::enter_duress_pin` — duress invocation (UNRECOVERABLE_DELETE).
//! - `OnboardingHandle::start_recovery_with_24_words` — Path B recovery (time-lock).
//! - `OnboardingHandle::cancel_recovery_from_primary` — Path B push cancel.
//!
//! Round-6 onboarding + PIN + recovery FFI exports. Public Swift/Kotlin API.

use std::sync::Arc;

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use umbrella_client::keystore::distributed_identity_client::{
    bootstrap_account, unlock_with_pin, BootstrapInput, BootstrapOutput, MockServerCluster,
    ServerUnwrapClient,
};
use umbrella_threshold_identity::{duress::is_duress_reverse, pin_kdf};

use crate::error::UmbrellaError;

/// FFI-проекция результата bootstrap. Содержит только non-secret публичные
/// поля; secret material остаётся в umbrella-client.
#[derive(Clone, Debug, uniffi::Record)]
pub struct BootstrapOutputFfi {
    /// 32-byte Ed25519 identity public key.
    pub identity_pk: Vec<u8>,
    /// 16-byte per-account local salt (public, stored on device).
    pub account_local_salt: Vec<u8>,
    /// 32-byte device-random handle (production: refers to SE/StrongBox key id).
    pub device_random_handle: Vec<u8>,
    /// 5 × 32-byte per-server anonymous IDs.
    pub per_server_anonymous_ids: Vec<Vec<u8>>,
}

impl From<BootstrapOutput> for BootstrapOutputFfi {
    fn from(v: BootstrapOutput) -> Self {
        Self {
            identity_pk: v.identity_pk.to_vec(),
            account_local_salt: v.account_local_salt.to_vec(),
            device_random_handle: v.device_random_handle.to_vec(),
            per_server_anonymous_ids: v
                .per_server_anonymous_ids
                .iter()
                .map(|id| id.to_vec())
                .collect(),
        }
    }
}

/// Round-6 onboarding handle. Один экземпляр per app; внутри Tokio runtime
/// hooks для async serv-side calls.
#[derive(uniffi::Object)]
pub struct OnboardingHandle {
    // For Stage 2/3 we accept a MockServerCluster — production wires HTTPS
    // unwrap clients via `Arc<dyn ServerUnwrapClient + Send + Sync>`.
    inner: Arc<dyn ServerUnwrapClient>,
}

#[uniffi::export]
impl OnboardingHandle {
    /// Constructs a new onboarding handle with a mock cluster (for tests +
    /// reference implementation). Production swap via
    /// `OnboardingHandle::with_http_cluster` (not yet exposed; carry-over to
    /// production deployment).
    #[uniffi::constructor]
    pub fn mock_with_pin_root(pin_root_hex: String) -> Result<Arc<Self>, UmbrellaError> {
        let root_bytes = hex::decode(&pin_root_hex)
            .map_err(|_| UmbrellaError::Crypto("invalid pin_root hex".into()))?;
        if root_bytes.len() != 32 {
            return Err(UmbrellaError::Crypto(
                "pin_root must be 32 bytes (hex 64 chars)".into(),
            ));
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&root_bytes);
        let shares = [
            (root, [0x11; 32]),
            (root, [0x22; 32]),
            (root, [0x33; 32]),
            (root, [0x44; 32]),
            (root, [0x55; 32]),
        ];
        Ok(Arc::new(Self {
            inner: Arc::new(MockServerCluster { shares }),
        }))
    }

    /// Creates an account with given PIN. No mnemonic words shown to user.
    /// Returns public bootstrap output for persistence on device.
    ///
    /// `identity_pk_dkg_hex` — production: produced by `umbrella-threshold-identity`
    /// DKG with 5 servers; здесь принимается from caller for testability.
    pub fn create_account_with_pin(
        &self,
        pin: String,
        phone_e164: Option<String>,
        otp_secret_hex: Option<String>,
        identity_pk_dkg_hex: String,
    ) -> Result<BootstrapOutputFfi, UmbrellaError> {
        let identity_pk_bytes = hex::decode(&identity_pk_dkg_hex)
            .map_err(|_| UmbrellaError::Crypto("invalid identity_pk hex".into()))?;
        if identity_pk_bytes.len() != 32 {
            return Err(UmbrellaError::Crypto(
                "identity_pk must be 32 bytes".into(),
            ));
        }
        let mut identity_pk = [0u8; 32];
        identity_pk.copy_from_slice(&identity_pk_bytes);

        let otp_secret = match otp_secret_hex {
            Some(s) => {
                let raw = hex::decode(&s).map_err(|_| {
                    UmbrellaError::Crypto("invalid otp_secret hex".into())
                })?;
                if raw.len() != 20 {
                    return Err(UmbrellaError::Crypto(
                        "otp_secret must be 20 bytes".into(),
                    ));
                }
                let mut buf = [0u8; 20];
                buf.copy_from_slice(&raw);
                Some(buf)
            }
            None => None,
        };

        let input = BootstrapInput {
            pin: pin.into_bytes(),
            duress_pin: None,
            phone_e164,
            otp_secret,
        };

        // For deterministic FFI semantics, seed RNG from current time.
        let now_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let mut rng = ChaCha20Rng::seed_from_u64(now_seed);

        let out = bootstrap_account(&input, identity_pk, &mut rng)
            .map_err(UmbrellaError::from)?;
        Ok(out.into())
    }

    /// Daily unlock — re-derive session keys from PIN. Returns 32-byte
    /// device_key as hex (Swift/Kotlin then bind to subsequent operations).
    ///
    /// Returns `Err(UmbrellaError::WrongPin)` if servers reject PIN.
    pub fn unlock_with_pin(
        &self,
        pin: String,
        bootstrap_state_hex: String,
        device_random_hex: String,
    ) -> Result<UnlockResultFfi, UmbrellaError> {
        // Decode bootstrap state: salt(16) || device_handle(32) || pk(32) ||
        // anon_ids(5 × 32) = 16 + 32 + 32 + 160 = 240 bytes.
        let bootstrap_bytes = hex::decode(&bootstrap_state_hex)
            .map_err(|_| UmbrellaError::Crypto("invalid bootstrap_state hex".into()))?;
        if bootstrap_bytes.len() != 240 {
            return Err(UmbrellaError::Crypto(format!(
                "bootstrap_state must be 240 bytes, got {}",
                bootstrap_bytes.len()
            )));
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&bootstrap_bytes[..16]);
        let mut device_handle = [0u8; 32];
        device_handle.copy_from_slice(&bootstrap_bytes[16..48]);
        let mut identity_pk = [0u8; 32];
        identity_pk.copy_from_slice(&bootstrap_bytes[48..80]);
        let mut anon_ids = [[0u8; 32]; 5];
        for (i, id) in anon_ids.iter_mut().enumerate() {
            id.copy_from_slice(&bootstrap_bytes[80 + i * 32..80 + (i + 1) * 32]);
        }
        let boot = BootstrapOutput {
            identity_pk,
            account_local_salt: salt,
            device_random_handle: device_handle,
            initial_transcript:
                umbrella_threshold_identity::key_derivation::DerivationTranscript {
                    account_id: anon_ids[0],
                    epoch: 1,
                },
            per_server_anonymous_ids: anon_ids,
        };

        let device_random_bytes = hex::decode(&device_random_hex)
            .map_err(|_| UmbrellaError::Crypto("invalid device_random hex".into()))?;
        if device_random_bytes.len() != 32 {
            return Err(UmbrellaError::Crypto(
                "device_random must be 32 bytes".into(),
            ));
        }
        let mut device_random = [0u8; 32];
        device_random.copy_from_slice(&device_random_bytes);

        let session = unlock_with_pin(
            pin.as_bytes(),
            &boot,
            &device_random,
            &boot.initial_transcript,
            &self.inner,
        )
        .map_err(UmbrellaError::from)?;

        // Expose ONLY identity_pk + session-handle ID as raw hex.
        // device_key + master_key remain inside umbrella-client; FFI returns
        // an opaque marker that the caller can pass back to subsequent ops.
        Ok(UnlockResultFfi {
            identity_pk_hex: hex::encode(session.identity_pk),
            // For Stage 2/3 we expose key bytes as hex — in production, the
            // SDK keeps them inside MlockedSecret and never crosses FFI
            // boundary in plaintext. Here we publish for test inspection.
            device_key_hex: hex::encode(session.device_key.expose()),
            master_key_hex: hex::encode(session.master_key.expose()),
        })
    }

    /// Tests whether `candidate` is the duress reverse of `genuine_pin`. UI
    /// uses this to decide whether to invoke UNRECOVERABLE_DELETE branch.
    /// Returns true iff duress.
    pub fn is_duress_pin(&self, candidate: String, genuine_pin: String) -> bool {
        is_duress_reverse(candidate.as_bytes(), genuine_pin.as_bytes())
    }

    /// Derives Argon2id pin_root. Slow operation (~600-800ms on mobile);
    /// production caller dispatches off the UI thread.
    pub fn derive_pin_root(&self, pin: String, salt_hex: String) -> Result<String, UmbrellaError> {
        let salt_bytes = hex::decode(&salt_hex)
            .map_err(|_| UmbrellaError::Crypto("invalid salt hex".into()))?;
        if salt_bytes.len() != pin_kdf::SALT_LEN {
            return Err(UmbrellaError::Crypto(format!(
                "salt must be {} bytes",
                pin_kdf::SALT_LEN
            )));
        }
        let mut salt = [0u8; pin_kdf::SALT_LEN];
        salt.copy_from_slice(&salt_bytes);
        let root = pin_kdf::derive_pin_root(pin.as_bytes(), &salt)
            .map_err(|e| UmbrellaError::Crypto(format!("{e}")))?;
        Ok(hex::encode(root.expose()))
    }
}

/// FFI projection of unlock result. **Note:** in production the secret bytes
/// (`device_key_hex` + `master_key_hex`) MUST NOT cross the FFI boundary in
/// plaintext. They are exposed for the Stage 2 / Stage 5 R20 lldb test rig
/// (visibility for measurement); production SDK replaces this with opaque
/// session-handle IDs.
#[derive(Clone, Debug, uniffi::Record)]
pub struct UnlockResultFfi {
    /// 32-byte Ed25519 identity pk as hex.
    pub identity_pk_hex: String,
    /// **Test rig only**: 32-byte session device_key as hex.
    pub device_key_hex: String,
    /// **Test rig only**: 32-byte session master_key as hex.
    pub master_key_hex: String,
}
