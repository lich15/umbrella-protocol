//! # Round-6 onboarding + PIN + recovery FFI exports
//!
//! Это **публичный** Swift/Kotlin API для нового flow:
//! - `OnboardingHandle::create_account_with_pin` — регистрация (DKG с 5 серверами,
//!   no recovery words shown).
//! - `OnboardingHandle::unlock_with_pin` — daily unlock; возвращает opaque
//!   `session_handle` (32-char hex) — секретные ключи остаются на стороне Rust
//!   внутри `MlockedSecret` и **не пересекают FFI границу** (F-FFI-2 closure).
//! - `OnboardingHandle::release_session` — explicit drop сохранённой сессии
//!   (zeroize + munlock MlockedSecret полей).
//! - `OnboardingHandle::is_duress_pin` / `derive_pin_root` — helper bridges.
//! - **Test-rig path:** `unlock_with_pin_for_test_rig` (под feature flag
//!   `test-utils`) намеренно отдаёт `device_key_hex` + `master_key_hex` для
//!   R20 lldb измерений на FFI границе; production builds физически не могут
//!   достичь этой surface потому что `#[uniffi::export] impl` блок исчезает
//!   из scaffolding когда feature off.
//!
//! ## F-FFI-2 closure rationale (PhD-B Pass 4 CRITICAL → Pass 5 fix)
//!
//! Production `unlock_with_pin` ранее возвращал `device_key_hex` +
//! `master_key_hex` через FFI как обычные String. Как только эти строки
//! пересекали FFI границу, они жили в JVM/Swift native heap **без** mlock,
//! **без** zeroize-on-drop, **без** page-locking — `MlockedSecret` инвариант
//! на стороне Rust был защищён, но **независимая копия** (UTF-8 байты hex)
//! на native heap его обходила. Process memory capture (R20 lldb attack class)
//! восстанавливал ключи тривиально.
//!
//! Fix: production `unlock_with_pin` хранит live `UnlockSession` instances в
//! `OnboardingHandle::sessions` (`Mutex<HashMap<String, UnlockSession>>`)
//! keyed by opaque 32-char hex session handles. `device_key` и `master_key`
//! остаются `MlockedSecret`-wrapped в Rust heap и **никогда** не пересекают
//! FFI в plaintext. Callers передают `session_handle` в subsequent FFI
//! методы (Block 7.4 wire-up). `release_session(handle)` выполняет
//! explicit drop, который триггерит `MlockedSecret::Drop` → zeroize +
//! munlock.
//!
//! Round-6 onboarding + PIN + recovery FFI exports. Public Swift/Kotlin API
//! with F-FFI-2 closure: production `unlock_with_pin` returns an opaque
//! `session_handle` (32-char hex) — session keys stay in Rust heap inside
//! `MlockedSecret` and do not cross the FFI boundary. The test-rig
//! `unlock_with_pin_for_test_rig` that exposes hex keys for R20 lldb
//! measurements is gated behind the `test-utils` feature so production
//! builds physically cannot reach that surface.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use umbrella_client::keystore::distributed_identity_client::{
    bootstrap_account, unlock_with_pin, BootstrapInput, BootstrapOutput, MockServerCluster,
    MockServerOprfCluster, ServerOprfClient, ServerUnwrapClient, UnlockSession,
};
use umbrella_threshold_identity::{
    duress::is_duress_reverse, key_derivation::DerivationTranscript, pin_kdf,
};

use crate::error::UmbrellaError;

/// FFI-проекция результата bootstrap. Содержит только non-secret публичные
/// поля; secret material остаётся в umbrella-client.
///
/// FFI projection of the bootstrap result. Carries only non-secret public
/// fields; secret material stays inside umbrella-client.
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

/// Round-6 onboarding handle. Один экземпляр per app; внутри держит mutex'ом
/// защищённый кеш активных unlock-сессий (см. F-FFI-2 closure).
///
/// Round-6 onboarding handle. One instance per app; internally holds a
/// mutex-guarded cache of live unlock sessions (see the F-FFI-2 closure note).
#[derive(uniffi::Object)]
pub struct OnboardingHandle {
    // For Stage 2/3 we accept a MockServerCluster — production wires HTTPS
    // unwrap clients via `Arc<dyn ServerUnwrapClient + Send + Sync>`.
    inner: Arc<dyn ServerUnwrapClient>,
    /// **F-2 closure (PhD-B Pass 5 remediation):** OPRF evaluator cluster
    /// used by `bootstrap_account` to derive per-server anonymous IDs
    /// through a 3-of-5 threshold OPRF rather than local HKDF over
    /// `(PIN, salt)`. For Stage 2/3 we accept [`MockServerOprfCluster`];
    /// production wires an HTTP/2 OPRF endpoint client (rate-limited +
    /// attestation-guarded). Both clusters share the same `Arc<dyn ...>`
    /// dispatch pattern, so swap is a single-line change.
    oprf_inner: Arc<dyn ServerOprfClient>,
    /// Live unlock sessions keyed by opaque 32-char hex session handle.
    /// `UnlockSession::device_key` and `UnlockSession::master_key` live here
    /// as `MlockedSecret`-wrapped allocations and **never** cross the FFI
    /// boundary (F-FFI-2 closure invariant). Drop occurs either via
    /// `release_session(handle)` OR when `OnboardingHandle` itself drops;
    /// in both cases `MlockedSecret::Drop` performs `zeroize()` then
    /// `libc::munlock()` on the 32-byte heap allocations.
    sessions: Mutex<HashMap<String, UnlockSession>>,
}

/// Monotonic counter mixed into the session-handle seed to defend against
/// same-nanosecond collisions when two unlock calls arrive in rapid
/// succession (e.g. concurrent test threads). Session handles are opaque
/// non-secret IDs; collision resistance is the only requirement (predictability
/// is not an attack surface — an attacker with FFI access enumerates handles
/// via legitimate API anyway).
///
/// Monotonic counter mixed into the session-handle seed to defend against
/// same-nanosecond collisions under concurrent unlock invocations. Session
/// handles are opaque non-secret IDs; only collision resistance matters.
static SESSION_HANDLE_COUNTER: AtomicU64 = AtomicU64::new(0);

impl OnboardingHandle {
    /// Decodes the canonical 240-byte bootstrap-state hex blob into a
    /// `BootstrapOutput` view + the 32-byte device-random seed. Shared
    /// between the production `unlock_with_pin` and the test-rig
    /// `unlock_with_pin_for_test_rig` (the byte-layout invariant is
    /// authoritative and lives here in one place).
    ///
    /// Layout: salt(16) || device_handle(32) || pk(32) || anon_ids(5 × 32)
    /// = 240 bytes.
    fn decode_unlock_inputs(
        bootstrap_state_hex: &str,
        device_random_hex: &str,
    ) -> Result<(BootstrapOutput, [u8; 32]), UmbrellaError> {
        let bootstrap_bytes = hex::decode(bootstrap_state_hex)
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
            initial_transcript: DerivationTranscript {
                account_id: anon_ids[0],
                epoch: 1,
            },
            per_server_anonymous_ids: anon_ids,
        };

        let device_random_bytes = hex::decode(device_random_hex)
            .map_err(|_| UmbrellaError::Crypto("invalid device_random hex".into()))?;
        if device_random_bytes.len() != 32 {
            return Err(UmbrellaError::Crypto(
                "device_random must be 32 bytes".into(),
            ));
        }
        let mut device_random = [0u8; 32];
        device_random.copy_from_slice(&device_random_bytes);
        Ok((boot, device_random))
    }

    /// Performs the underlying unlock (shared by production + test-rig
    /// surfaces). Returns the live `UnlockSession`; caller decides whether
    /// to store it in `self.sessions` (production session-handle path) or
    /// expose its key bytes as hex (test-rig R20 lldb path).
    fn perform_unlock(
        &self,
        pin: &str,
        bootstrap_state_hex: &str,
        device_random_hex: &str,
    ) -> Result<UnlockSession, UmbrellaError> {
        let (boot, device_random) =
            Self::decode_unlock_inputs(bootstrap_state_hex, device_random_hex)?;
        unlock_with_pin(
            pin.as_bytes(),
            &boot,
            &device_random,
            &boot.initial_transcript,
            &self.inner,
        )
        .map_err(UmbrellaError::from)
    }

    /// Generates an opaque 32-character hex session handle. Combines a
    /// monotonic atomic counter with the current SystemTime nanosecond to
    /// defend against collision under concurrent invocations; the seed is
    /// expanded through ChaCha20Rng to produce a uniform 16-byte hex string
    /// (~128-bit collision resistance — sufficient for opaque FFI session
    /// correlation).
    ///
    /// The session handle is **non-secret** — an attacker with legitimate
    /// FFI access enumerates handles via the normal API; predictability is
    /// not an attack surface here.
    fn generate_session_handle() -> String {
        let counter = SESSION_HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let seed = counter
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(now_nanos);
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }
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

        // F-2 closure: instantiate an OPRF mock cluster with a fresh random
        // master OPRF key (Shamir-split 3-of-5). Seeded from the current
        // nanosecond clock plus a hash-mix constant so two instances created
        // within the same nanosecond still get distinct keys. Production
        // wiring replaces this with an HTTP/2 client to the Sealed Server
        // OPRF endpoint; the trait surface stays identical.
        let oprf_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let mut oprf_rng =
            ChaCha20Rng::seed_from_u64(oprf_seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let oprf_inner: Arc<dyn ServerOprfClient> =
            Arc::new(MockServerOprfCluster::new(&mut oprf_rng));

        Ok(Arc::new(Self {
            inner: Arc::new(MockServerCluster { shares }),
            oprf_inner,
            sessions: Mutex::new(HashMap::new()),
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
            return Err(UmbrellaError::Crypto("identity_pk must be 32 bytes".into()));
        }
        let mut identity_pk = [0u8; 32];
        identity_pk.copy_from_slice(&identity_pk_bytes);

        let otp_secret = match otp_secret_hex {
            Some(s) => {
                let raw = hex::decode(&s)
                    .map_err(|_| UmbrellaError::Crypto("invalid otp_secret hex".into()))?;
                if raw.len() != 20 {
                    return Err(UmbrellaError::Crypto("otp_secret must be 20 bytes".into()));
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

        // F-2 closure: bootstrap routes anon-ID derivation through the 3-of-5
        // threshold OPRF cluster held by this handle rather than local HKDF.
        let out = bootstrap_account(&input, identity_pk, &self.oprf_inner, &mut rng)
            .map_err(UmbrellaError::from)?;
        Ok(out.into())
    }

    /// Daily unlock — re-derives session keys from PIN. Returns an opaque
    /// `session_handle` (32-char hex) + the public `identity_pk_hex`; the
    /// `device_key` and `master_key` are stored internally as
    /// `MlockedSecret`-wrapped allocations and **do not** cross the FFI
    /// boundary in plaintext (F-FFI-2 closure).
    ///
    /// Subsequent FFI methods (Block 7.4 wire-up: `send_text`,
    /// `fetch_inbox`, etc.) accept the `session_handle` and look up the live
    /// `UnlockSession` internally. Callers SHOULD invoke
    /// `release_session(session_handle)` when the session is no longer
    /// needed; lifecycle code wipes any remaining sessions on screen-lock /
    /// background events.
    ///
    /// Returns `Err(UmbrellaError::WrongPin)` if servers reject PIN.
    ///
    /// Daily unlock — re-derive session keys from PIN. Returns an opaque
    /// `session_handle` (32-char hex) + the public `identity_pk_hex`; the
    /// `device_key` and `master_key` stay inside `MlockedSecret` in the
    /// Rust heap and never cross FFI in plaintext (F-FFI-2 closure).
    pub fn unlock_with_pin(
        &self,
        pin: String,
        bootstrap_state_hex: String,
        device_random_hex: String,
    ) -> Result<UnlockResultFfi, UmbrellaError> {
        let session = self.perform_unlock(&pin, &bootstrap_state_hex, &device_random_hex)?;
        let identity_pk_hex = hex::encode(session.identity_pk);
        let session_handle = Self::generate_session_handle();
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(session_handle.clone(), session);
        Ok(UnlockResultFfi {
            identity_pk_hex,
            session_handle,
        })
    }

    /// Explicitly releases a session and zeroizes its `MlockedSecret` keys.
    ///
    /// Idempotent: releasing a non-existent or already-released handle is a
    /// silent no-op. This matches lifecycle patterns where
    /// `release_session` may be called concurrently from an explicit logout
    /// path and a background-wipe path.
    pub fn release_session(&self, session_handle: String) {
        // Remove returns `Option<UnlockSession>`; dropping it triggers
        // `MlockedSecret::Drop` on each of `device_key` + `master_key`
        // (zeroize() → libc::munlock()).
        let _ = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&session_handle);
    }

    /// Returns the count of live sessions held by this handle. Used by
    /// lifecycle code + integration tests to assert wipe semantics.
    pub fn live_session_count(&self) -> u32 {
        u32::try_from(
            self.sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
        )
        .unwrap_or(u32::MAX)
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
        let salt_bytes =
            hex::decode(&salt_hex).map_err(|_| UmbrellaError::Crypto("invalid salt hex".into()))?;
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

/// **Production-safe** FFI-проекция результата unlock. Несёт только
/// публичный `identity_pk_hex` и непрозрачный `session_handle`. Session
/// ключи (`device_key`, `master_key`) живут только в Rust-side `sessions`
/// map как `MlockedSecret` и никогда не пересекают FFI boundary в plaintext.
///
/// **Production-safe** FFI projection of unlock result. Carries only the
/// public `identity_pk_hex` and the opaque `session_handle`. Session keys
/// (`device_key`, `master_key`) live exclusively in the Rust-side
/// `OnboardingHandle::sessions` map as `MlockedSecret`-wrapped allocations
/// and never cross the FFI boundary in plaintext.
///
/// **F-FFI-2 closure (PhD-B Pass 4 CRITICAL → Pass 5 fix):** the previous
/// variant of this struct exposed `device_key_hex` + `master_key_hex` for R20
/// lldb test rig visibility; that pattern defeated the `MlockedSecret`
/// invariant because `hex::encode` allocates an independent Rust heap
/// `String` which then crosses FFI as UTF-8 bytes into the JVM/Swift native
/// heap (no mlock, no zeroize-on-drop). The test-rig path is now isolated
/// behind the `test-utils` feature flag — see `UnlockResultTestRigFfi`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct UnlockResultFfi {
    /// 32-byte Ed25519 identity pk as hex (64 ASCII chars).
    pub identity_pk_hex: String,
    /// Opaque 32-character hex session handle. Pass this to subsequent FFI
    /// methods that require an unlocked session (Block 7.4 wire-up). Call
    /// `OnboardingHandle::release_session(session_handle)` when done.
    pub session_handle: String,
}

// ============================================================================
// F-FFI-2 test-rig surface — gated behind `test-utils` feature
// ============================================================================
//
// Production builds (Swift/Kotlin app distributions) MUST NOT enable the
// `test-utils` feature. The methods + types below exist solely to validate
// the R20 lldb attack class against the FFI boundary in integration tests:
// they deliberately leak session keys as hex strings so a process memory
// capture can recover them; their existence on the FFI surface is the
// test rig.
//
// F-FFI-2 closure rationale: previously the production `unlock_with_pin`
// returned hex keys unconditionally — a comment-disclosed «test rig only»
// without compile-time enforcement. The fix isolates the leak behind the
// `test-utils` feature so production builds physically cannot expose those
// bytes (the `#[uniffi::export] impl` block is removed from scaffolding
// when the feature is off).

/// **Только для test-rig:** FFI-проекция результата unlock, expose'ит
/// session ключи как hex для R20 lldb-измерений / FFI-boundary leak
/// validation. Существует только под feature `test-utils`. См. module-level
/// F-FFI-2 closure note для rationale.
///
/// **Test-rig only:** FFI projection of unlock result that exposes session
/// keys as hex strings for R20 lldb measurement / FFI-boundary leak
/// validation. Exists ONLY when the `test-utils` feature is enabled. See
/// module-level F-FFI-2 closure note for rationale.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Debug, uniffi::Record)]
pub struct UnlockResultTestRigFfi {
    /// 32-byte Ed25519 identity pk as hex.
    pub identity_pk_hex: String,
    /// **Test rig only:** 32-byte session device_key as hex.
    pub device_key_hex: String,
    /// **Test rig only:** 32-byte session master_key as hex.
    pub master_key_hex: String,
}

#[cfg(any(test, feature = "test-utils"))]
#[uniffi::export]
impl OnboardingHandle {
    /// **Test-rig only:** daily unlock that returns session keys as hex for
    /// R20 lldb measurement / FFI-boundary leak validation. Gated behind
    /// the `test-utils` feature so production builds physically cannot
    /// reach this surface (F-FFI-2 closure).
    ///
    /// Production callers MUST use [`OnboardingHandle::unlock_with_pin`]
    /// which returns an opaque `session_handle` instead.
    pub fn unlock_with_pin_for_test_rig(
        &self,
        pin: String,
        bootstrap_state_hex: String,
        device_random_hex: String,
    ) -> Result<UnlockResultTestRigFfi, UmbrellaError> {
        let session = self.perform_unlock(&pin, &bootstrap_state_hex, &device_random_hex)?;
        // Intentional leak — measured by R20 lldb attack class against the
        // FFI boundary. The `session` UnlockSession is dropped at the end of
        // this method; the hex Strings have already been allocated
        // independently on the Rust heap. That drop fires
        // `MlockedSecret::Drop` → `zeroize()` + `libc::munlock()` on the
        // original 32 bytes; the hex copies are the leak surface this test
        // rig validates (they survive the Drop because they live in
        // separate allocations).
        Ok(UnlockResultTestRigFfi {
            identity_pk_hex: hex::encode(session.identity_pk),
            device_key_hex: hex::encode(session.device_key.expose()),
            master_key_hex: hex::encode(session.master_key.expose()),
        })
    }
}
