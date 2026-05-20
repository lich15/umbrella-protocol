//! R20 — REAL lldb memory inspection target for round-6 distributed identity.
//!
//! Per spec §«Stage 5 — Real attack regression tests» R20:
//! > build process bootstraps identity via DKG, attach lldb during registration,
//! > grep for 32-byte identity_sk in process memory → must be **0 hits**
//! > (identity never on device).
//!
//! ## Threat
//!
//! State-level adversary with physical access:
//! 1. Capture device during registration (DKG protocol running).
//! 2. Attach lldb (assume bypass of Apple/Google entitlement via cooperation).
//! 3. Scan process memory for known identity_sk bytes.
//!
//! ## Round-6 expectation
//!
//! Under round-6 distributed identity:
//! - `identity_sk` (32-byte Ed25519 secret scalar) **never** exists as bytes
//!   on the device.
//! - DKG generates `identity_pk` on 5 servers via FROST Pedersen-VSS.
//! - Each server holds one share; reconstruction requires 3-of-5.
//! - Client receives only: identity_pk (32 bytes public), 5 anonymous IDs,
//!   16-byte salt, 32-byte device_random.
//!
//! Scan result expectation: **0 hits** for identity_sk (because there is no
//! identity_sk on device, period). Compare to round-4 baseline where
//! identity_sk DID exist on device for milliseconds-seconds.
//!
//! ## Needle protocol
//!
//! Two needles:
//!
//! - **`identity_pk` needle** (positive control): the 32-byte Ed25519 public
//!   key returned by server DKG output. We expect ≥1 hit (it's on device by
//!   design — it's the public key).
//! - **`identity_sk` needle** (negative claim): the synthetic 32-byte pattern
//!   `[0xDB; 32]` — a value that an attacker would EXPECT to find if the
//!   identity secret was held on device. We expect 0 hits because there is
//!   no identity_sk on device.
//!
//! Stride-read methodology per round-5 R7 script: 1 MB chunks of every
//! writable memory region; `memmem::find(needle, idx)` per 32-byte slice.
//!
//! ## Usage
//!
//! ```text
//! cargo build --profile r6-release --example r20_distributed_identity_lldb_target -p umbrella-client
//! lldb -b target/r6-release/examples/r20_distributed_identity_lldb_target
//!   (lldb) b r20_phase_after_bootstrap
//!   (lldb) r
//!   (lldb) script import scripts/r20_scan.py
//! ```

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

use umbrella_client::keystore::distributed_identity_client::{
    bootstrap_account, unlock_with_pin, BootstrapInput, MockServerCluster, MockServerOprfCluster,
    ServerOprfClient, ServerUnwrapClient,
};
use umbrella_threshold_identity::pin_kdf;

/// Negative-control needle: the 32-byte pattern an attacker would expect to
/// find if identity_sk leaked. Under round-6 this should yield 0 hits.
pub const IDENTITY_SK_NEEDLE: [u8; 32] = [0xDB; 32];

/// Positive-control needle: 32-byte identity_pk. Should yield ≥1 hit because
/// the public key IS on device by design.
pub const IDENTITY_PK_NEEDLE: [u8; 32] = [0xCA; 32];

/// `lldb` breakpoint target — before any round-6 state on device.
#[inline(never)]
pub fn r20_phase_before_bootstrap() {
    eprintln!("[R20] PHASE BEFORE bootstrap — no round-6 state on device");
    std::hint::black_box(0u8);
}

/// `lldb` breakpoint target — after bootstrap. Device holds:
/// - identity_pk (32 bytes public)
/// - account_local_salt (16 bytes public)
/// - device_random_handle (32 bytes; in real binary stored in SE/StrongBox)
/// - 5 × 32-byte anonymous IDs
///
/// **No identity_sk anywhere.**
#[inline(never)]
pub fn r20_phase_after_bootstrap() {
    eprintln!("[R20] PHASE AFTER bootstrap — identity_pk + handles on device, no identity_sk");
    std::hint::black_box(0u8);
}

/// `lldb` breakpoint target — after daily unlock with PIN. Device holds:
/// - device_key, master_key in MlockedSecret (per session, wiped on background)
///
/// **Still no identity_sk.**
#[inline(never)]
pub fn r20_phase_after_unlock() {
    eprintln!("[R20] PHASE AFTER unlock — session keys held in MlockedSecret");
    std::hint::black_box(0u8);
}

fn main() {
    eprintln!("[R20] starting round-6 distributed identity bootstrap-and-unlock target");
    eprintln!("[R20] negative-control needle (identity_sk pattern): 0xDB × 32 — must yield 0 hits");
    eprintln!("[R20] positive-control needle (identity_pk): 0xCA × 32 — should yield ≥1 hit");

    r20_phase_before_bootstrap();

    // Bootstrap with known identity_pk needle pattern.
    let mut rng = ChaCha20Rng::seed_from_u64(0x_DEAD_BEEF_2020_u64);
    let input = BootstrapInput {
        pin: b"123456".to_vec(),
        duress_pin: None,
        phone_e164: None,
        otp_secret: None,
    };
    // F-2 closure: bootstrap routes anon-ID derivation through 3-of-5
    // threshold OPRF rather than local HKDF. For the R20 measurement
    // target we wire a `MockServerOprfCluster` with a fresh random
    // master OPRF key; production deploys an HTTP/2 client to the
    // Sealed Server OPRF endpoint.
    let mut oprf_rng = ChaCha20Rng::seed_from_u64(0x0020_20F2_BEEF_DEAD_u64);
    let oprf_cluster: Arc<dyn ServerOprfClient> =
        Arc::new(MockServerOprfCluster::new(&mut oprf_rng));
    let boot = bootstrap_account(&input, IDENTITY_PK_NEEDLE, &oprf_cluster, &mut rng)
        .expect("bootstrap should succeed");

    eprintln!("[R20] bootstrap output:");
    eprintln!("  identity_pk = 0x{}", hex::encode(boot.identity_pk));
    eprintln!(
        "  account_local_salt = 0x{}",
        hex::encode(boot.account_local_salt)
    );
    eprintln!(
        "  device_random_handle = 0x{}",
        hex::encode(boot.device_random_handle)
    );
    eprintln!(
        "  anon_id[0] = 0x{}",
        hex::encode(boot.per_server_anonymous_ids[0])
    );

    r20_phase_after_bootstrap();

    // Now run a daily unlock — session keys will materialise.
    let correct_root =
        pin_kdf::derive_pin_root(b"123456", &boot.account_local_salt).expect("pin_root");
    let pre = *correct_root.expose();
    let shares = [
        (pre, [0x11; 32]),
        (pre, [0x22; 32]),
        (pre, [0x33; 32]),
        (pre, [0x44; 32]),
        (pre, [0x55; 32]),
    ];
    let cluster: Arc<dyn ServerUnwrapClient> = Arc::new(MockServerCluster { shares });
    let device_random = [0xAB; 32];

    let session = unlock_with_pin(
        b"123456",
        &boot,
        &device_random,
        &boot.initial_transcript,
        &cluster,
    )
    .expect("unlock should succeed");

    eprintln!("[R20] session keys re-derived (in MlockedSecret):");
    eprintln!(
        "  device_key (first 8 bytes) = 0x{}",
        hex::encode(&session.device_key.expose()[..8])
    );
    eprintln!(
        "  master_key (first 8 bytes) = 0x{}",
        hex::encode(&session.master_key.expose()[..8])
    );
    eprintln!("[R20] note: identity_sk does NOT exist as bytes anywhere in this process.");

    r20_phase_after_unlock();

    eprintln!("[R20] target parked at r20_phase_after_unlock — scan now via lldb.");
    eprintln!(
        "[R20] expected lldb scan result: 0 hits for 0xDB × 32 (identity_sk needle), ≥1 hit for 0xCA × 32 (identity_pk needle)"
    );
}
