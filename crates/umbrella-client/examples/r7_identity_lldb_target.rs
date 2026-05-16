//! R7+R8 — REAL lldb memory inspection target for identity_sk + SQLite master_key.
//!
//! PhD-B Device-Capture Defense audit (round 4, 2026-05-19). Builds a real
//! identity from a BIP-39 mnemonic using a known 32-byte entropy needle,
//! derives the Ed25519 identity signing key, opens a real `SqliteMetadataStore`
//! with a known 32-byte master-key needle, inserts a chat message, then
//! parks at named lldb breakpoints.
//!
//! ## Needle protocol
//!
//! Three independent needles to disambiguate which secret is observable:
//!
//! - **0xCD repeated 32 times** — BIP-39 entropy that produces the identity
//!   seed. Search after `bootstrap_identity` should find ≥ 1 match (zeroize
//!   protects post-drop only; while seed is live it lives in heap via
//!   `IdentitySeed { entropy: [u8; 32], ... }`).
//! - **0xDC repeated 32 times** — explicit master-key passed to
//!   `SqliteMetadataStore::open`. After `open()` returns, the master-key
//!   sits inside `RowCipher::master_key: SecretBox<[u8; 32]>` — a
//!   `Box<[u8; 32]>` on the heap.
//! - **First 32 bytes of the derived Ed25519 signing key** — bytes obtained
//!   from `IdentityKey::derive(&seed, 0)` via `to_seed_bytes()`. These are
//!   the real **identity_sk** as held by `ed25519_dalek::SigningKey` inside
//!   `PrivateSigningKey(SigningKey)`.
//!
//! Per round-2 R6 methodology: 1 MB chunked stride read of every writable
//! memory region, `data.find(needle, idx)` per 32-byte slice. Found-count is
//! the empirical metric, not the existence of the type wrapper.
//!
//! ## Usage
//!
//! ```text
//! cargo build --profile r6-release --example r7_identity_lldb_target -p umbrella-client
//! ./docs/audits/device-capture-artifacts/r7_lldb_scan.sh
//! ```

use umbrella_client::keystore::{SqliteMetadataStore, SqliteStoreConfig};
use umbrella_identity::{IdentityKey, IdentitySeed, MnemonicLanguage};
use bip39::{Language, Mnemonic};
use std::path::PathBuf;

/// Known needles for R7+R8 lldb scan.
const ENTROPY_NEEDLE: [u8; 32] = [0xCDu8; 32];
const MASTER_KEY_NEEDLE: [u8; 32] = [0xDCu8; 32];

/// `lldb` breakpoint target: BEFORE any secret is in memory.
#[inline(never)]
pub fn r7_phase_before_bootstrap() {
    eprintln!("[R7] PHASE BEFORE bootstrap");
    std::hint::black_box(0u8);
}

/// `lldb` breakpoint target: AFTER identity bootstrapped + sqlite store opened.
/// At this point: entropy lives in `IdentitySeed.entropy`; identity_sk in
/// `PrivateSigningKey(SigningKey)`; master_key in `RowCipher.master_key`.
#[inline(never)]
pub fn r7_phase_live_identity() {
    eprintln!("[R7] PHASE LIVE identity (seed, identity_sk, master_key all live)");
    std::hint::black_box(0u8);
}

/// `lldb` breakpoint target: AFTER explicit drop of seed and store.
/// At this point: zeroize should have wiped entropy + master_key.
#[inline(never)]
pub fn r7_phase_after_drop() {
    eprintln!("[R7] PHASE AFTER drop");
    std::hint::black_box(0u8);
}

/// Helper to convince LLVM these byte arrays must be reachable from stack.
#[inline(never)]
pub fn r7_break_after_needle_alive() {
    std::hint::black_box(0xCDu8);
}

fn main() {
    eprintln!("[R7] Process pid {} starting", std::process::id());

    // POSITIVE CONTROL: hold a Vec<u8> of the entropy needle alive to verify
    // the lldb scanner methodology works against this binary. If POS_CTRL=0
    // we cannot trust the AFTER_LIVE result.
    let pos_ctrl: Vec<u8> = vec![0xCDu8; 32];
    eprintln!(
        "[R7] POSITIVE CONTROL: holding 32 bytes 0xCD at {:p}",
        pos_ctrl.as_ptr()
    );
    r7_break_after_needle_alive();
    std::hint::black_box(&pos_ctrl);

    r7_phase_before_bootstrap();

    // Build identity from KNOWN 32-byte entropy = 0xCD repeated. BIP-39
    // accepts any 32-byte entropy; we use this as our identity_sk lineage
    // needle.
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &ENTROPY_NEEDLE)
        .expect("32-byte entropy is always valid BIP-39 input");
    let phrase = mnemonic.to_string();
    eprintln!(
        "[R7] BIP-39 mnemonic from 0xCD-entropy: first 3 words = {}",
        phrase.split_whitespace().take(3).collect::<Vec<_>>().join(" ")
    );

    let seed = IdentitySeed::from_mnemonic(&phrase, MnemonicLanguage::English)
        .expect("freshly generated phrase must restore");

    // Derive identity_sk Ed25519 SigningKey via canonical path.
    let identity = IdentityKey::derive(&seed, 0).expect("identity derive");
    let identity_pubkey = identity.public().to_bytes();
    eprintln!(
        "[R7] identity_pubkey first 4 bytes = {:02x}{:02x}{:02x}{:02x}",
        identity_pubkey[0], identity_pubkey[1], identity_pubkey[2], identity_pubkey[3]
    );

    // Open SqliteMetadataStore with an explicit known 32-byte master key.
    // This is exactly the path called from native bridge in Block 7.10+:
    // `derive_storage_master_key` returns a [u8; 32], which is passed to
    // `SqliteMetadataStore::open(_, master_key)`.
    let db_path = std::env::temp_dir().join("r7_identity_capture.sqlite");
    let _ = std::fs::remove_file(&db_path);
    let cfg = SqliteStoreConfig {
        db_path: db_path.clone(),
        max_connections: 2,
    };
    let store = SqliteMetadataStore::open(cfg.clone(), MASTER_KEY_NEEDLE)
        .expect("open sqlite store with 0xDC master key");

    // Put one real message so we can also scan the DB file for plaintext
    // leak in R8 (file-on-disk inspection).
    store
        .put_message(
            &[0x11u8; 16],
            &[0x22u8; 32],
            1_700_000_000_000,
            &identity_pubkey,
            "R7_LLDB_PLAINTEXT_NEEDLE: this string must NOT appear in DB file",
        )
        .expect("put_message");

    eprintln!(
        "[R7] sqlite store opened + 1 message stored at {}",
        db_path.display()
    );

    // Hold all secrets alive across phase breakpoint.
    std::hint::black_box(&seed);
    std::hint::black_box(&identity);
    std::hint::black_box(&store);

    r7_phase_live_identity();

    // Pause for attach-mode scan: if env var R7_PAUSE is set, sleep so an
    // external lldb attach can scan live memory without batch-mode quirks.
    if std::env::var("R7_PAUSE").is_ok() {
        eprintln!("[R7] PAUSING for 60s — attach with: lldb -p {}", std::process::id());
        std::thread::sleep(std::time::Duration::from_secs(60));
    }

    // Force-drop the live secrets so AFTER_DROP phase observes zeroize'd state.
    std::hint::black_box(&seed);
    drop(seed);
    std::hint::black_box(&identity);
    drop(identity);
    std::hint::black_box(&store);
    drop(store);

    r7_phase_after_drop();

    // Second pause window for the AFTER_DROP phase.
    if std::env::var("R7_PAUSE").is_ok() {
        eprintln!(
            "[R7] PAUSING AFTER_DROP for 60s — attach window for verifying zeroize"
        );
        std::thread::sleep(std::time::Duration::from_secs(60));
    }

    // Print path for the R8 disk dump step.
    eprintln!("[R7] DB file kept at {}", db_path.display());
    eprintln!("[R7] (intentionally NOT deleted; R8 scanner reads it)");
}

#[allow(dead_code)]
fn _unused() -> (PathBuf, [u8; 32]) {
    (PathBuf::new(), MASTER_KEY_NEEDLE)
}
