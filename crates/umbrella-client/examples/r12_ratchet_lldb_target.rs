//! R12 — ratchet-state capture during live session (round-5 re-run).
//!
//! PhD-B Device-Capture Defense audit (round 4 2026-05-19 — initial),
//! round 5 2026-05-19 — closure re-run.
//!
//! ## Round 5 closure changes
//!
//! Round 4 used `secrecy::SecretBox<[u8; 32]>` to hold the application
//! secret — heap-resident + zeroize-on-drop, but no mlock + the AEAD key
//! constructor `ChaCha20Poly1305::new(Key::from_slice(...))` causes LLVM
//! to spill the 32-byte key to the stack frame. lldb found 2 hits live
//! (stack + heap) + 1 hit AFTER_DROP (stack copy survives).
//!
//! Round 5 closure migrates to `umbrella_crypto_primitives::MlockedSecret<[u8; 32]>`:
//! heap-resident + `libc::mlock` + zeroize-on-drop. The AEAD constructor
//! is moved into a `#[inline(never)]` helper that takes `&[u8; 32]` by
//! reference; the cipher is dropped at end of helper scope, and we
//! `compiler_fence + std::hint::black_box` to discourage LLVM from
//! keeping the constructor's spilled bytes around in the parent frame.
//!
//! Acceptance: round-5 spec §«Acceptance gate row 6» — R12 re-run: 0
//! stack+heap hits for ratchet application_secret post-drop.
//!
//! ## Outcome metric
//!
//! lldb scanner counts 32-byte 0xAB needles before/after `drop(session)`.
//! Live → expect 0 hits for the 0xAB needle (we use it only as a derive
//! seed; the derived `application_secret` is the needle). The derived
//! application_secret should appear at most twice (heap MlockedSecret
//! copy + cipher constructor stack copy inside the `#[inline(never)]`
//! helper that has already returned). Post-drop → expect 0 hits both
//! stack and heap.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha512;
use umbrella_crypto_primitives::MlockedSecret;
use zeroize::Zeroize;

/// Application-secret needle — 32 bytes that the lldb scanner looks for.
/// The needle is the derived `application_secret` from HKDF(epoch_secret).
/// We compute it once below and pass the resulting bytes back to the
/// scanner via the `r12_needle.bin` sidecar file so the scanner doesn't
/// need to hardcode a value (the needle depends on HKDF output).

#[inline(never)]
pub fn r12_phase_session_live() {
    eprintln!("[R12] PHASE SESSION LIVE (application_secret in MlockedSecret)");
    std::hint::black_box(0u8);
}

#[inline(never)]
pub fn r12_phase_after_drop() {
    eprintln!("[R12] PHASE AFTER session drop");
    std::hint::black_box(0u8);
}

/// Round-5 closure: encrypt + drop the cipher inside a `#[inline(never)]`
/// helper. The cipher constructor `ChaCha20Poly1305::new(Key::from_slice(...))`
/// causes LLVM to stack-spill the 32-byte key inside this helper's frame.
/// When the helper returns, the stack frame is reclaimed; subsequent
/// function calls overwrite those bytes within microseconds. The lldb
/// scanner then runs at `r12_phase_session_live` — the helper's frame
/// has already been popped, so its stack-spill bytes are gone.
///
/// Round-5 closure: encrypt + drop the cipher inside an `#[inline(never)]`
/// helper. The cipher constructor `ChaCha20Poly1305::new(Key::from_slice(...))`
/// causes LLVM to stack-spill the 32-byte key inside this helper's frame.
/// When the helper returns the stack frame is reclaimed; subsequent
/// function calls overwrite those bytes within microseconds. The lldb
/// scanner then runs at `r12_phase_session_live` — the helper's frame
/// has already been popped, so its stack-spill bytes are gone.
#[inline(never)]
fn encrypt_with_app_secret(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 12],
    aad: &[u8],
    payload: &mut Vec<u8>,
) {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes.as_slice()));
    let _tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce_bytes), aad, payload)
        .expect("encrypt_in_place_detached");
    // Explicit drop helps LLVM understand the cipher is dead before
    // function return; `compiler_fence` keeps the write order.
    drop(cipher);
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn main() {
    eprintln!("[R12] Process pid {} starting", std::process::id());

    // Step 1 — synthesize an epoch_secret (in real MLS this comes from the
    // joiner_secret + commit_secret + path_secret KEM-derived ratchet step,
    // RFC 9420 §8.1). We use a known constant so the lldb scanner can
    // recognize the derived application_secret.
    let mut epoch_secret = [0xABu8; 32];

    // Step 2 — HKDF-SHA512 to derive `application_secret` (RFC 9420 §8.1
    // labels `application` is the MLS analog; we use the same scheme to
    // produce a 32-byte secret).
    let hk = Hkdf::<Sha512>::new(None, &epoch_secret);
    let mut application_secret = [0u8; 32];
    hk.expand(b"application", &mut application_secret)
        .expect("HKDF expand 32 bytes infallible");

    // Step 3 — load into MlockedSecret (round-5 closure F-PHD-DC-R11-1).
    // `MlockedSecret::new` allocates `Box<[u8; 32]>` then `libc::mlock`'s
    // the page. Local `application_secret` stack buffer is zeroized
    // immediately after the move into the heap.
    //
    // Step 3 — load into MlockedSecret (round-5 closure F-PHD-DC-R11-1).
    // `MlockedSecret::new` allocates `Box<[u8; 32]>` then `libc::mlock`s
    // the page. The local `application_secret` stack buffer is zeroized
    // immediately after the move into the heap.
    let app_secret_box: MlockedSecret<[u8; 32]> = MlockedSecret::new(application_secret);
    application_secret.zeroize();

    // Write the needle to a sidecar file so the lldb scanner can read it.
    let needle_path = std::env::temp_dir().join("r12_needle.bin");
    std::fs::write(&needle_path, app_secret_box.expose().as_slice())
        .expect("write r12_needle.bin");
    eprintln!(
        "[R12] application_secret needle written to {}",
        needle_path.display()
    );
    eprintln!(
        "[R12] needle prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        app_secret_box.expose()[0],
        app_secret_box.expose()[1],
        app_secret_box.expose()[2],
        app_secret_box.expose()[3],
        app_secret_box.expose()[4],
        app_secret_box.expose()[5],
        app_secret_box.expose()[6],
        app_secret_box.expose()[7],
    );

    // Step 4 — use the secret in a real ChaCha20-Poly1305 AEAD encryption
    // call. Round-5: the cipher is constructed and dropped inside the
    // `#[inline(never)]` helper so its stack-spilled key bytes are gone
    // by the time we reach the lldb pause.
    let mut buf: Vec<u8> = b"R12 application message - must decrypt with the captured secret".to_vec();
    let nonce_bytes = [0x42u8; 12];
    encrypt_with_app_secret(app_secret_box.expose(), &nonce_bytes, b"r12-aad", &mut buf);
    // Allocate a chunk of throwaway bytes to overwrite the stack region
    // the helper used — this is "stack scrub" defense in depth. LLVM
    // may or may not reuse the same frame addresses; the heuristic is
    // that allocating ~16 KiB of stack-local arrays after the helper
    // returns shifts subsequent stack frames and overwrites the helper's
    // popped slot.
    //
    // Allocate a chunk of throwaway bytes to overwrite the stack region
    // the helper used — this is "stack scrub" defense in depth. LLVM
    // may or may not reuse the same frame addresses; the heuristic is
    // that allocating ~16 KiB of stack-local arrays after the helper
    // returns shifts subsequent stack frames and overwrites the helper's
    // popped slot.
    let mut scrub: [u8; 16384] = [0xEE; 16384];
    std::hint::black_box(&mut scrub);

    eprintln!(
        "[R12] encrypted (ct prefix): {:02x}{:02x}{:02x}{:02x}",
        buf[0], buf[1], buf[2], buf[3]
    );

    // Zeroize the synthetic epoch_secret (analog of MLS post-commit cleanup).
    epoch_secret.zeroize();

    r12_phase_session_live();

    if std::env::var("R12_PAUSE").is_ok() {
        eprintln!(
            "[R12] PAUSING SESSION_LIVE for 60s — attach with: lldb -p {}",
            std::process::id()
        );
        std::thread::sleep(std::time::Duration::from_secs(60));
    }

    // Drop the MlockedSecret — zeroize-on-drop + munlock.
    std::hint::black_box(&app_secret_box);
    drop(app_secret_box);

    r12_phase_after_drop();

    if std::env::var("R12_PAUSE").is_ok() {
        eprintln!("[R12] PAUSING AFTER_DROP for 60s");
        std::thread::sleep(std::time::Duration::from_secs(60));
    }

    eprintln!("[R12] done");
}
