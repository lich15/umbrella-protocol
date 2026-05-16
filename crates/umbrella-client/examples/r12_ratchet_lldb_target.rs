//! R12 — ratchet-state capture during live session.
//!
//! PhD-B Device-Capture Defense audit (round 4, 2026-05-19).
//!
//! Models the structural shape of an MLS active session: a 32-byte
//! `application_secret` derived via HKDF-SHA512 from a known epoch_secret,
//! held in `SecretBox<[u8; 32]>` exactly as `umbrella-mls::UmbrellaGroup::
//! exporter_secret` returns it. Holds the secret across two
//! encrypt_application analog calls (ChaCha20-Poly1305 in-place AEAD),
//! pauses for live lldb attach, then drops.
//!
//! This is **not** a full MLS group rig (avoids 800-line UmbrellaProvider
//! setup). The audited security property is identical: any 32-byte ratchet
//! secret held in heap-resident `SecretBox` is reachable by an in-process
//! debugger. The MLS-specific `MlsGroup::group_epoch_secrets` is in fact
//! held in heap the same way (via openmls's `RatchetTree.secret_tree`).
//!
//! ## Outcome metric
//!
//! lldb scanner counts 32-byte 0xAB needles before/after `drop(session)`.
//! Live → expect ≥ 1 match (the SecretBox heap copy).
//! Post-drop → expect 0 (ZeroizeOnDrop semantics from `secrecy` 0.10.3).

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha512;
use zeroize::Zeroize;

/// Application-secret needle — 32 bytes that the lldb scanner looks for.
/// The needle is the derived `application_secret` from HKDF(epoch_secret).
/// We compute it once below and pass the resulting bytes back to the
/// scanner via the `r12_needle.bin` sidecar file so the scanner doesn't
/// need to hardcode a value (the needle depends on HKDF output).

#[inline(never)]
pub fn r12_phase_session_live() {
    eprintln!("[R12] PHASE SESSION LIVE (application_secret in SecretBox)");
    std::hint::black_box(0u8);
}

#[inline(never)]
pub fn r12_phase_after_drop() {
    eprintln!("[R12] PHASE AFTER session drop");
    std::hint::black_box(0u8);
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

    // Step 3 — load into SecretBox (analog of UmbrellaGroup::exporter_secret).
    let app_secret_box: SecretBox<[u8; 32]> = SecretBox::new(Box::new(application_secret));

    // Write the needle to a sidecar file so the lldb scanner can read it.
    let needle_path = std::env::temp_dir().join("r12_needle.bin");
    std::fs::write(&needle_path, app_secret_box.expose_secret().as_slice())
        .expect("write r12_needle.bin");
    eprintln!(
        "[R12] application_secret needle written to {}",
        needle_path.display()
    );
    eprintln!(
        "[R12] needle prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        app_secret_box.expose_secret()[0],
        app_secret_box.expose_secret()[1],
        app_secret_box.expose_secret()[2],
        app_secret_box.expose_secret()[3],
        app_secret_box.expose_secret()[4],
        app_secret_box.expose_secret()[5],
        app_secret_box.expose_secret()[6],
        app_secret_box.expose_secret()[7],
    );

    // Step 4 — use the secret in a real ChaCha20-Poly1305 AEAD encryption
    // call (analog of `MlsGroup::encrypt_application`).
    let cipher = ChaCha20Poly1305::new(Key::from_slice(app_secret_box.expose_secret().as_slice()));
    let mut buf: Vec<u8> = b"R12 application message - must decrypt with the captured secret".to_vec();
    let nonce_bytes = [0x42u8; 12];
    let _tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), b"r12-aad", &mut buf)
        .expect("encrypt_in_place_detached");

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

    // Drop the SecretBox — ZeroizeOnDrop should wipe.
    std::hint::black_box(&app_secret_box);
    drop(app_secret_box);

    r12_phase_after_drop();

    if std::env::var("R12_PAUSE").is_ok() {
        eprintln!("[R12] PAUSING AFTER_DROP for 60s");
        std::thread::sleep(std::time::Duration::from_secs(60));
    }

    eprintln!("[R12] done");
}
