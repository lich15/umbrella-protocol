//! F-CLIENT-FACADE-1 closure session 10e (2026-05-19): contract tests for
//! `CallSession::srtp_encrypt_rtp` / `srtp_decrypt_rtp` — real
//! `webrtc-srtp 0.17.1` integration в `SrtpPipeline`. Fifth piece of session
//! 10 milestone closure.
//!
//! ## What's wired
//!
//! `SrtpPipeline` теперь держит **два** `webrtc_srtp::context::Context`
//! instances одновременно — outbound encrypt (local master key/salt) + inbound
//! decrypt (remote master key/salt) — потому что Context webrtc-srtp one-way
//! по конструкции. `CallSession` exposes:
//!
//! 1. `srtp_encrypt_rtp(plaintext_rtp) -> Result<Vec<u8>>` — RFC 7714 §14
//!    `RTP header || ciphertext || 16-byte AEAD tag` (AEAD_AES_256_GCM).
//! 2. `srtp_decrypt_rtp(srtp_bytes) -> Result<Vec<u8>>` — replay check
//!    (64-frame sliding window) + AEAD verify + plaintext RTP.
//!
//! ## Coverage (10 scenarios)
//!
//! 1. `install_srtp_keying` + `is_srtp_keyed` → true (sanity).
//! 2. `srtp_encrypt_rtp` pre-keying → `ClientError::Internal("pre-keying ...")`.
//! 3. `srtp_decrypt_rtp` pre-keying → `ClientError::Internal("pre-keying ...")`.
//! 4. A.encrypt + B.decrypt round-trip with flipped key/salt halves
//!    yields original RTP plaintext.
//! 5. Tampered ciphertext byte → `CallError::AeadAuthFailure` on decrypt.
//! 6. Tampered AEAD tag byte → `CallError::AeadAuthFailure` on decrypt.
//! 7. Replay (same `(ssrc, sequence_number)` decrypted twice) →
//!    `ClientError::Internal("SRTP: replay ...")` second time.
//! 8. Wrong key on decrypt pipeline → `CallError::AeadAuthFailure`.
//! 9. Two consecutive sequence numbers encrypt → decrypt both OK
//!    (replay window admits monotonic forward progress).
//! 10. Determinism: two A-pipelines with identical keying produce
//!     identical ciphertext for identical input RTP packets.

use std::sync::Arc;

use async_trait::async_trait;
use rand::rngs::OsRng;

use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_calls::{CallError, CallPolicy};

use umbrella_client::call::{
    srtp_pipeline::{SrtpKeyingMaterial, SrtpProfile},
    CallSession, MediaError, MediaFrame, MediaSink, MediaSource, ModeEnforcement,
};
use umbrella_client::error::ClientError;
use umbrella_client::facade::chat_common::{PeerId, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT};
use umbrella_client::{ClientConfig, ClientCore};

use umbrella_identity::{IdentitySeed, MnemonicLanguage};

// AEAD_AES_256_GCM per-direction master key / salt lengths (RFC 7714 §14).
const KEY_HALF: usize = 32;
const SALT_HALF: usize = 12;

fn test_config() -> ClientConfig {
    ClientConfig {
        sealed_server_urls: (1..=5).map(|i| format!("http://stub-{i}:8080")).collect(),
        postman_url: "http://stub-postman:8080".into(),
        kt_url: "http://stub-kt:8080".into(),
        call_relay_url: "http://stub-call-relay:8080".into(),
        kt_monitor_interval_secs: 3600,
        wrapping_params: WrappingParams {
            version: 0x01,
            main_pubkey: [0u8; 32],
            server_pubkeys: [[0u8; 32]; 5],
            config: ThresholdConfig::new(3, 5).expect("3-of-5"),
        },
        default_ciphersuite: UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
    }
}

#[allow(deprecated, reason = "test seed pattern")]
fn test_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

struct NullSource;
#[async_trait]
impl MediaSource for NullSource {
    async fn pull_audio_frame(&self) -> Result<MediaFrame, MediaError> {
        Err(MediaError::Native("test".into()))
    }
    async fn pull_video_frame(&self) -> Result<MediaFrame, MediaError> {
        Err(MediaError::Native("test".into()))
    }
}

struct NullSink;
#[async_trait]
impl MediaSink for NullSink {
    async fn push_audio_frame(&self, _: MediaFrame) -> Result<(), MediaError> {
        Ok(())
    }
    async fn push_video_frame(&self, _: MediaFrame) -> Result<(), MediaError> {
        Ok(())
    }
}

async fn fresh_session() -> CallSession {
    let core = ClientCore::new_for_test(test_config(), test_seed())
        .await
        .expect("new_for_test");
    CallSession::start_with_enforcement(
        core,
        PeerId([0x99; 32]),
        CallPolicy::default(),
        ModeEnforcement::CloudMode,
        Arc::new(NullSource),
        Arc::new(NullSink),
    )
    .await
    .expect("start_with_enforcement")
}

/// Builds an SRTP keying material struct with **A's view** of the wire:
/// `key = key_a || key_b`, `salt = salt_a || salt_b`. A's encrypt context uses
/// the first half, decrypt context uses the second half. B uses the same
/// material с halves flipped: `key = key_b || key_a`, `salt = salt_b || salt_a`
/// — so что A.encrypt и B.decrypt оба ссылаются на key_a/salt_a.
fn material_a(key_a: &[u8], key_b: &[u8], salt_a: &[u8], salt_b: &[u8]) -> SrtpKeyingMaterial {
    let mut key = Vec::with_capacity(KEY_HALF * 2);
    key.extend_from_slice(key_a);
    key.extend_from_slice(key_b);
    let mut salt = Vec::with_capacity(SALT_HALF * 2);
    salt.extend_from_slice(salt_a);
    salt.extend_from_slice(salt_b);
    SrtpKeyingMaterial {
        key,
        salt,
        profile: SrtpProfile::AeadAes256Gcm,
    }
}

fn material_b(key_a: &[u8], key_b: &[u8], salt_a: &[u8], salt_b: &[u8]) -> SrtpKeyingMaterial {
    // Flipped halves so B.encrypt uses key_b (matches A.decrypt) и B.decrypt
    // uses key_a (matches A.encrypt).
    let mut key = Vec::with_capacity(KEY_HALF * 2);
    key.extend_from_slice(key_b);
    key.extend_from_slice(key_a);
    let mut salt = Vec::with_capacity(SALT_HALF * 2);
    salt.extend_from_slice(salt_b);
    salt.extend_from_slice(salt_a);
    SrtpKeyingMaterial {
        key,
        salt,
        profile: SrtpProfile::AeadAes256Gcm,
    }
}

/// Constructs the minimal RTP wire packet (12-byte fixed header + payload):
/// V=2, P=0, X=0, CC=0, M=0, PT=96 dynamic, then sequence/timestamp/ssrc/payload.
fn rtp_packet(sequence_number: u16, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12 + payload.len());
    bytes.push(0x80); // V=2, P=0, X=0, CC=0
    bytes.push(0x60); // M=0, PT=96 (dynamic payload type)
    bytes.extend_from_slice(&sequence_number.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes()); // timestamp = 0 (test fixture)
    bytes.extend_from_slice(&ssrc.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

// ============================================================================
// 1. install_srtp_keying + is_srtp_keyed → true (sanity)
// ============================================================================

#[tokio::test]
async fn install_srtp_keying_marks_session_keyed() {
    let session = fresh_session().await;
    assert!(
        !session.is_srtp_keyed().await,
        "fresh session must not be keyed"
    );
    let m = material_a(
        &[0x11; KEY_HALF],
        &[0x22; KEY_HALF],
        &[0x33; SALT_HALF],
        &[0x44; SALT_HALF],
    );
    session.install_srtp_keying(m).await.expect("install");
    assert!(
        session.is_srtp_keyed().await,
        "session must be keyed after install_srtp_keying"
    );
}

// ============================================================================
// 2. srtp_encrypt_rtp pre-keying fails closed
// ============================================================================

#[tokio::test]
async fn srtp_encrypt_rtp_pre_keying_fails_closed() {
    let session = fresh_session().await;
    let packet = rtp_packet(1, 0xDEAD_BEEF, b"hello");
    let err = session
        .srtp_encrypt_rtp(&packet)
        .await
        .expect_err("encrypt pre-keying must fail closed");
    assert!(
        matches!(&err, ClientError::Internal(msg) if msg.contains("pre-keying")),
        "expected Internal pre-keying error, got: {err:?}"
    );
}

// ============================================================================
// 3. srtp_decrypt_rtp pre-keying fails closed
// ============================================================================

#[tokio::test]
async fn srtp_decrypt_rtp_pre_keying_fails_closed() {
    let session = fresh_session().await;
    let packet = rtp_packet(1, 0xDEAD_BEEF, b"hello");
    let err = session
        .srtp_decrypt_rtp(&packet)
        .await
        .expect_err("decrypt pre-keying must fail closed");
    assert!(
        matches!(&err, ClientError::Internal(msg) if msg.contains("pre-keying")),
        "expected Internal pre-keying error, got: {err:?}"
    );
}

// ============================================================================
// 4. A.encrypt + B.decrypt round-trip recovers original RTP plaintext
// ============================================================================

#[tokio::test]
async fn encrypt_decrypt_roundtrip_recovers_plaintext() {
    let key_a = [0x11; KEY_HALF];
    let key_b = [0x22; KEY_HALF];
    let salt_a = [0x33; SALT_HALF];
    let salt_b = [0x44; SALT_HALF];

    let session_a = fresh_session().await;
    let session_b = fresh_session().await;

    session_a
        .install_srtp_keying(material_a(&key_a, &key_b, &salt_a, &salt_b))
        .await
        .expect("install A");
    session_b
        .install_srtp_keying(material_b(&key_a, &key_b, &salt_a, &salt_b))
        .await
        .expect("install B");

    let plaintext_payload = b"voice frame opus 20ms";
    let plaintext = rtp_packet(7, 0xCAFEBABE, plaintext_payload);

    let ciphertext = session_a
        .srtp_encrypt_rtp(&plaintext)
        .await
        .expect("encrypt");
    // Expected wire: 12-byte RTP header (unchanged) + payload + 16-byte tag.
    assert_eq!(
        ciphertext.len(),
        12 + plaintext_payload.len() + 16,
        "AEAD_AES_256_GCM SRTP packet must be header + payload + 16-byte tag"
    );
    // First 12 bytes (RTP header) must be unchanged.
    assert_eq!(
        &ciphertext[..12],
        &plaintext[..12],
        "RTP header must be plaintext"
    );

    let recovered = session_b
        .srtp_decrypt_rtp(&ciphertext)
        .await
        .expect("decrypt");
    assert_eq!(
        recovered, plaintext,
        "round-trip must recover original RTP packet"
    );
}

// ============================================================================
// 5. Tampered ciphertext byte → AEAD auth failure
// ============================================================================

#[tokio::test]
async fn tampered_ciphertext_byte_fails_aead_auth() {
    let key_a = [0xA1; KEY_HALF];
    let key_b = [0xA2; KEY_HALF];
    let salt_a = [0xB1; SALT_HALF];
    let salt_b = [0xB2; SALT_HALF];

    let session_a = fresh_session().await;
    let session_b = fresh_session().await;
    session_a
        .install_srtp_keying(material_a(&key_a, &key_b, &salt_a, &salt_b))
        .await
        .unwrap();
    session_b
        .install_srtp_keying(material_b(&key_a, &key_b, &salt_a, &salt_b))
        .await
        .unwrap();

    let plaintext = rtp_packet(11, 0xFEEDFACE, &[0x5A; 64]);
    let mut ciphertext = session_a.srtp_encrypt_rtp(&plaintext).await.unwrap();
    // Flip a single ciphertext byte (mid-payload, between header and tag).
    let target_idx = 12 + 10;
    ciphertext[target_idx] ^= 0xFF;

    let err = session_b
        .srtp_decrypt_rtp(&ciphertext)
        .await
        .expect_err("tampered ciphertext must reject");
    assert!(
        matches!(err, ClientError::Call(CallError::AeadAuthFailure)),
        "expected AeadAuthFailure, got: {err:?}"
    );
}

// ============================================================================
// 6. Tampered AEAD tag byte → AEAD auth failure
// ============================================================================

#[tokio::test]
async fn tampered_aead_tag_byte_fails_aead_auth() {
    let key_a = [0xC1; KEY_HALF];
    let key_b = [0xC2; KEY_HALF];
    let salt_a = [0xD1; SALT_HALF];
    let salt_b = [0xD2; SALT_HALF];

    let session_a = fresh_session().await;
    let session_b = fresh_session().await;
    session_a
        .install_srtp_keying(material_a(&key_a, &key_b, &salt_a, &salt_b))
        .await
        .unwrap();
    session_b
        .install_srtp_keying(material_b(&key_a, &key_b, &salt_a, &salt_b))
        .await
        .unwrap();

    let plaintext = rtp_packet(13, 0xABCD1234, &[0x7E; 32]);
    let mut ciphertext = session_a.srtp_encrypt_rtp(&plaintext).await.unwrap();
    // Flip last byte (inside the 16-byte AEAD tag).
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;

    let err = session_b
        .srtp_decrypt_rtp(&ciphertext)
        .await
        .expect_err("tampered AEAD tag must reject");
    assert!(
        matches!(err, ClientError::Call(CallError::AeadAuthFailure)),
        "expected AeadAuthFailure, got: {err:?}"
    );
}

// ============================================================================
// 7. Replay (same ssrc+seq decrypted twice) → Internal "replay"
// ============================================================================

#[tokio::test]
async fn replay_same_sequence_twice_rejected_on_decrypt() {
    let key_a = [0xE1; KEY_HALF];
    let key_b = [0xE2; KEY_HALF];
    let salt_a = [0xF1; SALT_HALF];
    let salt_b = [0xF2; SALT_HALF];

    let session_a = fresh_session().await;
    let session_b = fresh_session().await;
    session_a
        .install_srtp_keying(material_a(&key_a, &key_b, &salt_a, &salt_b))
        .await
        .unwrap();
    session_b
        .install_srtp_keying(material_b(&key_a, &key_b, &salt_a, &salt_b))
        .await
        .unwrap();

    let plaintext = rtp_packet(42, 0x1357_9BDF, b"replayable frame");
    let ciphertext = session_a.srtp_encrypt_rtp(&plaintext).await.unwrap();

    // First decrypt accepted.
    session_b
        .srtp_decrypt_rtp(&ciphertext)
        .await
        .expect("first decrypt must succeed");

    // Replay: same wire packet → must reject as duplicate sequence.
    let err = session_b
        .srtp_decrypt_rtp(&ciphertext)
        .await
        .expect_err("second decrypt (replay) must reject");
    assert!(
        matches!(&err, ClientError::Internal(msg) if msg.contains("SRTP: replay")),
        "expected Internal SRTP replay error, got: {err:?}"
    );
}

// ============================================================================
// 8. Wrong decrypt key → AEAD auth failure
// ============================================================================

#[tokio::test]
async fn wrong_decrypt_key_fails_aead_auth() {
    let key_a = [0x10; KEY_HALF];
    let key_b = [0x20; KEY_HALF];
    let salt_a = [0x30; SALT_HALF];
    let salt_b = [0x40; SALT_HALF];

    // session_b has DIFFERENT remote half (corrupted key_a) — its decrypt
    // context will not match session_a's encrypt context.
    let wrong_key_a = [0x99; KEY_HALF];

    let session_a = fresh_session().await;
    let session_wrong = fresh_session().await;
    session_a
        .install_srtp_keying(material_a(&key_a, &key_b, &salt_a, &salt_b))
        .await
        .unwrap();
    session_wrong
        .install_srtp_keying(material_b(&wrong_key_a, &key_b, &salt_a, &salt_b))
        .await
        .unwrap();

    let plaintext = rtp_packet(5, 0xAAAA_5555, b"this should not decrypt");
    let ciphertext = session_a.srtp_encrypt_rtp(&plaintext).await.unwrap();

    let err = session_wrong
        .srtp_decrypt_rtp(&ciphertext)
        .await
        .expect_err("wrong key must reject");
    assert!(
        matches!(err, ClientError::Call(CallError::AeadAuthFailure)),
        "expected AeadAuthFailure under wrong key, got: {err:?}"
    );
}

// ============================================================================
// 9. Two consecutive sequence numbers decrypt OK (replay window admits
//    monotonic forward progress)
// ============================================================================

#[tokio::test]
async fn consecutive_sequence_numbers_decrypt_independently() {
    let key_a = [0x55; KEY_HALF];
    let key_b = [0x66; KEY_HALF];
    let salt_a = [0x77; SALT_HALF];
    let salt_b = [0x88; SALT_HALF];

    let session_a = fresh_session().await;
    let session_b = fresh_session().await;
    session_a
        .install_srtp_keying(material_a(&key_a, &key_b, &salt_a, &salt_b))
        .await
        .unwrap();
    session_b
        .install_srtp_keying(material_b(&key_a, &key_b, &salt_a, &salt_b))
        .await
        .unwrap();

    let p1 = rtp_packet(100, 0x9999_8888, b"frame one");
    let p2 = rtp_packet(101, 0x9999_8888, b"frame two");

    let c1 = session_a.srtp_encrypt_rtp(&p1).await.unwrap();
    let c2 = session_a.srtp_encrypt_rtp(&p2).await.unwrap();

    let d1 = session_b
        .srtp_decrypt_rtp(&c1)
        .await
        .expect("decrypt seq 100");
    let d2 = session_b
        .srtp_decrypt_rtp(&c2)
        .await
        .expect("decrypt seq 101");
    assert_eq!(d1, p1, "frame 1 must round-trip");
    assert_eq!(d2, p2, "frame 2 must round-trip");
}

// ============================================================================
// 10. Determinism — two A-pipelines with identical keying produce identical
//     ciphertext for identical input RTP packets (AES-GCM is deterministic
//     given identical key/nonce; webrtc-srtp derives nonce from
//     master_salt XOR (ssrc, roc, seq), all of which are equal in the two
//     pipelines for the same input packet from a fresh state).
// ============================================================================

#[tokio::test]
async fn two_pipelines_with_same_keying_produce_identical_ciphertext() {
    let key_a = [0xDE; KEY_HALF];
    let key_b = [0xAD; KEY_HALF];
    let salt_a = [0xBE; SALT_HALF];
    let salt_b = [0xEF; SALT_HALF];

    let m = material_a(&key_a, &key_b, &salt_a, &salt_b);

    let session_a1 = fresh_session().await;
    let session_a2 = fresh_session().await;
    session_a1.install_srtp_keying(m.clone()).await.unwrap();
    session_a2.install_srtp_keying(m).await.unwrap();

    let plaintext = rtp_packet(
        77,
        0x0F0F_0F0F,
        b"determinism check 64 bytes payload here ......",
    );

    let c1 = session_a1.srtp_encrypt_rtp(&plaintext).await.unwrap();
    let c2 = session_a2.srtp_encrypt_rtp(&plaintext).await.unwrap();

    assert_eq!(
        c1, c2,
        "two pipelines with identical keying and identical input packet \
         (same ssrc, sequence, payload) must produce identical SRTP ciphertext"
    );
}
