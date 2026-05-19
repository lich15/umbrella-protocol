//! F-CLIENT-FACADE-1 closure session 8c3 (2026-05-19): contract tests for
//! [`umbrella_client::kt_monitor::verify_kt_witness_signatures_for_epoch_via_fetcher`]
//! — production-path witness 3-of-5 verification через
//! [`umbrella_client::transport::KtSignedRootsFetcher`] trait abstraction +
//! [`umbrella_kt::codec::decode_signed_epoch_root`] strict wire decoder.
//!
//! ## Sessions 8b vs 8c3
//!
//! Session 8b ([`facade_session8b_kt_witness_threshold.rs`]) covered semantic
//! threshold logic with **typed** stub staging — facade fetched `SignedEpochRoot`
//! Rust values напрямую from `StubKtTransport::fetch_staged_signed_root`.
//! Session 8c3 closes the wire-bytes leg: production `Http2KtTransport`
//! returns raw `Vec<u8>` length-prefixed frames; new helper deserialises through
//! `decode_signed_epoch_root` before reaching `verify_signed_epoch`. These
//! tests target что fail-closed chain (transport → decode → epoch-binding →
//! threshold) holds end-to-end через ту же `KtSignedRootsFetcher` поверхность
//! что production будет use'ать.
//!
//! ## Adversary capability for these tests
//!
//! Adversary controls **bytes на проводе** — может вернуть пустой ответ,
//! multi-frame split, truncated/malformed bytes, frame подписанный для
//! другой эпохи. Mock fetcher позволяет stage'ить любой такой response;
//! facade MUST fail-closed для каждого через одну из 5 layers chain'а
//! (постулат 14, ADR-009).
//!
//! Coverage (10 scenarios):
//!
//! 1. Success with single 5-of-5 frame at threshold 3.
//! 2. Success at exact 3-of-5 boundary.
//! 3. Fail-closed: fetcher returns empty frame list.
//! 4. Fail-closed: fetcher returns two frames (single-frame invariant).
//! 5. Fail-closed: frame has unknown version byte.
//! 6. Fail-closed: frame has trailing bytes after signatures.
//! 7. Fail-closed: frame truncated mid-signature payload.
//! 8. Fail-closed: frame's inner `signed.epoch` ≠ requested epoch
//!    (substitution defence-in-depth).
//! 9. Underlying fetcher error propagates as `ClientError::Network`.
//! 10. Empty `WitnessSet` (post-bootstrap default) → fail-closed
//!     `InsufficientValidSignatures` for honest 5-of-5 wire bytes.

use std::sync::Arc;

use async_trait::async_trait;
use rand_core::OsRng;
use tokio::sync::Mutex;

use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_client::error::ClientError;
use umbrella_client::facade::chat_common::UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT;
use umbrella_client::kt_monitor::verify_kt_witness_signatures_for_epoch_via_fetcher;
use umbrella_client::transport::KtSignedRootsFetcher;
use umbrella_client::{ClientConfig, UmbrellaClient};
use umbrella_crypto_primitives::sig::PrivateSigningKey;
use umbrella_identity::{IdentitySeed, MnemonicLanguage};
use umbrella_kt::{
    canonical_sign_payload, encode_signed_epoch_root, KtError, SignedEpochRoot, WitnessPublic,
    WitnessSet, WitnessSignature, SIGNATURE_WIRE_LEN, SIGNED_EPOCH_ROOT_HEADER_LEN,
    SIGNED_EPOCH_ROOT_WIRE_VERSION,
};

const TEST_EPOCH: u64 = 42;
const TEST_LOG_SIZE: u64 = 1_000_000;
const TEST_TIMESTAMP_MS: u64 = 1_715_000_000_000;
const TEST_THRESHOLD: usize = 3;
const TEST_ROOT: [u8; 32] = [0xCD; 32];

// ============================================================================
// Test rig: client bootstrap + witness keypair helpers
// ============================================================================

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
            config: ThresholdConfig::new(3, 5).expect("3-of-5 ThresholdConfig"),
        },
        default_ciphersuite: UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
    }
}

#[allow(
    deprecated,
    reason = "test seed gen — same pattern as facade_session8b_kt_witness_threshold.rs"
)]
fn test_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

async fn bootstrap_client() -> Arc<UmbrellaClient> {
    UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test")
}

struct TestWitness {
    sk: PrivateSigningKey,
    pk: WitnessPublic,
}

fn fresh_witness() -> TestWitness {
    let sk = PrivateSigningKey::generate(&mut OsRng);
    let pk = WitnessPublic::from_bytes(sk.verifying_key().to_bytes());
    TestWitness { sk, pk }
}

fn fresh_witness_set_of_5() -> (Vec<TestWitness>, WitnessSet) {
    let ws: Vec<TestWitness> = (0..5).map(|_| fresh_witness()).collect();
    let mut set = WitnessSet::new();
    for w in &ws {
        set.add(w.pk);
    }
    (ws, set)
}

fn sign_canonical(
    witness: &TestWitness,
    epoch: u64,
    root: &[u8; 32],
    log_size: u64,
    timestamp_ms: u64,
) -> WitnessSignature {
    let payload = canonical_sign_payload(epoch, root, log_size, timestamp_ms);
    let sig = witness.sk.sign(&payload);
    WitnessSignature {
        witness: witness.pk,
        signature: sig.to_bytes(),
    }
}

fn build_signed_root(
    signing_witnesses: &[&TestWitness],
    epoch: u64,
    root: [u8; 32],
    log_size: u64,
    timestamp_ms: u64,
) -> SignedEpochRoot {
    let signatures = signing_witnesses
        .iter()
        .map(|w| sign_canonical(w, epoch, &root, log_size, timestamp_ms))
        .collect();
    SignedEpochRoot {
        epoch,
        root,
        log_size,
        timestamp_unix_millis: timestamp_ms,
        signatures,
    }
}

// ============================================================================
// MockKtFetcher — controllable trait impl, stages exactly one response per call
// ============================================================================

/// In-memory mock реализующая [`KtSignedRootsFetcher`]. Тест stages один
/// response (Vec<Vec<u8>> либо `Err(ClientError)`); следующий `fetch_*`
/// дренирует. Если staging queue empty — возвращает empty Vec (что facade
/// fail-close через `SelfMonitoringMismatch { field:
/// "expected_single_signed_root_frame" }`).
#[derive(Default)]
struct MockKtFetcher {
    staged: Mutex<Option<Result<Vec<Vec<u8>>, ClientError>>>,
}

impl MockKtFetcher {
    fn new() -> Self {
        Self::default()
    }

    async fn stage_frames(&self, frames: Vec<Vec<u8>>) {
        *self.staged.lock().await = Some(Ok(frames));
    }

    async fn stage_error(&self, err: ClientError) {
        *self.staged.lock().await = Some(Err(err));
    }
}

#[async_trait]
impl KtSignedRootsFetcher for MockKtFetcher {
    async fn fetch_signed_root_frames(&self, _epoch: u64) -> Result<Vec<Vec<u8>>, ClientError> {
        let mut guard = self.staged.lock().await;
        match guard.take() {
            Some(Ok(frames)) => Ok(frames),
            Some(Err(e)) => Err(e),
            None => Ok(vec![]),
        }
    }
}

// ============================================================================
// Tests — happy path
// ============================================================================

#[tokio::test]
async fn verify_via_fetcher_succeeds_with_single_frame_5_of_5_valid_signatures_threshold_3() {
    // Honest server returns one wire-encoded SignedEpochRoot frame with all
    // 5 witness signatures. Decoder → verify chain → ok at threshold 3.
    let alice = bootstrap_client().await;
    let (ws, witness_set) = fresh_witness_set_of_5();
    let signed = build_signed_root(
        &ws.iter().collect::<Vec<_>>(),
        TEST_EPOCH,
        TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    let frame = encode_signed_epoch_root(&signed).expect("encode 5-of-5 frame");
    assert_eq!(
        frame.len(),
        SIGNED_EPOCH_ROOT_HEADER_LEN + 5 * SIGNATURE_WIRE_LEN,
        "5-sig frame must be exactly 58 + 5*96 = 538 bytes"
    );

    alice.core().set_kt_witness_set(witness_set).await;
    let fetcher = MockKtFetcher::new();
    fetcher.stage_frames(vec![frame]).await;

    verify_kt_witness_signatures_for_epoch_via_fetcher(
        &alice.core(),
        &fetcher,
        TEST_EPOCH,
        TEST_THRESHOLD,
    )
    .await
    .expect(
        "5-of-5 honest wire bytes MUST pass threshold-3 verification through \
         the production-path decoder chain without errors",
    );
}

#[tokio::test]
async fn verify_via_fetcher_succeeds_at_exact_3_of_5_threshold_boundary() {
    // Exactly 3 signatures on the wire — boundary case. Both wire decode
    // AND threshold check must pass.
    let alice = bootstrap_client().await;
    let (ws, witness_set) = fresh_witness_set_of_5();
    let three_signers: Vec<&TestWitness> = ws.iter().take(3).collect();
    let signed = build_signed_root(
        &three_signers,
        TEST_EPOCH,
        TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    let frame = encode_signed_epoch_root(&signed).expect("encode 3-of-5 frame");
    assert_eq!(
        frame.len(),
        SIGNED_EPOCH_ROOT_HEADER_LEN + 3 * SIGNATURE_WIRE_LEN,
        "3-sig frame must be exactly 58 + 3*96 = 346 bytes"
    );

    alice.core().set_kt_witness_set(witness_set).await;
    let fetcher = MockKtFetcher::new();
    fetcher.stage_frames(vec![frame]).await;

    verify_kt_witness_signatures_for_epoch_via_fetcher(
        &alice.core(),
        &fetcher,
        TEST_EPOCH,
        TEST_THRESHOLD,
    )
    .await
    .expect(
        "3-of-5 valid signatures on the wire MUST meet threshold 3 (exact boundary, \
         SPEC-09 §6 minimum acceptable)",
    );
}

// ============================================================================
// Tests — single-frame invariant defence
// ============================================================================

#[tokio::test]
async fn verify_via_fetcher_fails_closed_when_fetcher_returns_empty_frame_list() {
    // kt-svc serves zero frames для эпохи — production analogue: outage /
    // server delete / censorship before bundle materialised. Facade MUST
    // fail-close on the single-frame invariant.
    let alice = bootstrap_client().await;
    let (_ws, witness_set) = fresh_witness_set_of_5();
    alice.core().set_kt_witness_set(witness_set).await;
    let fetcher = MockKtFetcher::new();
    fetcher.stage_frames(vec![]).await; // explicit empty

    let result = verify_kt_witness_signatures_for_epoch_via_fetcher(
        &alice.core(),
        &fetcher,
        TEST_EPOCH,
        TEST_THRESHOLD,
    )
    .await;

    match result {
        Err(ClientError::Kt(KtError::SelfMonitoringMismatch { field })) => {
            assert_eq!(
                field, "expected_single_signed_root_frame",
                "empty frame list MUST surface as \
                 SelfMonitoringMismatch {{ field: \"expected_single_signed_root_frame\" }}; \
                 got field={field}"
            );
        }
        other => {
            panic!("empty frame list MUST fail-close with single-frame invariant; got {other:?}")
        }
    }
}

#[tokio::test]
async fn verify_via_fetcher_fails_closed_when_fetcher_returns_two_frames_violating_invariant() {
    // Adversary returns 2 wire-encoded SignedEpochRoot frames (e.g.,
    // honest-old + malicious-new with same epoch but different log_size
    // cross-binding) hoping facade picks one. Single-frame invariant
    // blocks immediately, no decode/verify attempted.
    let alice = bootstrap_client().await;
    let (ws, witness_set) = fresh_witness_set_of_5();
    let signed_a = build_signed_root(
        &ws.iter().collect::<Vec<_>>(),
        TEST_EPOCH,
        TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    let signed_b = build_signed_root(
        &ws.iter().collect::<Vec<_>>(),
        TEST_EPOCH,
        TEST_ROOT,
        TEST_LOG_SIZE + 1, // crossbinding differs
        TEST_TIMESTAMP_MS,
    );
    let frame_a = encode_signed_epoch_root(&signed_a).expect("encode A");
    let frame_b = encode_signed_epoch_root(&signed_b).expect("encode B");

    alice.core().set_kt_witness_set(witness_set).await;
    let fetcher = MockKtFetcher::new();
    fetcher.stage_frames(vec![frame_a, frame_b]).await;

    let result = verify_kt_witness_signatures_for_epoch_via_fetcher(
        &alice.core(),
        &fetcher,
        TEST_EPOCH,
        TEST_THRESHOLD,
    )
    .await;

    match result {
        Err(ClientError::Kt(KtError::SelfMonitoringMismatch { field })) => {
            assert_eq!(
                field, "expected_single_signed_root_frame",
                "multi-frame response MUST surface as \
                 SelfMonitoringMismatch {{ field: \"expected_single_signed_root_frame\" }}; \
                 got field={field}"
            );
        }
        other => panic!(
            "two-frame split-view attempt MUST fail-close with single-frame invariant; \
             got {other:?}"
        ),
    }
}

// ============================================================================
// Tests — strict wire decoder fail-close paths
// ============================================================================

#[tokio::test]
async fn verify_via_fetcher_fails_closed_when_frame_has_unknown_version_byte() {
    // Adversary serves a frame with version byte 0x02 (либо anything ≠ 0x01).
    // Strict decoder MUST reject before any verify attempt.
    let alice = bootstrap_client().await;
    let (ws, witness_set) = fresh_witness_set_of_5();
    let signed = build_signed_root(
        &ws.iter().collect::<Vec<_>>(),
        TEST_EPOCH,
        TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    let mut frame = encode_signed_epoch_root(&signed).expect("encode");
    frame[0] = 0x02; // unknown version
    assert_ne!(frame[0], SIGNED_EPOCH_ROOT_WIRE_VERSION);

    alice.core().set_kt_witness_set(witness_set).await;
    let fetcher = MockKtFetcher::new();
    fetcher.stage_frames(vec![frame]).await;

    let result = verify_kt_witness_signatures_for_epoch_via_fetcher(
        &alice.core(),
        &fetcher,
        TEST_EPOCH,
        TEST_THRESHOLD,
    )
    .await;

    match result {
        Err(ClientError::Kt(KtError::InvalidSignedEpochRootWire(tag))) => {
            assert_eq!(
                tag, "unknown_version",
                "version-byte tamper MUST surface as InvalidSignedEpochRootWire(\"unknown_version\"); \
                 got tag={tag}"
            );
        }
        other => panic!("unknown version byte MUST fail-close at decoder; got {other:?}"),
    }
}

#[tokio::test]
async fn verify_via_fetcher_fails_closed_when_frame_has_trailing_bytes_after_signatures() {
    // Adversary appends one byte of garbage past the last signature payload.
    // Strict decoder MUST reject — blocks server-side smuggling of out-of-band
    // data past documented field set.
    let alice = bootstrap_client().await;
    let (ws, witness_set) = fresh_witness_set_of_5();
    let signed = build_signed_root(
        &ws.iter().collect::<Vec<_>>(),
        TEST_EPOCH,
        TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    let mut frame = encode_signed_epoch_root(&signed).expect("encode");
    frame.push(0x42);

    alice.core().set_kt_witness_set(witness_set).await;
    let fetcher = MockKtFetcher::new();
    fetcher.stage_frames(vec![frame]).await;

    let result = verify_kt_witness_signatures_for_epoch_via_fetcher(
        &alice.core(),
        &fetcher,
        TEST_EPOCH,
        TEST_THRESHOLD,
    )
    .await;

    match result {
        Err(ClientError::Kt(KtError::InvalidSignedEpochRootWire(tag))) => {
            assert_eq!(
                tag, "trailing_bytes",
                "trailing byte MUST surface as InvalidSignedEpochRootWire(\"trailing_bytes\"); \
                 got tag={tag}"
            );
        }
        other => panic!("trailing byte MUST fail-close at decoder; got {other:?}"),
    }
}

#[tokio::test]
async fn verify_via_fetcher_fails_closed_when_frame_truncated_mid_signature_payload() {
    // Server returns a frame with `signature_count = 5` but only 4
    // signatures worth of bytes follow — truncated_signatures must reject
    // before any sig verify attempt.
    let alice = bootstrap_client().await;
    let (ws, witness_set) = fresh_witness_set_of_5();
    let signed = build_signed_root(
        &ws.iter().collect::<Vec<_>>(),
        TEST_EPOCH,
        TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    let mut frame = encode_signed_epoch_root(&signed).expect("encode");
    // Strip last 96-byte signature off the wire — header still claims 5 sigs
    // but only 4 are present.
    frame.truncate(frame.len() - SIGNATURE_WIRE_LEN);

    alice.core().set_kt_witness_set(witness_set).await;
    let fetcher = MockKtFetcher::new();
    fetcher.stage_frames(vec![frame]).await;

    let result = verify_kt_witness_signatures_for_epoch_via_fetcher(
        &alice.core(),
        &fetcher,
        TEST_EPOCH,
        TEST_THRESHOLD,
    )
    .await;

    match result {
        Err(ClientError::Kt(KtError::InvalidSignedEpochRootWire(tag))) => {
            assert_eq!(
                tag, "truncated_signatures",
                "header sig_count=5 but only 4 sigs on wire MUST surface as \
                 InvalidSignedEpochRootWire(\"truncated_signatures\"); got tag={tag}"
            );
        }
        other => panic!("truncated signature payload MUST fail-close at decoder; got {other:?}"),
    }
}

// ============================================================================
// Tests — epoch substitution defence-in-depth
// ============================================================================

#[tokio::test]
async fn verify_via_fetcher_fails_closed_when_inner_signed_epoch_differs_from_requested() {
    // Server returns wire-encoded honest 5-of-5 SignedEpochRoot но
    // signed.epoch=99 вместо requested 42. Decoder accepts (wire layout
    // valid), epoch-binding check catches mismatch, fails closed before
    // verify_signed_epoch is invoked.
    let alice = bootstrap_client().await;
    let (ws, witness_set) = fresh_witness_set_of_5();
    let signed = build_signed_root(
        &ws.iter().collect::<Vec<_>>(),
        99, // different epoch in signed payload
        TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    assert_eq!(signed.epoch, 99, "sanity: signed carries epoch 99");
    let frame = encode_signed_epoch_root(&signed).expect("encode");

    alice.core().set_kt_witness_set(witness_set).await;
    let fetcher = MockKtFetcher::new();
    fetcher.stage_frames(vec![frame]).await;

    let result = verify_kt_witness_signatures_for_epoch_via_fetcher(
        &alice.core(),
        &fetcher,
        TEST_EPOCH, // requested 42, frame contains 99
        TEST_THRESHOLD,
    )
    .await;

    match result {
        Err(ClientError::Kt(KtError::SelfMonitoringMismatch { field })) => {
            assert_eq!(
                field, "signed_epoch_mismatch",
                "epoch-substitution at wire layer MUST surface as \
                 SelfMonitoringMismatch {{ field: \"signed_epoch_mismatch\" }}; \
                 got field={field}"
            );
        }
        other => panic!("epoch substitution MUST fail-close at epoch-binding check; got {other:?}"),
    }
}

// ============================================================================
// Tests — transport-layer error propagation
// ============================================================================

#[tokio::test]
async fn verify_via_fetcher_propagates_underlying_network_error_from_fetcher() {
    // Production analogue: kt-svc returns 503 / TCP RST / DNS fail.
    // Fetcher's Err propagates without translation — facade does NOT
    // synthesize a fake decoder error.
    let alice = bootstrap_client().await;
    let (_ws, witness_set) = fresh_witness_set_of_5();
    alice.core().set_kt_witness_set(witness_set).await;

    let fetcher = MockKtFetcher::new();
    fetcher
        .stage_error(ClientError::Network(
            "simulated kt-svc 503 service unavailable".into(),
        ))
        .await;

    let result = verify_kt_witness_signatures_for_epoch_via_fetcher(
        &alice.core(),
        &fetcher,
        TEST_EPOCH,
        TEST_THRESHOLD,
    )
    .await;

    match result {
        Err(ClientError::Network(msg)) => {
            assert!(
                msg.contains("503") || msg.contains("service unavailable"),
                "Network error must propagate fetcher-supplied message verbatim; got: {msg}"
            );
        }
        other => {
            panic!("fetcher Network error MUST propagate unchanged through facade; got {other:?}")
        }
    }
}

// ============================================================================
// Tests — empty witness set + threshold semantics on wire path
// ============================================================================

#[tokio::test]
async fn verify_via_fetcher_fails_closed_for_honest_5_of_5_when_witness_set_unset_default_empty() {
    // Bootstrap invariant (session 8c1): fresh ClientCore has empty
    // `WitnessSet`. Production deployment must `set_kt_witness_set` before
    // first call. Wire-path helper MUST also fail-close под этот invariant —
    // не silently accept any signature when set is empty.
    let alice = bootstrap_client().await;
    let (ws, _ignored_witness_set) = fresh_witness_set_of_5();
    let signed = build_signed_root(
        &ws.iter().collect::<Vec<_>>(),
        TEST_EPOCH,
        TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    let frame = encode_signed_epoch_root(&signed).expect("encode");

    // Deliberately do NOT call alice.core().set_kt_witness_set(...).
    let fetcher = MockKtFetcher::new();
    fetcher.stage_frames(vec![frame]).await;

    let result = verify_kt_witness_signatures_for_epoch_via_fetcher(
        &alice.core(),
        &fetcher,
        TEST_EPOCH,
        TEST_THRESHOLD,
    )
    .await;

    match result {
        Err(ClientError::Kt(KtError::InsufficientValidSignatures { valid, required })) => {
            assert_eq!(
                valid, 0,
                "empty default WitnessSet filters every signature as unknown → 0 valid \
                 (wire-path symmetric с session 8c1 stub-path invariant)"
            );
            assert_eq!(required, TEST_THRESHOLD);
        }
        other => panic!(
            "default empty WitnessSet MUST fail-close even with 5 honest wire signatures; \
             got {other:?}"
        ),
    }
}
