//! F-CLIENT-FACADE-1 closure session 8b (2026-05-19): contract tests for
//! [`umbrella_client::kt_monitor::verify_kt_witness_signatures_for_epoch`].
//! Closes the **split-view** attack class (SPEC-09 §6 + ADR-009 multi-witness
//! section) at the facade-on-demand level: client stages
//! [`umbrella_kt::SignedEpochRoot`] + pinned 5-witness set on the stub
//! transport, facade fetches + verifies 3-of-5 threshold; any attempted
//! substitution / tampering / under-threshold scenario → fail-closed
//! `ClientError::Kt(KtError::InsufficientValidSignatures | SelfMonitoringMismatch)`
//! per постулат 14 (no silent acceptance).
//!
//! ## Threat model and coverage
//!
//! SPEC-09 §6 + ADR-009 multi-witness: KT log operator может показывать
//! разным клиентам разные версии root'а (split-view). Self-monitoring
//! (session 8a) видит только свою запись и не отличает «свой» view от
//! глобального. Multi-witness 3-of-5: 5 независимых witness'ов в разных
//! юрисдикциях каждую эпоху подписывают root и публикуют в свой канал;
//! клиент принимает эпоху только при ≥ 3 валидных уникальных подписях.
//! Захват одного оператора лога не достаточен — нужно co-opt'ить ≥ 3
//! независимых witness-серверов одновременно.
//!
//! Test scenarios (10 attack/property classes):
//!
//! 1. **5/5 valid** — все 5 witness'ов подписали → threshold 3 ok.
//! 2. **3/5 valid threshold boundary** — ровно 3 подписи → threshold 3 ok.
//! 3. **2/5 fail-closed** — только 2 подписи → threshold 3 fail.
//! 4. **No signed root staged** — fail-closed на отсутствие подписей.
//! 5. **Epoch substitution defence-in-depth** — server returns SignedEpochRoot
//!    с `signed.epoch=99` под key=42 (валидные подписи, но не той эпохи) →
//!    facade detects mismatch.
//! 6. **Tampered root** — `signed.root` модифицирован после signing → все
//!    подписи невалидны на проверке canonical_sign_payload.
//! 7. **Tampered log_size** — `signed.log_size` модифицирован → все
//!    подписи невалидны (SPEC-09 §5.3 cross-binding).
//! 8. **Duplicate signatures from same witness** — anti-Sybil dedup: same
//!    witness count'ится один раз (3 raw подписи, 2 уникальных → fail).
//! 9. **Unknown witness ignored** — подпись от witness'а не из pinned set'а
//!    игнорируется (silently skipped, не add'ится к count).
//! 10. **Order invariance** — re-ordering signatures в `signed.signatures`
//!     не меняет результат (insertion order independence).
//!
//! Используются реальные Ed25519 keypair'ы (через
//! `umbrella_crypto_primitives::sig::PrivateSigningKey::generate`) +
//! реальные подписи через `canonical_sign_payload` SPEC-09 §5.3 wire-format,
//! не моки signature bytes (feedback_real_not_paperwork).

use std::sync::Arc;

use rand_core::OsRng;
use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_client::facade::chat_common::UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT;
use umbrella_client::kt_monitor::verify_kt_witness_signatures_for_epoch;
use umbrella_client::{ClientConfig, ClientError, UmbrellaClient};
use umbrella_crypto_primitives::sig::PrivateSigningKey;
use umbrella_identity::{IdentitySeed, MnemonicLanguage};
use umbrella_kt::{
    canonical_sign_payload, KtError, SignedEpochRoot, WitnessPublic, WitnessSet, WitnessSignature,
};

const TEST_EPOCH: u64 = 42;
const TEST_LOG_SIZE: u64 = 1_000_000;
const TEST_TIMESTAMP_MS: u64 = 1_715_000_000_000;
const TEST_THRESHOLD: usize = 3;
const TEST_ROOT: [u8; 32] = [0xCD; 32];

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
    reason = "test seed gen — same pattern as facade_session8a_kt_self_monitor.rs"
)]
fn test_seed() -> IdentitySeed {
    IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
}

async fn bootstrap_client() -> Arc<UmbrellaClient> {
    UmbrellaClient::bootstrap_for_test(test_config(), test_seed())
        .await
        .expect("bootstrap_for_test")
}

/// One witness — secret signing key + derived public.
struct TestWitness {
    sk: PrivateSigningKey,
    pk: WitnessPublic,
}

fn fresh_witness() -> TestWitness {
    let sk = PrivateSigningKey::generate(&mut OsRng);
    let pk = WitnessPublic::from_bytes(sk.verifying_key().to_bytes());
    TestWitness { sk, pk }
}

/// 5 independent witness keypairs + corresponding pinned `WitnessSet`.
fn fresh_witness_set_of_5() -> (Vec<TestWitness>, WitnessSet) {
    let ws: Vec<TestWitness> = (0..5).map(|_| fresh_witness()).collect();
    let mut set = WitnessSet::new();
    for w in &ws {
        set.add(w.pk);
    }
    (ws, set)
}

/// Real Ed25519 signature over `canonical_sign_payload(epoch, root, log_size,
/// timestamp_ms)` (SPEC-09 §5.3, 80-byte canonical form).
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

/// Build a `SignedEpochRoot` (`signed.epoch=epoch`, `signed.root=root`, ...)
/// with one valid signature per witness in `signing_witnesses`.
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
// Tests — threshold semantics
// ============================================================================

#[tokio::test]
async fn verify_witness_signatures_succeeds_with_5_of_5_valid_signatures() {
    // All 5 witnesses signed honestly; threshold 3 trivially met.
    let alice = bootstrap_client().await;
    let (ws, witness_set) = fresh_witness_set_of_5();
    let signed = build_signed_root(
        &ws.iter().collect::<Vec<_>>(),
        TEST_EPOCH,
        TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );

    alice.core().kt_transport().set_witness_set(witness_set);
    alice
        .core()
        .kt_transport()
        .push_staged_signed_root(TEST_EPOCH, signed);

    verify_kt_witness_signatures_for_epoch(&alice.core(), TEST_EPOCH, TEST_THRESHOLD)
        .await
        .expect(
            "5-of-5 honest witness signatures MUST pass threshold-3 verification \
             without errors",
        );
}

#[tokio::test]
async fn verify_witness_signatures_succeeds_with_3_of_5_valid_signatures_threshold_boundary() {
    // Exactly 3 of 5 signed → threshold 3 boundary held. Critical
    // SPEC-09 §6 invariant: 3-of-5 is the minimum acceptable.
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

    alice.core().kt_transport().set_witness_set(witness_set);
    alice
        .core()
        .kt_transport()
        .push_staged_signed_root(TEST_EPOCH, signed);

    verify_kt_witness_signatures_for_epoch(&alice.core(), TEST_EPOCH, TEST_THRESHOLD)
        .await
        .expect(
            "3-of-5 valid signatures MUST meet threshold 3 (exact boundary, \
             SPEC-09 §6 minimum acceptable)",
        );
}

#[tokio::test]
async fn verify_witness_signatures_fails_closed_with_2_of_5_valid_signatures_under_threshold() {
    // Only 2 witnesses signed — below threshold 3. Models adversary who
    // compromised only 2 of 5 witnesses; threshold must hold against this.
    let alice = bootstrap_client().await;
    let (ws, witness_set) = fresh_witness_set_of_5();
    let two_signers: Vec<&TestWitness> = ws.iter().take(2).collect();
    let signed = build_signed_root(
        &two_signers,
        TEST_EPOCH,
        TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );

    alice.core().kt_transport().set_witness_set(witness_set);
    alice
        .core()
        .kt_transport()
        .push_staged_signed_root(TEST_EPOCH, signed);

    let result =
        verify_kt_witness_signatures_for_epoch(&alice.core(), TEST_EPOCH, TEST_THRESHOLD).await;

    match result {
        Err(ClientError::Kt(KtError::InsufficientValidSignatures { valid, required })) => {
            assert_eq!(valid, 2, "expected exactly 2 valid signatures counted");
            assert_eq!(
                required, TEST_THRESHOLD,
                "expected threshold to be reported"
            );
        }
        other => panic!(
            "2-of-5 MUST fail with InsufficientValidSignatures {{ valid: 2, required: 3 }}; \
             got {other:?}"
        ),
    }
}

#[tokio::test]
async fn verify_witness_signatures_fails_closed_when_no_signed_root_staged_for_epoch() {
    // No SignedEpochRoot staged. Production analogue: kt-svc cannot serve
    // signed-roots endpoint (censorship / outage). Постулат 14 fail-closed.
    let alice = bootstrap_client().await;
    let (_, witness_set) = fresh_witness_set_of_5();
    alice.core().kt_transport().set_witness_set(witness_set);
    // Deliberately do NOT push any SignedEpochRoot.

    let result =
        verify_kt_witness_signatures_for_epoch(&alice.core(), TEST_EPOCH, TEST_THRESHOLD).await;

    match result {
        Err(ClientError::Kt(KtError::InsufficientValidSignatures { valid, required })) => {
            assert_eq!(valid, 0, "no signed root staged → 0 valid signatures");
            assert_eq!(required, TEST_THRESHOLD);
        }
        other => panic!(
            "missing signed root MUST fail with InsufficientValidSignatures \
             {{ valid: 0, required: 3 }}; got {other:?}"
        ),
    }
}

// ============================================================================
// Tests — substitution / tampering attacks
// ============================================================================

#[tokio::test]
async fn verify_witness_signatures_detects_signed_root_under_wrong_epoch_substitution_attack() {
    // Server returns a SignedEpochRoot whose internal `signed.epoch=99` does
    // NOT match the requested epoch=42, despite being keyed under 42 on the
    // wire (server may have served an older honest epoch with 5 valid
    // signatures, hoping the client treats it as fresh). Facade's
    // defence-in-depth check `signed.epoch == requested_epoch` MUST detect.
    let alice = bootstrap_client().await;
    let (ws, witness_set) = fresh_witness_set_of_5();
    let different_epoch_inside: u64 = 99;
    // 5 valid signatures BUT for epoch=99, not 42.
    let signed = build_signed_root(
        &ws.iter().collect::<Vec<_>>(),
        different_epoch_inside,
        TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    assert_eq!(
        signed.epoch, different_epoch_inside,
        "sanity: signed.epoch carries the wrong epoch"
    );

    alice.core().kt_transport().set_witness_set(witness_set);
    alice
        .core()
        .kt_transport()
        .push_staged_signed_root(TEST_EPOCH, signed); // staged under requested key=42

    let result =
        verify_kt_witness_signatures_for_epoch(&alice.core(), TEST_EPOCH, TEST_THRESHOLD).await;

    match result {
        Err(ClientError::Kt(KtError::SelfMonitoringMismatch { field })) => {
            assert_eq!(
                field, "signed_epoch_mismatch",
                "epoch-substitution attack MUST surface as \
                 SelfMonitoringMismatch {{ field: \"signed_epoch_mismatch\" }}; \
                 got field={field}"
            );
        }
        other => panic!(
            "epoch substitution MUST fail with SelfMonitoringMismatch \
             {{ field: \"signed_epoch_mismatch\" }}; got {other:?}"
        ),
    }
}

#[tokio::test]
async fn verify_witness_signatures_detects_tampered_root_invalidates_all_signatures() {
    // Honest 5 witnesses signed root R; server flips one bit in `signed.root`
    // before returning. canonical_sign_payload now uses tampered_R, but
    // signatures were over R — verify fails on all 5.
    let alice = bootstrap_client().await;
    let (ws, witness_set) = fresh_witness_set_of_5();
    let original_root = TEST_ROOT;
    let mut signed = build_signed_root(
        &ws.iter().collect::<Vec<_>>(),
        TEST_EPOCH,
        original_root,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    // Single-bit flip in root post-signing — models stale-or-corrupted root
    // injection by malicious log operator.
    signed.root[0] ^= 0x01;

    alice.core().kt_transport().set_witness_set(witness_set);
    alice
        .core()
        .kt_transport()
        .push_staged_signed_root(TEST_EPOCH, signed);

    let result =
        verify_kt_witness_signatures_for_epoch(&alice.core(), TEST_EPOCH, TEST_THRESHOLD).await;

    match result {
        Err(ClientError::Kt(KtError::InsufficientValidSignatures { valid, required })) => {
            assert_eq!(
                valid, 0,
                "tampered root → all 5 signatures invalid → 0 valid; got valid={valid}"
            );
            assert_eq!(required, TEST_THRESHOLD);
        }
        other => panic!(
            "tampered root MUST fail with InsufficientValidSignatures \
             {{ valid: 0, required: 3 }}; got {other:?}"
        ),
    }
}

#[tokio::test]
async fn verify_witness_signatures_detects_tampered_log_size_invalidates_all_signatures() {
    // SPEC-09 §5.3 cross-binding: canonical_sign_payload includes log_size.
    // Tampered log_size → all signatures invalid on canonical_sign_payload
    // mismatch.
    let alice = bootstrap_client().await;
    let (ws, witness_set) = fresh_witness_set_of_5();
    let mut signed = build_signed_root(
        &ws.iter().collect::<Vec<_>>(),
        TEST_EPOCH,
        TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    // Adversary inflates log_size by 1 (e.g., to hide an injected ghost entry).
    signed.log_size = TEST_LOG_SIZE + 1;

    alice.core().kt_transport().set_witness_set(witness_set);
    alice
        .core()
        .kt_transport()
        .push_staged_signed_root(TEST_EPOCH, signed);

    let result =
        verify_kt_witness_signatures_for_epoch(&alice.core(), TEST_EPOCH, TEST_THRESHOLD).await;

    match result {
        Err(ClientError::Kt(KtError::InsufficientValidSignatures { valid, required })) => {
            assert_eq!(
                valid, 0,
                "tampered log_size → SPEC-09 §5.3 cross-binding triggers signature \
                 invalidation across all 5; got valid={valid}"
            );
            assert_eq!(required, TEST_THRESHOLD);
        }
        other => panic!(
            "tampered log_size MUST fail with InsufficientValidSignatures \
             {{ valid: 0, required: 3 }}; got {other:?}"
        ),
    }
}

// ============================================================================
// Tests — dedup & set semantics
// ============================================================================

#[tokio::test]
async fn verify_witness_signatures_rejects_duplicate_signatures_from_same_witness_anti_sybil() {
    // Adversary с 2 honestly-signed подписями копирует одну из них трижды,
    // надеясь нарастить count до threshold. Helper МUST dedup по witness
    // pubkey: 3 raw подписи, но только 2 уникальных witness'а → fail.
    let alice = bootstrap_client().await;
    let (ws, witness_set) = fresh_witness_set_of_5();
    let sig_a = sign_canonical(
        &ws[0],
        TEST_EPOCH,
        &TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    let sig_b = sign_canonical(
        &ws[1],
        TEST_EPOCH,
        &TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    let signed = SignedEpochRoot {
        epoch: TEST_EPOCH,
        root: TEST_ROOT,
        log_size: TEST_LOG_SIZE,
        timestamp_unix_millis: TEST_TIMESTAMP_MS,
        // 3 raw signatures, 2 unique witnesses (ws[0] appears twice).
        signatures: vec![sig_a, sig_b, sig_a],
    };

    alice.core().kt_transport().set_witness_set(witness_set);
    alice
        .core()
        .kt_transport()
        .push_staged_signed_root(TEST_EPOCH, signed);

    let result =
        verify_kt_witness_signatures_for_epoch(&alice.core(), TEST_EPOCH, TEST_THRESHOLD).await;

    match result {
        Err(ClientError::Kt(KtError::InsufficientValidSignatures { valid, required })) => {
            assert_eq!(
                valid, 2,
                "anti-Sybil dedup: same witness counts once even with duplicated \
                 raw signatures; expected valid=2, got valid={valid}"
            );
            assert_eq!(required, TEST_THRESHOLD);
        }
        other => panic!(
            "duplicate signatures from same witness MUST fail with \
             InsufficientValidSignatures {{ valid: 2, required: 3 }}; got {other:?}"
        ),
    }
}

#[tokio::test]
async fn verify_witness_signatures_ignores_signatures_from_unknown_witness_outside_pinned_set() {
    // Adversary controls a witness NOT in the pinned 5-set (e.g.,
    // attacker-generated keypair). Their signature must be silently
    // ignored — not count toward threshold. 2 known + 1 unknown → 2 valid.
    let alice = bootstrap_client().await;
    let (ws, witness_set) = fresh_witness_set_of_5();
    let attacker_witness = fresh_witness(); // not in pinned set

    let sig_known_0 = sign_canonical(
        &ws[0],
        TEST_EPOCH,
        &TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    let sig_known_1 = sign_canonical(
        &ws[1],
        TEST_EPOCH,
        &TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    let sig_attacker = sign_canonical(
        &attacker_witness,
        TEST_EPOCH,
        &TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    let signed = SignedEpochRoot {
        epoch: TEST_EPOCH,
        root: TEST_ROOT,
        log_size: TEST_LOG_SIZE,
        timestamp_unix_millis: TEST_TIMESTAMP_MS,
        signatures: vec![sig_known_0, sig_known_1, sig_attacker],
    };

    alice.core().kt_transport().set_witness_set(witness_set);
    alice
        .core()
        .kt_transport()
        .push_staged_signed_root(TEST_EPOCH, signed);

    let result =
        verify_kt_witness_signatures_for_epoch(&alice.core(), TEST_EPOCH, TEST_THRESHOLD).await;

    match result {
        Err(ClientError::Kt(KtError::InsufficientValidSignatures { valid, required })) => {
            assert_eq!(
                valid, 2,
                "unknown-witness signature MUST be silently skipped — adversary cannot \
                 boost count by minting their own witness pubkey; expected valid=2, \
                 got valid={valid}"
            );
            assert_eq!(required, TEST_THRESHOLD);
        }
        other => panic!(
            "unknown witness MUST be ignored; expected InsufficientValidSignatures \
             {{ valid: 2, required: 3 }}; got {other:?}"
        ),
    }
}

#[tokio::test]
async fn verify_witness_signatures_order_invariant_under_signature_reordering() {
    // Property: reordering `signed.signatures` must not change verification
    // outcome. Guards against accidental position-dependent logic in
    // canonical payload construction либо verify loop.
    let alice = bootstrap_client().await;
    let (ws, witness_set) = fresh_witness_set_of_5();
    let three_signers: Vec<&TestWitness> = ws.iter().take(3).collect();
    let mut signed_forward = build_signed_root(
        &three_signers,
        TEST_EPOCH,
        TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    let mut signed_reversed = signed_forward.clone();
    signed_reversed.signatures.reverse();
    // Sanity: actually different ordering.
    assert_ne!(
        signed_forward.signatures[0].witness, signed_reversed.signatures[0].witness,
        "reverse must change ordering"
    );
    // Mutate forward to a clone-via-cycle so we can compare both paths.
    signed_forward.signatures.rotate_left(1);

    alice
        .core()
        .kt_transport()
        .set_witness_set(witness_set.clone());

    alice
        .core()
        .kt_transport()
        .push_staged_signed_root(TEST_EPOCH, signed_forward);
    verify_kt_witness_signatures_for_epoch(&alice.core(), TEST_EPOCH, TEST_THRESHOLD)
        .await
        .expect("rotated 3-of-5 signatures must still pass threshold");

    // Restage with the reversed ordering — same expected outcome.
    alice
        .core()
        .kt_transport()
        .push_staged_signed_root(TEST_EPOCH, signed_reversed);
    verify_kt_witness_signatures_for_epoch(&alice.core(), TEST_EPOCH, TEST_THRESHOLD)
        .await
        .expect("reversed 3-of-5 signatures must still pass threshold");
}

#[tokio::test]
async fn verify_witness_signatures_detects_single_bit_flip_in_one_signature_reducing_count() {
    // Adversary intercepts a published witness signature and flips one bit
    // (transport-level tampering OR malicious cache). That single signature
    // becomes invalid — counts drop from 3 → 2 valid, threshold 3 fails.
    let alice = bootstrap_client().await;
    let (ws, witness_set) = fresh_witness_set_of_5();
    let three_signers: Vec<&TestWitness> = ws.iter().take(3).collect();
    let mut signed = build_signed_root(
        &three_signers,
        TEST_EPOCH,
        TEST_ROOT,
        TEST_LOG_SIZE,
        TEST_TIMESTAMP_MS,
    );
    signed.signatures[0].signature[0] ^= 0x01;

    alice.core().kt_transport().set_witness_set(witness_set);
    alice
        .core()
        .kt_transport()
        .push_staged_signed_root(TEST_EPOCH, signed);

    let result =
        verify_kt_witness_signatures_for_epoch(&alice.core(), TEST_EPOCH, TEST_THRESHOLD).await;

    match result {
        Err(ClientError::Kt(KtError::InsufficientValidSignatures { valid, required })) => {
            assert_eq!(
                valid, 2,
                "single-bit-flip in one signature MUST invalidate that one signature \
                 (count 3 → 2); got valid={valid}"
            );
            assert_eq!(required, TEST_THRESHOLD);
        }
        other => panic!(
            "single-sig bit-flip MUST fail with InsufficientValidSignatures \
             {{ valid: 2, required: 3 }}; got {other:?}"
        ),
    }
}
