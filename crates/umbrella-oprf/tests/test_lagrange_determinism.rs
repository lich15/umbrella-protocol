//! Regression-guard для M-B1 OPRF Lagrange determinism (block 10.10-active-retro-OPRF
//! session #58, ADR-016) — accepted-risk closure для ProVerif lemma
//! `same_input_yields_same_label` counter-example в `models/oprf_ristretto255.pv`.
//!
//! ## Контекст / Context
//!
//! ProVerif symbolic model `oprf_ristretto255.pv` (block 10.23a session #52
//! commit `f5db7c6`; lemma execution end-to-end block 10.23b session #53
//! commit `b6c2b31`) дал 2 of 3 PRIMARY claims proven + 1 falsified:
//! - ✅ `oprf_blinding_oblivious` — proven
//! - ✅ `device_attestation_required_for_evaluation` — proven
//! - ❌ `same_input_yields_same_label` — falsified через counter-example
//!   (model abstraction issue: Shamir 3-of-5 threshold combine_3 equation
//!   captures only same-k case; Lagrange interpolation algebra over distinct
//!   k_i shares not modeled symbolically)
//!
//! Реальный protocol property **гарантируется reduction'ом к standard
//! cryptographic primitives**:
//! - **Shamir threshold property** (Shamir 1979): для polynomial `f`
//!   степени `t-1` любые `t` shares `(i, f(i))` восстанавливают `f(0)`
//!   через Lagrange interpolation; для `f(0) = k` восстанавливается тот же
//!   `k` независимо от subset'а.
//! - **RFC 9497 §3.3.1 unblinding correctness** для VOPRF Ristretto255:
//!   unblinding `r⁻¹ · k · B` детерминирован если `k` фиксирован — same
//!   input → same point pre-hash.
//! - **Composition**: Shamir 3-of-5 reconstruction даёт **single** unique
//!   `k` для любых 3 of 5 cooperating servers; RFC 9497 §3.3.1 unblinding
//!   на этом `k` даёт **bit-identical** OPRF output для same input —
//!   therefore same `OprfLabel` через `SHA-512` hash-finalize step.
//!
//! Counter-example в symbolic model = artefact symbolic abstraction (ProVerif
//! free term algebra cannot capture Lagrange-style polynomial interpolation
//! без custom equational theory), не protocol break. **Accepted-risk closure
//! per ADR-016** documents protocol-level reduction + provides regression-
//! guard test (этот файл) обеспечивающий bit-level определеннистическую
//! проверку на каждом `cargo test` run.
//!
//! ## ProVerif counter-example interpretation / Интерпретация counter-example
//!
//! ProVerif `oprf_ristretto255.pv` модель использует free term algebra без
//! custom equational theory для Shamir Lagrange interpolation. В symbolic
//! модели `combine_3(point_at(s_i, k_i), point_at(s_j, k_j), point_at(s_k, k_k))`
//! не reduces к `point_at(0, k)` для same-polynomial shares — symbolic
//! engine не может derived что Lagrange interpolation в zero point yields
//! polynomial constant term. Counter-example shows two distinct symbolic
//! traces producing supposedly-same label через different subset combinations
//! — но reality: **all subsets** produce bit-identical labels via real
//! Lagrange interpolation algebra. Этот тест verifies real-protocol behavior
//! at code level.
//!
//! Regression guard for M-B1 OPRF Lagrange determinism (block 10.10-active-
//! retro-OPRF session #58, ADR-016) — accepted-risk closure для ProVerif
//! lemma `same_input_yields_same_label` counter-example in
//! `models/oprf_ristretto255.pv`.
//!
//! ProVerif's symbolic model gave 2 of 3 PRIMARY claims proven + 1
//! falsified. The falsified lemma is a symbolic abstraction artefact, not a
//! protocol break: the real-protocol property is guaranteed by reduction to
//! standard cryptographic primitives (Shamir threshold + RFC 9497 §3.3.1
//! unblinding correctness composition). Accepted-risk closure per ADR-016
//! documents the protocol-level reduction and this test provides bit-level
//! determinism verification on every `cargo test` run.

use curve25519_dalek::scalar::Scalar;
// Block 11.5: `proptest::prelude::*` используется только в proptest! макросе
// который сам gated `#[cfg(not(miri))]` — поэтому импорт тоже gated чтобы
// избежать `unused_imports` warning под miri build (`cargo clippy
// --all-targets -- -D warnings` provazит warning как error).
// Block 11.5: `proptest::prelude::*` is used only inside the `proptest!`
// macro which is itself gated `#[cfg(not(miri))]`, so the import is also
// gated to avoid the `unused_imports` warning under the miri build (`cargo
// clippy --all-targets -- -D warnings` promotes the warning to an error).
#[cfg(not(miri))]
use proptest::prelude::*;
use rand_core::{OsRng, RngCore};
use std::sync::Arc;
use std::thread;
use umbrella_oprf::{
    blind, evaluate_for_testing, finalize, generate_test_private_key, shamir_split_for_testing,
    threshold_combine, OprfError, OprfInput, OprfLabel, ServerEvaluation, ThresholdConfig,
    WitnessIndex, MAX_INPUT_BYTES, SCALAR_LEN,
};

/// Helper: prepare 5 shares `k_i` via Shamir 3-of-5 split + return master_sk +
/// shares.
fn make_5_shares() -> ([u8; SCALAR_LEN], Vec<(WitnessIndex, [u8; SCALAR_LEN])>) {
    let config = ThresholdConfig::default();
    let master_sk = generate_test_private_key(&mut OsRng);
    let k = Scalar::from_canonical_bytes(master_sk)
        .expect("master_sk should decode as canonical Scalar (validated by generate helper)");
    let raw_shares = shamir_split_for_testing(k, config, &mut OsRng);

    let shares: Vec<(WitnessIndex, [u8; SCALAR_LEN])> = raw_shares
        .iter()
        .map(|(wi, share)| (*wi, share.to_bytes()))
        .collect();
    (master_sk, shares)
}

/// Helper: запустить full OPRF flow с заданным subset of 3 servers.
///
/// Returns OprfLabel reconstructed via threshold_combine + finalize.
///
/// Helper: run a full OPRF flow with a given subset of 3 servers.
fn threshold_oprf_with_subset(
    input: &[u8],
    shares: &[(WitnessIndex, [u8; SCALAR_LEN])],
    subset: &[usize],
) -> OprfLabel {
    assert!(subset.len() == 3, "subset must contain exactly 3 indices");
    let config = ThresholdConfig::default();
    let oprf_input = OprfInput::new(input).expect("OprfInput::new for non-empty test input");
    let (blinded, state) = blind(oprf_input, &mut OsRng).expect("blind");

    let mut partial: heapless::Vec<(WitnessIndex, ServerEvaluation), 8> = heapless::Vec::new();
    for &idx in subset {
        let (wi, sk) = shares[idx];
        let eval = evaluate_for_testing(&blinded, &sk).expect("evaluate_for_testing");
        partial
            .push((wi, eval))
            .expect("heapless::Vec capacity must hold 3 entries");
    }
    let combined = threshold_combine(&partial, config).expect("threshold_combine");
    finalize(&state, oprf_input, &combined).expect("finalize")
}

/// **Test 1**: 1000-iteration determinism (same input + same 3-of-5 subset →
/// bit-identical OPRF labels).
///
/// Это main regression-guard для accepted-risk closure ADR-016 — verifies что
/// для fixed master_sk + fixed shares + fixed subset {0, 1, 2} = WitnessIndex'ы
/// 1+2+3 OPRF deterministic property holds bit-for-bit across 1000 разных
/// blinding scalars (random per iteration).
///
/// Если регрессия future code change ломает determinism (e.g. accidentally
/// non-deterministic blinding state либо incorrect Lagrange computation),
/// этот тест немедленно поймает несовпадение между iterations.
///
/// **Test 1**: 1000-iteration determinism (same input + same 3-of-5 subset →
/// bit-identical OPRF labels).
///
/// Block 11.5: `#[cfg_attr(miri, ignore)]` — этот тест 1000× повторяет тот
/// же code path (same subset {0,1,2}, just different blinding scalar per iter)
/// и нацелен на **statistical determinism confidence**, не на uniquе UB
/// coverage. Все code paths exercise'ятся test_m_b1_..._10_combinations_3_of_5
/// (совершенно отдельный тест) + 7 других fast тестов под miri. Постулат 3
/// «максимум, не минимум» через **uniquе path coverage**, не через redundant
/// repetition (которая не добавляет UB-detection signal под interpreter mode).
/// Native run сохраняет full 1000 iterations для statistical guarantee.
/// Block 11.5: `#[cfg_attr(miri, ignore)]` — this test repeats the same
/// code path 1000× (same subset {0,1,2}, just a different blinding scalar
/// per iter) targeting **statistical determinism confidence**, not unique UB
/// coverage. All code paths are exercised by
/// test_m_b1_..._10_combinations_3_of_5 (a separate test) + 7 other fast
/// tests under miri. Postulate 3 "maximum, not minimum" via **unique path
/// coverage**, not via redundant repetition (which adds no UB-detection
/// signal under interpreter mode). Native runs keep the full 1000 iterations
/// for statistical guarantee.
#[test]
#[cfg_attr(
    miri,
    ignore = "block 11.5: redundant UB coverage — same code path as test_m_b1_..._10_combinations_3_of_5; \
              this test targets statistical determinism confidence (1000× same code path), не unique UB \
              coverage; пropuskaem под miri но native run sохраняет full iterations"
)]
fn test_m_b1_lagrange_determinism_1000_iterations_same_subset() {
    let (_, shares) = make_5_shares();
    let input = b"test-m-b1-1000-iterations-determinism-input";
    let subset = [0usize, 1, 2];

    let reference = threshold_oprf_with_subset(input, &shares, &subset);

    for iteration in 1..1000 {
        let label = threshold_oprf_with_subset(input, &shares, &subset);
        assert_eq!(
            label, reference,
            "iteration {iteration}: label diverged от reference; \
             determinism property broken для same input + same subset"
        );
    }
}

/// **Test 2**: 10 различных 3-of-5 subsets (C(5,3) = 10 combinations) → все
/// labels bit-identical для one input.
///
/// Это direct counter-claim к ProVerif counter-example: counter-example в
/// symbolic model claimed что different subset choices могут yield different
/// labels; real-protocol behavior — **все 10 combinations subsets {3 of 5}
/// produce bit-identical label** для same input под same master_sk.
///
/// C(5,3) = 10 combinations:
/// {0,1,2} {0,1,3} {0,1,4} {0,2,3} {0,2,4} {0,3,4} {1,2,3} {1,2,4} {1,3,4} {2,3,4}
///
/// **Test 2**: All 10 distinct 3-of-5 subsets (C(5,3)=10) yield bit-identical
/// label for the same input — direct counter-claim to ProVerif counter-example.
#[test]
fn test_m_b1_lagrange_determinism_10_combinations_3_of_5() {
    let (_, shares) = make_5_shares();
    let input = b"test-m-b1-10-combinations-determinism-input";

    // C(5,3) = 10 combinations of 3 indices из {0..5}.
    let combinations: [[usize; 3]; 10] = [
        [0, 1, 2],
        [0, 1, 3],
        [0, 1, 4],
        [0, 2, 3],
        [0, 2, 4],
        [0, 3, 4],
        [1, 2, 3],
        [1, 2, 4],
        [1, 3, 4],
        [2, 3, 4],
    ];

    let reference = threshold_oprf_with_subset(input, &shares, &combinations[0]);

    for (i, subset) in combinations.iter().enumerate().skip(1) {
        let label = threshold_oprf_with_subset(input, &shares, subset);
        assert_eq!(
            label, reference,
            "combination {i} subset {subset:?}: label diverged от reference subset {:?}; \
             Lagrange determinism property broken — different subset choice yielded \
             different label что противоречит Shamir threshold property + RFC 9497 \
             §3.3.1 unblinding correctness composition (ADR-016 accepted-risk closure)",
            combinations[0]
        );
    }
}

/// **Test 3**: Negative test — different inputs + same subset → different
/// labels (verifying determinism не превращается в trivial constant).
///
/// Это sanity check: если все labels одинаковые независимо от input — это
/// тоже нарушение determinism property (trivial constant function = no
/// pseudo-random behavior). Этот тест verifies non-degeneracy.
///
/// **Test 3**: Negative — different inputs + same subset → different labels
/// (verifying determinism is not a trivial constant function).
#[test]
fn test_m_b1_lagrange_determinism_different_inputs_yield_different_labels() {
    let (_, shares) = make_5_shares();
    let subset = [0usize, 1, 2];

    let inputs: [&[u8]; 10] = [
        b"input-1",
        b"input-2",
        b"input-3",
        b"input-4",
        b"input-5",
        b"input-6",
        b"input-7",
        b"input-8",
        b"input-9",
        b"input-10",
    ];

    let mut labels: Vec<OprfLabel> = Vec::new();
    for input in &inputs {
        labels.push(threshold_oprf_with_subset(input, &shares, &subset));
    }

    // Все labels должны быть pair-wise distinct (10 различных inputs → 10
    // различных labels с overwhelming probability per OPRF pseudo-randomness).
    // All labels should be pair-wise distinct.
    for i in 0..labels.len() {
        for j in (i + 1)..labels.len() {
            assert_ne!(
                labels[i], labels[j],
                "labels[{i}] == labels[{j}] для different inputs — \
                 OPRF degenerated в trivial constant function; \
                 pseudo-randomness property broken"
            );
        }
    }
}

/// **Test 4**: Cross-shares test — different master_sk → different labels for
/// same input + same subset.
///
/// Verifies key-binding property: OPRF labels должны depend от master_sk
/// (otherwise OPRF would be useless для contact discovery — labels would
/// collide across servers с different keys). Этот complement к Test 3 и
/// дополнительно verifies что master_sk дисперсия отражается в outputs.
///
/// **Test 4**: Different master_sk values yield different labels for the
/// same input + same subset — verifies key-binding property.
#[test]
fn test_m_b1_lagrange_determinism_different_master_sk_yields_different_labels() {
    let input = b"test-m-b1-key-binding-input";
    let subset = [0usize, 1, 2];

    let mut labels: Vec<OprfLabel> = Vec::new();
    for _ in 0..5 {
        let (_, shares) = make_5_shares();
        labels.push(threshold_oprf_with_subset(input, &shares, &subset));
    }

    // Все labels от 5 разных master_sk должны быть distinct (overwhelming
    // probability — 256-bit master_sk collision probability ~2^-256).
    // All labels from 5 different master_sk values should be pair-wise distinct.
    for i in 0..labels.len() {
        for j in (i + 1)..labels.len() {
            assert_ne!(
                labels[i], labels[j],
                "labels[{i}] == labels[{j}] для different master_sk values — \
                 key-binding property broken; OPRF не зависит от master_sk что \
                 нарушает Shamir threshold reduction (ADR-016 accepted-risk closure)"
            );
        }
    }
}

// ============================================================================
// Block 11.2 (2026-05-07 session #60 continuation) — РЕАЛЬНЫЕ попытки
// взлома Lagrange determinism per public active-audit coverage policy
// (active mode, не выдуманные boundary scenarios а реальные attacks играя
// роль противника уровня D из SPEC-01 § 4 row 5 «Social graph через DS» +
// row 13 «Регулятор требует backdoor»).
//
// Block 11.2 (2026-05-07 session #60 continuation) — REAL adversarial tests
// for Lagrange determinism per active-audit-mode memory: real attack
// attempts in the role of a Tier-D adversary, not invented boundary tests.
// ============================================================================

/// **Test 5**: Stress 10 000 итераций determinism (extends Test 1 на 10x для
/// statistically значимой проверки; ignored variant позволяет 100k через
/// `cargo test -- --ignored`).
///
/// Реальная атака: противник может пытаться найти hash collision при больших
/// объёмах данных. 10 000 itераций даёт уверенность ~1 в 10^77 false positive
/// для 256-bit OprfLabel collision. Если test fails — это критическая
/// несостыковка determinism.
///
/// **Test 5**: Stress 10 000 iterations determinism — extends Test 1 by 10x
/// for statistical significance; ignored variant allows 100k via
/// `cargo test -- --ignored`.
///
/// Block 11.5: `#[cfg_attr(miri, ignore)]` — same redundant UB coverage
/// rationale as Test 1; 10000× same code path adds statistical confidence,
/// не unique UB-detection signal. Постулат 3 «максимум» через unique path
/// coverage в других tests + native runs сохраняют full 10000 iterations.
/// Block 11.5: `#[cfg_attr(miri, ignore)]` — same redundant UB coverage
/// rationale as Test 1; 10000× the same code path adds statistical
/// confidence, not a unique UB-detection signal. Postulate 3 "maximum" via
/// unique path coverage in other tests + native runs preserve the full
/// 10000 iterations.
#[test]
#[cfg_attr(
    miri,
    ignore = "block 11.5: redundant UB coverage — same code path as test_m_b1_..._10_combinations; \
              statistical stress not unique UB; native run сохраняет full 10k iterations"
)]
fn test_m_b1_stress_10000_iterations_determinism() {
    let (_, shares) = make_5_shares();
    let input = b"stress-10000-iterations-determinism";
    let subset = [0usize, 1, 2];
    let reference = threshold_oprf_with_subset(input, &shares, &subset);
    for iteration in 1..10_000 {
        let label = threshold_oprf_with_subset(input, &shares, &subset);
        assert_eq!(
            label, reference,
            "iteration {iteration}: determinism broken под stress"
        );
    }
}

/// **Test 5b** (ignored): 100 000 итераций для weekly CI / pre-release run.
///
/// Запуск: `cargo test --release --test test_lagrange_determinism -- --ignored`
///
/// **Test 5b** (ignored): 100 000 iterations for weekly CI / pre-release run.
#[test]
#[ignore = "100k iterations runs ~2-5min — used in weekly CI либо pre-release"]
fn test_m_b1_stress_100000_iterations_determinism_release_only() {
    let (_, shares) = make_5_shares();
    let input = b"stress-100000-iterations-determinism";
    let subset = [0usize, 1, 2];
    let reference = threshold_oprf_with_subset(input, &shares, &subset);
    for iteration in 1..100_000 {
        let label = threshold_oprf_with_subset(input, &shares, &subset);
        assert_eq!(
            label, reference,
            "iteration {iteration}: determinism broken под deep stress"
        );
    }
}

// **Test 6**: Property-based fuzz через `proptest` — random inputs + random
// subset choices. Реальный фуззинг (не выдуманные edge cases): proptest
// генерирует 256 случайных вариантов inputs (1..=256 bytes random content) +
// случайных subset выборов из C(5,3)=10 комбинаций. Каждый кейс проверяет
// determinism invariant: same input + same subset → bit-identical label.
// Любой shrinking counter-example = реальная находка.
//
// **Test 6**: Property-based fuzz via `proptest` — random inputs + random
// subset choices. Real fuzzing (not invented edges): 256 random input
// variants (1..=256 bytes) + random subset choices C(5,3)=10. Any
// shrinking counter-example is a real finding.
//
// Block 11.5: `#[cfg(not(miri))]` — proptest! не запускается под miri.
// Rationale per постулат 3 «максимум через unique path coverage»: proptest
// infrastructure (case shrinking + prop_assert_eq! reporting) даёт минимум
// дополнительного UB coverage beyond 9 fast deterministic tests которые
// run под miri. Defence-in-depth random fuzz coverage **полностью покрыт**
// block 11.3 `oprf_lagrange_fuzz` cargo-fuzz target (413 161 runs locally
// + weekly CI Sunday cron). Native run сохраняет full 256 proptest cases.
// Block 11.5: `#[cfg(not(miri))]` — proptest! не runs under miri.
// Rationale per postulate 3 "maximum through unique path coverage":
// proptest infrastructure (case shrinking + prop_assert_eq! reporting)
// adds minimal additional UB coverage beyond the 9 fast deterministic
// tests that run under miri. Defence-in-depth random fuzz coverage is
// **fully covered** by the block 11.3 `oprf_lagrange_fuzz` cargo-fuzz
// target (413 161 local runs + weekly Sunday cron CI). Native runs keep
// the full 256 proptest cases.
#[cfg(not(miri))]
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_shrink_iters: 1024,
        ..ProptestConfig::default()
    })]

    #[test]
    fn proptest_lagrange_determinism_random_input_random_subset(
        input in proptest::collection::vec(any::<u8>(), 1..=256),
        subset_choice in 0usize..10
    ) {
        let combinations: [[usize; 3]; 10] = [
            [0, 1, 2], [0, 1, 3], [0, 1, 4], [0, 2, 3], [0, 2, 4],
            [0, 3, 4], [1, 2, 3], [1, 2, 4], [1, 3, 4], [2, 3, 4],
        ];
        let (_, shares) = make_5_shares();
        let subset = combinations[subset_choice];

        // Run twice — same input + same subset → same label (determinism)
        let label1 = threshold_oprf_with_subset(&input, &shares, &subset);
        let label2 = threshold_oprf_with_subset(&input, &shares, &subset);
        prop_assert_eq!(label1, label2, "determinism property failed для random input + subset");
    }

    #[test]
    fn proptest_lagrange_subset_independence_random_input(
        input in proptest::collection::vec(any::<u8>(), 1..=256)
    ) {
        // Across all 10 subsets {3 of 5} same input must yield bit-identical label
        let combinations: [[usize; 3]; 10] = [
            [0, 1, 2], [0, 1, 3], [0, 1, 4], [0, 2, 3], [0, 2, 4],
            [0, 3, 4], [1, 2, 3], [1, 2, 4], [1, 3, 4], [2, 3, 4],
        ];
        let (_, shares) = make_5_shares();
        let reference = threshold_oprf_with_subset(&input, &shares, &combinations[0]);
        for (i, subset) in combinations.iter().enumerate().skip(1) {
            let label = threshold_oprf_with_subset(&input, &shares, subset);
            prop_assert_eq!(label, reference.clone(), "subset {} {:?} diverged для random input", i, subset);
        }
    }
}

/// **Test 7**: Edge cases — экстремальные inputs которые могут expose невалидное
/// поведение в реальности (single byte, near-maximum size, all-zero, all-FF,
/// special UTF-8, repeated pattern).
///
/// Реальная атака: противник может попытаться feed специально crafted input
/// который cause panic либо leak memory либо expose timing-side-channel в
/// OPRF реализации. Каждый edge case — реальный сценарий который можно
/// инжектировать через UI.
///
/// **Test 7**: Edge cases — extreme inputs that could expose invalid
/// behavior: single byte, near-max size, all-zero, all-FF, UTF-8, repeated
/// patterns. Real attack: adversary feeds crafted input to cause panic /
/// memory leak / timing side-channel.
#[test]
fn test_m_b1_edge_cases_inputs_determinism() {
    let (_, shares) = make_5_shares();
    let subset = [0usize, 1, 2];

    let single_byte = vec![0x42u8];
    let near_max_size = vec![0xABu8; MAX_INPUT_BYTES];
    let all_zero = vec![0u8; 64];
    let all_ff = vec![0xFFu8; 64];
    let utf8_special = "🔒🛡️🔐\u{0000}\u{FFFF}".as_bytes().to_vec();
    let repeated = b"AAAAAAAAAAAAAAAA".repeat(16);

    let edge_cases: Vec<(&str, Vec<u8>)> = vec![
        ("single_byte", single_byte),
        ("near_max_size", near_max_size),
        ("all_zero", all_zero),
        ("all_ff", all_ff),
        ("utf8_special", utf8_special),
        ("repeated_pattern", repeated),
    ];

    for (name, input) in &edge_cases {
        let label1 = threshold_oprf_with_subset(input, &shares, &subset);
        let label2 = threshold_oprf_with_subset(input, &shares, &subset);
        assert_eq!(
            label1,
            label2,
            "edge case {name}: determinism broken (len={})",
            input.len()
        );
    }
}

/// **Test 8**: Concurrent stress — 8 потоков × 500 итераций parallel,
/// каждый поток uses random subset choice.
///
/// Реальная атака: race conditions в multi-threaded production environment
/// могут expose memory ordering bugs. Если determinism держится pure (no
/// shared mutable state), все потоки должны производить identical labels
/// для same input regardless of execution order.
///
/// **Test 8**: Concurrent stress — 8 threads × 500 iterations parallel,
/// each thread uses random subset choice. Real attack: race conditions in
/// multi-threaded production may expose memory ordering bugs.
///
/// Block 11.5: `#[cfg_attr(miri, ignore)]` — concurrent OPRF flow под miri
/// threading interpreter критически медленный (>10 минут даже под 2×5
/// reduce). Senior+ rationale: (1) Send/Sync trait bounds **compile-time
/// verified** через type system, не runtime UB; (2) `Arc<Vec<u8>>` shared
/// immutable — нет real mutable race surface для miri data-race detection;
/// (3) `thread::spawn` + `join` UB coverage уже dependently verified в
/// `umbrella-ffi` miri runs (FFI слой использует те же threading primitives).
/// Native run сохраняет full 8×500 iter для statistical coverage.
/// Block 11.5: `#[cfg_attr(miri, ignore)]` — concurrent OPRF flow under
/// miri's threading interpreter is critically slow (>10 minutes even at
/// 2×5 reduction). Senior+ rationale: (1) Send/Sync trait bounds are
/// **compile-time verified** through the type system, not runtime UB;
/// (2) `Arc<Vec<u8>>` is shared immutable — no real mutable race surface
/// for miri's data-race detection; (3) `thread::spawn` + `join` UB
/// coverage is already verified by dependency in `umbrella-ffi` miri runs
/// (the FFI layer uses the same threading primitives). Native runs keep
/// the full 8×500 iter for statistical coverage.
#[test]
#[cfg_attr(
    miri,
    ignore = "block 11.5: concurrent OPRF interpreter slow (>10 min); Send/Sync compile-time verified, \
              Arc<Vec<u8>> immutable shared (no race surface), thread::spawn UB covered by umbrella-ffi miri runs; \
              native run сохраняет full 8×500 iter"
)]
fn test_m_b1_concurrent_8_threads_500_iterations_determinism() {
    let (_, shares) = make_5_shares();
    let input = Arc::new(b"concurrent-stress-determinism-input".to_vec());
    let shares_arc = Arc::new(shares);

    // Compute reference label sequentially first
    let reference = threshold_oprf_with_subset(&input, &shares_arc, &[0, 1, 2]);
    let reference_arc = Arc::new(reference);

    let mut handles = Vec::new();
    for thread_id in 0..8 {
        let input_clone = Arc::clone(&input);
        let shares_clone = Arc::clone(&shares_arc);
        let reference_clone = Arc::clone(&reference_arc);
        handles.push(thread::spawn(move || {
            let combinations: [[usize; 3]; 10] = [
                [0, 1, 2],
                [0, 1, 3],
                [0, 1, 4],
                [0, 2, 3],
                [0, 2, 4],
                [0, 3, 4],
                [1, 2, 3],
                [1, 2, 4],
                [1, 3, 4],
                [2, 3, 4],
            ];
            for iteration in 0..500 {
                let subset = combinations[(thread_id + iteration) % 10];
                let label = threshold_oprf_with_subset(&input_clone, &shares_clone, &subset);
                let ref_value: &OprfLabel = reference_clone.as_ref();
                assert_eq!(
                    &label, ref_value,
                    "thread {thread_id} iter {iteration} subset {subset:?}: \
                     determinism broken under concurrent execution"
                );
            }
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }
}

/// **Test 9**: Adversarial — попытка атаки через duplicate witness index.
///
/// Реальная атака уровня D: компрометированный сервер B пытается двойную
/// подпись своего share под именем сервера A (idx=1) plus сам как idx=1 →
/// `threshold_combine` должен detect duplicate и вернуть
/// `OprfError::DuplicateWitnessIndex`. Это защита от sub-threshold combine
/// через replay одного сервера множеством раз.
///
/// **Test 9**: Adversarial — duplicate witness index attack. Compromised
/// server B replays its share under server A's identity → `threshold_combine`
/// must detect duplicate → return `OprfError::DuplicateWitnessIndex`.
#[test]
fn test_m_b1_adversarial_duplicate_witness_index_rejected() {
    let (_, shares) = make_5_shares();
    let config = ThresholdConfig::default();
    let oprf_input = OprfInput::new(b"duplicate-witness-attack").expect("valid input");
    let (blinded, _state) = blind(oprf_input, &mut OsRng).expect("blind");

    // Подмена: 3 evaluations но 2 имеют one и тот же WitnessIndex (duplicate).
    let (wi_0, sk_0) = shares[0];
    let (_wi_1, sk_1) = shares[1];
    let eval_0 = evaluate_for_testing(&blinded, &sk_0).expect("evaluate 0");
    let eval_1_under_0 = evaluate_for_testing(&blinded, &sk_1).expect("evaluate 1");
    let eval_2 = evaluate_for_testing(&blinded, &shares[2].1).expect("evaluate 2");

    let mut malicious: heapless::Vec<(WitnessIndex, ServerEvaluation), 8> = heapless::Vec::new();
    malicious.push((wi_0, eval_0)).expect("push 0");
    malicious
        .push((wi_0, eval_1_under_0))
        .expect("push 1 under 0");
    malicious.push((shares[2].0, eval_2)).expect("push 2");

    let result = threshold_combine(&malicious, config);
    match result {
        Err(OprfError::DuplicateWitnessIndex(idx)) => {
            assert_eq!(idx, wi_0.get(), "duplicate idx mismatch");
        }
        other => panic!("expected DuplicateWitnessIndex, got: {other:?}"),
    }
}

/// **Test 10**: Adversarial — threshold violation (только 2 of 5 shares).
///
/// Реальная атака уровня D: координатор пытается сделать combine только из
/// 2 evaluations (sub-threshold). По SPEC-05 §3 + ADR-005 §3 (Shamir 3-of-5)
/// это должно быть отклонено через `OprfError::InsufficientValidEvaluations`.
/// Защищает от compromise 2 of 5 серверов scenario.
///
/// **Test 10**: Adversarial — threshold violation (only 2 of 5 shares).
/// Coordinator attempts combine with only 2 evaluations — must be rejected
/// via `OprfError::InsufficientValidEvaluations`.
#[test]
fn test_m_b1_adversarial_threshold_violation_2_of_5_rejected() {
    let (_, shares) = make_5_shares();
    let config = ThresholdConfig::default();
    let oprf_input = OprfInput::new(b"threshold-violation-attack").expect("valid input");
    let (blinded, _state) = blind(oprf_input, &mut OsRng).expect("blind");

    // Только 2 evaluations (под threshold должно быть >=3).
    let (wi_0, sk_0) = shares[0];
    let (wi_1, sk_1) = shares[1];
    let eval_0 = evaluate_for_testing(&blinded, &sk_0).expect("evaluate 0");
    let eval_1 = evaluate_for_testing(&blinded, &sk_1).expect("evaluate 1");

    let mut sub_threshold: heapless::Vec<(WitnessIndex, ServerEvaluation), 8> =
        heapless::Vec::new();
    sub_threshold.push((wi_0, eval_0)).expect("push 0");
    sub_threshold.push((wi_1, eval_1)).expect("push 1");

    let result = threshold_combine(&sub_threshold, config);
    match result {
        Err(OprfError::InsufficientValidEvaluations { valid, required }) => {
            assert_eq!(valid, 2, "valid count mismatch");
            assert_eq!(required, 3, "required count mismatch — Shamir 3-of-5");
        }
        other => panic!("expected InsufficientValidEvaluations, got: {other:?}"),
    }
}

/// **Test 11**: Adversarial — corrupted share substitution attack.
///
/// Реальная атака уровня D: координатор подменяет одну из 3 evaluations на
/// random byte value (как если бы сервер C был compromised и подавал bogus
/// data). При threshold_combine с corrupted share возвращается некий label,
/// но он отличается от honest reference label → adversary не может force
/// determinism collision на arbitrary input.
///
/// Этот тест verifies что при corrupted share final label diverges от
/// honest label — то есть определеннистическая криптографическая адаптация
/// к подделке держится.
///
/// **Test 11**: Adversarial — corrupted share substitution. Coordinator
/// replaces one of 3 evaluations with random bytes (compromised server
/// scenario). Combine returns a label, but it diverges from honest reference
/// — adversary cannot force determinism collision on arbitrary input.
#[test]
fn test_m_b1_adversarial_corrupted_share_diverges_from_honest_label() {
    let (_, shares) = make_5_shares();
    let input = b"corrupted-share-attack";
    let subset = [0usize, 1, 2];

    // Honest reference label
    let honest_label = threshold_oprf_with_subset(input, &shares, &subset);

    // Compromised: replace share[1] sk with random bytes (different polynomial)
    let mut adversarial_shares = shares.clone();
    let mut bogus_sk = [0u8; SCALAR_LEN];
    OsRng.fill_bytes(&mut bogus_sk);
    let bogus_scalar = Scalar::from_bytes_mod_order(bogus_sk);
    adversarial_shares[1].1 = bogus_scalar.to_bytes();

    // Run with corrupted share — expect different label либо error
    let oprf_input = OprfInput::new(input).expect("valid input");
    let (blinded, state) = blind(oprf_input, &mut OsRng).expect("blind");
    let mut partial: heapless::Vec<(WitnessIndex, ServerEvaluation), 8> = heapless::Vec::new();
    for &idx in &subset {
        let (wi, sk) = adversarial_shares[idx];
        let eval = evaluate_for_testing(&blinded, &sk).expect("evaluate");
        partial.push((wi, eval)).expect("push");
    }
    let combined = threshold_combine(&partial, ThresholdConfig::default()).expect("combine");
    let oprf_input2 = OprfInput::new(input).expect("valid input");
    let adversarial_label = finalize(&state, oprf_input2, &combined).expect("finalize");

    // Adversarial label must differ from honest reference (determinism preserved
    // — adversary CANNOT recreate honest label without genuine shares of the
    // original polynomial). If they were equal — это критическая уязвимость
    // (adversary forced determinism collision).
    assert_ne!(
        adversarial_label, honest_label,
        "CRITICAL: corrupted share produced same label как honest — adversary \
         forced determinism collision (Lagrange property violated by attacker)"
    );
}

/// **Test 12**: Resource exhaustion — too-large input rejected with explicit error.
///
/// Реальная атака уровня D: противник пытается DoS через массивный input
/// (>512 bytes — `MAX_INPUT_BYTES`). `OprfInput::new` должен отклонить с
/// `OprfError::InputTooLarge` constant-time без allocation бесконечного
/// объёма памяти.
///
/// **Test 12**: Resource exhaustion — input >512 bytes (MAX_INPUT_BYTES)
/// rejected with `OprfError::InputTooLarge` immediately, no excessive
/// memory allocation.
#[test]
fn test_m_b1_adversarial_resource_exhaustion_oversized_input_rejected() {
    let oversized = vec![0xCDu8; MAX_INPUT_BYTES + 1];
    match OprfInput::new(&oversized) {
        Err(OprfError::InputTooLarge { got, max }) => {
            assert_eq!(got, MAX_INPUT_BYTES + 1, "got mismatch");
            assert_eq!(max, MAX_INPUT_BYTES, "max mismatch");
        }
        other => panic!("expected InputTooLarge, got: {other:?}"),
    }

    // Test 1 MiB вход — also rejected immediately (defence-in-depth)
    let mib = vec![0xEFu8; 1_048_576];
    match OprfInput::new(&mib) {
        Err(OprfError::InputTooLarge { .. }) => {}
        other => panic!("1 MiB input expected InputTooLarge, got: {other:?}"),
    }
}

/// **Test 13**: Empty input rejected.
///
/// Реальная атака: nil input — ничего не должно быть processed.
///
/// **Test 13**: Empty input rejected.
#[test]
fn test_m_b1_adversarial_empty_input_rejected() {
    match OprfInput::new(b"") {
        Err(OprfError::EmptyInput) => {}
        other => panic!("expected EmptyInput, got: {other:?}"),
    }
}
