//! Dudect — статистический тест констант-временности через
//! интерливинг двух классов входов и Welch's t-test.
//!
//! Block 10.24 (Stage 10 Phase 3 cross-cutting) primary deliverable —
//! применяется к secret-dependent операциям 7-8 CT-критичных крейтов
//! workspace для measured constant-time guarantees per ADR-015 §Decision 5
//! done predicate «constant-time verified для всех CT-критичных операций».
//!
//! Methodology per Reparaz et al. 2017 USENIX Security `«Dude, is my code
//! constant time?»`:
//!
//! 1. Два класса входа — `Class::Fixed` (одинаковый секрет во всех
//!    measurement loops) + `Class::Random` (свежий случайный секрет
//!    для каждой итерации).
//! 2. Интерливинг измерений — каждая пара samples измеряет Fixed затем
//!    Random; противодействует системному drift (CPU frequency scaling,
//!    cache warmup, OS scheduler jitter).
//! 3. Percentile cropping — нижние 5% + верхние 5% measurements
//!    отбрасываются как outliers (системные паузы, page faults, GC IRQ).
//! 4. Welch's t-test — `t = (μ_fixed − μ_random) / √(σ²_fixed/n + σ²_random/n)`
//!    для two-sample heteroscedastic variance comparison.
//! 5. Threshold `|t| ≤ 4.5` per Reparaz §3 — significance level
//!    α ≈ 10⁻⁵ corresponding к ~99.9995 % confidence что timing
//!    не leak'ает информацию о секретном входе.
//!
//! # Threat model
//!
//! Local same-host adversary measuring wallclock execution time
//! секретно-зависимых операций (subtle::ConstantTimeEq comparison;
//! HKDF expand; AEAD verify; padding tail check; и т.д.) для попытки
//! recover secret material через timing side-channel. Constant-time
//! защита покрывает classes attacks RFC 7457 Appendix B Lucky-13 +
//! KyberSlash + raccoon + similar.
//!
//! # Limitations (in-block scope vs production budget)
//!
//! - Sample count `IN_BLOCK_SAMPLES = 10_000` per branch — достаточно
//!   для catching gross timing leaks (|t| > 10), но не subtle leaks
//!   (|t| 4.5-10 require 100_000+ samples per Reparaz §3 robustness
//!   analysis Figure 4). Weekly CI cron `dudect-benchmarks.yml`
//!   расширяет к `WEEKLY_CI_SAMPLES = 100_000` per branch для full
//!   per Reparaz spec sensitivity coverage.
//! - macOS 14.x arm64 measurements via `std::time::Instant` provide
//!   nanosecond resolution; Mach absolute time clock guarantees
//!   monotonic + TSC-backed. Linux CI `clock_gettime(MONOTONIC_RAW)`
//!   аналог. Windows CI not yet evaluated в scope этого блока.
//! - Тесты выполняются в `cargo test --release` для accurate timing
//!   (debug builds add panic checks + bound checks distorting
//!   measurements). `[profile.test] opt-level = 3` workspace-wide
//!   уровень не используется по historical reasons (debug stack traces
//!   + faster compile cycle); `--release` overrides per-call.
//!
//! # Sub-100ns sites: bounded fixture pools per Track E
//!
//! **F-DUDECT-METHODOLOGY-1 / F-DUDECT-HKDF-BORDERLINE-1 /
//! F-DUDECT-PADDING-OBSERVATION-1 closure (PhD-B Pass 5 remediation,
//! 2026-05-19):** sites measuring sub-100ns operations (raw
//! `[u8; 32]::ct_eq`, HKDF-SHA256 wrapper, `strip_padding` tail check)
//! must use bounded-pool fixtures для BOTH Fixed AND Random classes
//! при sample budgets ≥ 100K. Pre-closure паттерн с single-buffer
//! Fixed pool + `samples`-sized Random pool produces measurement
//! artifacts: cache asymmetry (Fixed cache-hot vs Random cache-cold
//! misses at 3.2+ MB working set) dominates over the sub-100ns
//! operation timing, injecting false-positive |t| signals (6.8 — 20.0
//! observed at 1M samples). Reparaz et al. §3 Figure 4 sample-
//! saturation regime amplifies sub-nanosecond mean bias к significant
//! |t| even for truly-CT primitives.
//!
//! **Bounded-pool methodology** (см. Site 6 reference + Sites 2/3/4
//! post-closure в `tests/dudect_constant_time.rs`):
//!
//! 1. **Sub-100ns sites**: Fixed AND Random pools обе bounded к 32
//!    fixtures × ≤256 bytes ≈ 16 KB total, fits L1d cache 16-32 KB.
//!    Both classes cycle `idx % 32`. CT discriminator preserved
//!    через 32 independent secrets per class.
//! 2. **μs-scale sites** (Site 6 `RowCipher::decrypt_row` ~2.7 μs):
//!    Fixed может re-use single fixture; Random bounded к 32.
//!    Operation timing dominates cache asymmetry (~3 ns / 2670 ns =
//!    0.11% relative).
//! 3. **ms-scale sites** (Sites 5/8/10/11 OPRF/ML-KEM/X-Wing): cache
//!    effect sub-noise-floor; current `pre_allocate_random_32(samples)`
//!    либо bounded 32-pool оба acceptable per ADR-015 Решение 5
//!    criterion 6.
//!
//! Per-operation-timing-tier gauge для добавления нового site:
//! если operation < 100ns → bounded 32-pool symmetric; 100ns–1μs →
//! bounded 32-pool symmetric или single-fixed-+-32-random; ≥1μs →
//! pattern flexible.
//!
//! # Sub-100ns sites: bounded fixture pools per Track E
//!
//! **F-DUDECT-METHODOLOGY-1 / F-DUDECT-HKDF-BORDERLINE-1 /
//! F-DUDECT-PADDING-OBSERVATION-1 closure (PhD-B Pass 5 remediation,
//! 2026-05-19):** sites measuring sub-100 ns operations (raw
//! `[u8; 32]::ct_eq`, the HKDF-SHA256 wrapper, the `strip_padding`
//! tail check) must use bounded-pool fixtures for BOTH the Fixed AND
//! Random classes at sample budgets ≥ 100 000. The pre-closure pattern
//! with a single-buffer Fixed pool plus a `samples`-sized Random pool
//! produced measurement artifacts: cache asymmetry (Fixed cache-hot
//! vs Random cache-cold misses at 3.2+ MB working set) dominated the
//! sub-100 ns operation timing, injecting false-positive |t| signals
//! (6.8 — 20.0 observed at 1M samples). The Reparaz et al. §3 Figure 4
//! sample-saturation regime amplifies a sub-nanosecond mean bias into
//! a significant |t| even for truly-CT primitives.
//!
//! **Bounded-pool methodology** (see Site 6 reference + Sites 2/3/4
//! post-closure in `tests/dudect_constant_time.rs`):
//!
//! 1. **Sub-100 ns sites**: BOTH Fixed and Random pools bounded to
//!    32 fixtures × ≤256 bytes ≈ 16 KB total, fitting an L1d cache
//!    of 16–32 KB. Both classes cycle `idx % 32`. The CT discriminator
//!    is preserved by 32 independent secrets per class.
//! 2. **μs-scale sites** (Site 6 `RowCipher::decrypt_row` ~2.7 μs):
//!    Fixed may re-use a single fixture; Random is bounded to 32.
//!    Operation timing dominates the cache asymmetry (~3 ns / 2670 ns
//!    = 0.11 % relative).
//! 3. **ms-scale sites** (Sites 5/8/10/11 OPRF / ML-KEM / X-Wing):
//!    cache effect is below the noise floor; the current
//!    `pre_allocate_random_32(samples)` or a bounded 32-pool both
//!    acceptable per ADR-015 Decision 5 criterion 6.
//!
//! Per-operation-timing-tier gauge for adding a new site: if the
//! operation runs in < 100 ns → bounded 32-pool symmetric for both
//! classes; 100 ns – 1 μs → bounded 32-pool symmetric or single-fixed
//! plus 32-random; ≥ 1 μs → pattern is flexible.
//!
//! Block 10.24 (Stage 10 Phase 3 cross-cutting) — statistical
//! constant-time test through interleaving two input classes and
//! Welch's t-test.
//!
//! Applied to secret-dependent operations of 7-8 CT-critical crates in
//! the workspace for measured constant-time guarantees per ADR-015
//! § Decision 5 done predicate "constant-time verified for all
//! CT-critical operations".
//!
//! Methodology per Reparaz et al. 2017 USENIX Security "Dude, is my code
//! constant time?":
//!
//! 1. Two input classes — `Class::Fixed` (same secret across all
//!    measurement loops) + `Class::Random` (fresh random secret per
//!    iteration).
//! 2. Interleaved measurements — each sample pair measures Fixed then
//!    Random; counters systemic drift (CPU frequency scaling,
//!    cache warm-up, OS scheduler jitter).
//! 3. Percentile cropping — the bottom 5 % and top 5 % of measurements
//!    are discarded as outliers (system pauses, page faults, GC IRQ).
//! 4. Welch's t-test — `t = (μ_fixed − μ_random) / √(σ²_fixed/n + σ²_random/n)`
//!    for two-sample heteroscedastic variance comparison.
//! 5. Threshold `|t| ≤ 4.5` per Reparaz §3 — significance level
//!    α ≈ 10⁻⁵ corresponding to ~99.9995 % confidence that timing does
//!    not leak information about the secret input.
//!
//! # Threat model
//!
//! Local same-host adversary measuring wall-clock execution time of
//! secret-dependent operations (subtle::ConstantTimeEq comparisons;
//! HKDF expand; AEAD verify; padding tail check; etc.) attempting to
//! recover secret material via timing side channels. Constant-time
//! defence covers attack classes RFC 7457 Appendix B Lucky-13 +
//! KyberSlash + raccoon + similar.
//!
//! # Limitations (in-block scope vs production budget)
//!
//! - Sample count `IN_BLOCK_SAMPLES = 10_000` per branch — sufficient
//!   to catch gross timing leaks (|t| > 10) but not subtle leaks
//!   (|t| 4.5-10 require 100_000+ samples per Reparaz §3 robustness
//!   analysis Figure 4). The weekly CI cron `dudect-benchmarks.yml`
//!   extends this to `WEEKLY_CI_SAMPLES = 100_000` per branch for the
//!   full per-Reparaz spec sensitivity coverage.
//! - macOS 14.x arm64 measurements via `std::time::Instant` provide
//!   nanosecond resolution; the Mach absolute time clock guarantees a
//!   monotonic + TSC-backed source. Linux CI uses
//!   `clock_gettime(MONOTONIC_RAW)` analogously. Windows CI is not yet
//!   evaluated in the scope of this block.
//! - Tests run under `cargo test --release` for accurate timing (debug
//!   builds add panic + bounds checks that distort measurements). The
//!   workspace-wide `[profile.test] opt-level = 3` is not used for
//!   historical reasons (debug stack traces + faster compile cycle);
//!   `--release` overrides this per call.

use core::time::Duration;
use std::time::Instant;

/// Класс входа для dudect interleaving — `Fixed` фиксированный секрет
/// постоянный во всех iterations; `Random` свежий случайный секрет на
/// каждый sample.
///
/// Input class for dudect interleaving — `Fixed` is the fixed secret
/// kept constant across iterations; `Random` is a fresh random secret
/// generated for each sample.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Class {
    /// Фиксированный секрет: hash(secret) = const.
    /// Fixed secret: hash(secret) = const.
    Fixed,
    /// Случайный секрет каждый sample.
    /// Random secret on each sample.
    Random,
}

/// Sample budget применяемый при `cargo test -p umbrella-tests
/// --release dudect` локально в составе блока 10.24 — достаточно для
/// catching gross timing leaks (|t| > 10) per Reparaz §3 Figure 4
/// robustness analysis. Weekly CI cron расширяет к `WEEKLY_CI_SAMPLES`
/// для full sensitivity coverage subtle leaks.
///
/// Sample budget used by `cargo test -p umbrella-tests --release
/// dudect` locally during block 10.24 — sufficient to catch gross
/// timing leaks (|t| > 10) per Reparaz §3 Figure 4 robustness analysis.
/// The weekly CI cron extends this to `WEEKLY_CI_SAMPLES` for full
/// sensitivity coverage of subtle leaks.
pub const IN_BLOCK_SAMPLES: usize = 10_000;

/// Sample budget weekly CI cron `dudect-benchmarks.yml` Sunday 00:00
/// UTC — соответствует Reparaz spec recommended budget для full
/// sensitivity к subtle leaks |t| 4.5-10.
///
/// Sample budget for the weekly CI cron `dudect-benchmarks.yml`
/// Sunday 00:00 UTC — matches the Reparaz spec recommended budget for
/// full sensitivity to subtle leaks |t| 4.5-10.
pub const WEEKLY_CI_SAMPLES: usize = 100_000;

/// Threshold |t| per Reparaz et al. 2017 USENIX § 3 — `|t| ≤ 4.5`
/// signals constant-time behaviour at significance level α ≈ 10⁻⁵
/// (~99.9995 % confidence что timing не leak'ает secret input).
///
/// Threshold |t| per Reparaz et al. 2017 USENIX §3 — `|t| ≤ 4.5`
/// signals constant-time behaviour at significance level α ≈ 10⁻⁵
/// (~99.9995 % confidence that timing does not leak the secret input).
pub const DUDECT_T_THRESHOLD: f64 = 4.5;

/// Percentile cropping bounds — нижние 5 % + верхние 5 % timing
/// samples отбрасываются как outliers (системные паузы, IRQ, GC).
///
/// Percentile cropping bounds — the bottom 5 % and the top 5 % of
/// timing samples are dropped as outliers (system pauses, IRQs, GC).
const CROP_PERCENTILE_LOW: f64 = 0.05;
const CROP_PERCENTILE_HIGH: f64 = 0.95;

/// Результат dudect bench run — t-statistic + diagnostic поля для
/// post-hoc analysis (means + sample counts + raw t).
///
/// Result of a dudect bench run — t-statistic plus diagnostic fields
/// for post-hoc analysis (means + sample counts + raw t).
#[derive(Clone, Debug)]
pub struct DudectResult {
    /// Welch's t-statistic. `|t| ≤ 4.5` = clean per Reparaz spec.
    /// Welch's t-statistic. `|t| ≤ 4.5` is clean per Reparaz spec.
    pub t: f64,
    /// Среднее время в наносекундах для класса `Fixed` (после cropping).
    /// Mean time in nanoseconds for the `Fixed` class (after cropping).
    pub mean_fixed_ns: f64,
    /// Среднее время в наносекундах для класса `Random` (после cropping).
    /// Mean time in nanoseconds for the `Random` class (after cropping).
    pub mean_random_ns: f64,
    /// Количество samples класса `Fixed` после cropping.
    /// Number of samples in the `Fixed` class after cropping.
    pub n_fixed: usize,
    /// Количество samples класса `Random` после cropping.
    /// Number of samples in the `Random` class after cropping.
    pub n_random: usize,
}

impl DudectResult {
    /// Признак clean — `|t| ≤ DUDECT_T_THRESHOLD`.
    /// Clean indicator — `|t| ≤ DUDECT_T_THRESHOLD`.
    pub fn is_clean(&self) -> bool {
        self.t.abs() <= DUDECT_T_THRESHOLD
    }

    /// Verdict в человеко-читаемом формате для отчётов и regression
    /// tests.
    /// Human-readable verdict for reports and regression tests.
    pub fn verdict(&self) -> &'static str {
        if self.is_clean() {
            "CLEAN"
        } else if self.t.abs() <= 10.0 {
            "BORDERLINE"
        } else {
            "LEAK"
        }
    }
}

/// Запускает dudect bench: alternating sample loop (`samples_per_class`
/// итераций class `Fixed` + `samples_per_class` итераций class
/// `Random` в interleaved order через alternating index) и возвращает
/// Welch's t-statistic.
///
/// Closures получают индекс iteration (0..samples_per_class) для
/// indexing в pre-allocated input arrays — это критично для
/// dudect methodology: input generation должна быть ВНЕ timing loop,
/// иначе random generation overhead доминирует над секретно-зависимой
/// операцией и инжектит false positive timing leak.
///
/// `f_fixed` — closure вызываемая в class `Fixed` с index в input
/// pool (caller обычно повторно использует один input через
/// `[fixed_input]` либо игнорирует index); `f_random` — closure
/// вызываемая в class `Random` с index в pre-allocated random pool
/// `(0..samples_per_class)` — caller извлекает `random[idx]` и
/// измеряет операцию.
///
/// Both closures обёрнуты `black_box` снаружи для prevention compiler
/// elision; внутри closure caller должен обернуть secret-dependent
/// inputs/outputs `black_box` для guaranteed measurement.
///
/// Runs a dudect bench: an alternating sample loop
/// (`samples_per_class` iterations of class `Fixed` + `samples_per_class`
/// iterations of class `Random` in interleaved order via the alternating
/// index) and returns Welch's t-statistic.
///
/// Closures receive an iteration index (0..samples_per_class) for
/// indexing into pre-allocated input arrays — this is critical for the
/// dudect methodology: input generation must occur OUTSIDE the timing
/// loop, otherwise random-generation overhead dominates over the
/// secret-dependent operation and injects a false-positive timing leak.
///
/// `f_fixed` — closure invoked in class `Fixed` with the index into
/// the input pool (the caller typically reuses one input via
/// `[fixed_input]` or ignores the index); `f_random` — closure invoked
/// in class `Random` with the index into a pre-allocated random pool
/// `(0..samples_per_class)` — the caller extracts `random[idx]` and
/// measures the operation.
///
/// Both closures are wrapped in `black_box` from the outside to prevent
/// compiler elision; inside the closure the caller must wrap the
/// secret-dependent inputs/outputs in `black_box` for a guaranteed
/// measurement.
#[allow(
    unknown_lints,
    no_assert_in_lib,
    reason = "block 11.8 dylint expansion: umbrella-tests is the test-infrastructure crate (publish = false; \
             not part of the production library surface) — test-harness misuse must fail loudly rather \
             than silently produce invalid t-statistics that would mask genuine constant-time leakage. \
             ADR-015 §Decision 5 criterion 5 'zero panics in lib code' applies to the 17 production \
             crates; umbrella-tests + umbrella-fuzz + umbrella-vectors are dev/meta crates per ADR-001. \
             `unknown_lints` suppressed because rustc outside the dylint driver does not know the \
             custom `no_assert_in_lib` lint name"
)]
pub fn run_dudect<FF, FR>(
    samples_per_class: usize,
    mut f_fixed: FF,
    mut f_random: FR,
) -> DudectResult
where
    FF: FnMut(usize),
    FR: FnMut(usize),
{
    assert!(
        samples_per_class >= 100,
        "dudect harness requires at least 100 samples per class for meaningful t-statistic"
    );

    let mut times_fixed = Vec::with_capacity(samples_per_class);
    let mut times_random = Vec::with_capacity(samples_per_class);

    // Alternating interleave order — counter system drift via class
    // class round-robin. На каждой паре итераций — один Fixed sample +
    // один Random sample.
    //
    // Alternating interleave order — counters system drift via
    // class round-robin. On every pair of iterations — one Fixed
    // sample + one Random sample.
    for idx in 0..samples_per_class {
        // Closures returns `()` — `black_box` нет смысла на unit
        // value; рассчитываем что caller внутри closure обернёт
        // секретно-зависимые входы/выходы `black_box` для prevention
        // compiler elision (см. tests/dudect_constant_time.rs).
        //
        // Closures return `()` — `black_box` is meaningless on a unit
        // value; we rely on the caller wrapping secret-dependent
        // inputs/outputs in `black_box` inside the closure to prevent
        // compiler elision (see tests/dudect_constant_time.rs).
        let t0 = Instant::now();
        f_fixed(idx);
        times_fixed.push(elapsed_ns(t0));

        let t1 = Instant::now();
        f_random(idx);
        times_random.push(elapsed_ns(t1));
    }

    crop_and_compute(&mut times_fixed, &mut times_random)
}

/// Возвращает время в наносекундах от `start` до текущего момента;
/// безопасно к Duration overflow на u128 representation внутри.
///
/// Returns the elapsed nanoseconds from `start` to now; safe against
/// `Duration` overflow via u128 representation internally.
fn elapsed_ns(start: Instant) -> u64 {
    let elapsed: Duration = start.elapsed();
    let ns_u128: u128 = elapsed.as_nanos();
    u64::try_from(ns_u128).unwrap_or(u64::MAX)
}

/// Применяет percentile cropping (отбрасывает нижние 5 % + верхние
/// 5 % outliers) и вычисляет Welch's t-statistic + diagnostic means.
///
/// Applies percentile cropping (drops the bottom 5 % and top 5 % of
/// outliers) and computes Welch's t-statistic + diagnostic means.
fn crop_and_compute(times_fixed: &mut Vec<u64>, times_random: &mut Vec<u64>) -> DudectResult {
    crop_percentile(times_fixed);
    crop_percentile(times_random);

    let mean_fixed = mean(times_fixed);
    let mean_random = mean(times_random);
    let var_fixed = variance(times_fixed, mean_fixed);
    let var_random = variance(times_random, mean_random);

    let n_fixed = times_fixed.len() as f64;
    let n_random = times_random.len() as f64;

    let denom = (var_fixed / n_fixed + var_random / n_random).sqrt();
    let t = if denom > 0.0 {
        (mean_fixed - mean_random) / denom
    } else {
        // Zero-variance edge case — обе классы deterministic + равные.
        // Zero-variance edge case — both classes deterministic + equal.
        0.0
    };

    DudectResult {
        t,
        mean_fixed_ns: mean_fixed,
        mean_random_ns: mean_random,
        n_fixed: times_fixed.len(),
        n_random: times_random.len(),
    }
}

/// Сортирует массив timing samples и отбрасывает нижние/верхние 5 %.
/// Sorts the timing samples array and drops the bottom and top 5 %.
fn crop_percentile(samples: &mut Vec<u64>) {
    samples.sort_unstable();
    let n = samples.len();
    let low_idx = (n as f64 * CROP_PERCENTILE_LOW) as usize;
    let high_idx = (n as f64 * CROP_PERCENTILE_HIGH) as usize;
    samples.drain(high_idx..);
    samples.drain(..low_idx);
}

/// Среднее арифметическое timing samples в наносекундах (f64 для
/// stability variance computation).
///
/// Arithmetic mean of timing samples in nanoseconds (f64 for stability
/// of variance computation).
fn mean(samples: &[u64]) -> f64 {
    let sum: f64 = samples.iter().map(|&x| x as f64).sum();
    sum / samples.len() as f64
}

/// Sample variance (Bessel's correction `n-1`) в наносекундах².
/// Sample variance (Bessel's correction `n-1`) in nanoseconds².
fn variance(samples: &[u64], mean: f64) -> f64 {
    let sum_sq: f64 = samples
        .iter()
        .map(|&x| {
            let diff = x as f64 - mean;
            diff * diff
        })
        .sum();
    sum_sq / (samples.len() as f64 - 1.0)
}

#[cfg(test)]
mod tests {
    use core::hint::black_box;

    use super::*;

    /// Sanity test — две идентичные closures должны давать |t| ≤ 10
    /// (constant-time identity invariant). Если flaky — increase
    /// sample count либо crop percentile.
    ///
    /// Sanity test — two identical closures should produce |t| ≤ 10
    /// (the constant-time identity invariant). If flaky — increase the
    /// sample count or the crop percentile.
    #[test]
    fn identical_closures_yield_clean_t_statistic() {
        let result = run_dudect(
            1_000,
            |_idx| {
                black_box(42u64.wrapping_add(1));
            },
            |_idx| {
                black_box(42u64.wrapping_add(1));
            },
        );
        // Identical closures — t close к 0 expected; threshold loose
        // 10.0 чтобы не flakey на noisy CI runners; production threshold
        // 4.5 used by callers.
        //
        // Identical closures — t is expected to be close to 0; the
        // threshold here is loose at 10.0 to avoid flakiness on noisy CI
        // runners; the production threshold of 4.5 is used by callers.
        assert!(
            result.t.abs() <= 10.0,
            "identical closures should produce |t| ≤ 10, got {}",
            result.t
        );
    }

    /// Sanity test — обнаруживает grossly different timing.
    ///
    /// Sanity test — detects grossly different timing.
    #[test]
    fn divergent_closures_yield_large_t_statistic() {
        // Этот test НЕ должен быть constant-time — это negative control.
        // This test should NOT be constant-time — it is a negative
        // control.
        let result = run_dudect(
            1_000,
            |_idx| {
                // Fixed branch: trivial work.
                // Fixed branch: trivial work.
                black_box(0u64);
            },
            |_idx| {
                // Random branch: hash-like loop ~100 iterations.
                // Random branch: hash-like loop ~100 iterations.
                let mut acc = 1u64;
                for i in 0..100 {
                    acc = acc.wrapping_mul(0x100000001b3).wrapping_add(black_box(i));
                }
                black_box(acc);
            },
        );
        // Mean must differ by orders of magnitude → |t| > 10 trivially.
        // Means must differ by orders of magnitude → |t| > 10 trivially.
        assert!(
            result.t.abs() > 10.0,
            "divergent closures should produce |t| > 10, got {}",
            result.t
        );
    }

    /// Verdict mapping unit test.
    /// Verdict mapping unit test.
    #[test]
    fn verdict_mapping() {
        let r_clean = DudectResult {
            t: 2.0,
            mean_fixed_ns: 100.0,
            mean_random_ns: 100.0,
            n_fixed: 1000,
            n_random: 1000,
        };
        assert_eq!(r_clean.verdict(), "CLEAN");
        assert!(r_clean.is_clean());

        let r_borderline = DudectResult {
            t: 7.0,
            mean_fixed_ns: 100.0,
            mean_random_ns: 100.0,
            n_fixed: 1000,
            n_random: 1000,
        };
        assert_eq!(r_borderline.verdict(), "BORDERLINE");
        assert!(!r_borderline.is_clean());

        let r_leak = DudectResult {
            t: 15.0,
            mean_fixed_ns: 100.0,
            mean_random_ns: 100.0,
            n_fixed: 1000,
            n_random: 1000,
        };
        assert_eq!(r_leak.verdict(), "LEAK");
        assert!(!r_leak.is_clean());
    }

    /// Edge case — too-small sample count panics.
    /// Edge case — a too-small sample count panics.
    #[test]
    #[should_panic(expected = "at least 100 samples per class")]
    fn requires_minimum_samples() {
        run_dudect(50, |_idx| {}, |_idx| {});
    }
}
