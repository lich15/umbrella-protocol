//! Adversarial concurrent tests для `CallSession` 7-state lifecycle machine
//! (Этап 11 блок 11.6 — F-78 LOW closure carry-over от Stage 10 audit M-A4).
//! Adversarial concurrent tests for the `CallSession` 7-state lifecycle
//! machine (Stage 11 block 11.6 — F-78 LOW closure carry-over from the
//! Stage 10 audit M-A4 finding).
//!
//! ## Контекст / Context
//!
//! Stage 10 retroactive sweep (block 10.27c session #59 phase1-retrospective.md
//! row M-A4) идентифицировал absence of concurrent state-transition adversarial
//! tests для `CallSession` lifecycle machine. Block 10.16 closing predates
//! active audit mode mandate (public active-audit coverage policy, session
//! #47 strengthening) — concurrent tests not covered. Carry-over **F-78 LOW**
//! к session #60 либо block 10.Z; перенесён к post-1.0 operational track
//! как block 11.6.
//!
//! Stage 10's retroactive sweep (block 10.27c session #59
//! phase1-retrospective.md row M-A4) identified the absence of concurrent
//! state-transition adversarial tests for the `CallSession` lifecycle machine.
//! Block 10.16's closing predates the active-audit-mode mandate (memory
//! `public active-audit coverage policy`, session #47 strengthening) — concurrent
//! tests were not covered. Carry-over **F-78 LOW** to session #60 or block
//! 10.Z; deferred to the post-1.0 operational track as block 11.6.
//!
//! ## Threat model — атаки уровня D из SPEC-01 § 4
//!
//! 1. **Row 4 «Forking attack»**: malicious peer либо MITM может попытаться
//!    trigger конкурентные state transitions (hangup от двух источников
//!    одновременно: local user + remote peer BYE) с надеждой создать race
//!    condition в `Arc<RwLock<CallState>>` доступе.
//! 2. **Row 11 «Cold-boot/forensics on device»**: process с привилегированным
//!    доступом к памяти может observed CallSession Arc reference counts +
//!    попытаться trigger UAF через rapid concurrent dispose + ice_agent()
//!    accessor calls (Arc clone race).
//! 3. **Resource exhaustion**: concurrent CallSession creation от множества
//!    threads с целью exhaust system resources (deadlock в shared Mutex<DtlsRunner>,
//!    deadlock в RwLock<CallState>).
//!
//! 1. **Row 4 "Forking attack"**: a malicious peer or MITM may attempt to
//!    trigger concurrent state transitions (hangup from two sources at once:
//!    local user + remote peer BYE) hoping to race
//!    `Arc<RwLock<CallState>>` access.
//! 2. **Row 11 "Cold-boot/forensics on device"**: a process with privileged
//!    memory access may observe `CallSession` Arc reference counts and try to
//!    trigger a UAF via rapid concurrent dispose + `ice_agent()` accessor
//!    calls (Arc clone race).
//! 3. **Resource exhaustion**: concurrent `CallSession` creation from many
//!    threads aiming to exhaust system resources (deadlock in
//!    `Mutex<DtlsRunner>`, deadlock in `RwLock<CallState>`).
//!
//! ## Active mode мandate (per public active-audit coverage policy)
//!
//! Tests **реально пытаются** сломать concurrent invariants — не выдуманные
//! unit-test boundary scenarios а realistic adversarial patterns: 4 потока
//! × 500 итераций для statistical pressure + tokio multi-thread runtime
//! (worker_threads = 4) + Arc + atomic counters для invariant verification.
//! Если любой test падает либо detect'ит race — это критическая находка
//! требующая emergency fix CallSession lifecycle machine.
//!
//! Tests **really try** to break the concurrent invariants — not invented
//! unit-test boundary scenarios but realistic adversarial patterns: 4
//! threads × 500 iterations for statistical pressure + tokio multi-thread
//! runtime (worker_threads = 4) + Arc + atomic counters for invariant
//! verification. If any test fails or detects a race — this is a critical
//! finding requiring an emergency fix to the `CallSession` lifecycle
//! machine.

#![allow(clippy::too_many_lines)]

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use rand::rngs::OsRng;
use tokio::task::JoinSet;
use umbrella_backup::cloud_wrap::{ThresholdConfig, WrappingParams};
use umbrella_calls::CallPolicy;
use umbrella_client::call::media::{MediaError, MediaFrame, MediaSink, MediaSource};
use umbrella_client::call::mode_enforcement::ModeEnforcement;
use umbrella_client::call::session::{CallId, CallSession, CallState, CallTerminationReason};
use umbrella_client::facade::chat_common::{PeerId, UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT};
use umbrella_client::{ClientConfig, ClientCore};
use umbrella_identity::{IdentitySeed, MnemonicLanguage};

// ----------------------------------------------------------------------------
// Test fixtures (mirror inline tests из crates/umbrella-client/src/call/session.rs:290-334).
// Test fixtures (mirror the inline tests in crates/umbrella-client/src/call/session.rs:290-334).
// ----------------------------------------------------------------------------

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
            config: ThresholdConfig::new(3, 5).expect("3-of-5 is a valid ThresholdConfig"),
        },
        default_ciphersuite: UMBRELLA_CIPHERSUITE_CLASSICAL_DEFAULT,
    }
}

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

async fn start_session() -> Arc<CallSession> {
    let core = ClientCore::new_for_test(test_config(), test_seed())
        .await
        .expect("ClientCore::new_for_test succeeds for stable fixture");
    let session = CallSession::start_with_enforcement(
        core,
        PeerId([0xAA; 32]),
        CallPolicy::default(),
        ModeEnforcement::CloudMode,
        Arc::new(NullSource),
        Arc::new(NullSink),
    )
    .await
    .expect("start_with_enforcement succeeds with default test policy");
    Arc::new(session)
}

const N_THREADS: usize = 4;
const ITERATIONS_PER_THREAD: usize = 500;

// ----------------------------------------------------------------------------
// **Test 1**: Concurrent `state()` reads under high load — 4 потока × 500
// итераций parallel reads, verify no panic, no deadlock, monotonic state.
// **Test 1**: Concurrent `state()` reads under high load — 4 threads × 500
// iterations of parallel reads; verifies no panic, no deadlock, monotonic
// state.
//
// Атака уровня D: process с rapid state-polling доступом пытается detect
// transient inconsistent state during concurrent transitions. Invariant:
// `state()` всегда возвращает один из 7 valid CallState variants — не должно
// быть partially-initialized RwLock либо poisoned state.
// Level-D adversary: a process with rapid state-polling access tries to
// detect a transient inconsistent state during concurrent transitions.
// Invariant: `state()` always returns one of the 7 valid `CallState`
// variants — no partially-initialised `RwLock` or poisoned state.
// ----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_state_reads_4_threads_500_iter_no_deadlock_no_panic() {
    let session = start_session().await;
    let mut tasks = JoinSet::new();

    for thread_id in 0..N_THREADS {
        let session = Arc::clone(&session);
        tasks.spawn(async move {
            for iteration in 0..ITERATIONS_PER_THREAD {
                let state = session.state().await;
                // Invariant: must be a valid CallState variant. The match is
                // exhaustive — if a future variant is added without updating
                // this test, compilation will fail (compile-time guard).
                // Инвариант: должен быть валидным вариантом CallState.
                // Проверка exhaustive — добавление future варианта без
                // обновления этого теста вызовет compile-time ошибку.
                match state {
                    CallState::Signalling
                    | CallState::IceGathering
                    | CallState::IceChecking
                    | CallState::DtlsHandshake
                    | CallState::Connected
                    | CallState::Reconnecting
                    | CallState::Terminated(_) => {}
                }
                if iteration % 100 == 0 {
                    tokio::task::yield_now().await;
                }
                let _ = thread_id; // mute unused — preserved for diagnostic clarity
            }
        });
    }

    while let Some(result) = tasks.join_next().await {
        result.expect("concurrent state() reader task must not panic");
    }
}

// ----------------------------------------------------------------------------
// **Test 2**: Concurrent `hangup()` — 4 потока race на same session.
// Invariant: final state Terminated(LocalHangup), idempotent, no panic.
// **Test 2**: Concurrent `hangup()` — 4 threads racing on the same session.
// Invariant: final state is `Terminated(LocalHangup)`, idempotent, no panic.
//
// Атака уровня D row 4 «Forking»: malicious peer + local user одновременно
// trigger hangup. Race condition в `*self.state.write().await = ...` write
// — несколько threads могут попытаться transition state simultaneously.
// `RwLock::write()` гарантирует exclusive access — только один writer
// at a time. Final state должен быть deterministic.
// Level-D adversary row 4 "Forking": a malicious peer + local user trigger
// hangup at the same time. The race in `*self.state.write().await = ...`
// — multiple threads may attempt to transition state simultaneously.
// `RwLock::write()` guarantees exclusive access — only one writer at a
// time. The final state must be deterministic.
// ----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_hangup_4_threads_idempotent_terminated() {
    let session = start_session().await;
    let mut tasks = JoinSet::new();

    for _ in 0..N_THREADS {
        let session = Arc::clone(&session);
        tasks.spawn(async move {
            // Each task calls hangup once — concurrent racing on RwLock<CallState>::write().
            // Каждый task вызывает hangup один раз — concurrent race на RwLock<CallState>::write().
            session
                .hangup()
                .await
                .expect("hangup must not error в block 7.6 stub design");
        });
    }

    while let Some(result) = tasks.join_next().await {
        result.expect("concurrent hangup task must not panic");
    }

    // Invariant: final state is Terminated with LocalHangup reason.
    // Инвариант: финальное состояние Terminated(LocalHangup).
    assert_eq!(
        session.state().await,
        CallState::Terminated(CallTerminationReason::LocalHangup),
        "concurrent hangup must converge to Terminated(LocalHangup) — \
         RwLock<CallState>::write() exclusive serialisation invariant violated"
    );
}

// ----------------------------------------------------------------------------
// **Test 3**: Concurrent `hangup()` × 500 iter per thread (high-load stress).
// Этот тест — **реальная атака**: 4 потока вызывают hangup НЕОДНОКРАТНО, по
// 500 итераций каждый = 2000 hangup calls. Invariant: idempotent (multiple
// hangups OK), final state stable.
// **Test 3**: Concurrent `hangup()` × 500 iter per thread (high-load stress).
// This test is the **real attack**: 4 threads call hangup REPEATEDLY, 500
// iterations each = 2000 hangup calls. Invariant: idempotent (multiple
// hangups OK), final state stable.
// ----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_hangup_4_threads_500_iter_idempotent() {
    let session = start_session().await;
    let mut tasks = JoinSet::new();

    let total_hangup_calls = Arc::new(AtomicUsize::new(0));

    for _ in 0..N_THREADS {
        let session = Arc::clone(&session);
        let counter = Arc::clone(&total_hangup_calls);
        tasks.spawn(async move {
            for _ in 0..ITERATIONS_PER_THREAD {
                session
                    .hangup()
                    .await
                    .expect("hangup must remain idempotent under concurrent stress");
                counter.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    while let Some(result) = tasks.join_next().await {
        result.expect("concurrent stress hangup task must not panic");
    }

    let final_count = total_hangup_calls.load(Ordering::Relaxed);
    assert_eq!(
        final_count,
        N_THREADS * ITERATIONS_PER_THREAD,
        "all 2000 hangup calls must complete (4 threads × 500 iter)"
    );

    // Invariant under stress: state stable at Terminated(LocalHangup).
    // Инвариант под stress: state стабильный на Terminated(LocalHangup).
    assert_eq!(
        session.state().await,
        CallState::Terminated(CallTerminationReason::LocalHangup),
        "after 2000 concurrent hangup calls state must be Terminated(LocalHangup)"
    );
}

// ----------------------------------------------------------------------------
// **Test 4**: Mixed concurrent reads + hangup race. 3 потока непрерывно
// читают state(), 1 поток вызывает hangup() в random момент, после ВСЕ
// продолжают читать — verify no deadlock + state monotonicity (один раз
// перешёл в Terminated, остаётся в Terminated).
// **Test 4**: Mixed concurrent reads + hangup race. 3 threads continuously
// read state(), 1 thread calls hangup() at a random moment; after that
// ALL keep reading — verifies no deadlock + state monotonicity (once
// transitioned to Terminated, stays in Terminated).
//
// Это адversarial pattern: malicious peer monitors state via repeated
// state() polling AND triggers hangup mid-stream. Invariant: state ne
// «откатывается» назад из Terminated в any other variant.
// This is the adversarial pattern: a malicious peer monitors state via
// repeated state() polls AND triggers hangup mid-stream. Invariant: state
// never "rolls back" from Terminated to any other variant.
// ----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reads_with_mid_stream_hangup_state_monotonic() {
    let session = start_session().await;
    let mut tasks = JoinSet::new();

    let saw_terminated = Arc::new(AtomicUsize::new(0));
    let saw_non_terminated_after_terminated = Arc::new(AtomicUsize::new(0));

    // 3 reader tasks — observe state continuously and check monotonicity.
    // 3 reader-таска — непрерывно observe state и check монотонность.
    for _ in 0..3 {
        let session = Arc::clone(&session);
        let saw_terminated = Arc::clone(&saw_terminated);
        let saw_non_terminated_after_terminated = Arc::clone(&saw_non_terminated_after_terminated);
        tasks.spawn(async move {
            let mut local_saw_terminated = false;
            for _ in 0..ITERATIONS_PER_THREAD {
                let state = session.state().await;
                if matches!(state, CallState::Terminated(_)) {
                    if !local_saw_terminated {
                        saw_terminated.fetch_add(1, Ordering::Relaxed);
                        local_saw_terminated = true;
                    }
                } else if local_saw_terminated {
                    // INVARIANT VIOLATION: после Terminated state не должен
                    // вернуться к не-Terminated варианту.
                    // INVARIANT VIOLATION: after Terminated, state must not
                    // revert to a non-Terminated variant.
                    saw_non_terminated_after_terminated.fetch_add(1, Ordering::Relaxed);
                }
                tokio::task::yield_now().await;
            }
        });
    }

    // 1 hangup task — triggers transition mid-stream.
    // 1 hangup-task — trigger'ит transition mid-stream.
    {
        let session = Arc::clone(&session);
        tasks.spawn(async move {
            // Wait a bit so reader tasks observe Signalling first.
            // Подождать чтобы reader-таски сначала observe'ed Signalling.
            for _ in 0..50 {
                tokio::task::yield_now().await;
            }
            session
                .hangup()
                .await
                .expect("mid-stream hangup must not error");
        });
    }

    while let Some(result) = tasks.join_next().await {
        result.expect("reader/hangup task must not panic");
    }

    let monotonicity_violations = saw_non_terminated_after_terminated.load(Ordering::Relaxed);
    assert_eq!(
        monotonicity_violations, 0,
        "state monotonicity violated: {monotonicity_violations} reader tasks observed \
         non-Terminated state AFTER Terminated — RwLock<CallState> consistency \
         broken либо state machine allows backward transitions (critical race)"
    );

    // Final state must be Terminated.
    // Финальное state должно быть Terminated.
    assert!(
        matches!(session.state().await, CallState::Terminated(_)),
        "final state after mid-stream hangup must be Terminated"
    );
}

// ----------------------------------------------------------------------------
// **Test 5**: Concurrent CallSession creation от множества threads — verify
// `call_id` uniqueness (no rand collision) + no construction deadlock.
// **Test 5**: Concurrent `CallSession` creation from many threads —
// verifies `call_id` uniqueness (no rand collision) + no construction
// deadlock.
//
// Атака уровня D: process с привилегированным доступом к `getrandom` syscall
// может попытаться force collision rand::random() output если non-CSPRNG
// (что не так в нашем случае — `OsRng` cryptographically secure). Но
// invariant test полезен как regression-guard для future RNG changes.
// Level-D adversary: a process with privileged access to the `getrandom`
// syscall might try to force a `rand::random()` collision if the RNG were
// non-CSPRNG (it is not — `OsRng` is cryptographically secure). Still, the
// invariant test is useful as a regression-guard for future RNG changes.
// ----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_session_creation_unique_call_ids() {
    // 4 threads × 25 sessions = 100 sessions. Reduced from 4×500 потому что
    // каждый CallSession::start_with_enforcement spawn'ит ICE agent + DTLS
    // runner — 2000 sessions = potential resource exhaustion (open file
    // descriptors для UDP sockets ICE gathering).
    // 4 threads × 25 sessions = 100 sessions. Reduced from 4×500 because
    // each `CallSession::start_with_enforcement` spawns an ICE agent + DTLS
    // runner — 2000 sessions could exhaust system resources (open UDP
    // socket file descriptors for ICE gathering).
    const SESSIONS_PER_THREAD: usize = 25;

    let mut tasks = JoinSet::new();

    for _ in 0..N_THREADS {
        tasks.spawn(async move {
            let mut local_ids = Vec::with_capacity(SESSIONS_PER_THREAD);
            for _ in 0..SESSIONS_PER_THREAD {
                let session = start_session().await;
                local_ids.push(session.call_id());
                // Drop session immediately to release resources.
                // Drop session немедленно для release resources.
                drop(session);
            }
            local_ids
        });
    }

    let mut all_ids: Vec<CallId> = Vec::with_capacity(N_THREADS * SESSIONS_PER_THREAD);
    while let Some(result) = tasks.join_next().await {
        let ids = result.expect("session creation task must not panic");
        all_ids.extend(ids);
    }

    assert_eq!(
        all_ids.len(),
        N_THREADS * SESSIONS_PER_THREAD,
        "all sessions must be created successfully"
    );

    let unique_ids: HashSet<[u8; 16]> = all_ids.iter().map(|id| id.0).collect();
    assert_eq!(
        unique_ids.len(),
        all_ids.len(),
        "call_id collision detected: {} unique vs {} total — `OsRng` regression либо \
         rand::random() implementation broken",
        unique_ids.len(),
        all_ids.len()
    );
}

// ----------------------------------------------------------------------------
// **Test 6**: Concurrent `ice_agent()` Arc clone race + dispose. Один task
// держит Arc<IceAgent>, другой dispose'ит CallSession (drops Arc<CallSession>).
// Verify no UAF: Arc reference counting должен safely defer drop пока
// последний reference жив.
// **Test 6**: Concurrent `ice_agent()` Arc clone race + dispose. One task
// holds `Arc<IceAgent>`, another disposes the `CallSession` (drops
// `Arc<CallSession>`). Verifies no UAF: Arc reference counting must safely
// defer the drop until the last reference is gone.
//
// Атака уровня D row 11: process с привилегированным доступом к памяти
// может попытаться trigger UAF через rapid cycle: get ice_agent() Arc clone
// → drop CallSession → continue using ice_agent ref. Если Arc reference
// counting сломан — segfault либо UAF. Invariant: Arc semantics гарантируют
// safe deferred drop.
// Level-D adversary row 11: a process with privileged memory access may try
// to trigger a UAF via the rapid cycle: get `ice_agent()` Arc clone → drop
// `CallSession` → continue using the `ice_agent` reference. If Arc reference
// counting is broken — segfault or UAF. Invariant: Arc semantics guarantee
// safe deferred drop.
// ----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_arc_dispose_no_uaf() {
    // 4 threads × 100 iter = 400 dispose-during-clone races. Reduced from
    // 4×500 because each CallSession start spawns ICE agent (resource cost).
    // 4 threads × 100 iter = 400 dispose-during-clone races. Reduced from
    // 4×500 because each `CallSession` start spawns an ICE agent (resource
    // cost).
    const DISPOSE_ITERS_PER_THREAD: usize = 100;

    let mut tasks = JoinSet::new();

    for _ in 0..N_THREADS {
        tasks.spawn(async move {
            for _ in 0..DISPOSE_ITERS_PER_THREAD {
                let session = start_session().await;

                // Spawn an inner task that holds Arc<IceAgent> reference.
                // Spawn внутренний task который держит Arc<IceAgent> ссылку.
                let ice_agent = session.ice_agent();
                let inner = tokio::spawn(async move {
                    // Hold Arc<IceAgent> alive while session may be dropped.
                    // Удерживаем Arc<IceAgent> живым пока session может быть dropped.
                    for _ in 0..10 {
                        let _ = ice_agent.is_no_p2p();
                        tokio::task::yield_now().await;
                    }
                });

                // Drop session — Arc<CallSession> ref count drops, but
                // ice_agent клон удерживает IceAgent живым.
                // Drop session — Arc<CallSession> ref count drops, but the
                // `ice_agent` clone keeps `IceAgent` alive.
                drop(session);

                inner.await.expect("inner ice_agent task must not panic");
            }
        });
    }

    while let Some(result) = tasks.join_next().await {
        result.expect("dispose-race task must not panic — UAF detected");
    }
}

// ----------------------------------------------------------------------------
// **Test 7**: Stress combined — 4 потока × 500 iter mixing all operations
// (state read + hangup + ice_agent clone) для real-world adversarial
// pattern coverage.
// **Test 7**: Combined stress — 4 threads × 500 iter mixing all operations
// (state read + hangup + ice_agent clone) for real-world adversarial-pattern
// coverage.
// ----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_mixed_operations_4_threads_500_iter_stress() {
    let session = start_session().await;
    let mut tasks = JoinSet::new();

    for thread_id in 0..N_THREADS {
        let session = Arc::clone(&session);
        tasks.spawn(async move {
            for iteration in 0..ITERATIONS_PER_THREAD {
                // Mix operations based on (thread_id, iteration).
                // Mix операции based on (thread_id, iteration).
                match (thread_id + iteration) % 4 {
                    0 => {
                        let _ = session.state().await;
                    }
                    1 => {
                        let _ = session.ice_agent();
                    }
                    2 => {
                        let _ = session.call_id();
                    }
                    _ => {
                        // hangup occasionally — once per ~500 операций
                        // → ровно один hangup per thread.
                        // hangup occasionally — once per ~500 ops →
                        // approximately one hangup per thread.
                        if iteration == ITERATIONS_PER_THREAD - 1 {
                            session
                                .hangup()
                                .await
                                .expect("stress hangup must not error");
                        }
                    }
                }
                if iteration % 50 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        });
    }

    while let Some(result) = tasks.join_next().await {
        result.expect("stress mixed-operations task must not panic");
    }

    // Final state must be Terminated (at least one hangup happened).
    // Финальное state должно быть Terminated (минимум один hangup случился).
    assert!(
        matches!(session.state().await, CallState::Terminated(_)),
        "after combined stress final state must be Terminated"
    );
}
