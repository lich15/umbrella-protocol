//! Микро-бенчмарки для max_ratchet режима — Task 7 carry-over из max-ratchet v3 spec 2026-05-20.
//!
//! Измеряет реальные накладные расходы каждой из 4 защит max_ratchet режима против
//! baseline UmbrellaGroup::encrypt_application. Результаты заменяют ожидаемые числа в
//! `docs/audits/max-ratchet-deniability-spec-2026-05-20.md` §5.
//!
//! Запуск (Apple M2 / arm64): `cargo bench -p umbrella-mls --bench max_ratchet_benchmark`
//!
//! 4 теста:
//! - `baseline_encrypt_application` — UmbrellaGroup::encrypt_application изолированно
//! - `force_rekey` — UmbrellaGroup::force_rekey изолированно
//! - `max_ratchet_encrypt_with_rekey_authenticated` — MaxRatchetGroup полный поток
//!   (force_rekey + counter + exporter_secret + SPQR HMAC)
//! - `spqr_compute_hmac_256B` — spqr::compute_hmac над 256-байт payload изолированно
//!
//! Setup для encrypt-style тестов создаёт fresh client + group на каждый iter через
//! `iter_batched(PerIteration)` — гарантирует что openmls keystore не conflict'ует на
//! повторном `GroupId` и что измеряется только сам encrypt-call. Setup-фаза криптографически
//! дорогая (~1-2 ms) но criterion измеряет только closure body.
//!
//! Micro-benchmarks for the max_ratchet mode — Task 7 carry-over from the
//! max-ratchet v3 spec 2026-05-20.

use std::hint::black_box;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

use openmls::group::GroupId;
#[allow(deprecated)]
use umbrella_identity::IdentitySeed;
use umbrella_identity::{Clock, InMemoryKeyStore, KeyStore, MnemonicLanguage, SystemClock};
use umbrella_mls::max_ratchet::spqr;
use umbrella_mls::{
    MaxRatchetGroup, UmbrellaCiphersuite, UmbrellaGroup, UmbrellaProvider,
    UMBRELLA_DEFAULT_CIPHERSUITE,
};

const CS: UmbrellaCiphersuite = UMBRELLA_DEFAULT_CIPHERSUITE;
const T0: u64 = 1_700_000_000;
const PAYLOAD: &[u8] = b"benchmark payload representative of a typical chat message: ~64 bytes here";

/// Bench-клиент: keystore + провайдер. Создаётся заново на каждый iter setup чтобы не
/// конфликтовать с openmls KeyPackage storage state между итерациями.
///
/// Bench client: keystore + provider. Created fresh in each iter setup to avoid
/// openmls KeyPackage storage state conflicts between iterations.
struct BenchClient {
    ks: Arc<InMemoryKeyStore>,
    provider: UmbrellaProvider,
    device_index: u32,
}

impl BenchClient {
    fn new() -> Self {
        let mut rng = rand_core::OsRng;
        #[allow(deprecated)]
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let ks = InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>)
            .expect("InMemoryKeyStore::open");
        ks.add_device(0, None).expect("add_device 0");
        Self {
            ks: Arc::new(ks),
            provider: UmbrellaProvider::default(),
            device_index: 0,
        }
    }
}

/// Создаёт свежую single-member группу для прогрева перед измерением.
fn fresh_group(client: &BenchClient) -> UmbrellaGroup {
    UmbrellaGroup::create_private(
        &client.provider,
        client.ks.as_ref(),
        client.device_index,
        CS,
        GroupId::from_slice(&[0xB0u8; 16]),
        T0,
    )
    .expect("UmbrellaGroup::create_private in benchmark setup")
}

fn bench_baseline_encrypt(c: &mut Criterion) {
    c.bench_function("baseline_encrypt_application", |b| {
        b.iter_batched(
            || {
                let client = BenchClient::new();
                let group = fresh_group(&client);
                (client, group)
            },
            |(client, mut group)| {
                let ct = group
                    .encrypt_application(&client.provider, client.ks.as_ref(), black_box(PAYLOAD))
                    .expect("encrypt_application");
                black_box(ct);
            },
            BatchSize::PerIteration,
        );
    });
}

fn bench_force_rekey(c: &mut Criterion) {
    c.bench_function("force_rekey", |b| {
        b.iter_batched(
            || {
                let client = BenchClient::new();
                let group = fresh_group(&client);
                (client, group)
            },
            |(client, mut group)| {
                let commit = group
                    .force_rekey(&client.provider, client.ks.as_ref(), black_box(T0 + 1))
                    .expect("force_rekey");
                black_box(commit);
            },
            BatchSize::PerIteration,
        );
    });
}

fn bench_max_ratchet_full(c: &mut Criterion) {
    c.bench_function("max_ratchet_encrypt_with_rekey_authenticated", |b| {
        b.iter_batched(
            || {
                let client = BenchClient::new();
                let group = fresh_group(&client);
                let max_group = MaxRatchetGroup::new(group);
                (client, max_group)
            },
            |(client, mut max_group)| {
                let outgoing = max_group
                    .encrypt_with_rekey_authenticated(
                        &client.provider,
                        client.ks.as_ref(),
                        black_box(PAYLOAD),
                        black_box(T0 + 1),
                    )
                    .expect("encrypt_with_rekey_authenticated");
                black_box(outgoing);
            },
            BatchSize::PerIteration,
        );
    });
}

fn bench_spqr_hmac_256b(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let message = vec![0u8; 256];
    c.bench_function("spqr_compute_hmac_256B", |b| {
        b.iter(|| {
            let mac = spqr::compute_hmac(black_box(&key), black_box(&message));
            black_box(mac);
        });
    });
}

/// SPQR HMAC over varying payload sizes — characterize bandwidth scaling.
fn bench_spqr_hmac_payload_sizes(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let mut group = c.benchmark_group("spqr_compute_hmac_scaling");
    for size in [64usize, 256, 1024, 4096, 16384] {
        let message = vec![0u8; size];
        group.bench_function(format!("payload_{}_bytes", size), |b| {
            b.iter(|| {
                let mac = spqr::compute_hmac(black_box(&key), black_box(&message));
                black_box(mac);
            });
        });
    }
    group.finish();
}

/// SPQR HMAC verify (constant-time) — should be same order как compute.
fn bench_spqr_verify_hmac_256b(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let message = vec![0u8; 256];
    let mac = spqr::compute_hmac(&key, &message);
    c.bench_function("spqr_verify_hmac_256B", |b| {
        b.iter(|| {
            let ok = spqr::verify_hmac(black_box(&key), black_box(&message), black_box(&mac));
            black_box(ok);
        });
    });
}

criterion_group!(
    benches,
    bench_baseline_encrypt,
    bench_force_rekey,
    bench_max_ratchet_full,
    bench_spqr_hmac_256b,
    bench_spqr_hmac_payload_sizes,
    bench_spqr_verify_hmac_256b
);
criterion_main!(benches);
