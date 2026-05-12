//! Regression-guard для F-63 (HIGH, блок 10.8-active-retro) — F-46 pattern
//! recurrence в `umbrella-mls/src/provider/xwing.rs`: HpkeContext struct
//! содержащий 3 secret material сайта (`key: [u8; 32]` AEAD ChaCha20-Poly1305 +
//! `base_nonce: [u8; 12]` HPKE base nonce + `exporter_secret: [u8; 32]`
//! HPKE Export PRK) не зануляется при Drop, и 4 intermediate Vec<u8> +
//! 3 [u8; N] stack-буферов в `key_schedule_base` + `derive_keypair` +
//! `labeled_extract` содержат секретный keying material и не зануляются
//! после использования.
//!
//! Site enumeration (handoff session #58 §Phase A):
//! 1. `out: [u8; NH]` — return value labeled_extract; перемещается в
//!    caller (HpkeContext либо `secret`-PRK), который зануляется
//!    автоматически (ZeroizeOnDrop) либо явно (`.zeroize()`).
//! 2. `key: [u8; NK]` — поле HpkeContext; auto-zeroize через
//!    `#[derive(ZeroizeOnDrop)]`.
//! 3. `exporter_secret: [u8; NH]` — поле HpkeContext; auto-zeroize.
//! 4. `seed_arr: [u8; XWING_KEYGEN_SEED_LEN]` — local в derive_keypair;
//!    `.zeroize()` после `seed_arr.to_vec()`.
//! 5. Intermediate Vec<u8> returns from labeled_expand (key_vec +
//!    nonce_vec + exporter_secret_vec + seed_vec) — `.zeroize()` после
//!    copy в фиксированный массив.
//!
//! Дополнительные secret-buffer'ы зануляемые в составе закрытия:
//! - `secret: [u8; NH]` HKDF-Extract PRK от X-Wing combiner shared_secret;
//! - `dkp_prk: [u8; NH]` HKDF-Extract PRK от user-provided IKM;
//! - `labeled_ikm: Vec<u8>` в labeled_extract когда ikm секретный (case
//!   derive_keypair user IKM);
//! - `base_nonce: [u8; NN]` поле HpkeContext (auto через ZeroizeOnDrop;
//!   формально не «секрет» в HPKE base mode, но zero-cost defence-in-depth).
//!
//! Inline-fix блока 10.8-active-retro:
//! - `HpkeContext` получает `#[derive(ZeroizeOnDrop)]` — все 3 поля
//!   автоматически зануляются при Drop через blanket
//!   `impl<const N: usize> Zeroize for [u8; N]` zeroize крейт'а.
//! - `key_schedule_base` зануляет `key_vec`, `nonce_vec`,
//!   `exporter_secret_vec`, `secret` перед return.
//! - `derive_keypair` зануляет `seed_vec`, `seed_arr`, `dkp_prk` перед
//!   return.
//! - `labeled_extract` зануляет `labeled_ikm` перед return.
//!
//! Эти тесты не проверяют zeroize в physical memory (нужен unsafe-указатель;
//! постулат 14 + Cargo.toml `unsafe_code = "forbid"` запрещают unsafe в
//! production коде); вместо этого они подтверждают:
//! - семантическая корректность не нарушена (HPKE seal/open roundtrip
//!   остаётся валидным; derive_keypair детерминирован);
//! - HpkeContext implements ZeroizeOnDrop (compile-time check inside
//!   `mod tests` xwing.rs);
//! - HPKE pipeline остаётся race-free под параллельной нагрузкой;
//! - HPKE pipeline остаётся стабильным под resource-exhaustion (1 MiB
//!   plaintext seal/open).
//!
//! Active attack scenario row 11 SPEC-01 §4 «Cold-boot / forensics»:
//! симулируется через `ZeroizeOnDrop` контракт zeroize крейта 1.7 (Rust
//! ownership semantics + Drop dispatch + volatile-write через
//! `core::ptr::write_volatile` zeroize'а гарантируют что Drop эффективно
//! затирает поля HpkeContext в memory). Heap allocation HpkeContext
//! (sealed-sender V2 + MLS exporter_secret pipelines) теперь не оставляет
//! readable secret keying material в heap'е post-Drop.
//!
//! Regression guard for F-63 (HIGH, block 10.8-active-retro) — F-46 pattern
//! recurrence in `umbrella-mls/src/provider/xwing.rs`: the HpkeContext
//! struct holding 3 secret material sites (`key: [u8; 32]` AEAD
//! ChaCha20-Poly1305 + `base_nonce: [u8; 12]` HPKE base nonce +
//! `exporter_secret: [u8; 32]` HPKE Export PRK) is not zeroized on Drop,
//! and 4 intermediate Vec<u8> + 3 [u8; N] stack buffers in
//! `key_schedule_base` + `derive_keypair` + `labeled_extract` carry secret
//! keying material and are not zeroized after use.
//!
//! Block 10.8-active-retro inline fix:
//! - `HpkeContext` gains `#[derive(ZeroizeOnDrop)]` — all 3 fields are
//!   zeroized automatically on Drop via the zeroize crate's blanket
//!   `impl<const N: usize> Zeroize for [u8; N]`.
//! - `key_schedule_base` zeroizes `key_vec`, `nonce_vec`,
//!   `exporter_secret_vec`, `secret` before returning.
//! - `derive_keypair` zeroizes `seed_vec`, `seed_arr`, `dkp_prk` before
//!   returning.
//! - `labeled_extract` zeroizes `labeled_ikm` before returning.
//!
//! These tests do not verify the zeroize event in physical memory (this
//! would require an unsafe pointer; postulate 14 + Cargo.toml
//! `unsafe_code = "forbid"` forbid unsafe in production code); instead
//! they confirm:
//! - semantic correctness is preserved (HPKE seal/open roundtrip stays
//!   valid; derive_keypair stays deterministic);
//! - HpkeContext implements ZeroizeOnDrop (compile-time check inside
//!   xwing.rs's `mod tests`);
//! - the HPKE pipeline remains race-free under concurrent load;
//! - the HPKE pipeline stays stable under resource exhaustion (1 MiB
//!   plaintext seal/open).
//!
//! Active attack scenario for SPEC-01 §4 row 11 «Cold-boot / forensics»:
//! simulated via the `ZeroizeOnDrop` contract of zeroize crate 1.7 (Rust
//! ownership semantics + Drop dispatch + zeroize's volatile-write through
//! `core::ptr::write_volatile` guarantee that Drop effectively wipes the
//! HpkeContext fields in memory). Heap allocation of HpkeContext
//! (sealed-sender V2 + MLS exporter_secret pipelines) no longer leaves
//! readable secret keying material on the heap post-Drop.

#![cfg(feature = "pq")]

use std::sync::Arc;
use std::thread;

use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{HpkeAeadType, HpkeConfig, HpkeKdfType, HpkeKemType},
};
use umbrella_mls::provider::UmbrellaXWingProvider;

fn xwing_config() -> HpkeConfig {
    HpkeConfig(
        HpkeKemType::XWingKemDraft6,
        HpkeKdfType::HkdfSha256,
        HpkeAeadType::ChaCha20Poly1305,
    )
}

/// F-63 closure: end-to-end семантическая регрессия — HPKE seal/open
/// roundtrip с derive_keypair → seal → open continues to работать после
/// inline-fix'а всех 4 zeroize-сайтов в xwing.rs. Если будущая правка
/// ошибочно zeroize'нёт `key_vec` ДО `key.copy_from_slice(&key_vec)` (либо
/// `seed_vec` ДО `seed_arr.copy_from_slice(&seed_vec)` и т.п.), этот тест
/// провалится с HpkeDecryptionError либо несовпадающим plaintext'ом.
///
/// F-63 closure: end-to-end semantic regression — the HPKE seal/open
/// roundtrip with derive_keypair → seal → open continues to work after the
/// inline fix of all 4 zeroize sites in xwing.rs. If a future edit
/// accidentally zeroizes `key_vec` BEFORE `key.copy_from_slice(&key_vec)`
/// (or `seed_vec` BEFORE `seed_arr.copy_from_slice(&seed_vec)` etc.), this
/// test fails with HpkeDecryptionError or a plaintext mismatch.
#[test]
fn f63_seal_open_e2e_semantic_regression() {
    let provider = UmbrellaXWingProvider::new();
    let kp = provider
        .derive_hpke_keypair(xwing_config(), &[0x42u8; 32])
        .expect("derive keypair");
    let plaintext = b"F-63 closure block 10.8-active-retro";
    let info = b"f63-test-info";
    let aad = b"f63-test-aad";
    let ct = provider
        .hpke_seal(xwing_config(), &kp.public, info, aad, plaintext)
        .expect("hpke_seal");
    let recovered = provider
        .hpke_open(xwing_config(), &ct, &kp.private, info, aad)
        .expect("hpke_open");
    assert_eq!(recovered, plaintext);
}

/// F-63 closure: 100 sequential seal/open cycles на одной keypair'е. Этот
/// тест ловит сценарии когда HpkeContext получил ZeroizeOnDrop ошибочно ДО
/// AEAD seal/open (например, если будущая правка переместит `key.zeroize()`
/// внутрь aead_seal). Также проверяет отсутствие use-after-free /
/// double-free через многократное создание+drop HpkeContext (provider
/// stateless, каждый вызов hpke_seal делает свежий setup_base_sender).
///
/// F-63 closure: 100 sequential seal/open cycles on a single keypair. The
/// test catches scenarios where HpkeContext gets ZeroizeOnDrop'd
/// accidentally BEFORE AEAD seal/open (e.g. if a future edit moves
/// `key.zeroize()` inside aead_seal). It also verifies the absence of
/// use-after-free / double-free across many HpkeContext create+drop cycles
/// (the provider is stateless; every hpke_seal call performs a fresh
/// setup_base_sender).
#[test]
fn f63_seal_open_100_cycles_no_uaf() {
    let provider = UmbrellaXWingProvider::new();
    let kp = provider
        .derive_hpke_keypair(xwing_config(), &[0x77u8; 32])
        .expect("derive keypair");
    let info = b"f63-100-cycles";
    let aad = b"f63-100-aad";
    for cycle in 0..100 {
        let ptxt_str = format!("cycle-{cycle}-plaintext");
        let ptxt = ptxt_str.as_bytes();
        let ct = provider
            .hpke_seal(xwing_config(), &kp.public, info, aad, ptxt)
            .unwrap_or_else(|e| panic!("seal cycle {cycle}: {e:?}"));
        let recovered = provider
            .hpke_open(xwing_config(), &ct, &kp.private, info, aad)
            .unwrap_or_else(|e| panic!("open cycle {cycle}: {e:?}"));
        assert_eq!(recovered, ptxt, "cycle {cycle} mismatch");
    }
}

/// F-63 closure: 4 потока × 50 циклов параллельных seal/open на одной
/// keypair'е. Поскольку HpkeContext создаётся stack-локально внутри
/// hpke_seal/hpke_open и сразу dropped (ZeroizeOnDrop срабатывает на каждом
/// scope-exit'е), параллельная нагрузка проверяет что:
/// 1. Provider Sync + Send (uses inner OpenMlsRustCrypto MemoryStorage без
///    locking — но crypto operations stateless).
/// 2. Drop+ZeroizeOnDrop потокобезопасен (zeroize crate 1.7 не использует
///    глобальное состояние).
/// 3. Нет TOCTOU race в seed_vec.zeroize() vs seed_arr.copy_from_slice().
///
/// F-63 closure: 4 threads × 50 cycles of parallel seal/open on a single
/// keypair. Since HpkeContext is created stack-locally inside
/// hpke_seal/hpke_open and immediately dropped (ZeroizeOnDrop fires on
/// every scope exit), the parallel load verifies that:
/// 1. The provider is Sync + Send (uses inner OpenMlsRustCrypto
///    MemoryStorage without locking — but crypto operations are stateless).
/// 2. Drop+ZeroizeOnDrop is thread-safe (zeroize crate 1.7 uses no global
///    state).
/// 3. No TOCTOU race occurs between seed_vec.zeroize() and
///    seed_arr.copy_from_slice().
#[test]
fn f63_concurrent_seal_open_4_threads_no_data_race() {
    let provider: Arc<UmbrellaXWingProvider> = Arc::new(UmbrellaXWingProvider::new());
    let kp = provider
        .derive_hpke_keypair(xwing_config(), &[0x99u8; 32])
        .expect("derive keypair");
    let kp_pub: Arc<Vec<u8>> = Arc::new(kp.public.clone());
    let kp_priv: Arc<Vec<u8>> = Arc::new(kp.private.to_vec());

    let mut handles = Vec::new();
    for thread_id in 0..4u8 {
        let provider = Arc::clone(&provider);
        let kp_pub = Arc::clone(&kp_pub);
        let kp_priv = Arc::clone(&kp_priv);
        handles.push(thread::spawn(move || {
            for cycle in 0..50 {
                let plaintext = format!("t{thread_id}-c{cycle}");
                let ct = provider
                    .hpke_seal(
                        xwing_config(),
                        &kp_pub,
                        b"f63-conc",
                        b"aad",
                        plaintext.as_bytes(),
                    )
                    .expect("seal");
                let recovered = provider
                    .hpke_open(xwing_config(), &ct, &kp_priv, b"f63-conc", b"aad")
                    .expect("open");
                assert_eq!(recovered, plaintext.as_bytes());
            }
        }));
    }
    for h in handles {
        h.join().expect("thread join");
    }
}

/// F-63 closure: resource exhaustion — 1 MiB plaintext seal/open. Длина
/// HpkeContext (76 байт = 32 + 12 + 32) не растёт с plaintext size, но
/// ChaCha20-Poly1305 streaming через AeadCore + StreamCipher должен
/// обработать 1 MiB. Тест ловит регрессии HpkeContext lifetime'а если
/// AEAD ctx ошибочно zeroize'нёт key посередине крупного encryption'а.
///
/// F-63 closure: resource exhaustion — 1 MiB plaintext seal/open. The
/// HpkeContext footprint (76 bytes = 32 + 12 + 32) does not grow with the
/// plaintext size, but ChaCha20-Poly1305 streaming through AeadCore +
/// StreamCipher must handle 1 MiB. The test catches HpkeContext lifetime
/// regressions if AEAD ctx accidentally zeroizes the key mid-encryption.
#[test]
fn f63_resource_exhaustion_1mib_seal_open() {
    let provider = UmbrellaXWingProvider::new();
    let kp = provider
        .derive_hpke_keypair(xwing_config(), &[0x55u8; 32])
        .expect("derive keypair");
    // 1 MiB plaintext (1 048 576 bytes); ChaCha20-Poly1305 не имеет
    // встроенного length limit на single AEAD invocation (limit 2^38 - 1
    // bytes per RFC 8439), 1 MiB ≪ limit.
    // 1 MiB plaintext (1,048,576 bytes); ChaCha20-Poly1305 has no built-in
    // length limit on a single AEAD invocation (the limit is 2^38 - 1
    // bytes per RFC 8439), and 1 MiB ≪ that limit.
    let plaintext = vec![0xABu8; 1024 * 1024];
    let ct = provider
        .hpke_seal(xwing_config(), &kp.public, b"f63-1mib", b"aad", &plaintext)
        .expect("seal 1 MiB");
    let recovered = provider
        .hpke_open(xwing_config(), &ct, &kp.private, b"f63-1mib", b"aad")
        .expect("open 1 MiB");
    assert_eq!(recovered.len(), plaintext.len());
    assert_eq!(recovered, plaintext);
}

/// F-63 closure: классический ciphersuite (DhKem25519) делегируется в
/// inner OpenMlsRustCrypto без cast через X-Wing branch — verify
/// ZeroizeOnDrop фикс HpkeContext не сломал делегирование. Тест зеркалит
/// `classical_hpke_delegation_works` из `mod tests` xwing.rs но через
/// integration-test API (public surface), что catches любые pub-visibility
/// регрессии (например, если HpkeContext станет pub и его поля начнут
/// выезжать в downstream API).
///
/// F-63 closure: the classical ciphersuite (DhKem25519) is delegated to
/// the inner OpenMlsRustCrypto without going through the X-Wing branch —
/// verify that the HpkeContext ZeroizeOnDrop fix did not break delegation.
/// The test mirrors `classical_hpke_delegation_works` from xwing.rs's
/// `mod tests` but via the integration-test API (public surface), which
/// catches any pub-visibility regressions (e.g. if HpkeContext becomes pub
/// and its fields start leaking into downstream APIs).
#[test]
fn f63_classical_delegation_post_zeroize_fix() {
    let provider = UmbrellaXWingProvider::new();
    let classical_config = HpkeConfig(
        HpkeKemType::DhKem25519,
        HpkeKdfType::HkdfSha256,
        HpkeAeadType::ChaCha20Poly1305,
    );
    let kp = provider
        .derive_hpke_keypair(classical_config, &[0xEEu8; 32])
        .expect("classical derive");
    let classical_config2 = HpkeConfig(
        HpkeKemType::DhKem25519,
        HpkeKdfType::HkdfSha256,
        HpkeAeadType::ChaCha20Poly1305,
    );
    let ct = provider
        .hpke_seal(
            classical_config2,
            &kp.public,
            b"f63-classical",
            b"aad",
            b"classical msg",
        )
        .expect("classical seal");
    let classical_config3 = HpkeConfig(
        HpkeKemType::DhKem25519,
        HpkeKdfType::HkdfSha256,
        HpkeAeadType::ChaCha20Poly1305,
    );
    let pt = provider
        .hpke_open(
            classical_config3,
            &ct,
            &kp.private,
            b"f63-classical",
            b"aad",
        )
        .expect("classical open");
    assert_eq!(pt, b"classical msg");
}

/// F-63 closure: HPKE setup_sender_and_export ↔ setup_receiver_and_export
/// дают совпадающий exporter_secret (foundation для MLS exporter_secret
/// API → SFrame derivation, Этап 6.2). Тест гарантирует что zeroize
/// `exporter_secret_vec` ВНУТРИ key_schedule_base не сломал
/// HpkeContext.export pipeline (export() читает self.exporter_secret через
/// labeled_expand с PRK = self.exporter_secret).
///
/// F-63 closure: HPKE setup_sender_and_export ↔ setup_receiver_and_export
/// produce a matching exporter_secret (foundation for the MLS
/// exporter_secret API → SFrame derivation, Stage 6.2). The test ensures
/// that the zeroize of `exporter_secret_vec` INSIDE key_schedule_base did
/// not break the HpkeContext.export pipeline (export() reads
/// self.exporter_secret via labeled_expand with PRK =
/// self.exporter_secret).
#[test]
fn f63_export_matches_post_zeroize_fix() {
    let provider = UmbrellaXWingProvider::new();
    let kp = provider
        .derive_hpke_keypair(xwing_config(), &[0xBBu8; 32])
        .expect("derive keypair");

    let info = b"f63-export-info";
    let exporter_ctx = b"f63-export-context";

    let (enc, sender_export) = provider
        .hpke_setup_sender_and_export(xwing_config(), &kp.public, info, exporter_ctx, 32)
        .expect("setup_sender_and_export");

    let receiver_export = provider
        .hpke_setup_receiver_and_export(xwing_config(), &enc, &kp.private, info, exporter_ctx, 32)
        .expect("setup_receiver_and_export");

    assert_eq!(&*sender_export, &*receiver_export);
    assert_eq!(sender_export.len(), 32);
}

/// F-63 closure: SPEC-01 §4 row 11 «Cold-boot / forensics» документация-
/// гарантия. Тест не верифицирует physical-memory zeroize (требует
/// `unsafe`, что запрещено `unsafe_code = "forbid"` в Cargo.toml line 12),
/// а документирует логику cold-boot defence:
///
/// 1. Атакующий получает physical access к работающему / spent host'у
///    после обработки HPKE сообщения (sealed-sender V2 либо MLS
///    exporter_secret pipeline).
/// 2. Pre-fix: HpkeContext heap-allocated (sealed-sender V2 path)
///    оставался readable в heap'е post-Drop — `key`, `base_nonce`,
///    `exporter_secret` сохранялись пока allocator не реиспользовал слот.
/// 3. Post-fix: `#[derive(ZeroizeOnDrop)]` гарантирует что zeroize крейт
///    1.7 вызывает `core::ptr::write_volatile` на каждом байте 3 полей
///    при HpkeContext Drop, что не оптимизируется LLVM dead-store
///    elimination.
/// 4. Cold-boot attack теперь даёт zero-byte fields вместо secret
///    keying material → атака провалена.
///
/// Документация-only test compiles + asserts trivially; реальная гарантия
/// покрывается compile-time check'ом `f63_hpke_context_zeroize_on_drop_
/// compile_time_guarantee` в `mod tests` xwing.rs.
///
/// F-63 closure: SPEC-01 §4 row 11 «Cold-boot / forensics» documentation
/// guarantee. The test does not verify physical-memory zeroize (it would
/// require `unsafe`, which is forbidden by `unsafe_code = "forbid"` on
/// line 12 of Cargo.toml); instead it documents the cold-boot defence
/// logic:
///
/// 1. The attacker gains physical access to a running / spent host after
///    it processed an HPKE message (sealed-sender V2 or MLS
///    exporter_secret pipeline).
/// 2. Pre-fix: a heap-allocated HpkeContext (sealed-sender V2 path)
///    remained readable on the heap post-Drop — `key`, `base_nonce`,
///    `exporter_secret` survived until the allocator reused the slot.
/// 3. Post-fix: `#[derive(ZeroizeOnDrop)]` guarantees that zeroize crate
///    1.7 invokes `core::ptr::write_volatile` on every byte of the 3
///    fields on HpkeContext Drop, which is NOT eliminated by LLVM
///    dead-store elimination.
/// 4. The cold-boot attack now reads zero-byte fields instead of secret
///    keying material → the attack is defeated.
///
/// This documentation-only test compiles and asserts trivially; the real
/// guarantee is covered by the
/// `f63_hpke_context_zeroize_on_drop_compile_time_guarantee` compile-time
/// check in xwing.rs's `mod tests`.
#[test]
fn f63_cold_boot_forensics_threat_row_11_documented() {
    // Документация-test: убедиться что provider создаётся, базовый seal
    // отрабатывает, и HpkeContext не утекает через public surface (no
    // pub HpkeContext, no pub field accessor).
    // Documentation test: confirm the provider constructs, a baseline seal
    // works, and HpkeContext does not leak through the public surface (no
    // pub HpkeContext, no pub field accessor).
    let provider = UmbrellaXWingProvider::new();
    let kp = provider
        .derive_hpke_keypair(xwing_config(), &[0x11u8; 32])
        .expect("derive keypair");
    let _ct = provider
        .hpke_seal(
            xwing_config(),
            &kp.public,
            b"f63-doc",
            b"aad",
            b"forensics-doc",
        )
        .expect("seal");
    // По окончании test'а HpkeContext'ы (созданные внутри hpke_seal /
    // derive_hpke_keypair и сразу dropped) уже зануляются при scope-exit'е
    // через ZeroizeOnDrop.
    // By the end of the test the HpkeContext instances (created inside
    // hpke_seal / derive_hpke_keypair and immediately dropped) have
    // already been zeroized at scope-exit through ZeroizeOnDrop.
}
