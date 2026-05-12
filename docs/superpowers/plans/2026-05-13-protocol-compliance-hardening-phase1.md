# Protocol Compliance Hardening Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Закрыть первую фазу утверждённой спецификации `docs/superpowers/specs/2026-05-13-protocol-compliance-hardening-design.md`: контрольные суммы векторов, строгий отказ неизвестному устройству, честные тесты разделённого вида журнала ключей, запрет тихого тестового запуска через публичный FFI.
**Architecture:** Исправления идут малыми вертикальными срезами: сначала воспроизводимый красный сигнал, затем один кодовый фикс, затем связанный документ. Боевой путь, который пока не собран до конца, должен отказывать явно, а не пользоваться тестовыми заглушками.
**Tech Stack:** Rust workspace, Cargo locked tests, UniFFI, SHA-256 vector checks, `umbrella-backup`, `umbrella-tests`, `umbrella-ffi`, public Markdown docs.

---

## Source Of Truth

- `docs/WORKING_RULES.md`
- `docs/superpowers/specs/2026-05-13-protocol-compliance-hardening-design.md`
- `docs/README.md`
- `docs/security/kt-witness-operator-policy.md`
- `crates/umbrella-vectors/data/SOURCES.md`
- `crates/umbrella-vectors/CHECKSUMS.txt`
- `crates/umbrella-backup/src/cloud_wrap/transport.rs`
- `crates/umbrella-tests/tests/stage9_drill_c_server_compromise.rs`
- `crates/umbrella-ffi/src/export/client.rs`
- `crates/umbrella-client/src/core.rs`

## Implementation Tasks

### 1. Fix Reproducible Vector Checksum Gate

- [ ] Reproduce the current red gate from the repository root:

```bash
cargo test -p umbrella-vectors --test test_F_74_checksum_integrity --locked
```

Expected current failure:

```text
data/stability-x-wing.json: SHA-256 mismatch
expected 80a90d3b557ae20b87faa300345511292366fd57529db880e21043e4bbe31da2
got      61fe01f4b4ec1335627ba4baacde63476bcb4ec237e46b93da121185cf662855
```

- [ ] Confirm the root cause is a stale checksum line, not an uncommitted vector edit:

```bash
git status --short
shasum -a 256 crates/umbrella-vectors/data/*.json
git ls-files crates/umbrella-vectors/data/stability-x-wing.json crates/umbrella-vectors/CHECKSUMS.txt
```

Expected evidence:

```text
git status --short
```

prints nothing, both files are tracked, and `stability-x-wing.json` hashes to:

```text
61fe01f4b4ec1335627ba4baacde63476bcb4ec237e46b93da121185cf662855
```

- [ ] Update `crates/umbrella-vectors/CHECKSUMS.txt` line for `data/stability-x-wing.json` to the actual committed file hash:

```text
61fe01f4b4ec1335627ba4baacde63476bcb4ec237e46b93da121185cf662855  data/stability-x-wing.json
```

- [ ] Keep `crates/umbrella-vectors/data/SOURCES.md` unchanged unless the vector file itself changes. The document already says vectors and checksums must change in the same review.

- [ ] Verify:

```bash
cargo test -p umbrella-vectors --test test_F_74_checksum_integrity --locked
```

Expected final result:

```text
test result: ok
```

- [ ] Commit this iteration:

```bash
git add crates/umbrella-vectors/CHECKSUMS.txt
git commit -m "vectors: refresh x-wing checksum"
```

### 2. Reject Unknown Devices After ADR-008 Authorization State Exists

- [ ] Add the failing regression test to `crates/umbrella-backup/src/cloud_wrap/transport.rs` near the existing ADR-008 tests around `adr008_unknown_device_falls_back_to_legacy_reject`:

```rust
#[test]
fn adr008_unknown_device_rejected_when_device_entries_enabled() {
    let (servers, _k) = build_honest_cluster();
    let mut transport = MockUnwrapTransport::new(servers);

    let (_known_sk, known_vk) = make_device_keypair();
    transport.register_device_entry(
        known_vk,
        DeviceEntryState {
            flag: DeviceEntryStateFlag::Active,
            authorized_since: 1,
            history_cutoff: 0,
            identity_pubkey_at_publish: [0x11u8; 32],
        },
    );

    let (unknown_sk, unknown_vk) = make_device_keypair();
    let r_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64);
    let req = make_request(&unknown_sk, unknown_vk, r_point.compress().to_bytes());
    let err = transport.dispatch(&req).unwrap_err();

    assert!(matches!(err, BackupError::CryptoVerificationFailed));
}
```

- [ ] Run the red test:

```bash
cargo test -p umbrella-backup adr008_unknown_device_rejected_when_device_entries_enabled --locked
```

Expected red signal before the fix: the test panics at `unwrap_err()` because the unknown device incorrectly receives shares.

- [ ] Fix the root cause in `crates/umbrella-backup/src/cloud_wrap/transport.rs` inside `check_authorization_state`:

```rust
let Some(entry) = self.device_entries.get(&request.device_pubkey) else {
    // Неизвестное устройство при включённом ADR-008 состоянии не получает доли.
    // Unknown devices fail closed once ADR-008 authorization state is active.
    return Err(BackupError::CryptoVerificationFailed);
};
```

- [ ] Keep the legacy test `adr008_unknown_device_falls_back_to_legacy_reject`, but rename it to make the boundary explicit:

```rust
fn legacy_unknown_device_rejected_by_allowlist_when_adr008_state_absent()
```

The test body remains the legacy allowlist path.

- [ ] Run focused ADR-008 coverage:

```bash
cargo test -p umbrella-backup adr008 --locked
```

Expected final result:

```text
test result: ok
```

- [ ] Run the full package test after the focused pass:

```bash
cargo test -p umbrella-backup --all-features --locked
```

Expected final result:

```text
test result: ok
```

- [ ] Commit this iteration:

```bash
git add crates/umbrella-backup/src/cloud_wrap/transport.rs
git commit -m "backup: fail closed for unknown adr008 devices"
```

### 3. Make Key-Transparency Split-View Tests Truthful

- [ ] In `crates/umbrella-tests/tests/stage9_drill_c_server_compromise.rs`, replace `c6_split_view_defeated_by_witness_consensus` with a narrower test name:

```rust
fn c6_mismatched_root_with_wrong_signatures_is_rejected()
```

Use the existing test body: signatures over `root_a` are attached to `root_b`, and verification must return `KtError::InsufficientValidSignatures { valid: 0, .. }`.

- [ ] Replace the overclaiming comment above the test with the real guarantee:

```rust
/// Подмена корня с подписями от другого корня отклоняется: подписи не проходят
/// проверку над полученным корнем.
///
/// Root substitution with signatures from a different root is rejected:
/// signatures do not verify against the received root.
```

- [ ] Add the truth-boundary test immediately after it:

```rust
#[test]
fn c6_malicious_threshold_split_view_is_locally_accepted_and_requires_gossip_detection() {
    let witnesses: Vec<TestWitness> = vec![
        fresh_witness("DE"),
        fresh_witness("US"),
        fresh_witness("CH"),
        fresh_witness("SG"),
        fresh_witness("BR"),
    ];
    let witness_refs: Vec<&TestWitness> = witnesses.iter().collect();
    let set = build_witness_set(&witness_refs);

    let epoch = 100;
    let root_a = [0xAA; 32];
    let root_b = [0xBB; 32];
    let malicious_threshold = &witness_refs[0..3];

    let sigs_a = sign_epoch_with_witnesses(malicious_threshold, epoch, &root_a);
    let sigs_b = sign_epoch_with_witnesses(malicious_threshold, epoch, &root_b);

    let view_a = SignedEpochRoot {
        epoch,
        root: root_a,
        log_size: 1,
        timestamp_unix_millis: 1_700_000_000_000,
        signatures: sigs_a,
    };
    let view_b = SignedEpochRoot {
        epoch,
        root: root_b,
        log_size: 1,
        timestamp_unix_millis: 1_700_000_000_000,
        signatures: sigs_b,
    };

    verify_signed_epoch(&view_a, &set, WITNESS_THRESHOLD)
        .expect("threshold-signed root_a verifies locally");
    verify_signed_epoch(&view_b, &set, WITNESS_THRESHOLD)
        .expect("threshold-signed root_b also verifies locally");

    assert_ne!(
        view_a.root, view_b.root,
        "same epoch with divergent threshold-signed roots requires monitoring detection"
    );
}
```

- [ ] Update the Russian half of `docs/security/kt-witness-operator-policy.md` to use simple Russian for the same truth boundary. Replace “witness”, “epoch root”, “self-monitoring”, “public gossip”, and “safety-number” in the Russian section with plain wording such as “свидетель”, “корень эпохи”, “самопроверка”, “публичная сверка наблюдений”, and “номер безопасности”.

- [ ] Run the focused test:

```bash
cargo test -p umbrella-tests c6_ --features pq --locked
```

Expected final result:

```text
test result: ok
```

- [ ] Commit this iteration:

```bash
git add crates/umbrella-tests/tests/stage9_drill_c_server_compromise.rs docs/security/kt-witness-operator-policy.md
git commit -m "tests: state kt split-view boundary honestly"
```

### 4. Stop Public FFI Bootstrap From Using Test Constructors

- [ ] Add focused tests in a new file `crates/umbrella-ffi/tests/production_bootstrap.rs`.

Use the fixed BIP-39 24-word test phrase already documented by `umbrella-identity`:

```rust
const VALID_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon art";
```

Use a valid FFI config helper:

```rust
fn valid_config() -> ClientConfigFfi {
    ClientConfigFfi {
        sealed_server_urls: vec![
            "https://sealed-0.example.invalid".into(),
            "https://sealed-1.example.invalid".into(),
            "https://sealed-2.example.invalid".into(),
            "https://sealed-3.example.invalid".into(),
            "https://sealed-4.example.invalid".into(),
        ],
        postman_url: "https://postman.example.invalid".into(),
        kt_url: "https://kt.example.invalid".into(),
        call_relay_url: "https://relay.example.invalid".into(),
        kt_monitor_interval_secs: 3600,
        main_pubkey: vec![0x11; 32],
        server_pubkeys: vec![vec![0x22; 32]; 5],
        wrapping_version: 1,
    }
}
```

Add a helper for the expected error:

```rust
fn assert_production_bootstrap_unavailable(err: UmbrellaError) {
    match err {
        UmbrellaError::Internal(message) => {
            assert!(message.contains("production bootstrap is not available"));
            assert!(message.contains("test constructors"));
        }
        other => panic!("expected Internal production-bootstrap error, got {other:?}"),
    }
}
```

Add at least these tests:

```rust
#[tokio::test]
async fn public_bootstrap_does_not_call_test_constructor() {
    let err = UmbrellaClientHandle::bootstrap(valid_config(), VALID_MNEMONIC.into())
        .await
        .unwrap_err();
    assert_production_bootstrap_unavailable(err);
}

#[cfg(not(feature = "pq"))]
#[tokio::test]
async fn public_bootstrap_classical_does_not_call_test_constructor() {
    let err = UmbrellaClientHandle::bootstrap_classical(valid_config(), VALID_MNEMONIC.into())
        .await
        .unwrap_err();
    assert_production_bootstrap_unavailable(err);
}

#[cfg(feature = "pq")]
#[tokio::test]
async fn public_bootstrap_pq_does_not_call_test_constructor() {
    let err = UmbrellaClientHandle::bootstrap_pq(valid_config(), VALID_MNEMONIC.into())
        .await
        .unwrap_err();
    assert_production_bootstrap_unavailable(err);
}
```

- [ ] Add `tokio` as a dev dependency in `crates/umbrella-ffi/Cargo.toml`:

```toml
[dev-dependencies]
tokio = { workspace = true }
```

- [ ] Run the red tests before the code change:

```bash
cargo test -p umbrella-ffi public_bootstrap --locked
```

Expected red signal before the fix: the constructors return `Ok` handles from `*_for_test`, so `unwrap_err()` panics.

- [ ] Add a private helper to `crates/umbrella-ffi/src/export/client.rs` near the imports:

```rust
fn production_bootstrap_unavailable() -> UmbrellaError {
    UmbrellaError::Internal(
        "production bootstrap is not available: public FFI must not use test constructors until every client transport and required production verifier is wired"
            .into(),
    )
}
```

- [ ] Change `UmbrellaClientHandle::bootstrap`, `bootstrap_pq`, and `bootstrap_classical` to parse the mnemonic and config, then return the fail-fast error instead of calling `UmbrellaClient::*_for_test`:

```rust
let _seed = IdentitySeed::from_mnemonic(&mnemonic_phrase, MnemonicLanguage::English)
    .map_err(|e| UmbrellaError::Identity(e.to_string()))?;
let _rust_config: ClientConfig = config.try_into()?;
Err(production_bootstrap_unavailable())
```

This keeps existing input validation behavior and removes the silent test bootstrap path.

- [ ] Update rustdoc comments for all three constructors in `crates/umbrella-ffi/src/export/client.rs`:

```rust
/// Боевой запуск пока запрещён: конструктор проверяет входные данные и
/// возвращает понятную ошибку, пока клиентские транспорты и боевые проверки
/// не подключены полностью.
///
/// Production bootstrap is currently gated: the constructor validates inputs
/// and returns a clear error until client transports and production verifiers
/// are wired end to end.
```

- [ ] Remove the unused `UmbrellaClient` import from `crates/umbrella-ffi/src/export/client.rs`.

- [ ] Run focused FFI tests:

```bash
cargo test -p umbrella-ffi public_bootstrap --locked
cargo test -p umbrella-ffi public_bootstrap --features pq --locked
```

Expected final result for both:

```text
test result: ok
```

- [ ] Run the whole FFI crate:

```bash
cargo test -p umbrella-ffi --all-features --locked
```

Expected final result:

```text
test result: ok
```

- [ ] Commit this iteration:

```bash
git add crates/umbrella-ffi/Cargo.toml crates/umbrella-ffi/src/export/client.rs crates/umbrella-ffi/tests/production_bootstrap.rs
git commit -m "ffi: fail fast for unavailable production bootstrap"
```

### 5. Update Public Claims To Match The Code

- [ ] Update `README.md` English and Russian opening status. Replace production-ready wording with a precise status:

```text
Umbrella Protocol is a source-available cryptographic protocol stack under
protocol-compliance hardening. The repository contains implemented Rust
cryptographic crates and test harnesses, but the public FFI/client production
bootstrap is gated until every required transport and verifier is wired end to
end.
```

Russian wording:

```text
Umbrella Protocol — исходно доступный криптографический набор, который сейчас
проходит приведение к документам. В репозитории есть реализованные
криптографические крейты и тестовые стенды, но публичный боевой запуск клиента
через FFI закрыт до полной связки транспортов и боевых проверок.
```

- [ ] Update `docs/README.md` current status with the same truth: source package is public for verification, but not a complete public production client bootstrap while phase-1 hardening is active.

- [ ] Update `docs/security/release-manifest-v1.0.0.txt` status lines so the manifest no longer says “production-ready” without the FFI bootstrap caveat.

- [ ] Keep `docs/WORKING_RULES.md` unchanged. It already contains the 15 project postulates and the exact rule that unfinished public paths must not look production-ready.

- [ ] Run documentation and policy checks:

```bash
bash scripts/audit-public-access-notices.sh
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
```

Expected final result:

```text
audit-public-access-notices passes
cargo doc exits 0
```

- [ ] Commit this iteration:

```bash
git add README.md docs/README.md docs/security/release-manifest-v1.0.0.txt
git commit -m "docs: align production claims with hardening status"
```

### 6. Final Workspace Verification

- [ ] Run format:

```bash
cargo fmt --all -- --check
```

Expected:

```text
exit code 0
```

- [ ] Run focused tests once more:

```bash
cargo test -p umbrella-vectors --test test_F_74_checksum_integrity --locked
cargo test -p umbrella-backup adr008 --locked
cargo test -p umbrella-tests c6_ --features pq --locked
cargo test -p umbrella-ffi public_bootstrap --locked
cargo test -p umbrella-ffi public_bootstrap --features pq --locked
```

Expected:

```text
test result: ok
```

- [ ] Run the release gate from the approved spec:

```bash
cargo test --workspace --all-features --locked
```

Expected:

```text
test result: ok
```

- [ ] Run the documentation gate:

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
```

Expected:

```text
exit code 0
```

- [ ] Confirm no uncommitted changes remain:

```bash
git status --short
```

Expected:

```text
```

## Notes For Implementers

- Do not create a fake production constructor in this phase. A real constructor requires all required transports and verifiers to be wired end to end, including the broader TLS, pinning, and platform-verifier work that must be covered by separate follow-up plans.
- Do not remove test constructors from `umbrella-client`; they remain explicitly test-only Rust APIs for crate tests and integration tests.
- Do not weaken vector integrity tests. The checksum file changes only because the committed file is canonical and the checksum line is stale.
- Keep public comments bilingual for open Rust interfaces, as required by `docs/WORKING_RULES.md`.
- After this phase, write separate plans for TLS/pinning, platform attestation production verifier, calls/mobile/server readiness gates, and formal/lint pipeline truthfulness.
