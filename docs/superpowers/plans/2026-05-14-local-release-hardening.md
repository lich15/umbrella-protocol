# Local Release Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** закрыть локальные выпускные ворота Umbrella Protocol без настоящих серверов и реальных устройств: формальные модели, fuzz, нагрузка, split-view, гонки, секреты и закрытый отказ недоделанных путей.

**Architecture:** фаза добавляет один повторяемый локальный запуск `local-release-hardening`, два новых атакующих Rust-набора и один строгий аудит исходников. Короткий режим обязан проходить в обычной разработке, длинный режим остаётся честным ночным запуском перед выпуском и не выдаётся за серверную проверку миллиона пользователей.

**Tech Stack:** Rust workspace, Cargo locked gates, shell scripts, cargo-fuzz, ProVerif, Tamarin, Miri runbook, Ed25519 witness signatures, KT Merkle root, replay guards, Markdown-документы на простом русском.

---

## File Structure

- Create: `scripts/run-local-release-hardening.sh` — единая короткая команда локальных выпускных ворот; пишет evidence в `target/audit-evidence/local-release-hardening/<timestamp>/`.
- Create: `scripts/audit-local-release-hardening.sh` — аудит утечек секретов и недоделанных путей, которые не должны выглядеть боевыми.
- Create: `crates/umbrella-kt/tests/split_view_exchange.rs` — локальный симулятор: две подписанные KT-истории могут пройти порог, но сверка клиентов обязана увидеть разные корни.
- Create: `crates/umbrella-tests/tests/local_load_and_race.rs` — локальная нагрузка на KT/witness/replay и многопоточные проверки без серверов.
- Modify: `scripts/audit-protocol-core-attack-gates.sh` — добавить новые split-view, load/race и local-release gates в обязательную матрицу.
- Modify: `scripts/run-fuzz-overnight.sh` — добавить явный короткий режим через аргумент времени и сохранить честное поведение при отсутствии nightly/cargo-fuzz.
- Create: `docs/audits/local-release-hardening-status-2026-05-14.md` — свежий статус локальных ворот и честные границы.
- Modify: `docs/security/current-status.md` — добавить новый локальный hardening status и границы.
- Modify: `docs/security/production-readiness-boundaries.md` — указать, что локальная нагрузка не равна серверной проверке.
- Modify: `docs/security/protocol-core-attack-gates.md` — добавить новые доказательства split-view сверки, локальной нагрузки, гонок и аудита секретов.
- Modify: `docs/audits/formal-lint-status-2026-05-13.md` — связать старый формальный статус с новым свежим прогоном или честным отказом инструмента.
- Modify: `README.md`, `docs/README.md` — добавить команды локальных ворот.

---

### Task 1: Add KT Split-View Exchange Simulator

**Files:**
- Create: `crates/umbrella-kt/tests/split_view_exchange.rs`
- Test: `crates/umbrella-kt/tests/split_view_exchange.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/umbrella-kt/tests/split_view_exchange.rs` with this structure:

```rust
use rand_core::{OsRng, RngCore};
use umbrella_crypto_primitives::sig::PrivateSigningKey;
use umbrella_kt::{
    canonical_sign_payload, verify_signed_epoch, SignedEpochRoot, WitnessPublic, WitnessSet,
    WitnessSignature, NODE_HASH_LEN,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct KtObservation {
    client: &'static str,
    epoch: u64,
    root: [u8; NODE_HASH_LEN],
    log_size: u64,
}

fn split_view_detected(a: &KtObservation, b: &KtObservation) -> bool {
    a.epoch == b.epoch && (a.root != b.root || a.log_size != b.log_size)
}

fn make_witnesses() -> Vec<(PrivateSigningKey, WitnessPublic)> {
    (0..5)
        .map(|_| {
            let mut rng = OsRng;
            let sk = PrivateSigningKey::generate(&mut rng);
            let pk = WitnessPublic::from_bytes(sk.verifying_key().to_bytes());
            (sk, pk)
        })
        .collect()
}

fn witness_set(witnesses: &[(PrivateSigningKey, WitnessPublic)]) -> WitnessSet {
    let mut set = WitnessSet::new();
    for (_, public) in witnesses {
        set.add(*public);
    }
    set
}

fn signed_view(
    witnesses: &[(PrivateSigningKey, WitnessPublic)],
    signer_indices: &[usize],
    epoch: u64,
    root: [u8; NODE_HASH_LEN],
    log_size: u64,
    timestamp_unix_millis: u64,
) -> SignedEpochRoot {
    let payload = canonical_sign_payload(epoch, &root, log_size, timestamp_unix_millis);
    let signatures = signer_indices
        .iter()
        .map(|idx| {
            let (sk, public) = &witnesses[*idx];
            WitnessSignature {
                witness: *public,
                signature: sk.sign(&payload).to_bytes(),
            }
        })
        .collect();
    SignedEpochRoot {
        epoch,
        root,
        log_size,
        timestamp_unix_millis,
        signatures,
    }
}

#[test]
fn threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence() {
    let witnesses = make_witnesses();
    let set = witness_set(&witnesses);

    let mut honest_root = [0u8; NODE_HASH_LEN];
    let mut evil_root = [0u8; NODE_HASH_LEN];
    OsRng.fill_bytes(&mut honest_root);
    OsRng.fill_bytes(&mut evil_root);

    let alice_view = signed_view(&witnesses, &[0, 1, 2], 42, honest_root, 50_000, 1_700_000_100);
    let bob_view = signed_view(&witnesses, &[0, 1, 2], 42, evil_root, 50_001, 1_700_000_101);

    verify_signed_epoch(&alice_view, &set, 3).expect("alice sees a locally valid 3-of-5 epoch");
    verify_signed_epoch(&bob_view, &set, 3).expect("bob sees a locally valid 3-of-5 epoch");

    let alice_observation = KtObservation {
        client: "alice",
        epoch: alice_view.epoch,
        root: alice_view.root,
        log_size: alice_view.log_size,
    };
    let bob_observation = KtObservation {
        client: "bob",
        epoch: bob_view.epoch,
        root: bob_view.root,
        log_size: bob_view.log_size,
    };

    assert!(
        split_view_detected(&alice_observation, &bob_observation),
        "client observation exchange must detect same-epoch KT split-view"
    );
}
```

- [ ] **Step 2: Run the test and verify red state**

Run:

```bash
cargo test -p umbrella-kt threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence --all-features --locked
```

Expected: FAIL at compile stage because the new file has not been created before this step.

- [ ] **Step 3: Create the test file**

Apply the code from Step 1 exactly, with dual Russian/English comments only where the intent is not obvious.

- [ ] **Step 4: Run focused KT test**

Run:

```bash
cargo test -p umbrella-kt threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence --all-features --locked
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/umbrella-kt/tests/split_view_exchange.rs
git commit -m "kt: add split view exchange simulator"
```

---

### Task 2: Add Local Load And Race Tests

**Files:**
- Create: `crates/umbrella-tests/tests/local_load_and_race.rs`
- Test: `crates/umbrella-tests/tests/local_load_and_race.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/umbrella-tests/tests/local_load_and_race.rs` with three tests:

```rust
use std::sync::{Arc, Mutex};
use std::thread;

use rand_core::{OsRng, RngCore};
use umbrella_crypto_primitives::sig::PrivateSigningKey;
use umbrella_kt::{
    build_audit_path, canonical_sign_payload, leaf_hash, merkle_root, verify_inclusion,
    verify_signed_epoch, SignedEpochRoot, WitnessPublic, WitnessSet, WitnessSignature,
    NODE_HASH_LEN,
};
use umbrella_server_blind_postman::{ReplayDecision, ReplayGuard};

fn make_witnesses() -> Vec<(PrivateSigningKey, WitnessPublic)> {
    (0..5)
        .map(|_| {
            let mut rng = OsRng;
            let sk = PrivateSigningKey::generate(&mut rng);
            let pk = WitnessPublic::from_bytes(sk.verifying_key().to_bytes());
            (sk, pk)
        })
        .collect()
}

fn witness_set(witnesses: &[(PrivateSigningKey, WitnessPublic)]) -> WitnessSet {
    let mut set = WitnessSet::new();
    for (_, public) in witnesses {
        set.add(*public);
    }
    set
}

fn signed_epoch(
    witnesses: &[(PrivateSigningKey, WitnessPublic)],
    epoch: u64,
    root: [u8; NODE_HASH_LEN],
    log_size: u64,
) -> SignedEpochRoot {
    let payload = canonical_sign_payload(epoch, &root, log_size, 1_700_000_000 + epoch);
    let signatures = witnesses
        .iter()
        .take(3)
        .map(|(sk, public)| WitnessSignature {
            witness: *public,
            signature: sk.sign(&payload).to_bytes(),
        })
        .collect();
    SignedEpochRoot {
        epoch,
        root,
        log_size,
        timestamp_unix_millis: 1_700_000_000 + epoch,
        signatures,
    }
}

#[test]
fn local_load_many_kt_leaves_keep_valid_inclusion_and_witness_roots() {
    const LEAVES: usize = 4096;
    let witnesses = make_witnesses();
    let set = witness_set(&witnesses);

    let leaves: Vec<[u8; NODE_HASH_LEN]> = (0..LEAVES)
        .map(|idx| leaf_hash(format!("account-{idx}:device-{}", idx % 8).as_bytes()))
        .collect();
    let root = merkle_root(&leaves);
    let signed = signed_epoch(&witnesses, 77, root, LEAVES as u64);

    verify_signed_epoch(&signed, &set, 3).expect("local load root must keep 3-of-5 witness validity");

    for idx in [0usize, 1, 255, 1024, 2048, 4095] {
        let path = build_audit_path(&leaves, idx);
        verify_inclusion(&leaves[idx], idx, LEAVES, &path, &root)
            .expect("selected loaded leaves must keep valid inclusion proof");
    }
}

#[test]
fn concurrent_replay_guard_accepts_one_duplicate_hash_and_rejects_the_rest() {
    let guard = Arc::new(Mutex::new(ReplayGuard::new(60)));
    let mut hash = [0u8; 32];
    OsRng.fill_bytes(&mut hash);

    let handles: Vec<_> = (0..32)
        .map(|_| {
            let guard = Arc::clone(&guard);
            thread::spawn(move || {
                guard
                    .lock()
                    .expect("replay guard mutex poisoned")
                    .check_and_record(hash, 1_700_000_000)
            })
        })
        .collect();

    let mut accepts = 0usize;
    let mut duplicates = 0usize;
    for handle in handles {
        match handle.join().expect("worker thread must not panic") {
            ReplayDecision::Accept => accepts += 1,
            ReplayDecision::Duplicate => duplicates += 1,
        }
    }

    assert_eq!(accepts, 1, "exactly one racing replay must be accepted");
    assert_eq!(duplicates, 31, "all other racing replays must be rejected");
}

#[test]
fn concurrent_witness_verification_has_no_shared_state_corruption() {
    let witnesses = make_witnesses();
    let set = Arc::new(witness_set(&witnesses));

    let signed_epochs: Vec<_> = (0..64u64)
        .map(|epoch| {
            let mut root = [0u8; NODE_HASH_LEN];
            root[0..8].copy_from_slice(&epoch.to_be_bytes());
            signed_epoch(&witnesses, epoch, root, 1024 + epoch)
        })
        .collect();

    let handles: Vec<_> = signed_epochs
        .into_iter()
        .map(|signed| {
            let set = Arc::clone(&set);
            thread::spawn(move || verify_signed_epoch(&signed, &set, 3))
        })
        .collect();

    for handle in handles {
        handle
            .join()
            .expect("witness verification thread must not panic")
            .expect("signed epoch must verify");
    }
}
```

- [ ] **Step 2: Run the tests and verify red state**

Run:

```bash
cargo test -p umbrella-tests local_load_and_race --all-features --locked
```

Expected: FAIL at compile stage before the file exists.

- [ ] **Step 3: Create the test file**

Apply the code from Step 1. Keep the load count at `4096` so the check is meaningful locally but not confused with a real server load test.

- [ ] **Step 4: Run focused tests**

Run:

```bash
cargo test -p umbrella-tests local_load --all-features --locked
cargo test -p umbrella-tests concurrent_replay_guard --all-features --locked
cargo test -p umbrella-tests concurrent_witness_verification --all-features --locked
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/umbrella-tests/tests/local_load_and_race.rs
git commit -m "tests: add local load and race gates"
```

---

### Task 3: Add Secret Leak And Incomplete Path Audit

**Files:**
- Create: `scripts/audit-local-release-hardening.sh`
- Modify: `scripts/audit-protocol-core-attack-gates.sh`

- [ ] **Step 1: Write the failing audit**

Create `scripts/audit-local-release-hardening.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

evidence_dir="${1:-target/audit-evidence/local-release-hardening/manual}"
mkdir -p "$evidence_dir"

failed=0

require_pattern() {
  local file="$1"
  local pattern="$2"
  if [[ ! -f "$file" ]]; then
    echo "missing $file" >&2
    failed=1
    return
  fi
  if ! grep -Eqi "$pattern" "$file"; then
    echo "$file does not contain required local hardening evidence: $pattern" >&2
    failed=1
  fi
}

reject_public_secret_debug() {
  local output="$evidence_dir/secret-debug-candidates.txt"
  rg -n "derive\\(.*Debug|#\\[derive\\([^\\]]*Debug|impl Debug|println!|eprintln!|dbg!|tracing::|log::" \
    crates/umbrella-{backup,client,identity,kt,oprf,sealed-sender,server-blind-postman,pq,crypto-primitives}/src \
    >"$output" || true
  if rg -n "secret|seed|mnemonic|private|sk|share|token" "$output" >/dev/null; then
    echo "secret-bearing debug/log candidates found; inspect $output" >&2
    failed=1
  fi
}

reject_prod_todo_unimplemented() {
  local output="$evidence_dir/prod-todo-unimplemented.txt"
  rg -n "todo!\\(|unimplemented!\\(|panic!\\(|unwrap\\(|expect\\(" \
    crates/umbrella-{backup,client,identity,kt,oprf,sealed-sender,server-blind-postman,pq,crypto-primitives}/src \
    >"$output" || true
  if rg -n "todo!\\(|unimplemented!\\(" "$output" >/dev/null; then
    echo "production todo/unimplemented found; inspect $output" >&2
    failed=1
  fi
}

require_pattern "crates/umbrella-kt/tests/split_view_exchange.rs" "threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence"
require_pattern "crates/umbrella-tests/tests/local_load_and_race.rs" "local_load_many_kt_leaves_keep_valid_inclusion_and_witness_roots"
require_pattern "crates/umbrella-tests/tests/local_load_and_race.rs" "concurrent_replay_guard_accepts_one_duplicate_hash_and_rejects_the_rest"
require_pattern "scripts/run-local-release-hardening.sh" "verify-formal-production-readiness"
require_pattern "scripts/run-local-release-hardening.sh" "run-fuzz-overnight"
require_pattern "docs/audits/local-release-hardening-status-2026-05-14.md" "локальная нагрузка не равна серверной проверке"

reject_public_secret_debug
reject_prod_todo_unimplemented

if [[ "$failed" -ne 0 ]]; then
  exit "$failed"
fi

echo "local release hardening audit OK"
```

- [ ] **Step 2: Make it executable**

Run:

```bash
chmod +x scripts/audit-local-release-hardening.sh
```

- [ ] **Step 3: Run and verify red state**

Run:

```bash
bash scripts/audit-local-release-hardening.sh
```

Expected: FAIL until Tasks 1, 2, 4 and 5 add the required files and docs.

- [ ] **Step 4: Extend protocol attack audit**

Add these checks to `scripts/audit-protocol-core-attack-gates.sh`:

```bash
require_pattern "crates/umbrella-kt/tests/split_view_exchange.rs" "threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence"
require_pattern "crates/umbrella-tests/tests/local_load_and_race.rs" "local_load_many_kt_leaves_keep_valid_inclusion_and_witness_roots"
require_pattern "crates/umbrella-tests/tests/local_load_and_race.rs" "concurrent_replay_guard_accepts_one_duplicate_hash_and_rejects_the_rest"
require_pattern "scripts/audit-local-release-hardening.sh" "secret-bearing debug/log candidates"
require_pattern "docs/audits/local-release-hardening-status-2026-05-14.md" "split-view"
```

- [ ] **Step 5: Commit after green state**

Do not commit this audit while it is red. Commit it with the orchestrator and docs after Task 5:

```bash
git add scripts/audit-local-release-hardening.sh scripts/audit-protocol-core-attack-gates.sh
git commit -m "security: audit local release hardening gates"
```

---

### Task 4: Add One Local Release Hardening Runner

**Files:**
- Create: `scripts/run-local-release-hardening.sh`
- Modify: `scripts/run-fuzz-overnight.sh`

- [ ] **Step 1: Write the runner**

Create `scripts/run-local-release-hardening.sh`:

```bash
#!/usr/bin/env bash
set -uo pipefail

mode="${1:-short}"
case "$mode" in
  short) fuzz_seconds="${LOCAL_HARDENING_FUZZ_SECONDS:-5}" ;;
  long) fuzz_seconds="${LOCAL_HARDENING_FUZZ_SECONDS:-1800}" ;;
  *) echo "usage: $0 [short|long]" >&2; exit 2 ;;
esac

timestamp="$(date -u +"%Y%m%d-%H%M%S")"
evidence_dir="target/audit-evidence/local-release-hardening/$timestamp"
mkdir -p "$evidence_dir"
summary="$evidence_dir/summary.txt"

failed=0

run_gate() {
  local name="$1"
  shift
  local log="$evidence_dir/${name}.log"
  echo "== $name ==" | tee -a "$summary"
  echo "command: $*" | tee -a "$summary"
  if "$@" >"$log" 2>&1; then
    echo "status: PASS" | tee -a "$summary"
  else
    local code="$?"
    echo "status: FAIL ($code), see $log" | tee -a "$summary"
    failed=1
  fi
  echo "" | tee -a "$summary"
}

echo "Umbrella local release hardening" | tee "$summary"
echo "mode: $mode" | tee -a "$summary"
echo "started: $(date -u)" | tee -a "$summary"
echo "evidence: $evidence_dir" | tee -a "$summary"
echo "" | tee -a "$summary"

run_gate formal-readiness bash scripts/verify-formal-production-readiness.sh "$evidence_dir/formal-readiness"
run_gate proverif-models bash scripts/verify-proverif-models.sh "$evidence_dir/proverif"
run_gate tamarin-models bash scripts/verify-tamarin-models.sh "$evidence_dir/tamarin"
run_gate kt-split-view cargo test -p umbrella-kt threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence --all-features --locked
run_gate local-load cargo test -p umbrella-tests local_load_many_kt_leaves_keep_valid_inclusion_and_witness_roots --all-features --locked
run_gate local-race-replay cargo test -p umbrella-tests concurrent_replay_guard_accepts_one_duplicate_hash_and_rejects_the_rest --all-features --locked
run_gate local-race-witness cargo test -p umbrella-tests concurrent_witness_verification_has_no_shared_state_corruption --all-features --locked
run_gate protocol-attack-audit bash scripts/audit-protocol-core-attack-gates.sh
run_gate test-only-boundary-audit bash scripts/audit-test-only-production-boundary.sh
run_gate local-hardening-audit bash scripts/audit-local-release-hardening.sh "$evidence_dir/local-hardening-audit"

if command -v cargo-fuzz >/dev/null 2>&1 && cargo +nightly --version >/dev/null 2>&1; then
  run_gate fuzz-smoke bash scripts/run-fuzz-overnight.sh "$fuzz_seconds" kt_entry_v2_parser sealed_sender_v2_parser wrapped_key_v2_parser oprf_parse_blinded_request
else
  echo "== fuzz-smoke ==" | tee -a "$summary"
  echo "status: FAIL" | tee -a "$summary"
  echo "reason: cargo-fuzz or nightly Rust is missing; this is not counted as success" | tee -a "$summary"
  echo "" | tee -a "$summary"
  failed=1
fi

echo "finished: $(date -u)" | tee -a "$summary"
echo "failed: $failed" | tee -a "$summary"

exit "$failed"
```

- [ ] **Step 2: Make it executable**

Run:

```bash
chmod +x scripts/run-local-release-hardening.sh
```

- [ ] **Step 3: Run and verify red state**

Run:

```bash
bash scripts/run-local-release-hardening.sh short
```

Expected: FAIL until Tasks 1, 2, 3 and 5 are complete, or fail honestly if formal/fuzz tools are absent.

- [ ] **Step 4: Keep `run-fuzz-overnight.sh` honest**

Do not make missing `nightly` or missing `cargo-fuzz` pass. If this script already fails closed on missing tools, leave behavior unchanged and update docs only.

- [ ] **Step 5: Commit after green state**

Commit this with Task 3 or Task 5 when the short runner reaches honest green or documented tool-missing red:

```bash
git add scripts/run-local-release-hardening.sh scripts/run-fuzz-overnight.sh
git commit -m "security: add local release hardening runner"
```

---

### Task 5: Update Documents And Evidence Status

**Files:**
- Create: `docs/audits/local-release-hardening-status-2026-05-14.md`
- Modify: `docs/security/current-status.md`
- Modify: `docs/security/production-readiness-boundaries.md`
- Modify: `docs/security/protocol-core-attack-gates.md`
- Modify: `docs/audits/formal-lint-status-2026-05-13.md`
- Modify: `README.md`
- Modify: `docs/README.md`

- [ ] **Step 1: Create the status document**

Create `docs/audits/local-release-hardening-status-2026-05-14.md`:

```markdown
# Локальные выпускные ворота Umbrella Protocol

Дата: 2026-05-14

Этот документ фиксирует только локальные проверки. Он не заменяет настоящие
серверы, реальные Android/iOS устройства и боевое развёртывание свидетелей KT.

## Что проверяется локально

| Ворота | Команда | Что доказывает |
|---|---|---|
| Формальные модели | `bash scripts/verify-formal-production-readiness.sh`, `bash scripts/verify-proverif-models.sh`, `bash scripts/verify-tamarin-models.sh` | текущие модели проходят или честно показывают отсутствие внешнего инструмента |
| Fuzz smoke | `bash scripts/run-fuzz-overnight.sh 5 kt_entry_v2_parser sealed_sender_v2_parser wrapped_key_v2_parser oprf_parse_blinded_request` | разборщики не падают на коротком потоке мусорных входов |
| Ночной fuzz | `bash scripts/run-fuzz-overnight.sh 1800` | длинный прогон всех fuzz-целей перед выпуском |
| Локальная нагрузка | `cargo test -p umbrella-tests local_load_many_kt_leaves_keep_valid_inclusion_and_witness_roots --all-features --locked` | KT Merkle root, inclusion proof и witness-порог работают на тысячах локальных листьев |
| Гонки replay | `cargo test -p umbrella-tests concurrent_replay_guard_accepts_one_duplicate_hash_and_rejects_the_rest --all-features --locked` | при одновременном повторе принимается только первый запрос |
| Гонки witness | `cargo test -p umbrella-tests concurrent_witness_verification_has_no_shared_state_corruption --all-features --locked` | параллельная проверка подписанных эпох не портит состояние |
| KT split-view сверка | `cargo test -p umbrella-kt threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence --all-features --locked` | две локально подписанные версии одной эпохи обнаруживаются при обмене наблюдениями клиентов |
| Секреты и закрытые пути | `bash scripts/audit-local-release-hardening.sh` | секретные типы и недоделанные пути не должны выглядеть как боевые |

## Честные границы

- Локальная нагрузка не равна серверной проверке на миллион активных пользователей.
- KT split-view считается полностью закрытым только после живой сверки клиентов,
  наблюдения свидетелей и серверного развёртывания.
- Если ProVerif, Tamarin, nightly Rust или cargo-fuzz отсутствуют, это отказ
  соответствующих ворот, а не успех.
- Публичный боевой клиент остаётся закрыт, пока серверная и мобильная связка не
  готовы.
```

- [ ] **Step 2: Update current status**

In `docs/security/current-status.md`, add one Russian and one English bullet that point to `docs/audits/local-release-hardening-status-2026-05-14.md` and say that local hardening is not server/device proof.

- [ ] **Step 3: Update production boundaries**

In `docs/security/production-readiness-boundaries.md`, add a closed gate for local release hardening and a boundary that real servers, real devices and live KT gossip remain outside this local proof.

- [ ] **Step 4: Update attack gates**

In `docs/security/protocol-core-attack-gates.md`, add rows for:

```markdown
| KT | split-view обнаруживается при обмене наблюдениями клиентов | локально закрыто обнаружение | `threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence` |
| Нагрузка | тысячи локальных KT-листьев с proof и witness-порогом | закрыто локальным тестом | `local_load_many_kt_leaves_keep_valid_inclusion_and_witness_roots` |
| Гонки | одновременный replay одного hash | закрыто локальным тестом | `concurrent_replay_guard_accepts_one_duplicate_hash_and_rejects_the_rest` |
| Гонки | параллельная проверка witness-эпох | закрыто локальным тестом | `concurrent_witness_verification_has_no_shared_state_corruption` |
| Секреты | отладочный вывод и недоделанные пути | закрыто локальным аудитом | `scripts/audit-local-release-hardening.sh` |
```

- [ ] **Step 5: Update formal/lint status**

In `docs/audits/formal-lint-status-2026-05-13.md`, add a 2026-05-14 note that the fresh local hardening runner is now the preferred aggregate command and that missing external tools remain release blockers.

- [ ] **Step 6: Update command indexes**

Add to `README.md` and `docs/README.md`:

```markdown
bash scripts/run-local-release-hardening.sh short
bash scripts/run-local-release-hardening.sh long
bash scripts/audit-local-release-hardening.sh
```

- [ ] **Step 7: Run docs/audit checks**

Run:

```bash
bash scripts/audit-protocol-core-attack-gates.sh
bash scripts/audit-local-release-hardening.sh
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add docs/audits/local-release-hardening-status-2026-05-14.md docs/security/current-status.md docs/security/production-readiness-boundaries.md docs/security/protocol-core-attack-gates.md docs/audits/formal-lint-status-2026-05-13.md README.md docs/README.md
git commit -m "docs: record local release hardening gates"
```

---

### Task 6: Run Full Local Gates And Fix By Root Cause

**Files:**
- Modify only files implicated by a verified failure.

- [ ] **Step 1: Run short local hardening**

Run:

```bash
bash scripts/run-local-release-hardening.sh short
```

Expected: PASS if all local tools are installed; otherwise FAIL with a clear missing-tool reason in `target/audit-evidence/local-release-hardening/<timestamp>/summary.txt`.

- [ ] **Step 2: If any gate fails, use systematic debugging**

For each failure:

```text
1. Read the full log in target/audit-evidence/local-release-hardening/<timestamp>/<gate>.log.
2. Re-run the smallest failing command directly.
3. Identify the exact source file or missing external tool.
4. Write or keep the failing test/audit.
5. Apply one fix.
6. Re-run the smallest command.
7. Re-run the aggregate runner.
```

- [ ] **Step 3: Run final Rust checks**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
cargo test --workspace --all-features --locked
```

Expected: all PASS, or a documented external-tool boundary if the failure is outside Rust code.

- [ ] **Step 4: Commit final fixes or verification docs**

```bash
git status --short
git add <changed-files>
git commit -m "security: complete local release hardening gates"
```

---

## Self-Review

- Spec coverage: the plan covers fresh formal run, fuzz, local load, KT split-view exchange, race checks, secret leak checks, unfinished fail-closed audit, docs, and per-iteration commits.
- Scope boundary: no task writes to `/Users/daniel/Documents/Projects/Messenger/rust_1mlrd`; servers and real devices remain out of scope.
- Fresh references checked on 2026-05-14: Rust Fuzz Book for `cargo fuzz run`, Tamarin manual for warning handling, ProVerif manual behavior for true/false results, and Miri notes for race/undefined-behavior limits.
- Execution choice: user already selected inline execution in this session, so implementation continues after the plan commit.
