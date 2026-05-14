# External Crypto Release Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** провести полный внешний крипто-ресерч Umbrella Protocol, превратить найденные классы атак в локальные атакующие проверки, закрытые отказы, документы и выпускной evidence-пакет.

**Architecture:** фаза идёт маленькими итерациями: сначала создаётся внешний реестр атак и повторяемый аудит, затем каждая область протокола проверяется “снаружи внутрь” и “изнутри наружу”. Любая применимая атака получает Rust-тест или скрипт; если требуется сервер, `rust_1mlrd` или реальные Android/iOS устройства, локальный путь закрывается отказом и записывается как честная граница выпуска.

**Tech Stack:** Rust workspace, Cargo locked gates, cargo-fuzz, Miri, ProVerif/Tamarin scripts, cargo-deny/RustSec, Markdown-документы на русском, web-проверка первичных источников.

---

## Scope And Boundaries

- Не трогать `/Users/daniel/Documents/Projects/Messenger/rust_1mlrd`.
- Не трогать реальные Android/iOS устройства.
- Не открывать публичный FFI/client bootstrap.
- Не заявлять “невозможно взломать”.
- Если внешний инструмент отсутствует, это блокер или честная граница, а не успех.
- После каждой законченной итерации: обновить связанные `.md`, запустить фокусные проверки, сделать коммит.

## File Structure

- Create: `docs/security/external-crypto-attack-ledger-2026-05-14.md` — внешний реестр атак: источник, дата доступа, область Umbrella, статус, доказательство.
- Create: `scripts/audit-external-crypto-attack-ledger.sh` — повторяемая проверка, что реестр содержит все обязательные области, источники и статусы.
- Modify: `scripts/audit-protocol-core-attack-gates.sh` — требовать ссылку на внешний реестр и ключевые новые доказательства.
- Modify: `scripts/audit-public-access-notices.sh` — требовать, что публичные документы не обещают внешний выпуск без серверов и устройств.
- Modify: `docs/security/protocol-core-attack-gates.md` — добавить внешний источник для каждой локально закрытой атаки.
- Modify: `docs/security/current-status.md` — обновить статус внешнего выпускного аудита.
- Modify: `docs/security/production-readiness-boundaries.md` — уточнить границы серверов, живых устройств, KT-свидетелей и мобильных мостов.
- Modify/Create tests under:
  - `crates/umbrella-oprf/tests/`
  - `crates/umbrella-kt/tests/`
  - `crates/umbrella-client/src/transport/`
  - `crates/umbrella-pq/tests/`
  - `crates/umbrella-backup/tests/`
  - `crates/umbrella-sealed-sender/tests/`
  - `crates/umbrella-tests/tests/`
- Evidence directory: `target/audit-evidence/external-crypto-release/20260514/`.

---

### Task 1: Create External Attack Ledger And Audit Gate

**Files:**
- Create: `docs/security/external-crypto-attack-ledger-2026-05-14.md`
- Create: `scripts/audit-external-crypto-attack-ledger.sh`
- Modify: `scripts/audit-protocol-core-attack-gates.sh`
- Modify: `docs/security/protocol-core-attack-gates.md`

- [ ] **Step 1: Write the initial failing audit script**

Create `scripts/audit-external-crypto-attack-ledger.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

ledger="docs/security/external-crypto-attack-ledger-2026-05-14.md"
failed=0

require_file() {
  if [[ ! -f "$ledger" ]]; then
    echo "missing external crypto attack ledger: $ledger" >&2
    exit 1
  fi
}

require_pattern() {
  local pattern="$1"
  if ! grep -Eqi "$pattern" "$ledger"; then
    echo "$ledger missing required pattern: $pattern" >&2
    failed=1
  fi
}

reject_pattern() {
  local pattern="$1"
  if grep -Eqi "$pattern" "$ledger"; then
    echo "$ledger contains forbidden wording: $pattern" >&2
    failed=1
  fi
}

require_file

require_pattern "RFC 9497"
require_pattern "RFC 9420"
require_pattern "RFC 9180"
require_pattern "RFC 9605"
require_pattern "RFC 8446"
require_pattern "FIPS 203"
require_pattern "FIPS 204"
require_pattern "FIPS 205"
require_pattern "WebAuthn"
require_pattern "Apple App Attest"
require_pattern "Android Play Integrity"
require_pattern "Signal"
require_pattern "KyberSlash"
require_pattern "RustSec"
require_pattern "cargo-deny"
require_pattern "SLSA"

require_pattern "OPRF"
require_pattern "KT"
require_pattern "TLS"
require_pattern "PQ"
require_pattern "Backup"
require_pattern "Sealed Sender"
require_pattern "MLS"
require_pattern "SFrame"
require_pattern "Устройства"
require_pattern "Зависимости"

require_pattern "закрыто тестом"
require_pattern "закрыто отказом"
require_pattern "граница выпуска"
require_pattern "неприменимо"

reject_pattern "TBD|TODO|FIXME"
reject_pattern "100%|невозможно взломать|абсолютно безопас"

if [[ "$failed" -ne 0 ]]; then
  exit "$failed"
fi

echo "external crypto attack ledger OK"
```

- [ ] **Step 2: Run the audit and confirm it fails before the ledger exists**

Run:

```bash
bash scripts/audit-external-crypto-attack-ledger.sh
```

Expected: FAIL with `missing external crypto attack ledger`.

- [ ] **Step 3: Create the ledger with required seeded rows**

Create `docs/security/external-crypto-attack-ledger-2026-05-14.md`:

```markdown
# Внешний реестр атак Umbrella Protocol

Дата: 2026-05-14

Этот файл связывает внешние источники с локальными проверками Umbrella
Protocol. Форумы и журналы используются как разведка идей, но итоговый статус
должен опираться на стандарт, статью, advisory, код или воспроизводимый тест.

## Статусы

- `закрыто тестом` — есть Rust-тест, fuzz-цель или скрипт, который ломает атаку.
- `закрыто отказом` — локальный путь не открывается и возвращает понятную ошибку.
- `граница выпуска` — нужна серверная часть, живое устройство, внешние корни доверия или боевые свидетели.
- `неприменимо` — атака не относится к текущему коду; причина записана.

## Матрица

| Область | Источник | Дата доступа | Атака простыми словами | Место в Umbrella | Статус | Доказательство |
|---|---|---|---|---|---|---|
| OPRF | RFC 9497 `https://www.rfc-editor.org/rfc/rfc9497` | 2026-05-14 | неверная точка, повтор, неправильная финализация | `umbrella-oprf` | закрыто тестом | `crates/umbrella-oprf/tests/test_lagrange_determinism.rs`, `crates/umbrella-oprf/src/primitives.rs` |
| KT | CONIKS / key transparency papers, Trillian docs | 2026-05-14 | split-view при злых свидетелях | `umbrella-kt` | граница выпуска | локальное обнаружение есть, полное закрытие требует обмена наблюдениями |
| TLS | RFC 8446 `https://www.rfc-editor.org/rfc/rfc8446` | 2026-05-14 | downgrade, replay, слабый транспорт | `umbrella-client/src/transport` | закрыто тестом | `pinning.rs`, `http2_client.rs` |
| PQ | FIPS 203 `https://csrc.nist.gov/pubs/fips/203/final` | 2026-05-14 | неправильный ML-KEM ciphertext и timing-риск | `umbrella-pq` | закрыто тестом | `ml_kem_decapsulate_fuzz`, dependency gate |
| PQ | FIPS 204 `https://csrc.nist.gov/pubs/fips/204/final` | 2026-05-14 | неправильная ML-DSA подпись | `umbrella-pq`, `umbrella-identity` | закрыто тестом | hybrid signature parser/fuzz |
| PQ | FIPS 205 `https://csrc.nist.gov/pubs/fips/205/final` | 2026-05-14 | неправильный SLH-DSA режим | `umbrella-identity` | граница выпуска | SLH-DSA остаётся отдельной выпускной проверкой identity/PQ режима |
| PQ | KyberSlash `https://eprint.iacr.org/2024/1049` | 2026-05-14 | timing leakage при decapsulation | `umbrella-pq` | закрыто тестом | dependency policy + fuzz no-panic |
| Backup | RFC 9180 `https://www.rfc-editor.org/rfc/rfc9180` | 2026-05-14 | неверный AAD и replay | `umbrella-backup` | закрыто тестом | backup AAD/replay tests |
| Sealed Sender | Signal specs `https://signal.org/docs/specifications/` | 2026-05-14 | replay к другому получателю, подмена подписи | `umbrella-sealed-sender` | закрыто тестом | sealed sender real attack tests |
| MLS | RFC 9420 `https://www.rfc-editor.org/rfc/rfc9420` | 2026-05-14 | downgrade и group-state inconsistency | `umbrella-mls` | закрыто тестом | MLS parser/group tests |
| SFrame | RFC 9605 `https://www.rfc-editor.org/rfc/rfc9605` | 2026-05-14 | tampered frame/header, nonce/key misuse | `umbrella-calls`, `umbrella-vectors` | закрыто тестом | SFrame vectors and parser tests |
| Устройства | W3C WebAuthn `https://www.w3.org/TR/webauthn-3/` | 2026-05-14 | rollback счётчика и mismatch ключа | `umbrella-platform-verifier` | закрыто тестом | WebAuthn tests |
| Устройства | Apple App Attest `https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server` | 2026-05-14 | fake attestation без Apple trust material | `umbrella-platform-verifier` | закрыто отказом | production verifier unavailable |
| Устройства | Android Play Integrity `https://developer.android.com/google/play/integrity` | 2026-05-14 | fake verdict без Google trust material | `umbrella-platform-verifier` | закрыто отказом | production verifier unavailable |
| Зависимости | RustSec `https://rustsec.org/advisories/` | 2026-05-14 | уязвимая зависимость | workspace | закрыто тестом | `scripts/audit-dependency-policy.sh` |
| Зависимости | cargo-deny `https://embarkstudios.github.io/cargo-deny/` | 2026-05-14 | обход политики зависимостей | workspace | закрыто тестом | `cargo deny check` |
| Зависимости | SLSA `https://slsa.dev/spec/v1.1/` | 2026-05-14 | ложная цепочка поставки | workspace | граница выпуска | SLSA используется как ориентир, уровень не заявляется |

## Обязательные границы

- `rust_1mlrd` не трогаем.
- Реальные Android/iOS устройства не трогаем.
- Серверная интеграция не входит в эту фазу.
- Публичный FFI/client bootstrap остаётся закрыт.
```

- [ ] **Step 4: Run the audit and confirm it passes**

Run:

```bash
bash scripts/audit-external-crypto-attack-ledger.sh
```

Expected: PASS with `external crypto attack ledger OK`.

- [ ] **Step 5: Wire the new audit into protocol gate audit**

In `scripts/audit-protocol-core-attack-gates.sh`, add before the final success echo:

```bash
require_pattern "docs/security/external-crypto-attack-ledger-2026-05-14.md" "RFC 9497"
require_pattern "docs/security/external-crypto-attack-ledger-2026-05-14.md" "KyberSlash"
require_pattern "docs/security/external-crypto-attack-ledger-2026-05-14.md" "граница выпуска"
bash scripts/audit-external-crypto-attack-ledger.sh
```

- [ ] **Step 6: Run gates**

Run:

```bash
bash scripts/audit-external-crypto-attack-ledger.sh
bash scripts/audit-protocol-core-attack-gates.sh
```

Expected: both PASS.

- [ ] **Step 7: Commit**

```bash
git add docs/security/external-crypto-attack-ledger-2026-05-14.md scripts/audit-external-crypto-attack-ledger.sh scripts/audit-protocol-core-attack-gates.sh
git commit -m "security: add external crypto attack ledger"
```

---

### Task 2: OPRF External Attack Pass

**Files:**
- Create: `crates/umbrella-oprf/tests/external_rfc9497_attacks.rs`
- Modify: `docs/security/external-crypto-attack-ledger-2026-05-14.md`
- Modify: `docs/security/protocol-core-attack-gates.md`

- [ ] **Step 1: Add RFC 9497 regression tests**

Create `crates/umbrella-oprf/tests/external_rfc9497_attacks.rs`:

```rust
use umbrella_oprf::{
    threshold_combine, BlindedRequest, OprfError, OprfInput, ServerEvaluation,
    ThresholdConfig, MAX_INPUT_BYTES,
};

#[test]
fn rfc9497_input_length_boundaries_are_fail_closed() {
    let empty = OprfInput::new(&[]).unwrap_err();
    assert!(matches!(empty, OprfError::EmptyInput));

    let too_large = vec![0x41; MAX_INPUT_BYTES + 1];
    let err = OprfInput::new(&too_large).unwrap_err();
    assert!(matches!(
        err,
        OprfError::InputTooLarge {
            got,
            max
        } if got == MAX_INPUT_BYTES + 1 && max == MAX_INPUT_BYTES
    ));

    let max = vec![0x42; MAX_INPUT_BYTES];
    OprfInput::new(&max).expect("max-size OPRF input must remain accepted");
}

#[test]
fn rfc9497_rejects_wrong_wire_lengths_and_bad_points() {
    let short = BlindedRequest::from_bytes(&[0u8; 31]).unwrap_err();
    assert!(matches!(
        short,
        OprfError::WrongWireLength {
            expected: 32,
            got: 31
        }
    ));

    let long = ServerEvaluation::from_bytes(&[0u8; 33]).unwrap_err();
    assert!(matches!(
        long,
        OprfError::WrongWireLength {
            expected: 32,
            got: 33
        }
    ));

    let bad_point = [0xFFu8; 32];
    assert!(matches!(
        BlindedRequest::from_bytes(&bad_point).unwrap_err(),
        OprfError::InvalidRistrettoEncoding
    ));
    assert!(matches!(
        ServerEvaluation::from_bytes(&bad_point).unwrap_err(),
        OprfError::InvalidRistrettoEncoding
    ));
}

#[test]
fn rfc9497_threshold_precheck_rejects_subthreshold_before_any_success() {
    let shares = heapless::Vec::<_, 8>::new();
    let err = threshold_combine(&shares, ThresholdConfig::default()).unwrap_err();
    assert!(matches!(
        err,
        OprfError::InsufficientValidEvaluations {
            valid: 0,
            required: 3
        }
    ));
}
```

- [ ] **Step 2: Run the new OPRF tests**

Run:

```bash
cargo test -p umbrella-oprf --test external_rfc9497_attacks --all-features --locked
```

Expected: PASS.

- [ ] **Step 3: Re-run existing OPRF attack gates**

Run:

```bash
cargo test -p umbrella-oprf --all-features --locked threshold_combine_rejects_duplicate_index
cargo test -p umbrella-oprf --all-features --locked threshold_tampered_share_breaks_combine
cargo test -p umbrella-oprf --all-features --locked production_context_rejects_replayed_server_nonce_after_first_success
```

Expected: all PASS.

- [ ] **Step 4: Update ledgers**

In `docs/security/external-crypto-attack-ledger-2026-05-14.md`, update the OPRF row proof to include:

```text
`crates/umbrella-oprf/tests/external_rfc9497_attacks.rs`
```

In `docs/security/protocol-core-attack-gates.md`, add an OPRF row:

```markdown
| OPRF | RFC 9497 wrong length, bad Ristretto point, empty/oversize input | закрыто тестом | `external_rfc9497_attacks.rs` |
```

- [ ] **Step 5: Run focused gates**

Run:

```bash
cargo test -p umbrella-oprf --test external_rfc9497_attacks --all-features --locked
bash scripts/audit-external-crypto-attack-ledger.sh
bash scripts/audit-protocol-core-attack-gates.sh
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbrella-oprf/tests/external_rfc9497_attacks.rs docs/security/external-crypto-attack-ledger-2026-05-14.md docs/security/protocol-core-attack-gates.md
git commit -m "oprf: add external rfc9497 attack gates"
```

---

### Task 3: KT External Split-View And Equivocation Pass

**Files:**
- Modify: `docs/security/external-crypto-attack-ledger-2026-05-14.md`
- Modify: `docs/security/protocol-core-attack-gates.md`
- Test existing: `crates/umbrella-kt/tests/phd_attacks.rs`
- Test existing: `crates/umbrella-kt/tests/split_view_exchange.rs`

- [ ] **Step 1: Re-run the local split-view and equivocation tests**

Run:

```bash
cargo test -p umbrella-kt --test phd_attacks threshold_compromised_views_can_verify_but_safety_numbers_diverge --all-features --locked
cargo test -p umbrella-kt --test split_view_exchange threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence --all-features --locked
cargo test -p umbrella-kt --test phd_attacks attack_replay_old_signed_epoch_blocked_by_monotonic_epoch_check --all-features --locked
cargo test -p umbrella-kt --test phd_attacks attack_canonical_sign_payload_binds_log_size_post_fix_f_phd_s68_1 --all-features --locked
```

Expected: all PASS.

- [ ] **Step 2: Update the KT ledger wording**

In `docs/security/external-crypto-attack-ledger-2026-05-14.md`, replace the KT proof text with:

```text
`threshold_compromised_views_can_verify_but_safety_numbers_diverge` proves local acceptance under malicious threshold; `threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence` proves local detection only after client observation exchange. Full prevention remains a release boundary for server-side gossip/self-monitoring/witness operations.
```

- [ ] **Step 3: Ensure public attack-gate wording stays honest**

In `docs/security/protocol-core-attack-gates.md`, ensure the KT split-view row contains:

```text
честная граница
```

and the client exchange row contains:

```text
локально закрыто обнаружение
```

- [ ] **Step 4: Run audits**

Run:

```bash
bash scripts/audit-external-crypto-attack-ledger.sh
bash scripts/audit-protocol-core-attack-gates.sh
```

Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
git add docs/security/external-crypto-attack-ledger-2026-05-14.md docs/security/protocol-core-attack-gates.md
git commit -m "kt: align external split view attack ledger"
```

---

### Task 4: TLS Pinning And Downgrade Pass

**Files:**
- Modify: `crates/umbrella-client/src/transport/http2_client.rs`
- Modify: `crates/umbrella-client/src/transport/pinning.rs`
- Modify: `docs/security/external-crypto-attack-ledger-2026-05-14.md`
- Modify: `docs/security/protocol-core-attack-gates.md`

- [ ] **Step 1: Run existing TLS/pinning attack tests**

Run:

```bash
cargo test -p umbrella-client production_transport_rejects_http_url --all-features --locked
cargo test -p umbrella-client production_transport_rejects_test_hosts --all-features --locked
cargo test -p umbrella-client production_transport_rejects_ip_literal_hosts --all-features --locked
cargo test -p umbrella-client matching_pin_does_not_bypass_inner_certificate_failure --all-features --locked
cargo test -p umbrella-client wrong_key_for_same_server_is_rejected_after_inner_accepts --all-features --locked
```

Expected: all PASS.

- [ ] **Step 2: Check whether IPv4-mapped IPv6 rejection already exists**

Run:

```bash
rg -n "::ffff:127\\.0\\.0\\.1|production_transport_rejects_ipv4_mapped_ipv6" crates/umbrella-client/src/transport
```

Expected: at least one match in `http2_client.rs`. If no match, add this test inside the existing `#[cfg(test)]` module in `crates/umbrella-client/src/transport/http2_client.rs`:

```rust
#[test]
fn production_transport_rejects_ipv4_mapped_ipv6_forbidden_hosts() {
    let urls = vec![
        "https://[::ffff:127.0.0.1]",
        "https://[::ffff:10.0.0.1]",
        "https://[::ffff:172.16.0.1]",
        "https://[::ffff:192.168.1.1]",
        "https://[::ffff:100.64.0.1]",
        "https://[::ffff:192.0.2.1]",
    ];

    for url in urls {
        let err = super::validate_production_base_url(url).unwrap_err();
        assert!(
            err.to_string().contains("forbidden") || err.to_string().contains("local"),
            "url {url} must be rejected, got {err}"
        );
    }
}
```

- [ ] **Step 3: Run the transport test package**

Run:

```bash
cargo test -p umbrella-client --all-features --locked transport
```

Expected: PASS.

- [ ] **Step 4: Update ledgers**

In `docs/security/external-crypto-attack-ledger-2026-05-14.md`, expand the TLS row proof with:

```text
`matching_pin_does_not_bypass_inner_certificate_failure`, `wrong_key_for_same_server_is_rejected_after_inner_accepts`, URL rejection tests in `http2_client.rs`
```

- [ ] **Step 5: Run audits**

Run:

```bash
bash scripts/audit-external-crypto-attack-ledger.sh
bash scripts/audit-protocol-core-attack-gates.sh
```

Expected: both PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbrella-client/src/transport/http2_client.rs docs/security/external-crypto-attack-ledger-2026-05-14.md docs/security/protocol-core-attack-gates.md
git commit -m "transport: align external tls pinning gates"
```

---

### Task 5: Post-Quantum And Dependency Advisory Pass

**Files:**
- Modify: `docs/security/external-crypto-attack-ledger-2026-05-14.md`
- Modify: `docs/audits/cargo-deny-policy.md`
- Test existing: `crates/umbrella-fuzz`
- Test existing: `scripts/audit-dependency-policy.sh`

- [ ] **Step 1: Run dependency policy**

Run:

```bash
bash scripts/audit-dependency-policy.sh
```

Expected: PASS. If it fails, use systematic debugging: read the advisory output, identify the dependency and advisory, then decide whether to upgrade, deny, or document a temporary release blocker.

- [ ] **Step 2: Run focused PQ parser/fuzz smoke**

Run:

```bash
bash scripts/run-fuzz-overnight.sh 30 ml_kem_decapsulate_fuzz hybrid_signature_parser xwing_ciphertext_parser xwing_pubkey_parser
```

Expected: each target prints `PASS (no crash in 30s)` and final `Failed: 0 / 4`.

- [ ] **Step 3: Record evidence path**

Run:

```bash
ls -td target/fuzz-overnight/* | head -1
```

Expected: newest directory path printed. Copy that path into `docs/security/external-crypto-attack-ledger-2026-05-14.md` in the PQ proof cell.

- [ ] **Step 4: Update cargo deny policy doc**

Append to `docs/audits/cargo-deny-policy.md`:

```markdown
## External PQ advisory pass, 2026-05-14

Checked against the external release-audit ledger:

- FIPS 203 / ML-KEM parameter and ciphertext handling is covered by PQ tests and `ml_kem_decapsulate_fuzz`.
- KyberSlash is tracked as a dependency/backend risk, not as a parser-only risk.
- `scripts/audit-dependency-policy.sh` remains the release gate for RustSec/cargo-deny advisories.
```

- [ ] **Step 5: Run checks**

Run:

```bash
bash scripts/audit-dependency-policy.sh
bash scripts/audit-external-crypto-attack-ledger.sh
```

Expected: both PASS.

- [ ] **Step 6: Commit**

```bash
git add docs/security/external-crypto-attack-ledger-2026-05-14.md docs/audits/cargo-deny-policy.md
git commit -m "security: record external pq advisory pass"
```

---

### Task 6: Backup And HPKE/AAD Pass

**Files:**
- Modify: `docs/security/external-crypto-attack-ledger-2026-05-14.md`
- Modify: `docs/security/protocol-core-attack-gates.md`
- Test existing: `crates/umbrella-backup`

- [ ] **Step 1: Run backup tamper and replay tests**

Run:

```bash
cargo test -p umbrella-backup --all-features --locked verify_rejects_tampered_chat_id
cargo test -p umbrella-backup --all-features --locked verify_rejects_tampered_recipient_device_pubkey
cargo test -p umbrella-backup --all-features --locked verify_rejects_tampered_timestamp
cargo test -p umbrella-backup --all-features --locked verify_rejects_tampered_token
cargo test -p umbrella-backup --all-features --locked verify_rejects_tampered_nonce
cargo test -p umbrella-backup --all-features --locked verify_rejects_wrong_device_pubkey
cargo test -p umbrella-backup --all-features --locked production_context_rejects_replayed_server_nonce_after_first_success
cargo test -p umbrella-backup --all-features --locked unwrap_fails_on_tampered_aad
cargo test -p umbrella-backup --all-features --locked v2_unwrap_rejects_tampered_canonical_aad
```

Expected: all PASS.

- [ ] **Step 2: Run V1/V2 mixed corpus tests**

Run:

```bash
cargo test -p umbrella-backup --test v1_v2_mixed_corpus --all-features --locked
```

Expected: PASS.

- [ ] **Step 3: Update ledgers**

In `docs/security/external-crypto-attack-ledger-2026-05-14.md`, expand the Backup row proof with:

```text
tamper tests in `cloud_wrap/signed_request.rs`, AAD tests in `cloud_wrap/unwrap.rs` and `cloud_wrap/pq_wrap.rs`, mixed V1/V2 corpus tests
```

- [ ] **Step 4: Run audits**

Run:

```bash
bash scripts/audit-external-crypto-attack-ledger.sh
bash scripts/audit-protocol-core-attack-gates.sh
```

Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
git add docs/security/external-crypto-attack-ledger-2026-05-14.md docs/security/protocol-core-attack-gates.md
git commit -m "backup: record external hpke aad attack gates"
```

---

### Task 7: Sealed Sender External Replay And Signature Pass

**Files:**
- Modify: `docs/security/external-crypto-attack-ledger-2026-05-14.md`
- Modify: `docs/security/protocol-core-attack-gates.md`
- Test existing: `crates/umbrella-sealed-sender`

- [ ] **Step 1: Run sealed sender real attack tests**

Run:

```bash
cargo test -p umbrella-sealed-sender --all-features --locked forged_inner_signature_rejected_after_successful_v2_decrypt
cargo test -p umbrella-sealed-sender --test phd_real_attacks_sealed_sender --all-features --locked real_attack_replay_envelope_to_different_recipient_aad_blocks
cargo test -p umbrella-sealed-sender --test phd_real_attacks_sealed_sender --all-features --locked real_attack_cross_version_replay_v1_to_v2_blocked
cargo test -p umbrella-sealed-sender --test phd_real_attacks_sealed_sender --all-features --locked real_fuzz_v2_unseal_100k_random_bytes_no_panic_no_silent_accept
```

Expected: all PASS.

- [ ] **Step 2: Update ledgers**

In `docs/security/external-crypto-attack-ledger-2026-05-14.md`, expand the Sealed Sender row proof with:

```text
forged inner signature test, cross-recipient replay test, cross-version replay test, random V2 unseal fuzz test
```

- [ ] **Step 3: Run audits**

Run:

```bash
bash scripts/audit-external-crypto-attack-ledger.sh
bash scripts/audit-protocol-core-attack-gates.sh
```

Expected: both PASS.

- [ ] **Step 4: Commit**

```bash
git add docs/security/external-crypto-attack-ledger-2026-05-14.md docs/security/protocol-core-attack-gates.md
git commit -m "sealed-sender: record external replay gates"
```

---

### Task 8: MLS, SFrame, And Calls Boundary Pass

**Files:**
- Modify: `docs/security/external-crypto-attack-ledger-2026-05-14.md`
- Modify: `docs/security/production-readiness-boundaries.md`
- Modify: `docs/security/current-status.md`
- Test existing: `crates/umbrella-mls`
- Test existing: `crates/umbrella-calls`
- Test existing: `crates/umbrella-vectors`

- [ ] **Step 1: Run focused MLS/SFrame/calls tests**

Run:

```bash
cargo test -p umbrella-mls --all-features --locked
cargo test -p umbrella-calls --all-features --locked
cargo test -p umbrella-vectors --all-features --locked
```

Expected: all PASS.

- [ ] **Step 2: Run SFrame fuzz smoke**

Run:

```bash
bash scripts/run-fuzz-overnight.sh 30 fuzz_sframe_header_parse fuzz_sframe_frame_parse
```

Expected: final `Failed: 0 / 2`.

- [ ] **Step 3: Update calls boundary**

In `docs/security/production-readiness-boundaries.md`, ensure there is a calls/SFrame boundary paragraph with this wording:

```markdown
### Calls and SFrame

Local Rust code checks parser safety, vectors and mode enforcement, but this is
not a real production calling proof. Real media transport, network behaviour,
device audio/video stacks and server relay deployment remain release
boundaries.
```

- [ ] **Step 4: Update ledgers**

In `docs/security/external-crypto-attack-ledger-2026-05-14.md`, expand MLS and SFrame proof cells with:

```text
focused Rust package tests plus SFrame fuzz smoke evidence under `target/fuzz-overnight/`
```

- [ ] **Step 5: Run audits**

Run:

```bash
bash scripts/audit-external-crypto-attack-ledger.sh
bash scripts/audit-public-access-notices.sh
```

Expected: both PASS.

- [ ] **Step 6: Commit**

```bash
git add docs/security/external-crypto-attack-ledger-2026-05-14.md docs/security/production-readiness-boundaries.md docs/security/current-status.md
git commit -m "calls: record external mls sframe boundaries"
```

---

### Task 9: Device Attestation And Public Bootstrap Pass

**Files:**
- Modify: `docs/security/external-crypto-attack-ledger-2026-05-14.md`
- Modify: `docs/security/current-status.md`
- Modify: `docs/security/production-readiness-boundaries.md`
- Test existing: `crates/umbrella-platform-verifier`
- Test existing: `crates/umbrella-oprf`
- Test existing: `crates/umbrella-backup`
- Test existing: `crates/umbrella-ffi`

- [ ] **Step 1: Run device verifier tests**

Run:

```bash
cargo test -p umbrella-platform-verifier --all-features --locked webauthn_rejects_counter_rollback
cargo test -p umbrella-platform-verifier --all-features --locked webauthn_rejects_context_device_key_not_registered_key
cargo test -p umbrella-oprf --all-features --locked production_policy_rejects_testing_attestation_even_after_valid_signature
cargo test -p umbrella-backup --all-features --locked production_policy_rejects_testing_attestation_even_after_valid_signature
```

Expected: all PASS.

- [ ] **Step 2: Run public FFI closed-boundary tests**

Run:

```bash
cargo test -p umbrella-ffi --all-features --locked
cargo test -p umbrella-ffi-swift --all-features --locked
cargo test -p umbrella-ffi-kotlin --all-features --locked
```

Expected: all PASS. If a mobile bridge package has no runnable tests on this host, record the exact Cargo output in the audit evidence and mark it as a host/tooling boundary, not as production readiness.

- [ ] **Step 3: Update ledgers and current status**

In `docs/security/external-crypto-attack-ledger-2026-05-14.md`, expand device rows with:

```text
WebAuthn local tests pass; Apple App Attest and Android Play Integrity remain closed until external trust material and server/mobile integration are wired.
```

In `docs/security/current-status.md`, ensure the “not production-ready yet” list still includes:

```markdown
- real Apple and Android token validation with external trust material;
- public device-certification matrix;
```

- [ ] **Step 4: Run audits**

Run:

```bash
bash scripts/audit-external-crypto-attack-ledger.sh
bash scripts/audit-public-access-notices.sh
```

Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
git add docs/security/external-crypto-attack-ledger-2026-05-14.md docs/security/current-status.md docs/security/production-readiness-boundaries.md
git commit -m "devices: record external attestation boundaries"
```

---

### Task 10: Final Release Evidence Run

**Files:**
- Create: `docs/audits/external-crypto-release-audit-status-2026-05-14.md`
- Modify: `docs/audits/local-release-hardening-status-2026-05-14.md`
- Modify: `docs/README.md`
- Modify: `README.md`

- [ ] **Step 1: Create evidence directory**

Run:

```bash
mkdir -p target/audit-evidence/external-crypto-release/20260514
```

Expected: directory exists.

- [ ] **Step 2: Run final short gates and save logs**

Run:

```bash
cargo fmt --all -- --check 2>&1 | tee target/audit-evidence/external-crypto-release/20260514/cargo-fmt.log
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings 2>&1 | tee target/audit-evidence/external-crypto-release/20260514/cargo-clippy.log
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked 2>&1 | tee target/audit-evidence/external-crypto-release/20260514/cargo-doc.log
cargo test --workspace --all-features --locked 2>&1 | tee target/audit-evidence/external-crypto-release/20260514/cargo-test.log
bash scripts/audit-external-crypto-attack-ledger.sh 2>&1 | tee target/audit-evidence/external-crypto-release/20260514/audit-external-ledger.log
bash scripts/audit-protocol-core-attack-gates.sh 2>&1 | tee target/audit-evidence/external-crypto-release/20260514/audit-protocol-core.log
bash scripts/audit-public-access-notices.sh 2>&1 | tee target/audit-evidence/external-crypto-release/20260514/audit-public-access.log
bash scripts/audit-dependency-policy.sh 2>&1 | tee target/audit-evidence/external-crypto-release/20260514/audit-dependency-policy.log
bash scripts/audit-local-release-hardening.sh 2>&1 | tee target/audit-evidence/external-crypto-release/20260514/audit-local-release-hardening.log
```

Expected: every command exits 0.

- [ ] **Step 3: Run Miri gate and save logs**

Run:

```bash
bash scripts/run-miri-local-gates.sh target/audit-evidence/external-crypto-release/20260514/miri-local
```

Expected: summary ends with `Miri local gates OK`.

- [ ] **Step 4: Run full fuzz gate**

Run:

```bash
bash scripts/run-fuzz-overnight.sh
```

Expected: final summary ends with `Failed: 0 / 27`. Copy the newest `target/fuzz-overnight/<timestamp>/summary.txt` path into the status doc. If it produces a slow-unit, reproduce it once and 1000 times before calling it a finding.

- [ ] **Step 5: Run formal gate**

Run:

```bash
bash scripts/verify-formal-production-readiness.sh 2>&1 | tee target/audit-evidence/external-crypto-release/20260514/formal-production-readiness.log
```

Expected: exit 0 if tools are present and models pass. If ProVerif or Tamarin is missing, record the exact missing-tool output as a release blocker or formal-tooling boundary.

- [ ] **Step 6: Create final status document**

Create `docs/audits/external-crypto-release-audit-status-2026-05-14.md`:

```markdown
# Внешний крипто-аудит Umbrella Protocol

Дата: 2026-05-14

## Итог

Этот документ фиксирует выпускной внешний крипто-аудит без `rust_1mlrd`, без
реальных Android/iOS устройств и без настоящей серверной интеграции.

## Главные доказательства

- Внешний реестр атак: `docs/security/external-crypto-attack-ledger-2026-05-14.md`.
- Матрица локальных атак: `docs/security/protocol-core-attack-gates.md`.
- Evidence: `target/audit-evidence/external-crypto-release/20260514/`.

## Что закрыто локально

- OPRF: входы, wire-форматы, replay, threshold checks, production fail-closed.
- KT: локальная подмена отклоняется; split-view обнаруживается при обмене наблюдениями.
- TLS/pinning: pin не обходит обычную проверку сертификата; плохие адреса отвергаются.
- PQ: fuzz и dependency gates закрывают локальные parser/advisory проверки.
- Backup: replay, AAD, V1/V2 смешение, tamper.
- Sealed Sender: replay, cross-version, forged signature, random bytes.
- MLS/SFrame/calls: локальные parser/vector/mode gates.
- Устройства: WebAuthn локально; Apple/Android закрыто отказывают без внешних корней доверия.
- Зависимости: RustSec/cargo-deny gate.

## Что осталось внешней границей

- настоящие серверы;
- настоящие Android/iOS устройства;
- настоящие Apple/Google trust roots и token validation;
- живые KT-свидетели, gossip/self-monitoring и операционное развёртывание;
- публичный FFI/client bootstrap;
- реальная нагрузка на миллион активных пользователей.

## Команды

Команды и журналы лежат в `target/audit-evidence/external-crypto-release/20260514/`.
```

- [ ] **Step 7: Link final status in index docs**

Add a bullet to `docs/README.md` and `README.md`:

```markdown
- External crypto release audit: `docs/audits/external-crypto-release-audit-status-2026-05-14.md`
```

- [ ] **Step 8: Run final documentation audits**

Run:

```bash
git diff --check
bash scripts/audit-external-crypto-attack-ledger.sh
bash scripts/audit-public-access-notices.sh
```

Expected: all PASS.

- [ ] **Step 9: Commit**

```bash
git add docs/audits/external-crypto-release-audit-status-2026-05-14.md docs/audits/local-release-hardening-status-2026-05-14.md docs/README.md README.md
git commit -m "docs: record external crypto release audit status"
```

---

## Plan Self-Review Completed

- [x] The plan covers every spec area: OPRF, KT, TLS, PQ, Backup, Sealed Sender, MLS/SFrame/calls, devices, dependencies, final evidence.
- [x] The plan preserves the boundaries: no `rust_1mlrd`, no real Android/iOS devices, no server integration.
- [x] Every implementation task has concrete files, commands and expected results.
- [x] Every final claim is backed by a test, audit script, fuzz/Miri/formal evidence, closed refusal or release boundary.
- [x] The long full fuzz run is required for final release evidence, not for every small iteration.

Gaps found during plan review: none.
