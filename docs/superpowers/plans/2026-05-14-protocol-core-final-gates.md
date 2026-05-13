# Protocol Core Final Gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** закрыть оставшиеся локально доказуемые боевые ворота ядра Umbrella Protocol, не открывая публичный FFI-клиент, не подключая сервер и не делая финальную проверку реальных Apple/Android устройств.

**Architecture:** фаза идёт маленькими итерациями: сначала закрываем путь, который выглядит боевым, но не имеет полной боевой связки; затем усиливаем аудиты, TLS/SPKI, KT, OPRF, backup, Sealed Sender, зависимости и документы. Любая защита либо доказывается атакующим тестом, либо остаётся закрытой границей выпуска.

**Tech Stack:** Rust workspace, Cargo locked gates, UniFFI, reqwest 0.13, rustls 0.23, rustls-platform-verifier 0.7, cargo-deny 0.19, Ed25519, X-Wing, OPRF Ristretto255, Markdown-документы на простом русском.

---

## File Structure

- Modify: `crates/umbrella-client/src/core.rs` — закрыть `ClientCore::new_with_http2`, который сейчас звучит как боевой путь, но не несёт SPKI pins и оставляет часть транспортов заглушками.
- Modify: `crates/umbrella-client/src/transport/http2_client.rs` — добавить точечный тест IPv4-mapped IPv6 и закрепить, что боевой builder остаётся только через `build_production_http2_client`.
- Modify: `crates/umbrella-sealed-sender/src/hybrid_envelope.rs` — добавить настоящий unit-тест подделанной внутренней подписи V2.
- Modify: `crates/umbrella-sealed-sender/tests/v2_envelope_roundtrip.rs` — убрать пустой тест с названием `forged_inner_signature_rejected`.
- Create: `scripts/audit-test-only-production-boundary.sh` — запретить тестовым и неполным путям выглядеть боевыми.
- Modify: `scripts/audit-protocol-core-attack-gates.sh` — расширить проверку матрицы атак на закрытый `new_with_http2`, KT log_size/timestamp, Backup AAD, Sealed Sender forged signature и TLS/SPKI.
- Modify: `scripts/audit-dependency-policy.sh` — запускать `cargo deny check`, так как инструмент установлен локально, и сохранять evidence.
- Modify: `scripts/audit-public-access-notices.sh` — требовать упоминание закрытого `new_with_http2` и новой проверки тестовых путей.
- Modify: `docs/security/protocol-core-attack-gates.md` — добавить строки по закрытому `new_with_http2`, KT log_size/timestamp, Backup AAD и реальному forged-signature тесту.
- Modify: `docs/security/current-status.md` — обновить статус финальных локальных ворот.
- Modify: `docs/security/production-readiness-boundaries.md` — описать закрытие неполного HTTP/2 bootstrap и границу реальных устройств.
- Modify: `docs/README.md`, `README.md` — добавить ссылку на новый аудит тестовых путей, если разделы аудитов уже есть.

---

### Task 1: Close Production-Looking HTTP/2 Bootstrap

**Files:**
- Modify: `crates/umbrella-client/src/core.rs`
- Test: `crates/umbrella-client/src/core.rs`

- [ ] **Step 1: Write the failing test**

Append this test module to the end of `crates/umbrella-client/src/core.rs`:

```rust
#[cfg(test)]
mod production_boundary_tests {
    use super::*;
    use rand_core::OsRng;
    use umbrella_identity::{IdentitySeed, MnemonicLanguage};

    fn production_shaped_config() -> ClientConfig {
        ClientConfig {
            sealed_server_urls: (0..5)
                .map(|idx| format!("https://sealed-{idx}.umbrella.example"))
                .collect(),
            postman_url: "https://postman.umbrella.example".to_string(),
            kt_url: "https://kt.umbrella.example".to_string(),
            call_relay_url: "https://relay.umbrella.example".to_string(),
            ..ClientConfig::default()
        }
    }

    fn test_seed() -> IdentitySeed {
        IdentitySeed::generate(&mut OsRng, MnemonicLanguage::English)
    }

    #[tokio::test]
    async fn new_with_http2_fails_closed_until_full_production_transport_is_wired() {
        let result = ClientCore::new_with_http2(production_shaped_config(), test_seed())
            .await;
        let err = match result {
            Ok(_) => panic!("new_with_http2 must fail closed until production transport is fully wired"),
            Err(err) => err,
        };
        let msg = err.to_string();

        assert!(
            msg.contains("production HTTP/2 bootstrap is closed"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("SPKI") && msg.contains("stubs"),
            "error must name missing SPKI/stub boundary: {msg}"
        );
    }
}
```

- [ ] **Step 2: Run the test and confirm the current bug**

Run:

```bash
cargo test -p umbrella-client new_with_http2_fails_closed_until_full_production_transport_is_wired --all-features --locked
```

Expected: FAIL because `ClientCore::new_with_http2` currently builds a partial client instead of returning the closed-boundary error.

- [ ] **Step 3: Replace the misleading body with a closed error**

In `crates/umbrella-client/src/core.rs`, replace the body of `ClientCore::new_with_http2` with:

```rust
    pub async fn new_with_http2(config: ClientConfig, seed: IdentitySeed) -> Result<Arc<Self>> {
        let _ = (config, seed);
        Err(ClientError::Network(
            "production HTTP/2 bootstrap is closed: ClientCore::new_with_http2 does not carry SPKI pins and still leaves postman/KT/call relay stubs; use only explicit test constructors until full production transport wiring exists"
                .to_string(),
        ))
    }
```

- [ ] **Step 4: Update the doc comment above `new_with_http2`**

Replace the current doc comment for `new_with_http2` with this wording:

```rust
    /// Закрытая граница неполного HTTP/2 bootstrap.
    ///
    /// Этот метод оставлен как fail-fast защита для старых внутренних вызовов:
    /// он не должен создавать клиент, пока конфигурация не несёт SPKI pins для
    /// всех сервисов и пока `postman`, `kt` и `call_relay` не переведены с
    /// заглушек на реальные `dyn`-транспорты.
    ///
    /// Closed boundary for incomplete HTTP/2 bootstrap.
    ///
    /// This method remains as a fail-fast guard for older internal callers. It
    /// must not create a client until the config carries SPKI pins for all
    /// services and `postman`, `kt`, and `call_relay` are moved from stubs to
    /// real `dyn` transports.
    ///
    /// # Ошибки / Errors
    ///
    /// Всегда возвращает [`ClientError::Network`] с понятной причиной закрытия.
```

- [ ] **Step 5: Run focused client tests**

Run:

```bash
cargo test -p umbrella-client new_with_http2_fails_closed_until_full_production_transport_is_wired --all-features --locked
cargo test -p umbrella-client --all-features --locked
```

Expected: both commands PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbrella-client/src/core.rs
git commit -m "client: close incomplete http2 bootstrap"
```

---

### Task 2: Add Audit for Test-Only Production Boundaries

**Files:**
- Create: `scripts/audit-test-only-production-boundary.sh`
- Modify: `scripts/audit-public-access-notices.sh`

- [ ] **Step 1: Create the audit script**

Create `scripts/audit-test-only-production-boundary.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

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
    echo "$file does not contain required boundary: $pattern" >&2
    failed=1
  fi
}

reject_pattern() {
  local file="$1"
  local pattern="$2"

  if [[ ! -f "$file" ]]; then
    echo "missing $file" >&2
    failed=1
    return
  fi

  if grep -Eqi "$pattern" "$file"; then
    echo "$file contains forbidden production-looking test path: $pattern" >&2
    failed=1
  fi
}

require_pattern "crates/umbrella-ffi/src/export/client.rs" "production_bootstrap_unavailable"
require_pattern "crates/umbrella-ffi/src/export/client.rs" "public FFI must not use test constructors"
require_pattern "crates/umbrella-client/src/core.rs" "production HTTP/2 bootstrap is closed"
require_pattern "crates/umbrella-client/src/core.rs" "does not carry SPKI pins"
require_pattern "crates/umbrella-client/src/core.rs" "postman/KT/call relay stubs"
require_pattern "docs/security/production-readiness-boundaries.md" "new_with_http2"
require_pattern "docs/security/current-status.md" "new_with_http2"
require_pattern "docs/security/protocol-core-attack-gates.md" "new_with_http2"

reject_pattern "crates/umbrella-client/src/core.rs" "production \\[`ClientCore::new_with_http2`\\]"
reject_pattern "crates/umbrella-client/src/core.rs" "production \\[`UmbrellaClient::bootstrap_for_test`\\]"

if [[ "$failed" -ne 0 ]]; then
  exit "$failed"
fi

echo "test-only production boundary OK"
```

- [ ] **Step 2: Make it executable**

Run:

```bash
chmod +x scripts/audit-test-only-production-boundary.sh
```

- [ ] **Step 3: Run it and record expected red state before docs**

Run:

```bash
bash scripts/audit-test-only-production-boundary.sh
```

Expected: FAIL until the docs in Task 7 mention `new_with_http2`. This is acceptable red evidence for the audit.

- [ ] **Step 4: Extend public notice audit**

In `scripts/audit-public-access-notices.sh`, add these checks near the other `production-readiness-boundaries.md` checks:

```bash
require_pattern "docs/security/production-readiness-boundaries.md" "new_with_http2"
require_pattern "docs/security/current-status.md" "new_with_http2"
require_pattern "docs/security/protocol-core-attack-gates.md" "new_with_http2"
```

- [ ] **Step 5: Commit after docs Task 7 passes**

Do not commit this task alone while the new audit is red. Commit it together with Task 7 docs:

```bash
git add scripts/audit-test-only-production-boundary.sh scripts/audit-public-access-notices.sh docs/security/current-status.md docs/security/production-readiness-boundaries.md docs/security/protocol-core-attack-gates.md
git commit -m "security: audit test-only production boundaries"
```

---

### Task 3: Strengthen TLS/SPKI Transport Gates

**Files:**
- Modify: `crates/umbrella-client/src/transport/http2_client.rs`
- Modify: `scripts/audit-protocol-core-attack-gates.sh`

- [ ] **Step 1: Add IPv4-mapped IPv6 regression test**

In `crates/umbrella-client/src/transport/http2_client.rs`, inside the existing test module after `production_transport_rejects_ipv6_local_hosts`, add:

```rust
    #[test]
    fn production_transport_rejects_ipv4_mapped_ipv6_forbidden_hosts() {
        for url in [
            "https://[::ffff:127.0.0.1]",
            "https://[::ffff:10.0.0.1]",
            "https://[::ffff:100.64.0.10]",
            "https://[::ffff:192.0.2.10]",
        ] {
            let cfg = production_config_with_urls(vec![
                url,
                "https://sealed-1.umbrella.example",
                "https://sealed-2.umbrella.example",
                "https://sealed-3.umbrella.example",
                "https://sealed-4.umbrella.example",
            ]);

            let err = cfg.validate().unwrap_err();
            assert!(
                format!("{err}").contains("test host"),
                "{url} must be rejected, got {err}"
            );
        }
    }
```

- [ ] **Step 2: Run focused transport tests**

Run:

```bash
cargo test -p umbrella-client production_transport_rejects_ipv4_mapped_ipv6_forbidden_hosts --all-features --locked
cargo test -p umbrella-client production_client_builds_with_real_pinning_verifier --all-features --locked
cargo test -p umbrella-client matching_pin_does_not_bypass_inner_certificate_failure --all-features --locked
```

Expected: all PASS. If the first test fails, the root cause is `mapped_ipv4_from_v6` not being applied correctly; fix only that helper.

- [ ] **Step 3: Extend protocol gate audit**

In `scripts/audit-protocol-core-attack-gates.sh`, add:

```bash
require_pattern "crates/umbrella-client/src/transport/http2_client.rs" "::ffff:127\\.0\\.0\\.1"
require_pattern "crates/umbrella-client/src/transport/http2_client.rs" "production_client_builds_with_real_pinning_verifier"
require_pattern "crates/umbrella-client/src/transport/pinning.rs" "matching_pin_does_not_bypass_inner_certificate_failure"
require_pattern "crates/umbrella-client/src/transport/pinning.rs" "wrong_key_for_same_server_is_rejected_after_inner_accepts"
```

- [ ] **Step 4: Run focused client and audit checks**

Run:

```bash
cargo test -p umbrella-client --all-features --locked
bash scripts/audit-protocol-core-attack-gates.sh
```

Expected: both PASS after Task 7 docs are updated.

- [ ] **Step 5: Commit**

```bash
git add crates/umbrella-client/src/transport/http2_client.rs scripts/audit-protocol-core-attack-gates.sh
git commit -m "client: harden mapped ipv6 transport gate"
```

---

### Task 4: Expand KT, OPRF, and Backup Proof Matrix

**Files:**
- Modify: `scripts/audit-protocol-core-attack-gates.sh`
- Modify: `docs/security/protocol-core-attack-gates.md`

- [ ] **Step 1: Extend the audit with existing real attack names**

In `scripts/audit-protocol-core-attack-gates.sh`, add:

```bash
require_pattern "crates/umbrella-kt/tests/phd_attacks.rs" "attack_canonical_sign_payload_binds_log_size_post_fix_f_phd_s68_1"
require_pattern "crates/umbrella-kt/tests/phd_attacks.rs" "attack_replay_old_signed_epoch_blocked_by_monotonic_epoch_check"
require_pattern "crates/umbrella-backup/src/cloud_wrap/unwrap.rs" "unwrap_fails_on_tampered_aad"
require_pattern "crates/umbrella-backup/src/cloud_wrap/pq_wrap.rs" "v2_unwrap_rejects_tampered_canonical_aad"
require_pattern "crates/umbrella-oprf/src/threshold.rs" "threshold_combine_rejects_duplicate_index"
require_pattern "crates/umbrella-oprf/src/threshold.rs" "threshold_tampered_share_breaks_combine"
```

- [ ] **Step 2: Run audit to expose any missing exact names**

Run:

```bash
bash scripts/audit-protocol-core-attack-gates.sh
```

Expected: if a test name differs, FAIL names the missing pattern. Investigate with:

```bash
rg -n "duplicate|tampered|canonical_sign_payload|tampered_aad" crates/umbrella-kt crates/umbrella-oprf crates/umbrella-backup
```

Use the exact existing test name if the test is real. In the current tree the
duplicate witness test is `threshold_combine_rejects_duplicate_index`.

- [ ] **Step 3: Run focused tests**

Run:

```bash
cargo test -p umbrella-kt attack_canonical_sign_payload_binds_log_size_post_fix_f_phd_s68_1 --all-features --locked
cargo test -p umbrella-kt attack_replay_old_signed_epoch_blocked_by_monotonic_epoch_check --all-features --locked
cargo test -p umbrella-backup unwrap_fails_on_tampered_aad --all-features --locked
cargo test -p umbrella-backup v2_unwrap_rejects_tampered_canonical_aad --all-features --locked
cargo test -p umbrella-oprf threshold_combine_rejects_duplicate_index --all-features --locked
```

Expected: all listed commands PASS. If a command has no matching test, update the audit to the exact real test name only after reading the test body and confirming it performs the attack.

- [ ] **Step 4: Commit**

```bash
git add scripts/audit-protocol-core-attack-gates.sh docs/security/protocol-core-attack-gates.md
git commit -m "security: expand protocol attack evidence"
```

---

### Task 5: Replace Empty Sealed Sender Forged-Signature Test

**Files:**
- Modify: `crates/umbrella-sealed-sender/src/hybrid_envelope.rs`
- Modify: `crates/umbrella-sealed-sender/tests/v2_envelope_roundtrip.rs`
- Modify: `scripts/audit-protocol-core-attack-gates.sh`

- [ ] **Step 1: Confirm the current inert test**

Run:

```bash
sed -n '207,234p' crates/umbrella-sealed-sender/tests/v2_envelope_roundtrip.rs
```

Expected: the test named `forged_inner_signature_rejected` only binds variables and does not call `unseal_v2`.

- [ ] **Step 2: Add the real unit test where private helpers are available**

In `crates/umbrella-sealed-sender/src/hybrid_envelope.rs`, inside `#[cfg(test)] mod tests`, add this test after `wrong_recipient_seed_cannot_unseal_v2`:

```rust
    #[test]
    fn forged_inner_signature_rejected_after_successful_v2_decrypt() {
        let alice = fresh_keystore();
        let eve = fresh_keystore();
        let bob = fresh_keystore();
        let (bob_xwing_pk, bob_xwing_sk) = fresh_xwing_keypair();
        let mut rng = OsRng;
        let message = b"forged-inner-signature";

        let (xwing_ct, shared_secret) =
            xwing_encaps(&mut rng, &bob_xwing_pk).expect("xwing encaps");
        let (aead_key, aead_nonce) =
            derive_v2_keys(&shared_secret, &xwing_ct, &bob_xwing_pk).expect("v2 keys");

        let payload = signature_payload_v2(&xwing_ct, message);
        let eve_signature = eve.sign_with_identity(&payload);

        let mut inner = Vec::with_capacity(INNER_HEADER_LEN + message.len());
        inner.extend_from_slice(&alice.identity_public().to_bytes());
        inner.extend_from_slice(&eve_signature.to_bytes());
        inner.extend_from_slice(message);

        let padded = pad_to_bucket(&inner).expect("pad forged inner");
        let ad = aead_ad_v2(&xwing_ct, &bob_xwing_pk);
        let inner_ct = aead_key
            .encrypt(&aead_nonce, &ad, &padded)
            .expect("encrypt forged inner");

        let mut wire = Vec::with_capacity(VERSION_LEN + XWING_CIPHERTEXT_LEN + inner_ct.len());
        wire.push(SealedSenderVersion::V2HybridXWing.as_u8());
        wire.extend_from_slice(&xwing_ct);
        wire.extend_from_slice(&inner_ct);

        let err = unseal_v2(bob.as_ref(), &bob_xwing_pk, &bob_xwing_sk, &wire).unwrap_err();
        assert!(matches!(err, SealedSenderError::InvalidSignature));
    }
```

- [ ] **Step 3: Remove the inert integration test**

Delete the whole `forged_inner_signature_rejected` test from `crates/umbrella-sealed-sender/tests/v2_envelope_roundtrip.rs` lines 207-234. The real test now lives in `hybrid_envelope.rs`, where private construction helpers are available.

- [ ] **Step 4: Update protocol audit**

In `scripts/audit-protocol-core-attack-gates.sh`, add:

```bash
require_pattern "crates/umbrella-sealed-sender/src/hybrid_envelope.rs" "forged_inner_signature_rejected_after_successful_v2_decrypt"
require_pattern "crates/umbrella-sealed-sender/tests/phd_real_attacks_sealed_sender.rs" "real_fuzz_v2_unseal_100k_random_bytes_no_panic_no_silent_accept"
require_pattern "crates/umbrella-sealed-sender/tests/phd_real_attacks_sealed_sender.rs" "real_attack_replay_envelope_to_different_recipient_aad_blocks"
```

- [ ] **Step 5: Run focused Sealed Sender checks**

Run:

```bash
cargo test -p umbrella-sealed-sender forged_inner_signature_rejected_after_successful_v2_decrypt --all-features --locked
cargo test -p umbrella-sealed-sender v2_envelope_roundtrip --all-features --locked
bash scripts/audit-protocol-core-attack-gates.sh
```

Expected: all PASS after Task 7 docs are updated.

- [ ] **Step 6: Commit**

```bash
git add crates/umbrella-sealed-sender/src/hybrid_envelope.rs crates/umbrella-sealed-sender/tests/v2_envelope_roundtrip.rs scripts/audit-protocol-core-attack-gates.sh
git commit -m "sealed-sender: verify forged v2 signature"
```

---

### Task 6: Make Dependency Gate Real Locally

**Files:**
- Modify: `scripts/audit-dependency-policy.sh`
- Modify: `docs/audits/cargo-deny-policy.md`

- [ ] **Step 1: Replace the script with bincode plus cargo-deny checks**

Replace `scripts/audit-dependency-policy.sh` with:

```bash
#!/usr/bin/env bash
set -euo pipefail

evidence_dir="${1:-target/audit-evidence}"
mkdir -p "$evidence_dir"

tree_file="$evidence_dir/bincode-tree.txt"
cargo tree -e normal -i bincode >"$tree_file" 2>&1 || true

if grep -q "bincode v" "$tree_file"; then
  echo "bincode remains in normal dependency tree" >&2
  cat "$tree_file" >&2
  exit 1
fi

echo "bincode absent from normal dependency tree"

deny_file="$evidence_dir/cargo-deny-check.txt"
if ! command -v cargo-deny >/dev/null 2>&1; then
  echo "cargo-deny is required for the local release gate" | tee "$deny_file" >&2
  exit 1
fi

cargo deny check >"$deny_file" 2>&1
echo "cargo-deny check OK"
```

- [ ] **Step 2: Run dependency gate**

Run:

```bash
bash scripts/audit-dependency-policy.sh
```

Expected: PASS and evidence files under `target/audit-evidence/`.

- [ ] **Step 3: Update cargo-deny policy document**

In `docs/audits/cargo-deny-policy.md`, add this short Russian note under the Russian command section:

```markdown
Локальные ворота выпуска теперь запускают `bash scripts/audit-dependency-policy.sh`.
Скрипт проверяет, что `bincode` не попал в обычное дерево зависимостей, и
запускает `cargo deny check`. Если `cargo-deny` не установлен, это считается
отказом ворот, а не успешной проверкой.
```

- [ ] **Step 4: Commit**

```bash
git add scripts/audit-dependency-policy.sh docs/audits/cargo-deny-policy.md
git commit -m "security: enforce local dependency gate"
```

---

### Task 7: Update Security Documents

**Files:**
- Modify: `docs/security/protocol-core-attack-gates.md`
- Modify: `docs/security/current-status.md`
- Modify: `docs/security/production-readiness-boundaries.md`
- Modify: `README.md`
- Modify: `docs/README.md`

- [ ] **Step 1: Update attack matrix rows**

In `docs/security/protocol-core-attack-gates.md`, add or update these Russian rows:

```markdown
| Клиентский запуск | `ClientCore::new_with_http2` выглядит боевым, но не несёт SPKI pins и оставляет часть транспортов заглушками | закрыто отказом | `new_with_http2_fails_closed_until_full_production_transport_is_wired` |
| Транспорт | IPv4-mapped IPv6 ведёт на локальный, частный, CGNAT или документационный адрес | закрыто тестом | `production_transport_rejects_ipv4_mapped_ipv6_forbidden_hosts` |
| KT | подмена размера журнала или времени подписи свидетеля | закрыто тестом | `attack_canonical_sign_payload_binds_log_size_post_fix_f_phd_s68_1` |
| KT | повтор старой подписанной эпохи | закрыто тестом | `attack_replay_old_signed_epoch_blocked_by_monotonic_epoch_check` |
| OPRF | повтор witness index или подмена доли | закрыто тестом | `threshold_rejects_duplicate_witness_index`, `threshold_tampered_share_breaks_combine` |
| Backup | неверный AAD в V1/V2 развёртке | закрыто тестом | `unwrap_fails_on_tampered_aad`, `v2_unwrap_rejects_tampered_canonical_aad` |
| Sealed Sender | подделанная внутренняя подпись V2 после успешного расшифрования | закрыто тестом | `forged_inner_signature_rejected_after_successful_v2_decrypt` |
| Зависимости | опасная зависимость или cargo-deny policy обходятся локально | закрыто воротами | `scripts/audit-dependency-policy.sh` |
```

- [ ] **Step 2: Update current status**

In `docs/security/current-status.md`, under “Implemented and currently documented”, add:

```markdown
- incomplete `ClientCore::new_with_http2` bootstrap is fail-closed because it
  does not carry SPKI pins for every service and still leaves some transports
  on local stubs;
- local dependency release gate runs `cargo deny check` and rejects missing
  `cargo-deny` as a gate failure;
```

In the Russian section, add:

```markdown
- неполный `ClientCore::new_with_http2` закрыто отказывает, потому что он не
  несёт SPKI-ключи для всех сервисов и всё ещё оставляет часть транспортов на
  местных заглушках;
- локальные ворота зависимостей запускают `cargo deny check`; отсутствие
  `cargo-deny` считается отказом ворот, а не успехом;
```

- [ ] **Step 3: Update production readiness boundaries**

In `docs/security/production-readiness-boundaries.md`, under closed gates, add:

```markdown
- Incomplete HTTP/2 bootstrap: `ClientCore::new_with_http2` fails closed until
  the full production config carries SPKI pins for every service and replaces
  postman, KT, and call relay stubs with real transports.
```

In the Russian section, add:

```markdown
- Неполный HTTP/2 bootstrap: `ClientCore::new_with_http2` закрыто отказывает,
  пока полная боевая настройка не несёт SPKI-ключи для каждого сервиса и пока
  postman, KT и call relay не заменены с заглушек на реальные транспорты.
```

- [ ] **Step 4: Add audit script links**

If `README.md` and `docs/README.md` already list security scripts, add:

```markdown
- `scripts/audit-test-only-production-boundary.sh` — checks that test-only and
  incomplete paths do not look like production paths.
```

Russian wording:

```markdown
- `scripts/audit-test-only-production-boundary.sh` — проверяет, что тестовые и
  неполные пути не выглядят боевыми.
```

- [ ] **Step 5: Run docs audits**

Run:

```bash
bash scripts/audit-test-only-production-boundary.sh
bash scripts/audit-protocol-core-attack-gates.sh
bash scripts/audit-public-access-notices.sh
```

Expected: all PASS.

- [ ] **Step 6: Commit**

If Task 2 was not committed yet, include its scripts in this commit:

```bash
git add docs/security/protocol-core-attack-gates.md docs/security/current-status.md docs/security/production-readiness-boundaries.md README.md docs/README.md scripts/audit-test-only-production-boundary.sh scripts/audit-public-access-notices.sh
git commit -m "docs: update final protocol gates"
```

---

### Task 8: Final Verification Gates

**Files:**
- No code changes unless a gate exposes a root cause.

- [ ] **Step 1: Run focused package gates**

Run:

```bash
cargo test -p umbrella-client --all-features --locked
cargo test -p umbrella-kt --all-features --locked
cargo test -p umbrella-oprf --all-features --locked
cargo test -p umbrella-backup --all-features --locked
cargo test -p umbrella-sealed-sender --all-features --locked
```

Expected: all PASS.

- [ ] **Step 2: Run audit gates**

Run:

```bash
bash scripts/audit-test-only-production-boundary.sh
bash scripts/audit-protocol-core-attack-gates.sh
bash scripts/audit-public-access-notices.sh
bash scripts/audit-dependency-policy.sh
```

Expected: all PASS.

- [ ] **Step 3: Run full Rust gates**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
cargo test --workspace --all-features --locked
```

Expected: all PASS. If any command fails, follow `superpowers:systematic-debugging`: read the error, reproduce the smallest failing command, find the root cause, write or update the failing test, fix one cause, rerun the exact command.

- [ ] **Step 4: Verify clean tree**

Run:

```bash
git status --short
```

Expected: no output.

If final verification requires a documentation note, commit it:

```bash
git add docs/security/current-status.md docs/security/production-readiness-boundaries.md docs/security/protocol-core-attack-gates.md
git commit -m "docs: record final protocol gate verification"
```

---

## Self-Review Checklist

- Spec coverage: every area in `2026-05-14-protocol-core-final-gates-design.md` maps to a task above.
- Test-only boundary: Task 1 and Task 2 close the misleading HTTP/2 constructor and add an audit.
- TLS/SPKI: Task 3 extends mapped IPv6 coverage and audit checks around real pinning.
- KT: Task 4 binds matrix/audit to root, epoch, log size, timestamp, replay and split-view truth.
- OPRF: Task 4 verifies duplicate witness and tampered-share evidence.
- Backup: Task 4 verifies AAD and V1/V2 evidence.
- Sealed Sender: Task 5 replaces an inert test with a real forged-signature attack.
- Dependencies: Task 6 makes `cargo deny check` part of the local gate.
- Docs and final gates: Task 7 and Task 8 update documents and run full verification.
