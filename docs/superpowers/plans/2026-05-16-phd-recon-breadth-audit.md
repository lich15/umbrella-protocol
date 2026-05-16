# PhD-style Recon-Breadth Security Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run a recon-breadth active red-team audit across the 21 Umbrella
Protocol crates from a D-level state adversary mindset, surfacing blind spots
beyond the existing protocol-core attack ledger, and closing every confirmed
finding with an attack test, a fix, a ledger row, and an audit-report entry.

**Architecture:** Macro-task per crate (Tier 1 deep, Tier 2 medium,
Tier 3 boundary, Tier 4 sanity). Each crate task walks a fixed 20-category
hypothesis matrix and uses a single shared per-finding workflow (failing
attack test → root-cause fix → ledger row → report entry → commit). Stop
condition at 60% context budget with handoff.

**Tech Stack:** Rust workspace (`cargo`, `cargo test`, `cargo clippy`,
`cargo fmt`, `cargo deny`), `bash scripts/audit-*` gate scripts, `git`
direct-to-branch commits on `codex/phd-security-audit`.

**Spec reference:** `docs/superpowers/specs/2026-05-16-phd-recon-breadth-audit-design.md`
(commit `4c67f172`).

---

## Shared per-finding workflow (referenced by every Tier 1-3 task)

When a hypothesis is confirmed during a crate task, run this loop. Do NOT
skip steps even if the fix feels obvious.

1. **Name the attack.** Pick a test name in the form
   `attack_<class>_<specific>_<crate>` — adversarial naming, not behavioral.
   Example: `attack_serde_unbounded_vec_blows_memory_in_blind_postman_parser`.
2. **Write the failing test.** Place in `crates/<crate>/tests/` if integration,
   `crates/<crate>/src/<module>/tests/` if unit. The test MUST exercise the
   actual attacker path end to end (build malicious input → call public API →
   assert security property holds).
3. **Run the test and confirm it fails for the right reason.**
   `cargo test -p <crate> --all-features --locked -- attack_<name>`. Read the
   failure mode. If it fails because of a panic in a different place, refine.
4. **Implement the minimal fix.** Touch only what closes the root cause.
   No "while I'm here" cleanups. One variable at a time.
5. **Run the targeted test plus the full crate suite.**
   - `cargo test -p <crate> --all-features --locked -- attack_<name>` → PASS
   - `cargo test -p <crate> --all-features --locked` → PASS (no regression)
6. **Run formatting and lints.**
   - `cargo fmt --all -- --check`
   - `cargo clippy -p <crate> --all-targets --all-features --locked -- -D warnings`
7. **If a release-critical path was touched, run the workspace gate.**
   `cargo test --workspace --all-features --locked`.
8. **Add a row to the ledger.**
   - Local closed-by-test attacks → `docs/security/protocol-core-attack-gates.md`
     (both Russian and English mirror sections). Use the existing table format:
     `| Area | Attack | Status | Proof |`.
   - External-research-driven attacks → append a row to
     `docs/security/external-crypto-attack-ledger-2026-05-15.md` OR create
     `docs/security/external-crypto-attack-ledger-2026-05-16.md` if the
     external source is new.
9. **Run the ledger consistency script.**
   `bash scripts/audit-protocol-core-attack-gates.sh`. It must pass.
10. **Append a row to the audit report.**
    `docs/audits/security-hardening-audit-2026-05-16.md` in the
    `## Что было найдено и исправлено` table (Area / In plain words / What was
    done). Mirror in the English section.
11. **Commit the block.** Direct commit on the current branch
    (`codex/phd-security-audit`). Use HEREDOC and the `Co-Authored-By` trailer:

    ```bash
    git add <touched files>
    git commit -m "$(cat <<'EOF'
    <area>: close <attack name short>

    <2-3 sentence explanation: what the attacker did, what now stops them>

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    EOF
    )"
    ```

12. **Run the 6-question PhD-vs-A self-check on the commit (mental).** Per
    `feedback_phd_vs_a_level_distinguisher`: was the test name adversarial?
    Is the fix at root cause? Is the ledger row honest? Is the report row
    honest? Did I claim PhD level (NO — recon-breadth, A-level per finding)?
    Is severity tagged per §7a of the spec?
13. **If the finding is Critical severity (§7a),** stop the scan immediately,
    record it at the top of the report, then resume after the fix is
    committed.

---

## Shared 20-category hypothesis matrix (referenced by every Tier 1-3 task)

Apply this list to each crate. Per category, sketch 1-3 specific hypotheses
relevant to that crate's responsibilities. If the crate clearly has no
surface for a category (for example, no parser → no recursion attack),
record "n/a" in the task notes and move on. If 3+ hypotheses in one category
all fail, move to the next category (do not pile fixes).

1. Cross-crate state-machine confusion (callers in inconsistent state).
2. Integer overflow / arithmetic edge cases (`usize`, durations, lengths).
3. Panic paths as DoS (`unwrap`, `expect`, indexing on untrusted input).
4. Error-message information leak (`Display`, error variants).
5. Deserialization DoS (allocations, recursion, mempool).
6. Race conditions outside replay (signing oracles, two-phase operations).
7. FFI memory safety (UB on Swift/Kotlin, ABI mismatch, length/capacity).
8. Error-handling fail-open (`Err` arms returning `Ok`, `continue` skipping
   verification).
9. Constant-time violations beyond MAC/eq (HashMap, branchy code on secrets).
10. Log/Debug paths missed by 2026-05-15 redaction pass.
11. Domain-separation collisions (HKDF labels, hash prefixes, context tags).
12. KDF context mistakes (salt reuse, info collisions across schemes).
13. Algorithm-agility version confusion (future bytes, feature-flag versioning,
    fall-through arms).
14. RNG fallback to non-CSPRNG; partially seeded generators.
15. TOCTOU on config, nonce, or policy checks.
16. Zeroize gaps in intermediate buffers (Vec growth, BytesMut realloc,
    panic-unwind paths).
17. Serde untrusted-bound bypass (no length cap, unbounded `Vec<T>`, recursive
    `Option<Box<...>>`).
18. Stack overflow via recursive parsers.
19. Allocator-timing oracles.
20. Floating-point edge cases (subnormals, NaN) — scan only where applicable.

---

## Shared stop-check (run at the start of EVERY task)

Before starting a task:

- [ ] **Stop-check 1: Context budget.** If session context utilisation is
      approaching 60% (memory: `feedback_context_60pct`), STOP. Create
      `docs/audits/security-hardening-audit-2026-05-16-handoff-N.md` listing:
      completed crates, in-flight hypothesis, open categories per remaining
      tier, and the next task ID to resume. Commit the handoff and stop.
- [ ] **Stop-check 2: 3+ failed hypotheses in one category.** Per the
      systematic-debugging Phase 4.5 escalation: do not pile fixes, move to
      the next category and note the failure pattern in the report.
- [ ] **Stop-check 3: Critical finding outstanding.** If a Critical (§7a)
      finding is in flight, finish it before starting a new task.

---

## Task 0: Setup audit report skeleton

**Files:**
- Create: `docs/audits/security-hardening-audit-2026-05-16.md`

- [ ] **Step 1: Verify branch and clean tree.**

  ```bash
  git branch --show-current
  git status
  ```

  Expected: branch `codex/phd-security-audit`, tree clean (the spec commit
  `4c67f172` is in).

- [ ] **Step 2: Create the report skeleton.** Use the structure of
      `docs/audits/security-hardening-audit-2026-05-15.md` as the template.

  Write file `docs/audits/security-hardening-audit-2026-05-16.md` with:

  ```markdown
  # Аудит безопасности и усиление, 2026-05-16

  Этот документ фиксирует свежую recon-breadth итерацию активной красной
  команды: я прошёл по 21 крейту Umbrella Protocol с моделью угроз
  адверсария уровня D из SPEC-01 §4 (полный сетевой MITM, частичная
  компрометация инфры, HSM-стенды, длительный пассивный сбор), искал
  пробелы вне существующего реестра боевых атак и закрывал каждую
  подтверждённую находку failing-then-passing атакующим тестом,
  минимальным исправлением, строкой в реестре и записью в этом отчёте.

  Это не заявление "невозможно взломать". Это запись о том, что закрыто
  локально кодом, тестами и скриптами в рамках одного раунда A-level
  rigor per finding с PhD-style adversary mindset. Реальные серверы,
  настоящие Android/iOS-устройства, внешний формальный прогон, длинный
  ночной fuzz и независимый аудит остаются обязательными выпускными
  границами.

  Базовое описание раунда: `docs/superpowers/specs/2026-05-16-phd-recon-breadth-audit-design.md`.

  ## Что было найдено и исправлено

  | Область | Дыра простыми словами | Что сделано |
  |---|---|---|
  | _placeholder — заполнится по ходу_ | | |

  ## Critical findings (если есть)

  _Раздел заполняется при появлении Critical-серьёзности по §7а спецификации._

  ## Новые реальные проверки

  _Список новых attack-тестов с краткими описаниями._

  ## Что прошло локально

  _Список cargo/script команд с результатами._

  ## Что не закрыто этой итерацией

  - настоящие Android/iOS-устройства и их platform attestation;
  - настоящее серверное развёртывание;
  - живой KT gossip между независимыми свидетелями и клиентами;
  - длинный ночной fuzz перед выпуском в чистом окружении;
  - свежий внешний формальный прогон и независимый ручной аудит.

  ## English mirror

  _Параллельная English секция (заполняется в конце раунда либо по ходу
  per finding)._
  ```

- [ ] **Step 3: Commit the skeleton.**

  ```bash
  git add docs/audits/security-hardening-audit-2026-05-16.md
  git commit -m "$(cat <<'EOF'
  docs: open 2026-05-16 phd recon-breadth audit report

  Skeleton for the recon-breadth round defined in
  docs/superpowers/specs/2026-05-16-phd-recon-breadth-audit-design.md. Per
  the spec, findings get appended row-by-row as Tier 1-3 crates are walked.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  EOF
  )"
  ```

- [ ] **Step 4: Confirm the existing audit gate scripts work on this branch.**

  ```bash
  bash scripts/audit-protocol-core-attack-gates.sh
  ```

  Expected: pass (no rows changed yet).

---

## Task 1: Tier 1 — umbrella-identity

**Files:**
- Read: `crates/umbrella-identity/src/lib.rs`,
        `crates/umbrella-identity/src/identity_key.rs`,
        `crates/umbrella-identity/src/device_key.rs`,
        `crates/umbrella-identity/src/derive.rs`,
        `crates/umbrella-identity/src/seed.rs`,
        `crates/umbrella-identity/src/code_recovery.rs`,
        `crates/umbrella-identity/src/path.rs`,
        `crates/umbrella-identity/src/keystore.rs`,
        `crates/umbrella-identity/src/attestation.rs`,
        `crates/umbrella-identity/src/cloud_wrap_recovery.rs`,
        `crates/umbrella-identity/src/hybrid_device_key.rs`,
        `crates/umbrella-identity/src/hybrid_identity.rs`,
        `crates/umbrella-identity/src/slh_dsa_backup.rs`,
        `crates/umbrella-identity/src/identity_x25519.rs`,
        `crates/umbrella-identity/src/error.rs`
- Read: `crates/umbrella-identity/tests/test_active_audit_phd.rs`,
        `crates/umbrella-identity/tests/slh_dsa_backup_recovery.rs`,
        `crates/umbrella-identity/tests/hybrid_identity_roundtrip.rs`
- Per finding: create test in `crates/umbrella-identity/tests/attack_*.rs`
        (or extend an existing `tests/test_active_audit_phd.rs` if related)
- Per finding: code fix in the relevant `crates/umbrella-identity/src/<mod>.rs`
- Per finding: ledger row in `docs/security/protocol-core-attack-gates.md`
- Per finding: report row in `docs/audits/security-hardening-audit-2026-05-16.md`

- [ ] **Step 0: Run the shared stop-check** (see "Shared stop-check" above).

- [ ] **Step 1: Enumerate the public API.**

  ```bash
  grep -nE '^[[:space:]]*pub (fn|struct|enum|trait|mod|use)' crates/umbrella-identity/src/*.rs
  ```

  Expected: a list of every exported symbol. Note all `pub fn` entry points
  that accept bytes/strings/raw indices from outside the crate (attestation
  tokens, mnemonic strings, derivation paths, server nonces, recovery
  material).

- [ ] **Step 2: Sketch the trust-boundary diagram in a scratch note.**

  Identify which inputs are attacker-controllable and which are
  same-tenant-only. The honest answer for this crate: BIP-39 mnemonic strings
  from a recovery flow (attacker may inject malformed UTF-8 or oversize),
  derivation paths from the configuration, attestation tokens from the
  platform verifier, server-side challenge bytes, and cloud-wrap material.

- [ ] **Step 3: Walk the 20-category hypothesis matrix.** Per category, write
      down 0-3 specific hypotheses for this crate. Suggested seed hypotheses
      for `umbrella-identity` (extend as you read code; do not blindly stop
      at this list):

  - Category 2 (integer overflow): does `DerivationPath` reject paths longer
    than `usize::MAX / mem::size_of::<HardenedIndex>()` cleanly, or panic on
    `Vec::reserve` / index multiplication?
  - Category 3 (panic): mnemonic parsing on shorter/longer-than-24-word input;
    does any `unwrap` or `[idx]` access on attacker bytes survive?
  - Category 4 (error info leak): do `IdentityError` variants embed any seed
    bytes, key bytes, or partial mnemonic words in `Display` output?
  - Category 5 (deserialization DoS): is there any `Vec::with_capacity(len)`
    or `String::with_capacity(len)` driven by attacker-controlled length?
  - Category 10 (Debug paths): do `IdentityKey`, `DeviceKey`, `MasterKey`,
    `ExtendedSecret`, `IdentitySeed`, `CodeRecoveryMnemonic` derive `Debug`
    in a way that prints bytes? (`Zeroize` + manual `Debug` should be used
    for all of these — check.)
  - Category 11 (domain separation): do `CODE_RECOVERY_HKDF_INFO`,
    `ROTATION_DOMAIN_SEPARATOR`, `ATTESTATION_DOMAIN_SEPARATOR`,
    `CLOUD_WRAP_RECOVERY_HKDF_INFO`, `SLH_DSA_BACKUP_ROTATION_CONTEXT` share
    any prefix that could enable a collision across schemes?
  - Category 12 (KDF context): does BIP-32-Ed25519 derive use a fixed salt
    that is reused with another scheme? Are HKDF `info` bytes unique?
  - Category 14 (RNG): is `OsRng` the only source for key generation? Any
    test-only RNG that could survive into a release path?
  - Category 15 (TOCTOU): attestation expiry check vs use — can a token be
    used after expiry due to a re-read race?
  - Category 16 (zeroize): does `IdentitySeed::drop` zero the entropy buffer?
    Are intermediate buffers in `derive_rotated_identity_material` zeroed?
  - Category 17 (serde): if any of these types is `Deserialize`, is `Vec<T>`
    bounded? Are mnemonic strings length-capped before allocation?

- [ ] **Step 4: For each confirmed hypothesis, run the shared per-finding
      workflow** (see "Shared per-finding workflow" at the top of this doc).
      Do not skip steps.

- [ ] **Step 5: When the matrix is exhausted (or 3+ hypotheses in a row in a
      single category fail), run crate-level verification.**

  ```bash
  cargo fmt --all -- --check
  cargo clippy -p umbrella-identity --all-targets --all-features --locked -- -D warnings
  cargo test -p umbrella-identity --all-features --locked
  bash scripts/audit-protocol-core-attack-gates.sh
  ```

  Expected: all green. If any was already touched by a per-finding commit,
  this is the final crate-level smoke.

- [ ] **Step 6: Add a `## Tier 1 progress` note to the audit report.**

  Append to `docs/audits/security-hardening-audit-2026-05-16.md`:

  ```markdown
  - `umbrella-identity`: walked categories 1-20; N confirmed findings,
    M closed by test; categories X/Y/Z noted n/a.
  ```

- [ ] **Step 7: Commit the crate close-out (if anything beyond per-finding
      commits remains).** Otherwise note in the audit-progress section and
      proceed to Task 2.

---

## Task 2: Tier 1 — umbrella-mls

**Files:**
- Read: `crates/umbrella-mls/src/lib.rs`,
        `crates/umbrella-mls/src/ciphersuite.rs`,
        `crates/umbrella-mls/src/credential.rs`,
        `crates/umbrella-mls/src/group.rs`,
        `crates/umbrella-mls/src/group_policy.rs`,
        `crates/umbrella-mls/src/key_package.rs`,
        `crates/umbrella-mls/src/parser.rs`,
        `crates/umbrella-mls/src/provider/`,
        `crates/umbrella-mls/src/signer.rs`,
        `crates/umbrella-mls/src/caps.rs`,
        `crates/umbrella-mls/src/error.rs`
- Read: `crates/umbrella-mls/tests/pq_downgrade_resistant.rs`,
        `crates/umbrella-mls/tests/xwing_provider_handshake.rs`
- Per finding artifacts as in Task 1.

- [ ] **Step 0: Run the shared stop-check.**

- [ ] **Step 1: Enumerate the public API.**

  ```bash
  grep -nE '^[[:space:]]*pub (fn|struct|enum|trait|mod|use)' crates/umbrella-mls/src/*.rs crates/umbrella-mls/src/**/*.rs
  ```

- [ ] **Step 2: Sketch the trust-boundary diagram in a scratch note.**

  MLS handles attacker-controlled `MlsMessageIn`, `KeyPackageIn`,
  external-add proposals (forbidden for private groups), group state
  serialised by remote peers, ciphersuite negotiation bytes,
  Ed25519/Ed448-only policy enforcement, and openmls wire formats.

- [ ] **Step 3: Walk the 20-category hypothesis matrix.** Seed hypotheses
      specific to MLS:

  - Category 1 (state confusion): can a group accept a commit whose epoch
    advanced past the receiver's view by more than 1 (out-of-order welcome
    + commit)?
  - Category 2 (overflow): are `MAX_EXPORTER_LEN`, `KEY_PACKAGE_LIFETIME_SECS`,
    `PRIVATE_GROUP_MAX_LIFETIME_SECS` enforced consistently? Any time
    arithmetic that wraps on `u64`?
  - Category 3 (panic): `parse_key_package_safe`, `parse_mls_message_safe`
    — do they panic on truncated input, oversize fields, malformed varints?
    What about `KEY_PACKAGE_MIN_BYTES` / `MLS_MESSAGE_MIN_BYTES` boundary off-by-one?
  - Category 5 (deserialization DoS): does the parser cap the size of nested
    extensions, the credential field, the leaf-node `application_id` field?
    Can an attacker submit a `KeyPackage` whose `extensions` list expands to
    1 GB?
  - Category 8 (fail-open): in `UmbrellaGroup::process_incoming_message`, is
    there an `Err` arm that returns `Ok(Discarded)` for a malformed message
    that should have been a hard error?
  - Category 13 (algorithm agility): is the Ed25519/Ed448-only policy
    enforced at every entry point or just at `ciphersuite.rs` constructor?
    Can a `KeyPackage` carrying a forbidden ciphersuite slip in via
    `external_init` PSK group?
  - Category 17 (serde bounds): see Category 5.
  - Category 18 (stack overflow): can a recursive extension list cause stack
    overflow during parsing?

- [ ] **Step 4: For each confirmed hypothesis, run the shared per-finding
      workflow.**

- [ ] **Step 5: Crate-level verification.**

  ```bash
  cargo fmt --all -- --check
  cargo clippy -p umbrella-mls --all-targets --all-features --locked -- -D warnings
  cargo test -p umbrella-mls --all-features --locked
  bash scripts/audit-protocol-core-attack-gates.sh
  ```

- [ ] **Step 6: Add a `## Tier 1 progress` note.**

- [ ] **Step 7: Commit close-out if needed.**

---

## Task 3: Tier 1 — umbrella-sealed-sender

**Files:**
- Read: `crates/umbrella-sealed-sender/src/lib.rs`,
        `crates/umbrella-sealed-sender/src/version.rs`,
        `crates/umbrella-sealed-sender/src/hybrid_envelope.rs`
- Read: existing adversarial tests
  `crates/umbrella-sealed-sender/tests/phd_real_attacks_sealed_sender.rs`,
  `crates/umbrella-sealed-sender/tests/v1_v2_mixed_corpus.rs`,
  `crates/umbrella-sealed-sender/tests/v2_envelope_roundtrip.rs`

- [ ] **Step 0: Run the shared stop-check.**

- [ ] **Step 1: Enumerate the public API.**

  ```bash
  grep -nE '^[[:space:]]*pub (fn|struct|enum|trait|mod|use)' crates/umbrella-sealed-sender/src/*.rs
  ```

- [ ] **Step 2: Sketch the trust-boundary diagram.**

  Attacker controls the outer envelope bytes, version prefix, recipient AAD
  bytes, ciphertext, signature payload, sender-key payload.

- [ ] **Step 3: Walk the 20-category hypothesis matrix.** Seed:

  - Category 1 (state confusion): can a V1 envelope be parsed under V2 state
    and accepted as V2 (cross-version replay)? Existing tests cover
    `real_attack_cross_version_replay_v1_to_v2_blocked` — look for the
    reverse, partial corruption, V1.5 future-byte, mixed-length boundaries.
  - Category 3 (panic): does any `unwrap` survive on a malformed envelope?
  - Category 5 (deserialization DoS): is the inner ciphertext length capped?
    Can an attacker submit a giant `inner_signature` field?
  - Category 8 (fail-open): the V2 inner-signature verification path — any
    `Err` arm that swallows the failure?
  - Category 9 (constant-time): is the inner-signature comparison
    constant-time? Is the recipient-key lookup constant-time?
  - Category 11 (domain separation): does V2 use the SAME label as V1 for
    any HKDF/HMAC step? Any prefix collision between V1 and V2 AAD?
  - Category 13 (version confusion): future bytes (V3, V4) — does the
    parser fall through to V2 or hard-reject?
  - Category 17 (serde bounds): see Category 5.

- [ ] **Step 4: Per-finding workflow.**

- [ ] **Step 5: Crate-level verification.**

  ```bash
  cargo fmt --all -- --check
  cargo clippy -p umbrella-sealed-sender --all-targets --all-features --locked -- -D warnings
  cargo test -p umbrella-sealed-sender --all-features --locked
  ```

- [ ] **Step 6: Progress note.**
- [ ] **Step 7: Close-out commit if needed.**

---

## Task 4: Tier 1 — umbrella-backup

**Files:**
- Read: `crates/umbrella-backup/src/lib.rs`,
        `crates/umbrella-backup/src/error.rs`,
        `crates/umbrella-backup/src/identity_adapters.rs`,
        `crates/umbrella-backup/src/cloud_wrap/`,
        `crates/umbrella-backup/src/device_transfer/`
- Read existing adversarial tests:
  `crates/umbrella-backup/tests/pq_threshold_wrap.rs`,
  `crates/umbrella-backup/tests/v1_v2_mixed_corpus.rs`,
  `crates/umbrella-backup/tests/test_F_76.rs`

- [ ] **Step 0: Stop-check.**

- [ ] **Step 1: Enumerate the public API.**

  ```bash
  grep -nE '^[[:space:]]*pub (fn|struct|enum|trait|mod|use)' crates/umbrella-backup/src/*.rs crates/umbrella-backup/src/**/*.rs
  ```

- [ ] **Step 2: Trust-boundary sketch.**

  Cloud-wrap unwrap is invoked with attacker-controlled wire bytes (V1 vs V2
  format), AAD canonicalisation inputs, signed-request payloads (chat_id,
  recipient device pubkey, timestamp, token, server nonce, device key),
  threshold-PQ shares from 5 different servers (2 may be malicious).

- [ ] **Step 3: 20-category walk.** Seed:

  - Category 1 (state confusion): can a signed request from device A be
    accepted under device B's session if both have valid attestations?
  - Category 5 (deserialization DoS): cloud-wrap V1/V2 parser size caps —
    are they strict?
  - Category 6 (race): two parallel `unwrap` calls with the same server
    nonce — does the replay guard hold?
  - Category 8 (fail-open): unwrap on a malformed PQ-share — does it fall
    back to classical?
  - Category 11 (domain separation): AAD for V1 vs V2 — same prefix anywhere?
  - Category 13 (version confusion): V2-byte-prefix V1-length boundary —
    existing tests cover `v2_byte_prefix_v1_length_buffer_rejected_by_both`;
    look for V3-future, partial V2 with V1 trailer.
  - Category 15 (TOCTOU): timestamp check vs use in signed request — can
    the request live past `production_timestamp_window_secs`?
  - Category 16 (zeroize): the recovered key material after `unwrap` — is
    it zeroed in `Drop`? In error-return paths?
  - Category 17 (serde bounds): see Category 5.

- [ ] **Step 4: Per-finding workflow.**

- [ ] **Step 5: Crate verification.**

  ```bash
  cargo fmt --all -- --check
  cargo clippy -p umbrella-backup --all-targets --all-features --locked -- -D warnings
  cargo test -p umbrella-backup --all-features --locked
  ```

- [ ] **Step 6: Progress note.**
- [ ] **Step 7: Close-out commit if needed.**

---

## Task 5: Tier 1 — umbrella-oprf

**Files:**
- Read: `crates/umbrella-oprf/src/lib.rs` and all submodules under
  `crates/umbrella-oprf/src/`.
- Existing tests: `crates/umbrella-oprf/tests/external_rfc9497_attacks.rs`,
  plus whatever else is present in `crates/umbrella-oprf/tests/`.

- [ ] **Step 0: Stop-check.**

- [ ] **Step 1: Enumerate public API.**

  ```bash
  ls crates/umbrella-oprf/src/
  grep -nE '^[[:space:]]*pub (fn|struct|enum|trait|mod|use)' crates/umbrella-oprf/src/*.rs
  ```

- [ ] **Step 2: Trust-boundary sketch.**

  Inputs: blinded points (Ristretto), tokens, server nonces, device pubkeys,
  threshold shares, witness signatures. The ledger already covers tampering
  variants and RFC 9497 boundaries. Look for:

  - Category 6 (race): two parallel threshold combines for the same client
    request — does the witness-index ledger hold under contention?
  - Category 9 (constant-time): the `verify` path — is the failure indicator
    constant-time? Does `verify_rejects_tampered_blinded` short-circuit on
    the first bad byte?
  - Category 11 (domain separation): the OPRF HKDF chain — any label reused
    in `umbrella-backup` cloud-wrap?
  - Category 15 (TOCTOU): server-nonce reuse window — is the same nonce
    rejected after the first success even across concurrent threads?
    Existing test `production_context_rejects_replayed_server_nonce_after_first_success`
    covers single-thread; look for ordering of insert vs check under
    contention.
  - Category 17 (serde bounds): any `Vec<Share>` without an enforced cap?

- [ ] **Step 3: 20-category walk** (seeded as above; extend as you read).

- [ ] **Step 4: Per-finding workflow.**

- [ ] **Step 5: Crate verification.**

  ```bash
  cargo fmt --all -- --check
  cargo clippy -p umbrella-oprf --all-targets --all-features --locked -- -D warnings
  cargo test -p umbrella-oprf --all-features --locked
  ```

- [ ] **Step 6: Progress note.**
- [ ] **Step 7: Close-out commit if needed.**

---

## Task 6: Tier 1 — umbrella-pq

**Files:**
- Read: `crates/umbrella-pq/src/lib.rs` and submodules.
- Existing tests in `crates/umbrella-pq/tests/`.

- [ ] **Step 0: Stop-check.**

- [ ] **Step 1: Enumerate public API.**

  ```bash
  ls crates/umbrella-pq/src/
  grep -nE '^[[:space:]]*pub (fn|struct|enum|trait|mod|use)' crates/umbrella-pq/src/*.rs
  ```

- [ ] **Step 2: Trust-boundary sketch.**

  Hybrid X25519/ML-KEM, SLH-DSA-backup, KyberSlash external advisory.
  Attacker controls: encapsulated shared secrets, ML-KEM ciphertext,
  decapsulation inputs.

- [ ] **Step 3: 20-category walk.** Seed:

  - Category 8 (fail-open): on PQ decap failure, does the hybrid fall back
    to classical only — i.e., effectively a PQ-removed downgrade? Existing
    test `pq_downgrade_resistant` in `umbrella-mls` is one defence; look
    for the same property in `umbrella-pq` direct unwrap paths.
  - Category 9 (constant-time): KyberSlash class — does the implementation
    avoid the published timing oracle in decapsulation? If using external
    crate, check the version against the KyberSlash advisory.
  - Category 11 (domain separation): hybrid combiner labels — does the
    HKDF binding for the hybrid shared secret use a label unique to this
    scheme?
  - Category 14 (RNG): ML-KEM keygen and encap RNG — `OsRng` only?
  - Category 17 (serde bounds): PQ payloads have very specific lengths;
    is mismatched-length rejected hard?

- [ ] **Step 4: Per-finding workflow.**

- [ ] **Step 5: Crate verification.**

  ```bash
  cargo fmt --all -- --check
  cargo clippy -p umbrella-pq --all-targets --all-features --locked -- -D warnings
  cargo test -p umbrella-pq --all-features --locked
  ```

- [ ] **Step 6: Progress note.**
- [ ] **Step 7: Close-out commit if needed.**

---

## Task 7: Tier 1 — umbrella-crypto-primitives

**Files:**
- Read: `crates/umbrella-crypto-primitives/src/lib.rs` and submodules.

- [ ] **Step 0: Stop-check.**

- [ ] **Step 1: Enumerate public API.**

  ```bash
  ls crates/umbrella-crypto-primitives/src/
  grep -nE '^[[:space:]]*pub (fn|struct|enum|trait|mod|use)' crates/umbrella-crypto-primitives/src/*.rs
  ```

- [ ] **Step 2: Trust-boundary sketch.**

  Low-level: HKDF, HMAC, AES-GCM-SIV or ChaCha20-Poly1305, X25519, Ed25519,
  Ristretto255, BIP-32-Ed25519. Direct callers are other crates, so
  attacker inputs reach here through them; here we audit the building
  blocks.

- [ ] **Step 3: 20-category walk.** Seed:

  - Category 9 (constant-time): every `eq` / `ct_eq` on secret data — is it
    using `subtle::ConstantTimeEq` or equivalent? Any `==` on `&[u8]`
    derived from a MAC tag, KDF output, or signature?
  - Category 11 (domain separation): per primitive, is the HKDF `info`
    derived from a constant that contains the crate name + the operation
    name?
  - Category 14 (RNG): scan for `thread_rng()`, `SmallRng`, `StdRng`. Any
    occurrence outside test code is a finding.
  - Category 16 (zeroize): `Drop` impls for symmetric keys, HMAC keys,
    secret scalars — do they zero?
  - Category 17 (serde): does the crate expose `Deserialize` for any secret
    type? If yes, that's a finding by itself.

- [ ] **Step 4: Per-finding workflow.**

- [ ] **Step 5: Crate verification.**

  ```bash
  cargo fmt --all -- --check
  cargo clippy -p umbrella-crypto-primitives --all-targets --all-features --locked -- -D warnings
  cargo test -p umbrella-crypto-primitives --all-features --locked
  ```

- [ ] **Step 6: Progress note.**
- [ ] **Step 7: Close-out commit if needed.**

---

## Task 8: Tier 1 — umbrella-kt

**Files:**
- Read: `crates/umbrella-kt/src/lib.rs` and submodules. Recent KT split-view
  hardening landed in commits a9b0dd66, 28b4a048, af0f806a, 7c7883a2.

- [ ] **Step 0: Stop-check.**

- [ ] **Step 1: Enumerate public API.**

  ```bash
  ls crates/umbrella-kt/src/
  grep -nE '^[[:space:]]*pub (fn|struct|enum|trait|mod|use)' crates/umbrella-kt/src/*.rs
  ```

- [ ] **Step 2: Trust-boundary sketch.**

  Inputs: signed tree heads, inclusion proofs, consistency proofs, witness
  signatures (up to threshold t=3 of 5 may be malicious), epoch counters,
  log_size monotonicity, observation history. Existing ledger
  (`docs/security/external-crypto-attack-ledger-2026-05-15.md`) and
  attack-gates rows are dense — focus on what's NOT there.

- [ ] **Step 3: 20-category walk.** Seed:

  - Category 1 (state confusion): can the observation history accept an
    epoch N+1 root whose `previous_root` points at a root that was never
    observed by this client (i.e., a fork tip)?
  - Category 2 (overflow): `log_size` is bounded but `u64` — anywhere the
    arithmetic could wrap?
  - Category 6 (race): two threads observing the same epoch concurrently
    — does the equivocation evidence collector see both, neither, or
    duplicate?
  - Category 10 (Debug paths): the recent privacy-safe encoding test
    `public_observation_encoding_round_trips_without_private_account_data`
    locks the wire format. Are there OTHER serialised forms (in-memory
    diagnostic, error variants) that still leak the private fields?
  - Category 11 (domain separation): the witness signing payload — is the
    domain tag unique vs other Ed25519 signing in this crate or in
    `umbrella-identity`?
  - Category 15 (TOCTOU): witness ledger insert vs equivocation check —
    can a witness sign two roots between the check and the insert?
  - Category 17 (serde bounds): observation history persistence — is the
    history list bounded? Can a client be DoSed by being fed a history of
    1 M epochs?

- [ ] **Step 4: Per-finding workflow.**

- [ ] **Step 5: Crate verification.**

  ```bash
  cargo fmt --all -- --check
  cargo clippy -p umbrella-kt --all-targets --all-features --locked -- -D warnings
  cargo test -p umbrella-kt --all-features --locked
  ```

- [ ] **Step 6: Progress note.**
- [ ] **Step 7: Close-out commit if needed.**

---

## Task 9: Tier 2 — umbrella-client + umbrella-server-blind-postman

**Files:**
- Read: all `.rs` files in `crates/umbrella-client/src/` and
  `crates/umbrella-server-blind-postman/src/`.
- Per finding: as in Task 1.

- [ ] **Step 0: Stop-check.**

- [ ] **Step 1: Enumerate public API of both crates.**

  ```bash
  grep -nE '^[[:space:]]*pub (fn|struct|enum|trait|mod|use)' crates/umbrella-client/src/**/*.rs
  grep -nE '^[[:space:]]*pub (fn|struct|enum|trait|mod|use)' crates/umbrella-server-blind-postman/src/**/*.rs
  ```

- [ ] **Step 2: Trust-boundary sketch.**

  Client: orchestrates identity, MLS, sealed sender, backup, OPRF, transport.
  Server postman: routes envelopes, enforces rate limits, replay-window,
  blind matching. Attacker can submit malicious envelopes, malformed
  routing tags, and probe the rate-limit / replay-window interaction
  (already partly closed by 2026-05-15 audit).

- [ ] **Step 3: 20-category walk** — emphasis on categories 1-6, 8, 14, 17:

  - Category 1: cross-crate confusion (e.g., a sealed-sender envelope
    delivered to the wrong group_id is silently routed).
  - Category 3: panic-DoS on the routing parser.
  - Category 5: deserialization DoS on the envelope queue.
  - Category 6: replay-window race vs rate-limit ordering (the 2026-05-15
    fix changed the order — look for related interleavings).
  - Category 8: fail-open on transport setup errors in `ClientCore` — does
    any path silently revert to test transport?
  - Category 17: serde bounds on routing fields.

- [ ] **Step 4: Per-finding workflow.**

- [ ] **Step 5: Crate verification.**

  ```bash
  cargo fmt --all -- --check
  cargo clippy -p umbrella-client --all-targets --all-features --locked -- -D warnings
  cargo clippy -p umbrella-server-blind-postman --all-targets --all-features --locked -- -D warnings
  cargo test -p umbrella-client --all-features --locked
  cargo test -p umbrella-server-blind-postman --all-features --locked
  ```

- [ ] **Step 6: Progress note.**
- [ ] **Step 7: Close-out commit if needed.**

---

## Task 10: Tier 2 — umbrella-padding + umbrella-calls + umbrella-platform-verifier

**Files:**
- Read all `.rs` under `crates/umbrella-padding/src/`,
  `crates/umbrella-calls/src/`, `crates/umbrella-platform-verifier/src/`.

- [ ] **Step 0: Stop-check.**

- [ ] **Step 1: Enumerate public API of all three.**

- [ ] **Step 2: Trust-boundary sketch.**

  Padding: length leakage, padded ciphertext format, malicious unpad.
  Calls: MLS-SFrame, media frame parsing. Platform-verifier: WebAuthn
  assertion, Apple/Android token parsing (fail-closed boundaries already
  declared).

- [ ] **Step 3: 20-category walk** — emphasis 1-6, 8, 9, 14, 17:

  - Padding category 5/17/18: oversize padded ciphertext, recursive layer
    parsing.
  - Padding category 16 (zeroize): on `unpad`, is the recovered plaintext
    zeroed in error paths? The existing
    `zeroizing_payload_debug_redacts_bytes` test addresses Debug; check
    actual drop.
  - Calls category 3/5: SFrame header parser panic on truncated input.
  - Calls category 11: SFrame domain separation vs MLS exporter.
  - Platform-verifier category 8: fail-open on WebAuthn parse — does any
    error path produce `Ok(Verified)`?

- [ ] **Step 4: Per-finding workflow.**

- [ ] **Step 5: Crate verification (run for each crate touched).**

- [ ] **Step 6: Progress note.**
- [ ] **Step 7: Close-out commit if needed.**

---

## Task 11: Tier 3 — umbrella-ffi + umbrella-ffi-swift + umbrella-ffi-kotlin + umbrella-core + umbrella-tests

**Files:**
- Read: `crates/umbrella-ffi/src/`, `crates/umbrella-ffi-swift/src/`,
  `crates/umbrella-ffi-kotlin/src/`, `crates/umbrella-core/src/`,
  `crates/umbrella-tests/src/`.

- [ ] **Step 0: Stop-check.**

- [ ] **Step 1: Enumerate public API and `extern "C"` surfaces.**

  ```bash
  grep -nE '^[[:space:]]*(pub )?(extern "C" fn|pub fn|pub struct|pub enum)' crates/umbrella-ffi*/src/**/*.rs
  ```

- [ ] **Step 2: Trust-boundary sketch.**

  FFI: every byte that crosses the C ABI is attacker-typed. Pointer +
  length pairs, opaque handles, UTF-8 strings, callback pointers (if any),
  buffer lifetime contracts.

- [ ] **Step 3: 20-category walk** — emphasis 2, 3, 7, 8, 17:

  - Category 2 (overflow): pointer + length pairs — does any function trust
    `len` without bounding it to `isize::MAX`?
  - Category 3 (panic): does any FFI function call `unwrap` on attacker
    input? Panic-unwinding across the FFI boundary is UB.
  - Category 7 (FFI memory safety): pointer alignment, double-free, use-
    after-free, lifetime of returned `&CStr`.
  - Category 8 (fail-open): error codes — does every `Err` return a
    non-zero code AND clear the out-pointer?
  - Category 17 (serde / unbounded): if the FFI deserialises JSON or
    bincode, are caps enforced before crossing back into the Rust crate?

- [ ] **Step 4: Per-finding workflow.**

- [ ] **Step 5: Crate verification.**

  ```bash
  cargo fmt --all -- --check
  cargo clippy -p umbrella-ffi --all-targets --all-features --locked -- -D warnings
  cargo clippy -p umbrella-ffi-swift --all-targets --all-features --locked -- -D warnings
  cargo clippy -p umbrella-ffi-kotlin --all-targets --all-features --locked -- -D warnings
  cargo clippy -p umbrella-core --all-targets --all-features --locked -- -D warnings
  cargo test -p umbrella-ffi --all-features --locked
  cargo test -p umbrella-ffi-swift --all-features --locked
  cargo test -p umbrella-ffi-kotlin --all-features --locked
  cargo test -p umbrella-core --all-features --locked
  cargo test -p umbrella-tests --all-features --locked
  ```

- [ ] **Step 6: Progress note.**
- [ ] **Step 7: Close-out commit if needed.**

---

## Task 12: Tier 4 — sanity scan of non-production crates

**Crates:** `umbrella-fuzz`, `umbrella-formal-verification`,
`umbrella-vectors`, `umbrella-lints`.

These are not in the production data path. The audit goal is:

1. Confirm they are not accidentally pulled into a release binary.
2. Confirm they do not contain real secrets in test vectors.
3. Confirm fuzz harnesses cannot be repurposed to amplify a real-network
   DoS if accidentally shipped.

- [ ] **Step 0: Stop-check.**

- [ ] **Step 1: Confirm `Cargo.toml` exclusion / dev-only roles.**

  ```bash
  grep -A2 -n '^\[\(package\|dependencies\|dev-dependencies\)\]' crates/umbrella-{fuzz,formal-verification,vectors,lints}/Cargo.toml
  ```

  Expected: these crates are either `publish = false`, dev-only, or not
  depended on by `umbrella-client` / `umbrella-server-blind-postman` /
  `umbrella-ffi*`.

- [ ] **Step 2: Spot-check for stray secrets in vectors.**

  ```bash
  grep -nrE 'BEGIN (PRIVATE|EC|RSA) KEY|-----BEGIN OPENSSH|0x[0-9a-fA-F]{60,}' crates/umbrella-vectors/
  ```

  Expected: no real private keys; only deterministic test material.

- [ ] **Step 3: Brief audit-report note.**

  Add to `docs/audits/security-hardening-audit-2026-05-16.md`:

  ```markdown
  - Tier 4 sanity: umbrella-fuzz / umbrella-formal-verification /
    umbrella-vectors / umbrella-lints confirmed dev-only with no production
    data-path role and no stray private material.
  ```

- [ ] **Step 4: No commit unless something was found.** If nothing was found,
      this fact is recorded in the audit-report progress and the next task
      runs.

---

## Task 13: Cross-cutting and consolidation

- [ ] **Step 0: Stop-check.**

- [ ] **Step 1: Run the full release-critical verification.**

  ```bash
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  cargo test --workspace --all-features --locked
  bash scripts/audit-protocol-core-attack-gates.sh
  bash scripts/audit-pq-backend-policy.sh
  bash scripts/audit-local-release-hardening.sh target/local-release-hardening/short
  bash scripts/audit-public-access-notices.sh
  bash scripts/audit-dependency-policy.sh target/audit-evidence-phd-security-20260516
  ```

  If any fails, return to the relevant crate task and fix.

- [ ] **Step 2: Finalise the audit report.**

  Edit `docs/audits/security-hardening-audit-2026-05-16.md`:

  - Fill in `## Что было найдено и исправлено` with all rows
    (table now complete, no placeholder row).
  - Fill in `## Новые реальные проверки` with the list of new attack tests
    that were added.
  - Fill in `## Что прошло локально` with the actual commands and a
    one-word `pass`/`fail` per item.
  - Mirror everything into the `## English mirror` section.
  - If zero findings: explicit "No new findings; existing ledger fully
    covers the reviewed surface" statement in both languages.

- [ ] **Step 3: Honesty self-check on the report.**

  Apply the 6-question PhD-vs-A distinguisher:

  1. Findings count: list is honest (no inflated rows).
  2. Test naming: every attack test starts with `attack_` and names the
     specific class.
  3. Tamarin/ProVerif engagement: this round is recon-breadth; report says
     so. No false PhD-level claim.
  4. dudect 1M: not required for this round; if any timing finding was
     surfaced, it is flagged for a follow-up B-deep session.
  5. Reduction sketches: not required; not claimed.
  6. Literature: any external paper cited is referenced by exact title and
     year; no fabricated citations.

  Fix the report inline if any check fails.

- [ ] **Step 4: Commit the consolidation.**

  ```bash
  git add docs/audits/security-hardening-audit-2026-05-16.md \
          docs/security/protocol-core-attack-gates.md \
          docs/security/external-crypto-attack-ledger-2026-05-16.md 2>/dev/null
  git commit -m "$(cat <<'EOF'
  docs: close 2026-05-16 phd recon-breadth audit round

  Final report and ledger consolidation for the recon-breadth round. All
  Tier 1 + Tier 2 + Tier 3 crates walked, Tier 4 confirmed dev-only, N
  findings closed by failing-then-passing attack tests and root-cause fixes,
  full workspace verification (cargo fmt / clippy / test --workspace, all
  scripts/audit-*.sh) green. recon-breadth A-level rigor per finding with
  PhD-style adversary mindset; deeper-treatment candidates marked for
  follow-up B-deep sessions.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  EOF
  )"
  ```

  If there were ZERO findings, the commit message says "0 findings; ledger
  rows unchanged; report records the negative result honestly."

- [ ] **Step 5: Final branch state check.**

  ```bash
  git log --oneline codex/phd-security-audit ^main | head -30
  git status
  ```

  Expected: clean tree; the audit-round commits are visible above the spec
  commit (`4c67f172`).

---

## Task 14: Branch handling decision

The user owns the merge decision. Do NOT merge to main without explicit
authorisation (memory: `feedback_direct_to_main` applies to commits, not to
merges that are not specifically authorised; ask).

- [ ] **Step 1: Summarise the round to the user in chat.** Include:

  - Round outcome (findings count by severity, or honest zero).
  - List of new attack tests.
  - List of new ledger rows.
  - Whether the workspace gates are green.
  - Recommendation: merge `codex/phd-security-audit` to `main` (if any
    fixes landed), OR keep the branch open for a follow-up B-deep session
    (if a Critical/cryptographic-core finding was deferred).

- [ ] **Step 2: Ask the user for the merge decision before doing anything
      destructive (squash, rebase, force-push).**

---

## Self-review (run by the planning agent after writing the plan)

**1. Spec coverage:**

- §1 Goal → addressed by tasks 0-13 collectively.
- §2 Threat model → encoded in trust-boundary sketches in every task.
- §3 Attack categories → encoded in the shared 20-category matrix.
- §4 Per-tier approach → Tasks 1-12 implement the per-tier budget.
- §5 Per-finding workflow → encoded in the shared workflow + Steps 4 of
  each task.
- §6 Deliverables → Tasks 0 / per-finding / 13 produce report + per-finding
  artefacts + handoff doc if needed.
- §7 Stop conditions → shared stop-check at the start of every task.
- §7a Severity taxonomy → referenced in workflow step 12 and report.
- §8 Honesty self-check → Task 13 Step 3.
- §9 Verification gates → end of every crate task and Task 13 Step 1.
- §10 Resolved open questions → encoded in workflow step 13 (critical
  pause), report skeleton (zero-findings clause), and shared workflow note
  about on-demand fuzz/miri.
- §11 Non-goals → not touched by any task (no FFI bootstrap, no live KT
  deployment, no Apple/Play wiring, no refactoring).
- §12 Done predicate → Task 13 Step 1 fulfils condition (1); Task 0 +
  shared stop-check fulfils condition (2).

No gaps.

**2. Placeholder scan:**

- No "TBD", "TODO", "implement later", "fill in details" in any task.
- Every step is concrete. The per-finding workflow contains the exact
  shell commands.
- Report-skeleton placeholders inside the report file itself (e.g., the
  empty table row) are intentional and explicitly resolved in Task 13
  Step 2.

**3. Type consistency:** The plan does not introduce new Rust types — it
applies an audit process. Test naming convention (`attack_<class>_<specific>_<crate>`)
and commit-message style are consistent across the document.

No inline fixes needed.

---

## Execution handoff

Plan complete and saved to
`docs/superpowers/plans/2026-05-16-phd-recon-breadth-audit.md`. Two
execution options:

**1. Subagent-Driven (recommended)** — dispatch a fresh subagent per Task
(per crate). Each subagent gets the shared workflow + matrix + the
specific crate context. Main session reviews findings between tasks. Best
fit for the 60% context budget because each subagent gets a fresh window.

**2. Inline Execution** — execute tasks in the current session via
superpowers:executing-plans with batch checkpoints. Risks hitting the 60%
budget before Tier 3 completes; will require a mid-round handoff.

Which approach?
