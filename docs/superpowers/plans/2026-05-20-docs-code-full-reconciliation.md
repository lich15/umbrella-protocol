# Docs ↔ Code Full Reconciliation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Привести 14 Tier 1 + 16 Tier 2 публичных docs к `main` HEAD `938d1a89` (workspace v3.0.0) per design `docs/superpowers/specs/2026-05-20-docs-code-full-reconciliation-design.md`. Закрыть 10-category drift catalog двумя atomic commits на `main` (Phase A — Tier 1 rebuild + v3.0.0 ceremony artifacts; Phase B — Tier 2 annotations + closure banners + plan historical-notes).

**Architecture:** Phase A (атомарный commit) — 4 new files + 10 rewrite files в Tier 1 + bilingual EN-first standardization (Category 6 Option A). Phase B (атомарный commit) — 5 annotation edits + 4 closure banners + 7 plan historical-note prefixes. Phase C (memory cleanup) — отдельная сессия, не в этом плане. Между phases — grep acceptance gate из design §4. Direct commits в `main` per `feedback_direct_to_main`.

**Tech Stack:** Markdown, Bash, `grep`, `git`. Тестовых suites не запускаются (это docs-only reconciliation; нет code-behavior changes).

---

## Source Documents

- **PRIMARY SPEC:** `docs/superpowers/specs/2026-05-20-docs-code-full-reconciliation-design.md` — drift catalog (10 categories) + resolution direction + acceptance criteria
- **Source-of-truth verified facts** (use directly без re-grepping):
  - Workspace `version = "3.0.0"` (`Cargo.toml`)
  - Tags: `v1.1.0` (2026-05-15) + `v3.0.0` (2026-05-20 commit `1ee8dbb3`)
  - **88 commits** since v1.1.0
  - **25 main-workspace members** (24 `crates/umbrella-*` + `xtask`) + 1 sub-workspace `crates/umbrella-lints/`
  - **18 formal models** (14 `.spthy` + 4 `.pv`)
  - **2179+ release-mode tests** (Round 7 baseline floor; post-1.1.0 series adds further)
  - **29 fuzz targets** in `crates/umbrella-fuzz/fuzz/fuzz_targets/`
  - **182 MlockedSecret usages** across workspace
  - **12 lemmas** in `multi_device_authorization.spthy`
- **Resolution closures referenced in v3.0.0 release notes:**
  - F-CLIENT-FACADE-1 MILESTONE 10/10: commit `9417096b` (session 10f)
  - Pass 5 remediation 18 findings: commits `471e7928`..`23eda73a`
  - Max Ratchet v3 10/10: commits `5907a9cd`, `bd17c571`, `078234b5`, `2b56ba7a`, `b1b9968a`, `7337afc7`, `87db7ad1`, `11805ba9`, `41f1cf71`, `62505ba4`
  - Round 7 discovery merge: commit `acff5e5b` (Security hardening: PhD-level audits, distributed identity, PSI discovery)
  - v3.0.0 ceremony bump: commit `1ee8dbb3`
  - Reconciliation predecessor: commit `de9b73bc`

## File Structure

### Phase A — Tier 1 (atomic commit)

**Create (4 new files):**
- `docs/security/release-notes-v3.0.0.md` — consolidated post-1.1.0 series release notes (EN-first / RU-at-end)
- `docs/security/release-manifest-v3.0.0.txt` — release verification manifest
- `docs/security/sbom-v3.0.0.json` — regenerated SBOM (derived from `sbom-v1.1.0.json` + workspace state)
- *(Conditional)* `docs/security/pgp-key.asc` — if user publishes fingerprint; default = remove ref from `SECURITY.md`

**Rewrite (10 files):**
- `README.md` (root) — Version 3.0.0 baseline + 25-member workspace inventory + Max Ratchet v3 + Round 7
- `docs/README.md` — Version 3.0.0 baseline + content tree refresh
- `CHANGELOG.md` — add v3.0.0 section consolidating post-1.1.0 series
- `docs/security/current-status.md` — v3.0.0 baseline + fix line 14 vs :52 contradiction
- `docs/security/protocol-core-attack-gates.md` — fix R23 name, add D-6/D-7/D-8 rows, EN-first layout
- `docs/security/production-readiness-boundaries.md` — v3.0.0 baseline, EN-first layout
- `docs/integration/README.md` — resolve narrative-code mismatch with `facade/` rustdoc
- `docs/integration/gateway-svc-contract.md` — fix line 244 post-closure stale, SPEC-11 §4
- `docs/comparison/umbrella-vs-messengers-2026-05-18.md` — 6 drift items
- `docs/WORKING_RULES.md` — bilingual EN-first + postulate 11 update
- `SECURITY.md` — remove broken `pgp-key.asc` references at line 17 + 76

### Phase B — Tier 2 (atomic commit)

**Annotate (4 files):**
- `docs/audits/formal-lint-status-2026-05-13.md` — clarify «of 18 total»
- `docs/audits/dudect-saturation-methodology-2026-05-19.md` — refresh v2.0.0 → v3.0.0
- `docs/audits/full-fuzz-and-miri-run-2026-05-14.md` — annotate 27 → 29
- `docs/audits/local-release-hardening-status-2026-05-14.md` — annotate 27 → 29

**Closure banners (4 files):**
- `docs/audits/device-capture-artifacts/r7_findings.md`
- `docs/audits/device-capture-artifacts/r9_r11_findings.md`
- `docs/audits/device-capture-artifacts/r10_findings.md`
- `docs/audits/device-capture-artifacts/r12_findings.md`

**Historical-note prefix (7 plan files):**
- `docs/superpowers/plans/2026-05-13-documentation-truth-alignment.md`
- `docs/superpowers/plans/2026-05-14-external-crypto-release-audit.md`
- `docs/superpowers/plans/2026-05-14-local-release-hardening.md`
- `docs/superpowers/plans/2026-05-14-protocol-core-attack-gates.md`
- `docs/superpowers/plans/2026-05-14-protocol-core-final-gates.md`
- `docs/superpowers/plans/2026-05-16-phd-recon-breadth-audit.md`
- `docs/superpowers/plans/2026-05-20-max-ratchet-deniability.md`

---

# PHASE A — Tier 1 Rebuild

> ⚠ Phase A не commit'ит после каждой task — все file edits stage'ятся в working tree до Task A15 (atomic commit).

## Task A1: Create `docs/security/release-notes-v3.0.0.md`

**Files:**
- Create: `docs/security/release-notes-v3.0.0.md`

- [ ] **Step 1: Write release-notes-v3.0.0.md (EN-first / RU-at-end)**

Структура:
1. Header `# Umbrella Protocol v3.0.0 Release Notes`
2. Date: 2026-05-20
3. Bilingual anchors `[English](#english) | [Русский](#русский)`
4. `## English` section:
   - One-paragraph summary: «Umbrella Protocol v3.0.0 is the post-v1.1.0 hardening release consolidating F-CLIENT-FACADE-1 MILESTONE 10/10 closure, PhD-B Pass 5 remediation (18 findings closed), Round 7 private contact discovery merge (PSI + @username with KT bind), Max Ratchet v3 (default-on aggressive DH + 5-minute timer rekey + post-quantum extension + SPQR HMAC deniable authentication), and the CI v3.0.0 ceremony cleanup.»
   - `### Added` — list:
     - `umbrella-discovery` crate (~5000 LoC; OPRF-PSI + `@username` lookup with KT bind; 38 D-1..D-8 attack-regression sub-tests; `discovery.spthy` Tamarin model)
     - Max Ratchet v3 layer over MLS (modules `crates/umbrella-mls/src/max_ratchet/{config,counter,timer,spqr,group,state,envelope}.rs`)
     - 5 new Tamarin models: `aggressive_dh_pcs.spthy`, `spqr_deniability.spthy`, `discovery.spthy`, `sealed_servers_threshold_3of5.spthy`, `sealed_servers_threshold_universal.spthy`
     - 2 new fuzz targets: `max_ratchet_envelope_decode.rs`, `max_ratchet_envelope_roundtrip.rs`
     - Public wire-contract spec `docs/spec/discovery-integration.md`
     - Backend integration contract `docs/integration/gateway-svc-contract.md`
   - `### Changed` — list:
     - **Workspace version 1.1.0 → 3.0.0** (commit `1ee8dbb3 chore(release): bump workspace version 1.1.0 → 3.0.0`)
     - F-CLIENT-FACADE-1: 12 sub-sessions (1, 2, 3, 4, 5, 6/6c, 7, 8a/8b/8c1-3, 9/9a-9f, 10/10a-10f) wired WebSocket + QUIC + MLS facades + KT self-monitor + identity rotation + calls + device transfer (commit `9417096b` session 10f)
     - PhD-B Pass 5 remediation: 18 findings closed across 20 commits `471e7928..23eda73a` (4 CRITICAL: F-1 Shamir 3-of-5 Lagrange / F-2 server-side OPRF / F-3 honest R23 naming / F-FFI-2 session-handle pattern; 5 HIGH: F-4 R21 FROST 3-of-5 / F-MLS-1 compile-time gate / F-CLIENT-HW-1 + F-IDENT-1 + F-IDENT-2 hw bootstrap closes M-FINAL-1; 6 MEDIUM formal-model tautologies в `mls_ed25519`, `kt_v1_self_monitoring`, `kt_v2_self_monitoring`, `sframe_rfc9605`, `downgrade_resistance`, `type_safe_enforcement`; 3 dudect measurement-artefact via bounded-pool pattern)
     - `ClientCore.identity` now `Option<Arc<IdentityKey>>` and `None` on the hw bootstrap path; ephemeral `IdentitySeed::generate` materialisation eliminated
   - `### Security` — list:
     - M-FINAL-1 closed via Pass 5 commit `e7b034ff` (F-CLIENT-HW-1)
     - All Pass 5 ship-blockers closed (0 BLOCKER + 0 MAJOR remaining)
     - Tamarin: 14 models verified under `tamarin-prover 1.12.0` (was 9 at v1.1.0)
     - ProVerif: 4 models (unchanged)
   - `### Verification` — commands:
     ```bash
     cargo fmt --all -- --check
     cargo test --workspace --all-features --locked
     cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
     bash scripts/audit-protocol-core-attack-gates.sh
     bash scripts/audit-local-release-hardening.sh
     bash scripts/audit-public-access-notices.sh
     bash scripts/audit-pq-backend-policy.sh
     bash scripts/verify-tamarin-models.sh
     bash scripts/verify-proverif-models.sh
     ```
   - `### Carry-overs to next release`:
     - External cryptographic review (Cure53 / NCC / Trail of Bits) — pre-ship step
     - Real-device runtime tests (iOS Secure Enclave / Android StrongBox) — Block 7.10 CI integration
     - F-PHD-RP-R3-1 SLSA L3 + cargo-vet + reproducible-build verification gate
     - F-PHD-PQ-5 X-Wing KAT vectors 2..n (draft-connolly-cfrg-xwing-kem-10 Appendix C)
     - F-PHD-PQ-6 FIPS 203 ACVP test vector set for ML-KEM-768
5. `---` separator
6. `## Русский` section — mirror of English with same structure, Russian text
7. Cross-references in both sections:
   - `docs/audits/ROUND-1-TO-7-SUMMARY.md`
   - `docs/audits/phd-b-pass5-remediation-2026-05-19.md`
   - `docs/audits/max-ratchet-deniability-spec-2026-05-20.md`
   - `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md`
   - `docs/integration/gateway-svc-contract.md`
   - `docs/spec/discovery-integration.md`
   - `docs/security/current-status.md`
   - `docs/security/production-readiness-boundaries.md`

Reference: existing `docs/security/release-notes-v1.1.0.md` для шаблона / стиля.

## Task A2: Create `docs/security/release-manifest-v3.0.0.txt`

**Files:**
- Create: `docs/security/release-manifest-v3.0.0.txt`

- [ ] **Step 1: Write release manifest (plain text)**

Структура (use existing `docs/security/release-manifest-v1.1.0.txt` как template):
```
Umbrella Protocol v3.0.0 Release Manifest
=========================================

Release date: 2026-05-20
Release tag: v3.0.0
Release commit: 1ee8dbb3fc67f451b9b749b773b3da9c92d2ef55
Workspace version: 3.0.0

Verification commands:
  cargo test --workspace --all-features --locked
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  bash scripts/audit-public-access-notices.sh
  bash scripts/audit-pq-backend-policy.sh
  bash scripts/audit-dependency-policy.sh

Source-of-truth references:
  README.md, CHANGELOG.md, docs/security/release-notes-v3.0.0.md,
  docs/security/current-status.md,
  docs/security/protocol-core-attack-gates.md,
  docs/audits/ROUND-1-TO-7-SUMMARY.md,
  docs/audits/phd-b-pass5-remediation-2026-05-19.md,
  docs/audits/max-ratchet-deniability-spec-2026-05-20.md.

Current hardening status: docs/security/current-status.md
Текущий статус приведения к документам: docs/security/current-status.md

End of manifest.
```

## Task A3: Create `docs/security/sbom-v3.0.0.json`

**Files:**
- Create: `docs/security/sbom-v3.0.0.json`

- [ ] **Step 1: Check for SBOM generation script**

```bash
ls scripts/ | grep -i sbom
ls scripts/ | grep -i bom
grep -rln "sbom-v1.1.0.json\|SBOM" scripts/ 2>/dev/null | head -5
```

Expected: either find generation script or fall back to manual copy + version bump.

- [ ] **Step 2: Generate SBOM (либо via script либо manual)**

Если есть `scripts/generate-sbom.sh` или похожее — run it pointing at v3.0.0 output. Если нет — copy `sbom-v1.1.0.json` → `sbom-v3.0.0.json` и обновить `name`, `version`, `serialNumber`, `metadata.timestamp` fields для v3.0.0.

```bash
cp docs/security/sbom-v1.1.0.json docs/security/sbom-v3.0.0.json
# Open in editor, replace version 1.1.0 → 3.0.0 in metadata block, add new crates umbrella-discovery + umbrella-threshold-identity
```

Required updates в JSON:
- `metadata.component.version`: `1.1.0` → `3.0.0`
- `metadata.timestamp`: today
- `components[]`: add `umbrella-discovery@3.0.0` + `umbrella-threshold-identity@3.0.0`; bump existing umbrella-* versions от 1.1.0 → 3.0.0

## Task A4: Resolve broken `pgp-key.asc` reference in `SECURITY.md`

**Files:**
- Modify: `SECURITY.md:17,76`

Default decision (per design doc): **remove broken references**. If user publishes fingerprint later, separate small commit.

- [ ] **Step 1: Edit `SECURITY.md:17` (English section)**

Replace:
```markdown
PGP key fingerprint: to be published at `docs/security/pgp-key.asc`.
```

With:
```markdown
PGP key not available for this release; please submit reports via `security@umbrellax.io` and the team will reply with a key for follow-up encrypted exchange.
```

- [ ] **Step 2: Edit `SECURITY.md:76` (Russian section)**

Replace:
```markdown
PGP fingerprint будет опубликован в `docs/security/pgp-key.asc`.
```

With:
```markdown
PGP-ключ для этого релиза не опубликован; присылайте сообщения на `security@umbrellax.io`, команда ответит с ключом для последующего зашифрованного обмена.
```

## Task A5: Rewrite `README.md` (root) к v3.0.0

**Files:**
- Modify: `README.md` (5 lines + crate inventory + recap section)

- [ ] **Step 1: Update version line 77 + 543**

Replace 5 sites of «1.1.0 (last release tag)» / «1.1.0 (последний тег)» / «v1.1.0» с **«3.0.0 (last release tag — `v3.0.0` ceremony 2026-05-20 via commit `1ee8dbb3`)»** / EN equivalent. Use Edit tool с replace_all=false для each — verify uniqueness первого.

Exact lines (verified via earlier grep):
- Line 39: `Supply-chain hardening for 1.1.0 removes...` → `Supply-chain hardening (initially in 1.1.0, carried into 3.0.0) removes...`
- Line 48: `(rounds 1-6 merged 2026-05-18 in commit ... PR #6; round 7 discovery merged subsequently) on the 1.1.0 codebase.` → `(rounds 1-6 merged 2026-05-18 commit `84b4d576` PR #6; round 7 merged subsequently) on the 1.1.0 codebase; further v3.0.0 hardening (F-CLIENT-FACADE-1 10/10 + Pass 5 + Max Ratchet v3) consolidated post-merge.`
- Line 60: `The post-1.1.0 release branch additionally carries Max Ratchet v3` → `The v3.0.0 release additionally consolidates Max Ratchet v3`
- Line 77: `Version: **1.1.0** (last release tag) plus a post-1.1.0 hardening series on...` → `Version: **3.0.0** (last release tag, ceremony 2026-05-20 commit `1ee8dbb3`). Earlier release: v1.1.0 (2026-05-15). The post-v1.1.0 hardening series consolidated в v3.0.0: F-CLIENT-FACADE-1 milestone closure, Pass 5 remediation, Round 7 discovery merge, и Max Ratchet v3.`
- Line 447: `[docs/security/release-notes-v1.1.0.md](...)` → add new bullet referencing `docs/security/release-notes-v3.0.0.md` (keep existing 1.1.0 reference as historical)
- Russian equivalent line 543: «Версия: **1.1.0** (последний тег)...» → «Версия: **3.0.0** (последний тег, церемония 2026-05-20 commit `1ee8dbb3`). Предыдущий релиз: v1.1.0 (2026-05-15). Серия post-v1.1.0 hardening сведена в v3.0.0: закрытие F-CLIENT-FACADE-1, Pass 5 remediation, влитие Round 7 discovery и Max Ratchet v3.»

- [ ] **Step 2: Update crate inventory** (lines 117-146 EN + 585-610 RU)

Verify text: «`crates/umbrella-formal-verification`: 14 Tamarin + 4 ProVerif models» — already correct (verified earlier). Keep as-is.

Add explicit note под inventory: «`crates/umbrella-lints` is a separate sub-workspace outside the main Cargo workspace; the main workspace has 25 members (24 umbrella-* + xtask).»

- [ ] **Step 3: Update version mentioning in Russian section line 39 RU equivalent**

Russian text mirror update.

## Task A6: Rewrite `docs/README.md` к v3.0.0

**Files:**
- Modify: `docs/README.md` (lines 1, 9-10, 73-94, 247-265)

- [ ] **Step 1: Update version baseline в English section**

Replace «Umbrella Protocol 1.1.0» / «release tag `v1.1.0` plus a post-1.1.0 hardening series» → «Umbrella Protocol 3.0.0 (release tag `v3.0.0` ceremony 2026-05-20 commit `1ee8dbb3`; consolidates post-v1.1.0 hardening series)».

- [ ] **Step 2: Update version baseline в Russian section**

Mirror Russian update.

- [ ] **Step 3: Add release-notes-v3.0.0.md reference в section «Current release notes»**

После existing reference `security/release-notes-v1.1.0.md (1.1.0 baseline...)` добавить:
```markdown
- `security/release-notes-v3.0.0.md` (v3.0.0 release ceremony 2026-05-20).
```

## Task A7: Add v3.0.0 section to `CHANGELOG.md`

**Files:**
- Modify: `CHANGELOG.md` (line 7 — insert before)

- [ ] **Step 1: Insert v3.0.0 section above «Post-1.1.0 Max Ratchet v3 — 2026-05-20»**

After header `## English` (line 5), insert new section:

```markdown
### 3.0.0 — 2026-05-20

Release ceremony consolidating post-1.1.0 hardening:

Added:
- Max Ratchet v3 (default-on aggressive DH + 5-minute timer rekey + PQ extension every 3rd commit + SPQR HMAC deniable authentication); see `docs/audits/max-ratchet-deniability-spec-2026-05-20.md` + `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md`
- `umbrella-discovery` crate (Round 7: OPRF-PSI + `@username` lookup with KT bind; 38 D-1..D-8 attack tests)
- `umbrella-threshold-identity` crate (Round 6: FROST-Ed25519 DKG, PIN/Argon2id model, duress detection, time-lock recovery)
- 2 fuzz targets: `max_ratchet_envelope_{decode,roundtrip}.rs`
- 5 Tamarin models: `aggressive_dh_pcs`, `spqr_deniability`, `discovery`, `sealed_servers_threshold_3of5`, `sealed_servers_threshold_universal`
- Public wire-contract `docs/spec/discovery-integration.md`
- Backend integration contract `docs/integration/gateway-svc-contract.md`

Changed:
- Workspace package version: 1.1.0 → 3.0.0 (commit `1ee8dbb3`)
- F-CLIENT-FACADE-1 MILESTONE 10/10 closed (12 sub-sessions; commit `9417096b`)
- PhD-B Pass 5 remediation: 18 findings closed (20 commits `471e7928..23eda73a`)
- `ClientCore.identity`: `Option<Arc<IdentityKey>>` and `None` on hw bootstrap path; M-FINAL-1 closed via Pass 5 commit `e7b034ff` (F-CLIENT-HW-1)
- 6 Tamarin model tautologies replaced with substantive multi-rule correspondence lemmas
- 3 dudect measurement-artefact findings closed via bounded-pool pattern at sub-100 ns sites; F-DUDECT-HKDF-BORDERLINE-1 methodology documented в `docs/audits/dudect-saturation-methodology-2026-05-19.md`

Security:
- 0 BLOCKER + 0 MAJOR (M-FINAL-1 closed) + 1 MINOR-5 carry-over (FFI `with_http_cluster`)
- 14 Tamarin models verified under `tamarin-prover 1.12.0`; 4 ProVerif models (unchanged)
- Workspace baseline 2179+ release-mode tests (post-Round 7 floor; post-1.1.0 series adds further)

Verification: see `docs/security/release-notes-v3.0.0.md` § Verification.
```

- [ ] **Step 2: Russian mirror**

Перед line «Max Ratchet v3 после 1.1.0 — 2026-05-20» (line 276) вставить Russian section с тем же содержанием.

## Task A8: Rewrite `docs/security/current-status.md` к v3.0.0 + fix narrative contradiction

**Files:**
- Modify: `docs/security/current-status.md` (7 × «1.1.0» + lines 14, 52, 70, 182)

- [ ] **Step 1: Fix line 14 narrative contradiction**

Replace line 14 «remaining open item (F-CLIENT-FACADE-1 — chat-facade stubs) is a Block 7.4 engineering milestone, not a security finding» с «**F-CLIENT-FACADE-1 was a Block 7.4 engineering milestone (not a security finding); it has been CLOSED via session 10f commit `9417096b` MILESTONE 10/10 — see § ниже для подробного breakdown**. Integration contract for the closure is documented в `docs/integration/gateway-svc-contract.md`.»

(Sentence consistent с line 52 «F-CLIENT-FACADE-1 MILESTONE 10/10 CLOSED».)

- [ ] **Step 2: Replace 7 «1.1.0» mentions → «3.0.0»**

Use `grep -n "1\.1\.0" docs/security/current-status.md` для locate; replace each in context («Umbrella Protocol 1.1.0» → «Umbrella Protocol 3.0.0»). Keep historical references to `v1.1.0 release tag (2026-05-15)` where context is historical.

- [ ] **Step 3: Add «v3.0.0 release ceremony» summary section**

После update block «Update 2026-05-19» (line 6-65) добавить new update block «Update 2026-05-20 — v3.0.0 release ceremony» summarizing: F-CLIENT-FACADE-1 10/10 closure, Max Ratchet v3, version bump, CI v3.0.0 cleanup.

## Task A9: Rewrite `docs/security/protocol-core-attack-gates.md`

**Files:**
- Modify: `docs/security/protocol-core-attack-gates.md` (3 changes: R23 row line 64, add D-6/D-7/D-8 rows, layout reverse RU↔EN)

- [ ] **Step 1: Fix R23 row line 64**

Replace:
```markdown
| Идентичность | подделанный установочный пакет проходит обновление | закрыто тестом | `attack_r23_5_registry_detects_fake_version`: ≥4-of-5 registries должны совпасть |
```

With:
```markdown
| Идентичность | подделанный установочный пакет проходит обновление | закрыто тестом (decision-logic уровень) | `decision_logic_r23_5_registry_acceptance_gate`: ≥4-of-5 registries должны совпасть. Honest-naming closure per Pass 5 commit `f68c6fa6` (F-3); real Sigstore + CT pipeline integration остаётся operational milestone, не code carry-over. |
```

- [ ] **Step 2: Add D-6/D-7/D-8 rows after D-5 (lines 77-82)**

После D-5 row insert:

```markdown
| Discovery | reuse anon-ID между queries → linkability | закрыто тестом | `attack_d6_anon_id_reuse`: 10 000-iteration CSPRNG regression test; per-query `fresh_query_salt` CSPRNG by-construction |
| Discovery | rate-limit bypass via parallel sibling devices | закрыто тестом (client-side) + carry-over (server coordination) | `attack_d7_rate_limit_bypass`: `ClientBudgetState` 100/h + 5000/day enforced; server-coordination obligation в backend spec `rust_1mlrd` (out of repo) |
| Discovery | cardinality-timing side-channel | закрыто тестом (с измеренным residual) | `attack_d8_cardinality_timing`: HashSet lookup constant-time; padding policy advisory; measured ratio ≤2× per discovery cycle |
```

- [ ] **Step 3: Reverse layout to EN-first / RU-at-end**

Currently RU first (line 1 — line 102) → EN at end (line 103+).

Actions:
1. Read full file
2. Identify EN/RU sections
3. Rewrite с swapped order: EN section first (lines 1..N), `---` separator, RU section at end
4. Update anchor links `[English](#english) | [Русский](#русский)` to match new order

## Task A10: Rewrite `docs/security/production-readiness-boundaries.md` к v3.0.0 + EN-first

**Files:**
- Modify: `docs/security/production-readiness-boundaries.md`

- [ ] **Step 1: Update «2179+» baseline mention line 15**

Already says «2179+ release-mode tests» — keep as-is, OK (was verified).

- [ ] **Step 2: Update version baseline и v3.0.0 ceremony**

Replace v1.1.0-baseline language с «Umbrella Protocol v3.0.0 release» framing где applicable. Add «v3.0.0 ceremony 2026-05-20 commit `1ee8dbb3`» reference.

- [ ] **Step 3: Normalize layout to EN-first / RU-at-end**

Currently mixed (title/date RU, EN section, RU section). Restructure:
1. Title line: `# Production Readiness Boundaries` (English)
2. Bilingual anchors `[English](#english) | [Русский](#русский)`
3. Body EN section first
4. `---` separator
5. RU section at end

## Task A11: Fix `docs/integration/README.md` narrative-code mismatch

**Files:**
- Modify: `docs/integration/README.md` (line 54)

- [ ] **Step 1: Verify «Block 7.2 stub» comments в facade source**

```bash
grep -n "Block 7.2 stub" crates/umbrella-client/src/facade/*.rs
```

Expected:
- `crates/umbrella-client/src/facade/secret_chat.rs:92`
- `crates/umbrella-client/src/facade/cloud_chat.rs:373`

- [ ] **Step 2: Add narrative acknowledgment к README**

После line 54 (где упоминается «facade methods ... return a Block 7.2 stub») добавить bilingual note:

```markdown
> **Note (2026-05-20 reconciliation):** Some `facade/secret_chat.rs` и `facade/cloud_chat.rs` rustdoc fragments still reference «Block 7.2 stub» wording; that wording predates session 10f closure and is now historical. F-CLIENT-FACADE-1 MILESTONE 10/10 (commit `9417096b`) wired all listed methods. A separate session may refresh rustdoc to remove stale Block 7.2 stub mentions; the rustdoc text is not load-bearing for the wiring contract.
```

(Default = narrative ack, не trying to rewrite rustdoc в этой Phase A.)

## Task A12: Fix `docs/integration/gateway-svc-contract.md`

**Files:**
- Modify: `docs/integration/gateway-svc-contract.md` (line 150 SPEC-11 ref + line 244 post-closure stale)

- [ ] **Step 1: Replace SPEC-11 §4 reference line 150**

Replace:
```markdown
  family slot per SPEC-11 §4.
```

With:
```markdown
  family slot per private spec (working notes; see `docs/security/protocol-core-attack-gates.md` для public surface).
```

- [ ] **Step 2: Replace line 244 post-closure stale**

Replace:
```markdown
Future closure of F-CLIENT-FACADE-1 may include an explicit
```

With:
```markdown
F-CLIENT-FACADE-1 closure session 10f (commit `9417096b`) added an explicit
```

(Verify next-line context still consistent после edit.)

## Task A13: Rewrite `docs/comparison/umbrella-vs-messengers-2026-05-18.md` (6 drift items)

**Files:**
- Modify: `docs/comparison/umbrella-vs-messengers-2026-05-18.md` (lines 27, 236, 18, 200, 261, 213)

- [ ] **Step 1: Line 27 — «16 моделей» → «18»**

Replace:
```markdown
| E2E Audit | Yes | 16 формальных моделей Tamarin/ProVerif + 5 кругов PhD-уровня аудита |
```

With:
```markdown
| E2E Audit | Yes | 18 формальных моделей (14 Tamarin + 4 ProVerif) + 7 раундов PhD-B аудита (rounds 1-7 closed 2026-05-18; Pass 1-5 закрыты 2026-05-19) |
```

- [ ] **Step 2: Line 236 — second «16 моделей» mention**

Locate via `grep -n "16 моделей" docs/comparison/umbrella-vs-messengers-2026-05-18.md` (предполагается line 236). Replace «16 моделей в umbrella-formal-verification» → «18 моделей (14 .spthy + 4 .pv)».

- [ ] **Step 3: Line 18 — «2080+ тестов» → «2179+»**

Replace:
```markdown
| Active | Yes | Активная разработка, 2024-2026, baseline 2080+ тестов |
```

With:
```markdown
| Active | Yes | Активная разработка, 2024-2026, baseline 2179+ release-mode тестов (post-Round 7 floor; post-v1.1.0 серия добавляет ещё) |
```

- [ ] **Step 4: Line 200 — HW Keystore «Designed» → «Yes wired»**

Locate via `grep -n "Designed.*PersistentKeyStoreCallback\|HW Keystore" docs/comparison/umbrella-vs-messengers-2026-05-18.md`. Replace «Designed (PersistentKeyStoreCallback interface, M-FINAL-1 production wire-up для v1.2.x; сейчас demo wire-up)» с «Yes (PersistentKeyStoreCallback wired; HwBackedKeyStore eliminates in-heap seed + identity_sk; M-FINAL-1 closed Pass 5 commit `e7b034ff` F-CLIENT-HW-1; F-IDENT-1 + F-IDENT-2 closed commit `46784d1a`)».

- [ ] **Step 5: Line 261 — F-3 «Partial» → «Yes closed Pass 5»**

Locate via `grep -n "Partial.*cosign\|F-3 ship-decision" docs/comparison/umbrella-vs-messengers-2026-05-18.md`. Replace «Partial (cosign signed v1.0.0 + design 5-registry detection — F-3 ship-decision pending)» с «Yes (cosign signed releases + design 5-registry detection; F-3 closed Pass 5 commit `f68c6fa6` via honest-naming refactor `decision_logic_r23_5_registry_acceptance_gate`)».

- [ ] **Step 6: Line 213 — «13 lemmas» → «12 lemmas»**

Replace:
```markdown
- **Umbrella:** Yes (ADR-008 + formal Tamarin-verified multi_device_authorization.spthy — 13 substantive lemmas)
```

With:
```markdown
- **Umbrella:** Yes (ADR-008 + formal Tamarin-verified `multi_device_authorization.spthy` — 12 substantive lemmas)
```

## Task A14: Rewrite `docs/WORKING_RULES.md` bilingual EN-first + postulate 11

**Files:**
- Modify: `docs/WORKING_RULES.md` (full file restructure)

- [ ] **Step 1: Add EN section at top, RU at bottom**

Structure:
1. Title line: `# Working Rules / Рабочие правила`
2. Bilingual anchors `[English](#english) | [Русский](#русский)`
3. `## English` section — 15 postulates in English translation
4. `---` separator
5. `## Русский` section — existing 15 postulates Russian text

- [ ] **Step 2: Update postulate 11 в обоих языках**

Russian (line 27):
```markdown
11. **Документация пишется по-русски, простым языком.** Не прятать смысл за
```

Replace with:
```markdown
11. **Публичная документация — EN-first с Russian-секцией в конце**, простым языком. Внутренние рабочие правила (`WORKING_RULES.md`, closure-снимки audits, inverse-layout legacy файлы) могут быть RU-only по исключению. Не прятать смысл за
```

EN translation:
```markdown
11. **Public documentation — English-first with a Russian section at the end**, plain language. Internal working rules (`WORKING_RULES.md`, audit closure snapshots, inverse-layout legacy files) may be Russian-only by exception. Do not hide meaning behind
```

## Task A15: Phase A atomic commit

**Files:**
- All Phase A files staged

- [ ] **Step 1: Run acceptance grep checks (NEGATIVE — must return 0 hits)**

```bash
grep -rn "Version.*1\.1\.0.*last release tag\|Umbrella Protocol 1\.1\.0" README.md docs/README.md docs/security/current-status.md && echo "FAIL: 1.1.0 baseline still in Tier 1" || echo "PASS: no 1.1.0 baseline in Tier 1"
grep -rn "2080+ release-mode tests\|2080+ тестов" docs/security/ docs/comparison/ && echo "FAIL" || echo "PASS"
grep -rn "16 формальных моделей\|16 models\|16 Tamarin/ProVerif" docs/comparison/ && echo "FAIL" || echo "PASS"
grep -rn "attack_r23_5_registry_detects_fake_version" docs/security/ && echo "FAIL" || echo "PASS"
grep -rn "Future closure of F-CLIENT-FACADE-1 may include" docs/integration/ && echo "FAIL" || echo "PASS"
grep -rn "13 substantive lemmas.*multi_device_authorization" docs/comparison/ && echo "FAIL" || echo "PASS"
grep -rn "pgp-key\.asc" SECURITY.md && echo "FAIL: broken pgp-key.asc ref still in SECURITY.md" || echo "PASS"
grep -rn "SPEC-11" docs/integration/ && echo "FAIL: SPEC-11 ref still in integration docs" || echo "PASS"
```

Expected: all PASS.

- [ ] **Step 2: Run acceptance grep checks (POSITIVE — must return positive hits)**

```bash
ls docs/security/release-notes-v3.0.0.md docs/security/release-manifest-v3.0.0.txt docs/security/sbom-v3.0.0.json
grep -l "Version 3\.0\.0\|Umbrella Protocol 3\.0\.0\|version 3\.0\.0" README.md docs/README.md docs/security/current-status.md  # ≥3 hits
grep -l "3\.0\.0\|v3.0.0" CHANGELOG.md  # ≥1 hit
grep -l "D-6\|D-7\|D-8" docs/security/protocol-core-attack-gates.md  # ≥1 hit
grep -rn "decision_logic_r23_5_registry_acceptance_gate" docs/security/protocol-core-attack-gates.md  # ≥1 hit
grep -rn "18 формальных моделей\|18 моделей\|14 spthy + 4 pv\|14 Tamarin + 4 ProVerif" docs/comparison/  # ≥1 hit
grep -rn "12 substantive lemmas" docs/comparison/  # ≥1 hit
```

Expected: all positive hits.

- [ ] **Step 3: Verify `git diff --check`**

```bash
git diff --check
```

Expected: no whitespace errors.

- [ ] **Step 4: Stage all Phase A files**

```bash
git add README.md CHANGELOG.md SECURITY.md \
  docs/README.md \
  docs/security/release-notes-v3.0.0.md \
  docs/security/release-manifest-v3.0.0.txt \
  docs/security/sbom-v3.0.0.json \
  docs/security/current-status.md \
  docs/security/protocol-core-attack-gates.md \
  docs/security/production-readiness-boundaries.md \
  docs/integration/README.md \
  docs/integration/gateway-svc-contract.md \
  docs/comparison/umbrella-vs-messengers-2026-05-18.md \
  docs/WORKING_RULES.md
```

- [ ] **Step 5: Commit Phase A atomically**

```bash
git commit -m "$(cat <<'EOF'
docs(reconciliation): Phase A — Tier 1 rebuild к v3.0.0 baseline + bilingual EN-first

Closes 14 Tier 1 drift items per design 2026-05-20-docs-code-full-reconciliation-design.md §3 Tier 1:

NEW:
- docs/security/release-notes-v3.0.0.md — consolidated post-v1.1.0 series notes
- docs/security/release-manifest-v3.0.0.txt — verification manifest
- docs/security/sbom-v3.0.0.json — regenerated SBOM

REWRITE:
- README.md (root) — Version 3.0.0 + 25-member workspace + Max Ratchet v3 + Round 7
- docs/README.md — v3.0.0 baseline
- CHANGELOG.md — add v3.0.0 section consolidating post-1.1.0 series
- docs/security/current-status.md — v3.0.0 baseline + fix narrative contradiction (line 14 vs :52)
- docs/security/protocol-core-attack-gates.md — fix R23 stale name, add D-6/D-7/D-8 rows, EN-first layout
- docs/security/production-readiness-boundaries.md — v3.0.0 baseline, EN-first layout
- docs/integration/README.md — resolve narrative-code mismatch с facade/* rustdoc
- docs/integration/gateway-svc-contract.md — fix line 244 post-closure stale + SPEC-11 §4 ref
- docs/comparison/umbrella-vs-messengers-2026-05-18.md — 6 drift items (16→18 models, 2080→2179, HW wired, F-3 closed, 13→12 lemmas)
- docs/WORKING_RULES.md — bilingual EN-first + postulate 11 update (EN-first public docs)
- SECURITY.md — remove broken pgp-key.asc references

Verification: §4 acceptance grep checks all pass (no 1.1.0 baseline / no SPEC-11 / no attack_r23_5_registry stale name / no Future closure of F-CLIENT-FACADE-1 in Tier 1).

Source-of-truth: workspace v3.0.0 (commit 1ee8dbb3); 88 commits с v1.1.0; 25 workspace members + 1 sub-workspace; 18 formal models (14 .spthy + 4 .pv); 2179+ tests post-Round 7; 29 fuzz targets; 182 MlockedSecret usages; 12 lemmas в multi_device_authorization.spthy.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

Expected: commit succeeds; `git status` shows clean working tree.

- [ ] **Step 6: Verify commit on `main`**

```bash
git log -1 --format="%h %s" && git status --short --branch
```

Expected: most recent commit = «docs(reconciliation): Phase A — ...»; clean working tree.

---

# PHASE B — Tier 2 Limited-Touch

> ⚠ Phase B не commit'ит после каждой task — все edits stage'ятся до Task B12 (atomic commit).

## Task B1: Clarify `formal-lint-status-2026-05-13.md` «of 18 total»

**Files:**
- Modify: `docs/audits/formal-lint-status-2026-05-13.md` (line 20 + EN equivalent)

- [ ] **Step 1: Edit line 20 — annotation update**

Replace:
```markdown
| Tamarin models | `bash scripts/verify-tamarin-models.sh` | 0 | Passed (snapshot 2026-05-13: 9 Tamarin models verified). Post-1.1.0 the model count grew to 14: `aggressive_dh_pcs.spthy`, `spqr_deniability.spthy`, `discovery.spthy`, `sealed_servers_threshold_3of5.spthy`, `sealed_servers_threshold_universal.spthy` added across Round 7, Pass 5 remediation, and Max Ratchet v3 Task 5 PhD-B. |
```

With:
```markdown
| Tamarin models | `bash scripts/verify-tamarin-models.sh` | 0 | Passed (snapshot 2026-05-13: 9 Tamarin models verified). Post-v1.1.0 the Tamarin model count grew to 14 (additions: `aggressive_dh_pcs.spthy`, `spqr_deniability.spthy`, `discovery.spthy`, `sealed_servers_threshold_3of5.spthy`, `sealed_servers_threshold_universal.spthy` across Round 7 + Pass 5 + Max Ratchet v3 Task 5); plus 4 ProVerif models (`backup_wrap_v2.pv`, `oprf_ristretto255.pv`, `sealed_sender_v1.pv`, `sealed_sender_v2.pv`); **18 total formal models at HEAD `938d1a89` (v3.0.0)**. |
```

- [ ] **Step 2: Mirror в Russian section (line 53)**

Locate via `grep -n "9 Tamarin models" docs/audits/formal-lint-status-2026-05-13.md` — apply similar annotation in Russian.

## Task B2: Refresh `dudect-saturation-methodology-2026-05-19.md` к v3.0.0

**Files:**
- Modify: `docs/audits/dudect-saturation-methodology-2026-05-19.md` (lines 1, 8, 11-13, 30, 171, 286)

- [ ] **Step 1: Update title line 1**

Replace:
```markdown
# Dudect Saturation Methodology — Decision Document v2.0.0
```

With:
```markdown
# Dudect Saturation Methodology — Decision Document v3.0.0
```

- [ ] **Step 2: Update reconciliation note lines 11-15**

Replace:
```markdown
> **Versioning note (2026-05-20 reconciliation):** "v2.0.0" в этом
> документе referred to the intended next ship label. The most recent
> git tag is still `v1.1.0`; the `v2.0.0` ceremony (tag + cosign
> signing) is a separate administrative step tracked under the
> repository-root `CHANGELOG.md`.
```

With:
```markdown
> **Versioning note (2026-05-20 reconciliation, refresh 2):** This decision document was originally written with v2.0.0 as the intended next ship label; that label was skipped (workspace jumped 1.1.0 → 3.0.0, commit `1ee8dbb3` ceremony 2026-05-20, tag `v3.0.0`). All mentions of «v2.0.0» в этом документе should be read as «v3.0.0» — the substantive decision (SHIP with documented methodology limit + monthly cron) applies к v3.0.0.
```

- [ ] **Step 3: Replace remaining «v2.0.0» mentions (lines 8, 30, 171, 286)**

```bash
sed -i.bak 's/v2\.0\.0/v3.0.0/g' docs/audits/dudect-saturation-methodology-2026-05-19.md
rm docs/audits/dudect-saturation-methodology-2026-05-19.md.bak
```

(Verify line 1 title also updated; rerun Step 1 если sed missed it due to context.)

## Task B3: Annotate `full-fuzz-and-miri-run-2026-05-14.md` 27 → 29

**Files:**
- Modify: `docs/audits/full-fuzz-and-miri-run-2026-05-14.md` (lines 11, 46, 107)

- [ ] **Step 1: Add annotation banner at top**

Insert после frontmatter:

```markdown
> **Annotation (2026-05-20 reconciliation):** The «27 fuzz targets» counts на lines 11, 46, 107 reflect the snapshot at 2026-05-14. **Current HEAD `938d1a89` has 29 fuzz targets** — 2 added 2026-05-20 для Max Ratchet v3: `max_ratchet_envelope_decode.rs` + `max_ratchet_envelope_roundtrip.rs`. Other counts (0 panics, miri pass) are still accurate for the 27 targets in scope at audit time.
```

## Task B4: Annotate `local-release-hardening-status-2026-05-14.md` 27 → 29

**Files:**
- Modify: `docs/audits/local-release-hardening-status-2026-05-14.md` (lines 39, 43)

- [ ] **Step 1: Add same annotation as Task B3**

Insert similar banner: «Annotation (2026-05-20 reconciliation): «27 fuzz targets» refers к 2026-05-14 snapshot; HEAD now has 29 (Max Ratchet v3 pair added)».

## Task B5: Closure banner `r7_findings.md`

**Files:**
- Modify: `docs/audits/device-capture-artifacts/r7_findings.md`

- [ ] **Step 1: Insert closure banner at top of file**

After title line, before body, insert:

```markdown
> **CLOSURE BANNER (2026-05-20 reconciliation):** The CRITICAL findings F-PHD-DC-R7-1 / R7-2 / R7-3 documented в этом artifact are **CLOSED** as of:
> - Round 5 closure (`docs/audits/phd-b-device-capture-closure-2026-05-19.md`): R7-1, R7-2, R7-3 защищены через `HwBackedKeyStore` + `MlockedSecret<T>` + `IdentitySeed::Box<[u8; N]>` heap refactor;
> - Pass 5 remediation (`docs/audits/phd-b-pass5-remediation-2026-05-19.md`): F-IDENT-1 + F-IDENT-2 commit `46784d1a`; F-CLIENT-HW-1 commit `e7b034ff` closes M-FINAL-1.
> 
> This file remains as an archive of the round-4 audit findings at the time of writing.
```

## Task B6: Closure banner `r9_r11_findings.md`

**Files:**
- Modify: `docs/audits/device-capture-artifacts/r9_r11_findings.md`

- [ ] **Step 1: Insert closure banner at top**

```markdown
> **CLOSURE BANNER (2026-05-20 reconciliation):** F-PHD-DC-R9-1 + F-PHD-DC-R11-1 documented в этом artifact are **CLOSED** as of Round 5 closure (`docs/audits/phd-b-device-capture-closure-2026-05-19.md`). `MlockedSecret<T>` was added в `crates/umbrella-crypto-primitives/src/mlocked.rs` and wired across the workspace (current HEAD has **182 MlockedSecret usages**). This file remains as an archive of the round-4 audit findings at the time of writing.
```

## Task B7: Closure banner `r10_findings.md`

**Files:**
- Modify: `docs/audits/device-capture-artifacts/r10_findings.md`

- [ ] **Step 1: Insert closure banner at top**

```markdown
> **CLOSURE BANNER (2026-05-20 reconciliation):** F-PHD-DC-R10-1 (HW Keystore not wired) documented в этом artifact is **CLOSED** as of Round 5 closure + Pass 5 remediation: `PersistentKeyStoreCallback` trait wired через `ClientCore::new_with_hw_callback`; `HwBackedKeyStore` eliminates in-heap seed + identity_sk (commit `46784d1a`); `core.identity` is `Option<Arc<IdentityKey>>` and `None` on hw bootstrap path (commit `e7b034ff` F-CLIENT-HW-1 closes M-FINAL-1). This file remains as an archive of the round-4 audit findings at the time of writing.
```

## Task B8: Closure banner `r12_findings.md`

**Files:**
- Modify: `docs/audits/device-capture-artifacts/r12_findings.md`

- [ ] **Step 1: Insert closure banner at top**

```markdown
> **CLOSURE BANNER (2026-05-20 reconciliation):** F-PHD-DC-R12-1 + F-PHD-DC-R12-2 documented в этом artifact are **CLOSED** as of Round 5 closure + Pass 5 remediation. `Key::from_slice` stack-copy hardened via `Box<[u8; N]>` heap refactor + `MlockedSecret<T>` wrapping; application_secret live extraction prevented through HW keystore wire-up (R10-1 closure). This file remains as an archive of the round-4 audit findings at the time of writing.
```

## Task B9-B14: Plan historical-note prefixes (7 plan files)

**Files:**
- Modify: 7 plan files (Category 5)

- [ ] **Step 1: Template historical note**

```markdown
> **Historical note (2026-05-20 reconciliation):** This plan documents the pre-v3.0.0 implementation track for [<topic>]. The work has been superseded by:
> - <closure reference>
>
> The unchecked task boxes below are planning text, not the current active task list. Current status lives в `docs/security/current-status.md` + `docs/audits/ROUND-1-TO-7-SUMMARY.md`.
```

- [ ] **Step 2: Add historical-note prefix to each of 7 plans**

For each:
1. `plans/2026-05-13-documentation-truth-alignment.md` — closure ref: «v3.0.0 reconciliation pass (`docs/superpowers/specs/2026-05-20-docs-code-full-reconciliation-design.md`)»
2. `plans/2026-05-14-external-crypto-release-audit.md` — closure ref: «5-pass PhD-B sweep (`docs/audits/phd-b-pass5-remediation-2026-05-19.md`)»
3. `plans/2026-05-14-local-release-hardening.md` — closure ref: «Stage 9 closure + v3.0.0 ceremony»
4. `plans/2026-05-14-protocol-core-attack-gates.md` — closure ref: «Pass 5 ship-blocker closure + `docs/security/protocol-core-attack-gates.md`»
5. `plans/2026-05-14-protocol-core-final-gates.md` — closure ref: «F-CLIENT-FACADE-1 MILESTONE 10/10 (commit `9417096b`)»
6. `plans/2026-05-16-phd-recon-breadth-audit.md` — closure ref: «5-pass PhD-B sweep (Pass 1-5 closed 2026-05-18 + 2026-05-19)»
7. `plans/2026-05-20-max-ratchet-deniability.md` — closure ref: «Max Ratchet v3 10/10 (`docs/audits/max-ratchet-deniability-spec-2026-05-20.md`; commits `5907a9cd`, `bd17c571`, `078234b5`, `2b56ba7a`, `b1b9968a`, `7337afc7`, `87db7ad1`, `11805ba9`, `41f1cf71`, `62505ba4`)»

Each prefix goes between the `# Title` line and the first body section.

## Task B15: Phase B atomic commit

**Files:**
- All Phase B files staged

- [ ] **Step 1: Run acceptance grep checks**

```bash
# Negative
grep -rn "v2\.0\.0 ship\|SHIP for v2\.0\.0\|Decision Document v2\.0\.0" docs/audits/dudect-saturation-methodology-2026-05-19.md && echo "FAIL" || echo "PASS"
grep -rn "27 fuzz целей\|27 fuzz targets\|0 падений из 27" docs/audits/full-fuzz-and-miri-run-2026-05-14.md docs/audits/local-release-hardening-status-2026-05-14.md | grep -v "Annotation" && echo "FAIL: unannotated 27 still present" || echo "PASS"

# Positive
grep -l "v3\.0\.0" docs/audits/dudect-saturation-methodology-2026-05-19.md  # ≥1 hit
grep -l "18 total formal models\|14 spthy + 4 pv\|14 Tamarin + 4 ProVerif" docs/audits/formal-lint-status-2026-05-13.md  # ≥1 hit
grep -l "29 fuzz" docs/audits/full-fuzz-and-miri-run-2026-05-14.md docs/audits/local-release-hardening-status-2026-05-14.md  # ≥2 hits (если используется «29»)
grep -l "CLOSURE BANNER" docs/audits/device-capture-artifacts/r7_findings.md docs/audits/device-capture-artifacts/r9_r11_findings.md docs/audits/device-capture-artifacts/r10_findings.md docs/audits/device-capture-artifacts/r12_findings.md  # 4 hits
grep -l "Historical note (2026-05-20 reconciliation)" docs/superpowers/plans/2026-05-13-documentation-truth-alignment.md docs/superpowers/plans/2026-05-14-external-crypto-release-audit.md docs/superpowers/plans/2026-05-14-local-release-hardening.md docs/superpowers/plans/2026-05-14-protocol-core-attack-gates.md docs/superpowers/plans/2026-05-14-protocol-core-final-gates.md docs/superpowers/plans/2026-05-16-phd-recon-breadth-audit.md docs/superpowers/plans/2026-05-20-max-ratchet-deniability.md  # 7 hits
```

Expected: all PASS / positive hits.

- [ ] **Step 2: Stage all Phase B files**

```bash
git add docs/audits/formal-lint-status-2026-05-13.md \
  docs/audits/dudect-saturation-methodology-2026-05-19.md \
  docs/audits/full-fuzz-and-miri-run-2026-05-14.md \
  docs/audits/local-release-hardening-status-2026-05-14.md \
  docs/audits/device-capture-artifacts/r7_findings.md \
  docs/audits/device-capture-artifacts/r9_r11_findings.md \
  docs/audits/device-capture-artifacts/r10_findings.md \
  docs/audits/device-capture-artifacts/r12_findings.md \
  docs/superpowers/plans/2026-05-13-documentation-truth-alignment.md \
  docs/superpowers/plans/2026-05-14-external-crypto-release-audit.md \
  docs/superpowers/plans/2026-05-14-local-release-hardening.md \
  docs/superpowers/plans/2026-05-14-protocol-core-attack-gates.md \
  docs/superpowers/plans/2026-05-14-protocol-core-final-gates.md \
  docs/superpowers/plans/2026-05-16-phd-recon-breadth-audit.md \
  docs/superpowers/plans/2026-05-20-max-ratchet-deniability.md
```

- [ ] **Step 3: Commit Phase B atomically**

```bash
git commit -m "$(cat <<'EOF'
docs(reconciliation): Phase B — Tier 2 annotations + closure banners + plan historical-notes

Closes 16 Tier 2 drift items per design 2026-05-20-docs-code-full-reconciliation-design.md §3 Tier 2:

ANNOTATIONS:
- docs/audits/formal-lint-status-2026-05-13.md — clarify «of 18 total = 14 spthy + 4 pv»
- docs/audits/dudect-saturation-methodology-2026-05-19.md — refresh v2.0.0 (skipped) → v3.0.0
- docs/audits/full-fuzz-and-miri-run-2026-05-14.md — annotate 27 → 29 (max_ratchet pair added)
- docs/audits/local-release-hardening-status-2026-05-14.md — annotate 27 → 29

CLOSURE BANNERS (4 device-capture artifacts):
- docs/audits/device-capture-artifacts/r7_findings.md
- docs/audits/device-capture-artifacts/r9_r11_findings.md (note: 182 MlockedSecret usages at HEAD)
- docs/audits/device-capture-artifacts/r10_findings.md
- docs/audits/device-capture-artifacts/r12_findings.md

HISTORICAL-NOTE PREFIXES (7 superseded plans):
- plans/2026-05-13-documentation-truth-alignment.md (ironic: добавляет notes другим, у себя нет)
- plans/2026-05-14-external-crypto-release-audit.md (superseded by PhD-B Pass 5)
- plans/2026-05-14-local-release-hardening.md (superseded by Stage 9 closure)
- plans/2026-05-14-protocol-core-attack-gates.md (superseded by Pass 5 ship-blocker closure)
- plans/2026-05-14-protocol-core-final-gates.md (superseded by F-CLIENT-FACADE-1 10/10)
- plans/2026-05-16-phd-recon-breadth-audit.md (subsumed by 5-pass PhD-B sweep)
- plans/2026-05-20-max-ratchet-deniability.md (8 closure commits done)

All edits preserve Tier 3 archive integrity per design §2.7 archive policy.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 4: Verify clean working tree**

```bash
git status --short --branch
git log -3 --format="%h %s"
```

Expected: clean tree; last 3 commits = «docs(reconciliation): Phase B», «docs(reconciliation): Phase A», «docs(reconciliation): full docs↔code reconciliation design v2.0».

---

## Final Handoff

After Phase A + Phase B complete:

1. Push to `origin/main` (per `feedback_direct_to_main`):

```bash
git push origin main
```

2. Verify pushed state:

```bash
git log origin/main..main  # expected: empty (all pushed)
```

3. (Optional, separate session) Phase C — Memory cleanup:
   - Update `MEMORY.md` size optimization
   - Update `feedback_post_1_0_0_clusters_closed.md` body: «v2.0.0 ship-ready» → «v3.0.0 released 2026-05-20»
   - Update `project_post_1_0_0_clusters_closed.md` similarly

4. (Optional, separate session) Refresh `facade/secret_chat.rs:92` + `facade/cloud_chat.rs:373` rustdoc to remove «Block 7.2 stub» wording if user wants to close Category 3.5 fully on the source side (default = narrative ack в integration/README.md suffices).

5. Summarize в plain Russian:
   - все Tier 1 публичные docs синхронизированы с workspace v3.0.0;
   - 4 v3.0.0 release artifacts опубликованы;
   - Tier 2 annotations + closure banners + 7 plan historical-notes добавлены;
   - acceptance grep checks (negative + positive) все пройдены;
   - Tier 3 archive integrity сохранена (60+ session artifacts не тронуты).

## Self-Review Checklist

- [x] **Spec coverage:** Все 10 categories из design `2026-05-20-docs-code-full-reconciliation-design.md` §2 имеют corresponding tasks. Phase A покрывает Categories 1-3 (Tier 1) + 6 (layout standard); Phase B покрывает Categories 3 partial (annotations) + 4 (closure banners) + 5 (plan historical-notes). Categories 7 (Tier 3 archive — no action), 8 (memory — separate session), 9 (Tier 3 archive — closure banners cover relevant items), 10 (Tier 3 archive — no action) — explicit no-action documented.
- [x] **Placeholder scan:** Нет «TBD» / «TODO» / «fill in details». «Default decision» в Task A4 documented с rationale (safer = remove ref). SBOM regeneration в Task A3 has fallback path (copy + edit) if no script exists.
- [x] **Scope honesty:** Plan covers ровно Phase A + B. Phase C (memory cleanup) + facade rustdoc refresh — explicit deferred / optional «separate session» items. Не пытается переписать Tier 3 archives.
- [x] **File consistency:** Каждый modified/created файл listed в File Structure section и referenced в matching task. 14 Tier 1 + 16 Tier 2 = 30 changes total (including 4 NEW files в Tier 1).
- [x] **Type / signature consistency:** Не applicable (markdown-only changes, no code symbols). Filename references консистентны throughout (например `decision_logic_r23_5_registry_acceptance_gate` используется одинаково в Task A9 и в acceptance grep Task A15 Step 2).
