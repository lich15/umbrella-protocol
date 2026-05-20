# Docs ↔ Code Full Reconciliation — Design v2.0

**Date:** 2026-05-20 (session #67, post-v3.0.0 ceremony)
**Author:** Claude Opus 4.7 (1M context) per user directive «привести протокол в соответствии с кодом и документам чтобы не было расхождений»
**Supersedes:** `2026-05-20-docs-code-reconciliation-design.md` (predecessor design at HEAD `2028e69d`; partially executed via commit `de9b73bc`, then v3.0.0 ceremony invalidated several items)
**Scope:** Comprehensive drift inventory between `/docs` (105 `.md` files, 36 086 LoC) + repository-root meta-files (`README.md`, `CHANGELOG.md`, `PUBLIC_ACCESS.md`, `SECURITY.md`, `CONTRIBUTING.md`) and `main` HEAD `938d1a89`, plus resolution direction. Replaces the 2026-05-20 predecessor design (which targeted HEAD `2028e69d`, before the v3.0.0 release ceremony).

---

## 1. Method

For each public `.md` file under `/docs` plus the repository-root meta-files, the following claim categories are checked against source-of-truth:

- versioning (release tag, workspace package version);
- test counts (`cargo test --workspace --all-features` baseline);
- audit-finding status (CRITICAL / HIGH / MEDIUM open vs closed);
- file paths (cross-document links and code references);
- formal-model counts;
- crate inventory (which crates exist + their roles);
- public surface features (Max Ratchet v3 / aggressive DH / SPQR / discovery / threshold-identity);
- documentation layout standard (English-first vs Russian-first vs single-language).

Source-of-truth references:

1. `Cargo.toml` workspace `version = "3.0.0"`; **25 workspace members** (24 `crates/umbrella-*` + `xtask`); `crates/umbrella-lints/` is an **explicit sub-workspace** outside main workspace per its own header comment.
2. `git log v1.1.0..HEAD`: **88 commits since v1.1.0**; v3.0.0 tag created 2026-05-20 (commit `1ee8dbb3 chore(release): bump workspace version 1.1.0 → 3.0.0 для v3.0.0 ceremony`).
3. `crates/umbrella-formal-verification/models/`: **14 `.spthy` + 4 `.pv` = 18 formal models** (additions since v1.1.0: `aggressive_dh_pcs.spthy`, `spqr_deniability.spthy`, `discovery.spthy`, `sealed_servers_threshold_3of5.spthy`, `sealed_servers_threshold_universal.spthy`).
4. Workspace test baseline at Round 7: **2179** tests (`cargo test --release --workspace --all-features`); post-1.1.0 series (F-CLIENT-FACADE-1 10/10 + Pass 5 + Max Ratchet v3 + Tasks 1-5 PhD-B) adds further tests above that floor; exact post-v3.0.0 count requires a fresh `cargo test` run (captured separately in the release-ceremony pass).
5. Fuzz targets at HEAD: **29** (`crates/umbrella-fuzz/fuzz/fuzz_targets/`); includes `max_ratchet_envelope_decode.rs` + `max_ratchet_envelope_roundtrip.rs` added 2026-05-20.
6. `MlockedSecret` usage: **182 occurrences across the workspace**.
7. `multi_device_authorization.spthy`: **12 lemmas**.

Method execution: 7 parallel sub-agents read all 105 `.md` files in `/docs` completely (per user explicit requirement «без пропусков»); 6 source-of-truth files were read by the main session; ~20 numeric facts were verified via direct `grep` before this design was committed.

Per `docs/WORKING_RULES.md` postulate 7-8 — «Документы обновляются после каждого изменения. Код и описание не должны расходиться» — and per the user directive 2026-05-20 — «привести протокол в соответствии с кодом» — the resolution direction is **A: update docs to match current code** for active docs, **archive policy** for session-artifact files (specs/plans/handoffs/closure reports).

Closed-state audit reports (snapshots at the moment of closure) are **NOT** rewritten — only their indices / cross-references are corrected, and a 1-line closure banner is added where the carry-over status diverges materially from current state. That preserves the historical record while removing broken navigation.

---

## 2. Drift catalog

### Category 1 — 🔴 TOP-PRIORITY: v3.0.0 release ceremony incomplete in public docs

The `v3.0.0` git tag was created 2026-05-20 (commit `1ee8dbb3`), but Tier 1 public docs were not refreshed to reflect the v1.1.0 → v3.0.0 version jump or to publish v3.0.0 release artifacts. The predecessor design's commit `de9b73bc` updated docs to «v1.1.0 + post-1.1.0 series»; the version bump came afterwards and was not propagated.

| # | Item | Source file:line | Reality | Resolution |
|---|------|------------------|---------|------------|
| 1.1 | `docs/security/release-notes-v3.0.0.md` | absent in `docs/security/` | v3.0.0 tag exists; 10 commits since tag; major changes (F-CLIENT-FACADE-1 10/10 + Pass 5 + Round 7 + Max Ratchet v3 + CI v3.0.0 ceremony) | **CREATE** new file (English first, Russian at end) |
| 1.2 | `docs/security/release-manifest-v3.0.0.txt` | absent | same | **CREATE** new file |
| 1.3 | `docs/security/sbom-v3.0.0.json` | absent | same | **CREATE** new file (regenerate SBOM) |
| 1.4 | `README.md:39,48,60,77,447` | «Version: **1.1.0** (last release tag)» + 4 other 1.1.0 sites | last tag = v3.0.0 | **REWRITE** version line + add v3.0.0 release-notes link |
| 1.5 | `docs/README.md:1,9-10,73-94,247-265` | «Umbrella Protocol 1.1.0» | v3.0.0 | **REWRITE** version baseline |
| 1.6 | `CHANGELOG.md:7,49,74,98,115` | last entry «Post-1.1.0 Max Ratchet v3 — 2026-05-20» + 4 other 1.1.0 sites; **no v3.0.0 section** | v3.0.0 ceremony done | **ADD** v3.0.0 section consolidating post-1.1.0 series |
| 1.7 | `docs/security/current-status.md` (7 × «1.1.0» mentions) | «Umbrella Protocol 1.1.0» | v3.0.0 | **REWRITE** version baseline |

### Category 2 — Broken cross-references

| # | Item | Source file:line | Reality | Resolution |
|---|------|------------------|---------|------------|
| 2.1 | `docs/security/pgp-key.asc` referenced | `SECURITY.md:17,76` | **FILE MISSING** in `docs/security/` | **CREATE** file with real PGP fingerprint **OR** remove broken commitment |
| 2.2 | `SPEC-11 §4` referenced | `gateway-svc-contract.md:150` («family slot per SPEC-11 §4») | no SPEC-11 file in `docs/spec/` (only `discovery-integration.md`) | **REPLACE** with public-doc-internal anchor or remove SPEC-11 reference |
| 2.3 | `docs/specifications/SPEC-01..13` + `docs/adr/ADR-001..015` | `phd-b-final-consolidation-2026-05-18.md` body | no such directories — private specs live in `.local-private/specs/` | **No action** — Tier 3 archive closure report; historical snapshot |
| 2.4 | `endpoint_registry.rs` | `gateway-svc-contract.md:246` («may include») | not yet in `crates/umbrella-client/src/transport/` | **No action** — explicitly hedged forward-looking text |
| 2.5 | `attack_r23_5_registry_detects_fake_version` | `protocol-core-attack-gates.md:64` | real file: `decision_logic_r23_5_registry_acceptance_gate.rs` (F-3 Pass 5 commit `f68c6fa6` honest-naming closure) | **REWRITE** row to point at the renamed test |

### Category 3 — Status drift (docs OLD, code CURRENT)

| # | Item | Docs claim | Reality | Resolution |
|---|------|-----------|---------|------------|
| 3.1 | **`dudect-saturation-methodology-2026-05-19.md`** v2.0.0 cluster (7 mentions: title, lines 1, 8, 30, 171, 286 + recon-note 11-13 «v1.1.0 still latest tag») | v2.0.0 ship label | v2.0.0 was **skipped**: workspace 1.1.0 → 3.0.0 jump (commit `1ee8dbb3`), tag `v3.0.0` exists from 2026-05-20 | **REWRITE** to v3.0.0 throughout; refresh recon-note |
| 3.2 | **`comparison/umbrella-vs-messengers-2026-05-18.md` drift cluster** (6 items) | line 27/236 «16 моделей»; line 18 «2080+»; line 200 HW «Designed/demo wire-up»; line 261 F-3 «Partial ship-decision pending»; line 213 «13 substantive lemmas multi_device_authorization» | 18 models (14 + 4 pv); 2179+; HW Yes wired Pass 5; F-3 closed Pass 5; **12** lemmas (verified directly) | **REWRITE** 6 row corrections |
| 3.3 | `formal-lint-status-2026-05-13.md:20` | already inline-fixed 9 → 14 spthy («Post-1.1.0 the model count grew to 14») | total = 18 (14 spthy + 4 pv) — annotation does not state the 4 ProVerif models | **CLARIFY** «of 18 total = 14 Tamarin + 4 ProVerif» |
| 3.4 | `full-fuzz-and-miri-run-2026-05-14.md:11,46,107` + `local-release-hardening-status-2026-05-14.md:39,43` | «27 целей» / «27 fuzz targets» | **29** at HEAD (max_ratchet pair added 2026-05-20) | **ANNOTATE** with 2026-05-20 note «+2 max_ratchet targets» |
| 3.5 | `docs/integration/README.md` «10/10 closure» narrative | claims 10/10 closure across 12 sub-sessions | source `facade/secret_chat.rs:92` + `facade/cloud_chat.rs:373` still contain «Block 7.2 stub» rustdoc | **CHOICE**: update facade rustdoc to remove «Block 7.2 stub» wording **OR** add narrative-code mismatch acknowledgment to README |
| 3.6 | `current-status.md:14` «single remaining open item (F-CLIENT-FACADE-1 — chat-facade stubs) Block 7.4 engineering milestone» **vs** line 52 «F-CLIENT-FACADE-1 MILESTONE 10/10 CLOSED» | line 14 contradicts line 52 within the same file | F-CLIENT-FACADE-1 CLOSED via commit `9417096b` | **REWRITE** line 14 to match line 52 — narrative consistency |
| 3.7 | `gateway-svc-contract.md:244` «Future closure of F-CLIENT-FACADE-1 may include» | post-closure stale | F-CLIENT-FACADE-1 CLOSED commit `9417096b`; line 260 already says «sessions 1-10f implemented» | **REWRITE** line 244 to past tense / remove «may include» |
| 3.8 | `protocol-core-attack-gates.md` Discovery D-1..D-5 rows | only D-1..D-5 in gates table | D-6 / D-7 / D-8 attack test files exist (`attack_d{6,7,8}_*.rs`) | **ADD** D-6, D-7, D-8 rows to the gates table |

### Category 4 — Obsolete attack-artifact claims (Tier 3 — closure banners)

| # | Item | Resolution |
|---|------|------------|
| 4.1 | `device-capture-artifacts/r7_findings.md`, `r10_findings.md`, `r12_findings.md` — claim CRITICAL F-PHD-DC-R7-1/R10-1/R12 OPEN | **ADD** 1-line closure banner pointing to Pass 5 cluster (commits 471e7928..23eda73a) and `phd-b-distributed-identity-closure-2026-05-19.md` |
| 4.2 | `device-capture-artifacts/r9_r11_findings.md` — claim «secrets in RAM without mlock» pre-MlockedSecret | **ADD** 1-line closure banner: MlockedSecret wired (182 occurrences across workspace, 22 production sites) |

### Category 5 — Stale plans without `Historical note` prefix

7 plan files describe pre-3.0.0 work that has been superseded but lack the 1-line historical-note prefix used by the 3 plans that were properly marked (`production-attestation-gate`, `protocol-compliance-hardening-phase1`, `protocol-compliance-hardening-phase2`).

| # | File | Why superseded |
|---|------|----------------|
| 5.1 | `plans/2026-05-13-documentation-truth-alignment.md` | Replaced by the 2026-05-20 reconciliation (predecessor design + this design) — ironic, since this plan adds historical notes to others |
| 5.2 | `plans/2026-05-14-external-crypto-release-audit.md` | Subsumed by 5-pass PhD-B sweep + Pass 5 remediation |
| 5.3 | `plans/2026-05-14-local-release-hardening.md` | Subsumed by Stage 9 closure + Round 7 + v3.0.0 ceremony |
| 5.4 | `plans/2026-05-14-protocol-core-attack-gates.md` | Ship-blocker status closed at Pass 5 |
| 5.5 | `plans/2026-05-14-protocol-core-final-gates.md` | F-CLIENT-FACADE-1 10/10 separately addressed `new_with_http2` |
| 5.6 | `plans/2026-05-16-phd-recon-breadth-audit.md` | Subsumed by 5-pass PhD-B sweep (Pass 1-5 done 2026-05-18) |
| 5.7 | `plans/2026-05-20-max-ratchet-deniability.md` | 8 closure commits done (Tasks 1-9 all closed); no historical flag |

Action: **ADD** 1-line historical-note prefix to each of the 7 plans (cheap fix, preserves archive intent).

### Category 6 — 🆕 Cross-document layout standard inconsistency

`CONTRIBUTING.md:34,114` mandates «English first, Russian at end» for public Markdown documentation. Several active docs violate this:

| # | File | Layout |
|---|------|--------|
| 6.1 | `docs/WORKING_RULES.md` | Russian-only; postulate 11 (line 27) «Документация пишется по-русски» — internal contradiction with CONTRIBUTING.md doc-standard |
| 6.2 | `docs/security/protocol-core-attack-gates.md` | Russian first / English at end (inverse standard) |
| 6.3 | `docs/security/production-readiness-boundaries.md` | Mixed layout (title/date RU, EN section, RU section) |
| 6.4 | `docs/spec/discovery-integration.md` | English-only, no Russian section |
| 6.5 | `docs/audits/security-hardening-audit-2026-05-15.md` | RU-only (no EN mirror, while 05-16 and 05-17 audits are bilingual) |

**RESOLVED 2026-05-20: Option A — bilingual EN-first everywhere** (per user directive «привести протокол в соответствии с кодом и документам чтобы не было расхождений»):

- Add EN translation to `docs/WORKING_RULES.md` (currently RU-only).
- Reverse `docs/security/protocol-core-attack-gates.md` to EN-first / RU-at-end (currently inverse).
- Normalize `docs/security/production-readiness-boundaries.md` layout to EN-first / RU-at-end.
- Add RU section to `docs/spec/discovery-integration.md` (currently EN-only).
- Add EN mirror to `docs/audits/security-hardening-audit-2026-05-15.md` (currently RU-only, while 2026-05-16 and 2026-05-17 are bilingual).
- Update `docs/WORKING_RULES.md` postulate 11 from «Документация пишется по-русски, простым языком» to «Публичная документация — EN-first с Russian-секцией в конце; внутренние рабочие правила могут быть RU-only по исключению» (bilingual).

The Option B alternative (defer + document exceptions) was considered and rejected — it preserves layout heterogeneity that contradicts the public-doc standard mandated by `CONTRIBUTING.md`.

### Category 7 — Tier 3 archive policy (per existing design §4.4 — no action)

The following 60+ files are session artifacts and stay as written:

- All PhD-B Pass 1-4 sweeps + supplements (`phd-b-full-sweep-pass{1,2,2-supplemental,3,4,4-supplemental}-2026-05-18.md`)
- All round 1-7 closure reports + ledgers (`phd-b-hybrid-pq-{audit,reality-pass,hedged-encaps,ledger}-2026-05-19.md`, `phd-b-device-capture-{defense,closure}-2026-05-19.md`, `phd-b-distributed-identity-closure-2026-05-19.md`, `phd-b-discovery-{closure,ledger}-2026-05-18.md`, `phd-b-final-{consolidation-2026-05-18,independent-review-2026-05-19,pass5-remediation-2026-05-19}.md`)
- All Max Ratchet v3 spec + evidence files (`max-ratchet-{deniability-spec,v3-security-evidence}-2026-05-20.md`)
- All `device-capture-artifacts/` + `reality-pass-artifacts/` (10 per-finding artifact files)
- All `docs/superpowers/{specs,plans,handoffs}/` (54 files; specs = approved designs, plans = task lists, handoffs = session-to-session records)
- Tool policy docs (`cargo-deny-policy.md`, `dylint-rules.md`, `fuzz-runbook.md`, `miri-runbook.md`, `reproducible-builds.md`) — alive but minor v3.0.0 annotations only if material drift, otherwise no action
- Historical security audits (`security-hardening-audit-2026-05-{15,16,17}.md`) — archives, no edits beyond Category 4 closure banners

### Category 8 — Memory drift (separate cleanup track, not part of this commit)

| # | Item | Resolution |
|---|------|------------|
| 8.1 | `MEMORY.md` size warning «38.2KB exceeds 24.4KB limit» (index entries too long) | Split long index entries into topic files; keep `MEMORY.md` under ~150 chars per line |
| 8.2 | `project_post_1_0_0_clusters_closed.md` body says «v2.0.0 ship-ready pending push 54 локальных commits + tag ceremony» | Update to «v3.0.0 released 2026-05-20 (commit `1ee8dbb3` + tag pushed); 10 post-v3.0.0 commits are CI cleanup» |

---

## 3. Resolution direction summary

### Tier 1 (rebuild — one atomic commit on `main` per `feedback_direct_to_main`)

**Create**:

1. `docs/security/release-notes-v3.0.0.md`
2. `docs/security/release-manifest-v3.0.0.txt`
3. `docs/security/sbom-v3.0.0.json` (regenerate via existing SBOM tooling)
4. `docs/security/pgp-key.asc` (publish real fingerprint) **OR** strike broken commitment from `SECURITY.md`

**Rewrite**:

5. `README.md` root — Version 3.0.0 baseline, updated crate map (25 main-workspace members + 1 sub-workspace), feature matrix reflecting Max Ratchet v3 + Round 7 + F-CLIENT-FACADE-1 10/10
6. `docs/README.md` — Version 3.0.0 baseline
7. `CHANGELOG.md` — add v3.0.0 section consolidating post-1.1.0 series
8. `docs/security/current-status.md` — v3.0.0 baseline; fix line 14 vs line 52 narrative contradiction (Category 3.6)
9. `docs/security/protocol-core-attack-gates.md` — fix R23 row name (Category 2.5), add D-6/D-7/D-8 rows (Category 3.8), standardize EN/RU layout per Category 6 choice
10. `docs/security/production-readiness-boundaries.md` — v3.0.0 baseline, standardize layout per Category 6 choice
11. `docs/integration/README.md` — resolve narrative-code mismatch (Category 3.5)
12. `docs/integration/gateway-svc-contract.md` — fix line 244 post-closure stale text (Category 3.7); fix SPEC-11 §4 reference (Category 2.2)
13. `docs/comparison/umbrella-vs-messengers-2026-05-18.md` — 6 drift items (Category 3.2)
14. `docs/WORKING_RULES.md` — resolve postulate 11 vs CONTRIBUTING.md doc-standard per Category 6 choice

### Tier 2 (limited-touch annotations)

15. `docs/audits/formal-lint-status-2026-05-13.md` — clarify «of 18 total = 14 spthy + 4 pv» (Category 3.3)
16. `docs/audits/dudect-saturation-methodology-2026-05-19.md` — refresh to v3.0.0 throughout (Category 3.1)
17. `docs/audits/full-fuzz-and-miri-run-2026-05-14.md` + `local-release-hardening-status-2026-05-14.md` — annotate 27 → 29 (Category 3.4)
18. `docs/audits/device-capture-artifacts/{r7,r9_r11,r10,r12}_findings.md` — 1-line closure banners (Category 4)
19. 7 plan files (Category 5) — 1-line historical-note prefix each

### Tier 3 (no edit — archive policy)

20. All audit closure reports, ledgers, session artifacts, specs, handoffs, and tool-policy docs not enumerated in Tier 1/2 above. Stay as written. Their indices (Tier 1 `INDEX.md` + `ROUND-1-TO-7-SUMMARY.md`) point at them with corrected paths if needed.

### Memory cleanup (separate task — not part of this commit)

21. `MEMORY.md` size optimization (Category 8.1)
22. `project_post_1_0_0_clusters_closed.md` update (Category 8.2)

The result is a reconciled public document tree where:

1. Every cross-reference resolves to an existing file.
2. F-CLIENT-FACADE-1 status, test counts, formal-model counts, and v1.2.x carry-over closures match `main` HEAD.
3. Max Ratchet v3, Round 7 discovery, threshold-identity, and the 25 workspace members are all visible in the top-level inventory.
4. Closed audit findings keep their closure reports as archives; their open/closed state in the active docs is current.
5. v3.0.0 release ceremony artifacts (release notes, manifest, SBOM) are published for `v3.0.0` git tag.

---

## 4. Acceptance criteria

After execution, the following `grep` checks return **0 hits** in Tier 1 + Tier 2 files (excluding Tier 3 archives):

```bash
grep -rn "Version.*1\.1\.0.*last release tag\|Umbrella Protocol 1\.1\.0" README.md docs/README.md docs/security/current-status.md
grep -rn "2080+ release-mode tests\|2080+ тестов" docs/security/ docs/comparison/
grep -rn "16 формальных моделей\|16 models\|16 Tamarin/ProVerif" docs/comparison/
grep -rn "v2.0.0 ship\|SHIP for v2.0.0\|Decision Document v2.0.0" docs/audits/dudect-saturation-methodology-2026-05-19.md
grep -rn "attack_r23_5_registry_detects_fake_version" docs/security/
grep -rn "27 fuzz целей\|27 fuzz targets\|0 падений из 27" docs/audits/full-fuzz-and-miri-run-2026-05-14.md docs/audits/local-release-hardening-status-2026-05-14.md
grep -rn "Future closure of F-CLIENT-FACADE-1 may include" docs/integration/
grep -rn "13 substantive lemmas.*multi_device_authorization" docs/comparison/
```

The following `grep` checks return **positive hits**:

```bash
ls docs/security/release-notes-v3.0.0.md docs/security/release-manifest-v3.0.0.txt docs/security/sbom-v3.0.0.json
grep -l "Version 3\.0\.0\|Umbrella Protocol 3\.0\.0\|version 3\.0\.0" README.md docs/README.md docs/security/current-status.md  # ≥3 hits
grep -l "v3.0.0\|3\.0\.0" CHANGELOG.md  # ≥1 hit
grep -l "D-6\|D-7\|D-8" docs/security/protocol-core-attack-gates.md  # ≥1 hit (Discovery rows)
grep -rn "18 formal models\|18 моделей\|14 spthy + 4 pv\|14 Tamarin + 4 ProVerif" docs/audits/formal-lint-status-2026-05-13.md docs/comparison/  # ≥2 hits
grep -rn "29 fuzz" docs/audits/full-fuzz-and-miri-run-2026-05-14.md docs/audits/local-release-hardening-status-2026-05-14.md  # ≥2 hits
grep -rn "decision_logic_r23_5_registry_acceptance_gate" docs/security/protocol-core-attack-gates.md  # ≥1 hit
```

---

## 5. Implementation order

Implementation is handed off to the `writing-plans` skill which produces a task-by-task plan. The expected sequence:

1. **Phase A — version baseline rebuild (Tier 1 atomic commit)**:
   - Items 1-14 from §3 Tier 1 above
   - Single atomic commit on `main` per `feedback_direct_to_main`
2. **Phase B — Tier 2 annotations + closure banners (Tier 2 atomic commit)**:
   - Items 15-19 from §3 Tier 2 above
   - Single atomic commit on `main`
3. **Phase C — memory cleanup (separate session)**:
   - Items 21-22 from §3
   - Separate small commit; not blocking

Each phase ends with the acceptance `grep` checks from §4 above.

Category 6 layout-standard is **Option A — bilingual EN-first everywhere** (resolved 2026-05-20 per user directive). Phase A items 9, 10, 14 + the `protocol-core-attack-gates.md` row additions in item 9 + Phase B item 19 (7 plan historical-notes — bilingual) implement Option A.

---

## 6. Non-goals

- Re-running `cargo test --workspace --all-features` to capture the exact post-v3.0.0 test count. The reconciliation uses «2179+» (the Round 7 baseline confirmed in `ROUND-1-TO-7-SUMMARY.md` §5) as the floor; the precise number is captured separately when the author runs the full suite for the next release ceremony.
- Releasing a new git tag (`v3.0.1` or later). The reconciliation publishes v3.0.0 release artifacts that were missing; the v3.0.0 tag itself already exists.
- Updating `.local-private/specs/SPEC-OVERVIEW.md`. Private spec updates are out of scope; the user maintains those separately.
- Adding new audit findings or running a fresh PhD-B pass. The reconciliation is descriptive (matching docs to existing code), not prescriptive (no new audit work).
- Editing `docs/superpowers/{plans,specs,handoffs}/` content beyond the 7 plan historical-note prefixes in Tier 2 item 19. Specs and handoffs are session artifacts and stay as written.
- Editing `crates/` source code. Exception: if Category 3.5 resolution is «update facade rustdoc to remove Block 7.2 stub wording», that is a 2-line rustdoc edit (not a code-behavior change) and may be included in Phase B. Default: keep code untouched, add narrative acknowledgment to README.
- External cryptographic review (Cure53 / NCC / Trail of Bits). Pre-ship step tracked separately under `release-notes-v3.0.0.md` carry-overs.

---

## 7. Supersession note

This design supersedes `2026-05-20-docs-code-reconciliation-design.md` (the predecessor design at HEAD `2028e69d`). The predecessor design:

- Was partially executed via commit `de9b73bc docs(reconciliation): sync public docs with main HEAD per 2026-05-20 reconciliation pass` (closing predecessor §2 Categories 1-3 items 1.1, 2.1, 2.2-2.8, 2.9-2.11);
- Anticipated the v3.0.0 release ceremony as a separate administrative step (predecessor §4.2);
- Did not cover the post-version-bump drift (Category 1 above) because the version bump happened **after** the predecessor design was written;
- Did not cover the cross-document layout standard inconsistency (Category 6 above) which surfaced during the full-coverage parallel-agent read of all 105 `.md` files;
- Did not cover the narrative-code mismatch in `current-status.md:14 vs :52` and `docs/integration/README.md` vs `facade/` rustdoc (Categories 3.5, 3.6, 3.7).

The predecessor design stays in `docs/superpowers/specs/` as a Tier 3 archive (session artifact) per the archive policy.
