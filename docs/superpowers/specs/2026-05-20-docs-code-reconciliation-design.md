# Docs ↔ Code Reconciliation — Design

**Date:** 2026-05-20
**Author:** Claude Opus 4.7 (1M context) per user explicit directive
**Scope:** Inventory and resolution of drift between `/docs` and the
`main` branch state. The repository accumulated 76 commits since the
last release tag `v1.1.0` (Pass 5 closure + F-CLIENT-FACADE-1 milestone
10/10 + Max Ratchet v3 implementation + dudect/Tamarin PhD-B closures
+ post-Pass-5 carry-overs) without updates to the top-level public
documents. This design doc catalogs the drift, classifies each item,
and lists the targeted edits required to bring the public docs into
agreement with the current `main` HEAD `2028e69d`.

---

## 1. Method

For each public document under `/docs`, plus the repository-root
`README.md` and `CHANGELOG.md`, the doc claims about

- versioning (release tag, workspace package version);
- test counts (`cargo test --workspace --all-features` baseline);
- audit-finding status (CRITICAL / HIGH / MEDIUM open vs closed);
- file paths (cross-document links and code references);
- formal-model counts;
- crate inventory (which crates exist + their roles);
- public surface features (Max Ratchet v3 / aggressive DH / SPQR /
  discovery / threshold-identity)

are checked against:

1. `Cargo.toml` (workspace version + crate list);
2. `git log --oneline v1.1.0..HEAD` (76 unreleased commits);
3. `crates/<name>/src/` source headers and module structure;
4. `crates/umbrella-formal-verification/models/` filesystem (14
   `.spthy` + 4 `.pv` = 18 formal models);
5. recent in-tree memory cross-references where the user explicitly
   chose a divergent resolution.

Per `docs/WORKING_RULES.md` §7-8 — "Документы обновляются после каждого
изменения. Код и описание не должны расходиться" — and per the user
directive on 2026-05-20 — "привести протокол в соответствии с кодом" —
the resolution direction is **A: update docs to match current code**
in every drift item below, unless explicitly noted.

Closed-state audit reports (snapshots at the moment of closure) are
**NOT** rewritten — only their indices / cross-references are corrected.
That preserves the historical record while removing broken navigation.

---

## 2. Drift catalog

### Category 1 — Broken cross-references

| # | Item | Source file:line | Reality | Resolution |
|---|------|------------------|---------|------------|
| 1.1 | `ROUND-1-TO-6-SUMMARY.md` referenced as filename | `README.md:422`, `docs/README.md:28-29 + 186-187`, `docs/audits/INDEX.md:8`, `docs/security/production-readiness-boundaries.md:11`, `.local-private/specs/SPEC-OVERVIEW.md:126,157` | Actual file is `docs/audits/ROUND-1-TO-7-SUMMARY.md` (Round 7 added 2026-05-18) | Rename refs to `ROUND-1-TO-7-SUMMARY.md` |
| 1.2 | `docs/specifications/SPEC-01..SPEC-13 публичны` claim | `docs/comparison/umbrella-vs-messengers-2026-05-18.md:47` | SPEC-* normative files live in `.local-private/specs/` (not public); `docs/spec/` contains only `discovery-integration.md` | Change "Open Spec | Yes" justification to point at `docs/spec/discovery-integration.md` + public PDFs; drop SPEC-01..SPEC-13 path claim |
| 1.3 | `docs/spec/SPEC-01.md §4` ref | `docs/audits/max-ratchet-deniability-spec-2026-05-20.md:441` | No such public file | Change to `docs/security/protocol-core-attack-gates.md` + `.local-private/specs/SPEC-01-THREAT-MODEL.md` (internal pointer) |
| 1.4 | `docs/specs/` path in misc audit / handoff docs | `docs/audits/phd-b-final-consolidation-2026-05-18.md:343,585`, `docs/superpowers/handoffs/2026-05-18-phd-b-pass5-closed-remediation-handoff.md:23` | Same as 1.2 | **No action** — these are archived closure reports / handoffs (historical snapshots) |

### Category 2 — Status drift (docs OLD, code CURRENT)

| # | Item | Docs claim | Reality | Resolution |
|---|------|-----------|---------|------------|
| 2.1 | **F-CLIENT-FACADE-1** open / "closure planned across follow-up sessions" | `docs/README.md:95-100`, `docs/security/current-status.md:50-58`, `docs/integration/README.md:58-67`, `docs/integration/gateway-svc-contract.md:7-8,257-263`, `docs/audits/phd-b-pass5-remediation-2026-05-19.md:125-135` | **CLOSED** via commit `9417096b` (session 10f) → "F-CLIENT-FACADE-1 session 10f — initiate_device_transfer HW-signing+publish orchestration + 9 contract tests; MILESTONE 10/10 CLOSURE". All 12 sub-blocks (sessions 1-10f) on `main`. | Rewrite the "single open item" passages: F-CLIENT-FACADE-1 closed, 10/10 sessions on `main`; gateway-svc contract is the implemented surface, not a "future closure" plan |
| 2.2 | **Test count = 2080** | `docs/README.md:67-70`, `docs/security/current-status.md:83`, `docs/security/production-readiness-boundaries.md:14`, `docs/audits/phd-b-distributed-identity-closure-2026-05-19.md:35`, `docs/audits/phd-b-final-independent-review-2026-05-19.md:31` | 2080 was the **round-6 pre-round-7 baseline**. Round 7 + Pass 5 remediation + F-CLIENT-FACADE-1 session 1-10f + Max Ratchet v3 + dudect/Tamarin Tasks 1-5 added several hundred tests; ROUND-1-TO-7-SUMMARY §5 already records 2179 post-round-7. The current exact count requires a fresh `cargo test` run. | Replace "2080" with "2179+" in current-status / production-readiness / docs/README; the exact post-merge count is captured separately in a baseline refresh commit |
| 2.3 | **Tamarin models = 9** | `docs/audits/formal-lint-status-2026-05-13.md:20,53` | **14** `.spthy` files (added: `aggressive_dh_pcs.spthy`, `spqr_deniability.spthy`, `discovery.spthy`, `sealed_servers_threshold_3of5.spthy`, `sealed_servers_threshold_universal.spthy`) | Update to "14 Tamarin models verified"; 4 ProVerif unchanged |
| 2.4 | **Round 7 "awaiting PR review" on branch `audit/phd-b-discovery-2026-05-18`** | `docs/audits/ROUND-1-TO-7-SUMMARY.md:4-5`, `docs/audits/phd-b-discovery-closure-2026-05-18.md:201-203` | Local `git branch -a` shows only `main` (+ `origin/main`). `umbrella-discovery` crate is on `main`. Round 7 is merged. | Replace "awaiting PR" wording with "merged into `main`"; preserve closure-report content |
| 2.5 | **M-FINAL-1 still v1.2.x track** | `docs/audits/ROUND-1-TO-7-SUMMARY.md:144`, `.local-private/specs/SPEC-OVERVIEW.md:124-126,145-146` | **CLOSED** via Pass 5 commit `e7b034ff` (F-CLIENT-HW-1): `ClientCore.identity` → `Option<Arc<IdentityKey>>`, M-FINAL-1 disclosure block removed entirely. `current-status.md:21-29` already reflects this. | Mark M-FINAL-1 CLOSED in ROUND-1-TO-7-SUMMARY §2 / §9 Roadmap; preserve historical disclosure in the body but flag closure |
| 2.6 | **Max Ratchet v3 absent from public docs** | `README.md`, `docs/README.md`, `CHANGELOG.md`, `docs/security/release-notes-v1.1.0.md`, `docs/security/current-status.md`, `docs/security/protocol-core-attack-gates.md` — **0 mentions** | 5 modules in `crates/umbrella-mls/src/max_ratchet/` (config / counter / timer / spqr / group + state + envelope), 36 unit + 17 active-mode + 6 PQ + 5 proptest + 5 facade integration tests; 2 Tamarin models (`aggressive_dh_pcs.spthy` + `spqr_deniability.spthy`); benchmark numbers Apple M2 167.36 μs full overhead; closed as 10/10 acceptance criteria on 2026-05-20 | Add Max Ratchet v3 section to README.md, docs/README.md, CHANGELOG.md, current-status.md, protocol-core-attack-gates.md. Cross-link the two existing audit docs (`max-ratchet-deniability-spec-2026-05-20.md` + `max-ratchet-v3-security-evidence-2026-05-20.md`) |
| 2.7 | **Max Ratchet docs internal inconsistency** | `docs/audits/max-ratchet-deniability-spec-2026-05-20.md:4-5` says "Initial implementation merged (Tasks 1-5 of 8); facade integration + benchmarks pending follow-up sessions" but §8 says "10 of 10 implementation acceptance criteria achieved" | All 10/10 closed; §7.1-7.4 all CLOSED tags; commits `bd17c571` / `078234b5` / `2b56ba7a` on `main` | Fix the header status to match §8 |
| 2.8 | **Max Ratchet evidence "Not yet covered" stale** | `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md:341-346` lists dudect + Tamarin as carry-over | §4.1 already has 1M dudect numbers (Site 10 verify_hmac CLEAN 0.000 |t|) AND §2.1 / §3.1 already have Tamarin verification results for `aggressive_dh_pcs.spthy` / `spqr_deniability.spthy` (commits `b1b9968a`, `7337afc7`, `87db7ad1`) | Remove dudect + Tamarin from "Not yet covered"; retain only external-audit carry-over |
| 2.9 | **umbrella-discovery + umbrella-threshold-identity crates absent from public docs** | `README.md`, `docs/README.md`, `CHANGELOG.md`, `docs/security/release-notes-v1.1.0.md` — 0 mentions; only `docs/security/current-status.md` has 2 mentions | 2 production crates on `main` with 1.1.0 version stamps; Round 6 + Round 7 deliverables | Add both crates to crate inventory in README.md (root) §«Important crates» / «Главные папки» + docs/README.md crate map + CHANGELOG.md entry |
| 2.10 | **Round 7 absent from top-level docs** | `README.md`, `docs/README.md`, `CHANGELOG.md`, `docs/security/current-status.md`, `docs/security/release-notes-v1.1.0.md` — 0 "round 7" / "Round 7" mentions | Round 7 closure report + ledger + spec exist; `umbrella-discovery` crate on `main`; 2179 baseline | Mention Round 7 in CHANGELOG + docs/README + README repository map |
| 2.11 | **v1.2.x carry-overs that closed in Pass 5** | `docs/audits/ROUND-1-TO-7-SUMMARY.md:322-338` Roadmap lists M-FINAL-1, MINOR-4 (XOR-combine), MINOR-5 (FFI with_http_cluster), F-PHD-PQ-3 (downgrade_resistance) all as v1.2.x | Pass 5 closed: M-FINAL-1 (commit `e7b034ff`), MINOR-4 (commit `456ffe7f` Shamir Lagrange), F-PHD-PQ-3 (commit `c0082bc2` substantive lemmas). MINOR-5 OnboardingHandle `with_http_cluster` — not yet confirmed in code | Cross-out closed items in Roadmap with closure-commit references; leave MINOR-5 + F-PHD-PQ-{5,6,8} + R3-1 SLSA as open |
| 2.12 | **dudect-saturation-methodology referring to v2.0.0 ship** | `docs/audits/dudect-saturation-methodology-2026-05-19.md:1,8,165,280` "Decision Document v2.0.0" / "SHIP for v2.0.0" | Cargo.toml workspace version is `1.1.0`; no `v2.0.0` git tag; the commits referenced (`9417096b`, `76947fc0`) are post-1.1.0 unreleased. The v2.0.0 label is the document author's intended next ship label but the release ceremony hasn't run. | Acceptable as-is (decision document recording intent); add header note "v2.0.0 ceremony pending — `v1.1.0` is the most recent tag" |

### Category 3 — Public / private boundary leakage

| # | Item | Where | Resolution |
|---|------|-------|------------|
| 3.1 | "SPEC-01..SPEC-13 публичны" | `docs/comparison/umbrella-vs-messengers-2026-05-18.md:47` | Edited via 1.2 — restate as "open spec via public PDFs + `docs/spec/discovery-integration.md`" |
| 3.2 | ADR-006, ADR-013 references in public docs | `docs/audits/phd-b-pass5-remediation-2026-05-19.md:254-258` | Archived closure report (snapshot of internal references). **No action.** Pass 5 remediation report is the historical closure record; it stays as written |

### Category 4 — Version drift / release ceremony

| # | Item | State | Resolution |
|---|------|-------|------------|
| 4.1 | Cargo.toml workspace `1.1.0` | matches `v1.1.0` git tag | No action; this is the released version |
| 4.2 | 76 unreleased commits on `main` | post-1.1.0 ship-ready material (Max Ratchet v3 + F-CLIENT-FACADE-1 closure + Pass 5 remediation + Round 7 merge) | Author decision: tag ceremony `v2.0.0` (or `v3.0.0` if the author prefers to align with "Max Ratchet v3" naming) is an administrative step **outside** this reconciliation pass. This design records what should ship; the tag itself is a separate user action listed in the carry-over handoffs |
| 4.3 | SPEC-OVERVIEW.md (private) still describes "rounds 1-6 closed; M-FINAL-1 v1.2.x" | Private file; outdated against Round 7 + Pass 5 closures | Out of scope (private). Note as known divergence; user updates separately. Public docs are the authoritative source for this reconciliation |

### Category 5 — Stale handoffs

| # | Item | State | Resolution |
|---|------|-------|------------|
| 5.1 | `docs/superpowers/handoffs/2026-05-21-max-ratchet-v3-phd-b-tasks-4-5-handoff.md` describes Tasks 1-3 as A-level partial / 4-5 as PhD-B pending | Tasks 1, 2, 3, 4, 5 all CLOSED on `main` per latest 5 commits (`2028e69d` `87db7ad1` `7b94fc99` `7337afc7` `b1b9968a`) | Handoffs are session artifacts; **no action** — they are historical session records. The fact that the work continued past the handoff is itself information. ROUND-1-TO-7-SUMMARY / CHANGELOG updates will record the new closure state |
| 5.2 | Handoffs reference 64 / 68 local commits ahead of origin | Now 76 commits ahead | **No action** — same rationale as 5.1 |

---

## 3. Resolution direction summary

Per Category 2 (status drift), **A — update docs to match code** is
applied to every item:

- **Tier 1 (public-facing first-read documents)** — author edits in
  one atomic commit:
  - `README.md` (root)
  - `docs/README.md`
  - `CHANGELOG.md`
  - `docs/security/current-status.md`
  - `docs/security/release-notes-v1.1.0.md`
  - `docs/security/production-readiness-boundaries.md`
  - `docs/security/protocol-core-attack-gates.md`
  - `docs/audits/INDEX.md`
  - `docs/audits/ROUND-1-TO-7-SUMMARY.md`
  - `docs/comparison/umbrella-vs-messengers-2026-05-18.md`
  - `docs/integration/README.md`
  - `docs/integration/gateway-svc-contract.md`

- **Tier 2 (audit reports — only minor refresh)** — limited touch:
  - `docs/audits/formal-lint-status-2026-05-13.md` (Tamarin 9 → 14)
  - `docs/audits/max-ratchet-deniability-spec-2026-05-20.md` (header fix)
  - `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md`
    ("Not yet covered" trim)
  - `docs/audits/dudect-saturation-methodology-2026-05-19.md`
    (v2.0.0 ship-pending note)

- **Tier 3 (archived closure reports, handoffs, plans)** — **no edits**.
  They are historical snapshots and stay as written. Their indices
  (Tier 1 + INDEX.md) point at them with corrected paths if needed.

The result is a reconciled public document tree where:

1. Every cross-reference resolves to an existing file.
2. F-CLIENT-FACADE-1 status, test counts, formal-model counts,
   and v1.2.x carry-over closures match `main` HEAD.
3. Max Ratchet v3, Round 7 discovery, threshold-identity, and the
   24 crates are all visible in the top-level inventory.
4. Closed audit findings keep their closure reports as archives;
   their open/closed state in the index is current.

---

## 4. Non-goals

- Re-running `cargo test --workspace --all-features` to capture the
  exact post-merge test count. The reconciliation uses "2179+" (the
  Round 7 baseline confirmed in ROUND-1-TO-7-SUMMARY §5) as the floor;
  the precise number is captured separately when the author runs the
  full suite for the next release ceremony.
- Releasing a new git tag (`v2.0.0` / `v3.0.0`). The reconciliation
  prepares public docs for the ceremony; the ceremony itself is a
  separate administrative step.
- Updating `.local-private/specs/SPEC-OVERVIEW.md`. Private spec
  updates are out of scope; the user maintains those separately.
- Adding new audit findings or running a fresh PhD-B pass. The
  reconciliation is descriptive (matching docs to existing code), not
  prescriptive (no new audit work).
- Editing `docs/superpowers/{plans,specs,handoffs}/` content. Those
  are session artifacts and stay as written.

---

## 5. Acceptance criteria

After execution, the following grep checks return 0 hits in the
Tier 1 + Tier 2 files (excluding closure reports / handoffs):

- `grep -r "ROUND-1-TO-6-SUMMARY" docs/ README.md`
- `grep -r "closure planned across follow-up sessions" docs/`
- `grep -r "2080 release-mode tests" docs/`
- `grep -rn "docs/specifications/" docs/comparison/ docs/audits/INDEX.md`

And the following grep checks return positive hits:

- `grep -l "Max Ratchet" README.md docs/README.md CHANGELOG.md` — at
  least 3 files
- `grep -l "umbrella-discovery\|umbrella-threshold-identity" README.md docs/README.md CHANGELOG.md` — at least 3 files
- `grep -l "F-CLIENT-FACADE-1.*close\|MILESTONE 10/10\|10/10 sessions" docs/security/current-status.md docs/integration/README.md` — at least 2 files
- `grep -l "Round 7\|раунд 7" CHANGELOG.md docs/README.md` — at least 1 file

---

## 6. Implementation order

1. Top-level repository docs (README.md root + CHANGELOG.md).
2. `docs/README.md` index + Tier 1 status docs in `docs/security/`.
3. `docs/audits/INDEX.md` + `docs/audits/ROUND-1-TO-7-SUMMARY.md`.
4. `docs/integration/README.md` + `docs/integration/gateway-svc-contract.md`.
5. `docs/comparison/umbrella-vs-messengers-2026-05-18.md`.
6. Tier 2 limited-touch edits in `docs/audits/`.
7. Single atomic commit on `main` (per
   `feedback_direct_to_main.md` workflow), commit message
   referencing this design doc.

Execution proceeds in §6 order. The commit message records the
acceptance grep results inline.
