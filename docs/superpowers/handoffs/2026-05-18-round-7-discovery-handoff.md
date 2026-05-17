# Handoff — Round 7 Discovery (PhD-B), 2026-05-18

**Author:** Claude Opus 4.7 (1M context), prior session that closed rounds
1-6 via PR #6.
**Audience:** future session that opens round 7.
**Codebase state at handoff:** `main` @ `84b4d576` (post-PR-#6 merge,
post-docs refresh). Workspace baseline 2080 release-mode tests.

---

## 1. Why this handoff exists

Rounds 1-6 closed cryptanalysis + hedged-encaps + device-capture defense +
distributed-identity redesign on the **identity / on-device secrets** side
of the protocol. Round 7 turns to the **discovery** path — how a user
finds another user without leaking the address book to a server.

Two discovery primitives are in scope:

1. **Search by `@username`.** A user looks up another user by short
   handle. The server must not learn the handle in clear and must not
   correlate handles to account IDs across queries.
2. **Phone-number contact discovery via Private Set Intersection (PSI).**
   The client uploads phone numbers from the local address book to learn
   which contacts are already on Umbrella. The server must not learn the
   address book; the client must not learn anything beyond the
   intersection.

The round-2 OPRF reality pass already covered RFC 9497 OPRF on the
`umbrella-oprf` crate. The hard part is **end-to-end discovery**: PSI
protocol selection, server cluster model, batching, rate-limiting,
threshold quorum, replay protection, and KT (Key Transparency) bind so
that the discovery answer cannot be silently swapped.

---

## 2. Where the code is

Discovery code is partially present today; round 7 is mostly **net new**.

| Path                                                                  | Status                                                                                                            |
|-----------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| `crates/umbrella-oprf/`                                               | OPRF primitive crate. Ristretto255 + RFC 9497 attack-tested. Already used for backup unwrap and pending discovery. |
| `crates/umbrella-threshold-identity/src/anonymous_id.rs`              | HKDF-based 5-server anonymous-ID derivation introduced in round 6. Pattern is reusable for discovery anon-IDs.    |
| `crates/umbrella-oprf/src/lib.rs` (doc comment line 2)                | "Ristretto255 OPRF client for blinded contact discovery via Sealed Servers (3-of-5)" — this is the intended use site. |
| `crates/umbrella-server-blind-postman/src/router.rs`                  | Server-side routing. Discovery RPC routes will be added here.                                                     |
| `crates/umbrella-client/src/facade/chat_common.rs`                    | Client facade. Discovery API likely belongs here or in a new `discovery/` module.                                  |
| `crates/umbrella-discovery/`                                          | **Does not exist yet.** Round 7 should decide: new crate or module inside `umbrella-client`.                       |

The OPRF code is ready for the role of "blinded oracle". What is missing
is the PSI protocol layer (multi-batch oblivious lookup) and the discovery
client/server state machines.

---

## 3. Where the specifications live

Specifications relevant to discovery live in **two repos** because the
public protocol stack (`Umbrella Protocol`) and the private deployment
plans (`rust_1mlrd`) are separate codebases:

| Repo                                                                   | File                                                          | Notes                                                              |
|------------------------------------------------------------------------|---------------------------------------------------------------|---------------------------------------------------------------------|
| `Umbrella Protocol`                                                    | `.local-private/specs/SPEC-05-OPRF-CONTACT-DISCOVERY.md`      | Canonical spec for OPRF-based contact discovery. **Read first.**   |
| `Umbrella Protocol`                                                    | `.local-private/specs/SPEC-01-THREAT-MODEL.md`                | Adversary D (state-level); discovery applicable rows.              |
| `Umbrella Protocol`                                                    | `.local-private/specs/SPEC-OVERVIEW.md`                       | Cross-reference for SPEC-05 in the wider protocol context.         |
| `rust_1mlrd` (sibling repo)                                            | `docs/specs/` (sibling repo)                                  | Server-side discovery deployment, sharding, rate-limit policy.     |

`.local-private/` is git-ignored and not pushed to the public repo, so the
round-7 audit work must keep all references to those specs internal. The
public face of round 7 should live in `docs/audits/` + `docs/superpowers/
specs/` like rounds 1-6 did.

---

## 4. What round 7 should produce

Apply the round-1-through-6 pattern:

1. **Round 7 spec** at `docs/superpowers/specs/2026-05-XX-phd-b-discovery-design.md`.
   Topics: PSI protocol choice (Apple-style PSI-CA? RFC-style OPRF-PSI?
   Diffie-Hellman PSI? Cuckoo-filter assist?), state of art (CrypTen
   2020, Pinkas-Schneider-Zohner 2018), rate-limit story, threshold
   quorum, KT bind so server cannot swap the discovery answer, Sealed
   Sender compatibility for first-contact, denial-of-service surface,
   replay-protection, anonymous-id rotation.

2. **Round 7 PhD audit** at `docs/audits/phd-b-discovery-audit-2026-05-XX.md`.
   Adversary D from SPEC-01 §4. Real attack attempts in `attack_d*` test
   files in a new `crates/umbrella-discovery/tests/` (or wherever the
   crate boundary lands). Must include literature review of PSI attacks
   (membership inference, replay, padding attacks, side-channel from
   intersection-size disclosure, server-cluster collusion).

3. **Round 7 reality pass** at `docs/audits/phd-b-discovery-reality-pass-2026-05-XX.md`
   with end-to-end attack code. Examples to cover (from existing R-series
   pattern):
   - D-1: server learns plaintext phone numbers from blinded queries.
   - D-2: server correlates @username queries from the same client across
     time.
   - D-3: server returns a fake `device_pubkey` for the queried handle;
     KT bind must catch this.
   - D-4: 4-of-5 server cluster collusion still cannot recover the
     address book.
   - D-5: replay of an OPRF response to a different query.
   - D-6: anonymous-id reuse across queries → linkability.
   - D-7: rate-limit bypass via parallel queries from sibling devices.
   - D-8: timing side-channel from intersection-cardinality leak.

4. **Round 7 closure report** at `docs/audits/phd-b-discovery-closure-2026-05-XX.md`
   once the implementation lands the fixes. Same shape as the round-6
   closure: per-finding status, numerical results, acceptance gate, 6/6
   PhD self-check.

5. **Independent re-verification** as in round-1-6, fresh session, re-run
   every claim.

6. **Update**: `docs/audits/ROUND-1-TO-6-SUMMARY.md` to add a §12 "Round 7
   completion" pointer. Update the roadmap table accordingly.

---

## 5. Concrete files round 7 will need to create

```text
docs/superpowers/specs/2026-05-XX-phd-b-discovery-design.md
docs/audits/phd-b-discovery-audit-2026-05-XX.md
docs/audits/phd-b-discovery-reality-pass-2026-05-XX.md
docs/audits/phd-b-discovery-closure-2026-05-XX.md
docs/audits/phd-b-discovery-final-independent-review-2026-05-XX.md
docs/audits/phd-b-discovery-ledger-2026-05-XX.md

crates/umbrella-discovery/         (probable; or module inside umbrella-client)
crates/umbrella-discovery/src/lib.rs
crates/umbrella-discovery/src/psi.rs
crates/umbrella-discovery/src/username_lookup.rs
crates/umbrella-discovery/src/anonymous_query.rs
crates/umbrella-discovery/tests/attack_d1..d8.rs

crates/umbrella-server-blind-postman/src/discovery_routes.rs (or merge into router.rs)

crates/umbrella-client/src/discovery/  (client-side facade if not new crate)
```

Hook `umbrella-discovery` into the workspace `Cargo.toml` members list,
the `[workspace.dependencies]` table, and (if FFI exposure is in scope)
into `umbrella-ffi-swift` and `umbrella-ffi-kotlin`.

---

## 6. Pre-round-7 context the new session must read

In this order:

1. `docs/audits/ROUND-1-TO-6-SUMMARY.md` (this session's product) —
   establishes baseline.
2. `docs/audits/phd-b-final-independent-review-2026-05-19.md` — recall the
   M-FINAL-1 + MINOR-1..5 list; round 7 must not re-open them.
3. `.local-private/specs/SPEC-05-OPRF-CONTACT-DISCOVERY.md` — the protocol
   spec.
4. `.local-private/specs/SPEC-01-THREAT-MODEL.md` — adversary D row scope
   for discovery.
5. `crates/umbrella-oprf/src/lib.rs` — the OPRF primitive ready to be
   composed.
6. `crates/umbrella-threshold-identity/src/anonymous_id.rs` — reusable
   anonymous-ID derivation pattern from round 6.

Memory rules applicable (per index in `~/.claude/projects/.../memory/`):

- `feedback_phd_level_mandatory.md` — round 7 IS an active audit, so the
  PhD-B level requirement applies: Tamarin/ProVerif end-to-end + dudect
  1M samples for any constant-time-critical primitives + literature
  review (5+ papers on PSI) + reduction sketches with concrete numbers.
- `feedback_phd_no_partial.md` — full PhD-B (6/6 self-check pass) or
  handoff to fresh session. No "partial PhD apparatus".
- `feedback_phd_pass_full_model_reading.md` — read 100% of any
  Tamarin/ProVerif model used in the round, not just the preamble.
- `feedback_phd_vs_a_level_distinguisher.md` — apply the 6-question
  self-check before claiming PhD-B in the commit.
- `feedback_active_audit_mode.md` — real attack code in `attack_d*` test
  files, not synthetic boundary tests.
- `feedback_context_60pct.md` — stay under 60 % context; handoff before
  going over.
- `feedback_direct_to_main.md` — one block = one commit to `main`, no
  feature branches in the public repo. Rounds 1-6 used the
  `audit/phd-b-hybrid-pq-2026-05-19` branch + PR #6; round 7 may follow
  the same pattern if the work is large, or commit straight to `main` if
  it fits one session.
- `feedback_simple_language.md` — Russian explanations in the chat,
  English/Russian dual in the code and docs.

---

## 7. Open questions for round 7 to resolve

1. **PSI protocol choice.** Which PSI variant? Apple-style cuckoo +
   garbled circuit (Kales et al. CCS 2019) is fast but heavy on
   bandwidth. RFC-style OPRF-PSI (Pinkas-Rosulek-Trieu-Yanai 2018) is
   simpler but linear in set size. Round 7 spec must motivate the
   choice with concrete numbers (median address book 200-500 contacts,
   1 B user target).
2. **Anon-ID derivation.** Reuse the round-6 5-server HKDF anonymous-ID
   from `umbrella-threshold-identity::anonymous_id`? Or per-query
   ephemeral anon-IDs?
3. **KT bind.** How does the discovery response bind to a KT epoch so
   server cluster cannot swap a `(handle → device_pubkey)` mapping
   silently? Probably: the server returns the KT inclusion proof for
   the resolved device list at the discovery step.
4. **Sealed Sender compatibility.** First-contact discovery must not
   require the recipient's full device list — Sealed Sender V2 envelopes
   already work without that. Discovery should surface only the minimum
   needed to send the first envelope.
5. **Rate-limit + replay.** OPRF context (`umbrella-oprf`) already has
   server-nonce replay rejection. Discovery should reuse that or extend
   per-query state.
6. **Threshold cluster.** Round 6 used 5 Sealed Servers with 3-of-5
   threshold for identity. Discovery may need different thresholds or
   different clusters; round 7 spec must say.

---

## 8. Acceptance gate (proposed)

Round 7 acceptance gate, mirroring round 6 style:

1. PSI protocol formally verified (Tamarin or ProVerif). Lemmas:
   server-no-plaintext, client-no-extra-info, no-replay,
   anon-id-unlinkable.
2. `cargo test --release --workspace --all-features` green. Test count
   delta recorded.
3. 8+ D-series attack tests in `attack_d*` style.
4. KT bind end-to-end demonstrated: server cluster cannot return a
   fake device_pubkey without producing a verifiable KT inclusion proof
   that fails verification.
5. Independent reviewer fresh-session re-runs and signs off.

---

## 9. Reference to this session's discussion

This handoff was produced during the post-PR-#6 docs refresh on
2026-05-18. The decision to scope round 7 as discovery (rather than, say,
calls or storage migration) follows the natural ordering of the threat
model:

- Rounds 1-3 hardened the **encryption channel** (PQ, hedged-encaps).
- Rounds 4-5 hardened the **on-device key material** (device-capture).
- Round 6 hardened the **identity bootstrap** (distributed identity).
- Round 7 should harden the **first-contact lookup** (discovery).

Future rounds 8+ are likely group calls and KT-witness production
deployment.

---

**Status:** OPEN — ready for a fresh session to pick up.
