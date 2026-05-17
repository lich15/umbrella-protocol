# PhD-B Device-Capture Defense — Design Spec

**Date:** 2026-05-19 (fourth round, separate scope from hybrid PQ)
**Predecessors:** rounds 1-3 audited hybrid PQ subsystem. This round audits device-capture resistance — orthogonal class.

**Goal:** Real-world resistance against state-level adversary with **physical access to running device**. Not algorithmic protocol defense (already done) — operating system + hardware integration.

## Threat model

State-level adversary captures user's device:
- Phone is **on**, user session **unlocked** (или recently active).
- Adversary has root / kernel access on captured device — can attach debugger, dump memory, read filesystem.
- Cannot extract data from hardware security modules (Secure Enclave on Apple, StrongBox / TEE on Android) without exploiting silicon-level vulnerabilities.

**Distinction from round 2 R6:** round 2 verified that `zeroize` actually wipes seed buffers post-keygen. Round 4 asks broader question: **what secrets remain in process memory while the app is running**, and what protections exist beyond software zeroize?

## Real attack hypotheses (must execute, not document)

### R7 — Live memory extraction of long-term identity secret
**Setup:** Build umbrella-client integration test that bootstraps a real identity (24-words → `identity_sk` derived → bootstrapped into KeyStore). Keep process alive. Attach `lldb`. Search process memory for `identity_sk` bytes (32-byte known constant from test fixture).

**Outcome:**
- **Found** → CRITICAL (no hardware-backed protection). State-level adversary with kernel access on captured device extracts identity → impersonate forever.
- **Not found** → secret is either hardware-resident OR cleverly hidden. Document mechanism.

### R8 — SQLite database file extraction (offline)
**Setup:** Run umbrella-client, bootstrap identity, exit cleanly. Copy SQLite database file from disk. Examine: are rows encrypted? What encrypts them (`row_cipher.rs` says ChaCha20-Poly1305 + master_key)? Where is master_key stored — in SQLite itself, in a separate file, in Keychain/Keystore, hardcoded?

**Outcome:**
- master_key on disk in any form → CRITICAL (offline file extraction = full compromise).
- master_key in OS hardware keystore → secure (modulo OS attack surface).
- master_key derived from user-entered passphrase → strong (knowledge-factor).
- master_key in process memory only, regenerated from elsewhere on bootstrap → trace where.

### R9 — Cold-boot / swap-out attack on running secrets
**Setup:** Bootstrap identity, force process to swap out (cgroup memory limit on Linux, similar on macOS). Read swap file. Search for secret bytes.

**Outcome:**
- Found in swap → HIGH (cold-boot attack vector real). Need mlock-equivalent.
- Not found / swap encrypted by OS → document OS-level mitigation.

### R10 — Hardware keystore integration audit
**Setup:** Audit existence and depth of integration with:
- iOS Keychain / Secure Enclave (`SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`)
- Android Keystore / StrongBox (`KeyGenParameterSpec.Builder.setIsStrongBoxBacked(true)`)

Currently visible artifacts: `crates/umbrella-ffi-kotlin/` and `crates/umbrella-ffi-swift/` exist but per memory `feedback_active_audit_mode` block 10.21 the native bridges are "skeleton" — not wired through `uniffi callback_interface` until Block 7.10 / Stage 9 hardening (per ADR-010 Решение 7).

**Outcome:**
- No real integration → HIGH (architecture gap documented as known limitation OR closed with stub design + roadmap).
- Partial integration → trace what works.

### R11 — Process memory protection at rest
**Setup:** Audit whether secrets in `SecretBox`/`Zeroizing` are also locked via `mlock` / `VirtualLock` to prevent swap.

**Outcome:** mostly documentary — secrecy crate's `SecretBox` uses zeroize on drop but does NOT mlock by default. Document gap.

### R12 — Process re-attach during normal operation
**Setup:** Real running app (or its closest test analog). User actively reading messages — keys cached for AEAD decrypt. Attacker attaches lldb, dumps **session ratchet state**. Can attacker decrypt subsequent (forward-secret-by-ratchet) messages?

**Outcome:** if ratchet state in memory → attacker can decrypt while session lives, but cannot rewind past forward-secret deletions. Document boundary.

## Anti-paperwork rules (round 4)

Same as round 2: each finding must be paired with real running attack attempt:
- R7-R12 each require actual code execution against actual build.
- "Bridges are skeleton" claim from memory must be verified against current code (read files, don't trust memory blindly).
- Tamarin not applicable (this is OS-integration, not protocol). Replace deliverable with platform documentation citations (Apple Platform Security Guide, Android Keystore Developer Docs).
- dudect not applicable.
- Reduction sketches not applicable. Replace with **threat-defense matrix**: rows = R7-R12, cols = (attempt result, defense mechanism, severity, owner).

## Required deliverables

1. **Real R7 lldb run** with documented result (found / not found).
2. **Real R8 SQLite file extraction** with documented master_key location.
3. **R9 swap analysis** — at minimum static analysis if dynamic swap-force impractical.
4. **R10 integration audit** — file-by-file enumeration of iOS/Android bridge code, document what's stub vs implemented.
5. **R11 mlock audit** — grep for mlock / VirtualLock in workspace, document gap.
6. **R12 ratchet capture test** — real test on `umbrella-mls` or `umbrella-sealed-sender` with active session.
7. **Findings table** with severities and concrete remediation paths.
8. **Hardware integration design** for whichever gaps are HIGH/CRITICAL — minimum spec-level (not implementation), but real, not handwave.
9. **Threat-defense matrix** appendix.
10. **Final report** `docs/audits/phd-b-device-capture-defense-2026-05-19.md`.
11. **Ledger update**.

## Branch

Continue on `audit/phd-b-hybrid-pq-2026-05-19` (round 3 commits already there). Round 4 commits on top. Single PR at end for all four rounds.

## Severity classification rule

**Realistic-adversary severity, not academic:**
- CRITICAL: device-captured adversary trivially extracts identity / past messages plaintext.
- HIGH: extraction requires moderate work (file inspection, swap dump), no OS-level barriers beyond normal app sandbox.
- MEDIUM: extraction requires kernel-level access AND specific app state (running, unlocked).
- LOW: extraction theoretically possible under specific OS-cooperation scenario.
- INFO: covered by existing defense, document where.

## Acceptance gate

All 6 attack hypotheses (R7-R12) attempted with **runnable code**:
- R7 lldb script + Python scanner (analog of round 2 R6).
- R8 actual SQLite file dump + binary inspection.
- R9 static analysis at minimum (mlock grep + swap config inspection on darwin).
- R10 file-tree enumeration with code excerpts.
- R11 grep + analysis.
- R12 integration test with key extraction attempt.

If hardware-backed defense gaps found → either implement stub + roadmap OR document as known gap with concrete v1.x roadmap line (not "carry-over to next round" without specifics).

## Stop / handoff

Memory `feedback_phd_no_partial`. If context budget runs short before R7-R12 all attempted → partial state documented in report, no PhD-B claim. Realistic estimate: 2-3 hours.

## Out of scope

- Cryptographic protocol algorithmic defense (rounds 1-3 covered).
- Server-side compromise (sealed-servers threshold already proved universal in earlier session).
- Network-level attacks (transport security separate scope).
- Supply-chain attacks (round 2 R3 covered, F-PHD-RP-R3-1 carry-over noted).

## Literature

- Apple Platform Security Guide May 2024 — Secure Enclave, Keychain Services
- Android Keystore System (developer.android.com/training/articles/keystore) — StrongBox-backed keys
- NIST SP 800-57 Part 1 Rev. 5 — Key Management
- USENIX 2020 "Cold Boot Attacks Are Still Hot" (Bauer et al)
- "Lest We Remember: Cold-Boot Attacks on Encryption Keys" (Halderman et al 2009) — historical reference

## What does NOT count (round 4)

- "Bridges are skeleton per memory" without re-verifying current code.
- Tamarin lemma about Secure Enclave (wrong layer).
- Pure documentation finding without `lldb` attempt for in-memory secrets.
- "Recommend Keychain integration" without spec showing actual API contract.
- Mark all gaps as "carry-over to Stage 11" without concrete severity classification and roadmap reference.
