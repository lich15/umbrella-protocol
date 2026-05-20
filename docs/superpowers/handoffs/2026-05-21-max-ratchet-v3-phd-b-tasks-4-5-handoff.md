# Max Ratchet v3 — PhD-B Tasks 4-5 Handoff (2026-05-21)

## Контекст

Session 2026-05-21 продолжила handoff `2026-05-20-max-ratchet-v3-final-carry-overs-handoff.md` 5-task plan. **Закрыты 3 A-level задачи** (Tasks 1-3) тремя атомарными коммитами в main. **Остаются Tasks 4-5 PhD-B level** — handoff к следующей сессии с строгими требованиями.

## Закрыто за 2026-05-21 — 3 коммита

| # | Commit | Task | Status |
|---|---|---|---|
| 1 | `11805ba9` | Task 1 (PQ flag) | **Partial closure** — API gap (state.rs borrowed-mode method + 5 tests); facade dispatch carry-over к Stage 11+ (требует `pq_provider` field в ClientCore — sweeping refactor ~3-5 часов) |
| 2 | `41f1cf71` | Task 2 (SpqrAuthFailed migration) | **Fully closed** — strict-error refactor + 4 unit tests |
| 3 | `62505ba4` | Task 3 (cargo-fuzz) | **Fully closed** — 5.67M iterations / 0 panics + module relocation umbrella-client → umbrella-mls |

Test baselines post-session: 135/147 умbrella-mls (default/pq) + 479 умbrella-client + 5.67M fuzz iterations, 0 регрессий.

## Остающиеся Tasks 4-5 — PhD-B level (~7 часов total)

**ВАЖНО:** обе задачи **PhD-B mandatory** per [[feedback-phd-level-mandatory]]. Применять 6-question self-check [[feedback-phd-vs-a-level-distinguisher]] перед commit. Если 2+ checks fail → не claim PhD; либо honest A-level commit либо handoff к следующей сессии. **Запрет на «partial PhD wrapper»** [[feedback-phd-no-partial]].

## Task 4 (PhD-B, ~3 часа) — Local dudect 1M+ samples для SPQR HMAC

**Цель:** Production-grade constant-time validation для `spqr::compute_hmac` + `spqr::verify_hmac`. RustCrypto subtle::ConstantTimeEq audited upstream, но локальный dudect run против compiled SPQR code (Apple M2 + Linux GHA runner) даёт direct empirical evidence что compiler optimizations не вводят timing leak.

**Файлы для создания/изменения:**
- `crates/umbrella-mls/Cargo.toml` — добавить `dudect-bencher = "0.5"` в `[dev-dependencies]`
- `crates/umbrella-mls/benches/dudect_spqr.rs` NEW — 2 dudect benches (compute_hmac + verify_hmac)
- `.github/workflows/dudect-spqr.yml` NEW — weekly cron (mirror `.github/workflows/dudect-benchmarks.yml`)
- `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md` §4 — обновить с measured numbers

**Bench template:**
```rust
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use umbrella_mls::max_ratchet::spqr;

fn dudect_compute_hmac(runner: &mut CtRunner, rng: &mut BenchRng) {
    for _ in 0..100_000 {
        let class = if rng.next_u32() & 1 == 0 { Class::Left } else { Class::Right };
        let key = match class {
            Class::Left => [0u8; 32],
            Class::Right => {
                let mut k = [0u8; 32];
                rng.fill_bytes(&mut k);
                k
            }
        };
        let msg = [0x42u8; 256];
        runner.run_one(class, || spqr::compute_hmac(&key, &msg));
    }
}

fn dudect_verify_hmac(runner: &mut CtRunner, rng: &mut BenchRng) {
    // similar — verify_slice constant-time check;
    // mac classes: matching (Left) vs random tampered (Right)
}

ctbench_main!(dudect_compute_hmac, dudect_verify_hmac);
```

**Run:** `cargo run --release --bench dudect_spqr -- --continuous --samples 1000000`

**Acceptance:** t-statistic |t| < 5 на 1M+ samples (RustCrypto dudect threshold).

**6-question self-check перед commit:**
1. **Findings**: real timing measurements + reduction sketch present? (требуется yes)
2. **Test naming**: `dudect_*` adversarial naming with clear adversary scenarios (timing channel attacker measuring HMAC execution time)
3. **Engagement**: full RustCrypto subtle::ConstantTimeEq impl reading (verify Mac::verify_slice uses subtle internally)
4. **dudect 1M+ samples** confirmed (yes by design)
5. **Reduction sketches with concrete numbers**: t-statistic, sample count, computational bound (per HMAC-SHA256 PRF security ε ≤ 2⁻²⁵⁶ под Krawczyk 2010 Theorem 5)
6. **Literature engagement**: cite Almeida-Barbosa-Pinto-Vieira «Formal Verification of Side-Channel Countermeasures Using Self-Composition» Sci Comput Prog 2013 + Kocher 1996 «Timing Attacks on Implementations of DH, RSA, DSS, and Other Systems» + Krawczyk 2010 + Mac::verify_slice docs

Если 2+ checks fail → НЕ claim PhD в commit либо handoff.

## Task 5 (PhD-B, ~4 часа) — Tamarin/ProVerif formal model для SPQR deniability + DH PCS

**Цель:** Formal verification:
1. **Deniability**: третье лицо (court adversary) видя только public transcripts + sender/receiver pubkeys НЕ может attribute MAC к specific party. Math proof через Tamarin trace logic.
2. **Aggressive DH PCS**: после force_rekey, compromised chain key at epoch N НЕ декрипчивает messages at epoch N+1. Extension per-message variant с force_rekey.

**Prerequisites:** Tamarin prover installed locally. Если не installed — honest handoff per [[feedback-phd-no-partial]] с описанием attempted lemmas + где stuck.

**Файлы для создания/изменения:**
- `crates/umbrella-formal-verification/models/spqr_deniability.spthy` NEW
- `crates/umbrella-formal-verification/models/aggressive_dh_pcs.spthy` NEW
- `crates/umbrella-formal-verification/proofs/spqr_deniability_proof.txt` NEW (Tamarin output)
- `crates/umbrella-formal-verification/proofs/aggressive_dh_pcs_proof.txt` NEW
- `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md` §3 + §3.2 update
- `.github/workflows/formal-verification-weekly.yml` extension (если existing) либо NEW

**Model 1 sketch — SPQR deniability:**
```
theory SPQRDeniability begin
  builtins: hashing, symmetric-encryption

  rule SharedEpochSecret:
    [ Fr(~es) ]
    --[ HasEpochSecret(A, ~es), HasEpochSecret(B, ~es) ]->
    [ EpochSecret(A, ~es), EpochSecret(B, ~es) ]

  rule ComputeMACByAlice: ...
  rule ComputeMACByBob: ...

  lemma deniability_indistinguishability:
    "All m mac #i #j A B.
       ComputeMAC(A, m, mac) @ #i ∧ ComputeMAC(B, m, mac) @ #j
       ∧ HasEpochSecret(A, es) @ #k ∧ HasEpochSecret(B, es) @ #l
       ⟹ #i = #j ∨ (A = B)"
end
```

**Model 2 sketch — Aggressive DH PCS:**
```
lemma per_message_pcs:
  "All n ck ct #i.
     ChainKeyExtracted(n, ck) @ #i ∧ Encrypted(n+1, ct) @ #j
     ⟹ ¬(K(ck) ∧ Decrypts(ck, ct))"
```

**Run:** `tamarin-prover --prove spqr_deniability.spthy --output=spqr_deniability_proof.txt`

**Acceptance:** all lemmas pass либо honest exposure что lemma не доказывается + describe gap.

**6-question self-check перед commit:**
1. **Findings**: при reading модели проверить tautological lemmas per [[feedback-phd-pass-full-model-reading]] (read ALL .spthy line-by-line, не только preamble)
2. **Engagement**: **explicit LoC count claim** в commit message — «spqr_deniability.spthy lines 1-N of N (100%)» либо «lines 1-X of N (Y%)»
3. **Reduction sketch**: explicit DKDM (decision Diffie-Hellman key material) reduction для PCS lemma
4. **Literature**: cite Cohn-Gordon EuroS&P 2017 «Formal Security Analysis of MLS» + Borisov-Goldberg-Brewer WPES 2004 «Off-the-Record Communication» (original OTR deniability paper) + Alwen-Coretti-Dodis EUROCRYPT 2019 «The Double Ratchet: Security Notions, Proofs, and Modularization»

Если Tamarin не installed либо не доказывает lemma → honest handoff с описанием attempted lemma + где stuck. **Не claim PhD wrapper deliverables = PhD work** per session #66 lesson.

## Memory обязательно прочитать первым шагом

`~/.claude/projects/-Users-daniel-Documents-Projects-Messenger-Umbrella-Protocol/memory/`:

- `MEMORY.md` (индекс)
- `project_max_ratchet_v3_spec.md` (полное состояние v3 + Tasks 1-3 closure + 4-5 carry-overs)
- `feedback_real_not_paperwork.md` (правило)
- `feedback_phd_level_mandatory.md` (PhD-B обязательно)
- `feedback_phd_no_partial.md` (только full closure либо handoff)
- `feedback_phd_vs_a_level_distinguisher.md` (6-question self-check)
- `feedback_phd_pass_full_model_reading.md` (full model reading для Task 5)
- `feedback_direct_to_main.md` (workflow)
- `feedback_context_60pct.md` (бюджет)

## Repository state (2026-05-21 после Tasks 1-3 closure)

- Branch: main
- HEAD: `62505ba4` (Task 3 cargo-fuzz commit)
- **68 локальных коммитов ahead origin/main** — НЕ push без явной команды пользователя
- Working tree: clean
- Test baselines: 135/147 umbrella-mls + 479 umbrella-client + 5.67M fuzz iterations, 0 регрессий

## Правила работы — обязательны

1. **PUSH POLICY**: НЕ делать git push без явной команды пользователя
2. **ПРЯМЫЕ КОММИТЫ В MAIN** per [[feedback-direct-to-main]] (без feature branches, без Co-Authored-By)
3. **КОНТЕКСТ 60%** per [[feedback-context-60pct]] — при approach предупреждать + handoff
4. **TDD**: failing test → implement → passing test → commit (атомарно per task)
5. **REAL EXPLOITS NOT PAPERWORK** per [[feedback-real-not-paperwork]] — каждый commit измеренные numbers и/или real attack tests
6. **PHD-NO-PARTIAL** per [[feedback-phd-no-partial]] — только full closure либо honest handoff
7. **6-QUESTION SELF-CHECK** перед каждым PhD-B commit; если 2+ fail → не claim PhD
8. **READ rust_1mlrd ТОЛЬКО READ-ONLY**

## Первые шаги в новой сессии

1. Прочитай этот handoff + memory files выше параллельно
2. Запусти проверку текущего состояния:
   ```
   git log --oneline -5
   cargo test --offline --features pq,test-utils -p umbrella-mls --test test_max_ratchet_state_pq_real 2>&1 | grep "test result"
   cargo test --offline -p umbrella-client --lib facade::chat_common::tests 2>&1 | grep "test result"
   ```
3. Ожидаемое: 5/5 state PQ real + 5/5 chat_common::tests passing
4. **Решение** для следующей сессии — выбрать одну из 3 опций:
   - **Опция A (рекомендуемая)**: Сделать Task 4 (dudect, ~3 часа) в новой сессии. Если 6/6 self-check passes — commit. Иначе honest A-level либо handoff Task 5.
   - **Опция B**: Сделать Task 5 (Tamarin, ~4 часа) ОТДЕЛЬНО (требует full PhD attention). Risk: если Tamarin не installed — wasted exploration.
   - **Опция C**: Признать что обе задачи PhD-B + 7 часов scope требует **двух отдельных сессий**: Session A для Task 4, Session B для Task 5. Это safest per [[feedback-phd-no-partial]].

## Условия остановки / handoff в следующей сессии

- Контекст 60% approach → STOP + handoff
- 6/6 self-check для PhD claim не достижим → A-level honest либо handoff
- Tamarin/dudect не installed → honest handoff с описанием attempted
- Cross-cluster blocker → STOP + ask user

## Административные задачи пользователя (не код)

Сохраняются с предыдущего handoff:
1. Push 68 локальных commits — `git push origin main` после явной команды
2. Tag ceremony v3.0.0 — `git tag -s v3.0.0 -m "..."` + cosign signing
3. External crypto audit booking — Cure53 / NCC / Trail of Bits
4. Production rollout planning — coordinated client version bump
