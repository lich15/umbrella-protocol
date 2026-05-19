# Промт для следующей сессии — Max Ratchet v3 финальные carry-overs

═══════════════════════════════════════════════════════════════════════
  UMBRELLA PROTOCOL v3 — Max Ratchet финальные carry-overs (после 2026-05-20)
═══════════════════════════════════════════════════════════════════════

## КОНТЕКСТ ПРОЕКТА

Криптомессенджер Umbrella Protocol — приложение для миллиарда пользователей
с защитой от противника уровня D из SPEC-01 § 4 (государственная разведка
+ организованная преступность с физическим доступом к устройству, 13 угроз).

Max Ratchet v3 — максимальный режим криптографической защиты + отрицаемая
аутентификация default-on для всех пользователей. **Реализация 10/10
acceptance criteria закрыта 2026-05-20.** Остались только feature polish
+ formal evidence carry-overs.

## РЕПОЗИТОРИЙ

- Главный: `/Users/daniel/Documents/Projects/Messenger/Umbrella Protocol`
- Бэкенд READ-ONLY: `/Users/daniel/Documents/Projects/Messenger/rust_1mlrd`
- Ветка: `main`
- HEAD: `7d6728ea` (bench(mls,max_ratchet): +2 SPQR scaling)
- **64 локальных коммита ahead of origin/main — НЕ push без явной команды**
- Рабочее дерево: чистое

═══════════════════════════════════════════════════════════════════════
  ЧТО УЖЕ ЗАКОММИЧЕНО ЗА 2026-05-20 (CONTINUATION)
═══════════════════════════════════════════════════════════════════════

7 коммитов:
1. `bd17c571` — Task 7 Criterion benchmarks Apple M2 (167.36 μs full, 0.26 μs SPQR)
2. `078234b5` — Task 4.7 Real X-Wing combine integration (6 PQ tests)
3. `2b56ba7a` — Task 6 CloudChat/SecretChat facade integration v3 marker 0xFF
4. `64063ac1` — +5 active-mode security claim tests + evidence matrix
5. `a0c29b67` — Cleanup pre-existing warning + cross-link docs
6. `128a9887` — +5 proptest fuzz tests (1280 random inputs, 0 panics)
7. `7d6728ea` — +2 SPQR scaling benchmarks (1.69 GB/s peak, cost model)

**Implementation 10/10 acceptance criteria CLOSED. Test coverage:**
- 30 max_ratchet unit tests + 10 baseline integration tests
- 6 PQ integration tests (Task 4.7 real X-Wing)
- 10 facade integration tests (5 baseline + 5 active-mode security claims)
- 10 envelope codec unit tests + 5 proptest fuzz tests
- 6 criterion benchmarks (Apple M2 production-grade numbers)

═══════════════════════════════════════════════════════════════════════
  ОСТАВШИЕСЯ CARRY-OVERS — 5 ЗАДАЧ В ПОРЯДКЕ ВЫПОЛНЕНИЯ
═══════════════════════════════════════════════════════════════════════

## ЗАДАЧА 1 (A-level, ~1-2 часа) — Counter PQ flag auto-route в facade

**Цель:** сейчас `MaxRatchetState::encrypt_with_rekey_authenticated` (используется
в facade) НЕ routes к `encrypt_with_rekey_pq_authenticated` автоматически даже
если group создан с ciphersuite 0x004D (PQ-hybrid). Это значит facade users на
PQ-ciphersuite не получают real X-Wing combine + PQ-extended SPQR HMAC. Только
direct callers `MaxRatchetGroup::encrypt_with_rekey_pq_authenticated` получают
real PQ.

**Что нужно:**
1. В `crates/umbrella-mls/src/max_ratchet/state.rs` добавить новый метод
   `encrypt_with_rekey_pq_authenticated_borrowed` который принимает
   `pq_provider: &impl OpenMlsProvider` + `group: &mut UmbrellaGroup` —
   parallel `MaxRatchetState::encrypt_with_rekey_authenticated` но routes
   к `UmbrellaGroup::force_rekey_with_pq` под `#[cfg(feature = "pq")]`.

2. В `crates/umbrella-client/src/facade/chat_common.rs::send_mls_text` добавить
   dispatch: если `group.ciphersuite().is_post_quantum_hybrid()` AND provider
   является `UmbrellaXWingProvider` — route к PQ-authenticated path; иначе
   classical path.

3. Compile gate: PQ path только под `feature = "pq"`. Без feature path не
   compile'ится → no runtime panic.

**Файлы:**
- `crates/umbrella-mls/src/max_ratchet/state.rs` — добавить ~50 LoC PQ method
- `crates/umbrella-mls/src/lib.rs` — re-export если нужно
- `crates/umbrella-client/src/facade/chat_common.rs` — dispatch logic ~30 LoC
- `crates/umbrella-client/src/core.rs` — возможно accessor для XWing provider
  если facade нужно identify provider type

**Acceptance:**
- `cargo test --features pq -p umbrella-mls` — passes
- Integration test: создать group с ciphersuite 0x004D + UmbrellaXWingProvider,
  send 3 messages через facade, verify `pq_extension_used` reflects counter
  triggers (3rd send true)
- 0 регрессий в существующих 71 max_ratchet tests

**Real evidence (не paperwork):**
- Test что PQ-routed send produces SPQR mac которая отличается от
  classical-routed send той же plaintext (proves real X-Wing keying в facade)

---

## ЗАДАЧА 2 (A-level, ~1 час) — ClientError::SpqrAuthFailed strict-error migration

**Цель:** сейчас при SPQR HMAC verification failure receiver возвращает в-band
marker string `<SPQR-AUTH-FAILED>` в text field `DecryptedMessage`. Это работает
для test visibility но в production user может увидеть garbage text. Лучше
fail-loud через `Result<Option<DecryptedMessage>>` либо filter out на caller
level.

**Что нужно:**
1. Изменить sigl `decrypt_text_with_fallback` в `chat_common.rs` с
   `-> String` на `-> Result<Option<String>, ClientError>`:
   - `Ok(Some(text))` — normal decrypt + verify OK
   - `Ok(None)` — silent drop (legacy fallback path либо empty)
   - `Err(ClientError::SpqrAuthFailed)` — explicit failure
2. В `fetch_mls_inbox`:
   - `Ok(Some(text))` → push в `DecryptedMessage` collection
   - `Ok(None)` → skip (don't push)
   - `Err(SpqrAuthFailed)` → `tracing::warn!` + skip (fail-closed silent
     drop в production; в integration tests можно assert error count)
3. Удалить in-band marker `SPQR_AUTH_FAILED_MARKER` constant.
4. Обновить existing tests которые ассертили marker text → теперь assert
   что message dropped (длина collection меньше expected).

**Файлы:**
- `crates/umbrella-client/src/facade/chat_common.rs` — refactor (~30 LoC)
- `crates/umbrella-client/tests/facade_max_ratchet_v3.rs` — update tests
  для new error semantics
- `crates/umbrella-client/src/error.rs` — SpqrAuthFailed уже добавлен в этой
  сессии (commit `2b56ba7a`) но не engaged — теперь engage

**Acceptance:**
- `cargo test -p umbrella-client` — passes (existing tests not relying на marker)
- New test: inject malformed SPQR mac → fetch_inbox returns collection без
  malformed message; can verify через mock that warn log emitted
- 0 регрессий

**Real evidence:**
- Tampered MAC fails verify (already covered Test #9 в `end_to_end_alice_send_bob_decrypt_with_spqr_verify`)
- Production: malformed message не попадает в user UI (fail-closed)

---

## ЗАДАЧА 3 (A-level, ~1-2 часа) — Cargo-fuzz harness для v3 envelope codec

**Цель:** Proptest даёт 1280 random inputs (256 iter × 5 tests). Cargo-fuzz +
libFuzzer даёт coverage-guided mutation, миллионы iterations, persistent
corpus. Это closing gap в robustness validation.

**Что нужно:**
1. `cargo install cargo-fuzz` (nightly Rust required; check rust-toolchain.toml)
2. Создать `crates/umbrella-client/fuzz/` workspace:
   ```
   fuzz/
     Cargo.toml
     fuzz_targets/
       try_decode_v3.rs
       roundtrip_encode_decode.rs
   ```
3. Fuzz target 1 — `try_decode_v3`:
   ```rust
   #![no_main]
   use libfuzzer_sys::fuzz_target;
   use umbrella_client::facade::max_ratchet_envelope::try_decode_v3;
   
   fuzz_target!(|data: &[u8]| {
       let _ = try_decode_v3(data);  // must not panic
   });
   ```
4. Fuzz target 2 — roundtrip:
   ```rust
   #![no_main]
   use libfuzzer_sys::fuzz_target;
   use umbrella_client::facade::max_ratchet_envelope::{encode_v3, try_decode_v3};
   
   fuzz_target!(|data: &[u8]| {
       if data.len() < 65 { return; }
       let (commit, ct) = data.split_at(32);
       let mut mac = [0u8; 32];
       mac.copy_from_slice(&ct[..32]);
       let ct_real = &ct[32..];
       let blob = encode_v3(Some(commit), ct_real, Some(&mac));
       let decoded = try_decode_v3(&blob).expect("encoded blob must decode");
       assert_eq!(decoded.ciphertext_bytes, ct_real);
       assert_eq!(decoded.spqr_mac, mac);
   });
   ```
5. Run в CI 30 минут per target → cumulative ~10M iterations.
6. Document в `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md`
   §5 (codec robustness) с numbers.

**Файлы:**
- `crates/umbrella-client/fuzz/Cargo.toml` NEW
- `crates/umbrella-client/fuzz/fuzz_targets/try_decode_v3.rs` NEW
- `crates/umbrella-client/fuzz/fuzz_targets/roundtrip_encode_decode.rs` NEW
- `.github/workflows/fuzz-envelope.yml` NEW — weekly CI cron pattern
  (mirror existing `.github/workflows/cargo-vet-weekly.yml` либо `dudect-benchmarks.yml`)

**Acceptance:**
- `cargo fuzz run try_decode_v3 -- -max_total_time=300` — 5 минут без panic
- `cargo fuzz run roundtrip_encode_decode -- -max_total_time=300` — 5 минут без mismatch
- Persistent corpus в `fuzz/corpus/` (~100 interesting inputs found by libFuzzer)
- CI workflow runs weekly + uploads corpus artifact

**Real evidence:**
- 5+ minutes of fuzzing = ~1-10M iterations (depending на throughput)
- 0 panics, 0 unwrap failures = robust envelope codec proven empirically

---

## ЗАДАЧА 4 (PhD-B level, ~3 часа) — Local dudect 1M+ samples для SPQR HMAC

**ВАЖНО:** Это PhD-B-level work per [[feedback-phd-level-mandatory]]. Применять
6-question self-check distinguisher per [[feedback-phd-vs-a-level-distinguisher]]
перед commit. Если 2+ checks fail = не claim PhD в commit.

**Цель:** Production-grade constant-time validation для `spqr::compute_hmac` +
`spqr::verify_hmac`. Upstream RustCrypto `subtle::ConstantTimeEq` audited но
**локальная dudect run** против compiled SPQR code даёт direct evidence что
compiler optimizations не вводят timing leak.

**Что нужно:**
1. Добавить dependency `rust-dudect = "0.5"` (или newer) в umbrella-mls
   `[dev-dependencies]`. Workspace lookup — может быть уже добавлен ранее в
   workspace для других dudect benches (`crates/umbrella-tests`).
2. Создать `crates/umbrella-mls/benches/dudect_spqr.rs`:
   ```rust
   use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
   use umbrella_mls::max_ratchet::spqr;
   
   fn dudect_compute_hmac(runner: &mut CtRunner, rng: &mut BenchRng) {
       // Two classes: zero-key vs random-key; same plaintext
       // Constant-time → no statistical difference in measured time.
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
   
   fn dudect_verify_hmac(...) { /* similar — verify_slice constant-time check */ }
   
   ctbench_main!(dudect_compute_hmac, dudect_verify_hmac);
   ```
3. Run: `cargo run --release --bench dudect_spqr -- --continuous --samples 1000000`.
4. Acceptance: t-statistic `|t| < 5` (RustCrypto dudect threshold) на 1M+ samples.
5. Document numbers в `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md`
   с reduction sketch:
   ```
   Claim: HMAC-SHA256 constant-time (compute + verify)
   Evidence: dudect 1M samples Apple M2, t = X.XX (|t| < 5 → no measurable leak)
   Comparison: same-key vs random-key, same plaintext → 0 timing signal
   ```
6. Add weekly CI workflow `.github/workflows/dudect-spqr.yml` mirror'я
   existing `dudect-benchmarks.yml` pattern.

**Файлы:**
- `crates/umbrella-mls/Cargo.toml` — add dudect-bencher dev-dep
- `crates/umbrella-mls/benches/dudect_spqr.rs` NEW
- `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md` — §4 SPQR
  Integrity update с dudect numbers
- `.github/workflows/dudect-spqr.yml` NEW

**6-question self-check перед commit:**
1. Findings count: real timing measurements + reduction sketch present? (need yes)
2. Test naming honesty: `dudect_*` adversarial naming (yes)
3. Engagement: full RustCrypto subtle implementation review (must read full source
   of `subtle::ConstantTimeEq` impl для validation)
4. dudect 1M+ samples confirmed (yes by design)
5. Reduction sketches with concrete numbers: t-statistic, sample count, bound
6. Literature engagement: cite Almeida-Barbosa-Pinto-Vieira «Formal Verification
   of Side-Channel Countermeasures Using Self-Composition» Sci Comput Prog 2013,
   Kocher 1996 «Timing Attacks», и Mac::verify_slice doc

**Если 2+ checks fail → не claim PhD в commit, либо handoff.**

---

## ЗАДАЧА 5 (PhD-B level, ~4 часа) — Tamarin/ProVerif formal model для SPQR deniability + aggressive DH PCS

**ВАЖНО:** Это PhD-B-level work. Если Tamarin/ProVerif не installed локально
либо нет experience с writing models — handoff с описанием trade-off per
[[feedback-phd-no-partial]].

**Цель:** Formal verification что:
1. **Deniability:** третье лицо (court adversary) видя только публичные
   transcripts + sender/receiver pubkeys НЕ может attribute MAC к specific
   party. Math proof через Tamarin trace logic.
2. **Aggressive DH PCS:** после force_rekey, compromised chain key at epoch N
   НЕ декрипчивает messages at epoch N+1. Already mostly proven через MLS
   spec proofs (Cohn-Gordon et al EuroS&P 2017); нужно extension lemma для
   per-message variant с force_rekey.

**Что нужно:**
1. Найти существующие модели в `crates/umbrella-formal-verification/models/`
   — может быть `mls_pcs.spthy` либо `signal_deniability.spthy`. Если есть —
   extend; если нет — write from scratch.
2. **Model 1:** SPQR deniability `crates/umbrella-formal-verification/models/spqr_deniability.spthy`:
   ```
   theory SPQRDeniability begin
   builtins: hashing, symmetric-encryption
   
   /* Setup: Alice and Bob share epoch_secret via MLS exporter chain */
   rule SharedEpochSecret:
     [ Fr(~es) ]
     --[ HasEpochSecret(A, ~es), HasEpochSecret(B, ~es) ]->
     [ EpochSecret(A, ~es), EpochSecret(B, ~es) ]
   
   /* MAC = HMAC(epoch_secret, message) */
   rule ComputeMACByAlice: ... 
   rule ComputeMACByBob: ...
   
   /* Lemma: indistinguishability — same MAC regardless of producer */
   lemma deniability_indistinguishability:
     "All m mac #i #j A B.
        ComputeMAC(A, m, mac) @ #i ∧ ComputeMAC(B, m, mac) @ #j
        ∧ HasEpochSecret(A, es) @ #k ∧ HasEpochSecret(B, es) @ #l
        ⟹ #i = #j ∨ (A = B)"  /* MAC bytes equal regardless of producer */
   ```
3. **Model 2:** Aggressive DH PCS `crates/umbrella-formal-verification/models/aggressive_dh_pcs.spthy`:
   ```
   /* Property: chain_key at epoch N does NOT decrypt messages at epoch N+1 */
   lemma per_message_pcs:
     "All n ck ct #i.
        ChainKeyExtracted(n, ck) @ #i ∧ Encrypted(n+1, ct) @ #j
        ⟹ ¬(K(ck) ∧ Decrypts(ck, ct))"
   ```
4. Run Tamarin: `tamarin-prover --prove spqr_deniability.spthy
   --output=spqr_deniability_proof.txt`. Acceptance: all lemmas pass либо
   honest exposure что lemma не доказывается + describe gap.
5. Document в `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md`
   §3 Deniability + §3.2 Forward Secrecy с proof references.

**Файлы:**
- `crates/umbrella-formal-verification/models/spqr_deniability.spthy` NEW
- `crates/umbrella-formal-verification/models/aggressive_dh_pcs.spthy` NEW
- `crates/umbrella-formal-verification/proofs/spqr_deniability_proof.txt` NEW
  (Tamarin output)
- `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md` — update
- `.github/workflows/formal-verification-weekly.yml` extend (если existing)
  с new model

**6-question self-check перед commit (PhD-B):**
1. Findings: при чтении модели проверить не tautological lemmas (per
   [[feedback-phd-pass-full-model-reading]]: read ALL .spthy, не только preamble)
2. Engagement: 80%+ reading model end-to-end + verify lemma actually proves
   claimed property
3. Reduction sketch: explicit DKDM (decision Diffie-Hellman key material)
   reduction для PCS lemma
4. Literature: cite Cohn-Gordon EuroS&P 2017, Borisov-Goldberg-Brewer WPES 2004,
   Alwen-Coretti-Dodis EUROCRYPT 2019

**Если Tamarin не installed либо не доказывает lemma → honest handoff с
описанием attempted lemma + где stuck.**

═══════════════════════════════════════════════════════════════════════
  ПРАВИЛА РАБОТЫ — ОБЯЗАТЕЛЬНЫ
═══════════════════════════════════════════════════════════════════════

1. **PUSH POLICY:** НЕ делать `git push` без явной команды пользователя.
   Сейчас 64 локальных коммита не отправлены.

2. **ПРЯМЫЕ КОММИТЫ В MAIN** per [[feedback-direct-to-main]]:
   ```bash
   git -c user.name="Kirill Abramov" -c user.email="samuel.vens18@gmail.com" \
     commit --author="Kirill Abramov <samuel.vens18@gmail.com>" -m "..."
   ```
   БЕЗ Co-Authored-By в commit messages.

3. **КОНТЕКСТ 60%** per [[feedback-context-60pct]]: работаем до 60% (~600K
   из 1M). При приближении либо прогнозе overrun — handoff в свежую сессию.

4. **TDD:** failing test → implement → passing test → commit. Каждая task
   закрывается одним атомарным коммитом.

5. **REAL EXPLOITS NOT PAPERWORK** per [[feedback-real-not-paperwork]]:
   каждый commit должен содержать измеренные numbers и/или реальные working
   tests demonstrating closure. Не Tamarin леммы в одиночку без real exploit
   attempts; не t-statistic без context.

6. **PHD-NO-PARTIAL** per [[feedback-phd-no-partial]]: только full closure
   либо honest handoff. Не «частично работающее». Для PhD-B claim — full
   6/6 self-check pass либо A-level honest commit.

7. **ПРОСТОЙ РУССКИЙ ЯЗЫК** per [[feedback-simple-language]]: при обсуждении
   объяснять простым русским языком, термины с пояснением в скобках. В
   коде/документах — полные термины на английском.

8. **READ rust_1mlrd ТОЛЬКО READ-ONLY:** никаких изменений в
   `/Users/daniel/Documents/Projects/Messenger/rust_1mlrd`.

9. **PhD-LEVEL ДЛЯ AUDIT WORK** per [[feedback-phd-level-mandatory]]: Задачи
   4 (dudect) + 5 (Tamarin) обязательно PhD-B level. Задачи 1-3 — A-level OK.

═══════════════════════════════════════════════════════════════════════
  MEMORY ОБЯЗАТЕЛЬНО ПРОЧИТАТЬ ПЕРВЫМ ШАГОМ
═══════════════════════════════════════════════════════════════════════

`~/.claude/projects/-Users-daniel-Documents-Projects-Messenger-Umbrella-Protocol/memory/`:

- `MEMORY.md` (индекс)
- `project_max_ratchet_v3_spec.md` (полное состояние v3 + acceptance + carry-overs)
- `feedback_real_not_paperwork.md` (правило real tests)
- `feedback_phd_level_mandatory.md` (PhD-B обязательно для audit work)
- `feedback_phd_no_partial.md` (только full closure либо handoff)
- `feedback_phd_vs_a_level_distinguisher.md` (6-question self-check)
- `feedback_direct_to_main.md` (workflow)
- `feedback_context_60pct.md` (бюджет)
- `feedback_simple_language.md` (язык обсуждения)

═══════════════════════════════════════════════════════════════════════
  ПЕРВЫЕ ШАГИ В НОВОЙ СЕССИИ
═══════════════════════════════════════════════════════════════════════

1. Прочитай этот промт + memory files выше параллельно
2. Запусти проверку текущего состояния:
   ```bash
   git log --oneline -8
   cargo test --offline -p umbrella-client --test facade_max_ratchet_v3 2>&1 | grep "test result"
   cargo test --offline -p umbrella-client --test max_ratchet_envelope_proptest 2>&1 | grep "test result"
   cargo test --offline --features pq,test-utils -p umbrella-mls --test test_max_ratchet_pq_real 2>&1 | grep "test result"
   ```
   Ожидаемое: facade 10/10 + proptest 5/5 + PQ 6/6 passing
3. Прочитай `docs/audits/max-ratchet-deniability-spec-2026-05-20.md` §7-8 — verify 10/10
4. Прочитай `docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md` — current evidence
5. Выбери задачу по приоритету:
   - **Рекомендуемый порядок:** Задача 1 (PQ flag in facade, A-level) →
     Задача 2 (SpqrAuthFailed migration, A-level) →
     Задача 3 (cargo-fuzz harness, A-level) →
     Задача 4 (dudect, PhD-B — может быть отдельная сессия) →
     Задача 5 (Tamarin, PhD-B — может быть отдельная сессия)
   - **Альтернатива:** если у пользователя приоритет formal evidence — начать
     с Задач 4 + 5 (PhD-B вначале)

6. Озвучь user одной фразой какую задачу выбираешь и почему, потом приступай.

═══════════════════════════════════════════════════════════════════════
  УСЛОВИЯ ОСТАНОВКИ / HANDOFF
═══════════════════════════════════════════════════════════════════════

- Контекст 60% approach → STOP + handoff с описанием состояния
- 6/6 self-check для PhD claim не достижим → A-level honest либо handoff
- Tamarin verification fails локально → debug либо handoff с описанием attempted
- Cross-cluster blocker (например, нужно изменение в rust_1mlrd backend) → STOP + ask user

═══════════════════════════════════════════════════════════════════════
  АДМИНИСТРАТИВНЫЕ ЗАДАЧИ ПОЛЬЗОВАТЕЛЯ (НЕ КОД)
═══════════════════════════════════════════════════════════════════════

Эти задачи требуют решения пользователя, я их не делаю автоматически:

1. **Push 64 локальных commits** — `git push origin main` после явной команды
2. **Tag ceremony v3.0.0** — `git tag -s v3.0.0 -m "..."` + cosign signing
3. **External crypto audit booking** — Cure53 / NCC / Trail of Bits
   (post-implementation contract с external firm)
4. **Production rollout planning** — coordinated client version bump (server
   gateway-svc proto unchanged)

ПРИСТУПАЙ.
═══════════════════════════════════════════════════════════════════════
