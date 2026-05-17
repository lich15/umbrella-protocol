# PhD-style Active Red-Team Recon Audit — 2026-05-16

Author: Claude (Opus 4.7 1M) under owner direction.
Status: Design, awaiting plan after user approval.

## English

### 1. Goal

Run a recon-breadth security audit over the 21 Umbrella Protocol crates from a
D-level state adversary mindset. Goal: surface blind spots that the existing
`docs/security/protocol-core-attack-gates.md` matrix and the
`external-crypto-attack-ledger-2026-05-14.md` /
`external-crypto-attack-ledger-2026-05-15.md` do not yet name. Per finding,
write a failing attack test, fix the root cause, add the attack to the ledger,
and record the finding in `docs/audits/security-hardening-audit-2026-05-16.md`.

The output style follows the precedent of
`docs/audits/security-hardening-audit-2026-05-15.md`: short, evidence-first,
explicit about what is closed locally and what stays a release boundary.

### 2. Threat Model — D-level adversary

Aligned with SPEC-01 §4 and `SECURITY.md` out-of-scope:

- Full network MITM; compromised TLS root CA; BGP redirect; large passive
  collection for Store-Now-Decrypt-Later.
- Limited infra compromise: 2/5 Sealed Servers, OR t-1 KT witnesses at
  threshold t=3, OR a single rogue server in a routed-postman path.
- HSM-backed forgery rigs; cache-timing/dudect-class side-channel collection.
- Targeted device-side telemetry within the limits E2EE guarantees still hold
  (no plaintext key extraction by definition).

Out of scope (SECURITY.md):

- Social engineering of users or operators.
- Physical device access without a protocol attack.
- Volumetric DoS.
- Third-party CVEs with an upstream fix already in place.

### 3. Attack Categories — blind spots beyond the existing ledger

The ledger already covers tampering, replay, rollback, wire-format,
threshold, transport pinning, and `Debug`/log leakage. This round looks for
classes that are sparsely or not at all represented:

1. Cross-crate state-machine confusion.
2. Integer overflow / arithmetic edge cases (`usize`, durations, lengths).
3. Panic paths as DoS (`unwrap`, `expect`, indexing on untrusted input).
4. Error-message information leakage (`Display`, error variants with
   sensitive material).
5. Deserialization DoS (giant allocations, recursion, mempool exhaustion).
6. Race conditions outside replay (interleavings on signing oracles, two-phase
   operations, shared mutable state under contention).
7. FFI memory safety (UB on the Swift/Kotlin boundary, ABI mismatch,
   length-vs-capacity confusion, lifetime traps).
8. Error-handling fail-open (`Err` arms returning `Ok`, `continue` skipping
   verification).
9. Constant-time violations beyond MAC/eq (HashMap lookups, branchy code on
   secret-dependent values).
10. Log/Debug paths missed by the 2026-05-15 redaction pass.
11. Domain-separation collisions (HKDF labels, hash prefixes, context tags).
12. KDF context mistakes (salt reuse, info collisions across schemes).
13. Algorithm-agility version confusion (current ledger covers V1↔V2; check
   future bytes, feature-flag-based versioning, fall-through arms).
14. RNG fallback to non-CSPRNG; partially seeded generators.
15. TOCTOU on config, nonce, or policy checks.
16. Zeroize gaps in intermediate buffers (Vec growth, `BytesMut` realloc,
    panic-unwind paths).
17. Serde untrusted-bound bypass (no length cap on `visit_string`, unbounded
    `Vec<T>`, recursive `Option<Box<...>>`).
18. Stack overflow via recursive parsers.
19. Allocator-timing oracles.
20. Floating-point edge cases (subnormals, NaN) — unlikely in crypto but
    quickly scanned where applicable.

### 4. Per-tier approach

- **Tier 1 — deep (≈60% budget, 8 crates):** `umbrella-identity`,
  `umbrella-mls`, `umbrella-sealed-sender`, `umbrella-backup`, `umbrella-oprf`,
  `umbrella-pq`, `umbrella-crypto-primitives`, `umbrella-kt`.
  For each crate: enumerate `pub fn` entry points, trace untrusted-input
  data flow, map state machine if any, walk all 20 categories with a hypothesis
  → attack-test → root-cause loop.
- **Tier 2 — medium (≈25% budget, 5 crates):** `umbrella-client`,
  `umbrella-server-blind-postman`, `umbrella-padding`, `umbrella-calls`,
  `umbrella-platform-verifier`. Focus categories 1-6, 8, 14, 17.
- **Tier 3 — boundary (≈15% budget, 5 crates):** `umbrella-ffi`,
  `umbrella-ffi-swift`, `umbrella-ffi-kotlin`, `umbrella-core`,
  `umbrella-tests`. Focus categories 2, 3, 7, 8, 17 (FFI safety, panic,
  deserialization, fail-open).
- **Tier 4 — non-production (≤5% budget, 4 crates):** `umbrella-fuzz`,
  `umbrella-formal-verification`, `umbrella-vectors`, `umbrella-lints`. Quick
  sanity only; these are not in the production data path.

### 5. Per-finding workflow

1. Hypothesize a specific attack: "A D-level adversary with capability X can
   achieve impact Y through path Z."
2. Write a failing `attack_<class>_<specific>_<crate>` test that reproduces
   the attack end to end. Honest adversarial naming, not behavioral wrappers.
3. Confirm the test fails for the right reason (root cause per the
   systematic-debugging Phase 1 process). If it fails for an unrelated
   reason, re-form the hypothesis.
4. Implement a minimal fix that closes the root cause.
5. Verify: `cargo test -p <crate> --all-features --locked` is green; the new
   attack test passes; no regression in adjacent crates.
6. Update the ledger row in `docs/security/protocol-core-attack-gates.md`
   (local closed-by-test attacks) or the relevant external ledger.
7. Record the finding in `docs/audits/security-hardening-audit-2026-05-16.md`
   following the 2026-05-15 layout (area / what it was in plain terms / what
   was done).
8. Direct commit to `main`. One block = one commit (memory:
   `feedback_direct_to_main`).

### 6. Deliverables

- `docs/audits/security-hardening-audit-2026-05-16.md`.
- Per-finding: failing-then-passing attack test, code fix, ledger entry.
- Session handoff document if the 60% context budget is approached
  (`docs/audits/security-hardening-audit-2026-05-16-handoff-N.md`).

### 7. Stop conditions

- Context approaches the 60% budget (memory: `feedback_context_60pct`) →
  write handoff and stop.
- 3+ failed hypotheses in a single category (one of the 20 categories in
  §3) → move to the next category (systematic-debugging Phase 4.5: question
  the pattern, do not pile fixes).
- Tier 1 + Tier 2 + Tier 3 completed with zero new findings → honest negative
  result. No fabricated findings.

### 7a. Severity taxonomy

- **Critical:** E2EE bypass (plaintext recovery, sender unlinkability break),
  long-term key extraction, persistent integrity break, irrecoverable Sealed
  Sender / OPRF / KT trust break.
- **High:** Authenticated downgrade, replay across recipients/epochs, partial
  metadata leak, missing fail-closed on a release-critical path, panic-DoS
  reachable from untrusted wire input on a hot path.
- **Medium:** Information leak through `Debug`/logs of non-secret routing
  identifiers, integer-overflow without security impact, deserialization-DoS
  with localised effect, fail-open in a non-release-critical path.
- **Low:** Documentation drift, dead-code adversarial paths, hygiene
  (matchers, structure naming) without behavioural impact.

### 8. Honesty self-check

The 6-question PhD-vs-A distinguisher (memory:
`feedback_phd_vs_a_level_distinguisher`) is applied before any commit. Because
the user chose recon-breadth, this round is NOT B-level PhD (no Tamarin /
ProVerif full re-model, no per-finding dudect 1M samples, no IND-CPA/UF-CMA
reduction sketches). The audit report and commit messages must say
"recon-breadth pass, A-level rigor per finding with PhD-style adversary
mindset". Do not claim PhD level.

If a single finding warrants deeper PhD treatment (critical severity per §7a,
OR cryptographic-core finding where reduction is the only way to argue
soundness), call it out in the report and propose a follow-up B-deep session
for just that finding.

### 9. Verification gates after each fix

- `cargo fmt --all -- --check`.
- `cargo clippy -p <crate> --all-targets --all-features --locked -- -D warnings`.
- `cargo test -p <crate> --all-features --locked`.
- `bash scripts/audit-protocol-core-attack-gates.sh` if a row was added.
- `cargo test --workspace --all-features --locked` if a release-critical path
  was touched.

### 10. Resolved open questions

- **(a)** On a critical finding, pause the scan, fix immediately, commit, then
  resume. Do not batch criticals.
- **(b)** Real fuzz / miri / dudect runs only when a finding requires empirical
  proof. They are not on the standard per-finding gate list.
- **(c)** Zero findings is a valid outcome. The report will record the scan
  scope and an explicit "no new findings; existing ledger fully covers the
  reviewed surface" statement. No forced findings.

### 11. Non-goals

- No re-running of the existing 2026-05-15 hardening pass (already closed).
- No public FFI bootstrap completion (release boundary).
- No live KT witness deployment work (release boundary).
- No Apple App Attest / Play Integrity wiring (release boundary).
- No refactoring beyond what a fix requires (memory: no half-finished
  implementations, no "while I'm here" cleanup).

### 12. Done predicate

The audit round closes when one of these holds:

1. Tier 1 + Tier 2 + Tier 3 reviewed; all confirmed findings have an attack
   test, a fix, a ledger row, and a report entry; final commit on `main`;
   `bash scripts/audit-protocol-core-attack-gates.sh` and
   `cargo test --workspace --all-features --locked` are green.
2. Context budget at 60%: write handoff doc enumerating completed crates,
   open hypotheses, and remaining categories per tier; final commit on `main`.

---

## Русский

### 1. Цель

Активный recon-breadth аудит 21 крейта Umbrella Protocol от позиции
адверсария уровня D из SPEC-01 §4. Цель — найти то, что ещё не названо в
`docs/security/protocol-core-attack-gates.md`, и внешних реестрах от 14-15
мая. На каждую подтверждённую находку: failing-then-passing attack test,
минимальный fix, запись в реестре, запись в
`docs/audits/security-hardening-audit-2026-05-16.md`. Формат отчёта — как
2026-05-15: коротко, доказательства, честно про границы выпуска.

### 2. Модель угроз

Полный сетевой MITM, скомпрометированный root CA, BGP-перенаправление,
длительный пассивный сбор для Store-Now-Decrypt-Later; частичная
компрометация инфры (2 из 5 Sealed Servers либо t-1 свидетелей KT при
пороге t=3); HSM-стенды для подделки; cache-timing/dudect-уровень
side-channel; устройство-целевая телеметрия в пределах того, что не
ломает E2EE по определению.

Вне области (SECURITY.md): социальная инженерия, физический доступ без
протокольной атаки, объёмная DoS, чужие CVE с upstream-исправлением.

### 3. Классы атак — пробелы реестра

Тот же список 1-20 из английской секции 3. Существующие реестры закрывают
tampering/replay/rollback/wire-format/threshold/transport/Debug. Этот раунд
ищет: межкрейтовая путаница состояний, целочисленные переполнения, panic-DoS,
утечки через сообщения ошибок, deserialization-DoS, гонки за пределами
replay, FFI-памяти, fail-open в обработке ошибок, нарушения постоянного
времени за пределами очевидных, оставшиеся Debug/log paths, столкновения
domain separation, KDF-контексты, version confusion будущих байтов,
RNG-fallback, TOCTOU, zeroize-пробелы в промежуточных буферах, serde без
ограничений, recursion в парсерах, allocator-timing оракулы, плавающая
точка (если встретится).

### 4. Подход по уровням

- **Tier 1 — глубокий разбор (≈60% бюджета, 8 крейтов):** `umbrella-identity`,
  `umbrella-mls`, `umbrella-sealed-sender`, `umbrella-backup`, `umbrella-oprf`,
  `umbrella-pq`, `umbrella-crypto-primitives`, `umbrella-kt`. Для каждого
  крейта: перечисление `pub fn`, трассировка недоверенных данных, карта
  машины состояний при наличии, проход всех 20 классов с циклом гипотеза →
  атакующий тест → корневая причина.
- **Tier 2 — средний (≈25% бюджета, 5 крейтов):** `umbrella-client`,
  `umbrella-server-blind-postman`, `umbrella-padding`, `umbrella-calls`,
  `umbrella-platform-verifier`. Классы 1-6, 8, 14, 17.
- **Tier 3 — граница (≈15% бюджета, 5 крейтов):** `umbrella-ffi`,
  `umbrella-ffi-swift`, `umbrella-ffi-kotlin`, `umbrella-core`,
  `umbrella-tests`. Классы 2, 3, 7, 8, 17.
- **Tier 4 — небоевые (≤5%, 4 крейта):** `umbrella-fuzz`,
  `umbrella-formal-verification`, `umbrella-vectors`, `umbrella-lints` —
  быстрая проверка вменяемости.

### 5. Поток на находку

1. Сформулировать гипотезу: "Адверсарий с возможностью X достигает влияния Y
   через путь Z".
2. Написать падающий тест `attack_<класс>_<уточнение>_<крейт>` — реальное
   адверсариальное имя, не behavioral-обёртка.
3. Убедиться, что тест падает по правильной причине (Фаза 1 systematic-
   debugging). Если по другой — пересформировать гипотезу.
4. Сделать минимальное исправление корневой причины.
5. Проверить: `cargo test -p <крейт> --all-features --locked` зелёный,
   атакующий тест проходит, в соседних крейтах нет регрессий.
6. Обновить строку в `docs/security/protocol-core-attack-gates.md` либо во
   внешнем реестре.
7. Записать находку в `docs/audits/security-hardening-audit-2026-05-16.md`
   (формат 2026-05-15: область / простыми словами / что сделано).
8. Прямой коммит в `main`. Один блок = один коммит (память:
   `feedback_direct_to_main`).

### 6. Артефакты

- `docs/audits/security-hardening-audit-2026-05-16.md`.
- На находку: атакующий тест, исправление, строка реестра.
- Хэндофф-документ при приближении бюджета контекста к 60%.

### 7. Условия остановки

- Бюджет контекста ≈60% (память: `feedback_context_60pct`) → handoff и стоп.
- 3+ неудачных гипотезы в одном классе (один из 20 классов §3) → переход к
  следующему классу.
- Tier 1 + Tier 2 + Tier 3 пройдены без новых находок → честный negative
  result. Без выдуманных находок.

### 7а. Таксономия серьёзности

- **Critical:** обход E2EE (раскрытие plaintext, слом Sealed Sender
  unlinkability), извлечение долгоживущего ключа, постоянный слом
  целостности, невосстановимый слом доверия Sealed Sender / OPRF / KT.
- **High:** подделанное понижение алгоритма, replay между получателями или
  эпохами, частичная утечка метаданных, отсутствие fail-closed на боевом
  пути, panic-DoS из недоверенного wire input на горячем пути.
- **Medium:** утечка через `Debug`/логи нечувствительных routing-идентификаторов,
  integer-overflow без security-импакта, deserialization-DoS с локальным
  эффектом, fail-open на не-боевом пути.
- **Low:** дрейф документации, мёртвый адверсариальный код, гигиена
  (матчеры, наименования) без поведенческого импакта.

### 8. Самопроверка честности

6-вопросный distinguisher PhD-vs-A (память:
`feedback_phd_vs_a_level_distinguisher`) применяется перед каждым коммитом.
Поскольку выбран recon-breadth, этот раунд НЕ PhD-level B (нет полной
Tamarin/ProVerif-модели, нет dudect 1M на каждую находку, нет
IND-CPA/UF-CMA reduction sketch). В отчёте и сообщениях коммитов прямо
указывается: "recon-breadth pass, A-level rigor per finding с PhD-style
adversary mindset". PhD-уровень не заявляется.

Если конкретная находка требует более глубокого PhD-разбора (Critical
серьёзность по §7а, либо находка в крипто-ядре, где только reduction
позволяет аргументировать корректность), она помечается для отдельной
B-deep follow-up сессии и в текущей не дотягивается насильно.

### 9. Ворота проверки после каждого исправления

- `cargo fmt --all -- --check`.
- `cargo clippy -p <крейт> --all-targets --all-features --locked -- -D warnings`.
- `cargo test -p <крейт> --all-features --locked`.
- `bash scripts/audit-protocol-core-attack-gates.sh` если добавлена строка.
- `cargo test --workspace --all-features --locked` если затронут
  release-критичный путь.

### 10. Закрытые открытые вопросы

- **(а)** На critical-находку — пауза, немедленное исправление и коммит, затем
  продолжение. Critical не батчатся.
- **(б)** Реальные fuzz/miri/dudect запуски — только когда находка требует
  эмпирического доказательства, не стандартные ворота на каждую находку.
- **(в)** Zero findings — валидный результат. Отчёт фиксирует scope и явное
  "новых находок нет; существующий реестр покрывает рассмотренную поверхность".
  Без вынужденных находок.

### 11. Non-goals

- Не перезапускать 2026-05-15 hardening pass (уже закрыт).
- Не завершать публичный FFI bootstrap (граница выпуска).
- Не развёртывать живых KT-свидетелей (граница выпуска).
- Не подключать Apple App Attest / Play Integrity (граница выпуска).
- Никаких рефакторингов за пределами того, что требует исправление.

### 12. Done predicate

Раунд считается закрытым, когда выполнено одно из:

1. Tier 1 + Tier 2 + Tier 3 рассмотрены; у всех подтверждённых находок есть
   атакующий тест, исправление, строка реестра, запись в отчёте; финальный
   коммит в `main`; `bash scripts/audit-protocol-core-attack-gates.sh` и
   `cargo test --workspace --all-features --locked` зелёные.
2. Бюджет контекста ≈60%: хэндофф-документ с пройденными крейтами, открытыми
   гипотезами и оставшимися классами по уровням; финальный коммит в `main`.
