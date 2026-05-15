# PhD-deep B-level Audit — Multi-Device Authorization — 2026-05-17

> **Для нового сеанса:** этот документ — самостоятельное задание. В нём
> весь нужный контекст, ничего из предыдущего сеанса знать не требуется.
> Прочитай целиком до начала работы.

## English

### Mission

Run a B-level PhD-deep active red-team audit of the multi-device
authorization subsystem of Umbrella Protocol. The 2026-05-16
recon-breadth round closed with zero closed-by-test findings across all
21 crates; the owner explicitly chose this subsystem as the deep-dive
target because (a) it concentrates the most attack surface (~4 kLoC of
Rust + a 452-LoC Tamarin model), (b) the previous PhD-deep session #66
already found 4 real findings here (closed), and (c) the owner believes
more findings are still hiding behind the lemmas.

**Critical rule (from memory `feedback_phd_level_mandatory` and
`feedback_phd_vs_a_level_distinguisher`):** this round MUST be PhD-B
level. The owner will check the six-question self-check below and reject
the work if it is recon-breadth wrapped in PhD-style commit prose.

### Scope

Production code:
- `crates/umbrella-backup/src/cloud_wrap/authorization.rs` (1 814 LoC)
- `crates/umbrella-backup/src/cloud_wrap/signed_request.rs` (2 145 LoC)
- Adjacent: `crates/umbrella-backup/src/cloud_wrap/share.rs`,
  `wrap.rs`, `unwrap.rs`, `transport.rs`, `threshold.rs`,
  `identity_rotation.rs`, `pq_wrap.rs`,
  `crates/umbrella-identity/src/code_recovery.rs`,
  `crates/umbrella-identity/src/cloud_wrap_recovery.rs`,
  `crates/umbrella-identity/src/slh_dsa_backup.rs`,
  `crates/umbrella-identity/src/attestation.rs`.

Formal model:
- `crates/umbrella-formal-verification/models/multi_device_authorization.spthy`
  (452 LoC, Tamarin). Lemmas already in model:
  - `pending_state_required_before_active`
  - `active_device_signs_authorization`
  - `unauthorized_device_rejected_by_sealed_servers`
  - `twentyfour_words_leak_alone_insufficient`
  - `identity_rotation_atomic_dual_signature` (post-F-PHD-RETRO-1, see §5)
  - `revocation_terminal_state`
  - `honest_setup_executable` (exists-trace sanity)

Existing tests to be aware of:
- `crates/umbrella-backup/tests/pq_threshold_wrap.rs`
- `crates/umbrella-backup/tests/test_F_76.rs`
- `crates/umbrella-backup/tests/v1_v2_mixed_corpus.rs`
- `crates/umbrella-tests/tests/dudect_constant_time.rs`
- `crates/umbrella-tests/tests/local_load_and_race.rs`

### What is already closed (do not re-do)

- The whole recon-breadth round 2026-05-16
  (`docs/audits/security-hardening-audit-2026-05-16.md`). Three Low /
  hygiene observations are recorded there; do not rediscover them as
  PhD findings.
- The 14 protocol-core attack gates listed in
  `docs/security/protocol-core-attack-gates.md`.
- The external research mappings in
  `docs/security/external-crypto-attack-ledger-2026-05-{14,15}.md`.
- The PhD-deep session #66 findings in
  `multi_device_authorization.spthy` (the four findings the preamble
  records: misleading lemma name + wire-format abstraction gap +
  tautological lemma + RFC TV2 coverage gap).
- F-PHD-RETRO-1 fix (lemma `identity_rotation_atomic_dual_signature`
  added `SignedRotationOld` and `SignedRotationNew` action labels to
  rule premises — see line ~409 of the model).

### Threat model — D-level state adversary

Same as the recon-breadth round, restricted to the multi-device path:

- Adversary controls the full network between the client device, the
  blind-postman server, the sealed-server quorum (up to 2 of 5 fully
  compromised — own keys, see real-attack threshold below), and other
  client devices of the same identity.
- Adversary may obtain a partial leak: e.g., the 24 BIP-39 words alone,
  OR a single device private key alone, OR the cloud-wrap blob alone.
- Adversary may have HSM rigs for forgery attempts and cache-timing
  measurement equipment for dudect-class side-channel attacks.
- Adversary cannot break Ed25519 or X25519 below their standard
  assumptions; cannot break SLH-DSA-128f; cannot break X-Wing combiner.

Out of scope: physical device access, social engineering, third-party
CVEs with upstream fix.

### Six-question PhD-vs-A self-check (MANDATORY)

Apply this before each commit AND before declaring the round done.
Failing 2+ checks means it is A-level disguised as PhD — owner will
catch it and reject the work.

1. **Findings count.** PhD pass typically surfaces 5+ real findings (the
   bar comes from memory `feedback_phd_level_mandatory`). Zero findings
   after 3-4 hours of work is acceptable only if every other check below
   passes; otherwise it is a sign you stayed on the surface.
2. **Test naming honesty.** Every new test name must start with
   `attack_<adversary_capability>_<consequence>`, naming the real
   adversary capability. Behavioral wrappers like `test_rejects_xxx`
   that wrap an existing protection do not count as PhD findings.
3. **Tamarin model engagement.** You must read 80%+ of the .spthy file
   (≈360+ of 452 LoC). Lemma names can be misleading; tautological
   lemmas can verify without proving the claimed property. Quote
   specific lines you read. Memory note `feedback_phd_pass_full_model_reading`
   captures this lesson from session #66.
4. **dudect samples.** For constant-time properties (Ed25519 sig verify
   on signed_request, sealed-server unwrap input comparisons, recovery
   mnemonic word comparison), run dudect 1M+ samples per measurement
   and attach the t-statistic to the report. Less than 100k samples is
   not PhD evidence.
5. **Reduction sketches.** For each authentication or confidentiality
   claim, sketch the security reduction (IND-CPA for unwrap; UF-CMA for
   authorization signatures) with concrete numbers — bit security,
   number of queries assumed, adversarial advantage bound.
6. **Literature engagement.** Cite at least 5 papers / RFCs by exact
   title and year, with one sentence each on how they apply. A bare
   "see Smith 2018" without engagement does not count. Suggested
   starting reads:
   - Signal Sesame protocol (Whisper Systems, 2017).
   - WhatsApp multi-device protocol (Sangelinaras et al, 2023).
   - "Post-Compromise Security for Asynchronous Messaging" (Cohn-Gordon
     et al, 2016).
   - RFC 9420 (MLS) §5.4 GroupContext-bound signatures.
   - "On Ends-to-Ends Encryption" (Cremers et al, 2020, ETK class).
   - X-Wing combiner draft-connolly-cfrg-xwing-kem-10 §5.4.
   - SLH-DSA FIPS 205 §10.3 hash binding.
   - KyberSlash external advisory (Bernstein et al, 2024).

### Adversary scenarios to play end-to-end (concrete attack plays)

Pick at least three. Each is a real end-to-end attack attempt, not a
unit-test boundary check.

1. **Compromised 2-of-5 sealed-server quorum + threshold preserve.**
   Two sealed servers hand the adversary their private shares and
   actively collude. Goal: show the adversary still cannot recover the
   message key for a target chat. Prove via (a) Tamarin lemma update
   that names the 2-of-5 corruption explicitly, (b) integration test
   using two `MockTransport` shares as corrupted, (c) reduction sketch
   on threshold security under partial-corruption.
2. **24-words leak + multi-device hijack.** Adversary obtains the 24
   BIP-39 words from a backup snapshot (e.g., user typed them into a
   compromised paper-photo). Goal: prove the adversary cannot register
   a new device without ALSO compromising an already-active device (this
   is what `twentyfour_words_leak_alone_insufficient` claims — verify
   it is not tautological, i.e., it actually distinguishes the two
   secrets in the proof).
3. **Sealed-server replay across accounts.** Adversary captures a valid
   signed unwrap request for account A and replays it against account
   B's sealed-server endpoint (where the adversary has compromised
   account B's keystore but not A's). Goal: confirm `canonical_signing_input`
   binds account / chat / recipient strongly enough that the cross-
   account replay is rejected even with an otherwise-valid signature.
4. **Pending-device race during approval.** Adversary intercepts the
   pending-device publication and races to publish a different
   pending device with the same `device_index`. Two clients see two
   different pending entries; one is approved before the other is
   noticed. Goal: prove that the approval signature is bound to the
   specific device pubkey such that the wrong approval cannot be
   replayed to confirm the wrong pending entry.
5. **Identity rotation under revocation.** Adversary triggers identity
   rotation between the device-revoke event and the approval event of a
   replacement device. Goal: confirm the rotation atomicity proof
   (`identity_rotation_atomic_dual_signature`) holds and that the
   `revocation_terminal_state` restriction prevents reanimating the
   revoked device.
6. **Wire-format truncation under attestation expiry.** Adversary
   submits a signed unwrap request where the attestation token is
   truncated to one byte below the platform parser minimum. Goal:
   confirm fail-closed at the production verifier without leaking the
   sender's identity bytes or the timestamp; check the resulting error
   variant.
7. **Constant-time on recovery mnemonic comparison.** dudect 1M samples
   on the BIP-39 mnemonic comparison path during code-recovery rotation.
   If t > 5, that is a real finding.

### Deliverables (per finding AND for the round)

Per finding:
- `attack_<class>_<specific>_<crate>` test in the appropriate
  `crates/<crate>/tests/` directory. The test MUST exercise the actual
  attacker path end to end and MUST fail before the fix lands.
- Code fix that closes the root cause minimally (one variable at a
  time; no incidental cleanup).
- Tamarin lemma (where applicable) that names the adversary capability
  explicitly in the action-label premises and is **not** tautological.
- dudect sample log attached to the report if the finding involves a
  timing claim.
- Reduction sketch with concrete numbers in the report.
- Literature citation by title and year.
- Ledger entry in `docs/security/protocol-core-attack-gates.md`.
- Audit-report entry in
  `docs/audits/security-hardening-audit-2026-05-17.md`.

Round-level:
- Final report with explicit application of the six-question self-check
  to the round as a whole.
- Each commit on the round branch must include "PhD-B" in the message
  ONLY if the six-question self-check passes; if not, it must say
  "A-level (no PhD claim)".

### Verification gates

After each fix:
- `cargo fmt --all -- --check`
- `cargo clippy -p umbrella-backup -p umbrella-identity --all-targets --all-features --locked -- -D warnings`
- `cargo test -p umbrella-backup --all-features --locked`
- `cargo test -p umbrella-identity --all-features --locked`
- `bash scripts/audit-protocol-core-attack-gates.sh`
- Tamarin run: `tamarin-prover --prove crates/umbrella-formal-verification/models/multi_device_authorization.spthy`
  (must terminate; all lemmas verified or explicit `// TODO PhD-deep`
  markers placed). If `tamarin-prover` is not installed locally, document
  in the report and run via the existing `crates/umbrella-formal-verification/tests/`
  harness if present.
- For dudect: instrument the target function under
  `crates/umbrella-tests/tests/dudect_constant_time.rs` extension and
  attach the output.

### Stop conditions

- Context approaches 60% of the session window → write a handoff
  document and stop (memory `feedback_context_60pct`).
- 3+ failed hypotheses on the same target → stop and question the
  architecture before piling further fixes.
- 0 confirmed findings AND all six self-check items still pass at high
  confidence after the full Tamarin / dudect / literature work → this
  is a valid negative result. Record it explicitly. Memory
  `feedback_phd_level_mandatory` allows 0 findings only when the rest
  of the PhD apparatus is genuinely present.

### Branch policy

Direct commit to main as per memory `feedback_direct_to_main`. No
feature branches.

### Out of scope (do not touch)

- Anything in the recon-breadth-2026-05-16 report Low observations
  (those are tracked elsewhere).
- The release-boundary items (Apple App Attest / Play Integrity / real
  server deployment / live KT gossip / overnight fuzz / external manual
  audit).
- Refactoring beyond what each individual fix strictly requires.

### Starting command for the new session

In a fresh Claude Code session, the owner says:

> "Продолжи работу из
> `docs/superpowers/specs/2026-05-17-phd-deep-multi-device-auth-design.md`.
> Это PhD-B deep pass на multi-device authorization, scope согласован."

The new session must then:

1. Read this entire spec file.
2. Use `/brainstorming` ONLY to confirm any open design questions (most
   are already resolved here).
3. Use `/writing-plans` to lay out the per-scenario implementation steps.
4. Use `/executing-plans` to do the work.
5. Apply the six-question self-check before each commit.
6. Reach the done predicate.

---

## Русский

### Миссия

Провести B-уровень PhD-deep активный аудит подсистемы многоустройственной
авторизации Umbrella Protocol. Раунд 2026-05-16 (recon-breadth) закрылся
с нулём закрытых-тестом находок по всем 21 крейтам; владелец явно выбрал
эту подсистему для глубокого захода потому что (а) в ней сосредоточено
больше всего поверхности атаки (~4 тысячи строк Rust + 452 строки модели
Tamarin), (б) предыдущий PhD-deep сеанс #66 уже нашёл здесь 4 настоящих
находки (закрыты), и (в) владелец считает что ещё что-то прячется за
леммами.

**Критичное правило (из памяти `feedback_phd_level_mandatory` и
`feedback_phd_vs_a_level_distinguisher`):** этот раунд ДОЛЖЕН быть
PhD-B уровень. Владелец проверит шесть вопросов самопроверки ниже и
отвергнет работу если это окажется recon-breadth завернутый в PhD-обёртку.

### Область

Боевой код:
- `crates/umbrella-backup/src/cloud_wrap/authorization.rs` (1814 строк)
- `crates/umbrella-backup/src/cloud_wrap/signed_request.rs` (2145 строк)
- Смежно: `share.rs`, `wrap.rs`, `unwrap.rs`, `transport.rs`,
  `threshold.rs`, `identity_rotation.rs`, `pq_wrap.rs` в той же папке
  плюс `code_recovery.rs`, `cloud_wrap_recovery.rs`, `slh_dsa_backup.rs`,
  `attestation.rs` в `umbrella-identity/src`.

Формальная модель:
- `crates/umbrella-formal-verification/models/multi_device_authorization.spthy`
  (452 строки, Tamarin). Леммы в модели — см. английскую секцию.

### Что уже закрыто (не переделывать)

- Весь раунд recon-breadth 2026-05-16
  (`docs/audits/security-hardening-audit-2026-05-16.md`); три Low /
  гигиенических наблюдения там уже зафиксированы — не перепроверять как
  PhD-находки.
- 14 строк боевого реестра в
  `docs/security/protocol-core-attack-gates.md`.
- Внешние ссылки в
  `docs/security/external-crypto-attack-ledger-2026-05-{14,15}.md`.
- Четыре находки сеанса #66 в `multi_device_authorization.spthy`
  (преамбула фиксирует: misleading lemma name + wire-format abstraction
  gap + tautological lemma + RFC TV2 coverage gap).
- F-PHD-RETRO-1 fix леммы `identity_rotation_atomic_dual_signature`
  (около строки 409 модели — добавлены action labels
  `SignedRotationOld`/`SignedRotationNew` в premises правил).

### Модель угроз — адверсарий уровня D

- Полный сетевой MITM между клиентским устройством, blind-postman
  сервером, кворумом sealed-servers (до 2 из 5 полностью скомпрометированы
  — свои ключи у противника, см. сценарий ниже), и другими клиентскими
  устройствами одного identity.
- Частичная утечка: либо 24 BIP-39 слова сами по себе, либо приватный
  ключ одного устройства, либо облачно-завёрнутый blob.
- HSM-стенды для попыток подделки; cache-timing оборудование для
  dudect-класса атак по времени.

Вне области: физический доступ, социальная инженерия, чужие CVE с
upstream-исправлением.

### Шесть вопросов самопроверки PhD vs A (обязательно)

Применять перед каждым коммитом И перед заявлением что раунд закрыт.
Если 2+ проверки провалены — это A-уровень замаскированный под PhD,
владелец это поймает и отвергнет работу.

1. **Количество находок.** PhD-проход обычно даёт 5+ настоящих находок
   (планка из памяти `feedback_phd_level_mandatory`). Ноль находок
   после 3-4 часов работы допустим только если ВСЕ остальные проверки
   ниже пройдены безоговорочно; иначе это признак что остался на
   поверхности.
2. **Честность имён тестов.** Каждое новое имя теста должно начинаться
   с `attack_<возможность_противника>_<последствие>` и называть
   реальную возможность противника. Поведенческие обёртки вида
   `test_rejects_xxx` вокруг уже существующей защиты НЕ считаются PhD.
3. **Вовлечённость в модель Tamarin.** Нужно прочитать 80%+ файла
   .spthy (≈360+ строк из 452). Имена лемм могут вводить в заблуждение;
   тавтологические леммы могут проходить верификацию не доказывая
   заявленного свойства. Цитировать конкретные строки. Урок из памяти
   `feedback_phd_pass_full_model_reading` (сеанс #66).
4. **Выборок dudect.** Для свойств постоянного времени (Ed25519 verify
   на signed_request, сравнения входа sealed-server unwrap, сравнение
   слов мнемонической фразы при ротации) запускать dudect 1M+ выборок
   на каждое измерение и прикладывать t-статистику в отчёте. Меньше
   100k выборок — это не PhD-доказательство.
5. **Прикидки сводимости (reductions).** Для каждого заявления об
   аутентификации или конфиденциальности дать набросок сводимости
   (IND-CPA для unwrap; UF-CMA для подписей авторизации) с конкретными
   числами — биты безопасности, число запросов противника, оценка
   преимущества.
6. **Вовлечённость в литературу.** Цитировать не менее 5 статей / RFC
   по точному названию и году с предложением что каждая значит для
   нашего случая. Список начальных кандидатов — см. английскую секцию.

### Сценарии атаки (конкретные пьесы)

Выбрать минимум три. Каждый — настоящая попытка атаки end-to-end, не
unit-проверка границы.

1. **Компрометация 2 из 5 sealed-servers + порог сохраняется.** Два
   sealed-сервера выдают приватные доли и активно колаборируют.
   Доказать что противник всё равно не восстанавливает ключ
   сообщения. Через: (а) обновлённая лемма Tamarin с явным указанием
   2-of-5 corruption, (б) интеграционный тест с двумя `MockTransport`
   как corrupted, (в) набросок сводимости порога под частичной
   компрометацией.
2. **Утечка 24 слов + захват устройства.** Противник получил 24 BIP-39
   слова из снимка резервной копии. Доказать что без компрометации
   уже-активного устройства новое не зарегистрируешь (что
   `twentyfour_words_leak_alone_insufficient` и утверждает — проверить
   что лемма не тавтологична, реально разделяет два секрета в proof).
3. **Replay sealed-server между аккаунтами.** Противник перехватывает
   валидный signed unwrap для аккаунта A и проигрывает его на endpoint
   аккаунта B (где у него скомпрометирован keystore B но не A).
   Проверить что `canonical_signing_input` достаточно жёстко связывает
   account / chat / recipient.
4. **Гонка pending-устройства при approval.** Противник перехватывает
   публикацию pending-устройства и спешит опубликовать другое pending
   с тем же `device_index`. Два клиента видят два разных pending; один
   approved до того как замечено. Доказать что approval-подпись
   привязана к конкретному device pubkey так что неправильный approval
   нельзя replay'нуть на чужой pending.
5. **Ротация identity под revocation.** Противник пускает ротацию
   между revoke-событием и approval нового устройства. Подтвердить
   атомарность через `identity_rotation_atomic_dual_signature` и что
   restriction `revocation_terminal_state` предотвращает реанимацию
   revoked устройства.
6. **Усечение wire-формата на expired attestation.** Противник
   подкладывает signed unwrap с attestation-токеном на 1 байт короче
   минимума парсера платформы. Проверить fail-closed без утечки байт
   identity или timestamp; проверить тип ошибки.
7. **Постоянное время сравнения мнемоники при ротации.** dudect 1M
   выборок на сравнении мнемонической фразы во время code-recovery.
   Если t > 5 — настоящая находка.

### Артефакты (на находку и на раунд)

На находку:
- Атакующий тест `attack_<класс>_<уточнение>_<крейт>` в нужной папке
  `tests/`; должен падать ДО исправления.
- Минимальное исправление корневой причины.
- Лемма Tamarin (где применимо) явно называющая возможность противника
  в action-label premises и НЕ тавтологичная.
- Лог dudect-выборок прикладывается если находка про время.
- Набросок сводимости с конкретными числами в отчёте.
- Цитата литературы по названию и году.
- Строка реестра в `docs/security/protocol-core-attack-gates.md`.
- Запись в `docs/audits/security-hardening-audit-2026-05-17.md`.

Раунд:
- Финальный отчёт с явным применением шести вопросов самопроверки.
- В сообщениях коммитов слово "PhD-B" ставится ТОЛЬКО если самопроверка
  пройдена; иначе пишется "A-level (no PhD claim)".

### Ворота проверки

- `cargo fmt --all -- --check`
- `cargo clippy -p umbrella-backup -p umbrella-identity --all-targets --all-features --locked -- -D warnings`
- `cargo test -p umbrella-backup --all-features --locked`
- `cargo test -p umbrella-identity --all-features --locked`
- `bash scripts/audit-protocol-core-attack-gates.sh`
- Запуск Tamarin: `tamarin-prover --prove crates/umbrella-formal-verification/models/multi_device_authorization.spthy`.
  Если не установлен — задокументировать и использовать существующий
  harness в `crates/umbrella-formal-verification/tests/`.
- Для dudect — расширить `crates/umbrella-tests/tests/dudect_constant_time.rs`
  и приложить вывод.

### Условия остановки

- Бюджет контекста ≈60% → handoff и стоп.
- 3+ провальных гипотезы по одной цели → стоп, спросить про архитектуру.
- 0 подтверждённых находок при полностью пройденной самопроверке (вся
  Tamarin / dudect / литература реально сделана) — валидный negative
  result, явно фиксируется.

### Политика ветки

Прямой коммит в main (память `feedback_direct_to_main`).

### Команда запуска

В новом сеансе Claude Code владелец говорит:

> «Продолжи работу из
> `docs/superpowers/specs/2026-05-17-phd-deep-multi-device-auth-design.md`.
> Это PhD-B deep pass на multi-device authorization, scope согласован.»

Новый сеанс далее:

1. Читает этот файл целиком.
2. `/brainstorming` — только для уточнения оставшихся открытых вопросов.
3. `/writing-plans` — раскладка по сценариям.
4. `/executing-plans` — собственно работа.
5. Применяет шесть вопросов самопроверки перед каждым коммитом.
6. Доходит до done predicate.
