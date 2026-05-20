# Documentation Truth Alignment Implementation Plan

> **Historical note (2026-05-20 reconciliation):** This plan documents the pre-v3.0.0 implementation track for documentation truth alignment (Phase 1 + Phase 2). The work has been superseded by:
> - v3.0.0 reconciliation pass (`docs/superpowers/specs/2026-05-20-docs-code-full-reconciliation-design.md`)
>
> The unchecked task boxes below are planning text, not the current active task list. Current status lives в `docs/security/current-status.md` + `docs/audits/ROUND-1-TO-7-SUMMARY.md`.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Привести все документы Umbrella Protocol к одной честной картине текущей боевой готовности, без ложных обещаний и без смешивания тестовых путей с боевыми.

**Architecture:** Сначала создаётся один короткий статусный документ, затем публичные документы, приватные спецификации, старые планы и примеры приводятся к нему. Проверка строится на поиске опасных формулировок и существующем скрипте публичных уведомлений. Код протокола не меняется в этой фазе.

**Tech Stack:** Markdown, Bash, `rg`, существующий `scripts/audit-public-access-notices.sh`, Git.

---

## Source Documents

- `docs/superpowers/specs/2026-05-13-documentation-truth-alignment-design.md`
- `docs/WORKING_RULES.md`
- `docs/security/production-readiness-boundaries.md`
- `docs/audits/formal-lint-status-2026-05-13.md`
- `README.md`
- `.local-private/specs/SPEC-OVERVIEW.md`
- `.local-private/specs/SPEC-13-PQ-HYBRID.md`

## File Structure

- Create `docs/security/current-status.md`: one short status page that every other document can point to.
- Modify `docs/security/production-readiness-boundaries.md`: point readers to the new status page.
- Modify `README.md`: replace phase-specific status wording with current status wording.
- Modify `docs/README.md`: make the docs index point to the current status page.
- Modify `docs/security/release-manifest-v1.0.0.txt`: replace "Phase 2 status" with current hardening status.
- Modify `CHANGELOG.md`: remove broad "production-ready" wording and record this documentation alignment.
- Modify `PUBLIC_ACCESS.md`: avoid implying a complete deployed production protocol.
- Modify `scripts/audit-public-access-notices.sh`: require the new current status page and stop requiring stale Phase 2 wording.
- Modify `.local-private/specs/SPEC-OVERVIEW.md`: replace broad production-ready status with current honest status.
- Modify `.local-private/specs/SPEC-13-PQ-HYBRID.md`: narrow the PQ status to implemented PQ pieces without claiming whole-package production readiness.
- Modify `docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase1.md`: mark as historical.
- Modify `docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase2.md`: mark as historical.
- Modify `docs/superpowers/plans/2026-05-13-production-attestation-gate.md`: mark unchecked boxes as historical planning text, not active work.
- Modify `examples/android-harness/README.md` and `examples/ios-harness/README.md`: make Russian sections simpler and clearer.
- Modify `crates/umbrella-lints/README.md`: update the Dylint command to the command that the current audit status says is real.

## Task 1: Create The Current Status Page

**Files:**
- Create: `docs/security/current-status.md`
- Modify: `docs/security/production-readiness-boundaries.md`

- [ ] **Step 1: Create `docs/security/current-status.md`**

Create the file with this content:

```markdown
# Current Status

Дата: 2026-05-13

[English](#english) | [Русский](#русский)

## English

Umbrella Protocol 1.0.0 is a source-available Rust protocol package under
protocol-compliance hardening. It contains real cryptographic crates, test
harnesses, formal models, fuzzing entry points, and local verification scripts.

The full public client bootstrap is not open for production use yet. Public FFI
bootstrap fails closed until platform verifiers, mobile bridges, and server
integration are wired end to end.

Implemented and currently documented:

- cryptographic crates for identity, MLS profile, key transparency, OPRF,
  sealed sender, backup, padding, post-quantum helpers, and call primitives;
- internal HTTP/2 production builder with system certificate verification and
  SPKI pinning;
- server-side attestation gates for backup unwrap and OPRF that fail closed
  without a real platform verifier;
- local platform verifier crate with shared token checks and local WebAuthn
  assertion verification;
- Apple App Attest and Android Play Integrity paths that fail closed until
  external trust material, token parsers, and mobile/server integration are
  connected;
- formal and local lint gate status recorded in
  `docs/audits/formal-lint-status-2026-05-13.md`.

Not production-ready yet:

- public FFI/client bootstrap;
- Swift, Kotlin, and Web attestation bridges as trust boundaries;
- real server deployment integration;
- real Apple and Android token validation with external trust material;
- public device-certification matrix;
- full production witness deployment for key transparency.

The release rule is simple: if a path is not fully wired, it must fail closed or
be documented as a test harness. A test-only path must not look like a
production path.

## Русский

Umbrella Protocol 1.0.0 — набор Rust-крейтов протокола с доступным для чтения
исходным кодом. Сейчас проект проходит приведение к документам и усиление
боевых границ. В репозитории есть настоящие криптографические крейты, стенды
проверки, формальные модели, входы для фаззинга и локальные скрипты проверки.

Полный публичный запуск клиента ещё не открыт для боевого применения.
Публичный FFI-запуск закрыто отказывает, пока не связаны платформенные
проверяющие, мобильные мосты и серверная интеграция.

Что уже реализовано и описано:

- криптографические крейты для личности, MLS-профиля, прозрачности ключей,
  OPRF, скрытия отправителя, резервных копий, выравнивания сообщений,
  постквантовых помощников и заготовок звонков;
- внутренний боевой сборщик HTTP/2 с системной проверкой сертификата и
  закреплёнными SPKI-ключами;
- серверные проверки устройства для развёртки резервного ключа и OPRF, которые
  закрыто отказывают без настоящего платформенного проверяющего;
- локальный крейт платформенной проверки с общими проверками токена и локальной
  проверкой WebAuthn;
- пути Apple App Attest и Android Play Integrity, которые закрыто отказывают,
  пока не подключены внешние корни доверия, разбор токенов и мобильная/серверная
  связка;
- статус формальных проверок и местных правил в
  `docs/audits/formal-lint-status-2026-05-13.md`.

Что ещё не готово для боя:

- публичный запуск клиента через FFI;
- Swift, Kotlin и Web-мосты как границы доверия;
- связка с настоящим серверным развёртыванием;
- настоящая проверка Apple и Android токенов с внешними корнями доверия;
- публичная матрица сертификации устройств;
- полное боевое развёртывание свидетелей прозрачности ключей.

Правило выпуска простое: если путь не связан до конца, он должен закрыто
отказывать или быть явно описан как проверочный стенд. Тестовый путь не должен
выглядеть как боевой.
```

- [ ] **Step 2: Link the status page from `production-readiness-boundaries.md`**

In `docs/security/production-readiness-boundaries.md`, after `Дата: 2026-05-13`, insert:

```markdown
Summary status: [`current-status.md`](current-status.md).

Сводный статус: [`current-status.md`](current-status.md).
```

- [ ] **Step 3: Commit Task 1**

Run:

```bash
git add docs/security/current-status.md docs/security/production-readiness-boundaries.md
git commit -m "docs: add current protocol status"
```

Expected: commit succeeds and includes only those two documentation files.

## Task 2: Align Public Status Documents

**Files:**
- Modify: `README.md`
- Modify: `docs/README.md`
- Modify: `docs/security/release-manifest-v1.0.0.txt`
- Modify: `CHANGELOG.md`
- Modify: `PUBLIC_ACCESS.md`
- Modify: `scripts/audit-public-access-notices.sh`

- [ ] **Step 1: Update the English opening status in `README.md`**

Replace the English paragraph block that starts with `Phase 2 hardening is
active.` and ends with the link to
`docs/security/production-readiness-boundaries.md` with:

```markdown
Current hardening status is recorded in
[`docs/security/current-status.md`](docs/security/current-status.md). The
internal production HTTP/2 builder wires platform certificate verification
together with SPKI pinning. Public FFI bootstrap remains gated until real
platform attestation verifiers, mobile bridges, and server integration are wired
end to end. Cloud unwrap and OPRF have contextual server-side attestation gates
that fail closed without those real platform verifiers. A local
platform-verifier crate checks shared token-size, app/site, nonce, key,
signature, and counter rules where enough material is available. WebAuthn has
local assertion verification. Apple App Attest and Android Play Integrity still
fail closed until external trust material, platform-token parsers, and
mobile/server integration are wired. See
[`docs/security/production-readiness-boundaries.md`](docs/security/production-readiness-boundaries.md).
```

- [ ] **Step 2: Update the Russian opening status in `README.md`**

Replace the Russian paragraph block that starts with `Фаза 2 приведения к
документам активна.` and ends with the link to
`docs/security/production-readiness-boundaries.md` with:

```markdown
Текущий статус приведения к документам записан в
[`docs/security/current-status.md`](docs/security/current-status.md).
Внутренний боевой сборщик HTTP/2 связывает системную проверку сертификата с
закреплёнными SPKI-ключами. Публичный FFI-запуск остаётся закрыт, пока не
связаны настоящие платформенные проверяющие, мобильные мосты и серверная
интеграция. Развёртка облачного ключа и OPRF имеют серверные проверки с
контекстом, которые закрыто отказывают без настоящих платформенных
проверяющих. Локальный крейт платформенной проверки проверяет размер токена,
приложение или сайт, серверный вызов, ключ, подпись и счётчик там, где для
этого хватает данных. WebAuthn проверяется локально. Apple App Attest и Android
Play Integrity всё ещё закрыто отказывают, пока не подключены внешние корни
доверия, разбор платформенного токена и мобильная/серверная связка. Подробная
граница:
[`docs/security/production-readiness-boundaries.md`](docs/security/production-readiness-boundaries.md).
```

- [ ] **Step 3: Apply the same status wording to `docs/README.md`**

In `docs/README.md`, replace the English and Russian current-status paragraphs
with the same wording as Steps 1 and 2, but use relative links:

```markdown
[`security/current-status.md`](security/current-status.md)
[`security/production-readiness-boundaries.md`](security/production-readiness-boundaries.md)
```

- [ ] **Step 4: Update `docs/security/release-manifest-v1.0.0.txt`**

Replace the line prefix `Phase 2 status:` with `Current hardening status:`.

Replace the line prefix `Статус Фазы 2:` with `Текущий статус приведения к документам:`.

Keep the existing substance about HTTP/2, SPKI pinning, FFI fail-closed,
cloud unwrap, OPRF, and closed iOS/Android/Web verifiers.

- [ ] **Step 5: Update `CHANGELOG.md` English wording**

Under `Documentation refresh - 2026-05-12`, replace:

```markdown
- Kept public wording focused on the production package, reproducible local
  verification, non-commercial security review, and responsible disclosure.
```

with:

```markdown
- Kept public wording focused on the source-available protocol package,
  reproducible local verification, non-commercial security review, and
  responsible disclosure.
```

Replace:

```markdown
- Production-ready means complete for the published production scope; it does
  not mean risk-free or immune to future vulnerabilities.
```

with:

```markdown
- Current readiness is scoped by `docs/security/current-status.md`; no document
  should imply that unfinished public client paths are open for production use.
```

Replace:

```markdown
Initial clean production-ready source package.
```

with:

```markdown
Initial clean source package for public protocol inspection and hardening.
```

- [ ] **Step 6: Update `CHANGELOG.md` Russian wording**

Replace:

```markdown
- Формулировки оставлены вокруг production-пакета, локальной воспроизводимой
  проверки, некоммерческого security-review и ответственного раскрытия
  уязвимостей.
```

with:

```markdown
- Формулировки оставлены вокруг пакета протокола с доступным для чтения кодом,
  локальной воспроизводимой проверки, некоммерческого анализа безопасности и
  ответственного раскрытия уязвимостей.
```

Replace:

```markdown
- Production-ready означает завершённость в опубликованной области, но не
  обещает нулевой риск или невозможность будущих уязвимостей.
```

with:

```markdown
- Текущая готовность ограничена файлом `docs/security/current-status.md`;
  незавершённые публичные клиентские пути не должны выглядеть открытыми для
  боевого применения.
```

Replace:

```markdown
Первый чистый production-ready исходный пакет.
```

with:

```markdown
Первый чистый исходный пакет для публичной проверки протокола и дальнейшего
усиления.
```

- [ ] **Step 7: Update `PUBLIC_ACCESS.md` status implication**

In the English section, replace:

```markdown
The goal is simple: security researchers can inspect how the production protocol
is built without receiving permission to commercially reuse the implementation.
```

with:

```markdown
The goal is simple: security researchers can inspect how the published protocol
implementation is built without receiving permission to commercially reuse it.
```

In the Russian section, replace:

```markdown
Цель простая: исследователи безопасности могут проверить, как устроен
production-протокол, но это не даёт права коммерчески использовать реализацию.
```

with:

```markdown
Цель простая: исследователи безопасности могут проверить, как устроена
опубликованная реализация протокола, но это не даёт права коммерчески
использовать её.
```

- [ ] **Step 8: Update `scripts/audit-public-access-notices.sh`**

Replace the current Phase 2 checks:

```bash
require_pattern "README.md" "Phase 2 hardening is active|Фаза 2 приведения к документам активна"
require_pattern "docs/README.md" "Phase 2 hardening is active|Фаза 2 приведения к документам активна"
require_pattern "docs/security/release-manifest-v1.0.0.txt" "Phase 2 status|Статус Фазы 2"
```

with:

```bash
require_pattern "README.md" "Current hardening status|Текущий статус приведения к документам"
require_pattern "README.md" "current-status.md"
require_pattern "docs/README.md" "Current hardening status|Текущий статус приведения к документам"
require_pattern "docs/README.md" "current-status.md"
require_pattern "docs/security/current-status.md" "Public FFI bootstrap remains gated|Публичный FFI-запуск закрыто отказывает"
require_pattern "docs/security/current-status.md" "SPKI pinning|SPKI-ключами"
require_pattern "docs/security/current-status.md" "Apple App Attest"
require_pattern "docs/security/current-status.md" "Android Play Integrity"
require_pattern "docs/security/release-manifest-v1.0.0.txt" "Current hardening status|Текущий статус приведения к документам"
```

- [ ] **Step 9: Run public-documentation check**

Run:

```bash
bash scripts/audit-public-access-notices.sh
```

Expected:

```text
public access notices OK
```

- [ ] **Step 10: Commit Task 2**

Run:

```bash
git add README.md docs/README.md docs/security/release-manifest-v1.0.0.txt CHANGELOG.md PUBLIC_ACCESS.md scripts/audit-public-access-notices.sh
git commit -m "docs: align public readiness wording"
```

Expected: commit succeeds and the public-notice audit already passed.

## Task 3: Align Private Specifications

**Files:**
- Modify: `.local-private/specs/SPEC-OVERVIEW.md`
- Modify: `.local-private/specs/SPEC-13-PQ-HYBRID.md`

- [ ] **Step 1: Update `SPEC-OVERVIEW.md` header**

Replace:

```markdown
> Version 1.0.0 · Версия 1.0.0 · 2026-05-10 · Status: production-ready.
```

with:

```markdown
> Version 1.0.0 · Версия 1.0.0 · 2026-05-10 · Status: protocol-compliance hardening; public client bootstrap remains gated.
```

- [ ] **Step 2: Update `SPEC-OVERVIEW.md` section 6**

Replace section `## 6. Current Production Status` through the paragraph ending
with `recurring verification.` with:

```markdown
## 6. Current Hardening Status

Umbrella Protocol 1.0.0 is a source-available Rust protocol package under
protocol-compliance hardening. The current public status is recorded in
`docs/security/current-status.md`.

Implemented and checked inside this repository:

- Rust cryptographic crates and test harnesses;
- internal HTTP/2 builder with system certificate verification and SPKI pinning;
- server-side attestation gates for backup unwrap and OPRF;
- local platform-verifier crate with shared token checks and local WebAuthn
  assertion verification;
- dependency, formal, lint, documentation, and public-access gates listed in
  `docs/audits/formal-lint-status-2026-05-13.md`.

Not open as a full public production path:

- public FFI/client bootstrap;
- mobile bridges as trust boundaries;
- real server deployment integration;
- real Apple App Attest and Android Play Integrity token validation;
- full public key-transparency witness deployment.

Production hardening does not mean risk-free. Operators still need current
dependencies, monitored deployment, protected release keys, incident response,
and recurring verification.
```

- [ ] **Step 3: Update `SPEC-OVERVIEW.md` public document map**

In section `## 7. Public Document Map`, add this first bullet:

```markdown
- `docs/security/current-status.md` contains the current readiness boundary.
```

- [ ] **Step 4: Update `SPEC-13-PQ-HYBRID.md` header**

Replace:

```markdown
> Версия 1.0.0 · 2026-05-10 · Статус: production-ready.
```

with:

```markdown
> Версия 1.0.0 · 2026-05-10 · Статус: PQ-слой реализован в своей области; полный публичный клиентский запуск остаётся закрыт.
```

- [ ] **Step 5: Update `SPEC-13-PQ-HYBRID.md` opening status paragraph**

Replace:

```markdown
описывает что **уже реализовано** в v1.0.0 и какие гарантии даёт; публичный
статус выпуска описан в [`SPEC-OVERVIEW.md`](SPEC-OVERVIEW.md), change summary —
в [`CHANGELOG.md`](../../CHANGELOG.md).
```

with:

```markdown
описывает что **уже реализовано** в PQ-слое v1.0.0 и какие гарантии даёт в этой
области; общий статус готовности описан в
[`SPEC-OVERVIEW.md`](SPEC-OVERVIEW.md) и
[`docs/security/current-status.md`](../../docs/security/current-status.md), а
история изменений — в [`CHANGELOG.md`](../../CHANGELOG.md).
```

- [ ] **Step 6: Verify private spec status wording**

Run:

```bash
rg -n "Status: production-ready|Статус: production-ready|production-ready source package|production-ready исходный пакет" .local-private/specs
```

Expected: no output.

- [ ] **Step 7: Commit Task 3**

Run:

```bash
git add .local-private/specs/SPEC-OVERVIEW.md .local-private/specs/SPEC-13-PQ-HYBRID.md
git commit -m "docs: align private spec readiness status"
```

Expected: commit succeeds and includes only the two private spec files.

## Task 4: Mark Historical Plans Clearly

**Files:**
- Modify: `docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase1.md`
- Modify: `docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase2.md`
- Modify: `docs/superpowers/plans/2026-05-13-production-attestation-gate.md`

- [ ] **Step 1: Add historical note to Phase 1 plan**

After the heading in `docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase1.md`, insert:

```markdown
> Historical note, 2026-05-13: this file is a planning record, not the current
> active checklist. Later commits implemented or superseded these Phase 1
> items. Current readiness status lives in
> `docs/security/current-status.md` and
> `docs/security/production-readiness-boundaries.md`.
```

- [ ] **Step 2: Add historical note to Phase 2 plan**

After the heading in `docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase2.md`, insert:

```markdown
> Historical note, 2026-05-13: this file is a planning record, not the current
> active checklist. Later transport, attestation, and platform-verifier phases
> superseded the unchecked planning boxes below. Current readiness status lives
> in `docs/security/current-status.md` and
> `docs/security/production-readiness-boundaries.md`.
```

- [ ] **Step 3: Add historical note to production attestation gate plan**

After the heading in `docs/superpowers/plans/2026-05-13-production-attestation-gate.md`, insert:

```markdown
> Historical note, 2026-05-13: this file preserves the implementation plan used
> for the server-side attestation gate work. Unchecked boxes below are planning
> text, not the current active task list. Current readiness status lives in
> `docs/security/current-status.md` and
> `docs/security/production-readiness-boundaries.md`.
```

- [ ] **Step 4: Verify plans no longer look active without a note**

Run:

```bash
for f in \
  docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase1.md \
  docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase2.md \
  docs/superpowers/plans/2026-05-13-production-attestation-gate.md
do
  sed -n '1,8p' "$f"
done
```

Expected: each printed header includes `Historical note, 2026-05-13`.

- [ ] **Step 5: Commit Task 4**

Run:

```bash
git add docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase1.md docs/superpowers/plans/2026-05-13-protocol-compliance-hardening-phase2.md docs/superpowers/plans/2026-05-13-production-attestation-gate.md
git commit -m "docs: mark superseded plans historical"
```

Expected: commit succeeds and includes only the three plan files.

## Task 5: Clean Small Documentation Drift

**Files:**
- Modify: `examples/android-harness/README.md`
- Modify: `examples/ios-harness/README.md`
- Modify: `crates/umbrella-lints/README.md`

- [ ] **Step 1: Simplify Android harness Russian wording**

In `examples/android-harness/README.md`, replace:

```markdown
Это не production
мессенджер.
```

with:

```markdown
Это не боевой
мессенджер.
```

Replace:

```markdown
Harness нужен, чтобы проверить,
что AAR загружается, сгенерированные Kotlin bindings вызываются, и небольшой
smoke-surface работает на Android.
```

with:

```markdown
Проверочный проект нужен, чтобы убедиться, что AAR загружается,
сгенерированные Kotlin-привязки вызываются, и небольшой проверочный набор
работает на Android.
```

- [ ] **Step 2: Simplify iOS harness Russian wording**

In `examples/ios-harness/README.md`, replace:

```markdown
Это не
production мессенджер.
```

with:

```markdown
Это не
боевой мессенджер.
```

Replace:

```markdown
Harness нужен, чтобы проверить, что XCFramework загружается, сгенерированные
Swift bindings вызываются, и небольшой smoke-surface работает на iOS.
```

with:

```markdown
Проверочный проект нужен, чтобы убедиться, что XCFramework загружается,
сгенерированные Swift-привязки вызываются, и небольшой проверочный набор
работает на iOS.
```

- [ ] **Step 3: Update Dylint command in `crates/umbrella-lints/README.md`**

Replace the English command:

```bash
cargo dylint --all --manifest-path crates/umbrella-lints/Cargo.toml -- --workspace --all-targets --all-features
```

with:

```bash
DYLINT_RUSTFLAGS="-D warnings" cargo dylint --all --path crates/umbrella-lints --workspace -- --ignore-rust-version --all-targets --all-features --locked
```

Replace the Russian line:

```markdown
`umbrella-lints` содержит локальные Dylint-правила, которые Umbrella Protocol
использует в проверках безопасности и production-readiness.
```

with:

```markdown
`umbrella-lints` содержит локальные Dylint-правила, которые Umbrella Protocol
использует в проверках безопасности и готовности к выпуску.
```

Replace the Russian command with the same updated command.

- [ ] **Step 4: Commit Task 5**

Run:

```bash
git add examples/android-harness/README.md examples/ios-harness/README.md crates/umbrella-lints/README.md
git commit -m "docs: clean harness and lint wording"
```

Expected: commit succeeds and includes only the three documentation files.

## Task 6: Final Documentation Verification

**Files:**
- Modify only if verification exposes a real documentation issue.

- [ ] **Step 1: Run dangerous-word scan**

Run:

```bash
rg -n "production-ready|готов.*бо|полностью готов|TODO|TBD|FIXME|placeholder|stub|mock|for_test|test-only|заглуш" README.md CHANGELOG.md SECURITY.md PUBLIC_ACCESS.md CONTRIBUTING.md docs .local-private examples crates/umbrella-lints/README.md
```

Expected: output may still include:

- this plan and the approved design, because they intentionally name dangerous
  words as search targets;
- historical plans, if they have a historical note at the top;
- real test-only API names in private specifications, if the surrounding text
  clearly says they are test-only;
- `TBD` in `SPEC-13-PQ-HYBRID.md` only where it describes IANA placeholder
  values and does not promise final assignment.

Unexpected output:

- a current public status file saying the whole package is production-ready;
- a Russian section using `production-ready` instead of a plain Russian status;
- a plan with unchecked boxes and no historical note;
- a test harness described as a production messenger.

- [ ] **Step 2: Run public notice audit**

Run:

```bash
bash scripts/audit-public-access-notices.sh
```

Expected:

```text
public access notices OK
```

- [ ] **Step 3: Run Markdown whitespace check**

Run:

```bash
git diff --check
```

Expected: no output and exit code 0.

- [ ] **Step 4: Confirm working tree status**

Run:

```bash
git status --short --branch
```

Expected: only intentional documentation changes are present before the final
commit, or no changes if all earlier task commits already captured everything.

- [ ] **Step 5: Commit verification fixes if needed**

If Task 6 required extra documentation edits, run:

```bash
git add README.md CHANGELOG.md SECURITY.md PUBLIC_ACCESS.md CONTRIBUTING.md docs .local-private examples crates/umbrella-lints/README.md scripts/audit-public-access-notices.sh
git commit -m "docs: finish documentation truth alignment"
```

Expected: commit succeeds. If Task 6 produced no new edits, do not create an
empty commit.

## Final Handoff

After all tasks are complete, summarize in plain Russian:

- documents now point to `docs/security/current-status.md`;
- public and private documents no longer claim the whole package is fully ready
  for public production client use;
- old unchecked plans are marked historical;
- Dylint documentation uses the current real command;
- `rust_1mlrd` was not touched.

## Self-Review Checklist

- [x] Spec coverage: current status, all document areas, historical plans,
  dangerous-word scan, public-notice audit, and commit-per-iteration are covered.
- [x] Placeholder scan: plan uses dangerous words only as search targets or
  quoted text that must be replaced; no empty future-work sections are present.
- [x] Scope honesty: code is not changed; any real code bug found during
  documentation verification must become a separate approved phase.
- [x] File consistency: every modified file is listed before the task that
  touches it.
