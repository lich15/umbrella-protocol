# Umbrella Protocol Public Documentation

[English](#english) | [Русский](#русский)

## English

This `docs/` tree contains the public production documentation for Umbrella
Protocol 3.0.0 (release tag `v3.0.0` ceremony 2026-05-20 commit `1ee8dbb3`;
consolidates post-v1.1.0 hardening series: Pass 5 remediation,
F-CLIENT-FACADE-1 milestone 10/10, Round 7 discovery, Max Ratchet v3). It is
focused on materials that help a reader understand, build, verify, and test
the protocol without exposing private working material.

## Contents

- `audits/` - retained verification notes and tool-policy documents.
- `security/` - release manifest, SBOM, and security operation notes.
- `integration/` - backend integration contract used as the source-of-truth
  surface implemented by `crates/umbrella-client/src/transport/` across
  F-CLIENT-FACADE-1 sessions 1-10f.
- `spec/` — public wire-contract specs (currently
  `discovery-integration.md` for the Round 7 PSI + @username lookup
  surface).
- Current release notes:
  `security/release-notes-v1.1.0.md` (1.1.0 baseline; post-1.1.0
  additions are tracked in the repository-root `CHANGELOG.md`).
- `security/release-notes-v3.0.0.md` (v3.0.0 release ceremony 2026-05-20).
- Live dependency monitoring:
  `security/dependency-monitoring.md`.
- 2026-05-15 security-hardening audit:
  `audits/security-hardening-audit-2026-05-15.md`.
- 2026-05-16 memory-hygiene audit:
  `audits/security-hardening-audit-2026-05-16.md`.
- External crypto release audit:
  `audits/external-crypto-release-audit-status-2026-05-14.md`.
- PhD-B rounds 1-7 consolidated summary:
  `audits/ROUND-1-TO-7-SUMMARY.md`.
- PhD-B round 6 distributed-identity closure:
  `audits/phd-b-distributed-identity-closure-2026-05-19.md`.
- PhD-B round 7 discovery closure:
  `audits/phd-b-discovery-closure-2026-05-18.md`. Adds the
  `umbrella-discovery` crate (OPRF-PSI + `@username` lookup with KT
  bind) to the workspace, alongside the `umbrella-threshold-identity`
  crate introduced in round 6.
- PhD-B independent reviewer verdict (rounds 1-6):
  `audits/phd-b-final-independent-review-2026-05-19.md`.
- **PhD-B Pass 5 remediation closure**:
  `audits/phd-b-pass5-remediation-2026-05-19.md` — consolidated
  report of 20 closure commits resolving 18 Pass 5 findings (all
  CRITICAL + HIGH + MEDIUM security / formal). M-FINAL-1 closed via
  Pass 5 commit `e7b034ff` (F-CLIENT-HW-1).
- **F-CLIENT-FACADE-1 MILESTONE 10/10 closure**: 12 sub-sessions on
  `main` wiring WebSocket + QUIC transports + MLS facades + KT
  self-monitor + identity rotation + calls + device transfer; the
  integration contract at `integration/gateway-svc-contract.md` is
  the implemented surface, not a future plan.
- **Max Ratchet v3** specification + measured evidence:
  `audits/max-ratchet-deniability-spec-2026-05-20.md` (10/10 acceptance)
  + `audits/max-ratchet-v3-security-evidence-2026-05-20.md` (per-claim
  test → measurement → numerical bound matrix).
- **Dudect saturation methodology** decision document:
  `audits/dudect-saturation-methodology-2026-05-19.md`.
- `WORKING_RULES.md` - рабочие постулаты проекта.
- `superpowers/specs/` - утверждённые рабочие планы крупных изменений.
- root-level `UmbrellaX_protocol_public_en.pdf` and
  `UmbrellaX_protocol_public_ru.pdf` - current public protocol papers.

Historical progress logs, private protocol specifications, private working
notes, unrelated repository plans, local machine paths, private infrastructure
details, and obsolete release-risk wording are intentionally excluded from the
public documentation set.

## Current Status

Umbrella Protocol 3.0.0 (release tag `v3.0.0` ceremony 2026-05-20 commit
`1ee8dbb3`; consolidates post-v1.1.0 hardening series) is a source-available
package under security hardening. The repository is published for
transparency, non-commercial security testing, cryptographic testing,
reproducible builds, and responsible vulnerability disclosure.

A seven-round PhD-B level security audit (rounds 1-6 merged 2026-05-18
via commit `84b4d576`, PR #6; round 7 discovery merged subsequently) was
completed against the 1.1.0 codebase. The audit covered hybrid
post-quantum encapsulation hardening, reality-pass attack regressions
(R1-R6), hedged-encaps closure, device-capture defense (R7-R12), a
round-6 distributed-identity architectural redesign with attack tests
R20-R27, and a round-7 private contact discovery surface (PSI +
`@username` lookup) with D-1..D-8 attack regressions. The independent
reviewer verdict on rounds 1-6 in
[`audits/phd-b-final-independent-review-2026-05-19.md`](audits/phd-b-final-independent-review-2026-05-19.md)
returned 0 BLOCKER + 1 MAJOR (M-FINAL-1, since closed via Pass 5
commit `e7b034ff`) + 3 MINOR. The consolidated summary lives in
[`audits/ROUND-1-TO-7-SUMMARY.md`](audits/ROUND-1-TO-7-SUMMARY.md).
The post-round-7 workspace baseline is 2179+ release-mode tests; the
post-v1.1.0 series consolidated в v3.0.0 (F-CLIENT-FACADE-1 10/10, Pass 5
remediation, Max Ratchet v3, Tasks 1-5 PhD-B closures) adds further
tests to that floor.

**Pass 5 remediation closure (2026-05-19)** — a parallel PhD-B Pass 5
audit cycle opened 18 additional findings on top of the rounds 1-6
review. All 18 are closed in a focused remediation series of 20
commits on `main` (see
[`audits/phd-b-pass5-remediation-2026-05-19.md`](audits/phd-b-pass5-remediation-2026-05-19.md)).
Highlights:

- 4 CRITICAL ship-blockers closed (F-1 / F-2 / F-3 / F-FFI-2).
- 5 HIGH findings closed, including the M-FINAL-1 v1.2.x removal
  tracker — the ephemeral identity_sk materialisation on the hw
  bootstrap path is eliminated via F-CLIENT-HW-1
  (commit `e7b034ff`); `ClientCore.identity` is `Option<Arc<...>>`
  and `None` on hw path; `HwBackedKeyStore` provides the
  identity-sk routing via `PersistentKeyStoreCallback::sign_identity`
  (commit `46784d1a`, F-IDENT-1 + F-IDENT-2).
- 6 formal-model tautologies closed — all six Tamarin models
  (`mls_ed25519`, `kt_v1_self_monitoring`, `kt_v2_self_monitoring`,
  `sframe_rfc9605`, `downgrade_resistance`, `type_safe_enforcement`)
  now carry substantive multi-rule correspondence lemmas plus
  exists-trace non-vacuity anchors. All verify under
  `tamarin-prover` 1.12.0.
- 3 MEDIUM dudect measurement-artefact findings closed via
  bounded-pool refactor at sub-100 ns timing sites. Saturation
  methodology recorded in
  [`audits/dudect-saturation-methodology-2026-05-19.md`](audits/dudect-saturation-methodology-2026-05-19.md).

**F-CLIENT-FACADE-1 MILESTONE 10/10 closure (2026-05-19)** — closed
across 12 sub-sessions (1, 2, 3, 4, 5, 6, 6c, 7, 8a-8c, 9-9f, 10-10f)
wiring WebSocket + QUIC transports, MLS group create, sealed-sender,
KT self-monitor with 3-of-5 witness threshold, identity rotation
(HW-callback orchestration with atomic keystore slot swap), calls
(TURN allocation + DTLS / SRTP keying + SFrame multi-party media +
webrtc-srtp Context wire-up), and `initiate_device_transfer`. The
integration contract documented at
[`integration/gateway-svc-contract.md`](integration/gateway-svc-contract.md)
is the implemented surface; public FFI bootstrap remains gated on
platform attestation, mobile bridges, and server deployment.

**Max Ratchet v3 (2026-05-20)** — default-on aggressive DH ratchet +
5-minute timer rekey + post-quantum extension every third commit +
SPQR HMAC deniable authentication. 10/10 acceptance criteria closed;
real X-Wing combine into SPQR keying; dudect 1M-sample evidence for
`verify_hmac`; Tamarin formal models for PCS + deniability
(`crates/umbrella-formal-verification/models/aggressive_dh_pcs.spthy`
+ `spqr_deniability.spthy`). See
[`audits/max-ratchet-deniability-spec-2026-05-20.md`](audits/max-ratchet-deniability-spec-2026-05-20.md)
and [`audits/max-ratchet-v3-security-evidence-2026-05-20.md`](audits/max-ratchet-v3-security-evidence-2026-05-20.md).

The public FFI/client production bootstrap is gated until every required
transport and verifier is wired end to end. Cryptographic crates and test
harnesses remain available for verification, but unfinished public paths must
fail fast instead of using test-only constructors.

Current hardening status is recorded in
[`security/current-status.md`](security/current-status.md). The internal
production HTTP/2 builder wires platform certificate verification together with
SPKI pinning. Public FFI bootstrap remains gated until real platform
attestation verifiers, mobile bridges, and server integration are wired end to
end. Cloud unwrap and OPRF have contextual server-side attestation gates that
fail closed without those real platform verifiers. A local platform-verifier
crate checks shared token-size, app/site, nonce, key, signature, and counter
rules where enough material is available. WebAuthn has local assertion
verification. Apple App Attest and Android Play Integrity still fail closed
until external trust material, platform-token parsers, and mobile/server
integration are wired. The incomplete `ClientCore::new_with_http2` path also
fails closed until every service has SPKI pins and real postman, KT, and call
relay transports. See
[`security/production-readiness-boundaries.md`](security/production-readiness-boundaries.md).
Core protocol attack gates are recorded in
[`security/protocol-core-attack-gates.md`](security/protocol-core-attack-gates.md).
Version 1.1.0 added local KT split-view hardening (carried into v3.0.0):
public epoch observations, verifiable equivocation evidence, strict
observation history, witness non-equivocation memory, and privacy-safe
observation encoding. Live observation exchange and production witness
channels remain production boundaries.
It also removes the unused optional `hpke-rs` libcrux HPKE backend from the
root and fuzz lockfiles so `RUSTSEC-2026-0124` is closed in the checked
supply-chain graph, not ignored.
Live dependency monitoring is documented in
[`security/dependency-monitoring.md`](security/dependency-monitoring.md):
Dependabot prepares dependency PRs, while the daily monitor checks root/fuzz
RustSec advisories, cargo-deny policy, PQ/backend boundaries, and dry-run update
drift without merging updates into `main`.
The 2026-05-15 local security-hardening audit is recorded in
[`audits/security-hardening-audit-2026-05-15.md`](audits/security-hardening-audit-2026-05-15.md).
It covers reserved production DNS rejection, blind-postman replay-memory
hardening, and broad `Debug` redaction for plaintext, tokens, nonces, keys,
shares, QR payloads, TURN credentials, and routing identifiers.
The 2026-05-16 memory-hygiene pass is recorded in
[`audits/security-hardening-audit-2026-05-16.md`](audits/security-hardening-audit-2026-05-16.md).
It covers key-derivation, recovery-code, backup unwrap, and SQLite row
temporary zeroization, zeroizing Sealed Sender opened plaintext, and
system-RNG retry jitter.
Local audits also include `scripts/audit-test-only-production-boundary.sh`,
which checks that test-only and incomplete paths do not look like production
paths.
Local release hardening is recorded in
[`audits/local-release-hardening-status-2026-05-14.md`](audits/local-release-hardening-status-2026-05-14.md)
and can be run with:

```bash
bash scripts/run-local-release-hardening.sh short
bash scripts/run-local-release-hardening.sh long
bash scripts/audit-local-release-hardening.sh
```

The current status of formal verification and local lint gates is recorded in
[`audits/formal-lint-status-2026-05-13.md`](audits/formal-lint-status-2026-05-13.md).
A command counts as a current release gate only when that status file shows
exit code 0 for the exact command.

---

## Русский

Папка `docs/` содержит публичную production-документацию Umbrella Protocol
3.0.0 (release tag `v3.0.0` церемония 2026-05-20 commit `1ee8dbb3`;
консолидирует post-v1.1.0 hardening серию). Здесь оставлены материалы,
которые помогают понять, собрать, проверить и протестировать протокол без
раскрытия приватных рабочих материалов.

## Содержимое

- `audits/` - сохранённые заметки по проверкам и политики инструментов.
- `security/` - манифест выпуска, SBOM и заметки по безопасности.
- Заметки текущего выпуска:
  `security/release-notes-v1.1.0.md` (базовая линия 1.1.0; пост-1.1.0
  дополнения отражены в корневом `CHANGELOG.md`).
- `security/release-notes-v3.0.0.md` (церемония выпуска v3.0.0 2026-05-20).
- Живой мониторинг зависимостей:
  `security/dependency-monitoring.md`.
- Аудит усиления безопасности от 2026-05-15:
  `audits/security-hardening-audit-2026-05-15.md`.
- Аудит гигиены памяти от 2026-05-16:
  `audits/security-hardening-audit-2026-05-16.md`.
- Внешний крипто-аудит выпуска:
  `audits/external-crypto-release-audit-status-2026-05-14.md`.
- Сводка PhD-B раундов 1-7:
  `audits/ROUND-1-TO-7-SUMMARY.md`.
- PhD-B раунд 6 закрытие распределённой идентичности:
  `audits/phd-b-distributed-identity-closure-2026-05-19.md`.
- PhD-B независимая проверка финал:
  `audits/phd-b-final-independent-review-2026-05-19.md`.
- `WORKING_RULES.md` - рабочие постулаты проекта.
- `superpowers/specs/` - утверждённые рабочие планы крупных изменений.
- корневые `UmbrellaX_protocol_public_en.pdf` и
  `UmbrellaX_protocol_public_ru.pdf` - актуальные публичные документы
  протокола.

Исторические журналы прогресса, private protocol specifications, приватные
рабочие заметки, планы других репозиториев, локальные пути машины, приватные
детали инфраструктуры и устаревшие формулировки риска выпуска намеренно не
входят в публичный набор документации.

## Текущий статус

Umbrella Protocol 3.0.0 (release tag `v3.0.0` церемония 2026-05-20 commit
`1ee8dbb3`; консолидирует post-v1.1.0 hardening серию) — пакет с доступным
для чтения исходным кодом, который сейчас проходит усиление безопасности.
Репозиторий опубликован для прозрачности, некоммерческой проверки
безопасности, криптографических испытаний, воспроизводимых сборок и
ответственного раскрытия уязвимостей.

На кодовой базе 1.1.0 проведён PhD-B аудит из семи раундов (раунды 1-6
влиты в `main` 2026-05-18 коммитом `84b4d576`, PR #6; раунд 7 «discovery»
влит после). Аудит покрывает гибридную постквантовую инкапсуляцию,
regression-проверки атак R1-R6, закрытие hedged-encaps, защиту от изъятия
устройства (R7-R12), архитектурную переделку распределённой идентичности
раунда 6 с атакующими тестами R20-R27, а также раунд 7 — приватное
обнаружение контактов (OPRF-PSI + `@username` поиск) с атакующими тестами
D-1..D-8. Заключение независимого ревьюера по раундам 1-6 в
[`audits/phd-b-final-independent-review-2026-05-19.md`](audits/phd-b-final-independent-review-2026-05-19.md)
— 0 BLOCKER + 1 MAJOR (M-FINAL-1, закрыт через Pass 5 коммитом
`e7b034ff`) + 3 MINOR. Сводный отчёт по раундам:
[`audits/ROUND-1-TO-7-SUMMARY.md`](audits/ROUND-1-TO-7-SUMMARY.md).
Базовая линия рабочей области после раунда 7 — 2179+ release-mode
тестов; пост-v1.1.0 серия, сведённая в v3.0.0 (F-CLIENT-FACADE-1 10/10,
Pass 5 remediation, Max Ratchet v3, Tasks 1-5 PhD-B), добавляет ещё.

Публичный боевой запуск клиента через внешний интерфейс для мобильных привязок
закрыт до полной связки транспортов и боевых проверок. Криптографические крейты
и проверочные стенды остаются доступными для проверки, но незавершённые
публичные пути должны отказывать явно, а не пользоваться тестовыми
конструкторами.

Текущий статус приведения к документам записан в
[`security/current-status.md`](security/current-status.md). Внутренний боевой
сборщик HTTP/2 связывает системную проверку сертификата с закреплёнными
SPKI-ключами. Публичный FFI-запуск остаётся закрыт, пока не связаны настоящие
платформенные проверяющие, мобильные мосты и серверная интеграция. Развёртка
облачного ключа и OPRF имеют серверные проверки с контекстом, которые закрыто
отказывают без настоящих платформенных проверяющих. Локальный крейт
платформенной проверки проверяет размер токена, приложение или сайт, серверный
вызов, ключ, подпись и счётчик там, где для этого хватает данных. WebAuthn
проверяется локально. Apple App Attest и Android Play Integrity всё ещё закрыто
отказывают, пока не подключены внешние корни доверия, разбор платформенного
токена и мобильная/серверная связка. Неполный путь
`ClientCore::new_with_http2` тоже закрыто отказывает, пока каждый сервис не
получит SPKI-ключи и настоящие транспорты postman, KT и call relay. Подробная
граница:
[`security/production-readiness-boundaries.md`](security/production-readiness-boundaries.md).
Боевые атакующие ворота ядра протокола записаны в
[`security/protocol-core-attack-gates.md`](security/protocol-core-attack-gates.md).
Версия 1.1.0 добавила локальное усиление KT против split-view (перенесено
в v3.0.0): публичные наблюдения эпох, проверяемое доказательство
раздвоения, строгую историю наблюдений, память свидетеля и безопасный для
приватности формат наблюдения. Живой обмен наблюдениями и боевые каналы
свидетелей остаются границами выпуска.
Также из корневого и fuzz lockfile убран неиспользуемый optional libcrux-бэкенд
HPKE из `hpke-rs`, поэтому `RUSTSEC-2026-0124` закрыт в проверяемом графе
зависимостей, а не проигнорирован.
Живой мониторинг зависимостей описан в
[`security/dependency-monitoring.md`](security/dependency-monitoring.md):
Dependabot готовит PR с обновлениями, а ежедневный сторож проверяет RustSec для
корневого и fuzz lockfile, cargo-deny, PQ/backend-границы и доступные обновления
через dry-run без вливания изменений в `main`.
Локальный аудит усиления от 2026-05-15 записан в
[`audits/security-hardening-audit-2026-05-15.md`](audits/security-hardening-audit-2026-05-15.md).
Он покрывает запрет reserved DNS-имён в боевой настройке, защиту replay-памяти
blind postman и широкое скрытие `Debug` для plaintext, token, server nonce,
ключей, долей, QR payload, TURN password и routing identifiers.
Проход гигиены памяти от 2026-05-16 записан в
[`audits/security-hardening-audit-2026-05-16.md`](audits/security-hardening-audit-2026-05-16.md).
Он покрывает затирание временных значений вывода ключей, 12 слов
восстановления, внутреннего ключа резервной копии, временных строк SQLite,
очищаемый plaintext после раскрытия Sealed Sender и системный генератор для
задержки повторов.
Локальные аудиты также включают `scripts/audit-test-only-production-boundary.sh`;
он проверяет, что тестовые и неполные пути не выглядят боевыми.
Локальные выпускные ворота записаны в
[`audits/local-release-hardening-status-2026-05-14.md`](audits/local-release-hardening-status-2026-05-14.md)
и запускаются так:

```bash
bash scripts/run-local-release-hardening.sh short
bash scripts/run-local-release-hardening.sh long
bash scripts/audit-local-release-hardening.sh
```

Текущий статус формальных проверок и местных строгих правил записан в
[`audits/formal-lint-status-2026-05-13.md`](audits/formal-lint-status-2026-05-13.md).
Команда считается воротами выпуска только если в этом файле у неё указан код
0 для точного запуска.
