# Umbrella Protocol Public Documentation

[English](#english) | [Русский](#русский)

## English

This `docs/` tree contains the public production documentation for Umbrella
Protocol 1.1.0. It is focused on materials that help a reader understand, build,
verify, and test the protocol without exposing private working material.

## Contents

- `audits/` - retained verification notes and tool-policy documents.
- `security/` - release manifest, SBOM, and security operation notes.
- Current release notes:
  `security/release-notes-v1.1.0.md`.
- External crypto release audit:
  `audits/external-crypto-release-audit-status-2026-05-14.md`.
- `WORKING_RULES.md` - рабочие постулаты проекта.
- `superpowers/specs/` - утверждённые рабочие планы крупных изменений.
- root-level `UmbrellaX_protocol_public_en.pdf` and
  `UmbrellaX_protocol_public_ru.pdf` - current public protocol papers.

Historical progress logs, private protocol specifications, private working
notes, unrelated repository plans, local machine paths, private infrastructure
details, and obsolete release-risk wording are intentionally excluded from the
public documentation set.

## Current Status

Umbrella Protocol 1.1.0 is a source-available package under security
hardening. The repository is published for transparency,
non-commercial security testing, cryptographic testing, reproducible builds,
and responsible vulnerability disclosure.

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
Version 1.1.0 adds local KT split-view hardening: public epoch observations,
verifiable equivocation evidence, strict observation history, witness
non-equivocation memory, and privacy-safe observation encoding. Live observation
exchange and production witness channels remain production boundaries.
It also removes the unused optional `hpke-rs` libcrux HPKE backend from the
root and fuzz lockfiles so `RUSTSEC-2026-0124` is closed in the checked
supply-chain graph, not ignored.
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
1.1.0. Здесь оставлены материалы, которые помогают понять, собрать, проверить и
протестировать протокол без раскрытия приватных рабочих материалов.

## Содержимое

- `audits/` - сохранённые заметки по проверкам и политики инструментов.
- `security/` - манифест выпуска, SBOM и заметки по безопасности.
- Заметки текущего выпуска:
  `security/release-notes-v1.1.0.md`.
- Внешний крипто-аудит выпуска:
  `audits/external-crypto-release-audit-status-2026-05-14.md`.
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

Umbrella Protocol 1.1.0 — пакет с доступным для чтения исходным кодом, который
сейчас проходит усиление безопасности. Репозиторий опубликован для
прозрачности, некоммерческой проверки безопасности, криптографических
испытаний, воспроизводимых сборок и ответственного раскрытия уязвимостей.

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
Версия 1.1.0 добавляет локальное усиление KT против split-view: публичные
наблюдения эпох, проверяемое доказательство раздвоения, строгую историю
наблюдений, память свидетеля и безопасный для приватности формат наблюдения.
Живой обмен наблюдениями и боевые каналы свидетелей остаются границами выпуска.
Также из корневого и fuzz lockfile убран неиспользуемый optional libcrux-бэкенд
HPKE из `hpke-rs`, поэтому `RUSTSEC-2026-0124` закрыт в проверяемом графе
зависимостей, а не проигнорирован.
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
