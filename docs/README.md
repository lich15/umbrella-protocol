# Umbrella Protocol Public Documentation

[English](#english) | [Русский](#русский)

## English

This `docs/` tree contains the public production documentation for Umbrella
Protocol 1.0.0. It is focused on materials that help a reader understand, build,
verify, and test the protocol without exposing private working material.

## Contents

- `audits/` - retained verification notes and tool-policy documents.
- `security/` - release manifest, SBOM, and security operation notes.
- `WORKING_RULES.md` - рабочие постулаты проекта.
- `superpowers/specs/` - утверждённые рабочие планы крупных изменений.
- root-level `UmbrellaX_protocol_public_en.pdf` and
  `UmbrellaX_protocol_public_ru.pdf` - current public protocol papers.

Historical progress logs, private protocol specifications, private working
notes, unrelated repository plans, local machine paths, private infrastructure
details, and obsolete release-risk wording are intentionally excluded from the
public documentation set.

## Current Status

Umbrella Protocol 1.0.0 is a source-available package under
protocol-compliance hardening. The repository is published for transparency,
non-commercial security testing, cryptographic testing, reproducible builds,
and responsible vulnerability disclosure.

The public FFI/client production bootstrap is gated until every required
transport and verifier is wired end to end. Cryptographic crates and test
harnesses remain available for verification, but unfinished public paths must
fail fast instead of using test-only constructors.

Phase 2 hardening is active. The current boundary is documented in
[`security/production-readiness-boundaries.md`](security/production-readiness-boundaries.md).
The internal production HTTP/2 builder now wires platform certificate
verification together with SPKI pinning. Public FFI bootstrap remains gated
until real platform attestation verifiers, mobile bridges, and server
integration are wired end to end. Cloud unwrap and OPRF already have
contextual server-side attestation gates that fail closed without those real
platform verifiers. A local platform-verifier crate now checks shared
token-size, app/site, nonce, key, signature, and counter rules where enough
material is available. WebAuthn has local assertion verification. Apple App
Attest and Android Play Integrity still fail closed until external trust
material, platform-token parsers, and mobile/server integration are wired.

The current status of formal verification and local lint gates is recorded in
[`audits/formal-lint-status-2026-05-13.md`](audits/formal-lint-status-2026-05-13.md).
A command counts as a current release gate only when that status file shows
exit code 0 for the exact command.

---

## Русский

Папка `docs/` содержит публичную production-документацию Umbrella Protocol
1.0.0. Здесь оставлены материалы, которые помогают понять, собрать, проверить и
протестировать протокол без раскрытия приватных рабочих материалов.

## Содержимое

- `audits/` - сохранённые заметки по проверкам и политики инструментов.
- `security/` - манифест выпуска, SBOM и заметки по безопасности.
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

Umbrella Protocol 1.0.0 — пакет с доступным для чтения исходным кодом, который
сейчас проходит приведение к документам. Репозиторий опубликован для
прозрачности, некоммерческой проверки безопасности, криптографических
испытаний, воспроизводимых сборок и ответственного раскрытия уязвимостей.

Публичный боевой запуск клиента через внешний интерфейс для мобильных привязок
закрыт до полной связки транспортов и боевых проверок. Криптографические крейты
и проверочные стенды остаются доступными для проверки, но незавершённые
публичные пути должны отказывать явно, а не пользоваться тестовыми
конструкторами.

Фаза 2 приведения к документам активна. Текущая граница описана в
[`security/production-readiness-boundaries.md`](security/production-readiness-boundaries.md).
Внутренний боевой сборщик HTTP/2 теперь связывает системную проверку
сертификата с закреплёнными SPKI-ключами. Публичный FFI-запуск остаётся закрыт,
пока не связаны настоящие платформенные проверяющие, мобильные мосты и
серверная интеграция. Развёртка облачного ключа и OPRF уже имеют серверные
проверки с контекстом, которые закрыто отказывают без этих настоящих
платформенных проверяющих. Новый локальный крейт платформенной проверки уже
проверяет размер токена, приложение или сайт, серверный вызов, ключ, подпись и
счётчик там, где для этого хватает данных. WebAuthn проверяется локально.
Apple App Attest и Android Play Integrity всё ещё закрыты отказом, пока не
подключены внешние корни доверия, разбор платформенного токена и
мобильная/серверная связка.

Текущий статус формальных проверок и местных строгих правил записан в
[`audits/formal-lint-status-2026-05-13.md`](audits/formal-lint-status-2026-05-13.md).
Команда считается воротами выпуска только если в этом файле у неё указан код
0 для точного запуска.
