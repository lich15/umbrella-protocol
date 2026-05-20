# Umbrella Protocol 1.1.0 Release Notes

Дата: 2026-05-15

[English](#english) | [Русский](#русский)

> **Note (2026-05-20 reconciliation):** these notes describe the
> **v1.1.0 release baseline** as tagged on 2026-05-15. Post-1.1.0
> hardening additions on `main` — Pass 5 remediation closure (18
> findings closed across 20 commits), F-CLIENT-FACADE-1 MILESTONE 10/10
> closure (WebSocket + QUIC transports, MLS facades, KT self-monitor
> + 3-of-5 witness threshold, identity rotation, calls, device
> transfer), Round 7 discovery merge (umbrella-discovery crate),
> Max Ratchet v3 implementation (aggressive DH + 5-min timer rekey
> + PQ extend + SPQR HMAC deniable auth), and Tasks 1-5 PhD-B
> closures — are tracked in the repository-root `CHANGELOG.md`. The
> next release-tag ceremony is a separate administrative step.
>
> **Замечание (2026-05-20):** эти notes описывают **базовую линию
> v1.1.0**, тегированную 2026-05-15. Post-1.1.0 hardening в `main` —
> Pass 5 remediation closure, F-CLIENT-FACADE-1 MILESTONE 10/10
> closure, Round 7 discovery merge, Max Ratchet v3, Tasks 1-5 PhD-B
> closures — записаны в корневом `CHANGELOG.md`. Очередной
> release-tag ceremony — отдельный административный шаг.

## English

Version 1.1.0 is a security-hardening release. It makes the public repository
match the current protocol state more honestly: finished local protections are
documented as implemented, and unfinished production paths remain gated or
fail-closed.

### Added

- Local Key Transparency split-view hardening in `umbrella-kt`:
  - public epoch observations;
  - verifiable equivocation evidence;
  - strict observation history;
  - witness non-equivocation memory;
  - public observation encoding that excludes account ids, device lists,
    contacts, chats, and message content.
- OPRF attack tests based on RFC 9497 failure cases: bad wire lengths, invalid
  group points, input-size boundaries, and subthreshold responses.
- External crypto attack ledger entries that map standards and known attack
  classes to local tests or honest release boundaries.
- Release gate documents for local hardening, protocol-core attacks, and KT
  split-view detection.
- A local `hpke-rs 0.6.1` release patch that removes the unused optional
  libcrux HPKE backend from root and fuzz lockfiles, closing the
  `RUSTSEC-2026-0124` SBOM/audit exposure instead of ignoring it.

### Strengthened

- Production API honesty: public bootstrap paths stay fail-closed when a real
  production constructor is not fully wired.
- TLS and SPKI pinning gates: placeholder or unsafe production transport
  settings are rejected.
- Platform attestation gates: test-only platform verifiers and testing
  platforms are rejected in production contexts.
- Sealed sender, backup, OPRF, KT, calls, and post-quantum helpers have broader
  local tests for tamper, replay, downgrade, bad versions, race conditions, and
  malformed input.
- Supply-chain checks now verify both root and fuzz lockfiles so an unused
  vulnerable optional dependency cannot hide in a secondary lockfile.
- Production transport config rejects reserved DNS names such as `.example`,
  `.test`, `.local`, and `example.com/net/org`.
- Blind-postman routing records replay hashes only after rate-limit acceptance,
  so over-limit unique messages cannot fill replay memory.
- Sensitive protocol structs now redact `Debug` output for plaintext, media
  frames, attestation tokens, server nonces, device keys, signatures, shares,
  QR payloads, TURN credentials, and routing identifiers.
- Memory hygiene now covers BIP-39 and SLIP-0010 derivation temporaries, Sealed
  Sender opened plaintext via `OpenedMessage`, and system-RNG retry jitter.
- Full workspace tests and local audit scripts were rerun after merging to
  `main`.

### Still Not Production-Ready

- Real server deployment integration.
- Real Android and iOS device validation with external platform trust material.
- Live KT observation exchange between real clients.
- Public production witness channels and witness operations.
- Full production calling stack over real networks and real devices.

These are not hidden as "done". They remain release boundaries.

### Verified Locally

- `cargo fmt --all -- --check`
- `cargo test --workspace --all-features --locked`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked`
- `bash scripts/audit-protocol-core-attack-gates.sh`
- `bash scripts/audit-local-release-hardening.sh ...`
- `bash scripts/audit-public-access-notices.sh`
- `bash scripts/audit-pq-backend-policy.sh`
- `bash scripts/audit-dependency-policy.sh ...`
- `cargo audit -f crates/umbrella-fuzz/fuzz/Cargo.lock`

## Русский

Версия 1.1.0 — выпуск усиления безопасности. Она делает публичный репозиторий
честнее: то, что локально закрыто кодом и тестами, записано как реализованное;
то, что требует серверов и реальных устройств, остаётся закрытой границей
выпуска.

### Добавлено

- Локальное усиление Key Transparency против split-view в `umbrella-kt`:
  - публичные наблюдения эпох;
  - проверяемое доказательство раздвоения;
  - строгая история наблюдений;
  - память свидетеля, чтобы он не подписывал два разных корня одной эпохи;
  - публичный формат наблюдения без account_id, списка устройств, контактов,
    чатов и текста сообщений.
- Атакующие тесты OPRF по ошибкам из RFC 9497: плохие длины, неверные точки
  группы, границы размера входа и ответ ниже порога.
- Внешний реестр крипто-атак, где внешние стандарты и известные классы атак
  связаны с локальными тестами или честными границами выпуска.
- Документы выпускных ворот для локального усиления, атак на ядро протокола и
  обнаружения KT split-view.
- Локальная заплатка `hpke-rs 0.6.1`, которая убирает неиспользуемый optional
  libcrux-бэкенд HPKE из корневого и fuzz lockfile. Так закрыт
  `RUSTSEC-2026-0124` в SBOM/аудите без молчаливого игнорирования.

### Усилено

- Честность боевого API: публичные пути запуска остаются закрытыми отказом,
  если настоящий боевой конструктор ещё не связан до конца.
- TLS и SPKI pinning: небезопасные или заглушечные боевые настройки транспорта
  отвергаются.
- Платформенные проверки: тестовые платформы и тестовые проверяющие не проходят
  в боевом контексте.
- Sealed sender, backup, OPRF, KT, звонки и постквантовые помощники получили
  больше локальных тестов на подмену, повтор, откат версии, плохую версию,
  гонки и битый вход.
- Проверки цепочки зависимостей теперь смотрят и корневой lockfile, и fuzz
  lockfile, чтобы уязвимая optional-зависимость не пряталась во втором файле.
- Боевая настройка транспорта отвергает reserved DNS-имена вроде `.example`,
  `.test`, `.local` и `example.com/net/org`.
- Blind postman записывает replay hash только после прохождения rate-limit,
  поэтому уникальные сообщения сверх лимита не заполняют replay-память.
- Чувствительные структуры протокола теперь скрывают `Debug` для plaintext,
  media frames, attestation token, server nonce, device key, подписей, долей,
  QR payload, TURN password и routing identifiers.
- Гигиена памяти теперь покрывает временные значения вывода BIP-39,
  SLIP-0010, 12 слов восстановления, внутренний ключ резервной копии после
  V2-распаковки, очищаемый путь расшифрования строки SQLite, раскрытый
  plaintext Sealed Sender через `OpenedMessage` и системный генератор для
  задержки повторов.
- Полный прогон всей рабочей области и локальные аудит-скрипты были запущены
  после слияния в `main`.

### Всё ещё не готово для боя

- Связка с настоящим серверным развёртыванием.
- Проверка настоящих Android и iOS устройств с внешними корнями доверия.
- Живой обмен KT-наблюдениями между настоящими клиентами.
- Публичные боевые каналы свидетелей и эксплуатация свидетелей.
- Полный боевой стек звонков на настоящих сетях и устройствах.

Это не спрятано как "готово". Это остаётся границей выпуска.

### Проверено локально

- `cargo fmt --all -- --check`
- `cargo test --workspace --all-features --locked`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked`
- `bash scripts/audit-protocol-core-attack-gates.sh`
- `bash scripts/audit-local-release-hardening.sh ...`
- `bash scripts/audit-public-access-notices.sh`
- `bash scripts/audit-pq-backend-policy.sh`
- `bash scripts/audit-dependency-policy.sh ...`
- `cargo audit -f crates/umbrella-fuzz/fuzz/Cargo.lock`
