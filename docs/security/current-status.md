# Current Status

Дата: 2026-05-15

[English](#english) | [Русский](#русский)

## English

Umbrella Protocol 1.1.0 is a source-available Rust protocol package under
security hardening. It contains real cryptographic crates, test
harnesses, formal models, fuzzing entry points, and local verification scripts.

The full public client bootstrap is not open for production use yet. Public FFI
bootstrap fails closed until platform verifiers, mobile bridges, and server
integration are wired end to end.

Implemented and currently documented:

- current public release notes:
  `docs/security/release-notes-v1.1.0.md`;
- cryptographic crates for identity, MLS profile, key transparency, OPRF,
  sealed sender, backup, padding, post-quantum helpers, and call primitives;
- internal HTTP/2 production builder with system certificate verification and
  SPKI pinning;
- incomplete `ClientCore::new_with_http2` bootstrap is fail-closed because it
  does not carry SPKI pins for every service and still leaves some transports
  on local stubs;
- server-side attestation gates for backup unwrap and OPRF that fail closed
  without a real platform verifier;
- local platform verifier crate with shared token checks and local WebAuthn
  assertion verification;
- Apple App Attest and Android Play Integrity paths that fail closed until
  external trust material, token parsers, and mobile/server integration are
  connected;
- protocol-core attack gate matrix:
  `docs/security/protocol-core-attack-gates.md`;
- local KT split-view hardening: `umbrella-kt` has public epoch observations,
  verifiable equivocation evidence, strict observation history, witness
  non-equivocation memory, and a public observation encoding that excludes
  account ids, device lists, contacts, and chats;
- local release hardening status:
  `docs/audits/local-release-hardening-status-2026-05-14.md`. It covers local
  formal, fuzz, load, race, KT split-view exchange, secret-leak, and fail-closed
  audits, but it is not a real server or real device proof;
- mandatory server-nonce replay rejection in the production OPRF and backup
  unwrap contexts;
- local dependency release gate runs `cargo deny check` and rejects missing
  `cargo-deny` as a gate failure;
- root and fuzz lockfiles exclude the unused optional `hpke-rs` libcrux HPKE
  backend that pulled `RUSTSEC-2026-0124`; `scripts/audit-pq-backend-policy.sh`
  checks this boundary;
- live dependency monitoring is documented in
  `docs/security/dependency-monitoring.md`; Dependabot prepares dependency PRs,
  and the daily dependency monitor checks root/fuzz RustSec advisories,
  cargo-deny policy, PQ/backend boundaries, and dry-run update drift without
  merging updates into `main`;
- the 2026-05-15 security-hardening audit closed local debug/log leakage in
  sensitive protocol structs, rejected reserved DNS names in production
  transport config, and fixed the blind-postman replay-window growth path where
  unique over-limit messages could consume replay memory;
- external crypto attack ledger:
  `docs/security/external-crypto-attack-ledger-2026-05-14.md` and
  `docs/security/external-crypto-attack-ledger-2026-05-15.md`; they record
  external standards/advisories and the local tests or release boundaries that
  answer them;
- formal and local lint gate status recorded in
  `docs/audits/formal-lint-status-2026-05-13.md`.

Not production-ready yet:

- public FFI/client bootstrap;
- Swift, Kotlin, and Web attestation bridges as trust boundaries;
- real server deployment integration;
- real Apple and Android token validation with external trust material;
- real production calling stack: local MLS/SFrame/calls tests are present, but
  real media transport, network behaviour, device audio/video stacks, and
  server relay deployment are still release boundaries;
- public device-certification matrix;
- full production witness deployment for key transparency.
- live KT observation exchange and public witness channels.

The release rule is simple: if a path is not fully wired, it must fail closed or
be documented as a test harness. A test-only path must not look like a
production path.

## Русский

Umbrella Protocol 1.1.0 — набор Rust-крейтов протокола с доступным для чтения
исходным кодом. Сейчас проект проходит усиление безопасности и честное описание
боевых границ. В репозитории есть настоящие криптографические крейты, стенды
проверки, формальные модели, входы для фаззинга и локальные скрипты проверки.

Полный публичный запуск клиента ещё не открыт для боевого применения.
Публичный FFI-запуск закрыто отказывает, пока не связаны платформенные
проверяющие, мобильные мосты и серверная интеграция.

Что уже реализовано и описано:

- публичные заметки текущего выпуска:
  `docs/security/release-notes-v1.1.0.md`;
- криптографические крейты для личности, MLS-профиля, прозрачности ключей,
  OPRF, скрытия отправителя, резервных копий, выравнивания сообщений,
  постквантовых помощников и заготовок звонков;
- внутренний боевой сборщик HTTP/2 с системной проверкой сертификата и
  закреплёнными SPKI-ключами;
- неполный `ClientCore::new_with_http2` закрыто отказывает, потому что он не
  несёт SPKI-ключи для всех сервисов и всё ещё оставляет часть транспортов на
  местных заглушках;
- серверные проверки устройства для развёртки резервного ключа и OPRF, которые
  закрыто отказывают без настоящего платформенного проверяющего;
- локальный крейт платформенной проверки с общими проверками токена и локальной
  проверкой WebAuthn;
- пути Apple App Attest и Android Play Integrity, которые закрыто отказывают,
  пока не подключены внешние корни доверия, разбор токенов и мобильная/серверная
  связка;
- матрица боевых атакующих ворот ядра протокола:
  `docs/security/protocol-core-attack-gates.md`;
- локальное усиление KT против split-view: `umbrella-kt` имеет публичные
  наблюдения эпох, проверяемое доказательство раздвоения, строгую историю
  наблюдений, память свидетеля и публичный формат наблюдения без account_id,
  списка устройств, контактов и чатов;
- статус локальных выпускных ворот:
  `docs/audits/local-release-hardening-status-2026-05-14.md`. Там описаны
  местные формальные проверки, fuzz, нагрузка, гонки, KT split-view сверка,
  аудит утечек секретов и закрытых отказов, но это не доказательство настоящих
  серверов или реальных устройств;
- обязательная защита от повторного использования серверного вызова в боевых
  контекстах OPRF и развёртки резервного ключа;
- локальные ворота зависимостей запускают `cargo deny check`; отсутствие
  `cargo-deny` считается отказом ворот, а не успехом;
- корневой и fuzz lockfile не содержат неиспользуемый optional libcrux-бэкенд
  HPKE из `hpke-rs`, который тянул `RUSTSEC-2026-0124`; это проверяет
  `scripts/audit-pq-backend-policy.sh`;
- живой мониторинг зависимостей описан в
  `docs/security/dependency-monitoring.md`; Dependabot готовит PR с
  обновлениями, а ежедневный сторож проверяет RustSec для корневого и fuzz
  lockfile, cargo-deny, PQ/backend-границы и доступные обновления через dry-run,
  не вливая изменения в `main`;
- аудит усиления от 2026-05-15 закрыл локальные утечки через `Debug`/журналы в
  чувствительных структурах протокола, запретил reserved DNS-имена в боевой
  настройке транспорта и исправил рост replay-памяти blind postman, когда
  уникальные сообщения сверх лимита могли занимать replay-окно;
- внешний реестр криптографических атак:
  `docs/security/external-crypto-attack-ledger-2026-05-14.md` и
  `docs/security/external-crypto-attack-ledger-2026-05-15.md`; они связывают
  внешние стандарты и advisory с локальными тестами или честными границами
  выпуска;
- статус формальных проверок и местных правил в
  `docs/audits/formal-lint-status-2026-05-13.md`.

Что ещё не готово для боя:

- публичный запуск клиента через FFI;
- Swift, Kotlin и Web-мосты как границы доверия;
- связка с настоящим серверным развёртыванием;
- настоящая проверка Apple и Android токенов с внешними корнями доверия;
- настоящий боевой стек звонков: локальные MLS/SFrame/calls тесты есть, но
  настоящий медиа-транспорт, поведение сети, аудио/видео-стек устройств и
  серверное реле всё ещё остаются границами выпуска;
- публичная матрица сертификации устройств;
- полное боевое развёртывание свидетелей прозрачности ключей.
- живой обмен KT-наблюдениями и публичные каналы свидетелей.

Правило выпуска простое: если путь не связан до конца, он должен закрыто
отказывать или быть явно описан как проверочный стенд. Тестовый путь не должен
выглядеть как боевой.
