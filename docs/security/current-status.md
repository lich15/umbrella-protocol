# Current Status

Дата: 2026-05-14

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
- protocol-core attack gate matrix:
  `docs/security/protocol-core-attack-gates.md`;
- mandatory server-nonce replay rejection in the production OPRF and backup
  unwrap contexts;
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
- матрица боевых атакующих ворот ядра протокола:
  `docs/security/protocol-core-attack-gates.md`;
- обязательная защита от повторного использования серверного вызова в боевых
  контекстах OPRF и развёртки резервного ключа;
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
