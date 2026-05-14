# Production Readiness Boundaries

Дата: 2026-05-14

Summary status: [`current-status.md`](current-status.md).

Сводный статус: [`current-status.md`](current-status.md).

## English

This file records the current public production boundary for Phase 2
protocol-compliance hardening. The repository contains real Rust cryptographic
building blocks and test harnesses, but the public client bootstrap is not
production-ready until the unfinished gates below are wired end to end.

Closed gates:

- FFI bootstrap: public constructors fail fast instead of returning handles made
  through test constructors.
- HTTP/2 transport: the internal production builder validates real deployment
  hosts and builds a `reqwest` client with system certificate verification plus
  SPKI pinning. This does not open public FFI bootstrap yet.
- Incomplete HTTP/2 bootstrap: `ClientCore::new_with_http2` fails closed until
  the full production config carries SPKI pins for every service and replaces
  postman, KT, and call relay stubs with real transports.
- TLS pinning: placeholder acceptance is forbidden; the production transport
  uses a real `rustls` verifier that checks the normal certificate result first
  and only then checks the configured SPKI pins.
- Server-side attestation gate: cloud unwrap and OPRF production paths now have
  contextual Rust verifiers that check signature, server nonce, freshness,
  device state, platform, and an explicit platform verifier in fail-closed
  order.
- Server nonce replay: production OPRF and backup unwrap contexts require an
  explicit `ProductionNonceReplayGuard`. The first accepted request records the
  nonce as consumed, and a second use of the same nonce is rejected.
- Platform attestation verifiers: `Platform::Testing` is rejected by production
  verifiers. A local verifier crate now enforces shared token-size, app/site,
  nonce, key, signature, and counter rules where enough material is available.
  WebAuthn has local assertion verification. Apple App Attest and Android Play
  Integrity remain fail-closed until their external trust material, platform
  token parsers, and mobile/server integration are wired.
- Core attack matrix: `docs/security/protocol-core-attack-gates.md` records
  which tamper, replay, rollback, and mixed-version cases are covered by Rust
  tests.
- Local release hardening: `scripts/run-local-release-hardening.sh short`
  aggregates local formal checks, focused fuzz smoke, KT split-view exchange,
  local load, race checks, secret-leak audit, and fail-closed boundary audit.
  This is local evidence only and does not prove real server or real device
  readiness.
- Mobile bridge: Swift, Kotlin, and Web platform attestation bridges are not yet
  a production-ready trust boundary.
- Server integration: mock server behavior does not count as production
  deployment readiness.
- Live KT gossip/self-monitoring deployment remains a production boundary:
  local tests can detect divergent observations after clients exchange them,
  but cannot prove that a live network always performs that exchange.

### Calls and SFrame

Local Rust code checks parser safety, vectors and mode enforcement, but this is
not a real production calling proof. Real media transport, network behaviour,
device audio/video stacks and server relay deployment remain release
boundaries.

## Русский

Этот файл фиксирует текущую границу боевой готовности для Фазы 2 приведения к
документам. В репозитории есть настоящие Rust-крейты с криптографией и
проверочные стенды, но публичный запуск клиента ещё не готов для боя, пока
закрытые ворота ниже не связаны до конца.

Закрытые ворота:

- FFI bootstrap: публичные конструкторы сразу отказывают, а не возвращают
  клиент, собранный через тестовые конструкторы.
- HTTP/2 транспорт: внутренний боевой сборщик проверяет настоящие адреса
  развёртывания и собирает `reqwest`-клиент с системной проверкой сертификата
  плюс закреплёнными SPKI-ключами. Это ещё не открывает публичный FFI-запуск.
- Неполный HTTP/2 bootstrap: `ClientCore::new_with_http2` закрыто отказывает,
  пока полная боевая настройка не несёт SPKI-ключи для каждого сервиса и пока
  postman, KT и call relay не заменены с заглушек на реальные транспорты.
- TLS pinning: заглушка, которая “просто проходит”, запрещена; боевой
  транспорт использует настоящий `rustls`-проверяющий, который сначала
  проверяет обычный результат сертификата и только потом сверяет закреплённые
  SPKI-ключи.
- Серверная проверка устройства: боевые пути развёртки облачного ключа и OPRF
  теперь имеют контекстные Rust-проверяющие. Они по порядку проверяют подпись,
  серверный вызов, свежесть, состояние устройства, платформу и явный
  платформенный проверяющий. Любой отказ закрывает путь.
- Повтор серверного вызова: боевые контексты OPRF и развёртки резервного ключа
  требуют явный `ProductionNonceReplayGuard`. Первый принятый запрос записывает
  вызов как использованный, повтор того же вызова отвергается.
- Платформенные проверяющие: `Platform::Testing` отвергается боевыми
  проверяющими. Новый локальный крейт проверяет общие правила размера токена,
  приложения или сайта, серверного вызова, ключа, подписи и счётчика там, где
  для этого хватает данных. WebAuthn имеет локальную проверку утверждения.
  Apple App Attest и Android Play Integrity остаются закрыты отказом, пока не
  подключены внешние корни доверия, разбор платформенного токена и
  мобильная/серверная связка.
- Матрица атак ядра: `docs/security/protocol-core-attack-gates.md` фиксирует,
  какие подмены, повторы, откаты и смешения версий покрыты Rust-тестами.
- Локальные выпускные ворота: `scripts/run-local-release-hardening.sh short`
  собирает местные формальные проверки, короткий fuzz, KT split-view сверку,
  локальную нагрузку, проверки гонок, аудит утечек секретов и аудит закрытых
  отказов. Это только местное доказательство; оно не доказывает готовность
  настоящих серверов или реальных устройств.
- Мобильный мост: Swift, Kotlin и Web-мосты для attestation пока не являются
  боевой границей доверия.
- Серверная интеграция: поведение mock-сервера не считается готовностью
  боевого развёртывания.
- Живая KT gossip/self-monitoring связка остаётся границей выпуска: локальные
  тесты обнаруживают разные наблюдения после обмена клиентов, но не доказывают,
  что живая сеть всегда выполнит такой обмен.

### Звонки и SFrame

Локальный Rust-код проверяет безопасность парсеров, тестовые векторы и
соблюдение режимов, но это ещё не доказательство боевых звонков. Настоящий
медиа-транспорт, поведение сети, аудио/видео-стек устройств и серверное
развёртывание реле остаются границами выпуска.
