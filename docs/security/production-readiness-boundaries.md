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
- Mobile bridge: Swift, Kotlin, and Web platform attestation bridges are not yet
  a production-ready trust boundary.
- Server integration: mock server behavior does not count as production
  deployment readiness.

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
- Мобильный мост: Swift, Kotlin и Web-мосты для attestation пока не являются
  боевой границей доверия.
- Серверная интеграция: поведение mock-сервера не считается готовностью
  боевого развёртывания.
