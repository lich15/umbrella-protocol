# Production Readiness Boundaries

Дата: 2026-05-13

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
- Attestation: `Platform::Testing` is rejected by production verifiers. iOS,
  Android, and Web tokens fail closed until real platform verifiers are wired.
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
- Attestation: `Platform::Testing` отвергается боевыми проверяющими. iOS,
  Android и Web тоже отказывают, пока настоящие платформенные проверяющие не
  подключены.
- Мобильный мост: Swift, Kotlin и Web-мосты для attestation пока не являются
  боевой границей доверия.
- Серверная интеграция: поведение mock-сервера не считается готовностью
  боевого развёртывания.
