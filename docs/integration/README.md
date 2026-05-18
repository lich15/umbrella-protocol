# Backend Integration Documentation

[English](#english) | [Русский](#русский)

## English

This directory documents the integration contract between the
Umbrella Protocol client crates (`crates/umbrella-client/` and
peers) and the backend services. The contract is **read-only** as
far as the Umbrella Protocol repository is concerned — backend
implementation lives in a separate repository (`rust_1mlrd`) and
this directory captures only what the protocol's client side
needs to know to interoperate.

## Scope

The integration documentation covers:

- **`gateway-svc-contract.md`** — wire-format contract for the
  edge gateway (QUIC + WebSocket transports, ALPN/subprotocol
  identifiers, message envelope shapes, authentication flow,
  TLS pinning, NodePort surface).

## Why this exists

The Umbrella Protocol crates define the wire-format primitives
(MLS, sealed-sender, KT, threshold-wrap, OPRF, FROST) and the
client-side state machine. They do not define the network
endpoint surface — that is the backend gateway's responsibility.

Without an explicit integration contract, the client crates risk
drifting away from the backend's actual endpoint shapes and
authentication semantics, which would manifest as runtime errors
once real network calls are wired up.

The contract documented here serves three purposes:

1. **Specification** — what the gateway expects the client to
   send and what it promises to return. Sourced from
   `rust_1mlrd/proto/umbrellax/**/*.proto` + the gateway-svc
   Rust source via read-only inspection.
2. **Mock server harness** — basis for the `wiremock`-style
   mock backend used in
   `crates/umbrella-client/tests/mock_gateway/` (to be added
   during F-CLIENT-FACADE-1 closure).
3. **Regression boundary** — if the backend changes the wire
   format, contract tests on the client side fail loudly. The
   client crate does not silently follow backend drift.

## Relationship to F-CLIENT-FACADE-1

The Pass 5 PhD-B audit recorded F-CLIENT-FACADE-1 as a HIGH
honest-gap finding: every `CloudChat` and `SecretChat` facade
method at `crates/umbrella-client/src/facade/` returns a Block
7.2 stub (`Ok(MessageId([0u8; 16]))`). Closure of this finding
requires implementing the facade methods against real transports.

After the Pass 5 remediation series (2026-05-19), F-CLIENT-FACADE-1
is reclassified as a Block 7.4 engineering milestone, not a
security finding. The closure plan is decomposed across follow-up
sessions:

1. WebSocket transport implementation (`umx.pb.v1` Protobuf
   subprotocol).
2. QUIC transport implementation (`umx-quic-v1` ALPN) with
   auto-fallback to WebSocket.
3. Contract tests against a `wiremock` mock gateway.
4. Per-facade wire-up (`send_mls_text`, `receive`, `create_group`,
   `cloud_sync_history`, etc.).

The contract documented here is the technical foundation for
those sessions.

## Related Pass 5 remediation references

- `docs/audits/phd-b-pass5-remediation-2026-05-19.md` — Pass 5
  closure consolidated report.
- `docs/security/current-status.md` — current-status post-Pass-5.

---

## Русский

Этот каталог документирует контракт интеграции между
крейтами клиента Umbrella Protocol (`crates/umbrella-client/`
и сопутствующие) и серверными сервисами. Контракт **только для
чтения** с точки зрения репозитория Umbrella Protocol —
реализация бэкенда живёт в отдельном репозитории
(`rust_1mlrd`), а этот каталог фиксирует только то, что нужно
знать клиентской стороне протокола для совместимости.

## Состав

- **`gateway-svc-contract.md`** — wire-format контракт для
  edge-шлюза (транспорты QUIC + WebSocket, идентификаторы
  ALPN/subprotocol, формы конвертов сообщений, поток
  аутентификации, TLS-пиннинг, NodePort surface).

## Зачем это нужно

Крейты Umbrella Protocol определяют wire-format примитивы
(MLS, sealed-sender, KT, threshold-wrap, OPRF, FROST) и
state-машину клиентской стороны. Они не определяют поверхность
сетевых endpoint'ов — это ответственность серверного шлюза.

Без явного контракта интеграции крейты клиента могут «уплыть»
от реальных форм endpoint'ов и семантики аутентификации
бэкенда, что проявится как runtime-ошибки при подключении
реальных сетевых вызовов.

Документированный здесь контракт служит трём целям:

1. **Спецификация** — что шлюз ожидает от клиента и что обещает
   возвращать. Источник — `rust_1mlrd/proto/umbrellax/**/*.proto`
   + Rust-исходники gateway-svc через read-only инспекцию.
2. **Опора для mock-сервера** — базис для `wiremock`-style
   фиктивного бэкенда, который будет добавлен в
   `crates/umbrella-client/tests/mock_gateway/` при закрытии
   F-CLIENT-FACADE-1.
3. **Регрессионная граница** — если бэкенд меняет wire-format,
   контракт-тесты клиента шумно падают. Крейт клиента не следует
   тихим drift'ом за бэкендом.

## Связь с F-CLIENT-FACADE-1

PhD-B Pass 5 аудит зафиксировал F-CLIENT-FACADE-1 как HIGH
honest-gap находку: каждый facade-метод `CloudChat` и
`SecretChat` в `crates/umbrella-client/src/facade/` возвращает
Block 7.2 заглушку (`Ok(MessageId([0u8; 16]))`). Закрытие
требует реализации facade-методов против реальных транспортов.

После remediation-серии Pass 5 (2026-05-19), F-CLIENT-FACADE-1
переклассифицирована как Block 7.4 engineering milestone, а
не security-находка. План закрытия разбит на follow-up сессии:

1. Реализация WebSocket-транспорта (`umx.pb.v1` Protobuf
   subprotocol).
2. Реализация QUIC-транспорта (`umx-quic-v1` ALPN) с
   auto-fallback на WebSocket.
3. Контракт-тесты против `wiremock` mock-шлюза.
4. Wire-up per-фасад (`send_mls_text`, `receive`, `create_group`,
   `cloud_sync_history` и т.д.).

Документированный здесь контракт — техническое основание для
этих сессий.

## Связанные ссылки Pass 5 remediation

- `docs/audits/phd-b-pass5-remediation-2026-05-19.md` — Pass 5
  consolidated closure report.
- `docs/security/current-status.md` — current-status после
  Pass 5.
