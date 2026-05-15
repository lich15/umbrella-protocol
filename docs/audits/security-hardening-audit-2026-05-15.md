# Аудит безопасности и усиление, 2026-05-15

Этот документ фиксирует свежую локальную итерацию: я проверял код как атакующий,
искал обходы, утечки через отладочный вывод, переполнение внутренних окон
памяти и места, где тестовый или примерный путь мог выглядеть как боевой.

Это не заявление “невозможно взломать”. Это запись о том, что закрыто локально
кодом, тестами и скриптами. Реальные серверы, Android/iOS-устройства, внешний
формальный прогон перед выпуском, длинный ночной fuzz и независимый аудит всё
ещё остаются обязательными выпускными границами.

## Что было найдено и исправлено

| Область | Дыра простыми словами | Что сделано |
|---|---|---|
| Боевые адреса | Production-настройка могла принять reserved DNS-имена вроде `.example`, `.test`, `.local` как будто это настоящий боевой домен. | Боевой HTTP/2 config теперь закрыто отвергает эти имена. Тесты используют реалистичные `umbrellax.io`-адреса и отдельно проверяют отказ на reserved имена. |
| Blind postman | Уникальные сообщения сверх rate-limit записывались в replay-окно до отказа. Атакующий мог засыпать сервис новыми hash и раздувать память replay-окна, хотя сообщения уже должны были быть заблокированы лимитом. | Порядок стал таким: разобрать сообщение, проверить повтор без записи, проверить rate-limit, и только после разрешения записать hash в replay-окно. |
| Отладочный вывод | Многие боевые структуры с `Debug` могли унести в логи plaintext, media bytes, attestation token, server nonce, подписи, ключевые доли, QR payload, TURN password или linkable identifiers. | Для чувствительных структур добавлен ручной `Debug`: он показывает только безопасные длины, счётчики и статусы, а сами байты помечает как `<redacted>`. |
| Мобильная граница FFI | Расшифрованный текст сообщения и список sensitive peers могли попасть в отладочный вывод на границе мобильных привязок. | `MessageFfi` и `CallPolicyFfi` теперь скрывают тело сообщения и sensitive peers. |
| OPRF и backup | Подписанные запросы, platform input и production contexts могли раскрывать replay/correlation material в `Debug`. | OPRF и backup скрывают token, server nonce, device key, подписи, chat id, recipient key и ephemeral material. |
| KT и server routing | Parsed envelope мог раскрывать routing identifiers и replay hash в диагностике. | `ParsedEnvelope` теперь скрывает group id и message hash, оставляя только безопасную диагностику. |

## Новые реальные проверки

- `production_transport_rejects_reserved_dns_test_names` — боевой транспорт не
  принимает `.example`, `.test`, `.local` и `example.com/net/org`.
- `rate_limited_unique_messages_do_not_fill_replay_window` — сообщения,
  отклонённые rate-limit, не растят replay-память.
- `parsed_envelope_debug_redacts_routing_identifiers` — server-side envelope не
  печатает routing identifiers и replay hash.
- `signed_oprf_request_debug_redacts_replayable_request_material` — OPRF-запрос
  не печатает replay/correlation material.
- `signed_unwrap_request_debug_redacts_replayable_request_material` — backup
  unwrap-запрос не печатает replay/correlation material.
- `webauthn_debug_redacts_assertion_material` — WebAuthn assertion не попадает в
  отладочный вывод.
- `opened_envelope_debug_redacts_message_plaintext` — Sealed Sender не печатает
  раскрытое сообщение.
- `incoming_message_debug_redacts_application_payload` — MLS не печатает
  расшифрованный payload.
- `message_ffi_debug_redacts_plaintext` — FFI не печатает текст сообщения.
- `zeroizing_payload_debug_redacts_bytes` — payload после снятия padding не
  печатается в отладке.

## Что прошло локально

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo audit`
- `cargo audit -f crates/umbrella-fuzz/fuzz/Cargo.lock`
- `cargo test -p umbrella-client -p umbrella-calls -p umbrella-backup -p umbrella-oprf -p umbrella-platform-verifier -p umbrella-ffi -p umbrella-mls -p umbrella-padding -p umbrella-server-blind-postman --lib --all-features --locked`
- `cargo test -p umbrella-tests --test stage2_milestone rate_limited_unique_messages_do_not_fill_replay_window --all-features --locked`
- `cargo test -p umbrella-sealed-sender opened_envelope_debug_redacts_message_plaintext --all-features --locked`
- `bash scripts/audit-test-only-production-boundary.sh`
- `bash scripts/audit-protocol-core-attack-gates.sh`
- `bash scripts/audit-pq-backend-policy.sh`
- `bash scripts/audit-dependency-policy.sh target/audit-evidence-phd-security`
- `bash scripts/audit-local-release-hardening.sh target/local-release-hardening/short`
- `bash scripts/audit-public-access-notices.sh`
- `bash scripts/audit-github-actions.sh`

## Что не закрыто этой итерацией

- Настоящие Android/iOS устройства и их platform attestation.
- Настоящее серверное развёртывание и нагрузка уровня “миллион активных
  пользователей”.
- Полный живой KT gossip/self-monitoring между настоящими клиентами и
  независимыми свидетелями.
- Длинный ночной fuzz перед выпуском в чистом окружении.
- Свежий внешний формальный прогон и независимый ручной аудит перед релизом.

Правило остаётся прежним: если путь не связан до конца, он должен закрыто
отказывать или быть явно назван тестовым стендом.
