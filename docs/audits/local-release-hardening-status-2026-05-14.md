# Локальные выпускные ворота Umbrella Protocol

Дата: 2026-05-14

Этот документ фиксирует только локальные проверки. Он не заменяет настоящие
серверы, реальные Android/iOS устройства и боевое развёртывание свидетелей KT.

## Что проверяется локально

| Ворота | Команда | Что доказывает |
|---|---|---|
| Формальные модели | `bash scripts/verify-formal-production-readiness.sh`, `bash scripts/verify-proverif-models.sh`, `bash scripts/verify-tamarin-models.sh` | текущие модели проходят или честно показывают отсутствие внешнего инструмента |
| Fuzz smoke | `bash scripts/run-fuzz-overnight.sh 5 kt_entry_v2_parser sealed_sender_v2_parser wrapped_key_v2_parser oprf_parse_blinded_request` | разборщики не падают на коротком потоке мусорных входов |
| Ночной fuzz | `bash scripts/run-fuzz-overnight.sh 1800` | длинный прогон всех fuzz-целей перед выпуском |
| Локальная нагрузка | `cargo test -p umbrella-tests local_load_many_kt_leaves_keep_valid_inclusion_and_witness_roots --all-features --locked` | KT Merkle root, inclusion proof и witness-порог работают на тысячах локальных листьев |
| Гонки replay | `cargo test -p umbrella-tests concurrent_replay_guard_accepts_one_duplicate_hash_and_rejects_the_rest --all-features --locked` | при одновременном повторе принимается только первый запрос |
| Гонки witness | `cargo test -p umbrella-tests concurrent_witness_verification_has_no_shared_state_corruption --all-features --locked` | параллельная проверка подписанных эпох не портит состояние |
| KT split-view сверка | `cargo test -p umbrella-kt threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence --all-features --locked` | две локально подписанные версии одной эпохи обнаруживаются при обмене наблюдениями клиентов |
| Секреты и закрытые пути | `bash scripts/audit-local-release-hardening.sh` | секретные типы и недоделанные пути не должны выглядеть как боевые |

## Честные границы

- Локальная нагрузка не равна серверной проверке на миллион активных
  пользователей.
- KT split-view считается полностью закрытым только после живой сверки
  клиентов, наблюдения свидетелей и серверного развёртывания.
- Если ProVerif, Tamarin, nightly Rust или cargo-fuzz отсутствуют, это отказ
  соответствующих ворот, а не успех.
- Публичный боевой клиент остаётся закрыт, пока серверная и мобильная связка не
  готовы.

## Последний локальный результат

- `bash scripts/run-local-release-hardening.sh short` прошёл 2026-05-14 с кодом
  0. Сводка лежит в
  `target/audit-evidence/local-release-hardening/20260514-001957/summary.txt`.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets
  --all-features --locked -- -D warnings`, `RUSTDOCFLAGS="-D warnings" cargo
  doc --no-deps --workspace --all-features --locked` и `cargo test --workspace
  --all-features --locked` прошли 2026-05-14.
- `bash scripts/audit-dependency-policy.sh` прошёл 2026-05-14: запрещённая
  зависимость `bincode` отсутствует, `cargo deny check` завершился успешно.
- Полный тестовый журнал сохранён локально в
  `target/audit-evidence/local-release-hardening/final/cargo-test-workspace.log`.

## Единая команда

Короткий локальный прогон:

```bash
bash scripts/run-local-release-hardening.sh short
```

Длинный ночной прогон перед выпуском:

```bash
bash scripts/run-local-release-hardening.sh long
```
