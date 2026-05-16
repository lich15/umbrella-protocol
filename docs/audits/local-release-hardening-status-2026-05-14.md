# Локальные выпускные ворота Umbrella Protocol

Дата: 2026-05-14

Этот документ фиксирует только локальные проверки. Он не заменяет настоящие
серверы, реальные Android/iOS устройства и боевое развёртывание свидетелей KT.

## Что проверяется локально

| Ворота | Команда | Что доказывает |
|---|---|---|
| Формальные модели | `bash scripts/verify-formal-production-readiness.sh`, `bash scripts/verify-proverif-models.sh`, `bash scripts/verify-tamarin-models.sh` | текущие модели проходят или честно показывают отсутствие внешнего инструмента |
| Miri | `bash scripts/run-miri-local-gates.sh` | исполнимые под Miri FFI/OPRF пути не имеют найденных скрытых ошибок памяти; слишком тяжёлые OPRF property/threshold пути остаются в обычных locked тестах |
| Fuzz smoke | `bash scripts/run-fuzz-overnight.sh 5 kt_entry_v2_parser sealed_sender_v2_parser wrapped_key_v2_parser oprf_parse_blinded_request` | разборщики не падают на коротком потоке мусорных входов |
| Ночной fuzz | `bash scripts/run-fuzz-overnight.sh 1800` | длинный прогон всех fuzz-целей перед выпуском |
| Локальная нагрузка | `cargo test -p umbrella-tests local_load_many_kt_leaves_keep_valid_inclusion_and_witness_roots --all-features --locked` | KT Merkle root, inclusion proof и witness-порог работают на тысячах локальных листьев |
| Гонки replay | `cargo test -p umbrella-tests concurrent_replay_guard_accepts_one_duplicate_hash_and_rejects_the_rest --all-features --locked` | при одновременном повторе принимается только первый запрос |
| Гонки witness | `cargo test -p umbrella-tests concurrent_witness_verification_has_no_shared_state_corruption --all-features --locked` | параллельная проверка подписанных эпох не портит состояние |
| KT split-view сверка | `cargo test -p umbrella-kt threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence --all-features --locked` | две локально подписанные версии одной эпохи обнаруживаются при обмене наблюдениями клиентов |
| Гигиена памяти | `cargo test -p umbrella-identity -p umbrella-client -p umbrella-sealed-sender --all-features --locked` | временные значения вывода ключей затираются, Sealed Sender plaintext очищается при Drop, retry-jitter использует системный RNG |
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

- Внешний крипто-аудит 2026-05-14 записан в
  `docs/audits/external-crypto-release-audit-status-2026-05-14.md`.
  Evidence лежит в `target/audit-evidence/external-crypto-release/20260514/`,
  полный fuzz всех 27 целей лежит в
  `target/fuzz-overnight/20260514-191349/summary.txt` и завершился с итогом
  `Failed: 0 / 27`.
- По отдельному запросу 2026-05-14 запущены сфокусированный Miri-скрипт и
  полный fuzz всех 27 целей. Miri прошёл, fuzz завершился с итогом
  `Failed: 0 / 27`. Подробная запись:
  `docs/audits/full-fuzz-and-miri-run-2026-05-14.md`.
- `bash scripts/run-local-release-hardening.sh short` прошёл 2026-05-14 с кодом
  0. Сводка лежит в
  `target/audit-evidence/local-release-hardening/20260514-012520/summary.txt`.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets
  --all-features --locked -- -D warnings`, `RUSTDOCFLAGS="-D warnings" cargo
  doc --no-deps --workspace --all-features --locked` и `cargo test --workspace
  --all-features --locked` прошли 2026-05-14.
- `bash scripts/audit-dependency-policy.sh` прошёл 2026-05-14: запрещённая
  зависимость `bincode` отсутствует, `cargo deny check` завершился успешно.
- `bash scripts/run-miri-local-gates.sh` прошёл внутри общего прогона
  `20260514-012520` с кодом 0. OPRF Miri переведён на сфокусированные
  локальные ворота, потому что полный OPRF-пакет под Miri слишком медленный и
  дублирует обычные locked тесты.
- Полный тестовый журнал сохранён локально в
  `target/audit-evidence/local-release-hardening/final/cargo-test-workspace-after-miri.log`.
- Дополнительная гигиена памяти 2026-05-16 закрыта тестами
  `bip39_derivation_temporaries_are_zeroizing`,
  `slip10_derivation_temporaries_are_zeroized`,
  `code_recovery_temporaries_are_zeroizing`,
  `v2_inner_wrapped_key_plaintext_is_zeroizing`,
  `decrypt_row_zeroizing_returns_zeroizing_plaintext`,
  `row_cipher_sensitive_temporaries_are_zeroizing`,
  `opened_envelope_message_is_zeroizing_wrapper` и
  `retry_jitter_uses_system_rng_not_thread_rng`; подробности:
  `docs/audits/security-hardening-audit-2026-05-16.md`.

## Единая команда

Короткий локальный прогон:

```bash
bash scripts/run-local-release-hardening.sh short
```

Длинный ночной прогон перед выпуском:

```bash
bash scripts/run-local-release-hardening.sh long
```
