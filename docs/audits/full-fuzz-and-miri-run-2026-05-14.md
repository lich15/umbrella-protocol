# Полный fuzz и локальный Miri, 2026-05-14

Этот документ фиксирует ручной прогон по запросу: сфокусированный Miri-скрипт
и полный fuzz всех целей Umbrella Protocol.

## Что запускалось

| Проверка | Команда | Результат |
|---|---|---|
| Локальный Miri | `bash scripts/run-miri-local-gates.sh target/audit-evidence/local-release-hardening/miri-user-request-20260514-014025` | прошёл |
| Полный fuzz | `bash scripts/run-fuzz-overnight.sh` | прошёл, 0 падений из 27 целей |

## Miri

Сводка лежит тут:

```text
target/audit-evidence/local-release-hardening/miri-user-request-20260514-014025/summary.txt
```

Проверены четыре практичных участка:

- FFI;
- OPRF: боевой путь закрывается отказом, если включён тестовый проверяющий;
- OPRF: плохой сетевой ввод отвергается;
- короткий полный круг OPRF.

Полный OPRF-набор под Miri не запускался, потому что он слишком медленный для
локального интерпретатора. Эти тяжёлые свойства остаются в обычных Rust-тестах
и fuzz-прогонах.

## Полный fuzz

Сводка лежит тут:

```text
target/fuzz-overnight/20260514-014200/summary.txt
```

Итог:

```text
Failed: 0 / 27
```

Все 27 целей завершились без падения и аварийной остановки:

- `aead_malleability_fuzz`;
- `authorization_approval_parse`;
- `authorization_request_parse`;
- `authorization_revocation_parse`;
- `fuzz_sframe_frame_parse`;
- `fuzz_sframe_header_parse`;
- `hybrid_signature_parser`;
- `identity_rotation_parse`;
- `kt_entry_v2_parser`;
- `ml_kem_decapsulate_fuzz`;
- `mls_keypackage_parser`;
- `noise_initiator_msg2`;
- `noise_responder_msg1`;
- `oprf_lagrange_fuzz`;
- `oprf_parse_blinded_request`;
- `oprf_parse_server_evaluation`;
- `oprf_threshold_combine`;
- `parse_mls_envelope`;
- `qr_payload_parse`;
- `sealed_sender_v2_parser`;
- `strip_padding`;
- `unwrap_share_parse`;
- `verify_inclusion`;
- `wrapped_key_parse`;
- `wrapped_key_v2_parser`;
- `xwing_ciphertext_parser`;
- `xwing_pubkey_parser`.

## OPRF slow-unit

Во время `oprf_lagrange_fuzz` libFuzzer записал один slow-unit:

```text
crates/umbrella-fuzz/fuzz/artifacts/oprf_lagrange_fuzz/slow-unit-9cc1a4795838b66de39b718dd667be4f81ed1986
```

Байты образца:

```text
01 01 04 04 80
```

Что важно:

- это не падение;
- это не аварийная остановка;
- полный fuzz по этой цели завершился успешно;
- повторный запуск того же файла один раз выполнился за 4 мс;
- повторный запуск того же файла 1000 раз выполнился за 3.343 сек;
- `stat::slowest_unit_time_sec` при повторе был 0.

Вывод: на этом прогоне slow-unit не воспроизводится как устойчивая ошибка
протокола. Его надо хранить как наблюдение по скорости fuzz-окружения, но не
выдавать за закрытую или открытую сетевую уязвимость.

## Честные границы

- Этот прогон не заменяет реальные серверы и реальные устройства.
- Этот прогон не доказывает миллион активных пользователей.
- Этот прогон доказывает только то, что на данной машине все 27 fuzz-целей
  отработали свой лимит без падений.
- Перед выпуском надо повторить длинный fuzz в чистом выпускном окружении и
  сохранить новую сводку.
