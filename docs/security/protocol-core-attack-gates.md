# Боевые атакующие ворота ядра протокола

Дата: 2026-05-14

## Русский

Этот файл фиксирует, какие атаки ядро Umbrella Protocol проверяет локально.
Статус “закрыто тестом” означает, что есть Rust-тест, который ломает путь при
подмене, повторе, откате или неверной версии. Статус “граница выпуска” означает,
что локальный код честно не может доказать всю защиту без внешней связки, и
публичный боевой запуск остаётся закрыт.

| Область | Атака | Статус | Доказательство |
|---|---|---|---|
| Устройства | тестовая платформа в боевом пути | закрыто тестом | `production_policy_rejects_testing_attestation_even_after_valid_signature` в `umbrella-oprf` и `umbrella-backup` |
| Устройства | неизвестное, ожидающее или отозванное устройство | закрыто тестом | `production_context_rejects_unknown_pending_and_revoked_devices` |
| Устройства | откат WebAuthn-счётчика | закрыто тестом | `webauthn_rejects_counter_rollback` |
| Устройства | WebAuthn-ключ в контексте не совпадает с зарегистрированным | закрыто тестом | `webauthn_rejects_context_device_key_not_registered_key` |
| Клиентский запуск | `ClientCore::new_with_http2` выглядит боевым, но не несёт SPKI pins и оставляет часть транспортов заглушками | закрыто отказом | `new_with_http2_fails_closed_until_full_production_transport_is_wired` |
| Транспорт | `http://`, локальные, частные, link-local, CGNAT, IPv6-local и документационные адреса в боевой настройке | закрыто тестом | `production_transport_rejects_http_url`, `production_transport_rejects_test_hosts`, `production_transport_rejects_ip_literal_hosts`, `production_transport_rejects_link_local_and_cgnat_hosts`, `production_transport_rejects_ipv6_local_hosts` |
| Транспорт | IPv4-mapped IPv6 ведёт на локальный, частный, CGNAT или документационный адрес | закрыто тестом | `production_transport_rejects_ipv4_mapped_ipv6_forbidden_hosts` |
| Транспорт | неверный SPKI pin | закрыто тестом | `wrong_key_for_same_server_is_rejected_after_inner_accepts` |
| Транспорт | pin не должен обходить обычную проверку сертификата | закрыто тестом | `matching_pin_does_not_bypass_inner_certificate_failure` |
| KT | root без достаточных подписей | закрыто тестом | `two_of_five_signatures_rejected` |
| KT | подмена root, epoch или подписи | закрыто тестом | `tampered_root_all_signatures_invalid`, `tampered_epoch_all_signatures_invalid`, `tampered_signature_bit_flip_invalid` |
| KT | подмена размера журнала или времени подписи свидетеля | закрыто тестом | `attack_canonical_sign_payload_binds_log_size_post_fix_f_phd_s68_1` |
| KT | повтор старой подписанной эпохи | закрыто тестом | `attack_replay_old_signed_epoch_blocked_by_monotonic_epoch_check` |
| KT | split-view при трёх злых свидетелях | честная граница | `threshold_compromised_views_can_verify_but_safety_numbers_diverge`: локально обе версии могут пройти, поэтому нужны сверка наблюдений и самопроверка |
| KT | split-view обнаруживается при обмене наблюдениями клиентов | локально закрыто обнаружение | `threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence` |
| OPRF | подмена blinded, token, nonce или device key | закрыто тестом | `verify_rejects_tampered_blinded`, `verify_rejects_tampered_token`, `verify_rejects_tampered_nonce`, `verify_rejects_wrong_device_pubkey` |
| OPRF | повтор серверного вызова | закрыто тестом | `production_context_rejects_replayed_server_nonce_after_first_success` |
| OPRF | повтор witness index или подмена доли | закрыто тестом | `threshold_combine_rejects_duplicate_index`, `threshold_tampered_share_breaks_combine` |
| Backup | подмена chat_id, recipient, timestamp, token, nonce или device key | закрыто тестом | `verify_rejects_tampered_chat_id`, `verify_rejects_tampered_recipient_device_pubkey`, `verify_rejects_tampered_timestamp`, `verify_rejects_tampered_token`, `verify_rejects_tampered_nonce`, `verify_rejects_wrong_device_pubkey` |
| Backup | повтор серверного вызова | закрыто тестом | `production_context_rejects_replayed_server_nonce_after_first_success` и `mock_transport_rejects_replayed_server_nonce` |
| Backup | неверный AAD в V1/V2 развёртке | закрыто тестом | `unwrap_fails_on_tampered_aad`, `v2_unwrap_rejects_tampered_canonical_aad` |
| Backup | V1/V2 смешение форматов и тихий fallback | закрыто тестом | `v1_wire_rejected_by_v2_parser`, `v2_wire_rejected_by_v1_parser`, `v1_byte_prefix_v2_length_buffer_rejected_by_both`, `v2_byte_prefix_v1_length_buffer_rejected_by_both` |
| Sealed Sender | подмена ciphertext, ключа получателя, версии или подписи | закрыто тестом | `phd_real_attacks_sealed_sender.rs`, `v1_v2_mixed_corpus.rs`, `v2_envelope_roundtrip.rs` |
| Sealed Sender | подделанная внутренняя подпись V2 после успешного расшифрования | закрыто тестом | `forged_inner_signature_rejected_after_successful_v2_decrypt` |
| Sealed Sender | повтор к другому получателю | закрыто тестом | `real_attack_replay_envelope_to_different_recipient_aad_blocks` |
| Sealed Sender | V1 как V2 и V2 как V1 | закрыто тестом | `real_attack_cross_version_replay_v1_to_v2_blocked` |
| Зависимости | опасная зависимость или cargo-deny policy обходятся локально | закрыто воротами | `scripts/audit-dependency-policy.sh` |
| Нагрузка | тысячи локальных KT-листьев с proof и witness-порогом | закрыто локальным тестом | `local_load_many_kt_leaves_keep_valid_inclusion_and_witness_roots` |
| Гонки | одновременный replay одного hash | закрыто локальным тестом | `concurrent_replay_guard_accepts_one_duplicate_hash_and_rejects_the_rest` |
| Гонки | параллельная проверка witness-эпох | закрыто локальным тестом | `concurrent_witness_verification_has_no_shared_state_corruption` |
| Секреты | отладочный вывод и недоделанные пути | закрыто локальным аудитом | `scripts/audit-local-release-hardening.sh` |

## Внешний реестр

Внешние источники и классы атак теперь зафиксированы в
`docs/security/external-crypto-attack-ledger-2026-05-14.md`. Общий выпускной
аудит требует этот файл и проверяет, что в нём есть OPRF/RFC 9497, KyberSlash и
честная `граница выпуска` для мест, которые нельзя закрыть без серверов,
живых устройств или боевых свидетелей.

Оставшиеся границы выпуска:

- публичный FFI-запуск клиента остаётся закрыт;
- Apple App Attest и Android Play Integrity закрыто отказывают без внешних
  корней доверия, разбора токенов и серверной связки;
- боевые свидетели KT должны быть развёрнуты отдельно, потому что локальный код
  не может сам доказать отсутствие split-view при захвате трёх свидетелей;
- интеграция с настоящими серверами ещё не считается готовой.

## English

This file records local attack gates for the Umbrella Protocol core. “Covered by
test” means a Rust test rejects tampering, replay, rollback, or wrong-version
input. “Release boundary” means the public production path remains closed until
the external part is wired.
