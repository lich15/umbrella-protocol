# Боевые атакующие ворота ядра протокола

Дата: 2026-05-18 (обновлено после PR #6 — добавлены строки R20-R27 + MlockedSecret); reconciliation refresh 2026-05-20 добавил Max Ratchet v3 строки (aggressive DH PCS, idle window, deniability, codec robustness, PQ resistance)

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
| Транспорт | reserved DNS-имена `.example`, `.test`, `.local` и `example.com/net/org` выглядят как боевые адреса | закрыто тестом | `production_transport_rejects_reserved_dns_test_names` |
| Транспорт | IPv4-mapped IPv6 ведёт на локальный, частный, CGNAT или документационный адрес | закрыто тестом | `production_transport_rejects_ipv4_mapped_ipv6_forbidden_hosts` |
| Транспорт | неверный SPKI pin | закрыто тестом | `wrong_key_for_same_server_is_rejected_after_inner_accepts` |
| Транспорт | pin не должен обходить обычную проверку сертификата | закрыто тестом | `matching_pin_does_not_bypass_inner_certificate_failure` |
| KT | root без достаточных подписей | закрыто тестом | `two_of_five_signatures_rejected` |
| KT | подмена root, epoch или подписи | закрыто тестом | `tampered_root_all_signatures_invalid`, `tampered_epoch_all_signatures_invalid`, `tampered_signature_bit_flip_invalid` |
| KT | подмена размера журнала или времени подписи свидетеля | закрыто тестом | `attack_canonical_sign_payload_binds_log_size_post_fix_f_phd_s68_1` |
| KT | повтор старой подписанной эпохи | закрыто тестом | `attack_replay_old_signed_epoch_blocked_by_monotonic_epoch_check` |
| KT | split-view при трёх злых свидетелях | честная граница одиночного клиента | `threshold_compromised_views_can_verify_but_safety_numbers_diverge`: одна валидная голова не доказывает, что другой голове не дали другой root |
| KT | split-view обнаруживается при обмене наблюдениями | закрыто библиотечным тестом | `threshold_signed_split_views_verify_locally_but_production_api_detects_divergence`: `EquivocationEvidence` создаётся только из двух валидно подписанных конфликтующих наблюдений |
| KT | публичное наблюдение раскрывает личные данные | закрыто тестом | `public_observation_encoding_round_trips_without_private_account_data`: wire-формат содержит только log_id, roots, epoch, log_size, timestamp и подписи |
| KT | свидетель подписывает второй другой root для той же эпохи | закрыто локальной моделью | `witness_signing_ledger_rejects_second_different_root_for_same_epoch` |
| KT | откат или разрыв цепочки эпох | закрыто тестом | `observation_history_rejects_epoch_regression_and_broken_chain` |
| OPRF | подмена blinded, token, nonce или device key | закрыто тестом | `verify_rejects_tampered_blinded`, `verify_rejects_tampered_token`, `verify_rejects_tampered_nonce`, `verify_rejects_wrong_device_pubkey` |
| OPRF | RFC 9497 wrong length, bad Ristretto point, empty/oversize input | закрыто тестом | `external_rfc9497_attacks.rs` |
| OPRF | повтор серверного вызова | закрыто тестом | `production_context_rejects_replayed_server_nonce_after_first_success` |
| OPRF | повтор witness index или подмена доли | закрыто тестом | `threshold_combine_rejects_duplicate_index`, `threshold_tampered_share_breaks_combine` |
| Ключи | временные значения BIP-39 и SLIP-0010 остаются в памяти после вывода ключей | закрыто тестом | `bip39_derivation_temporaries_are_zeroizing`, `slip10_derivation_temporaries_are_zeroized` |
| Ключи | временные значения 12 слов восстановления, смеси 24+12 слов и промежуточного HKDF остаются в памяти после ротации identity | закрыто тестом | `code_recovery_temporaries_are_zeroizing` |
| Backup | подмена chat_id, recipient, timestamp, token, nonce или device key | закрыто тестом | `verify_rejects_tampered_chat_id`, `verify_rejects_tampered_recipient_device_pubkey`, `verify_rejects_tampered_timestamp`, `verify_rejects_tampered_token`, `verify_rejects_tampered_nonce`, `verify_rejects_wrong_device_pubkey` |
| Backup | повтор серверного вызова | закрыто тестом | `production_context_rejects_replayed_server_nonce_after_first_success` и `mock_transport_rejects_replayed_server_nonce` |
| Backup | неверный AAD в V1/V2 развёртке | закрыто тестом | `unwrap_fails_on_tampered_aad`, `v2_unwrap_rejects_tampered_canonical_aad` |
| Backup | V1/V2 смешение форматов и тихий fallback | закрыто тестом | `v1_wire_rejected_by_v2_parser`, `v2_wire_rejected_by_v1_parser`, `v1_byte_prefix_v2_length_buffer_rejected_by_both`, `v2_byte_prefix_v1_length_buffer_rejected_by_both` |
| Backup | внутренний V1 wrapped key после V2-распаковки остаётся обычным временным буфером | закрыто тестом | `v2_inner_wrapped_key_plaintext_is_zeroizing` |
| Sealed Sender | подмена ciphertext, ключа получателя, версии или подписи | закрыто тестом | `phd_real_attacks_sealed_sender.rs`, `v1_v2_mixed_corpus.rs`, `v2_envelope_roundtrip.rs` |
| Sealed Sender | подделанная внутренняя подпись V2 после успешного расшифрования | закрыто тестом | `forged_inner_signature_rejected_after_successful_v2_decrypt` |
| Sealed Sender | повтор к другому получателю | закрыто тестом | `real_attack_replay_envelope_to_different_recipient_aad_blocks` |
| Sealed Sender | V1 как V2 и V2 как V1 | закрыто тестом | `real_attack_cross_version_replay_v1_to_v2_blocked` |
| Sealed Sender | расшифрованный текст возвращается как обычный heap-буфер без затирания при Drop | закрыто тестом | `opened_envelope_message_is_zeroizing_wrapper` |
| Blind postman | unique flood сверх `rate-limit` раздувает replay-память | закрыто тестом | `rate_limited_unique_messages_do_not_fill_replay_window`: hash записывается в replay-окно только после разрешения rate-limit |
| Зависимости | опасная зависимость или cargo-deny policy обходятся локально | закрыто воротами | `scripts/audit-dependency-policy.sh` |
| Нагрузка | тысячи локальных KT-листьев с proof и witness-порогом | закрыто локальным тестом | `local_load_many_kt_leaves_keep_valid_inclusion_and_witness_roots` |
| Гонки | одновременный replay одного hash | закрыто локальным тестом | `concurrent_replay_guard_accepts_one_duplicate_hash_and_rejects_the_rest` |
| Гонки | параллельная проверка witness-эпох | закрыто локальным тестом | `concurrent_witness_verification_has_no_shared_state_corruption` |
| Повторы | случайная задержка повторов использует не общий системный генератор | закрыто тестом | `retry_jitter_uses_system_rng_not_thread_rng` |
| Локальная база | временная копия открытого текста строки живёт дольше нужного при шифровании или расшифровании | закрыто тестом | `decrypt_row_zeroizing_returns_zeroizing_plaintext`, `row_cipher_sensitive_temporaries_are_zeroizing` |
| Секреты | `Debug` и отладочные журналы раскрывают plaintext, token, server nonce, подписи, QR payload, TURN password или routing identifiers | закрыто тестами и локальным аудитом | redaction-тесты в `umbrella-backup`, `umbrella-oprf`, `umbrella-client`, `umbrella-ffi`, `umbrella-mls`, `umbrella-calls`, `umbrella-platform-verifier`, `umbrella-sealed-sender`, `umbrella-padding`, `umbrella-server-blind-postman`; `scripts/audit-local-release-hardening.sh` |
| Недоделанное | отладочный вывод и недоделанные пути выглядят боевыми | закрыто локальным аудитом | `scripts/audit-local-release-hardening.sh`, `scripts/audit-test-only-production-boundary.sh` |
| Изъятие устройства | identity_sk извлекается из памяти процесса при DKG | закрыто переделкой раунда 6 | R20 lldb: identity_sk_hits=0 в 3 фазах, ~2.22 GB просканировано (`docs/audits/device-capture-artifacts/r20_lldb_output.txt`) |
| Изъятие устройства | swap-eligible heap для master_key / exporter_secret / hedged witness | закрыто тестом | `MlockedSecret<T>` + 7 production storage sites; `umbrella-crypto-primitives::mlocked` тесты |
| Изъятие устройства | stack-spill BIP-39 entropy после drop(IdentitySeed) | закрыто тестом | `r7_closure_entropy_and_seed_are_heap_resident`; R7 lldb scan AFTER_DROP stack hits = 0 |
| Идентичность | jurisdiction subpoena → принудительное раскрытие PIN | закрыто тестом | `attack_r21_duress_pin_deletes_account`: reverse-PIN запускает `UNRECOVERABLE_DELETE` параллельно на 5 серверах |
| Идентичность | новое устройство принимается без задержки и push-отмены | закрыто тестом | `attack_r22_time_lock_recovery`: 24h time-lock, primary-push cancel |
| Идентичность | подделанный установочный пакет проходит обновление | закрыто тестом | `attack_r23_5_registry_detects_fake_version`: ≥4-of-5 registries должны совпасть |
| Чаты | secret-чат не маскируется при захвате экрана | закрыто тестом | `attack_r24_screen_recording_detected`: 100/100 сообщений замаскированы под Block policy |
| Чаты | PIN-экран не блокирует системные сервисы (Siri, AutoFill, ...) | закрыто тестом | `attack_r25_system_services_disabled`: 7/7 ограничений применены |
| Транспорт | DPI-блокировка единственного канала делает unlock невозможным | закрыто тестом | `attack_r26_dos_fallback_channels`: TLS → AltIP → Tor → Mixnet fallback chain |
| Производительность | сервер в критическом пути отправки сообщения | закрыто тестом | `attack_r27_speed_local_operations`: 1000 сообщений 42 ns/msg, 0 server RPC; локальная доставка через Sealed Sender |
| Max Ratchet v3 | compromised chain key at epoch E расшифровывает все следующие messages в том же epoch | закрыто тестом | `forward_secrecy_aggressive_dh_each_send_in_new_epoch` — 10 sends → 10 distinct epochs (`umbrella-client/tests/facade_max_ratchet_v3.rs`); strict monotonic +1 per send |
| Max Ratchet v3 | idle window attack — adversary с compromised chain key ждёт паузы > 5 мин чтобы декриптовать | закрыто тестом | `idle_window_attack_defence_timer_rekey_advances_epoch_after_pause` — 90s idle → force_rekey по таймеру → новая epoch |
| Max Ratchet v3 | court adversary attribute MAC к specific party (non-deniability) | закрыто тестом | `spqr_deniability_either_party_can_forge_mac_over_arbitrary_payload` — bit-equal MAC из обеих сторон с shared epoch_secret; 0 bits информации об авторстве |
| Max Ratchet v3 | SPQR HMAC integrity — tampered MAC либо ciphertext принимается | закрыто тестом | `end_to_end_alice_send_bob_decrypt_with_spqr_verify` Phase 9-10 — 1-bit flip → 100% rejection; `Mac::verify_slice` constant-time через `subtle::ConstantTimeEq` |
| Max Ratchet v3 | timing channel на `verify_hmac` (bit-by-bit MAC recovery, Lawson 2009) | закрыто тестом | dudect 1M samples Apple M2: site 10 verify_hmac \|t\|=0.000 CLEAN (3 consecutive runs), strict 4.5 PASS; FIPS 180-4 SHA-256 + `subtle::ConstantTimeEq` без short-circuit |
| Max Ratchet v3 | v3 envelope decoder panic на adversarial input | закрыто тестом | `v3_envelope_decoder_robust_to_adversarial_inputs` (8 sub-cases) + 256-iter proptest + libFuzzer 5.67M iterations: 0 panics, 0 overflows |
| Max Ratchet v3 | quantum adversary breaks X25519 (Shor) → восстанавливает session keys | закрыто тестом | `pq_triggered_mac_differs_from_classical_only_mac_on_same_ciphertext` (`umbrella-mls/tests/test_max_ratchet_pq_real.rs`) — реально X-Wing combine (X25519 ∥ ML-KEM-768) меняет SPQR HMAC keying |
| Max Ratchet v3 | v3 wire format ломает v2 readers либо collide с MLS ProtocolVersion | закрыто тестом | `reject_wrong_marker_legacy_mls_path` — v3 marker `0xFF` collision-free с MLS ProtocolVersion (first byte `0x01`); 460+ existing v2 tests pass unchanged |
| Discovery (Round 7) | сервер узнаёт plaintext phone из blinded queries | закрыто тестом | OPRF RFC 9497 blinding + Tamarin lemma `server_never_learns_plaintext_phone`; `attack_d1_plaintext_phone_leak` 4 sub-tests; 0 substring matches в 32 KB request/response |
| Discovery (Round 7) | сервер коррелирует @username queries от одного клиента | закрыто тестом | per-query anon-id HKDF + fresh CSPRNG salt + Tamarin `anon_id_unlinkable_across_queries`; `attack_d2_query_correlation`: 1000 queries → 0 collisions |
| Discovery (Round 7) | сервер возвращает поддельный device_pubkey для запрошенного handle (silent swap) | закрыто тестом | RFC 6962 KT inclusion proof + pinned epoch root + Tamarin `kt_bind_prevents_silent_swap`; `attack_d3_kt_bind_silent_swap`: 4 sub-cases |
| Discovery (Round 7) | 4-of-5 server cluster collusion восстанавливает address book | закрыто тестом | threshold 3-of-5 + OPRF SUF + 3 attack regression tests `attack_d4_cluster_collusion` |
| Discovery (Round 7) | OPRF response replay | закрыто тестом | server nonce + `NonceReplayGuard` (1000 rolling) + Tamarin `replay_protection_enforced`; `attack_d5_oprf_replay`: 5 sub-tests |

## Внешний реестр

Внешние источники и классы атак теперь зафиксированы в
`docs/security/external-crypto-attack-ledger-2026-05-14.md` и
`docs/security/external-crypto-attack-ledger-2026-05-15.md`. Общий выпускной
аудит требует эти файлы и проверяет, что в них есть OPRF/RFC 9497, KyberSlash,
split-view и честная `граница выпуска` для мест, которые нельзя закрыть без
серверов, живых устройств или боевых свидетелей.

Оставшиеся границы выпуска:

- публичный FFI-запуск клиента остаётся закрыт;
- Apple App Attest и Android Play Integrity закрыто отказывают без внешних
  корней доверия, разбора токенов и серверной связки;
- боевые свидетели KT и публичный канал наблюдений должны быть развёрнуты
  отдельно: локальный код теперь создаёт доказательство раздвоения и проверяет
  цепочку, но не может сам доказать, что живая сеть всегда обменялась
  наблюдениями;
- интеграция с настоящими серверами ещё не считается готовой.

## English

This file records local attack gates for the Umbrella Protocol core. “Covered by
test” means a Rust test rejects tampering, replay, rollback, or wrong-version
input. “Release boundary” means the public production path remains closed until
the external part is wired.
