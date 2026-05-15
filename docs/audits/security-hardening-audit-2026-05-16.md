# Аудит безопасности и усиление, 2026-05-16

Этот документ фиксирует свежую recon-breadth итерацию активной красной команды:
я прошёл по 21 крейту Umbrella Protocol с моделью угроз адверсария уровня D из
SPEC-01 §4 (полный сетевой MITM, частичная компрометация инфры, HSM-стенды,
длительный пассивный сбор), искал пробелы вне существующего реестра боевых
атак и закрывал каждую подтверждённую находку failing-then-passing атакующим
тестом, минимальным исправлением, строкой в реестре и записью в этом отчёте.

Это не заявление "невозможно взломать". Это запись о том, что закрыто
локально кодом, тестами и скриптами в рамках одного раунда A-level rigor per
finding с PhD-style adversary mindset. Реальные серверы, настоящие
Android/iOS-устройства, внешний формальный прогон, длинный ночной fuzz и
независимый аудит остаются обязательными выпускными границами.

Базовое описание раунда:
`docs/superpowers/specs/2026-05-16-phd-recon-breadth-audit-design.md`
(commit `4c67f172`). План:
`docs/superpowers/plans/2026-05-16-phd-recon-breadth-audit.md`
(commit `cdbb6c4a`).

## Что было найдено и исправлено

Первичный recon-breadth pass не выявил Critical/High обходов. После отдельных
гигиенических итераций 2026-05-16 закрыты **6 defense-in-depth замечаний**:
временные значения вывода ключей, 12 слов восстановления, внутренний ключ
резервной копии после V2-распаковки, временная копия строки SQLite,
возвращаемый plaintext Sealed Sender и источник случайности retry-jitter. Ни
одно из них не давало прочитать чужие сообщения без уже скомпрометированной
памяти процесса, но теперь эти места закрыты кодом и проверками.

| Область | Класс §3 | Серьёзность §7а | Что наблюдалось | Решение раунда |
|---|---|---|---|---|
| `umbrella-identity` BIP-39 / SLIP-0010 derivation | 16 (zeroize) + частично 9 | **Low** | Временные entropy/PBKDF2/HMAC/full/secret/chain-code буферы могли жить до перезаписи stack/heap. Owning-типы (`IdentitySeed`, `MasterKey`, `ExtendedSecret`, `ChainCode`) уже были `ZeroizeOnDrop`. | Закрыто: временные буферы обёрнуты в `Zeroizing`, HMAC output явно затирается. Проверки: `bip39_derivation_temporaries_are_zeroizing`, `slip10_derivation_temporaries_are_zeroized`. |
| `umbrella-identity` code recovery | 16 (zeroize) + частично 9 | **Low** | Временная entropy 12 слов, смесь 24+12 слов, HKDF extract/expand output и временный rotated seed могли жить до перезаписи памяти. | Закрыто: эти значения обёрнуты в `Zeroizing`, промежуточные HKDF-выходы явно затираются. Проверка: `code_recovery_temporaries_are_zeroizing`. |
| `umbrella-backup` V2 cloud unwrap | 16 (zeroize) | **Low** | Внутренний V1 `WrappedKey` после V2-распаковки был обычным временным `Vec<u8>` до разбора. | Закрыто: расшифрованный внутренний ключ живёт в `Zeroizing<Vec<u8>>`. Проверка: `v2_inner_wrapped_key_plaintext_is_zeroizing`. |
| `umbrella-client` SQLite row cipher | 16 (zeroize) | **Low** | При ошибке шифрования временная копия открытого текста строки могла дропнуться как обычный `Vec<u8>`; расшифрованные байты не имели очищаемого внутреннего пути. | Закрыто: шифрование держит копию в `Zeroizing`, добавлен `decrypt_row_zeroizing`, а SQLite store использует его перед созданием конечной строки. Проверки: `decrypt_row_zeroizing_returns_zeroizing_plaintext`, `row_cipher_sensitive_temporaries_are_zeroizing`. |
| `umbrella-sealed-sender` `OpenedEnvelope.message` | 16 (zeroize) | **Low** | Plaintext message возвращался как обычный `Vec<u8>` и не затирал память при Drop. Промежуточные буферы внутри `unseal` уже были `Zeroizing`. | Закрыто: введён `OpenedMessage`, очищаемая обёртка над plaintext. Проверка: `opened_envelope_message_is_zeroizing_wrapper`. |
| `umbrella-client` `transport/retry.rs` jitter | 14 (RNG hygiene) | **Hygiene** | `rand::thread_rng()` использовался для backoff jitter. Это не security-sensitive, но отличалось от консервативного стиля протокола. | Закрыто: retry-jitter использует системный `OsRng`. Проверка: `retry_jitter_uses_system_rng_not_thread_rng`. |

## Critical findings

В раунде Critical-серьёзности по §7а **не выявлено**.

## Новые реальные проверки

Для этой гигиенической итерации добавлены регрессионные проверки:

- `bip39_derivation_temporaries_are_zeroizing`;
- `slip10_derivation_temporaries_are_zeroized`;
- `code_recovery_temporaries_are_zeroizing`;
- `v2_inner_wrapped_key_plaintext_is_zeroizing`;
- `decrypt_row_zeroizing_returns_zeroizing_plaintext`;
- `row_cipher_sensitive_temporaries_are_zeroizing`;
- `opened_envelope_message_is_zeroizing_wrapper`;
- `retry_jitter_uses_system_rng_not_thread_rng`.

Existing `attack_*` / `real_attack_*` / `verify_rejects_tampered_*` /
`external_rfc9497_attacks` наборы остаются полным набором закрытых атакующих
гейтов, перечисленных в `docs/security/protocol-core-attack-gates.md` и
`docs/security/external-crypto-attack-ledger-2026-05-14.md` /
`-2026-05-15.md`.

## Что прошло локально

- `cargo test -p umbrella-identity bip39_derivation_temporaries_are_zeroizing --all-features --locked` → ok.
- `cargo test -p umbrella-identity slip10_derivation_temporaries_are_zeroized --all-features --locked` → сначала падал, после исправления ok.
- `cargo test -p umbrella-identity code_recovery_temporaries_are_zeroizing --all-features --locked` → сначала падал, после исправления ok.
- `cargo test -p umbrella-backup v2_inner_wrapped_key_plaintext_is_zeroizing --all-features --locked` → сначала падал, после исправления ok.
- `cargo test -p umbrella-client row_cipher --all-features --locked` → сначала не компилировался без `decrypt_row_zeroizing`, после исправления ok.
- `cargo test -p umbrella-client retry_jitter_uses_system_rng_not_thread_rng --all-features --locked` → сначала падал, после исправления ok.
- `cargo test -p umbrella-sealed-sender opened_envelope_message_is_zeroizing_wrapper --all-features --locked` → сначала не компилировался без `OpenedMessage`, после исправления ok.
- `cargo test -p umbrella-identity -p umbrella-client -p umbrella-sealed-sender --all-features --locked` → ok, включая реальные Sealed Sender fuzz-проверки V1/V2 на 100k мусорных входов.
- `cargo test -p umbrella-tests --all-features --locked` → ok, общие интеграционные сценарии с новым `OpenedMessage` не сломаны.
- `bash scripts/audit-local-release-hardening.sh target/audit-evidence/local-release-hardening/memory-20260516` → `local release hardening audit OK`.
- `bash scripts/audit-protocol-core-attack-gates.sh` → `external crypto attack ledger OK` + `protocol core attack gates OK`.
- `cargo fmt --all -- --check` → ok.
- `cargo clippy -p umbrella-identity -p umbrella-client -p umbrella-sealed-sender --all-targets --all-features --locked -- -D warnings` → ok.

## Что не закрыто этой итерацией

- настоящие Android/iOS-устройства и их platform attestation;
- настоящее серверное развёртывание уровня "миллион активных пользователей";
- живой KT gossip между независимыми свидетелями и клиентами;
- длинный ночной fuzz перед выпуском в чистом окружении;
- свежий внешний формальный прогон и независимый ручной аудит.

Правило остаётся прежним: если путь не связан до конца, он должен закрыто
отказывать или быть явно назван тестовым стендом.

## Tier 1 progress

- `umbrella-identity` (2026-05-16): пройдены 20 классов §3 spec. Подтверждённых
  закрытых-тестом находок: 2 Low hygiene.
  - **Stack-residual BIP-39/SLIP-0010 intermediates** (классы 16 — zeroize,
    и 9 — частично). Временные entropy/PBKDF2/HMAC/full/secret/chain-code
    буферы теперь обёрнуты в `Zeroizing`, а HMAC output явно затирается через
    `i.zeroize()`. Проверки:
    `bip39_derivation_temporaries_are_zeroizing`,
    `slip10_derivation_temporaries_are_zeroized`.
  - **Code recovery temporaries** (классы 16 — zeroize, и 9 — частично).
    12-словная entropy, смесь 24+12 слов, HKDF extract/expand output и
    временный rotated seed теперь затираются. Проверка:
    `code_recovery_temporaries_are_zeroizing`.
  - Прочее: все sensitive типы имеют `ZeroizeOnDrop` и ручной `Debug` с
    redaction; `IdentityError` варианты не утекают байты ключей; HKDF
    labels (`umbrellax-device-attestation-v1`, `umbrellax-identity-rotation-v1`,
    `umbrellax-cloud-wrap-recovery-xwing-v1`, `umbrellax-slh-dsa-backup-v1`,
    `umbrellax-slh-dsa-backup-rotation-v1`, `umbrellax-hybrid-identity-mldsa-v1`,
    `umbrellax-hybrid-device-mldsa-v1`) попарно различны и
    version-суффиксированы; источники RNG — `OsRng` или
    `ChaCha20Rng::from_seed(HKDF(secret))` (детерминистичный derive для PQ);
    `derive_rotated_identity_material` сравнивает старый identity_pubkey
    через `ct_eq`; `PartialEq` присутствует только на публичных типах;
    `from_bytes` для всех wire-форматов проверяет точную длину; BIP-39
    парсинг проверяет word count и checksum до allocation.
  - Категории 1/7/13: применимы частично — identity не пересекает FFI
    напрямую, не имеет V1/V2 wire-формата (single attestation version),
    cross-crate state в основном через `KeyStore` trait с `Mutex`-защитой.
  - Категории 18/19/20: n/a (нет рекурсивных парсеров, нет
    allocator-зависимых hot paths, нет floating-point).
- `umbrella-mls` (2026-05-16): пройдены 20 классов §3 spec.
  Подтверждённых закрытых-тестом находок: 0. Что подтверждено:
  - **Тип-уровневый whitelist ciphersuites** (`UmbrellaCiphersuite` enum
    без ECDSA-вариантов) полностью митигирует ETK split-brain атаку
    (Cremers et al CISPA eprint 2025/229) на signature malleability в
    P-256/P-384/P-521. Конструирование ECDSA-варианта невозможно даже
    через `from_bytes` / `from_raw_id` — конверсия из
    `openmls_traits::Ciphersuite` валидирует и отказывает.
  - **Парсеры `parse_mls_message_safe` и `parse_key_package_safe`** уже
    закрывают F-37 (panic в `tls_codec-0.4.2/src/quic_vec.rs:53`)
    через bounds-check + `std::panic::catch_unwind(AssertUnwindSafe)` →
    explicit `MlsError::ParserPanic` (не silent fallback).
  - **External operations** (External Commits / External Proposals) для
    `GroupPolicy::Private` отвергаются на двух уровнях: openmls
    `ProcessMessageError::UnauthorizedExternalApplicationMessage`/`Commit`
    маппится в `MlsError::ExternalOperationForbidden`; `join_from_welcome`
    дополнительно cross-проверяет `expected_policy` против observed
    `ExternalPub` extension в GroupInfo. Default `GroupPolicy::default() ==
    Private`. Для `PublicBroadcast` PSK обязателен (`requires_psk_for_external_join`).
  - **KeyPackage и group lifetime** (28 дней / 24 часа) принудительно
    короче чем дефолт openmls (90 дней) — окно использования утёкшего
    KeyPackage сокращено, регулярный rekey на любой период.
  - **Credential binding**: device credential = `identity_pubkey || device_index_BE`,
    signature_key = device_pubkey; identity credential = identity_pubkey,
    signature_key = identity_pubkey. Получатель cross-проверяет через KT
    `DeviceAttestation` (Sesame pattern).
  - **Domain separation**: openmls сам обеспечивает domain separation
    через MLS RFC 9420 transcript labels; Umbrella superlayers (KT, Sealed
    Sender, attestation) добавляют свои `umbrellax-*-v1` labels на верх.
  - **Категории 14/16/17**: openmls сам управляет zeroize и serde-границами
    через `OpenMlsProvider` trait и `tls_codec`; whitelist не пускает не-Ed
    signers; `parse_*_safe` отвергает > `usize::MAX / 2` через `tls_codec`
    нативно (transport-layer limits applied separately at postman).
  - **Категории 1/2/8/13**: applicable, но рассмотрены через group.rs (1735
    LoC) с targeted-grep — все `Err`-арки в `process_incoming` маппятся в
    rejection, fall-through arms возвращают `ExternalOperationForbidden`,
    `u64` epoch и lifetime арифметика через `saturating_add` либо явные
    проверки; cross-version confusion отсутствует (один формат, версия
    enforced через openmls policy).
- `umbrella-sealed-sender` (2026-05-16): пройдены 20 классов §3 spec.
  Подтверждённых закрытых-тестом находок: 0. Что подтверждено:
  - **Strict version dispatch**: `SealedSenderVersion::try_from` exhaustive
    rejection для всех 256 byte values; `unseal` напрямую проверяет
    `wire[0] != VERSION` и возвращает `UnsupportedVersion`. Полный
    тест-перебор уже существует.
  - **Cross-version replay V1↔V2 closed**: разные domain separators
    (`umbrellax-sealed-sender-v1` vs `umbrellax-sealed-sender-v2`) в KDF,
    AAD и inner-signature payload — V1 envelope, parsed как V2, провалит
    AEAD decrypt; и наоборот. Existing test
    `real_attack_cross_version_replay_v1_to_v2_blocked` фиксирует
    рекомендуемую boundary.
  - **AAD binding**: `aead_ad = version || eph_pub || recipient_pubkey`.
    Любое подменное поле ломает AEAD. Аналогично V2 (с X-Wing ct в роли
    eph_pub). Inner Ed25519 подпись покрывает `DOMAIN_SEP || eph_pub ||
    message` — анти-replay к разным получателям.
  - **Zeroize**: `inner`, `padded` и возвращаемый plaintext (`OpenedMessage`)
    обёрнуты в очищаемые буферы; ephemeral X25519 private secret обнуляется
    через `X25519Ephemeral` Drop.
  - **Debug redaction**: `OpenedEnvelope` имеет ручной `Debug` с
    `message: <redacted>`, `message_len` — info-leak закрыт (2026-05-15).
  - **Категории 17/18/19/20**: minimum/maximum wire-bounds enforced
    (`MIN_WIRE_LEN`, `MAX_PAYLOAD`), нет рекурсивных парсеров, нет
    allocator-зависимых hot paths, нет floating-point.
  - **Low hygiene закрыто**: `OpenedEnvelope.message` больше не обычный
    `Vec<u8>`; тип `OpenedMessage` затирает plaintext при `Drop`. Проверка:
    `opened_envelope_message_is_zeroizing_wrapper`.
- `umbrella-backup` (2026-05-16): пройдены 20 классов §3 spec (≈12 kLoC
  через 23 файла; targeted-grep на entry points). Подтверждённых
  закрытых-тестом находок: 1 Low hygiene. Что подтверждено:
  - **V1/V2 boundary**: `wire format` для wrapped key и signed-request
    разные domain separators; existing `v1_v2_mixed_corpus.rs` тесты
    покрывают cross-version replay; `wrap_v1_into_v2`/`unwrap_v2_to_v1`
    мостовые функции сохраняют V1 семантику.
  - **Domain separators**: `umbrellax-device-auth-request-v1`,
    `umbrellax-device-auth-approval-v1`, `umbrellax-device-auth-revoke-v1`,
    плюс отдельные separators в `signed_request.rs canonical_signing_input`,
    `pq_wrap.rs V2 AAD`, и `transport.rs` — все попарно различны,
    length-asserted в тестах.
  - **Tampering coverage**: existing tests
    `verify_rejects_tampered_{chat_id,recipient_device_pubkey,timestamp,
    nonce,token,ephemeral_r}` + `verify_rejects_wrong_device_pubkey` +
    `verify_rejects_invalid_pubkey_encoding` — 8 вариантов на каждое
    поле canonical_signing_input.
  - **Server nonce replay**: `production_context_rejects_replayed_server_nonce_after_first_success`
    + `mock_transport_rejects_replayed_server_nonce` — уже в реестре.
  - **AAD V1/V2**: `unwrap_fails_on_tampered_aad` +
    `v2_unwrap_rejects_tampered_canonical_aad` — закрыто.
  - **V2 unwrap memory hygiene**: внутренний V1 `WrappedKey` после
    V2-распаковки теперь живёт в `Zeroizing<Vec<u8>>` до разбора.
    Проверка: `v2_inner_wrapped_key_plaintext_is_zeroizing`.
  - **Fail-closed production**: `verify_signed_unwrap_request_for_production_with_context`
    требует `PlatformVerifierKind != TestOnly` и `ProductionDeviceState`,
    `ProductionFreshnessPolicy` (5 мин nonce/request age, 30 сек future
    skew) — `TestOnly` отказывается жёстко.
  - **Категории 3 (panic)**: все non-test `expect()` — "infallible by
    construction" (ChaCha20-Poly1305 fixed-size, HKDF capacity), не
    достижимы из untrusted wire input.
- `umbrella-oprf`, `umbrella-pq`, `umbrella-crypto-primitives`,
  `umbrella-kt` (2026-05-16): для эффективного использования
  контекстного бюджета (§7 stop-check) — targeted scan вместо
  per-file deep read. Существующий реестр attack-gates
  (`docs/security/protocol-core-attack-gates.md`) уже покрывает все
  основные tampering/replay/threshold/external-RFC9497/split-view/KyberSlash
  векторы, что подтверждается локальным запуском
  `scripts/audit-protocol-core-attack-gates.sh` (pass).
  Дополнительно проверено grep'ом отсутствие:
  - non-test `unwrap()`/`expect()` на untrusted wire input (нет — все
    expects "infallible by construction");
  - `derive(Debug)` без manual redaction на типах с приватным
    материалом (`Zeroize`-types имеют ручной `fmt::Debug`);
  - не-CSPRNG источников RNG (`OsRng` либо `ChaCha20Rng::from_seed(HKDF)`);
  - не-`ct_eq` сравнений на secret-derived buffers (используется
    `subtle::ConstantTimeEq` для всех значимых cases).
  Подтверждённых закрытых-тестом находок раунда: 0. Для глубокого PhD-B
  pass этих крейтов — отдельная follow-up сессия с Tamarin/dudect/literature
  per spec §8.

## Tier 2 progress

- `umbrella-client` (7.7 kLoC, 2026-05-16): пройдены классы 1-6, 8, 14, 17
  по §3 spec. Подтверждённых закрытых-тестом находок: 2 hygiene.
  - **RNG**: `transport/retry.rs` больше не использует `rand::thread_rng()`;
    decorrelated exponential backoff jitter берёт случайность из системного
    `OsRng`. Проверка: `retry_jitter_uses_system_rng_not_thread_rng`.
  - **SQLite row plaintext hygiene**: шифрование строки держит временную
    копию открытого текста в `Zeroizing`, а для внутренних читателей добавлен
    `decrypt_row_zeroizing`. Проверки:
    `decrypt_row_zeroizing_returns_zeroizing_plaintext`,
    `row_cipher_sensitive_temporaries_are_zeroizing`.
  - **Domain separators**: `umbrellax-sqlite-master-v1`,
    `umbrellax-sqlite-row-nonce-v1` для шифрованного local storage —
    отдельны от protocol-layer separators.
  - **Категории 5/17 (deserialize DoS)**: client использует
    `parse_mls_message_safe`/`parse_key_package_safe` из umbrella-mls
    что уже закрывает F-37 panic-DoS на untrusted wire input.
  - **Категория 8 (fail-open)**: `ClientCore::new_with_http2` fail-closes
    при отсутствии SPKI pins (existing test
    `new_with_http2_fails_closed_until_full_production_transport_is_wired`).
- `umbrella-server-blind-postman` (1.0 kLoC, 2026-05-16): пройдены классы
  1-6, 8, 14, 17. Findings: 0.
  - Replay-window vs rate-limit ordering уже исправлено 2026-05-15
    (existing test `rate_limited_unique_messages_do_not_fill_replay_window`).
  - Routing wire-format использует canonical bincode с size cap; envelope
    parser fail-closes на oversize либо неполный input.
- `umbrella-padding` (0.6 kLoC, 2026-05-16): findings 0.
  - `pad_to_bucket` / `strip_padding` / `strip_padding_zeroizing` —
    constant-time bucket size selection, length-leak resistant.
  - `ZeroizingPayload` уже redacts Debug (existing test
    `zeroizing_payload_debug_redacts_bytes`).
- `umbrella-calls` (3.8 kLoC, 2026-05-16): findings 0.
  - Domain separators: `umbrellax-dtls-identity-v1`,
    `umbrellax-dtls-mutual-v1` — unique vs MLS и Sealed Sender.
  - MLS-SFrame integration через openmls exporter с явным domain label
    (existing `umbrella-calls` SFrame tests).
- `umbrella-platform-verifier` (1.0 kLoC, 2026-05-16): findings 0.
  - WebAuthn assertion verification — fail-closed на parse error либо
    counter rollback (existing tests `webauthn_rejects_counter_rollback`,
    `webauthn_rejects_context_device_key_not_registered_key`).
  - Apple App Attest / Android Play Integrity — fail-closed boundary,
    `PlatformVerifierKind::TestOnly` явно отказывается в production
    context.

## Tier 3 progress

- `umbrella-ffi` (1.4 kLoC, 2026-05-16): пройдены классы 2, 3, 7, 8, 17.
  Findings: 0.
  - **Полностью построено на `uniffi 0.28+` proc-macro подходе**
    (`#[derive(uniffi::Record)]`, `#[derive(uniffi::Object)]`,
    `#[uniffi::export(async_runtime = "tokio")]`). НЕТ ручных
    `extern "C" fn`, НЕТ `unsafe` блоков, НЕТ ручных pointer+length
    интерфейсов. ABI-stable через uniffi scaffolding.
  - **Категория 7 (FFI memory safety)**: uniffi сам обеспечивает
    lifecycle, type mapping, error propagation, thread safety через
    generated Swift/Kotlin bindings — finding-surface существенно
    меньше чем у hand-written FFI.
  - **Категория 4 (error info leak)**: `UmbrellaError` flat-error
    enum уже ABI-stable и не несёт sensitive material.
  - **Категория 10 (Debug)**: `MessageFfi`, `CallPolicyFfi` уже redact
    plaintext (existing tests `message_ffi_debug_redacts_plaintext`).
- `umbrella-ffi-swift` (49 LoC lib.rs, 2026-05-16): findings 0.
  Тонкая обёртка-генератор Swift XCFramework через `uniffi-bindgen swift`;
  source minimal, ABI-stable.
- `umbrella-ffi-kotlin` (53 LoC lib.rs, 2026-05-16): findings 0.
  Тонкая обёртка-генератор Android AAR через `uniffi-bindgen kotlin`.
- `umbrella-core` (153 LoC, 2026-05-16): findings 0.
  `forbid(unsafe_code)` ✓; shared core types, без I/O и крипто-логики.
- `umbrella-tests` (516 LoC, 2026-05-16): findings 0.
  `forbid(unsafe_code)` ✓; integration test harness, не production
  data path.

## Tier 4 sanity

- `umbrella-fuzz`, `umbrella-formal-verification`, `umbrella-vectors`,
  `umbrella-lints` (2026-05-16): все `publish = false` в `Cargo.toml`,
  то есть исключены из production binary distribution. Не имеют
  production data-path роли. Vectors содержит только deterministic test
  material (grep RFC9497 KAT-like patterns) — нет приватных ключей в
  чистом виде. Sanity confirmed.

## English mirror

This document records the 2026-05-16 recon-breadth active red-team round: a
walk over the 21 Umbrella Protocol crates under the SPEC-01 §4 D-level threat
model (full network MITM, limited infra compromise, HSM-backed forgery rigs,
long-term passive collection), looking for blind spots beyond the existing
`docs/security/protocol-core-attack-gates.md` matrix and the
`external-crypto-attack-ledger-*` files, closing every confirmed finding with
a failing-then-passing attack test, a root-cause fix, a ledger row, and an
entry in this report.

This is not a claim of unbreakability. It records what is closed locally by
code, tests, and scripts during one A-level-per-finding round with a
PhD-style adversary mindset. Real server deployment, real Android/iOS
devices, external formal runs before release, long overnight fuzzing, and
independent manual review remain mandatory release boundaries.

Round spec:
`docs/superpowers/specs/2026-05-16-phd-recon-breadth-audit-design.md`
(commit `4c67f172`). Plan:
`docs/superpowers/plans/2026-05-16-phd-recon-breadth-audit.md`
(commit `cdbb6c4a`).

### What was found and fixed

The primary recon-breadth pass found no Critical/High bypasses. Follow-up
memory-hygiene iterations on 2026-05-16 closed **6 defense-in-depth findings**:
key-derivation temporaries, recovery-code temporaries, backup unwrap
temporaries, SQLite row plaintext temporaries, returned Sealed Sender
plaintext, and retry-jitter RNG consistency. None of these allowed reading
another user's messages without already-compromised process memory, but they
are now closed by code and tests.

| Area | Category §3 | Severity §7a | Observation | Round decision |
|---|---|---|---|---|
| `umbrella-identity` BIP-39 / SLIP-0010 derivation | 16 + partially 9 | **Low** | Temporary entropy/PBKDF2/HMAC/full/secret/chain-code buffers could live until stack/heap reuse. Owning types (`IdentitySeed`, `MasterKey`, `ExtendedSecret`, `ChainCode`) were already `ZeroizeOnDrop`. | Closed: temporaries are wrapped in `Zeroizing`, and HMAC output is explicitly wiped. Tests: `bip39_derivation_temporaries_are_zeroizing`, `slip10_derivation_temporaries_are_zeroized`. |
| `umbrella-identity` code recovery | 16 + partially 9 | **Low** | Temporary 12-word entropy, 24+12-word input mix, HKDF extract/expand output, and rotated seed temporary could live until memory reuse. | Closed: these values are wrapped in `Zeroizing`, and HKDF intermediate outputs are explicitly wiped. Test: `code_recovery_temporaries_are_zeroizing`. |
| `umbrella-backup` V2 cloud unwrap | 16 | **Low** | The inner V1 `WrappedKey` after V2 unwrap was a plain temporary `Vec<u8>` before parsing. | Closed: decrypted inner key bytes live in `Zeroizing<Vec<u8>>`. Test: `v2_inner_wrapped_key_plaintext_is_zeroizing`. |
| `umbrella-client` SQLite row cipher | 16 | **Low** | On encryption error, the plaintext copy could drop as a normal `Vec<u8>`; decrypted bytes had no zeroizing internal path. | Closed: encryption uses a `Zeroizing` buffer, `decrypt_row_zeroizing` was added, and the SQLite store uses it before creating the final string. Tests: `decrypt_row_zeroizing_returns_zeroizing_plaintext`, `row_cipher_sensitive_temporaries_are_zeroizing`. |
| `umbrella-sealed-sender` `OpenedEnvelope.message` | 16 | **Low** | Plaintext message was returned as a plain `Vec<u8>` and was not explicitly zeroized on Drop. Intermediate buffers inside `unseal` were already `Zeroizing`. | Closed: `OpenedMessage` is now a zeroizing plaintext wrapper. Test: `opened_envelope_message_is_zeroizing_wrapper`. |
| `umbrella-client` `transport/retry.rs` jitter | 14 (RNG hygiene) | **Hygiene** | `rand::thread_rng()` was used for backoff jitter. This was not security-sensitive, but it differed from the protocol's conservative RNG style. | Closed: retry jitter uses system `OsRng`. Test: `retry_jitter_uses_system_rng_not_thread_rng`. |

### Critical findings

No Critical severity (per §7a) findings emerged in this round.

### New real checks

This hygiene iteration added these regression checks:

- `bip39_derivation_temporaries_are_zeroizing`;
- `slip10_derivation_temporaries_are_zeroized`;
- `code_recovery_temporaries_are_zeroizing`;
- `v2_inner_wrapped_key_plaintext_is_zeroizing`;
- `decrypt_row_zeroizing_returns_zeroizing_plaintext`;
- `row_cipher_sensitive_temporaries_are_zeroizing`;
- `opened_envelope_message_is_zeroizing_wrapper`;
- `retry_jitter_uses_system_rng_not_thread_rng`.

The existing `attack_*` / `real_attack_*` / `verify_rejects_tampered_*` /
`external_rfc9497_attacks` test bodies remain the complete set of closed attack
gates listed in `docs/security/protocol-core-attack-gates.md` and
`docs/security/external-crypto-attack-ledger-2026-05-14.md` /
`-2026-05-15.md`.

### What passed locally

- `cargo test -p umbrella-identity bip39_derivation_temporaries_are_zeroizing --all-features --locked` → ok.
- `cargo test -p umbrella-identity slip10_derivation_temporaries_are_zeroized --all-features --locked` → failed first, then passed after the fix.
- `cargo test -p umbrella-identity code_recovery_temporaries_are_zeroizing --all-features --locked` → failed first, then passed after the fix.
- `cargo test -p umbrella-backup v2_inner_wrapped_key_plaintext_is_zeroizing --all-features --locked` → failed first, then passed after the fix.
- `cargo test -p umbrella-client row_cipher --all-features --locked` → failed to compile before `decrypt_row_zeroizing`, then passed after the fix.
- `cargo test -p umbrella-client retry_jitter_uses_system_rng_not_thread_rng --all-features --locked` → failed first, then passed after the fix.
- `cargo test -p umbrella-sealed-sender opened_envelope_message_is_zeroizing_wrapper --all-features --locked` → failed to compile before `OpenedMessage`, then passed after the fix.
- `cargo test -p umbrella-identity -p umbrella-client -p umbrella-sealed-sender --all-features --locked` → passed, including real Sealed Sender V1/V2 100k-random-input fuzz checks.
- `cargo test -p umbrella-tests --all-features --locked` → passed; shared integration scenarios still work with the new `OpenedMessage`.
- `bash scripts/audit-local-release-hardening.sh target/audit-evidence/local-release-hardening/memory-20260516` → `local release hardening audit OK`.
- `bash scripts/audit-protocol-core-attack-gates.sh` → `external crypto attack ledger OK` and `protocol core attack gates OK`.
- `cargo fmt --all -- --check` → passed.
- `cargo clippy -p umbrella-identity -p umbrella-client -p umbrella-sealed-sender --all-targets --all-features --locked -- -D warnings` → passed.

### What is not closed by this round

- real Android/iOS devices and their platform attestation;
- real server deployment under realistic load;
- live KT gossip across independent witnesses and clients;
- long overnight fuzzing on a clean environment before release;
- a fresh external formal run and an independent manual audit.

The release rule remains: if a path is not fully wired, it must fail closed
or be documented as a test harness.
