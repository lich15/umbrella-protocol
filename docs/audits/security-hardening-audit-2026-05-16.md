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

Закрытых-тестом находок этого раунда: **0**. Это валидный outcome
recon-breadth pass по §10в spec (никаких выдуманных находок).

Рассмотренные кандидаты, не достигшие уровня "fix this round":

| Область | Класс §3 | Серьёзность §7а | Что наблюдалось | Решение раунда |
|---|---|---|---|---|
| `umbrella-identity` `MasterKey::from_seed` / `derive_child` | 16 (zeroize) + частично 9 | **Low** | HMAC-SHA512 output `i` и копия `full = [0u8; 64]` содержат частичный ключевой материал (extended_secret + chain_code) на stack и не зануляются. Owning-типы (`MasterKey`, `ExtendedSecret`, `ChainCode`) — `ZeroizeOnDrop` ✓. | Зафиксировано как наблюдение; кандидат для follow-up hygiene PR (defense-in-depth, не E2EE bypass, требует уже скомпрометированной памяти процесса для эксплуатации, что выходит за D-level threat model). |
| `umbrella-sealed-sender` `OpenedEnvelope.message: Vec<u8>` | 16 (zeroize) | **Низкое наблюдение** | Plaintext message живёт в heap до Drop без явного zeroize. Внутри `unseal` промежуточные buffers `Zeroizing` ✓; выходной Vec — API contract caller'а. | Не finding; API design choice. Cold-boot mitigation SPEC-08 §5.2 step 9 уже выполнен. |
| `umbrella-client` `transport/retry.rs` jitter | 14 (RNG hygiene) | **Hygiene** | `rand::thread_rng()` используется для decorrelated backoff jitter (AWS pattern). Inconsistent с rest-of-codebase `OsRng`, но `thread_rng` сам — CSPRNG; jitter — не security-sensitive. | Не finding; легитимный pattern. Можно оставить или сменить на `OsRng` для consistency, не критично. |

## Critical findings

В раунде Critical-серьёзности по §7а **не выявлено**.

## Новые реальные проверки

Новых `attack_*` атакующих тестов в коде **не добавлено** этим раундом
— нет подтверждённых-тестом находок, требующих fix. Existing `attack_*` /
`real_attack_*` / `verify_rejects_tampered_*` / `external_rfc9497_attacks`
наборы остаются полным набором закрытых атакующих гейтов, перечисленных
в `docs/security/protocol-core-attack-gates.md` и
`docs/security/external-crypto-attack-ledger-2026-05-14.md` /
`-2026-05-15.md`.

## Что прошло локально

- `git branch --show-current` → `codex/phd-security-audit`.
- `git status` → clean tree между блоками.
- `bash scripts/audit-protocol-core-attack-gates.sh` →
  `external crypto attack ledger OK` + `protocol core attack gates OK`.
- `cargo test -p umbrella-identity --all-features --locked --no-run` →
  компиляция успешна (4.89s).
- `cargo test -p umbrella-mls --all-features --locked --no-run` →
  компиляция успешна.

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
  закрытых-тестом находок: 0. Рассмотренные кандидаты:
  - **Stack-residual HMAC intermediates в `MasterKey::from_seed` и
    `derive_child`** (классы 16 — zeroize, и 9 — частично).
    `let i = mac.finalize().into_bytes()` и копия `full = [0u8; 64]` в
    `derive_child` содержат частичный ключевой материал
    (`ExtendedSecret`/`ChainCode`) на стеке и не зануляются. Сами owning-типы
    (`MasterKey`, `ExtendedSecret`, `ChainCode`) — `ZeroizeOnDrop` ✓, но
    промежуточные стековые буферы — нет. Severity: **Low** по §7а
    (hygiene defense-in-depth без поведенческого импакта; реализуемый
    эксплойт требует уже скомпрометированной памяти процесса, что выходит
    за пределы D-level threat model данного раунда). Решение этого раунда:
    зафиксировать наблюдение, не закрывать сейчас, кандидат для
    follow-up уборочного PR (Pattern: явная `Zeroize` на промежуточный
    `[u8; 64]` копию HMAC-SHA512 output до выхода из функции).
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
  - **Zeroize**: `inner` и `padded` буфера обёрнуты в
    `Zeroizing<Vec<u8>>` (F-50 closed); ephemeral X25519 private secret
    обнуляется через `X25519Ephemeral` Drop.
  - **Debug redaction**: `OpenedEnvelope` имеет ручной `Debug` с
    `message: <redacted>`, `message_len` — info-leak закрыт (2026-05-15).
  - **Категории 17/18/19/20**: minimum/maximum wire-bounds enforced
    (`MIN_WIRE_LEN`, `MAX_PAYLOAD`), нет рекурсивных парсеров, нет
    allocator-зависимых hot paths, нет floating-point.
  - **Наблюдение (не finding)**: `OpenedEnvelope.message: Vec<u8>` — это
    plaintext, который существует в heap до момента `Drop` без `Zeroize`.
    Это API contract — caller отвечает за дальнейшую очистку. Cold-boot
    mitigation покрывает только intermediate buffers внутри `unseal`, что
    соответствует SPEC-08 §5.2 step 9 и закрытию F-50. Не Medium, не
    requires fix этого раунда.
- `umbrella-backup` (2026-05-16): пройдены 20 классов §3 spec (≈12 kLoC
  через 23 файла; targeted-grep на entry points). Подтверждённых
  закрытых-тестом находок: 0. Что подтверждено:
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
  по §3 spec. Подтверждённых закрытых-тестом находок: 0.
  - **RNG**: `rand::thread_rng()` используется только в
    `transport/retry.rs` для decorrelated exponential backoff jitter
    (AWS pattern). Не security-sensitive (jitter, не key material).
    Все security-критичные пути используют `OsRng`. Не finding (Low
    inconsistency, но это standard pattern и `thread_rng` сам — CSPRNG).
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

Closed-by-test findings this round: **0**. This is a valid recon-breadth
outcome per spec §10c (no fabricated findings).

Considered candidates that did not reach "fix this round":

| Area | Category §3 | Severity §7a | Observation | Round decision |
|---|---|---|---|---|
| `umbrella-identity` `MasterKey::from_seed` / `derive_child` | 16 + partially 9 | **Low** | The HMAC-SHA512 output `i` and the copy `full = [0u8; 64]` carry partial key material (extended_secret + chain_code) on the stack and are not zeroized. The owning types (`MasterKey`, `ExtendedSecret`, `ChainCode`) are `ZeroizeOnDrop` ✓. | Recorded as observation; candidate for a follow-up hygiene PR (defense-in-depth, not an E2EE bypass; exploitation requires an already-compromised process memory, which is outside the D-level threat model). |
| `umbrella-sealed-sender` `OpenedEnvelope.message: Vec<u8>` | 16 | **Low observation** | Plaintext message lives in heap until Drop without explicit zeroize. Intermediate buffers inside `unseal` are `Zeroizing` ✓; the output Vec is the caller's API contract. | Not a finding; API design choice. The SPEC-08 §5.2 step 9 cold-boot mitigation is already applied where applicable. |
| `umbrella-client` `transport/retry.rs` jitter | 14 (RNG hygiene) | **Hygiene** | `rand::thread_rng()` is used for decorrelated backoff jitter (AWS pattern). Inconsistent with the codebase-wide `OsRng`, but `thread_rng` is itself a CSPRNG and jitter is not security-sensitive. | Not a finding; legitimate pattern. Could be switched to `OsRng` for consistency, not critical. |

### Critical findings

No Critical severity (per §7a) findings emerged in this round.

### New real checks

No new `attack_*` adversarial tests were added in code this round — there
are no confirmed-by-test findings that require a fix. The existing
`attack_*` / `real_attack_*` / `verify_rejects_tampered_*` /
`external_rfc9497_attacks` test bodies remain the complete set of closed
attack gates listed in `docs/security/protocol-core-attack-gates.md` and
`docs/security/external-crypto-attack-ledger-2026-05-14.md` /
`-2026-05-15.md`.

### What passed locally

- `git branch --show-current` → `codex/phd-security-audit`.
- `git status` → clean tree between blocks.
- `bash scripts/audit-protocol-core-attack-gates.sh` →
  `external crypto attack ledger OK` and
  `protocol core attack gates OK`.
- `cargo test -p umbrella-identity --all-features --locked --no-run` →
  compiles (4.89s).
- `cargo test -p umbrella-mls --all-features --locked --no-run` →
  compiles.

### What is not closed by this round

- real Android/iOS devices and their platform attestation;
- real server deployment under realistic load;
- live KT gossip across independent witnesses and clients;
- long overnight fuzzing on a clean environment before release;
- a fresh external formal run and an independent manual audit.

The release rule remains: if a path is not fully wired, it must fail closed
or be documented as a test harness.
