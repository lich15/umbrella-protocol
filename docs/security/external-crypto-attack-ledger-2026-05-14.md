# Внешний реестр атак Umbrella Protocol

Дата: 2026-05-14

Этот файл связывает внешние источники с локальными проверками Umbrella
Protocol. Форумы и журналы используются как разведка идей, но итоговый статус
должен опираться на стандарт, статью, advisory, код или воспроизводимый тест.

## Статусы

- `закрыто тестом` — есть Rust-тест, fuzz-цель или скрипт, который ломает атаку.
- `закрыто отказом` — локальный путь не открывается и возвращает понятную ошибку.
- `граница выпуска` — нужна серверная часть, живое устройство, внешние корни доверия или боевые свидетели.
- `неприменимо` — атака не относится к текущему коду; причина записана.

## Матрица

| Область | Источник | Дата доступа | Атака простыми словами | Место в Umbrella | Статус | Доказательство |
|---|---|---|---|---|---|---|
| OPRF | RFC 9497 `https://www.rfc-editor.org/rfc/rfc9497` | 2026-05-14 | неверная точка, повтор, неправильная финализация | `umbrella-oprf` | закрыто тестом | `crates/umbrella-oprf/tests/external_rfc9497_attacks.rs`, `crates/umbrella-oprf/tests/test_lagrange_determinism.rs`, `crates/umbrella-oprf/src/primitives.rs` |
| KT | CONIKS `https://coniks.cs.princeton.edu/`, Trillian `https://transparency.dev/` | 2026-05-14 | split-view при злых свидетелях | `umbrella-kt` | граница выпуска | `threshold_compromised_views_can_verify_but_safety_numbers_diverge` показывает, что злой порог свидетелей локально может пройти; `threshold_signed_split_views_verify_locally_but_client_exchange_detects_divergence` показывает обнаружение только после обмена наблюдениями клиентов. Полное предотвращение остаётся границей выпуска для серверного обмена наблюдениями, самопроверки и боевых свидетелей. |
| TLS | RFC 8446 `https://www.rfc-editor.org/rfc/rfc8446` | 2026-05-14 | downgrade, replay, слабый транспорт | `umbrella-client/src/transport` | закрыто тестом | `matching_pin_does_not_bypass_inner_certificate_failure`, `wrong_key_for_same_server_is_rejected_after_inner_accepts`, URL rejection tests in `http2_client.rs` |
| PQ | FIPS 203 `https://csrc.nist.gov/pubs/fips/203/final` | 2026-05-14 | неправильный ML-KEM ciphertext и timing-риск | `umbrella-pq` | закрыто тестом | `ml_kem_decapsulate_fuzz`, dependency gate, fuzz evidence `target/fuzz-overnight/20260514-184411` |
| PQ | FIPS 204 `https://csrc.nist.gov/pubs/fips/204/final` | 2026-05-14 | неправильная ML-DSA подпись | `umbrella-pq`, `umbrella-identity` | закрыто тестом | hybrid signature parser/fuzz |
| PQ | FIPS 205 `https://csrc.nist.gov/pubs/fips/205/final` | 2026-05-14 | неправильный SLH-DSA режим | `umbrella-identity` | граница выпуска | SLH-DSA остаётся отдельной выпускной проверкой identity/PQ режима |
| PQ | KyberSlash `https://eprint.iacr.org/2024/1049` | 2026-05-14 | timing leakage при decapsulation | `umbrella-pq` | закрыто тестом | dependency policy + fuzz no-panic, evidence `target/fuzz-overnight/20260514-184411` |
| Backup | RFC 9180 `https://www.rfc-editor.org/rfc/rfc9180` | 2026-05-14 | неверный AAD и replay | `umbrella-backup` | закрыто тестом | tamper tests in `cloud_wrap/signed_request.rs`, AAD tests in `cloud_wrap/unwrap.rs` and `cloud_wrap/pq_wrap.rs`, mixed V1/V2 corpus tests |
| Sealed Sender | Signal specs `https://signal.org/docs/specifications/` | 2026-05-14 | replay к другому получателю, подмена подписи | `umbrella-sealed-sender` | закрыто тестом | forged inner signature test, cross-recipient replay test, cross-version replay test, random V2 unseal fuzz test |
| MLS | RFC 9420 `https://www.rfc-editor.org/rfc/rfc9420` | 2026-05-14 | downgrade и group-state inconsistency | `umbrella-mls` | закрыто тестом | MLS parser/group tests |
| SFrame | RFC 9605 `https://www.rfc-editor.org/rfc/rfc9605` | 2026-05-14 | tampered frame/header, nonce/key misuse | `umbrella-calls`, `umbrella-vectors` | закрыто тестом | SFrame vectors and parser tests |
| Устройства | WebAuthn `https://www.w3.org/TR/webauthn-3/` | 2026-05-14 | rollback счётчика и mismatch ключа | `umbrella-platform-verifier` | закрыто тестом | WebAuthn tests |
| Устройства | Apple App Attest `https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server` | 2026-05-14 | fake attestation без Apple trust material | `umbrella-platform-verifier` | закрыто отказом | production verifier unavailable |
| Устройства | Android Play Integrity `https://developer.android.com/google/play/integrity` | 2026-05-14 | fake verdict без Google trust material | `umbrella-platform-verifier` | закрыто отказом | production verifier unavailable |
| Зависимости | RustSec `https://rustsec.org/advisories/` | 2026-05-14 | уязвимая зависимость | workspace | закрыто тестом | `scripts/audit-dependency-policy.sh` |
| Зависимости | cargo-deny `https://embarkstudios.github.io/cargo-deny/` | 2026-05-14 | обход политики зависимостей | workspace | закрыто тестом | `cargo deny check` |
| Зависимости | SLSA `https://slsa.dev/spec/v1.1/` | 2026-05-14 | ложная цепочка поставки | workspace | граница выпуска | SLSA используется как ориентир, уровень не заявляется |

## Обязательные границы

- `rust_1mlrd` не трогаем.
- Реальные Android/iOS устройства не трогаем.
- Серверная интеграция не входит в эту фазу.
- Публичный FFI/client bootstrap остаётся закрыт.
