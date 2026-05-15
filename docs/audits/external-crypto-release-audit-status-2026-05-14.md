# Внешний крипто-аудит Umbrella Protocol

Дата: 2026-05-14

## Итог

Этот документ фиксирует выпускной внешний крипто-аудит без `rust_1mlrd`, без
реальных Android/iOS устройств и без настоящей серверной интеграции.

## Главные доказательства

- Внешний реестр атак: `docs/security/external-crypto-attack-ledger-2026-05-14.md`.
- Матрица локальных атак: `docs/security/protocol-core-attack-gates.md`.
- Evidence: `target/audit-evidence/external-crypto-release/20260514/`.
- Полный fuzz: `target/fuzz-overnight/20260514-191349/summary.txt`,
  итог `Failed: 0 / 27`.

## Что закрыто локально

- OPRF: входы, wire-форматы, replay, threshold checks, production fail-closed.
- KT: локальная подмена отклоняется; split-view обнаруживается при обмене
  наблюдениями.
- TLS/pinning: pin не обходит обычную проверку сертификата; плохие адреса
  отвергаются.
- PQ: fuzz и dependency gates закрывают локальные parser/advisory проверки.
- Backup: replay, AAD, V1/V2 смешение, tamper.
- Sealed Sender: replay, cross-version, forged signature, random bytes.
- MLS/SFrame/calls: локальные parser/vector/mode gates.
- Устройства: WebAuthn локально; Apple/Android закрыто отказывают без внешних
  корней доверия.
- Зависимости: RustSec/cargo-deny gate.

## Что осталось внешней границей

- настоящие серверы;
- настоящие Android/iOS устройства;
- настоящие Apple/Google trust roots и token validation;
- живые KT-свидетели, gossip/self-monitoring и операционное развёртывание;
- публичный FFI/client bootstrap;
- реальная нагрузка на миллион активных пользователей.

## Команды

Команды и журналы лежат в `target/audit-evidence/external-crypto-release/20260514/`.

Прогнано:

- `cargo fmt --all -- --check`;
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`;
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked`;
- `cargo test --workspace --all-features --locked`;
- `bash scripts/audit-external-crypto-attack-ledger.sh`;
- `bash scripts/audit-protocol-core-attack-gates.sh`;
- `bash scripts/audit-public-access-notices.sh`;
- `bash scripts/audit-dependency-policy.sh`;
- `bash scripts/audit-local-release-hardening.sh`;
- `bash scripts/run-miri-local-gates.sh target/audit-evidence/external-crypto-release/20260514/miri-local`;
- `bash scripts/run-fuzz-overnight.sh`;
- `bash scripts/verify-formal-production-readiness.sh`.
