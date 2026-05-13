# Formal And Local Lint Gate Status

Дата: 2026-05-13

## English

This note records the actual local status of the formal-verification and local
lint gates after Phase 2 hardening. The commands below were run from the
repository root. Raw outputs were captured under
`target/phase2-formal-lint-evidence/`; that directory is local evidence and is
not part of the committed public docs.

| Gate | Command | Exit | Status |
|---|---|---:|---|
| Format | `cargo fmt --all -- --check` | 0 | Passed, no formatter diff. |
| Clippy | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | 0 | Passed with warnings denied. |
| Rustdoc | `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked` | 0 | Passed with documentation warnings denied. |
| Formal readiness | `bash scripts/verify-formal-production-readiness.sh` | 0 | Passed: ProVerif `oprf_ristretto255` and the listed Tamarin downgrade lemmas verified. |
| ProVerif models | `bash scripts/verify-proverif-models.sh` | 0 | Passed: 4 ProVerif models verified. The script now falls back to `opam exec` when `proverif` is not directly in `PATH`. |
| Tamarin models | `bash scripts/verify-tamarin-models.sh` | 0 | Passed: 9 Tamarin models verified. |
| Dylint | `DYLINT_RUSTFLAGS="-D warnings" cargo dylint --all --path crates/umbrella-lints --workspace -- --ignore-rust-version --all-targets --all-features --locked` | 0 | Passed after loading the local lint crate through `--path`; findings are treated as errors. |

Important boundaries:

- These commands are current release gates only for the models and lint rules
  present in this repository today. They are not a mathematical proof of the
  whole deployed system.
- Dylint still uses pinned `nightly-2025-09-18` because the local lint crate is
  tied to Dylint and Clippy internals. `--ignore-rust-version` keeps the gate
  runnable while the main workspace declares stable Rust 1.95. A future Dylint
  maintenance pass should bump the nightly and `clippy_utils` together.
- The old documented Dylint command with `--manifest-path` is not counted as a
  gate because it can return exit 0 while loading no local lint libraries.

## Русский

Эта заметка фиксирует реальный локальный статус формальных проверок и местных
правил качества после Фазы 2. Команды запускались из корня репозитория. Сырые
выводы сохранены в `target/phase2-formal-lint-evidence/`; это локальное
доказательство, оно не входит в публичные документы коммита.

| Ворота | Команда | Код | Статус |
|---|---|---:|---|
| Формат | `cargo fmt --all -- --check` | 0 | Прошло, формат менять не надо. |
| Clippy | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | 0 | Прошло, предупреждения запрещены. |
| Документация Rust | `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked` | 0 | Прошло, предупреждения документации запрещены. |
| Общая формальная проверка | `bash scripts/verify-formal-production-readiness.sh` | 0 | Прошло: ProVerif `oprf_ristretto255` и Tamarin-леммы про downgrade подтверждены. |
| Модели ProVerif | `bash scripts/verify-proverif-models.sh` | 0 | Прошло: 4 модели ProVerif подтверждены. Скрипт теперь использует `opam exec`, если `proverif` не найден напрямую в `PATH`. |
| Модели Tamarin | `bash scripts/verify-tamarin-models.sh` | 0 | Прошло: 9 моделей Tamarin подтверждены. |
| Dylint | `DYLINT_RUSTFLAGS="-D warnings" cargo dylint --all --path crates/umbrella-lints --workspace -- --ignore-rust-version --all-targets --all-features --locked` | 0 | Прошло после загрузки местного крейта правил через `--path`; найденные проблемы считаются ошибками. |

Границы:

- Эти команды являются текущими воротами выпуска только для моделей и правил,
  которые сейчас есть в репозитории. Это не математическое доказательство всей
  развёрнутой системы.
- Dylint пока использует закреплённый `nightly-2025-09-18`, потому что местный
  крейт правил зависит от внутренних частей Dylint и Clippy. Флаг
  `--ignore-rust-version` нужен, чтобы ворота запускались при основном Rust
  1.95. Отдельным обслуживанием нужно синхронно обновить nightly и
  `clippy_utils`.
- Старую команду Dylint с `--manifest-path` больше нельзя считать воротами:
  она может вернуть код 0, но не загрузить местные правила.
