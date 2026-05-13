# Dylint Rules

[English](#english) | [Русский](#русский)

## English

Umbrella Protocol keeps custom lint rules in `crates/umbrella-lints`.

The current rules focus on production safety:

- avoid equality checks on secret byte wrappers;
- avoid `unwrap()` and `expect()` in library code;
- require bilingual documentation on public API items where the crate enforces
  it;
- reject panic-oriented helpers in production library paths.

## Command

```bash
DYLINT_RUSTFLAGS="-D warnings" cargo dylint --all --path crates/umbrella-lints --workspace -- --ignore-rust-version --all-targets --all-features --locked
```

The command must load `crates/umbrella-lints` through `--path`; the older
`--manifest-path` form can exit 0 while loading no local lint libraries.
`--ignore-rust-version` is required while the pinned Dylint nightly is older
than the stable Rust version declared by the main workspace.
`DYLINT_RUSTFLAGS="-D warnings"` makes local lint findings fail the gate.
Current gate status is recorded in
[`formal-lint-status-2026-05-13.md`](formal-lint-status-2026-05-13.md).

---

## Русский

Umbrella Protocol хранит собственные lint-правила в `crates/umbrella-lints`.

Текущие правила сфокусированы на production-безопасности:

- не сравнивать secret byte wrappers обычным equality;
- не использовать `unwrap()` и `expect()` в библиотечном коде;
- требовать двуязычную документацию публичного API там, где это проверяет
  крейт;
- отклонять panic-oriented helpers в production library paths.

## Команда

```bash
DYLINT_RUSTFLAGS="-D warnings" cargo dylint --all --path crates/umbrella-lints --workspace -- --ignore-rust-version --all-targets --all-features --locked
```

Команда должна загружать `crates/umbrella-lints` через `--path`; старый вариант
с `--manifest-path` может завершиться кодом 0, но не загрузить локальные
правила. `--ignore-rust-version` нужен, пока закреплённый nightly для Dylint
старше стабильного Rust, указанного основным workspace.
`DYLINT_RUSTFLAGS="-D warnings"` делает предупреждения локальных правил
ошибкой. Текущий статус ворот записан в
[`formal-lint-status-2026-05-13.md`](formal-lint-status-2026-05-13.md).
