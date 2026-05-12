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
cargo dylint --all --manifest-path crates/umbrella-lints/Cargo.toml -- --workspace --all-targets --all-features
```

The Dylint job is advisory for local development and enforced in CI where the
nightly toolchain is available.

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
cargo dylint --all --manifest-path crates/umbrella-lints/Cargo.toml -- --workspace --all-targets --all-features
```

Dylint advisory для локальной разработки и enforced в CI там, где доступен
nightly toolchain.
