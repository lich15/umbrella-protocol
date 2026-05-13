# Umbrella Lints

[English](#english) | [Русский](#русский)

## English

`umbrella-lints` contains local Dylint rules used by Umbrella Protocol during
security and production-readiness checks.

The crate is a development tool, not part of the runtime protocol. Its purpose
is to catch patterns that are easy to miss in review and risky in cryptographic
library code.

## Current Rules

- reject `unwrap()` and `expect()` in production library paths;
- reject `todo!()`, `unimplemented!()`, and `unreachable!()` in production
  library paths;
- reject assertion-style helpers where they can turn malformed input into a
  process panic;
- reject ordinary equality checks on secret byte wrappers;
- require bilingual public API documentation where the lint is enabled.

## Local Use

```bash
DYLINT_RUSTFLAGS="-D warnings" cargo dylint --all --path crates/umbrella-lints --workspace -- --ignore-rust-version --all-targets --all-features --locked
```

The CI policy is described in [`docs/audits/dylint-rules.md`](../../docs/audits/dylint-rules.md).

---

## Русский

`umbrella-lints` содержит локальные Dylint-правила, которые Umbrella Protocol
использует в проверках безопасности и готовности к выпуску.

Крейт является инструментом разработки, а не частью runtime-протокола. Его
задача - ловить шаблоны, которые легко пропустить при ревью и которые опасны в
криптографическом библиотечном коде.

## Текущие правила

- запрещают `unwrap()` и `expect()` в production library paths;
- запрещают `todo!()`, `unimplemented!()` и `unreachable!()` в production
  library paths;
- запрещают assertion-style helpers там, где malformed input может превратиться
  в process panic;
- запрещают обычные equality checks для secret byte wrappers;
- требуют двуязычную документацию публичного API там, где включён lint.

## Локальный запуск

```bash
DYLINT_RUSTFLAGS="-D warnings" cargo dylint --all --path crates/umbrella-lints --workspace -- --ignore-rust-version --all-targets --all-features --locked
```

Политика CI описана в [`docs/audits/dylint-rules.md`](../../docs/audits/dylint-rules.md).
