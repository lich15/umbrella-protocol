# Miri Runbook

[English](#english) | [Русский](#русский)

## English

Miri is used as a defense-in-depth check for undefined behavior in Rust code
paths that are practical to interpret.

## Local Commands

```bash
cargo +nightly miri test -p umbrella-ffi --features ffi-miri-flags
cargo +nightly miri test -p umbrella-oprf --all-features
```

Miri does not replace fuzzing, human code inspection, or platform testing. It
catches a specific class of Rust undefined-behavior issues and is most useful
when run on small focused packages.

---

## Русский

Miri используется как дополнительная проверка undefined behavior в тех путях
Rust-кода, которые практически можно интерпретировать.

## Локальные команды

```bash
cargo +nightly miri test -p umbrella-ffi --features ffi-miri-flags
cargo +nightly miri test -p umbrella-oprf --all-features
```

Miri не заменяет fuzzing, человеческую проверку кода или платформенные тесты.
Он ловит отдельный класс проблем undefined behavior в Rust и полезнее всего на
небольших сфокусированных пакетах.
