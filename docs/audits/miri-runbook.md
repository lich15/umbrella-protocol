# Miri Runbook

[English](#english) | [Русский](#русский)

## English

Miri is used as a defense-in-depth check for undefined behavior in Rust code
paths that are practical to interpret.

## Local Commands

```bash
bash scripts/run-miri-local-gates.sh
```

Miri does not replace fuzzing, human code inspection, or platform testing. It
catches a specific class of Rust undefined-behavior issues and is most useful
when run on small focused packages.

The FFI production bootstrap tests use `tokio` runtime setup. On macOS, Miri
does not support `kqueue`, so those specific async runtime tests are skipped
under Miri and are covered by native `cargo test --workspace --all-features
--locked`.

OPRF proptest blocks are skipped under Miri because interpreted Ristretto255
property runs are too slow for a local gate. Fixed OPRF tests still execute
under Miri; the full property set runs in native locked Cargo tests.
The max-size OPRF roundtrip and threshold algebra tests are also skipped under
Miri for the same runtime reason and remain mandatory in native locked Cargo
tests.

The script runs the practical OPRF filters: production fail-closed, bad wire
rejection, and one small OPRF roundtrip.

---

## Русский

Miri используется как дополнительная проверка undefined behavior в тех путях
Rust-кода, которые практически можно интерпретировать.

## Локальные команды

```bash
bash scripts/run-miri-local-gates.sh
```

Miri не заменяет fuzz-проверки, человеческую проверку кода или платформенные
тесты. Он ловит отдельный класс проблем неопределённого поведения в Rust и
полезнее всего на небольших сфокусированных пакетах.

Тесты FFI production bootstrap поднимают `tokio` runtime. На macOS Miri не
поддерживает `kqueue`, поэтому именно эти async runtime тесты под Miri явно
пропускаются и покрываются обычным `cargo test --workspace --all-features
--locked`.

OPRF proptest-блоки под Miri пропускаются, потому что интерпретируемые
Ristretto255 property-прогоны слишком медленные для локальных ворот.
Фиксированные OPRF-тесты под Miri всё равно выполняются; полный property-набор
идёт в обычных locked Cargo тестах.
OPRF max-size roundtrip и threshold algebra тесты по той же причине тоже
пропускаются под Miri, но остаются обязательными в обычных locked Cargo тестах.

Скрипт запускает практичные OPRF-фильтры: production fail-closed, отказ на
плохом wire и один короткий OPRF roundtrip.
