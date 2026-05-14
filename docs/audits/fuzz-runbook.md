# Fuzz Runbook

[English](#english) | [Русский](#русский)

## English

Umbrella Protocol fuzz targets live under `crates/umbrella-fuzz`.

## Local Smoke Run

```bash
cargo test -p umbrella-fuzz --all-features
```

## Extended Run

```bash
bash scripts/run-fuzz-overnight.sh
```

The extended run is intended for long-running local or scheduled environments.
Any crash artifact should be reduced, converted into a regression test, and
tracked through the normal vulnerability process when it affects security.

---

## Русский

Fuzz targets Umbrella Protocol находятся в `crates/umbrella-fuzz`.

## Быстрая локальная проверка

```bash
cargo test -p umbrella-fuzz --all-features
```

## Длинный запуск

```bash
bash scripts/run-fuzz-overnight.sh
```

Длинный запуск предназначен для локальной машины или планового окружения, где
можно долго гонять тесты. Любой файл аварии нужно уменьшить, превратить в
регрессионный тест и провести через обычный процесс уязвимостей, если он влияет
на безопасность.

## Если появился slow-unit

`slow-unit` не равен взлому и не равен падению. Его надо проверить отдельно:

1. Запустить сохранённый файл один раз через ту же fuzz-цель.
2. Запустить сохранённый файл много раз подряд.
3. Если задержка повторяется, искать причину в коде и добавлять регрессионную
   проверку.
4. Если задержка не повторяется, записать это как наблюдение окружения и
   сохранить путь к артефакту.

Пример 2026-05-14: `oprf_lagrange_fuzz` записал один slow-unit, но тот же файл
повторно выполнился за 4 мс, а 1000 повторов заняли 3.343 сек. Это не было
падением или аварийной остановкой и не подтвердилось как устойчивая ошибка
протокола.
