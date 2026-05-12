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
можно долго гонять тесты. Любой crash artifact нужно уменьшить, превратить в
регрессионный тест и провести через обычный процесс уязвимостей, если он влияет
на безопасность.
