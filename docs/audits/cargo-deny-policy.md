# Cargo Deny Policy

[English](#english) | [Русский](#русский)

## English

Umbrella Protocol uses `cargo-deny` to keep dependency licenses, advisories,
duplicate versions, and banned crates visible during release work.

## License Policy

Allowed third-party licenses are permissive or weak-copyleft licenses that do
not force redistribution of this source-available implementation under another
license. The repository's own license identifier is `LicenseRef-UPAL-1.0`.

Strong copyleft or source-available licenses that conflict with the repository
license are rejected unless a separate written legal decision is added.

## Advisory Policy

Known vulnerable dependencies fail the check unless the repository contains a
specific, dated exception with a technical reason. Exceptions must be narrow and
removed when a fixed dependency is available.

## Command

```bash
cargo deny check
```

The canonical configuration is [`deny.toml`](../../deny.toml).

---

## Русский

Umbrella Protocol использует `cargo-deny`, чтобы во время подготовки выпуска
были видны лицензии зависимостей, security advisory, дублирующиеся версии и
запрещённые крейты.

## Политика лицензий

Разрешены permissive и weak-copyleft лицензии сторонних зависимостей, которые
не заставляют распространять эту source-available реализацию под другой
лицензией. Собственный идентификатор лицензии репозитория:
`LicenseRef-UPAL-1.0`.

Strong copyleft или source-available лицензии, конфликтующие с лицензией
репозитория, отклоняются, если нет отдельного письменного юридического решения.

## Политика advisory

Известные уязвимые зависимости проваливают проверку, если в репозитории нет
точечного датированного исключения с технической причиной. Исключения должны
быть узкими и удаляться после появления исправленной зависимости.

## Команда

```bash
cargo deny check
```

Каноническая конфигурация: [`deny.toml`](../../deny.toml).
