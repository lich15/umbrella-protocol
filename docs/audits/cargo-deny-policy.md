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

## Duplicate-Version Exceptions

Duplicate dependencies are denied by default. Current narrow exceptions are
allowed only when the latest upstream release still forces the old dependency.
As of 2026-05-13, `openmls_rust_crypto 0.5.1` is the newest available MLS
RustCrypto provider and still pulls `hpke-rs` with `libcrux-sha3 0.0.8`.
Umbrella's own PQ layer uses `libcrux-ml-dsa 0.0.9`, `libcrux-ml-kem 0.0.9`,
and `libcrux-kem 0.0.8` so `RUSTSEC-2026-0125` and `RUSTSEC-2026-0126` are
fixed. The old OpenMLS transitive libcrux internals must be rechecked when a
new OpenMLS provider is released.

As of 2026-05-15, `hpke-rs 0.6.1` also declared an unused optional libcrux HPKE
backend that pulled `libcrux-chacha20poly1305 <0.0.8` into `Cargo.lock` and
SBOM (`RUSTSEC-2026-0124`). Umbrella does not use that backend; the release
patch in `third_party/hpke-rs-0.6.1-umbrella` removes only that optional edge.
The root and fuzz lockfiles must not contain `hpke-rs-libcrux`, `libcrux-aead`,
or `libcrux-chacha20poly1305`.

## Command

```bash
cargo deny check
```

Local release gates now run `bash scripts/audit-dependency-policy.sh`.
The script checks that `bincode` is absent from the normal dependency tree and
runs `cargo deny check`. Missing `cargo-deny` is a gate failure, not a
successful check.

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

## Исключения для дублей

Дубли зависимостей запрещены по умолчанию. Узкие исключения разрешены только
когда последний выпуск внешней библиотеки всё ещё тянет старую зависимость.
На 2026-05-13 `openmls_rust_crypto 0.5.1` — самый свежий доступный MLS
RustCrypto-провайдер, и он всё ещё тянет `hpke-rs` с `libcrux-sha3 0.0.8`.
Собственный PQ-слой Umbrella использует `libcrux-ml-dsa 0.0.9`,
`libcrux-ml-kem 0.0.9` и `libcrux-kem 0.0.8`, поэтому
`RUSTSEC-2026-0125` и `RUSTSEC-2026-0126` закрыты. Старые внутренности
libcrux внутри OpenMLS надо перепроверить, когда выйдет новый провайдер
OpenMLS.

На 2026-05-15 `hpke-rs 0.6.1` также объявлял неиспользуемый optional
libcrux-бэкенд HPKE, который попадал в `Cargo.lock` и SBOM через
`libcrux-chacha20poly1305 <0.0.8` (`RUSTSEC-2026-0124`). Umbrella этот бэкенд
не использует; выпускная заплатка в `third_party/hpke-rs-0.6.1-umbrella`
удаляет только эту optional-связь. Корневой и fuzz lockfile не должны содержать
`hpke-rs-libcrux`, `libcrux-aead` или `libcrux-chacha20poly1305`.

## Команда

```bash
cargo deny check
```

Локальные ворота выпуска теперь запускают `bash scripts/audit-dependency-policy.sh`.
Скрипт проверяет, что `bincode` не попал в обычное дерево зависимостей, и
запускает `cargo deny check`. Если `cargo-deny` не установлен, это считается
отказом ворот, а не успешной проверкой.

Каноническая конфигурация: [`deny.toml`](../../deny.toml).

## Внешняя PQ advisory-проверка, 2026-05-14

Сверено с внешним выпускным реестром атак:

- FIPS 203 / ML-KEM: параметры и обработка ciphertext покрыты PQ-тестами и
  `ml_kem_decapsulate_fuzz`.
- KyberSlash учитывается как риск зависимости и backend, а не только как риск
  парсера.
- `scripts/audit-dependency-policy.sh` остаётся выпускными воротами для
  RustSec и `cargo-deny`.
- Короткий локальный fuzz-прогон записан в
  `target/fuzz-overnight/20260514-184411`: 4 цели, падений нет.
