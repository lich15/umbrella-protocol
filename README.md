# Umbrella Protocol

[English](#english) | [Русский](#русский)

## English

Umbrella Protocol is a source-available cryptographic protocol stack under
security hardening for the private messenger UmbrellaX. The
repository contains implemented Rust cryptographic crates and test harnesses,
but the public FFI/client production bootstrap is gated until every required
transport and verifier is wired end to end.

Current hardening status is recorded in
[`docs/security/current-status.md`](docs/security/current-status.md). The
internal production HTTP/2 builder wires platform certificate verification
together with SPKI pinning. Public FFI bootstrap remains gated until real
platform attestation verifiers, mobile bridges, and server integration are wired
end to end. Cloud unwrap and OPRF have contextual server-side attestation gates
that fail closed without those real platform verifiers. A local
platform-verifier crate checks shared token-size, app/site, nonce, key,
signature, and counter rules where enough material is available. WebAuthn has
local assertion verification. Apple App Attest and Android Play Integrity still
fail closed until external trust material, platform-token parsers, and
mobile/server integration are wired. The incomplete
`ClientCore::new_with_http2` path also fails closed until every service has
SPKI pins and real postman, KT, and call relay transports. See
[`docs/security/production-readiness-boundaries.md`](docs/security/production-readiness-boundaries.md).
Core protocol attack gates are recorded in
[`docs/security/protocol-core-attack-gates.md`](docs/security/protocol-core-attack-gates.md).
Local KT split-view hardening is implemented in `umbrella-kt`: public epoch
observations, witness non-equivocation memory, strict observation history, and
privacy-safe observation encoding are available for client-side detection. Live
client observation exchange and public witness deployment remain production
boundaries.
Supply-chain hardening for 1.1.0 removes the unused optional `hpke-rs` libcrux
HPKE backend from the root and fuzz lockfiles, so `RUSTSEC-2026-0124` is closed
in the checked dependency graph instead of being ignored.
The 2026-05-16 memory-hygiene pass zeroizes key-derivation, recovery-code,
backup unwrap, and SQLite row temporaries, returns Sealed Sender opened
plaintext through a zeroizing wrapper, and uses the system RNG for retry jitter.
External crypto release audit:
[`docs/audits/external-crypto-release-audit-status-2026-05-14.md`](docs/audits/external-crypto-release-audit-status-2026-05-14.md).
PhD-B six-round audit (rounds 1-6) on the 1.1.0 codebase was merged on
2026-05-18 in commit `84b4d576` (PR #6). The consolidated summary lives at
[`docs/audits/ROUND-1-TO-6-SUMMARY.md`](docs/audits/ROUND-1-TO-6-SUMMARY.md);
the independent reviewer verdict is in
[`docs/audits/phd-b-final-independent-review-2026-05-19.md`](docs/audits/phd-b-final-independent-review-2026-05-19.md).
Post-audit workspace baseline is 2080 release-mode tests (up from 1977
pre round-6); one MAJOR scope-of-closure caveat (M-FINAL-1) is tracked for
v1.2.x.

This repository is public for transparency, reproducible builds, non-commercial
security testing, cryptographic testing, and responsible vulnerability reports.
Umbrella Protocol is source-available, not open-source. Commercial use and
embedding in a business product, service, SDK, messenger, or infrastructure
platform require written permission. Read the access rules before using the
code: [`PUBLIC_ACCESS.md`](PUBLIC_ACCESS.md) and [`LICENSE`](LICENSE).

Version: **1.1.0 security hardening**.

### Quick Start

Use these commands from the repository root.

```bash
git clone https://github.com/lich15/umbrella-protocol.git
cd umbrella-protocol
rustup show
cargo build --workspace --all-features --locked
cargo test -p umbrella-core --locked
```

If the build works, the local machine can compile the project. If the quick test
works, the local Rust setup is ready.

### Repository Map

```text
.
├── crates/                      Rust crates
├── docs/                        public protocol and security documents
├── docs/security/               release manifest and SBOM
├── UmbrellaX_protocol_public_en.pdf  public protocol paper, English
├── UmbrellaX_protocol_public_ru.pdf  public protocol paper, Russian
├── examples/android-harness/    Android test app
├── examples/ios-harness/        iOS test package
├── scripts/                     local verification scripts
├── oss-fuzz/                    fuzzing integration
├── supply-chain/                supply-chain policy data
├── .github/workflows/           GitHub checks
├── Cargo.toml                   Rust workspace list and shared versions
├── Cargo.lock                   locked dependency graph
└── rust-toolchain.toml          pinned Rust version
```

Important crates:

- `crates/umbrella-core`: shared core types.
- `crates/umbrella-crypto-primitives`: low-level cryptographic helpers.
- `crates/umbrella-pq`: post-quantum primitives and hybrid wrappers.
- `crates/umbrella-identity`: identity keys and recovery logic.
- `crates/umbrella-mls`: group messaging profile.
- `crates/umbrella-kt`: key transparency.
- `crates/umbrella-platform-verifier`: local fail-closed platform checks.
- `crates/umbrella-sealed-sender`: sender hiding.
- `crates/umbrella-backup`: backup and recovery flows.
- `crates/umbrella-calls`: call protection pieces.
- `crates/umbrella-client`: client-facing protocol API.
- `crates/umbrella-server-blind-postman`: server router component.
- `crates/umbrella-ffi`: shared mobile foreign-function layer.
- `crates/umbrella-ffi-swift`: Swift package bindings.
- `crates/umbrella-ffi-kotlin`: Kotlin and Android bindings.
- `crates/umbrella-tests`: integration, adversarial, and compatibility tests.
- `crates/umbrella-fuzz`: fuzzing targets.
- `crates/umbrella-formal-verification`: formal model entry points.
- `crates/umbrella-vectors`: deterministic test vectors.

### Install Tools

The Rust version is pinned in [`rust-toolchain.toml`](rust-toolchain.toml). When
`rustup` is installed, it switches to the right toolchain inside this folder.

On macOS:

```bash
xcode-select --install
rustup show
cargo --version
```

On Debian Trixie:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates clang cmake curl git make perl pkg-config build-essential
rustup show
cargo --version
```

For Android builds, also install Android Studio or the Android command-line
tools, the Android SDK, NDK `26.2.11394342`, Java 17, and Gradle.

For iOS builds, use macOS with Xcode installed.

### Build

Normal full build:

```bash
cargo build --workspace --all-features --locked
```

Build with default features disabled:

```bash
cargo build --workspace --no-default-features --locked
```

Build one crate when you only changed one area:

```bash
cargo build -p umbrella-identity --locked
cargo build -p umbrella-client --all-features --locked
```

### Test

Fast smoke test:

```bash
cargo test -p umbrella-core --locked
```

Test one crate:

```bash
cargo test -p umbrella-pq --locked
cargo test -p umbrella-mls --all-features --locked
```

Full Rust test suite:

```bash
cargo test --workspace --all-features --locked
```

Use the full test suite before a release tag, after cryptographic changes, after
serialization changes, and after changes that affect more than one crate.

### Check Code Quality

Formatting:

```bash
cargo fmt --all -- --check
```

Warnings and lint checks:

```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Documentation build:

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
```

Public access notices:

```bash
bash scripts/audit-public-access-notices.sh
```

Test-only and incomplete production boundaries:

```bash
bash scripts/audit-test-only-production-boundary.sh
```

GitHub workflow policy:

```bash
bash scripts/audit-github-actions.sh
```

Post-quantum backend policy:

```bash
bash scripts/audit-pq-backend-policy.sh
```

Dependency policy:

```bash
bash scripts/audit-dependency-policy.sh
```

### Common Cases

If you changed only documentation:

```bash
bash scripts/audit-public-access-notices.sh
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
```

If you changed one Rust crate:

```bash
cargo fmt --all -- --check
cargo test -p umbrella-identity --locked
cargo clippy -p umbrella-identity --all-targets --all-features --locked -- -D warnings
```

Replace `umbrella-identity` with the crate you changed.

If you changed cryptographic logic:

```bash
cargo test --workspace --all-features --locked
bash scripts/audit-pq-backend-policy.sh
bash scripts/audit-dependency-policy.sh
```

If you changed wire formats, stored data, or test vectors:

```bash
cargo test -p umbrella-vectors --locked
cargo test -p umbrella-tests --all-features --locked
cargo test --workspace --all-features --locked
```

If you changed public mobile APIs:

```bash
bash scripts/audit-uniffi-generated-api.sh
```

Then run the iOS or Android build below, depending on the changed binding.

### iOS Build

Run from the repository root on macOS with Xcode installed.

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
./crates/umbrella-ffi-swift/build-xcframework.sh release
```

Run the iOS example package:

```bash
cd examples/ios-harness
xcodebuild test \
  -scheme UmbrellaTestHarness \
  -destination "platform=iOS Simulator,name=iPhone 15,OS=latest"
```

The produced framework is written under `target/xcframework-build/`.

### Android Build

Run from the repository root after Android SDK, NDK, Java 17, and Gradle are
available.

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
cargo install cargo-ndk --version 3.5.4 --locked
./crates/umbrella-ffi-kotlin/build-aar.sh release
gradle -p examples/android-harness assembleRelease --no-daemon
```

The Android example output is written under:

```text
examples/android-harness/app/build/outputs/apk/release/
```

### Fuzzing And Formal Checks

Fuzzing entry points live in `crates/umbrella-fuzz/` and `oss-fuzz/`.

```bash
cargo test -p umbrella-fuzz --locked
bash scripts/run-fuzz-overnight.sh
bash scripts/run-local-release-hardening.sh short
bash scripts/run-local-release-hardening.sh long
bash scripts/audit-local-release-hardening.sh
```

Formal verification entry points live in `crates/umbrella-formal-verification/`.

```bash
bash scripts/verify-formal-production-readiness.sh
bash scripts/verify-proverif-models.sh
bash scripts/verify-tamarin-models.sh
```

These commands need the matching external tools installed locally.

The current status of formal verification and local lint gates is recorded in
[`docs/audits/formal-lint-status-2026-05-13.md`](docs/audits/formal-lint-status-2026-05-13.md).
Local release hardening status is recorded in
[`docs/audits/local-release-hardening-status-2026-05-14.md`](docs/audits/local-release-hardening-status-2026-05-14.md).
Memory-hygiene hardening status is recorded in
[`docs/audits/security-hardening-audit-2026-05-16.md`](docs/audits/security-hardening-audit-2026-05-16.md).
A command counts as a current release gate only when that status file shows
exit code 0 for the exact command.

### GitHub Checks

On a normal push to `main`, the repository runs fast production checks:

- `CI`: Debian Trixie build, macOS build, formatting, lints, dependency checks,
  documentation, and public notice checks.
- `FFI Build iOS`: runs when iOS, shared FFI, or client files change.
- `FFI Build Android`: runs when Android, shared FFI, or client files change.
- `cargo-deny`: dependency policy.
- `dylint`: local lint policy.

The long Rust test suite is not run on every push. It is in
`Full Test Suite` and runs manually or on the weekly schedule.

The Android emulator job can show:

```text
FFI Build Android / emulator-test (push) Skipped
```

This is expected. It means the real Android emulator test was intentionally not
started for this push. The emulator test is slow, so it is kept for manual and
scheduled runs. The Android AAR and example APK still build on push.

To run the skipped emulator check from GitHub, open Actions, choose
`FFI Build Android`, and press `Run workflow`.

### How To Use The Code

For a Rust application inside this repository, start with the client crate:

```toml
[dependencies]
umbrella-client = { path = "crates/umbrella-client" }
```

For lower-level integration, use the crate that matches the area you need:

- identity and recovery: `crates/umbrella-identity`;
- group messaging: `crates/umbrella-mls`;
- post-quantum operations: `crates/umbrella-pq`;
- key transparency: `crates/umbrella-kt`;
- sealed sender: `crates/umbrella-sealed-sender`;
- backup: `crates/umbrella-backup`;
- calls: `crates/umbrella-calls`;
- server routing: `crates/umbrella-server-blind-postman`;
- mobile bindings: `crates/umbrella-ffi`, `crates/umbrella-ffi-swift`,
  `crates/umbrella-ffi-kotlin`.

For mobile applications, use the example folders first:

- Android: `examples/android-harness`;
- iOS: `examples/ios-harness`.

These examples are small harnesses. They are meant to prove the bindings build
and can be called from mobile project code.

### Documentation

Start here:

- [`docs/README.md`](docs/README.md): public documentation index.
- [`UmbrellaX_protocol_public_en.pdf`](UmbrellaX_protocol_public_en.pdf):
  current public protocol paper in English.
- [`UmbrellaX_protocol_public_ru.pdf`](UmbrellaX_protocol_public_ru.pdf):
  current public protocol paper in Russian.
- [`docs/security/release-notes-v1.1.0.md`](docs/security/release-notes-v1.1.0.md):
  public notes for the current release.
- [`docs/security/release-manifest-v1.1.0.txt`](docs/security/release-manifest-v1.1.0.txt):
  release verification notes.
- [`docs/audits/ROUND-1-TO-6-SUMMARY.md`](docs/audits/ROUND-1-TO-6-SUMMARY.md):
  consolidated PhD-B audit summary for rounds 1-6 (merged 2026-05-18).
- [`SECURITY.md`](SECURITY.md): vulnerability reporting process.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): contribution rules.

### Contact

Security reports: `security@umbrellax.io`

Commercial licensing: `licensing@umbrellax.io`

## Русский

Umbrella Protocol — криптографический набор для приватного мессенджера
UmbrellaX, который сейчас проходит усиление безопасности. В репозитории есть
реализованные крейты на Rust и проверочные стенды, но публичный боевой запуск
клиента через внешний интерфейс для мобильных привязок закрыт до полной связки
транспортов и боевых проверок.

Текущий статус усиления безопасности записан в
[`docs/security/current-status.md`](docs/security/current-status.md).
Внутренний боевой сборщик HTTP/2 связывает системную проверку сертификата с
закреплёнными SPKI-ключами. Публичный FFI-запуск остаётся закрыт, пока не
связаны настоящие платформенные проверяющие, мобильные мосты и серверная
интеграция. Развёртка облачного ключа и OPRF имеют серверные проверки с
контекстом, которые закрыто отказывают без настоящих платформенных
проверяющих. Локальный крейт платформенной проверки проверяет размер токена,
приложение или сайт, серверный вызов, ключ, подпись и счётчик там, где для
этого хватает данных. WebAuthn проверяется локально. Apple App Attest и Android
Play Integrity всё ещё закрыто отказывают, пока не подключены внешние корни
доверия, разбор платформенного токена и мобильная/серверная связка. Неполный
путь `ClientCore::new_with_http2` тоже закрыто отказывает, пока каждый сервис
не получит SPKI-ключи и настоящие транспорты postman, KT и call relay.
Подробная граница:
[`docs/security/production-readiness-boundaries.md`](docs/security/production-readiness-boundaries.md).
Боевые атакующие ворота ядра протокола записаны в
[`docs/security/protocol-core-attack-gates.md`](docs/security/protocol-core-attack-gates.md).
Локальное усиление KT против split-view реализовано в `umbrella-kt`: публичные
наблюдения эпох, память свидетеля, строгая история наблюдений и безопасный для
приватности формат наблюдения доступны для обнаружения раздвоения клиентами.
Живой обмен наблюдениями клиентов и публичное развёртывание свидетелей остаются
границами боевого выпуска.
Усиление цепочки зависимостей в 1.1.0 убирает неиспользуемый optional
libcrux-бэкенд HPKE из `hpke-rs` в корневом и fuzz lockfile, поэтому
`RUSTSEC-2026-0124` закрыт в проверяемом графе зависимостей, а не игнорируется.
Проход гигиены памяти от 2026-05-16 затирает временные значения вывода ключей,
возвращает раскрытый plaintext Sealed Sender через очищаемую обёртку и
использует системный генератор для задержки повторов.
Внешний крипто-аудит выпуска:
[`docs/audits/external-crypto-release-audit-status-2026-05-14.md`](docs/audits/external-crypto-release-audit-status-2026-05-14.md).
PhD-B аудит из шести раундов (раунды 1-6) на кодовой базе 1.1.0 влит в
`main` 2026-05-18 коммитом `84b4d576` (PR #6). Сводный отчёт:
[`docs/audits/ROUND-1-TO-6-SUMMARY.md`](docs/audits/ROUND-1-TO-6-SUMMARY.md);
заключение независимого ревьюера —
[`docs/audits/phd-b-final-independent-review-2026-05-19.md`](docs/audits/phd-b-final-independent-review-2026-05-19.md).
После аудита базовая линия — 2080 release-mode тестов (плюс 103 теста к
1977 базовой линии до раунда 6); одна MAJOR-граница покрытия (M-FINAL-1)
вынесена в v1.2.x.

Репозиторий открыт для прозрачности, воспроизводимых сборок, некоммерческих
проверок безопасности, криптографических испытаний и ответственных сообщений об
уязвимостях. Исходный код доступен для чтения, но это не свободная лицензия.
Коммерческое использование и встраивание в бизнес-продукт, сервис, набор для
разработки, мессенджер или инфраструктурную платформу требуют письменного
разрешения. Перед использованием прочитайте правила доступа:
[`PUBLIC_ACCESS.md`](PUBLIC_ACCESS.md) и [`LICENSE`](LICENSE).

Версия: **1.1.0, усиление безопасности**.

### Быстрый старт

Все команды ниже запускаются из корня репозитория.

```bash
git clone https://github.com/lich15/umbrella-protocol.git
cd umbrella-protocol
rustup show
cargo build --workspace --all-features --locked
cargo test -p umbrella-core --locked
```

Если сборка прошла, компьютер умеет собирать проект. Если быстрый тест прошёл,
настройка Rust в порядке.

### Карта репозитория

```text
.
├── crates/                      крейты Rust
├── docs/                        публичные документы протокола и безопасности
├── docs/security/               манифест выпуска и список зависимостей
├── UmbrellaX_protocol_public_en.pdf  публичный документ протокола на английском
├── UmbrellaX_protocol_public_ru.pdf  публичный документ протокола на русском
├── examples/android-harness/    проверочное приложение для Android
├── examples/ios-harness/        проверочный пакет для iOS
├── scripts/                     локальные проверочные сценарии
├── oss-fuzz/                    связка для фаззинга
├── supply-chain/                правила цепочки поставок
├── .github/workflows/           проверки на GitHub
├── Cargo.toml                   список крейтов и общие версии
├── Cargo.lock                   закреплённый граф зависимостей
└── rust-toolchain.toml          закреплённая версия Rust
```

Главные папки с кодом:

- `crates/umbrella-core`: общие базовые типы.
- `crates/umbrella-crypto-primitives`: низкоуровневые криптографические помощники.
- `crates/umbrella-pq`: постквантовые примитивы и смешанные обёртки.
- `crates/umbrella-identity`: личность, ключи и восстановление.
- `crates/umbrella-mls`: групповые сообщения.
- `crates/umbrella-kt`: прозрачность ключей.
- `crates/umbrella-sealed-sender`: скрытие отправителя.
- `crates/umbrella-backup`: резервная копия и восстановление.
- `crates/umbrella-calls`: защитные части для звонков.
- `crates/umbrella-client`: слой для клиентского приложения.
- `crates/umbrella-server-blind-postman`: серверный маршрутизатор.
- `crates/umbrella-ffi`: общий слой для мобильных связок.
- `crates/umbrella-ffi-swift`: связка для Swift.
- `crates/umbrella-ffi-kotlin`: связка для Kotlin и Android.
- `crates/umbrella-tests`: общие, атакующие и совместимые тесты.
- `crates/umbrella-fuzz`: цели для фаззинга.
- `crates/umbrella-formal-verification`: входы для формальных моделей.
- `crates/umbrella-vectors`: повторяемые проверочные наборы.

### Что поставить

Версия Rust закреплена в [`rust-toolchain.toml`](rust-toolchain.toml). Если
установлен `rustup`, он сам выберет нужную версию внутри этой папки.

На macOS:

```bash
xcode-select --install
rustup show
cargo --version
```

На Debian Trixie:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates clang cmake curl git make perl pkg-config build-essential
rustup show
cargo --version
```

Для сборки Android также нужны Android Studio или командные инструменты Android,
Android SDK, NDK `26.2.11394342`, Java 17 и Gradle.

Для сборки iOS нужен macOS с установленным Xcode.

### Сборка

Обычная полная сборка:

```bash
cargo build --workspace --all-features --locked
```

Сборка с выключенными необязательными возможностями:

```bash
cargo build --workspace --no-default-features --locked
```

Сборка одной части, если менялась только одна папка:

```bash
cargo build -p umbrella-identity --locked
cargo build -p umbrella-client --all-features --locked
```

### Тесты

Быстрая проверка, чтобы понять, что окружение живое:

```bash
cargo test -p umbrella-core --locked
```

Тест одной части:

```bash
cargo test -p umbrella-pq --locked
cargo test -p umbrella-mls --all-features --locked
```

Полный набор тестов Rust:

```bash
cargo test --workspace --all-features --locked
```

Полный набор стоит запускать перед выпуском, после изменений в криптографии,
после изменений форматов данных и после правок, которые затрагивают несколько
крейтов сразу.

### Проверка качества

Форматирование:

```bash
cargo fmt --all -- --check
```

Предупреждения и строгие проверки:

```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Сборка документации:

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
```

Проверка публичных пометок доступа:

```bash
bash scripts/audit-public-access-notices.sh
```

Проверка тестовых и неполных боевых путей:

```bash
bash scripts/audit-test-only-production-boundary.sh
```

Проверка правил задач GitHub:

```bash
bash scripts/audit-github-actions.sh
```

Проверка правил постквантовых зависимостей:

```bash
bash scripts/audit-pq-backend-policy.sh
```

Проверка правил зависимостей:

```bash
bash scripts/audit-dependency-policy.sh
```

### Частые случаи

Если менялась только документация:

```bash
bash scripts/audit-public-access-notices.sh
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
```

Если менялся один крейт:

```bash
cargo fmt --all -- --check
cargo test -p umbrella-identity --locked
cargo clippy -p umbrella-identity --all-targets --all-features --locked -- -D warnings
```

Замените `umbrella-identity` на имя той части, которую меняли.

Если менялась криптографическая логика:

```bash
cargo test --workspace --all-features --locked
bash scripts/audit-pq-backend-policy.sh
bash scripts/audit-dependency-policy.sh
```

Если менялись форматы передачи, сохранённые данные или проверочные наборы:

```bash
cargo test -p umbrella-vectors --locked
cargo test -p umbrella-tests --all-features --locked
cargo test --workspace --all-features --locked
```

Если менялся публичный мобильный слой:

```bash
bash scripts/audit-uniffi-generated-api.sh
```

После этого запустите сборку iOS или Android ниже, смотря какая связка менялась.

### Сборка iOS

Запускайте из корня репозитория на macOS с установленным Xcode.

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
./crates/umbrella-ffi-swift/build-xcframework.sh release
```

Проверочный пакет iOS:

```bash
cd examples/ios-harness
xcodebuild test \
  -scheme UmbrellaTestHarness \
  -destination "platform=iOS Simulator,name=iPhone 15,OS=latest"
```

Готовая сборка появится в папке `target/xcframework-build/`.

### Сборка Android

Запускайте из корня репозитория после установки Android SDK, NDK, Java 17 и
Gradle.

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
cargo install cargo-ndk --version 3.5.4 --locked
./crates/umbrella-ffi-kotlin/build-aar.sh release
gradle -p examples/android-harness assembleRelease --no-daemon
```

Готовое проверочное приложение будет здесь:

```text
examples/android-harness/app/build/outputs/apk/release/
```

### Фаззинг и формальные проверки

Цели фаззинга находятся в `crates/umbrella-fuzz/` и `oss-fuzz/`.

```bash
cargo test -p umbrella-fuzz --locked
bash scripts/run-fuzz-overnight.sh
bash scripts/run-local-release-hardening.sh short
bash scripts/run-local-release-hardening.sh long
bash scripts/audit-local-release-hardening.sh
```

Входы для формальных моделей находятся в
`crates/umbrella-formal-verification/`.

```bash
bash scripts/verify-formal-production-readiness.sh
bash scripts/verify-proverif-models.sh
bash scripts/verify-tamarin-models.sh
```

Для этих команд нужны соответствующие внешние инструменты на компьютере.

Текущий статус формальных проверок и местных строгих правил записан в
[`docs/audits/formal-lint-status-2026-05-13.md`](docs/audits/formal-lint-status-2026-05-13.md).
Статус локальных выпускных ворот записан в
[`docs/audits/local-release-hardening-status-2026-05-14.md`](docs/audits/local-release-hardening-status-2026-05-14.md).
Команда считается воротами выпуска только если в этом файле у неё указан код
0 для точного запуска.

### Проверки на GitHub

При обычной отправке изменений в `main` запускаются быстрые рабочие проверки:

- `CI`: сборка на Debian Trixie, сборка на macOS, форматирование, строгие
  проверки, проверка зависимостей, документация и публичные пометки доступа.
- `FFI Build iOS`: запускается при изменениях в iOS, общем мобильном слое или
  клиентской части.
- `FFI Build Android`: запускается при изменениях в Android, общем мобильном
  слое или клиентской части.
- `cargo-deny`: правила зависимостей.
- `dylint`: местные строгие правила.

Длинный набор тестов Rust не запускается при каждой отправке. Он вынесен в
`Full Test Suite` и запускается вручную или по недельному расписанию.

Проверка Android с эмулятором может показывать:

```text
FFI Build Android / emulator-test (push) Skipped
```

Так и должно быть. Это значит, что настоящий тест в эмуляторе Android
специально не запускался для обычной отправки изменений. Эмулятор медленный,
поэтому он оставлен для ручного и планового запуска. При этом AAR и проверочное
приложение Android всё равно собираются при отправке.

Чтобы запустить пропущенную проверку с эмулятором на GitHub, откройте Actions,
выберите `FFI Build Android` и нажмите `Run workflow`.

### Как использовать код

Для приложения на Rust внутри этого репозитория начинайте с клиентского крейта:

```toml
[dependencies]
umbrella-client = { path = "crates/umbrella-client" }
```

Для более низкого уровня выбирайте папку по задаче:

- личность и восстановление: `crates/umbrella-identity`;
- групповые сообщения: `crates/umbrella-mls`;
- постквантовые операции: `crates/umbrella-pq`;
- прозрачность ключей: `crates/umbrella-kt`;
- скрытие отправителя: `crates/umbrella-sealed-sender`;
- резервная копия: `crates/umbrella-backup`;
- звонки: `crates/umbrella-calls`;
- серверная маршрутизация: `crates/umbrella-server-blind-postman`;
- мобильные связки: `crates/umbrella-ffi`, `crates/umbrella-ffi-swift`,
  `crates/umbrella-ffi-kotlin`.

Для мобильных приложений сначала смотрите проверочные папки:

- Android: `examples/android-harness`;
- iOS: `examples/ios-harness`.

Эти примеры маленькие. Их задача — показать, что мобильные связки собираются и
вызываются из кода мобильного проекта.

### Документация

Начинайте отсюда:

- [`docs/README.md`](docs/README.md): указатель публичной документации.
- [`UmbrellaX_protocol_public_en.pdf`](UmbrellaX_protocol_public_en.pdf):
  актуальный публичный документ протокола на английском.
- [`UmbrellaX_protocol_public_ru.pdf`](UmbrellaX_protocol_public_ru.pdf):
  актуальный публичный документ протокола на русском.
- [`docs/security/release-notes-v1.1.0.md`](docs/security/release-notes-v1.1.0.md):
  публичные заметки текущего выпуска.
- [`docs/security/release-manifest-v1.1.0.txt`](docs/security/release-manifest-v1.1.0.txt):
  заметки для проверки выпуска.
- [`docs/audits/ROUND-1-TO-6-SUMMARY.md`](docs/audits/ROUND-1-TO-6-SUMMARY.md):
  сводный отчёт PhD-B аудита из шести раундов (влит 2026-05-18).
- [`SECURITY.md`](SECURITY.md): порядок сообщения об уязвимости.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): правила участия.

### Контакты

Сообщения о безопасности: `security@umbrellax.io`

Коммерческая лицензия: `licensing@umbrellax.io`
