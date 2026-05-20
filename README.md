# Umbrella Protocol

[English](#english) | [Русский](#русский)

## English

Umbrella Protocol is a source-available cryptographic protocol stack under
security hardening for the private messenger UmbrellaX. The
repository contains implemented Rust cryptographic crates and test harnesses;
F-CLIENT-FACADE-1 closure landed on `main` across 12 sub-sessions (1 through
10f), wiring WebSocket + QUIC transports, MLS group create / sealed-sender /
KT self-monitor / identity rotation / call relay / device transfer through
the gateway-svc integration contract. The public FFI bootstrap remains gated
until external platform attestation, mobile bridges, and server deployment
are wired end to end.

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
PhD-B seven-round audit chain (rounds 1-6 merged 2026-05-18 in commit
`84b4d576` PR #6; round 7 discovery merged subsequently) on the 1.1.0
codebase. The consolidated summary lives at
[`docs/audits/ROUND-1-TO-7-SUMMARY.md`](docs/audits/ROUND-1-TO-7-SUMMARY.md);
the independent reviewer verdict on rounds 1-6 is in
[`docs/audits/phd-b-final-independent-review-2026-05-19.md`](docs/audits/phd-b-final-independent-review-2026-05-19.md);
the Pass 5 remediation closure consolidating 18 follow-up findings is in
[`docs/audits/phd-b-pass5-remediation-2026-05-19.md`](docs/audits/phd-b-pass5-remediation-2026-05-19.md).
Post-round-7 workspace baseline is 2179+ release-mode tests; the M-FINAL-1
scope-of-closure caveat was closed via Pass 5 commit `e7b034ff`
(F-CLIENT-HW-1) and `core.identity` is now `Option<Arc<IdentityKey>>` with
no ephemeral seed on the hw bootstrap path.

The post-1.1.0 release branch additionally carries Max Ratchet v3 — a
default-on aggressive DH ratchet + 5-minute timer rekey + post-quantum
extension on every 3rd commit + SPQR HMAC deniable authentication layer
over the MLS group. Implementation acceptance is 10/10 (`docs/audits/max-ratchet-deniability-spec-2026-05-20.md`)
with Apple M2 benchmark numbers, real X-Wing combine integration, dudect
1M-sample constant-time evidence for `verify_hmac`, and Tamarin formal
models for PCS + deniability (`docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md`).
External cryptographic review (Cure53 / NCC / Trail of Bits) is the
remaining pre-ship step.

This repository is public for transparency, reproducible builds, non-commercial
security testing, cryptographic testing, and responsible vulnerability reports.
Umbrella Protocol is source-available, not open-source. Commercial use and
embedding in a business product, service, SDK, messenger, or infrastructure
platform require written permission. Read the access rules before using the
code: [`PUBLIC_ACCESS.md`](PUBLIC_ACCESS.md) and [`LICENSE`](LICENSE).

Version: **1.1.0** (last release tag) plus a post-1.1.0 hardening series on
`main` carrying F-CLIENT-FACADE-1 milestone closure, Pass 5 remediation,
Round 7 discovery merge, and Max Ratchet v3. The next release ceremony is
an administrative step recorded separately.

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
- `crates/umbrella-crypto-primitives`: low-level cryptographic helpers + `MlockedSecret<T>`.
- `crates/umbrella-pq`: post-quantum primitives, X-Wing hybrid wrappers, hedged encaps.
- `crates/umbrella-identity`: identity keys and recovery logic.
- `crates/umbrella-threshold-identity`: FROST-Ed25519 DKG, PIN model (Argon2id), duress,
  time-lock recovery, attempt counter (round-6 distributed-identity track).
- `crates/umbrella-mls`: group messaging profile + `max_ratchet/` (aggressive DH +
  timer rekey + PQ extend + SPQR HMAC).
- `crates/umbrella-kt`: key transparency.
- `crates/umbrella-oprf`: RFC 9497 OPRF with 3-of-5 Shamir threshold.
- `crates/umbrella-discovery`: private contact discovery — OPRF-PSI + @username
  lookup with KT bind (round-7 track).
- `crates/umbrella-platform-verifier`: local fail-closed platform checks.
- `crates/umbrella-sealed-sender`: sender hiding + self-destruct + anti-forensic.
- `crates/umbrella-backup`: backup and recovery flows, hedged-encaps callers.
- `crates/umbrella-calls`: call protection pieces.
- `crates/umbrella-padding`: bucketed padding (7 buckets, RFC 9605 anti-correlation).
- `crates/umbrella-client`: client-facing protocol API + facade closure sessions 1-10f.
- `crates/umbrella-server-blind-postman`: server router component.
- `crates/umbrella-ffi`: shared mobile foreign-function layer.
- `crates/umbrella-ffi-swift`: Swift package bindings.
- `crates/umbrella-ffi-kotlin`: Kotlin and Android bindings.
- `crates/umbrella-tests`: integration, adversarial, and compatibility tests + dudect.
- `crates/umbrella-fuzz`: fuzzing targets including Max Ratchet v3 envelope codec.
- `crates/umbrella-formal-verification`: 14 Tamarin + 4 ProVerif models.
- `crates/umbrella-vectors`: deterministic test vectors.
- `crates/umbrella-lints`: local dylint rules.

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
- [`docs/audits/ROUND-1-TO-7-SUMMARY.md`](docs/audits/ROUND-1-TO-7-SUMMARY.md):
  consolidated PhD-B audit summary for rounds 1-7 (rounds 1-6 merged
  2026-05-18 PR #6; round 7 discovery subsequently).
- [`docs/audits/phd-b-pass5-remediation-2026-05-19.md`](docs/audits/phd-b-pass5-remediation-2026-05-19.md):
  Pass 5 remediation closure (20 commits resolving 18 findings).
- [`docs/audits/max-ratchet-deniability-spec-2026-05-20.md`](docs/audits/max-ratchet-deniability-spec-2026-05-20.md)
  and [`docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md`](docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md):
  Max Ratchet v3 specification + measured evidence matrix.
- [`SECURITY.md`](SECURITY.md): vulnerability reporting process.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): contribution rules.

### Contact

Security reports: `security@umbrellax.io`

Commercial licensing: `licensing@umbrellax.io`

## Русский

Umbrella Protocol — криптографический набор для приватного мессенджера
UmbrellaX, который сейчас проходит усиление безопасности. В репозитории есть
реализованные крейты на Rust и проверочные стенды; F-CLIENT-FACADE-1 закрыт
по 12 под-сессиям (1 — 10f) с боевыми WebSocket и QUIC транспортами,
созданием MLS-групп, sealed-sender, самопроверкой KT, ротацией identity,
звонками и передачей устройства через контракт интеграции gateway-svc.
Публичный FFI-запуск остаётся закрыт, пока не подключены платформенные
проверяющие, мобильные мосты и серверная интеграция.

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
PhD-B аудит из семи раундов (раунды 1-6 влиты в `main` 2026-05-18 коммитом
`84b4d576` PR #6; раунд 7 «discovery» влит после) на кодовой базе 1.1.0.
Сводный отчёт:
[`docs/audits/ROUND-1-TO-7-SUMMARY.md`](docs/audits/ROUND-1-TO-7-SUMMARY.md);
заключение независимого ревьюера по раундам 1-6 —
[`docs/audits/phd-b-final-independent-review-2026-05-19.md`](docs/audits/phd-b-final-independent-review-2026-05-19.md);
закрытие 18 находок Pass 5 — в
[`docs/audits/phd-b-pass5-remediation-2026-05-19.md`](docs/audits/phd-b-pass5-remediation-2026-05-19.md).
Базовая линия после раунда 7 — 2179+ release-mode тестов. MAJOR-граница
M-FINAL-1 закрыта в Pass 5 коммитом `e7b034ff` (F-CLIENT-HW-1):
`core.identity` теперь `Option<Arc<IdentityKey>>`, эфемерный seed на
hw bootstrap пути устранён.

Пост-1.1.0 ветка дополнительно несёт Max Ratchet v3 — default-on
агрессивный DH-храповик + 5-минутный таймер rekey + post-quantum
расширение каждые 3 commit'а + SPQR HMAC отрицаемая аутентификация
поверх MLS-группы. Реализация 10/10 acceptance закрыта 2026-05-20
([`docs/audits/max-ratchet-deniability-spec-2026-05-20.md`](docs/audits/max-ratchet-deniability-spec-2026-05-20.md))
с замерами на Apple M2, реальной X-Wing combine интеграцией,
постоянным временем `verify_hmac` (dudect 1M samples) и Tamarin
формальными моделями PCS + deniability
([`docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md`](docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md)).
Внешний крипто-аудит (Cure53 / NCC / Trail of Bits) остаётся
единственным pre-ship шагом.

Репозиторий открыт для прозрачности, воспроизводимых сборок, некоммерческих
проверок безопасности, криптографических испытаний и ответственных сообщений об
уязвимостях. Исходный код доступен для чтения, но это не свободная лицензия.
Коммерческое использование и встраивание в бизнес-продукт, сервис, набор для
разработки, мессенджер или инфраструктурную платформу требуют письменного
разрешения. Перед использованием прочитайте правила доступа:
[`PUBLIC_ACCESS.md`](PUBLIC_ACCESS.md) и [`LICENSE`](LICENSE).

Версия: **1.1.0** (последний тег) плюс серия post-1.1.0 hardening коммитов
на `main`: закрытие F-CLIENT-FACADE-1 milestone, remediation Pass 5,
влив Round 7 discovery и Max Ratchet v3. Очередной release-ceremony
вынесен в отдельный административный шаг.

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
- `crates/umbrella-crypto-primitives`: низкоуровневые криптографические помощники + `MlockedSecret<T>`.
- `crates/umbrella-pq`: постквантовые примитивы, X-Wing смешанные обёртки, hedged-encaps.
- `crates/umbrella-identity`: личность, ключи и восстановление.
- `crates/umbrella-threshold-identity`: FROST-Ed25519 DKG, PIN-модель (Argon2id),
  duress-PIN, time-lock восстановление, attempt counter (раунд 6 distributed identity).
- `crates/umbrella-mls`: групповые сообщения + `max_ratchet/` (агрессивный DH +
  таймер rekey + PQ-расширение + SPQR HMAC).
- `crates/umbrella-kt`: прозрачность ключей.
- `crates/umbrella-oprf`: RFC 9497 OPRF с порогом Шамира 3 из 5.
- `crates/umbrella-discovery`: приватное обнаружение контактов — OPRF-PSI и
  поиск по `@handle` с KT-bind (раунд 7).
- `crates/umbrella-sealed-sender`: скрытие отправителя + self-destruct + анти-форенсик.
- `crates/umbrella-backup`: резервная копия и восстановление, hedged-encaps вызовы.
- `crates/umbrella-calls`: защитные части для звонков.
- `crates/umbrella-padding`: bucketed padding (7 buckets, RFC 9605).
- `crates/umbrella-client`: слой для клиентского приложения + сессии 1-10f закрытия F-CLIENT-FACADE-1.
- `crates/umbrella-server-blind-postman`: серверный маршрутизатор.
- `crates/umbrella-ffi`: общий слой для мобильных связок.
- `crates/umbrella-ffi-swift`: связка для Swift.
- `crates/umbrella-ffi-kotlin`: связка для Kotlin и Android.
- `crates/umbrella-tests`: общие, атакующие, совместимые тесты + dudect.
- `crates/umbrella-fuzz`: цели для фаззинга, включая v3 envelope codec.
- `crates/umbrella-formal-verification`: 14 Tamarin + 4 ProVerif моделей.
- `crates/umbrella-vectors`: повторяемые проверочные наборы.
- `crates/umbrella-lints`: местные dylint правила.

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
- [`docs/audits/ROUND-1-TO-7-SUMMARY.md`](docs/audits/ROUND-1-TO-7-SUMMARY.md):
  сводный отчёт PhD-B аудита из семи раундов (раунды 1-6 влиты 2026-05-18
  PR #6; раунд 7 «discovery» влит после).
- [`docs/audits/phd-b-pass5-remediation-2026-05-19.md`](docs/audits/phd-b-pass5-remediation-2026-05-19.md):
  закрытие 18 находок Pass 5 (20 коммитов).
- [`docs/audits/max-ratchet-deniability-spec-2026-05-20.md`](docs/audits/max-ratchet-deniability-spec-2026-05-20.md)
  и [`docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md`](docs/audits/max-ratchet-v3-security-evidence-2026-05-20.md):
  спецификация Max Ratchet v3 + матрица измеренных доказательств.
- [`SECURITY.md`](SECURITY.md): порядок сообщения об уязвимости.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): правила участия.

### Контакты

Сообщения о безопасности: `security@umbrellax.io`

Коммерческая лицензия: `licensing@umbrellax.io`
