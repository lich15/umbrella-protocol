# UmbrellaX iOS Test Harness

[English](#english) | [Русский](#русский)

## English

This folder is a minimal Swift Package iOS harness used to validate the
`umbrella-ffi-swift` XCFramework and generated Swift bindings. It is not a
production messenger.

## Build

Run from the repository root:

```bash
./crates/umbrella-ffi-swift/build-xcframework.sh release
```

Expected outputs:

```text
target/xcframework-build/UmbrellaFFI.xcframework
target/xcframework-build/Sources/UmbrellaFFI/<generated swift>
```

`Package.swift` references the produced `UmbrellaFFI.xcframework` through a
local `binaryTarget(path:)`.

## Run Locally

```bash
open examples/ios-harness/Package.swift
```

In Xcode, choose a connected iPhone or a simulator, then run the
`UmbrellaTestHarness` scheme.

## Manual Checks

Use a real device when validating Secure Enclave or App Attest behavior. The
harness is intended to confirm that the XCFramework loads, generated Swift
bindings are callable, and the small smoke surface works on iOS.

No public device-certification matrix is claimed in this repository. Results
from private device labs should not be added here unless they are intended to be
published.

## CI

`.github/workflows/ffi-build-ios.yml` builds the XCFramework on macOS and runs
an iOS simulator test when iOS, shared FFI, or client files change.

---

## Русский

Эта папка содержит минимальный Swift Package iOS harness для проверки
`umbrella-ffi-swift` XCFramework и сгенерированных Swift bindings. Это не
production мессенджер.

## Сборка

Запускать из корня репозитория:

```bash
./crates/umbrella-ffi-swift/build-xcframework.sh release
```

Ожидаемые результаты:

```text
target/xcframework-build/UmbrellaFFI.xcframework
target/xcframework-build/Sources/UmbrellaFFI/<generated swift>
```

`Package.swift` ссылается на созданный `UmbrellaFFI.xcframework` через локальный
`binaryTarget(path:)`.

## Локальный запуск

```bash
open examples/ios-harness/Package.swift
```

В Xcode выберите подключённый iPhone или симулятор, затем запустите схему
`UmbrellaTestHarness`.

## Ручные проверки

Для Secure Enclave или App Attest лучше использовать реальное устройство.
Harness нужен, чтобы проверить, что XCFramework загружается, сгенерированные
Swift bindings вызываются, и небольшой smoke-surface работает на iOS.

Публичная матрица сертификации устройств в этом репозитории не заявляется.
Результаты приватных device lab проверок не нужно добавлять сюда, если они не
предназначены для публикации.

## CI

`.github/workflows/ffi-build-ios.yml` собирает XCFramework на macOS и запускает
iOS simulator test, когда меняются iOS, общий FFI или client files.
