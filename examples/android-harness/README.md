# UmbrellaX Android Test Harness

[English](#english) | [Русский](#русский)

## English

This folder is a minimal Gradle/Kotlin Android project used to validate the
`umbrella-ffi-kotlin` AAR and generated bindings. It is not a production
messenger.

## Build

Run from the repository root:

```bash
./crates/umbrella-ffi-kotlin/build-aar.sh release
gradle -p examples/android-harness assembleRelease --no-daemon
```

Expected outputs:

```text
target/jniLibs/<abi>/libumbrella_ffi_kotlin.so
target/aar-build/kotlin-bindings/uniffi/*.kt
examples/android-harness/app/build/outputs/apk/release/
```

## Requirements

- Android SDK with platform 35 and build-tools 35.0.0.
- Android NDK `26.2.11394342` exposed through `ANDROID_NDK_HOME`.
- JDK 17 or newer.
- `cargo-ndk` installed with `cargo install cargo-ndk --version 3.5.4 --locked`.

## Run Locally

```bash
cd examples/android-harness
./gradlew installRelease
adb shell am start -n xyz.umbrellax.testharness/.MainActivity
```

You can also open `examples/android-harness` in Android Studio and run the app
from there.

## Manual Checks

Use a real device when possible. The harness is intended to confirm that the
AAR loads, generated Kotlin bindings are callable, and the small smoke surface
works on Android.

No public device-certification matrix is claimed in this repository. Results
from private device labs should not be added here unless they are intended to be
published.

## CI

`.github/workflows/ffi-build-android.yml` builds the AAR and the example APK on
pushes that touch Android, shared FFI, or client files. The emulator job is
limited to manual and scheduled runs because it is slow.

---

## Русский

Эта папка содержит минимальный Gradle/Kotlin Android-проект для проверки
`umbrella-ffi-kotlin` AAR и сгенерированных binding-ов. Это не боевой
мессенджер.

## Сборка

Запускать из корня репозитория:

```bash
./crates/umbrella-ffi-kotlin/build-aar.sh release
gradle -p examples/android-harness assembleRelease --no-daemon
```

Ожидаемые результаты:

```text
target/jniLibs/<abi>/libumbrella_ffi_kotlin.so
target/aar-build/kotlin-bindings/uniffi/*.kt
examples/android-harness/app/build/outputs/apk/release/
```

## Требования

- Android SDK с platform 35 и build-tools 35.0.0.
- Android NDK `26.2.11394342` через `ANDROID_NDK_HOME`.
- JDK 17 или новее.
- `cargo-ndk`, установленный командой `cargo install cargo-ndk --version 3.5.4 --locked`.

## Локальный запуск

```bash
cd examples/android-harness
./gradlew installRelease
adb shell am start -n xyz.umbrellax.testharness/.MainActivity
```

Также можно открыть `examples/android-harness` в Android Studio и запустить
приложение оттуда.

## Ручные проверки

По возможности используйте реальное устройство. Проверочный проект нужен, чтобы
убедиться, что AAR загружается, сгенерированные Kotlin-привязки вызываются, и
небольшой проверочный набор работает на Android.

Публичная матрица сертификации устройств в этом репозитории не заявляется.
Результаты приватных device lab проверок не нужно добавлять сюда, если они не
предназначены для публикации.

## CI

`.github/workflows/ffi-build-android.yml` собирает AAR и пример APK при push,
который затрагивает Android, общий FFI или client files. Emulator job ограничен
ручными и плановыми запусками, потому что он медленный.
