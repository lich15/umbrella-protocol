#!/usr/bin/env bash
#
# Собрать native libs + Kotlin bindings для AAR из umbrella-ffi-kotlin.
# Gradle assembleRelease (в examples/android-harness) собирает финальный AAR.
#
# Usage:
#   ./build-aar.sh [release|debug]
#
# Требования:
#   - Android NDK r26d+ в $ANDROID_NDK_HOME
#   - cargo-ndk установлен: `cargo install cargo-ndk --locked`
#
# Build native libs + Kotlin bindings for the AAR from umbrella-ffi-kotlin.
# The final AAR is assembled by Gradle `assembleRelease` in
# examples/android-harness.
#
# Requirements:
#   - Android NDK r26d+ at $ANDROID_NDK_HOME
#   - cargo-ndk installed: `cargo install cargo-ndk --locked`
#
set -euo pipefail

PROFILE="${1:-release}"
if [[ "$PROFILE" != "release" && "$PROFILE" != "debug" ]]; then
    echo "usage: $0 [release|debug]" >&2
    exit 1
fi

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$CRATE_DIR/../.." && pwd)"
BUILD_DIR="$WORKSPACE_ROOT/target/aar-build"
KOTLIN_OUT="$BUILD_DIR/kotlin-bindings"
FALLBACK_KOTLIN_OUT="$CRATE_DIR/generated"
HARNESS_KOTLIN_OUT="$WORKSPACE_ROOT/examples/android-harness/app/build/generated/source/uniffi"
JNILIBS_OUT="$WORKSPACE_ROOT/target/jniLibs"

PROFILE_DIR="$PROFILE"
case "$(uname -s)" in
    Darwin) HOST_LIB_EXT="dylib" ;;
    Linux) HOST_LIB_EXT="so" ;;
    *)
        echo "unsupported host OS for Kotlin binding generation: $(uname -s)" >&2
        exit 1
        ;;
esac
HOST_LIB="$WORKSPACE_ROOT/target/$PROFILE_DIR/libumbrella_ffi_kotlin.$HOST_LIB_EXT"

rm -rf "$KOTLIN_OUT" "$HARNESS_KOTLIN_OUT"

mkdir -p "$KOTLIN_OUT" \
         "$HARNESS_KOTLIN_OUT" \
         "$JNILIBS_OUT/arm64-v8a" \
         "$JNILIBS_OUT/armeabi-v7a" \
         "$JNILIBS_OUT/x86_64" \
         "$JNILIBS_OUT/x86"

echo "==> cargo-ndk build for Android targets (profile=$PROFILE)"
declare -A TARGET_TO_ABI=(
    [aarch64-linux-android]=arm64-v8a
    [armv7-linux-androideabi]=armeabi-v7a
    [x86_64-linux-android]=x86_64
    [i686-linux-android]=x86
)

for target in "${!TARGET_TO_ABI[@]}"; do
    echo "   -> $target ($PROFILE)"
    if [[ "$PROFILE" == "release" ]]; then
        cargo ndk --target "$target" --platform 23 build --release -p umbrella-ffi-kotlin --locked
    else
        cargo ndk --target "$target" --platform 23 build -p umbrella-ffi-kotlin --locked
    fi

    abi="${TARGET_TO_ABI[$target]}"
    cp "$WORKSPACE_ROOT/target/$target/$PROFILE_DIR/libumbrella_ffi_kotlin.so" \
       "$JNILIBS_OUT/$abi/libumbrella_ffi_kotlin.so"
done

echo "==> host cdylib build for UniFFI metadata (profile=$PROFILE)"
if [[ "$PROFILE" == "release" ]]; then
    cargo build --release -p umbrella-ffi-kotlin --locked
else
    cargo build -p umbrella-ffi-kotlin --locked
fi

if [[ ! -f "$HOST_LIB" ]]; then
    echo "host library not found: $HOST_LIB" >&2
    exit 1
fi

echo "==> uniffi-bindgen-kotlin generate"
# Запуск на host (не на Android) — отдельный cargo run без --target.
#
# Runs on host (not Android); hence cargo run without --target.
if [[ "$PROFILE" == "release" ]]; then
    cargo run --release -p umbrella-ffi-kotlin --bin uniffi-bindgen-kotlin --locked -- \
        generate \
        --library \
        --crate umbrella_ffi \
        --language kotlin \
        --no-format \
        --out-dir "$KOTLIN_OUT" \
        "$HOST_LIB"
else
    cargo run -p umbrella-ffi-kotlin --bin uniffi-bindgen-kotlin --locked -- \
        generate \
        --library \
        --crate umbrella_ffi \
        --language kotlin \
        --no-format \
        --out-dir "$KOTLIN_OUT" \
        "$HOST_LIB"
fi

if ! find "$KOTLIN_OUT" -type f -name '*.kt' -print -quit | grep -q .; then
    echo "generated Kotlin bindings not found under $KOTLIN_OUT; using checked-in fallback" >&2
    find "$KOTLIN_OUT" -maxdepth 5 -print >&2 || true
    if ! find "$FALLBACK_KOTLIN_OUT" -type f -name '*.kt' -print -quit | grep -q .; then
        echo "fallback Kotlin bindings not found under $FALLBACK_KOTLIN_OUT" >&2
        exit 1
    fi
    rm -rf "$KOTLIN_OUT"
    mkdir -p "$KOTLIN_OUT"
    cp -R "$FALLBACK_KOTLIN_OUT"/. "$KOTLIN_OUT"/
fi

cp -R "$KOTLIN_OUT"/. "$HARNESS_KOTLIN_OUT"/

echo ""
echo "==> Done."
echo "   Kotlin bindings: $KOTLIN_OUT"
echo "   Android harness generated source: $HARNESS_KOTLIN_OUT"
echo "   Native libraries by ABI: $JNILIBS_OUT/{arm64-v8a,armeabi-v7a,x86_64,x86}/libumbrella_ffi_kotlin.so"
echo ""
echo "Next: gradle -p examples/android-harness assembleRelease --no-daemon"
