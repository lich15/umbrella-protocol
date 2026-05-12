#!/usr/bin/env bash
#
# Собрать XCFramework из umbrella-ffi-swift для iOS (device + simulator).
# Запускается только на macOS с установленным Xcode.
#
# Build XCFramework from umbrella-ffi-swift for iOS (device + simulator).
# macOS + Xcode required.
#
# Usage:
#   ./build-xcframework.sh [release|debug]
#
# Output:
#   target/xcframework-build/UmbrellaFFI.xcframework
#   target/xcframework-build/Sources/UmbrellaFFI/<swift-files>
#
set -euo pipefail

PROFILE="${1:-release}"
if [[ "$PROFILE" != "release" && "$PROFILE" != "debug" ]]; then
    echo "usage: $0 [release|debug]" >&2
    exit 1
fi

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$CRATE_DIR/../.." && pwd)"
BUILD_DIR="$WORKSPACE_ROOT/target/xcframework-build"
SWIFT_OUT="$BUILD_DIR/Sources/UmbrellaFFI"
XCF_OUT="$BUILD_DIR/UmbrellaFFI.xcframework"

mkdir -p "$SWIFT_OUT"
rm -rf "$XCF_OUT"

# cargo profile directory ("release" or "debug").
PROFILE_DIR="$PROFILE"

echo "==> cargo build for iOS targets (profile=$PROFILE)"
for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
    if [[ "$PROFILE" == "release" ]]; then
        cargo build --release --target "$target" -p umbrella-ffi-swift --locked
    else
        cargo build --target "$target" -p umbrella-ffi-swift --locked
    fi
done

DEVICE_LIB="$WORKSPACE_ROOT/target/aarch64-apple-ios/$PROFILE_DIR/libumbrella_ffi_swift.a"
SIM_ARM64_LIB="$WORKSPACE_ROOT/target/aarch64-apple-ios-sim/$PROFILE_DIR/libumbrella_ffi_swift.a"
SIM_X86_64_LIB="$WORKSPACE_ROOT/target/x86_64-apple-ios/$PROFILE_DIR/libumbrella_ffi_swift.a"
SIM_UNIVERSAL_LIB="$BUILD_DIR/libumbrella_ffi_swift_iossimulator.a"

echo "==> lipo combine iossimulator universal (arm64 + x86_64)"
lipo -create \
    "$SIM_ARM64_LIB" \
    "$SIM_X86_64_LIB" \
    -output "$SIM_UNIVERSAL_LIB"

echo "==> uniffi-bindgen-swift generate"
# Запускается на host target (host mac) — не на iOS target; поэтому
# отдельный cargo run без --target.
#
# Runs on host target (the mac itself), not iOS; hence cargo run without
# --target.
cargo run --release -p umbrella-ffi-swift --bin uniffi-bindgen-swift --locked -- \
    generate \
    --library "$DEVICE_LIB" \
    --language swift \
    --out-dir "$SWIFT_OUT"

echo "==> xcodebuild -create-xcframework"
xcodebuild -create-xcframework \
    -library "$DEVICE_LIB" \
    -headers "$SWIFT_OUT" \
    -library "$SIM_UNIVERSAL_LIB" \
    -headers "$SWIFT_OUT" \
    -output "$XCF_OUT"

echo ""
echo "==> Done."
echo "   XCFramework: $XCF_OUT"
echo "   Swift bindings: $SWIFT_OUT"
