// swift-tools-version: 5.9
//
// UmbrellaX iOS test harness Swift Package. Потребляет XCFramework,
// собранный через `crates/umbrella-ffi-swift/build-xcframework.sh`.
// Не production-мессенджер — manual smoke-test harness для Этапа 7.
//
// UmbrellaX iOS test harness Swift Package. Consumes the XCFramework
// built by `crates/umbrella-ffi-swift/build-xcframework.sh`. Not a
// production messenger — a manual smoke-test harness for Stage 7.

import PackageDescription

let package = Package(
    name: "UmbrellaTestHarness",
    platforms: [.iOS(.v14)],
    products: [
        .library(name: "UmbrellaTestHarness", targets: ["UmbrellaTestHarness"])
    ],
    dependencies: [],
    targets: [
        .binaryTarget(
            name: "UmbrellaFFI",
            path: "../../target/xcframework-build/UmbrellaFFI.xcframework"
        ),
        .target(
            name: "UmbrellaTestHarness",
            dependencies: ["UmbrellaFFI"]
        ),
        .testTarget(
            name: "UmbrellaTestHarnessTests",
            dependencies: ["UmbrellaTestHarness", "UmbrellaFFI"]
        )
    ]
)
