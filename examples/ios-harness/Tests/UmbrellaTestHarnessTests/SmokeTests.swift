import XCTest
@testable import UmbrellaTestHarness
import UmbrellaFFI

/// Swift Smoke Tests — прогоняются через `xcodebuild test` на iOS Simulator
/// (locally через `build-xcframework.sh` + Xcode, или в CI на macOS runner
/// через `.github/workflows/ffi-build-ios.yml`).
///
/// Покрывают: FFI Record roundtrip, KeyStoreBridge fresh state, Attestation
/// platform tag. Не требуют реального TURN/Sealed Servers — чистые local
/// checks.
///
/// Swift Smoke Tests — run via `xcodebuild test` on iOS Simulator (locally
/// via `build-xcframework.sh` + Xcode, or in CI on the macOS runner via
/// `.github/workflows/ffi-build-ios.yml`).
///
/// Covers FFI Record roundtrip, KeyStoreBridge fresh state, Attestation
/// platform tag. No real TURN / Sealed Servers required — purely local checks.
final class SmokeTests: XCTestCase {
    func testChatIdFfiBytesFieldLengthMatches() {
        let cid = ChatIdFfi(bytes: Data(count: 32))
        XCTAssertEqual(cid.bytes.count, 32)
    }

    func testPeerIdFfiBytesFieldLengthMatches() {
        let pid = PeerIdFfi(bytes: Data(count: 32))
        XCTAssertEqual(pid.bytes.count, 32)
    }

    func testCallPolicyFfiFieldsPassthroughFromInit() {
        let policy = CallPolicyFfi(
            defaultRouting: 1,
            sensitivePeers: [],
            allowP2pGlobal: false
        )
        XCTAssertEqual(policy.defaultRouting, 1)
        XCTAssertFalse(policy.allowP2pGlobal)
        XCTAssertTrue(policy.sensitivePeers.isEmpty)
    }

    func testKeyStoreBridgeHasIdentityFalseOnFreshDevice() async throws {
        let bridge = try KeyStoreBridge()
        try await bridge.purgeAll()
        let has = try await bridge.hasIdentity()
        XCTAssertFalse(has)
    }

    func testAttestationBridgePlatformTag() {
        let bridge = AttestationBridge()
        XCTAssertEqual(bridge.platformTag(), "iOs")
    }
}
