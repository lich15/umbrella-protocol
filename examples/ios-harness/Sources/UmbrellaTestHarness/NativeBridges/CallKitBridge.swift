import Foundation
import CallKit
import AVFoundation
import UmbrellaFFI

/// `CallKitBridge` — CallKit `CXProvider` + `CXCallController` для
/// outgoing/incoming call reports. `AVAudioSession` management для
/// media routing.
///
/// В Блоке 7.8 — skeleton (CXStartCallAction request, delegate fulfil).
/// Интеграция с `CallSessionHandle` (FFI) + `MediaSource`/`MediaSink` через
/// `AVAudioEngine` и `VideoToolbox` — в Блоке 7.10.
///
/// `CallKitBridge` — CallKit `CXProvider` + `CXCallController` for
/// outgoing/incoming call reports. `AVAudioSession` management for media
/// routing.
///
/// Block 7.8 ships a skeleton (CXStartCallAction request, delegate fulfil).
/// Integration with `CallSessionHandle` (FFI) + `MediaSource` / `MediaSink`
/// via `AVAudioEngine` and `VideoToolbox` arrives in Block 7.10.
final class CallKitBridge: NSObject {
    let provider: CXProvider
    let controller: CXCallController

    override init() {
        let cfg = CXProviderConfiguration()
        cfg.supportsVideo = true
        cfg.maximumCallsPerCallGroup = 1
        self.provider = CXProvider(configuration: cfg)
        self.controller = CXCallController()
        super.init()
        self.provider.setDelegate(self, queue: nil)
    }

    /// Start an outgoing call.
    func startOutgoingCall(uuid: UUID, remoteHandle: String) async throws {
        let startAction = CXStartCallAction(call: uuid, handle: CXHandle(type: .generic, value: remoteHandle))
        let transaction = CXTransaction(action: startAction)
        try await controller.request(transaction)
    }
}

extension CallKitBridge: CXProviderDelegate {
    func providerDidReset(_ provider: CXProvider) {}

    func provider(_ provider: CXProvider, perform action: CXStartCallAction) {
        action.fulfill()
    }

    func provider(_ provider: CXProvider, perform action: CXEndCallAction) {
        action.fulfill()
    }
}
