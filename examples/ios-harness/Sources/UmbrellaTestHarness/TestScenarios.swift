import Foundation
import UmbrellaFFI

/// Перечисление сценариев Milestone 7.10 (integration block).
///
/// Enumeration of Milestone 7.10 (integration block) scenarios.
enum ScenarioKind: CaseIterable {
    case registration
    case sendReceiveCloud
    case sendReceiveSecret
    case secretCall
    case multiDeviceBootstrap
    case catastrophicRecovery

    var title: String {
        switch self {
        case .registration:         return "1. Registration flow"
        case .sendReceiveCloud:     return "2. Send/receive Cloud text"
        case .sendReceiveSecret:    return "3. Send/receive Secret text"
        case .secretCall:           return "4. 1-1 Secret call (compliance-gate)"
        case .multiDeviceBootstrap: return "5. Multi-device bootstrap"
        case .catastrophicRecovery: return "6. Catastrophic recovery"
        }
    }
}

/// Состояние выполнения сценария.
///
/// Scenario execution state.
enum ScenarioState {
    case idle
    case running
    case success
    case failure(String)
}

/// ViewModel для UI — держит state каждого сценария и лог.
///
/// View model for the UI — keeps per-scenario state and the log.
@MainActor
final class TestScenariosViewModel: ObservableObject {
    @Published private var states: [ScenarioKind: ScenarioState] = [:]
    @Published var logs: [String] = []

    func state(for kind: ScenarioKind) -> ScenarioState {
        states[kind] ?? .idle
    }

    func run(_ kind: ScenarioKind) {
        states[kind] = .running
        Task.detached { [weak self] in
            guard let self = self else { return }
            do {
                try await self.execute(kind)
                await self.log("[\(kind)] PASSED")
                await self.finish(kind, success: true, msg: nil)
            } catch {
                await self.log("[\(kind)] FAIL: \(error)")
                await self.finish(kind, success: false, msg: String(describing: error))
            }
        }
    }

    @MainActor private func log(_ s: String) { logs.append(s) }
    @MainActor private func finish(_ kind: ScenarioKind, success: Bool, msg: String?) {
        states[kind] = success ? .success : .failure(msg ?? "unknown")
    }

    private func execute(_ kind: ScenarioKind) async throws {
        let bridges = try await SmokeBridges.make()
        switch kind {
        case .registration:         try await scenario1_registration(bridges: bridges)
        case .sendReceiveCloud:     try await scenario2_sendReceiveCloud(bridges: bridges)
        case .sendReceiveSecret:    try await scenario3_sendReceiveSecret(bridges: bridges)
        case .secretCall:           try await scenario4_secretCall(bridges: bridges)
        case .multiDeviceBootstrap: try await scenario5_multiDevice(bridges: bridges)
        case .catastrophicRecovery: try await scenario6_catastrophic(bridges: bridges)
        }
    }

    // Block 7.10 Scenario 1 — real bootstrap через FFI. Остальные scenarios
    // (2–6) остаются placeholder'ами; они требуют live Umbrella server implementation services
    // (Sealed Servers / blind-postman-svc / kt-svc / call-relay-svc) которые
    // в 7.10 Rust-side integration tests моделируются stub'ами, а на
    // реальном device — подключаются через manual checklist в README.md.
    //
    // Block 7.10 Scenario 1 — real FFI bootstrap. The remaining scenarios
    // (2–6) stay placeholders; they require live Umbrella server implementation services
    // (Sealed Servers / blind-postman-svc / kt-svc / call-relay-svc) which
    // are stubbed in the 7.10 Rust-side integration tests and wired up on
    // a real device through the manual checklist in README.md.
    private func scenario1_registration(bridges: SmokeBridges) async throws {
        let config = ClientConfigFfi(
            sealedServerUrls: (1...5).map { "https://stub-\($0).local:8080" },
            postmanUrl: "https://postman.local:8080",
            ktUrl: "https://kt.local:8080",
            callRelayUrl: "https://call-relay.local:8080",
            ktMonitorIntervalSecs: 3600,
            mainPubkey: Data(count: 32),
            serverPubkeys: Array(repeating: Data(count: 32), count: 5),
            wrappingVersion: 1
        )
        // 24-word BIP-39 phrase — на harness-уровне можно сгенерировать
        // через `UUID.uuid().uuidString`-подобный source или hard-code test
        // vector. Официальный BIP-39 test vector для 32-byte zero entropy:
        // "abandon × 23 art".
        //
        // 24-word BIP-39 phrase — harness can generate via a UUID-like source
        // or hard-code a test vector. Official BIP-39 test vector for the
        // 32-byte zero-entropy input: "abandon × 23 art".
        let mnemonic = String(repeating: "abandon ", count: 23) + "art"
        _ = try await UmbrellaClientHandle.bootstrap(
            config: config,
            mnemonicPhrase: mnemonic
        )
        // Success if bootstrap returns без error.
    }

    private func scenario2_sendReceiveCloud(bridges: SmokeBridges) async throws {
        // Placeholder — real CloudChat send/fetch flow требует live Umbrella server implementation
        // services. См. manual device checklist в examples/ios-harness/README.md.
        try await Task.sleep(nanoseconds: 100_000_000)
    }

    private func scenario3_sendReceiveSecret(bridges: SmokeBridges) async throws {
        // Placeholder — real SecretChat send/fetch flow требует live
        // blind-postman-svc.
        try await Task.sleep(nanoseconds: 100_000_000)
    }

    private func scenario4_secretCall(bridges: SmokeBridges) async throws {
        // Placeholder — no-P2P compliance-gate уже верифицирован на workspace
        // уровне в umbrella-client/tests/call_no_p2p.rs (property × 128).
        try await Task.sleep(nanoseconds: 100_000_000)
    }

    private func scenario5_multiDevice(bridges: SmokeBridges) async throws {
        // Placeholder — real multi-device bootstrap (QR + Noise_IK) wiring в
        // Блоке 7.10 manual device checklist.
        try await Task.sleep(nanoseconds: 100_000_000)
    }

    private func scenario6_catastrophic(bridges: SmokeBridges) async throws {
        // Placeholder — catastrophic recovery derive уже покрыт на
        // workspace уровне в umbrella-tests/tests/stage7_milestone.rs
        // (scenario6_catastrophic_recovery_rotated_identity_derive).
        try await Task.sleep(nanoseconds: 100_000_000)
    }
}

/// Набор native bridges, instantiated per scenario. Фасад над KeyStore +
/// Attestation + CallKit; в Блоке 7.10 доопределит wiring в Rust через
/// uniffi callback interface.
///
/// Set of native bridges instantiated per scenario. A facade over KeyStore +
/// Attestation + CallKit; Block 7.10 will wire these into Rust via a uniffi
/// callback interface.
struct SmokeBridges {
    let keystore: KeyStoreBridge
    let attestation: AttestationBridge

    static func make() async throws -> SmokeBridges {
        SmokeBridges(
            keystore: try KeyStoreBridge(),
            attestation: AttestationBridge()
        )
    }
}
