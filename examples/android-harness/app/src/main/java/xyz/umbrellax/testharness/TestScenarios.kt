package xyz.umbrellax.testharness

import android.content.Context
import uniffi.umbrella_ffi.ClientConfigFfi
import uniffi.umbrella_ffi.UmbrellaClientHandle
import xyz.umbrellax.testharness.nativebridges.AttestationBridge
import xyz.umbrellax.testharness.nativebridges.KeyStoreBridge

/**
 * Управляет запуском 6 смоук-сценариев Milestone 7.10. Каждый сценарий в
 * Блоке 7.9 — placeholder (no-op); реальные E2E реализации (bootstrap +
 * crypto stack + TURN allocation + webrtc-rs handshake) в Блоке 7.10.
 *
 * Runs the six Milestone 7.10 smoke scenarios. Each scenario in Block 7.9
 * is a placeholder (no-op); real end-to-end implementations (bootstrap +
 * crypto stack + TURN allocation + webrtc-rs handshake) land in Block 7.10.
 */
class TestScenarios(private val ctx: Context) {

    /** Execute scenario #[n], returns short `PASS`/`FAIL: reason`. */
    suspend fun run(n: Int): String {
        val bridges = SmokeBridges(KeyStoreBridge(ctx), AttestationBridge(ctx))
        return try {
            when (n) {
                1 -> scenario1Registration(bridges)
                2 -> scenario2CloudMessaging(bridges)
                3 -> scenario3SecretMessaging(bridges)
                4 -> scenario4SecretCall(bridges)
                5 -> scenario5MultiDevice(bridges)
                6 -> scenario6Catastrophic(bridges)
                else -> error("unknown scenario $n")
            }
            "PASS"
        } catch (e: Throwable) {
            "FAIL: ${e.message}"
        }
    }

    // Блок 7.10 Scenario 1 — real bootstrap через FFI. Остальные
    // scenarios 2–6 остаются placeholder'ами: требуют live Umbrella server implementation
    // services (Sealed Servers / blind-postman-svc / kt-svc /
    // call-relay-svc) которые в 7.10 Rust-side integration tests
    // моделируются stub'ами, а на реальном device — подключаются через
    // manual checklist в README.md.
    //
    // Block 7.10 Scenario 1 — real FFI bootstrap. Remaining scenarios
    // 2–6 stay placeholders; they require live Umbrella server implementation services
    // (Sealed Servers / blind-postman-svc / kt-svc / call-relay-svc)
    // stubbed in the 7.10 Rust-side integration tests and wired on real
    // devices through the manual checklist in README.md.
    private suspend fun scenario1Registration(b: SmokeBridges) {
        val config = ClientConfigFfi(
            sealedServerUrls = (1..5).map { "https://stub-$it.local:8080" },
            postmanUrl = "https://postman.local:8080",
            ktUrl = "https://kt.local:8080",
            callRelayUrl = "https://call-relay.local:8080",
            ktMonitorIntervalSecs = 3600uL,
            mainPubkey = ByteArray(32),
            serverPubkeys = List(5) { ByteArray(32) },
            wrappingVersion = 1u
        )
        // Официальный BIP-39 test vector для 32-byte zero entropy —
        // "abandon × 23 art". Real harness может генерировать через
        // cryptographic RNG.
        //
        // Official BIP-39 test vector for 32-byte zero entropy —
        // "abandon × 23 art". A real harness can generate one via a CSPRNG.
        val mnemonic = ("abandon ".repeat(23)) + "art"
        UmbrellaClientHandle.bootstrap(config, mnemonic)
    }

    private suspend fun scenario2CloudMessaging(b: SmokeBridges) { /* manual 7.10 */ }
    private suspend fun scenario3SecretMessaging(b: SmokeBridges) { /* manual 7.10 */ }
    private suspend fun scenario4SecretCall(b: SmokeBridges) { /* покрыт в call_no_p2p.rs */ }
    private suspend fun scenario5MultiDevice(b: SmokeBridges) { /* manual 7.10 */ }
    private suspend fun scenario6Catastrophic(b: SmokeBridges) { /* покрыт в stage7_milestone.rs */ }
}

/**
 * Набор native bridges, instantiated per scenario. Facade над KeyStore +
 * Attestation; в Блоке 7.10 будут wired в Rust через uniffi callback
 * interface.
 *
 * Native bridge bag instantiated per scenario. Facade over KeyStore +
 * Attestation; Block 7.10 wires them into Rust via uniffi callback
 * interfaces.
 */
data class SmokeBridges(
    val keystore: KeyStoreBridge,
    val attestation: AttestationBridge
)
