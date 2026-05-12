package xyz.umbrellax.testharness

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import xyz.umbrellax.testharness.nativebridges.AttestationBridge
import xyz.umbrellax.testharness.nativebridges.KeyStoreBridge

/**
 * Android-instrumented smoke tests — прогоняются через
 * `./gradlew connectedCheck` на API 31+ emulator (CI runner) или на
 * реальном device через Android Studio. Покрывают: Attestation platform
 * tag; KeyStore fresh state.
 *
 * FFI-типы (uniffi-generated `uniffi.umbrella_ffi.*`) смоук-тесты
 * появятся в Блоке 7.10 после добавления real uniffi callback interfaces
 * для KeyStore / Attestation.
 *
 * Android-instrumented smoke tests — run via `./gradlew connectedCheck` on
 * an API 31+ emulator (CI runner) or a real device through Android Studio.
 * Covers Attestation platform tag; KeyStore fresh state.
 *
 * FFI-type smoke tests (uniffi-generated `uniffi.umbrella_ffi.*`) arrive
 * in Block 7.10 once real uniffi callback interfaces for KeyStore /
 * Attestation land.
 */
@RunWith(AndroidJUnit4::class)
class SmokeTest {
    private val ctx: Context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun attestationBridgePlatformTagIsAndroid() {
        val bridge = AttestationBridge(ctx)
        assertEquals("Android", bridge.platformTag())
    }

    @Test
    fun keystoreBridgeHasIdentityFalseOnFresh() {
        val bridge = KeyStoreBridge(ctx)
        bridge.purgeAll()
        assertFalse(bridge.hasIdentity())
    }
}
