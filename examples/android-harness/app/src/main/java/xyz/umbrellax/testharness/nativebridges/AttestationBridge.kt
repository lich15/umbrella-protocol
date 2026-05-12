package xyz.umbrellax.testharness.nativebridges

import android.content.Context
import android.util.Base64
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * `AttestationBridge` — Google Play Integrity API wrapper для получения
 * platform attestation token'а.
 *
 * ## Скоуп Блока 7.9
 *
 * Skeleton: Rust `AttestationProvider` trait (см.
 * `crates/umbrella-client/src/attestation/provider_trait.rs`) **не
 * экспонирован** через uniffi как `callback_interface`. `AttestationBridge`
 * — standalone Kotlin утилитарный класс; real Rust ↔ Kotlin wiring
 * через uniffi callback interface в Блоке 7.10.
 *
 * `IntegrityManager.requestIntegrityToken(request)` производит cryptographic
 * proof что приложение running на genuine Android device с Play-installed APK.
 * Server-side verification — в Блоке 7.10.
 *
 * ## Block 7.9 scope
 *
 * Skeleton only: the Rust `AttestationProvider` trait is **not** exposed via
 * uniffi as a `callback_interface`. `AttestationBridge` is a standalone
 * Kotlin utility; real Rust ↔ Kotlin wiring via a uniffi callback interface
 * lands in Block 7.10.
 *
 * `IntegrityManager.requestIntegrityToken(request)` produces a cryptographic
 * proof that the app runs on a genuine Android device with a Play-installed
 * APK. Server-side verification is wired in Block 7.10.
 */
class AttestationBridge(private val ctx: Context) {

    private val manager = IntegrityManagerFactory.create(ctx)

    /** Platform tag. Matches Rust `Platform::Android`. */
    fun platformTag(): String = "Android"

    /**
     * Запрашивает Play Integrity token с `serverNonce` как challenge.
     *
     * Requests a Play Integrity token with `serverNonce` as the challenge.
     */
    suspend fun freshToken(serverNonce: ByteArray): ByteArray = suspendCancellableCoroutine { cont ->
        val nonceBase64 = Base64.encodeToString(
            serverNonce,
            Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING
        )
        val request = IntegrityTokenRequest.builder().setNonce(nonceBase64).build()

        manager.requestIntegrityToken(request)
            .addOnSuccessListener { response ->
                val token = response.token().toByteArray(Charsets.UTF_8)
                cont.resume(token)
            }
            .addOnFailureListener { err ->
                cont.resumeWithException(
                    RuntimeException("play integrity: ${err.message}", err)
                )
            }
    }
}
