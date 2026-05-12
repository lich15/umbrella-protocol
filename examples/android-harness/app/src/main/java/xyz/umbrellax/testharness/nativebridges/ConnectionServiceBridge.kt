package xyz.umbrellax.testharness.nativebridges

import android.content.ComponentName
import android.content.Context
import android.telecom.Connection
import android.telecom.ConnectionRequest
import android.telecom.ConnectionService
import android.telecom.PhoneAccount
import android.telecom.PhoneAccountHandle
import android.telecom.TelecomManager

/**
 * `UmbrellaConnectionService` + `PhoneAccountRegistrar` — Android Telecom
 * self-managed ConnectionService skeleton.
 *
 * Блок 7.9 — минимальный stub (outgoing/incoming create Connection без
 * media wiring). Интеграция с `CallSessionHandle` (FFI) + `AudioRecord`/
 * `MediaCodec` для media capture/playback — в Блоке 7.10.
 *
 * Block 7.9 ships a minimal stub (outgoing/incoming create Connection with
 * no media wiring). Integration with `CallSessionHandle` (FFI) +
 * `AudioRecord`/`MediaCodec` for media capture/playback arrives in
 * Block 7.10.
 */
class UmbrellaConnectionService : ConnectionService() {

    override fun onCreateOutgoingConnection(
        connectionManagerPhoneAccount: PhoneAccountHandle?,
        request: ConnectionRequest?
    ): Connection = object : Connection() {}

    override fun onCreateIncomingConnection(
        connectionManagerPhoneAccount: PhoneAccountHandle?,
        request: ConnectionRequest?
    ): Connection = object : Connection() {}
}

/**
 * Helper: регистрирует `UmbrellaConnectionService` в Android Telecom как
 * self-managed PhoneAccount. Requires `android.permission.MANAGE_OWN_CALLS`.
 */
object PhoneAccountRegistrar {
    private const val ACCOUNT_ID = "umbrellax_phone_account"

    fun register(ctx: Context) {
        val telecom = ctx.getSystemService(Context.TELECOM_SERVICE) as TelecomManager
        val handle = PhoneAccountHandle(
            ComponentName(ctx, UmbrellaConnectionService::class.java),
            ACCOUNT_ID
        )
        val account = PhoneAccount.builder(handle, "UmbrellaX")
            .setCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED)
            .build()
        telecom.registerPhoneAccount(account)
    }
}
