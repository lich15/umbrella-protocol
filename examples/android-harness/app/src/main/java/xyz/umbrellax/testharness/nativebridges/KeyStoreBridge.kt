package xyz.umbrellax.testharness.nativebridges

import android.content.Context
import android.os.Build
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore

/**
 * `KeyStoreBridge` — AndroidKeyStore + `EncryptedSharedPreferences` facade
 * для identity-seed и device-keys.
 *
 * ## Скоуп Блока 7.9
 *
 * Skeleton: Rust `PersistentKeyStore` trait (см.
 * `crates/umbrella-client/src/keystore/trait_def.rs`) **не экспонирован**
 * через uniffi как `callback_interface`. `KeyStoreBridge` — standalone
 * Kotlin класс; real two-way wiring Rust ↔ Kotlin через uniffi callback
 * interface приходит в Блоке 7.10 integration milestone.
 *
 * Identity-seed хранится в `EncryptedSharedPreferences` с `MasterKey`
 * внутри AndroidKeyStore. На API 28+ запрашивается
 * `setRequestStrongBoxBacked(true)` — master key размещается в
 * hardware StrongBox chip (Pixel 3+, Samsung S10+); на 23-27 fallback
 * to TEE.
 *
 * ## Block 7.9 scope
 *
 * Skeleton only: the Rust `PersistentKeyStore` trait is **not** exposed via
 * uniffi as a `callback_interface`. `KeyStoreBridge` is a standalone Kotlin
 * class; real two-way Rust ↔ Kotlin wiring via a uniffi callback interface
 * arrives in the Block 7.10 integration milestone.
 *
 * The identity seed is stored in `EncryptedSharedPreferences` with a
 * `MasterKey` backed by AndroidKeyStore. On API 28+ we request
 * `setRequestStrongBoxBacked(true)` — the master key lives in the
 * hardware StrongBox chip (Pixel 3+, Samsung S10+); on 23-27 it falls back
 * to TEE.
 */
class KeyStoreBridge(private val ctx: Context) {

    private val encPrefsName = "umbrellax_identity_seed"
    private val keystoreAlias = "umbrellax.identity"

    /** `true` если идентичность уже сохранена в Keystore / Encrypted prefs. */
    fun hasIdentity(): Boolean {
        val keystore = KeyStore.getInstance("AndroidKeyStore")
        keystore.load(null)
        if (keystore.containsAlias(keystoreAlias)) {
            return true
        }
        val prefs = ctx.getSharedPreferences(encPrefsName, Context.MODE_PRIVATE)
        return prefs.contains("seed_hex")
    }

    /** Сохранить 64-байтовый BIP-39 seed в EncryptedSharedPreferences. */
    fun storeSeed(seed: ByteArray) {
        val masterKey = MasterKey.Builder(ctx)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setRequestStrongBoxBacked(true)
                }
            }
            .build()

        val prefs = EncryptedSharedPreferences.create(
            ctx,
            encPrefsName,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
        prefs.edit().putString(
            "seed_hex",
            seed.joinToString(separator = "") { "%02x".format(it) }
        ).apply()
    }

    /** Удалить все записи — для fresh-state тестов. */
    fun purgeAll() {
        val prefs = ctx.getSharedPreferences(encPrefsName, Context.MODE_PRIVATE)
        prefs.edit().clear().apply()

        val keystore = KeyStore.getInstance("AndroidKeyStore")
        keystore.load(null)
        if (keystore.containsAlias(keystoreAlias)) {
            keystore.deleteEntry(keystoreAlias)
        }
    }
}
