import Foundation
import Security
import UmbrellaFFI

/// `KeyStoreBridge` — iOS Keychain + Secure Enclave facade для identity-seed
/// и device-keys.
///
/// # Скоуп Блока 7.8
///
/// Блок 7.8 ограничен skeleton-реализацией. `PersistentKeyStore` Rust trait
/// (см. `crates/umbrella-client/src/keystore/trait_def.rs`) **не экспонирован**
/// через uniffi как `callback_interface` в этом блоке — соответственно
/// `KeyStoreBridge` **не** наследует Rust trait и не передаётся в
/// `UmbrellaClientHandle` через FFI. Реальный two-way wiring через uniffi
/// callback interface появляется в Блоке 7.10 integration milestone.
///
/// Identity-seed хранится в Keychain с атрибутом
/// `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` — недоступен без passcode,
/// не синхронизируется в iCloud. Device-keys в Secure Enclave через
/// `SecKeyCreateRandomKey` с `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave`
/// — non-exportable P-256. Ed25519 → P-256 маппинг внутри SE — ADR-010 Решение 5.
///
/// # Block 7.8 scope
///
/// Block 7.8 ships a skeleton only. The `PersistentKeyStore` Rust trait
/// (`crates/umbrella-client/src/keystore/trait_def.rs`) is **not** exposed via
/// uniffi as a `callback_interface` here, so `KeyStoreBridge` does **not**
/// inherit the Rust trait and is not passed into `UmbrellaClientHandle`
/// through the FFI. Real two-way wiring via a uniffi callback interface
/// arrives in the Block 7.10 integration milestone.
///
/// The identity seed lives in Keychain with
/// `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` — unavailable without
/// device passcode, not iCloud-synced. Device keys live in Secure Enclave via
/// `SecKeyCreateRandomKey` with
/// `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave` — non-exportable P-256.
/// Ed25519 → P-256 mapping inside SE is ADR-010 Decision 5.
final class KeyStoreBridge {
    enum BridgeError: Error {
        case native(String)
    }

    private let identityAccount = "umbrellax.identity.seed"
    private let service = "xyz.umbrellax.testharness.keystore"

    init() throws {
        // pre-checks; Secure Enclave available on iPhone 5s+ (iOS 14+ requirement).
    }

    /// Проверить наличие идентичности в Keychain.
    ///
    /// Check whether an identity exists in Keychain.
    func hasIdentity() async throws -> Bool {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: identityAccount,
            kSecReturnData: false,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return true
        case errSecItemNotFound:
            return false
        default:
            throw BridgeError.native("SecItemCopyMatching status \(status)")
        }
    }

    /// Сохранить seed (24-слова BIP-39, 64 байта после PBKDF) в Keychain.
    ///
    /// Store the seed (24-word BIP-39, 64 bytes post-PBKDF) in Keychain.
    func storeSeed(_ seed: Data) async throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [],
            &error
        ), error == nil else {
            throw BridgeError.native("access control creation failed")
        }
        let attrs: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: identityAccount,
            kSecAttrAccessControl: access,
            kSecValueData: seed
        ]
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw BridgeError.native("SecItemAdd status \(status)")
        }
    }

    /// Удалить все записи нашего сервиса — для теста fresh-state.
    ///
    /// Delete all entries of our service — useful for fresh-state tests.
    func purgeAll() async throws {
        let q: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service
        ]
        SecItemDelete(q as CFDictionary)
    }
}
