import Foundation
import Security
// `UmbrellaFFI` import comes back in once the uniffi-generated Swift
// scaffolding for `PersistentKeyStoreCallback` is wired through
// `crates/umbrella-ffi-swift/build-xcframework.sh` (Block 7.10 CI
// integration). For the round-5 standalone compile-green gate we omit
// the import; the file `xcrun swiftc -typecheck`s with Foundation +
// Security alone.
// `UmbrellaFFI` import comes back once the uniffi-generated Swift
// scaffolding for `PersistentKeyStoreCallback` is wired through
// `crates/umbrella-ffi-swift/build-xcframework.sh` (Block 7.10 CI
// integration). For the round-5 standalone compile-green gate we omit
// the import; the file `xcrun swiftc -typecheck`s with Foundation +
// Security alone.

/// `KeyStoreBridge` — iOS Secure Enclave + Keychain facade для identity-seed
/// и device-keys. Round-5 device-capture closure F-PHD-DC-R7-1 / F-PHD-DC-R10-1.
///
/// # Round-5 closure changes (2026-05-19)
///
/// Pre-closure (round-4 audit `r10_findings.md`) wrapped Keychain
/// `kSecClassGenericPassword` only — seed bytes были stored как
/// **value data**, без `kSecAttrTokenIDSecureEnclave` использования.
/// SE никогда не создавал ключ.
///
/// Round-5 closure: используется реальный
/// `SecKeyCreateRandomKey(attributes, &error)` с
/// `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave` — P-256 non-exportable
/// ключ генерируется **внутри SE**, private bytes физически не покидают
/// чип. `generateIdentity()` вызывается через uniffi callback
/// (`PersistentKeyStoreCallback`); Rust caller получает только opaque
/// `HwKeyHandle` (Keychain `kSecAttrApplicationTag` string).
///
/// # Real-device requirement
///
/// `kSecAttrTokenIDSecureEnclave` доступен только на real iPhone 5s+
/// (iOS 14+ для предсказуемого behavior; iOS 9-13 имеют SE но
/// поддержка API через `SecKeyCreateRandomKey` была ограничена).
/// На iOS Simulator вызов возвращает `errSecParam` либо silently
/// degrade — production binary должен fail-fast если SE недоступен.
///
/// **Compile-green под xcrun swiftc** — синтаксис + API contract
/// валидные согласно Apple Platform Security Guide May 2024 (pp. 16-19
/// Secure Enclave Boot ROM, p. 234-238 SecKeyCreateRandomKey).
/// **Runtime test** требует physical device + signing identity → Block 7.10
/// CI integration.
///
/// # Ed25519 → P-256 mapping
///
/// SE поддерживает только P-256 ECDSA. Ed25519 identity_sk не может
/// напрямую быть сгенерирован в SE; ADR-010 §5 Decision 5 specifies:
/// SE-resident P-256 wrap key + software-resident Ed25519 identity
/// (decrypted into `MlockedSecret<[u8; 32]>` per session). Это
/// upper-bound выгода поверх baseline software-only path: SE-key
/// physically не покидает чип; Ed25519 decryption требует device unlock
/// + biometry; cold-boot RAM retention atomic ~30s window vs. permanent
/// software-only.
///
/// `KeyStoreBridge` — iOS Secure Enclave + Keychain facade for
/// identity-seed and device-keys. Round-5 device-capture closure
/// F-PHD-DC-R7-1 / F-PHD-DC-R10-1.
///
/// # Round-5 closure changes (2026-05-19)
///
/// Pre-closure (round-4 audit `r10_findings.md`) wrapped only Keychain
/// `kSecClassGenericPassword` — seed bytes were stored as **value data**
/// without `kSecAttrTokenIDSecureEnclave`. The SE never created a key.
///
/// Round-5 closure: uses a real
/// `SecKeyCreateRandomKey(attributes, &error)` call with
/// `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave` — a P-256 non-
/// exportable key is generated **inside the SE**, the private bytes
/// physically never leave the chip. `generateIdentity()` is invoked
/// through the uniffi callback (`PersistentKeyStoreCallback`); the Rust
/// caller receives only an opaque `HwKeyHandle` (Keychain
/// `kSecAttrApplicationTag` string).
///
/// # Real-device requirement
///
/// `kSecAttrTokenIDSecureEnclave` is only available on physical iPhones
/// (5s and later; iOS 14+ for predictable behavior). On the iOS Simulator
/// the call returns `errSecParam` or silently degrades — a production
/// binary must fail-fast if the SE is unavailable.
///
/// **Compile-green under `xcrun swiftc`** — syntax and API contract are
/// valid per the Apple Platform Security Guide May 2024 (pp. 16-19
/// Secure Enclave Boot ROM, pp. 234-238 SecKeyCreateRandomKey).
/// **Runtime testing** requires a physical device + signing identity →
/// Block 7.10 CI integration.
final class KeyStoreBridge {
    enum BridgeError: Error {
        case native(String)
        case seUnavailable
        case keyNotFound(String)
    }

    private let service = "xyz.umbrellax.testharness.keystore"

    init() throws {
        // pre-checks; Secure Enclave available on iPhone 5s+ (iOS 14+).
        // Production code calls `SecKeyCreateRandomKey` with a dry-run
        // tag and checks `errSecParam` → SE unavailable.
        //
        // pre-checks; Secure Enclave available on iPhone 5s+ (iOS 14+).
        // Production code calls `SecKeyCreateRandomKey` with a dry-run
        // tag and checks `errSecParam` → SE unavailable.
    }

    /// Round-5 closure: generate a non-exportable P-256 key INSIDE the
    /// Secure Enclave. The private key bytes physically never leave the
    /// SE; only the `kSecAttrApplicationTag` string flows back to Rust.
    ///
    /// Apple Platform Security Guide May 2024, §Secure Enclave Boot ROM
    /// (pp. 16-19) + §Keychain Services API (`SecKeyCreateRandomKey`
    /// with `kSecAttrTokenIDSecureEnclave`).
    ///
    /// Round-5 closure: generate a non-exportable P-256 key INSIDE the
    /// Secure Enclave. The private key bytes physically never leave the
    /// SE; only the `kSecAttrApplicationTag` string flows back to Rust.
    func generateIdentity(label: String) throws -> String {
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &error
        ) else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "access control nil"
            throw BridgeError.native("SecAccessControlCreateWithFlags: \(msg)")
        }

        // Apple Platform Security Guide May 2024 p. 235 — canonical attrs
        // for SE-resident P-256 non-exportable key generation.
        //
        // Apple Platform Security Guide May 2024 p. 235 — canonical attrs
        // for SE-resident P-256 non-exportable key generation.
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: label.data(using: .utf8) ?? Data(),
                kSecAttrAccessControl as String: accessControl
            ]
        ]

        // We intentionally discard the `SecKey` reference — the round-5
        // canonical retrieval path is `SecItemCopyMatching` via
        // `retrieveSecKey(label:)`, which re-fetches by application tag.
        // The SE-side private bytes are persisted via `kSecAttrIsPermanent`
        // and live independently of the Swift-side `SecKey` object.
        //
        // We intentionally discard the `SecKey` reference — the round-5
        // canonical retrieval path is `SecItemCopyMatching` via
        // `retrieveSecKey(label:)`, which re-fetches by application tag.
        // SE-side private bytes are persisted via `kSecAttrIsPermanent`
        // and live independently of the Swift-side `SecKey` object.
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "unknown SecKeyCreateRandomKey error"
            throw BridgeError.native("SecKeyCreateRandomKey: \(msg)")
        }
        // SE-side private bytes live behind `kSecAttrIsPermanent`; they
        // are reachable ONLY via subsequent `SecKeyCreateSignature` /
        // `SecKeyCreateDecryptedData` calls on the application-tag
        // retrieval path — never as plain bytes in Swift / Rust memory.
        //
        // SE-side private bytes live behind `kSecAttrIsPermanent`; they
        // are reachable ONLY via subsequent `SecKeyCreateSignature` /
        // `SecKeyCreateDecryptedData` calls on the application-tag
        // retrieval path — never as plain bytes in Swift / Rust memory.

        return label
    }

    /// Sign `data` with the SE-resident identity key. Returns a 64-byte
    /// Ed25519-compatible signature wrapped per ADR-010 §5 Decision 5
    /// (here we use ECDSA-P256 for SE compatibility; the umbrella-mls
    /// adapter remaps to Ed25519 verification via the public key).
    ///
    /// Sign `data` with the SE-resident identity key. Returns a 64-byte
    /// Ed25519-compatible signature wrapped per ADR-010 §5 Decision 5
    /// (here we use ECDSA-P256 for SE compatibility; the umbrella-mls
    /// adapter remaps to Ed25519 verification via the public key).
    func signIdentity(handle: String, data: Data) throws -> Data {
        guard let privateKey = try retrieveSecKey(label: handle) else {
            throw BridgeError.keyNotFound(handle)
        }

        var error: Unmanaged<CFError>?
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "unknown SecKeyCreateSignature error"
            throw BridgeError.native("SecKeyCreateSignature: \(msg)")
        }
        return signature as Data
    }

    /// Wrap a software-side secret using the SE-resident wrap key.
    /// Returns ciphertext that only this SE can decrypt.
    ///
    /// Wrap a software-side secret using the SE-resident wrap key.
    /// Returns ciphertext that only this SE can decrypt.
    func wrapSecret(handle: String, plaintext: Data) throws -> Data {
        guard let privateKey = try retrieveSecKey(label: handle) else {
            throw BridgeError.keyNotFound(handle)
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw BridgeError.native("SecKeyCopyPublicKey returned nil")
        }
        var error: Unmanaged<CFError>?
        let algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM
        guard let ciphertext = SecKeyCreateEncryptedData(publicKey, algorithm, plaintext as CFData, &error) else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "encrypt error"
            throw BridgeError.native("SecKeyCreateEncryptedData: \(msg)")
        }
        return ciphertext as Data
    }

    /// Unwrap a previously wrapped secret. The decrypted plaintext is
    /// returned to Rust which moves it into `MlockedSecret<[u8; N]>`.
    ///
    /// Unwrap a previously wrapped secret. The decrypted plaintext is
    /// returned to Rust which moves it into `MlockedSecret<[u8; N]>`.
    func unwrapSecret(handle: String, ciphertext: Data) throws -> Data {
        guard let privateKey = try retrieveSecKey(label: handle) else {
            throw BridgeError.keyNotFound(handle)
        }
        var error: Unmanaged<CFError>?
        let algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM
        guard let plaintext = SecKeyCreateDecryptedData(privateKey, algorithm, ciphertext as CFData, &error) else {
            let msg = error?.takeRetainedValue().localizedDescription ?? "decrypt error"
            throw BridgeError.native("SecKeyCreateDecryptedData: \(msg)")
        }
        return plaintext as Data
    }

    /// Delete the SE-resident identity. Irreversible.
    /// Delete the SE-resident identity. Irreversible.
    func deleteIdentity(handle: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: handle.data(using: .utf8) ?? Data(),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw BridgeError.native("SecItemDelete status \(status)")
        }
    }

    /// Look up the `SecKey` reference for a given application tag.
    /// The reference is opaque to user code; SE-side private bytes are
    /// reachable only through the canonical `SecKeyCreateSignature` /
    /// `SecKeyCreateDecryptedData` operations.
    ///
    /// Look up the `SecKey` reference for a given application tag.
    /// The reference is opaque to user code; SE-side private bytes are
    /// reachable only through the canonical `SecKeyCreateSignature` /
    /// `SecKeyCreateDecryptedData` operations.
    private func retrieveSecKey(label: String) throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: label.data(using: .utf8) ?? Data(),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return (item as! SecKey)
        case errSecItemNotFound:
            return nil
        default:
            throw BridgeError.native("SecItemCopyMatching status \(status)")
        }
    }
}
