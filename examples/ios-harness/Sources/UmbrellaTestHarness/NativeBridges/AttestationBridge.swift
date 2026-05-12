import Foundation
import DeviceCheck
import UmbrellaFFI

/// `AttestationBridge` — Apple App Attest (`DCAppAttestService`) обёртка
/// для генерации platform attestation token'а.
///
/// # Скоуп Блока 7.8
///
/// Skeleton-реализация: Rust `AttestationProvider` trait (см.
/// `crates/umbrella-client/src/attestation/provider_trait.rs`) **не
/// экспонирован** через uniffi как `callback_interface`. `AttestationBridge`
/// — самостоятельный iOS утилитарный класс; реальная интеграция Rust ↔ Swift
/// через uniffi callback interface в Блоке 7.10.
///
/// `generateKey` создаёт attestation key pair внутри Secure Enclave,
/// `attestKey(clientDataHash:)` делает attestation assertion (cryptographic
/// proof что приложение running на genuine Apple device). Server-side
/// verification — в Блоке 7.10.
///
/// # Block 7.8 scope
///
/// Skeleton only: the Rust `AttestationProvider` trait
/// (`crates/umbrella-client/src/attestation/provider_trait.rs`) is **not**
/// exposed via uniffi as a `callback_interface`. `AttestationBridge` is a
/// standalone iOS utility; real Rust ↔ Swift integration via a uniffi
/// callback interface lands in Block 7.10.
///
/// `generateKey` creates an attestation key pair inside Secure Enclave,
/// `attestKey(clientDataHash:)` produces an attestation assertion
/// (cryptographic proof that the app runs on a genuine Apple device). Server
/// verification is wired in Block 7.10.
final class AttestationBridge {
    enum BridgeError: Error {
        case notSupported
        case native(String)
    }

    private let service = DCAppAttestService.shared
    private var keyId: String?

    /// Генерирует attestation assertion для `serverNonce` (32-байтовый
    /// challenge от Sealed Server). Возвращает raw token bytes —
    /// переложенные в `PlatformAttestation` в Блоке 7.10.
    ///
    /// # Errors
    ///
    /// - `BridgeError.notSupported` если устройство не поддерживает App Attest.
    /// - `BridgeError.native` для underlying SDK error.
    ///
    /// Generates an attestation assertion for `serverNonce` (a 32-byte
    /// challenge from the Sealed Server). Returns the raw token bytes, which
    /// Block 7.10 repackages into `PlatformAttestation`.
    func freshToken(serverNonce: Data) async throws -> Data {
        guard service.isSupported else {
            throw BridgeError.notSupported
        }

        if keyId == nil {
            keyId = try await withCheckedThrowingContinuation { cont in
                service.generateKey { id, err in
                    if let err = err {
                        cont.resume(throwing: err)
                    } else if let id = id {
                        cont.resume(returning: id)
                    } else {
                        cont.resume(throwing: BridgeError.native("generateKey returned nil"))
                    }
                }
            }
        }

        let clientDataHash = serverNonce.subdata(in: 0..<min(32, serverNonce.count))

        return try await withCheckedThrowingContinuation { cont in
            service.attestKey(keyId!, clientDataHash: clientDataHash) { assertion, err in
                if let err = err {
                    cont.resume(throwing: err)
                } else if let assertion = assertion {
                    cont.resume(returning: assertion)
                } else {
                    cont.resume(throwing: BridgeError.native("attestKey returned nil"))
                }
            }
        }
    }

    /// Платформа — `iOS`. Matches Rust `Platform::iOs`.
    ///
    /// Platform — `iOS`. Matches Rust `Platform::iOs`.
    func platformTag() -> String { "iOs" }
}
