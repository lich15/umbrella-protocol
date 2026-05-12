//! `DtlsRunner` — владеет [`IdentityDtlsFingerprint`] для одной call session.
//!
//! Блок 7.6 (этот файл) — структурная подготовка: хранит local fingerprint
//! и session nonce, предоставляет [`DtlsRunner::verify_remote`] с
//! constant-time сравнением против expected fingerprint (derived from
//! peer identity + session nonce).
//!
//! Реальная интеграция с DTLS engine остаётся отдельной границей: этот модуль
//! делает только identity-binding и constant-time fingerprint verification.
//! Production dependency tree не линкует DTLS crate, пока нет поддерживаемого
//! пути без `bincode`.
//!
//! `DtlsRunner` owns the [`IdentityDtlsFingerprint`] for a single call
//! session.
//!
//! Block 7.6 (this file) is the structural scaffolding: stores the local
//! fingerprint and session nonce, exposes [`DtlsRunner::verify_remote`] with
//! constant-time comparison against the expected fingerprint (derived from
//! peer identity + session nonce).
//!
//! Real integration with a DTLS engine stays behind a separate boundary: this
//! module only performs identity-binding and constant-time fingerprint
//! verification. The production dependency tree does not link a DTLS crate
//! until a maintained path exists without `bincode`.

use umbrella_calls::IdentityDtlsFingerprint;

use crate::ClientError;

/// Runner DTLS 1.3 handshake для одной сессии звонка.
///
/// Runner for the DTLS 1.3 handshake of a single call session.
pub struct DtlsRunner {
    local_fingerprint: IdentityDtlsFingerprint,
    session_nonce: [u8; 16],
}

impl DtlsRunner {
    /// Создаёт runner с derived local fingerprint.
    ///
    /// `local_identity_pub` — 32-байтовый Ed25519 identity pubkey (публичная
    /// часть `umbrella_identity::IdentityKey`). `session_nonce` — 16-байтовое
    /// per-call random (не секретное; предотвращает fingerprint replay).
    ///
    /// Creates a runner with a derived local fingerprint.
    ///
    /// `local_identity_pub` — 32-byte Ed25519 identity pubkey (the public half
    /// of `umbrella_identity::IdentityKey`). `session_nonce` — 16-byte
    /// per-call random (not secret; prevents fingerprint replay).
    #[must_use]
    pub fn new(local_identity_pub: [u8; 32], session_nonce: [u8; 16]) -> Self {
        let local_fingerprint =
            IdentityDtlsFingerprint::derive(&local_identity_pub, &session_nonce);
        Self {
            local_fingerprint,
            session_nonce,
        }
    }

    /// Локальный identity-bound fingerprint — подставляется в DTLS
    /// certificate на блоке 7.10 интеграции.
    ///
    /// Local identity-bound fingerprint — embedded into the DTLS certificate
    /// in the Block 7.10 integration.
    #[must_use]
    pub fn local_fingerprint(&self) -> &IdentityDtlsFingerprint {
        &self.local_fingerprint
    }

    /// Проверяет удалённый fingerprint против ожидаемого (derived from
    /// `peer_identity_pub` + нашего `session_nonce`). Constant-time сравнение
    /// через [`IdentityDtlsFingerprint::verify_or_err`].
    ///
    /// # Ошибки / Errors
    ///
    /// - [`ClientError::Call`]`(CallError::IdentityBindingFailed)` если
    ///   remote fingerprint не совпадает с expected.
    ///
    /// Verifies the remote fingerprint against the expected one (derived from
    /// `peer_identity_pub` + our `session_nonce`). Constant-time comparison
    /// via [`IdentityDtlsFingerprint::verify_or_err`].
    ///
    /// # Errors
    ///
    /// - [`ClientError::Call`]`(CallError::IdentityBindingFailed)` if the
    ///   remote fingerprint does not match the expected one.
    pub fn verify_remote(
        &self,
        peer_identity_pub: &[u8; 32],
        remote_fingerprint: &IdentityDtlsFingerprint,
    ) -> Result<(), ClientError> {
        let expected = IdentityDtlsFingerprint::derive(peer_identity_pub, &self.session_nonce);
        expected
            .verify_or_err(remote_fingerprint)
            .map_err(Into::into)
    }

    /// Session nonce — 16 байт, использованные для derivation local и
    /// expected fingerprints.
    ///
    /// Session nonce — 16 bytes used for local and expected fingerprint
    /// derivation.
    #[must_use]
    pub fn session_nonce(&self) -> &[u8; 16] {
        &self.session_nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbrella_calls::CallError;

    #[test]
    fn new_derives_local_fingerprint_from_pub_and_nonce() {
        let pk = [0xAB; 32];
        let nonce = [0x42; 16];
        let runner = DtlsRunner::new(pk, nonce);
        let expected = IdentityDtlsFingerprint::derive(&pk, &nonce);
        assert_eq!(runner.local_fingerprint(), &expected);
        assert_eq!(runner.session_nonce(), &nonce);
    }

    #[test]
    fn verify_remote_ok_on_matching_peer_fingerprint() {
        let local_pk = [0xAA; 32];
        let peer_pk = [0xBB; 32];
        let nonce = [0x01; 16];
        let runner = DtlsRunner::new(local_pk, nonce);
        let peer_fp = IdentityDtlsFingerprint::derive(&peer_pk, &nonce);
        runner.verify_remote(&peer_pk, &peer_fp).unwrap();
    }

    #[test]
    fn verify_remote_err_on_wrong_peer_pubkey() {
        let local_pk = [0xAA; 32];
        let peer_pk = [0xBB; 32];
        let wrong_peer = [0xCC; 32];
        let nonce = [0x01; 16];
        let runner = DtlsRunner::new(local_pk, nonce);
        let peer_fp = IdentityDtlsFingerprint::derive(&peer_pk, &nonce);
        let err = runner.verify_remote(&wrong_peer, &peer_fp).unwrap_err();
        assert!(matches!(
            err,
            ClientError::Call(CallError::IdentityBindingFailed)
        ));
    }

    #[test]
    fn verify_remote_err_on_tampered_fingerprint() {
        let local_pk = [0xAA; 32];
        let peer_pk = [0xBB; 32];
        let nonce = [0x01; 16];
        let runner = DtlsRunner::new(local_pk, nonce);
        let tampered = IdentityDtlsFingerprint::derive(&peer_pk, &[0x99; 16]);
        let err = runner.verify_remote(&peer_pk, &tampered).unwrap_err();
        assert!(matches!(
            err,
            ClientError::Call(CallError::IdentityBindingFailed)
        ));
    }
}
