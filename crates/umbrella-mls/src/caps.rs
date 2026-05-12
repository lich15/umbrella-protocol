//! Canonical Umbrella capabilities для openmls Groups и KeyPackages.
//! Canonical Umbrella capabilities for openmls Groups and KeyPackages.
//!
//! Вынесены в отдельный модуль, чтобы `group` и `key_package` использовали одну и ту же
//! декларацию: только whitelist ciphersuites Ed25519/Ed448, только BasicCredential, никаких
//! experimental extensions/proposals.
//!
//! Extracted into a separate module so `group` and `key_package` use the same declaration:
//! whitelist-only Ed25519/Ed448 ciphersuites, BasicCredential only, no experimental
//! extensions/proposals.

use openmls::credentials::CredentialType;
use openmls::prelude::Capabilities;
use openmls::versions::ProtocolVersion;
use openmls_traits::types::Ciphersuite as OpenMlsCiphersuite;

use crate::ciphersuite::UmbrellaCiphersuite;

/// Все ciphersuites которые мы декларируем как поддерживаемые.
/// All ciphersuites we declare as supported.
///
/// Ровно whitelist `UmbrellaCiphersuite` — никаких ECDSA-вариантов. Декларация ECDSA в
/// capabilities открыла бы дверь к ETK-атаке даже если наш клиент их не использует: партнёр
/// по группе может принудить negotiate на ECDSA-ciphersuite при создании KeyPackage, и атакующий
/// в сети получил бы signature-malleable commits.
///
/// **PQ ciphersuite 0x004D (X-Wing) — только под feature `pq`.** Без feature клиент не имеет
/// `UmbrellaXWingProvider` и не может ни sealить, ни openить HPKE с X-Wing KEM (стандартный
/// `OpenMlsRustCrypto-0.5.1` падает в `unimplemented!()` на `HpkeKemType::XWingKemDraft6`).
/// Декларация без feature привела бы к runtime panic при handshake — нарушение постулата 14.
///
/// Exactly the `UmbrellaCiphersuite` whitelist — no ECDSA variants. Advertising ECDSA in
/// capabilities would expose the ETK attack even if our client does not use them: a group peer
/// could force-negotiate to an ECDSA ciphersuite on KeyPackage creation, and a network attacker
/// would gain signature-malleable commits.
///
/// **PQ ciphersuite 0x004D (X-Wing) is gated by feature `pq`.** Without the feature, the client
/// has no `UmbrellaXWingProvider` and cannot seal/open HPKE under X-Wing KEM (stock
/// `OpenMlsRustCrypto-0.5.1` panics in `unimplemented!()` on `HpkeKemType::XWingKemDraft6`).
/// Advertising it without the feature would lead to a runtime panic during handshake — postulate
/// 14 violation.
pub(crate) fn umbrella_supported_openmls_ciphersuites() -> Vec<OpenMlsCiphersuite> {
    #[cfg(not(feature = "pq"))]
    {
        vec![
            UmbrellaCiphersuite::Mls128X25519AesGcmSha256Ed25519.to_openmls(),
            UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519.to_openmls(),
            UmbrellaCiphersuite::Mls256X448AesGcmSha512Ed448.to_openmls(),
            UmbrellaCiphersuite::Mls256X448ChaChaSha512Ed448.to_openmls(),
        ]
    }
    #[cfg(feature = "pq")]
    {
        vec![
            UmbrellaCiphersuite::Mls128X25519AesGcmSha256Ed25519.to_openmls(),
            UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519.to_openmls(),
            UmbrellaCiphersuite::Mls256X448AesGcmSha512Ed448.to_openmls(),
            UmbrellaCiphersuite::Mls256X448ChaChaSha512Ed448.to_openmls(),
            UmbrellaCiphersuite::Mls256XWingChaChaSha256Ed25519.to_openmls(),
        ]
    }
}

/// Canonical Umbrella capabilities для leaf-node:
/// MLS 1.0 + whitelist ciphersuites + BasicCredential; никаких experimental extensions/proposals.
///
/// Canonical Umbrella leaf-node capabilities:
/// MLS 1.0 + whitelist ciphersuites + BasicCredential; no experimental extensions/proposals.
pub(crate) fn umbrella_capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&umbrella_supported_openmls_ciphersuites()),
        None,
        None,
        Some(&[CredentialType::Basic]),
    )
}
