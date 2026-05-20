//! Построение KeyPackage с canonical lifetime и whitelist ciphersuites.
//! Building KeyPackage with canonical lifetime and ciphersuite whitelist.
//!
//! KeyPackage — это публичный артефакт устройства, опубликованный в `key-svc` (Umbrella server implementation).
//! Когда другой пользователь хочет добавить нашего пользователя в чат, он скачивает наш
//! KeyPackage и использует его в Welcome-сообщении.
//!
//! Каноническая политика Umbrella:
//!
//! - Lifetime ровно `KEY_PACKAGE_LIFETIME_SECS` (28 дней) — устройства обязаны refresh
//!   свои KeyPackage в KT log минимум каждые 28 дней. Это укорачивает окно использования
//!   утёкшего KeyPackage злоумышленником.
//! - Capabilities декларируют только наши whitelist ciphersuites — даже если openmls в будущем
//!   добавит новые ECDSA-варианты, мы их не объявляем поддерживаемыми.
//! - Credential построен через `build_credential_for_device` — связан с device-key через KeyStore.
//!
//! KeyPackage is the public device artefact, published in `key-svc` (Umbrella server implementation). When another
//! user wants to add our user to a chat, they fetch our KeyPackage and use it in a Welcome
//! message.
//!
//! Umbrella canonical policy:
//!
//! - Lifetime exactly `KEY_PACKAGE_LIFETIME_SECS` (28 days) — devices must refresh their
//!   KeyPackage in the KT log at least every 28 days. This shrinks the window an attacker can
//!   exploit a leaked KeyPackage.
//! - Capabilities declare only our whitelist ciphersuites — even if openmls later adds new
//!   ECDSA variants, we don't advertise them as supported.
//! - Credential built via `build_credential_for_device` — bound to a device key via KeyStore.

use openmls::key_packages::{KeyPackageBuilder, KeyPackageBundle, Lifetime};
use openmls_traits::OpenMlsProvider;

use umbrella_identity::KeyStore;

use crate::caps::umbrella_capabilities;
use crate::ciphersuite::UmbrellaCiphersuite;
use crate::credential::build_credential_for_device;
use crate::error::{MlsError, Result};
use crate::group_policy::KEY_PACKAGE_LIFETIME_SECS;
use crate::signer::UmbrellaDeviceSigner;

/// Обёртка над `KeyPackageBundle` openmls фиксирующая что bundle построен по политике Umbrella.
/// Wrapper over openmls `KeyPackageBundle` recording that the bundle is built by Umbrella policy.
pub struct UmbrellaKeyPackageBundle {
    inner: KeyPackageBundle,
    ciphersuite: UmbrellaCiphersuite,
    device_index: u32,
}

impl UmbrellaKeyPackageBundle {
    /// Возвращает соответствующий публичный KeyPackage для публикации (в KT log / key-svc).
    /// Returns the corresponding public KeyPackage for publication (KT log / key-svc).
    pub fn key_package(&self) -> &openmls::key_packages::KeyPackage {
        self.inner.key_package()
    }

    /// Возвращает внутренний openmls bundle (для передачи в openmls API при join операциях).
    /// Returns the internal openmls bundle (for handing to openmls API on join operations).
    pub fn into_inner(self) -> KeyPackageBundle {
        self.inner
    }

    /// Возвращает ссылку на внутренний bundle без consume.
    /// Returns a reference to the internal bundle without consuming.
    pub fn as_inner(&self) -> &KeyPackageBundle {
        &self.inner
    }

    /// Ciphersuite которым построен этот KeyPackage.
    /// Ciphersuite this KeyPackage was built with.
    pub fn ciphersuite(&self) -> UmbrellaCiphersuite {
        self.ciphersuite
    }

    /// Device index подписавшего устройства.
    /// device_index of the signing device.
    pub fn device_index(&self) -> u32 {
        self.device_index
    }
}

/// Строит KeyPackage для указанного device по canonical Umbrella политике.
/// Builds a KeyPackage for the given device per canonical Umbrella policy.
///
/// `keystore` хранит ключи устройства, `device_index` — индекс подписывающего устройства,
/// `ciphersuite` — выбранный ciphersuite (должен быть из whitelist Ed25519/Ed448).
///
/// Возвращает `UmbrellaKeyPackageBundle` который содержит:
/// - публичный KeyPackage для публикации
/// - приватные части (HPKE init, encryption key) хранятся в provider storage автоматически
///
/// `keystore` holds the device's keys, `device_index` — the signing device's index,
/// `ciphersuite` — the chosen ciphersuite (must be from the Ed25519/Ed448 whitelist).
///
/// Returns an `UmbrellaKeyPackageBundle` containing:
/// - the public KeyPackage for publication
/// - private parts (HPKE init, encryption key) stored in the provider storage automatically
pub fn build_device_key_package(
    provider: &impl OpenMlsProvider,
    keystore: &dyn KeyStore,
    device_index: u32,
    ciphersuite: UmbrellaCiphersuite,
) -> Result<UmbrellaKeyPackageBundle> {
    let signer = UmbrellaDeviceSigner::new(keystore, device_index)?;
    let credential_with_key = build_credential_for_device(keystore, device_index)?;

    let bundle = KeyPackageBuilder::new()
        .key_package_lifetime(Lifetime::new(KEY_PACKAGE_LIFETIME_SECS))
        .leaf_node_capabilities(umbrella_capabilities())
        .build(
            ciphersuite.to_openmls(),
            provider,
            &signer,
            credential_with_key,
        )
        .map_err(|_| MlsError::KeyPackage {
            kind: "openmls KeyPackageBuilder::build failed",
        })?;

    Ok(UmbrellaKeyPackageBundle {
        inner: bundle,
        ciphersuite,
        device_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use openmls::prelude::tls_codec::Serialize as TlsSerialize;
    use openmls_traits::types::Ciphersuite as OpenMlsCiphersuite;

    use umbrella_identity::keystore::FixedClock;
    use umbrella_identity::{Clock, IdentitySeed, InMemoryKeyStore, MnemonicLanguage};

    use crate::provider::UmbrellaProvider;

    #[allow(
        deprecated,
        reason = "test-only seed gen для MLS KeyPackage test fixtures; production identity uses \
                  distributed_identity_client::bootstrap_account"
    )]
    fn fresh_keystore() -> (Arc<InMemoryKeyStore>, FixedClock) {
        let mut rng = rand_core::OsRng;
        let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
        let clock = FixedClock::new(1_700_000_000);
        let store =
            InMemoryKeyStore::open(seed, 0, Arc::new(clock.clone()) as Arc<dyn Clock>).unwrap();
        (Arc::new(store), clock)
    }

    fn provider() -> UmbrellaProvider {
        UmbrellaProvider::default()
    }

    #[test]
    fn build_succeeds_for_default_ciphersuite() {
        let (store, _) = fresh_keystore();
        store.add_device(0, None).unwrap();
        let provider = provider();
        let bundle = build_device_key_package(
            &provider,
            store.as_ref(),
            0,
            UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519,
        )
        .expect("build must succeed for default ciphersuite");

        assert_eq!(
            bundle.ciphersuite(),
            UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519
        );
        assert_eq!(bundle.device_index(), 0);
    }

    #[test]
    fn build_for_unknown_device_rejected() {
        let (store, _) = fresh_keystore();
        // Не регистрируем устройство 5.
        // Device 5 not registered.
        let provider = provider();
        let result = build_device_key_package(
            &provider,
            store.as_ref(),
            5,
            UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519,
        );
        assert!(matches!(
            result,
            Err(MlsError::Identity(
                umbrella_identity::IdentityError::UnknownDevice { index: 5 }
            ))
        ));
    }

    #[test]
    fn key_package_uses_requested_ciphersuite() {
        let (store, _) = fresh_keystore();
        store.add_device(0, None).unwrap();
        let provider = provider();
        let bundle = build_device_key_package(
            &provider,
            store.as_ref(),
            0,
            UmbrellaCiphersuite::Mls128X25519AesGcmSha256Ed25519,
        )
        .unwrap();
        assert_eq!(
            bundle.key_package().ciphersuite(),
            OpenMlsCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        );
    }

    #[test]
    fn key_package_signature_key_equals_device_pubkey() {
        let (store, _) = fresh_keystore();
        store.add_device(3, None).unwrap();
        let provider = provider();
        let bundle = build_device_key_package(
            &provider,
            store.as_ref(),
            3,
            UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519,
        )
        .unwrap();

        let device_pub = store.device_public(3).unwrap().to_bytes();
        let kp_sig_key: &[u8] = bundle.key_package().leaf_node().signature_key().as_slice();
        assert_eq!(kp_sig_key, device_pub);
    }

    #[test]
    fn key_package_credential_payload_equals_device_credential_layout() {
        let (store, _) = fresh_keystore();
        store.add_device(7, None).unwrap();
        let provider = provider();
        let bundle = build_device_key_package(
            &provider,
            store.as_ref(),
            7,
            UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519,
        )
        .unwrap();

        let cred_payload: &[u8] = bundle
            .key_package()
            .leaf_node()
            .credential()
            .serialized_content();
        // 32 байта identity_pubkey + 4 байта device_index_BE = 36
        // 32 bytes identity_pubkey + 4 bytes device_index_BE = 36
        assert_eq!(cred_payload.len(), 36);
        assert_eq!(&cred_payload[..32], &store.identity_public().to_bytes());
        assert_eq!(&cred_payload[32..36], &7u32.to_be_bytes());
    }

    #[test]
    fn capabilities_declare_only_whitelisted_ciphersuites() {
        let (store, _) = fresh_keystore();
        store.add_device(0, None).unwrap();
        let provider = provider();
        let bundle = build_device_key_package(
            &provider,
            store.as_ref(),
            0,
            UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519,
        )
        .unwrap();

        let caps = bundle.key_package().leaf_node().capabilities();
        let declared_ids: Vec<u16> = caps.ciphersuites().iter().map(|c| c.value()).collect();

        // Все declared должны быть из whitelist.
        // Each declared ciphersuite must be in the whitelist.
        for id in &declared_ids {
            UmbrellaCiphersuite::from_raw_id(*id)
                .unwrap_or_else(|_| panic!("declared ciphersuite {id:#06x} not in whitelist"));
        }

        // Все always-allowed whitelist значения должны быть declared. 0x004D X-Wing — только под
        // feature pq (без feature provider не имеет HPKE базы для X-Wing KEM). Это согласовано с
        // caps.rs::umbrella_supported_openmls_ciphersuites.
        // All always-allowed whitelisted ciphersuites must be declared. 0x004D X-Wing is only
        // declared under feature pq (without it, the provider has no HPKE base mode for the X-Wing
        // KEM). Aligned with caps.rs::umbrella_supported_openmls_ciphersuites.
        for whitelisted in [0x0001u16, 0x0003, 0x0004, 0x0006] {
            assert!(
                declared_ids.contains(&whitelisted),
                "whitelisted ciphersuite {whitelisted:#06x} must be declared in capabilities"
            );
        }

        // 0x004D объявлено если и только если feature pq включена.
        // 0x004D is declared if and only if feature pq is enabled.
        let xwing_declared = declared_ids.contains(&0x004D);
        assert_eq!(
            xwing_declared,
            cfg!(feature = "pq"),
            "0x004D X-Wing ciphersuite declaration must equal feature pq state \
             (declared={xwing_declared}, feature pq={})",
            cfg!(feature = "pq")
        );
    }

    #[test]
    fn capabilities_do_not_declare_ecdsa_variants() {
        let (store, _) = fresh_keystore();
        store.add_device(0, None).unwrap();
        let provider = provider();
        let bundle = build_device_key_package(
            &provider,
            store.as_ref(),
            0,
            UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519,
        )
        .unwrap();

        let caps = bundle.key_package().leaf_node().capabilities();
        let declared_ids: Vec<u16> = caps.ciphersuites().iter().map(|c| c.value()).collect();

        // ECDSA-варианты НЕ должны быть в declared — иначе ETK атака возможна.
        // ECDSA variants must NOT appear in declared — otherwise ETK attack is possible.
        for ecdsa in [0x0002u16, 0x0005, 0x0007] {
            assert!(
                !declared_ids.contains(&ecdsa),
                "ECDSA ciphersuite {ecdsa:#06x} MUST NOT be declared in capabilities (ETK attack mitigation)"
            );
        }
    }

    #[test]
    fn key_package_serializable_via_tls_codec() {
        let (store, _) = fresh_keystore();
        store.add_device(0, None).unwrap();
        let provider = provider();
        let bundle = build_device_key_package(
            &provider,
            store.as_ref(),
            0,
            UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519,
        )
        .unwrap();

        let serialized = bundle
            .key_package()
            .tls_serialize_detached()
            .expect("KeyPackage must serialize via tls_codec");
        // Минимальная sanity-проверка: размер публикуемого KeyPackage достаточный.
        // Minimal sanity check: published KeyPackage size is non-trivial.
        assert!(serialized.len() > 100);
    }

    #[test]
    fn distinct_devices_produce_distinct_key_packages() {
        let (store, _) = fresh_keystore();
        store.add_device(0, None).unwrap();
        store.add_device(1, None).unwrap();
        let provider = provider();
        let kp0 = build_device_key_package(
            &provider,
            store.as_ref(),
            0,
            UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519,
        )
        .unwrap();
        let kp1 = build_device_key_package(
            &provider,
            store.as_ref(),
            1,
            UmbrellaCiphersuite::Mls128X25519ChaChaSha256Ed25519,
        )
        .unwrap();

        assert_ne!(
            kp0.key_package().leaf_node().signature_key().as_slice(),
            kp1.key_package().leaf_node().signature_key().as_slice()
        );
    }
}
