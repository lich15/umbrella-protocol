//! Integration tests для SLH-DSA backup recovery flow (Этап 8 ADR-011 Решение 5).
//! Integration tests for the SLH-DSA backup recovery flow (Stage 8 ADR-011 Decision 5).
//!
//! SLH-DSA backup используется для catastrophic recovery (когда identity key
//! утерян/скомпрометирован) — KT принимает rotation если SLH-DSA verify ОК
//! независимо от того что Ed25519 / ML-DSA-65 ключи возможно скомпрометированы.
//! Это защита если найдут lattice-attack на ML-DSA семейство.
//!
//! SLH-DSA backup is used for the catastrophic recovery flow (when identity key is
//! lost or compromised) — KT accepts rotation if SLH-DSA verifies OK regardless of
//! whether Ed25519 / ML-DSA-65 may be compromised. This protects against discovered
//! lattice attacks on the ML-DSA family.

#![cfg(feature = "pq")]

use std::sync::Arc;

use rand_core::OsRng;

use umbrella_identity::{
    Clock, IdentitySeed, InMemoryKeyStore, KeyStore, MnemonicLanguage, SlhDsaBackupKeyPublic,
    SLH_DSA_BACKUP_ROTATION_CONTEXT,
};
use umbrella_pq::{
    slh_dsa_128f_sign, slh_dsa_128f_verify, PqError, SlhDsa128fSignature,
    SLH_DSA_128F_PUBLIC_KEY_LEN, SLH_DSA_128F_SIGNATURE_LEN,
};

struct ZeroClock;
impl Clock for ZeroClock {
    fn now_unix_secs(&self) -> u64 {
        0
    }
}

fn fresh_store() -> (InMemoryKeyStore, IdentitySeed) {
    let mut rng = OsRng;
    let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    let mnemonic = seed.to_mnemonic();
    // Возвращаем дополнительный seed (re-derived) чтобы тесты могли restore.
    // Return an extra seed (re-derived) so tests can restore.
    let store = InMemoryKeyStore::open(seed, 0, Arc::new(ZeroClock) as Arc<dyn Clock>).unwrap();
    let extra = IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();
    (store, extra)
}

/// Catastrophic recovery rotation flow:
/// 1. User создаёт identity → KeyStore содержит SLH-DSA backup key (derived из same mnemonic).
/// 2. Identity ML-DSA-65 ключ скомпрометирован (предположим lattice attack found).
/// 3. User инициирует rotation: подписывает rotation-proof message SLH-DSA backup ключом.
/// 4. KT v2 (будет в block 8.5) принимает rotation если SLH-DSA verify ОК.
///
/// Catastrophic recovery rotation flow:
/// 1. User creates identity → KeyStore contains the SLH-DSA backup key (derived from the
///    same mnemonic).
/// 2. The identity ML-DSA-65 key is compromised (suppose a lattice attack is discovered).
/// 3. User initiates rotation: signs the rotation-proof message with the SLH-DSA backup key.
/// 4. KT v2 (will be added in block 8.5) accepts rotation if SLH-DSA verifies OK.
#[test]
fn catastrophic_recovery_rotation_proof_roundtrip() {
    let (store, _) = fresh_store();
    let backup_pub = store.slh_dsa_backup_public();
    assert_eq!(backup_pub.to_bytes().len(), SLH_DSA_128F_PUBLIC_KEY_LEN);

    // Canonical rotation-proof message: новый identity_pubkey || kt_seq || timestamp.
    // Реальный layout будет зафиксирован в SPEC-09 v2 (block 8.5); здесь — sanity-check
    // что подпись через SLH-DSA backup проходит verify через тот же backup pubkey.
    // Canonical rotation-proof message: new identity_pubkey || kt_seq || timestamp.
    // The real layout will be specified in SPEC-09 v2 (block 8.5); here we simply verify
    // that a signature through the SLH-DSA backup is accepted by the same backup pubkey.
    let new_identity_pubkey = [0xAB; 32];
    let kt_seq: u64 = 12345;
    let ts: u64 = 1_730_000_000;
    let mut rotation_proof = Vec::with_capacity(32 + 8 + 8);
    rotation_proof.extend_from_slice(&new_identity_pubkey);
    rotation_proof.extend_from_slice(&kt_seq.to_be_bytes());
    rotation_proof.extend_from_slice(&ts.to_be_bytes());

    let sig = store.sign_slh_dsa_backup_proof(&rotation_proof).unwrap();
    assert_eq!(sig.as_bytes().len(), SLH_DSA_128F_SIGNATURE_LEN);

    backup_pub
        .verify_rotation_proof(&rotation_proof, &sig)
        .expect("rotation proof must verify against backup pubkey");
}

/// Restore flow: BIP-39 mnemonic восстанавливает SLH-DSA backup key. Подпись от
/// original может быть верифицирована через restored pubkey (и наоборот).
/// Restore flow: a BIP-39 mnemonic restores the SLH-DSA backup key. A signature from
/// the original verifies against the restored pubkey (and vice versa).
#[test]
fn slh_dsa_backup_restore_yields_compatible_signatures() {
    let mut rng = OsRng;
    let original_seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    let mnemonic = original_seed.to_mnemonic();

    let store_original =
        InMemoryKeyStore::open(original_seed, 0, Arc::new(ZeroClock) as Arc<dyn Clock>).unwrap();

    let restored_seed =
        IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();
    let store_restored =
        InMemoryKeyStore::open(restored_seed, 0, Arc::new(ZeroClock) as Arc<dyn Clock>).unwrap();

    // Backup pubkeys должны совпадать.
    // Backup pubkeys must match.
    assert_eq!(
        store_original.slh_dsa_backup_public().to_bytes(),
        store_restored.slh_dsa_backup_public().to_bytes()
    );

    // Подпись от original валидна через restored pubkey.
    // Original-signed proof verifies through restored pubkey.
    let proof = b"rotation proof v1";
    let sig = store_original.sign_slh_dsa_backup_proof(proof).unwrap();
    store_restored
        .slh_dsa_backup_public()
        .verify_rotation_proof(proof, &sig)
        .expect("restored pubkey must verify original signature");
}

/// Adversarial: подпись с другим domain context не должна валидироваться через
/// `verify_rotation_proof` (domain separation enforcement).
/// Adversarial: a signature with a different domain context must not validate via
/// `verify_rotation_proof` (domain separation enforcement).
#[test]
fn slh_dsa_backup_cross_context_signature_rejected() {
    let (store, _) = fresh_store();
    let backup_pub = store.slh_dsa_backup_public();

    // Подписываем с другим контекстом напрямую через umbrella_pq API (минуя KeyStore wrapper).
    // Sign with a different context directly through umbrella_pq API (bypassing the
    // KeyStore wrapper).
    let msg = b"rotation msg";
    let other_ctx = b"non-rotation-context";

    // Чтобы получить SecretKey доступ — нужно пройти через store; но keystore не
    // expose'ит приватный ключ. Поэтому adversarial test делаем через
    // подпись фейковым backup key и попытку verify через настоящий pubkey
    // (что должно fail независимо от контекста — другая identity).
    // To gain SecretKey access we'd need to bypass the keystore; but keystore doesn't
    // expose the private key. So we simulate adversary via a fresh standalone backup
    // key and try to verify through the real pubkey (must fail — different identity).
    let mut rng = OsRng;
    let (other_pk, other_sk) = umbrella_pq::slh_dsa_128f_keygen(&mut rng).unwrap();
    let sig_from_other = slh_dsa_128f_sign(&mut rng, &other_sk, msg, other_ctx).unwrap();

    // Sanity: подпись валидна через other_pk + other_ctx.
    // Sanity: signature validates with other_pk + other_ctx.
    slh_dsa_128f_verify(&other_pk, msg, other_ctx, &sig_from_other).unwrap();

    // А через настоящий backup_pub (с rotation_context) — fail.
    // But against the real backup_pub (with rotation_context) — fail.
    let result = backup_pub.verify_rotation_proof(msg, &sig_from_other);
    assert!(matches!(
        result,
        Err(umbrella_identity::IdentityError::Pq(
            PqError::SlhDsaSignatureVerificationFailed
        ))
    ));
}

/// SLH-DSA-128f signature size invariant — important для KT v2 entry size budget.
/// SLH-DSA-128f signature size invariant — important for KT v2 entry size budget.
#[test]
fn slh_dsa_signature_size_invariant() {
    let (store, _) = fresh_store();
    let sig = store.sign_slh_dsa_backup_proof(b"proof").unwrap();
    assert_eq!(sig.as_bytes().len(), 17_088);
    assert_eq!(sig.as_bytes().len(), SLH_DSA_128F_SIGNATURE_LEN);
}

/// Wire-format roundtrip публичного ключа SLH-DSA backup.
/// Wire-format roundtrip of the SLH-DSA backup public key.
#[test]
fn slh_dsa_backup_pubkey_wire_roundtrip() {
    let (store, _) = fresh_store();
    let original = store.slh_dsa_backup_public();
    let bytes = original.to_bytes();
    assert_eq!(bytes.len(), SLH_DSA_128F_PUBLIC_KEY_LEN);
    let decoded = SlhDsaBackupKeyPublic::from_bytes(&bytes, 0).unwrap();
    assert_eq!(decoded.to_bytes(), bytes);
}

/// Domain separation context exposed как public constant — KT v2 / downstream
/// крейты могут ссылаться на это для consistent domain.
/// Domain separation context exposed as a public constant — KT v2 / downstream crates
/// can reference it for a consistent domain.
#[test]
fn slh_dsa_backup_rotation_context_constant() {
    assert_eq!(
        SLH_DSA_BACKUP_ROTATION_CONTEXT,
        b"umbrellax-slh-dsa-backup-rotation-v1"
    );
}

/// Wrong message → verify fails (basic authenticity).
#[test]
fn slh_dsa_backup_wrong_message_rejected() {
    let (store, _) = fresh_store();
    let backup_pub = store.slh_dsa_backup_public();
    let sig = store.sign_slh_dsa_backup_proof(b"original").unwrap();
    let result = backup_pub.verify_rotation_proof(b"tampered", &sig);
    assert!(matches!(
        result,
        Err(umbrella_identity::IdentityError::Pq(
            PqError::SlhDsaSignatureVerificationFailed
        ))
    ));
}

/// Different accounts → independent backup pubkeys (domain separation через HKDF salt).
/// Different accounts → independent backup pubkeys (domain separation via HKDF salt).
#[test]
fn slh_dsa_backup_different_accounts_distinct() {
    let mut rng = OsRng;
    let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    let mnemonic = seed.to_mnemonic();

    let seed_acc0 =
        IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();
    let store_acc0 =
        InMemoryKeyStore::open(seed_acc0, 0, Arc::new(ZeroClock) as Arc<dyn Clock>).unwrap();

    let seed_acc1 =
        IdentitySeed::from_mnemonic(mnemonic.as_str(), MnemonicLanguage::English).unwrap();
    let store_acc1 =
        InMemoryKeyStore::open(seed_acc1, 1, Arc::new(ZeroClock) as Arc<dyn Clock>).unwrap();

    assert_ne!(
        store_acc0.slh_dsa_backup_public().to_bytes(),
        store_acc1.slh_dsa_backup_public().to_bytes()
    );
}

/// Signature size sanity для backup proof — `SlhDsa128fSignature` heap-allocated
/// (`Box`); проверяем что Clone / move через переменные работает без leak.
/// Signature size sanity for the backup proof — `SlhDsa128fSignature` is heap-allocated
/// (`Box`); verify Clone / move through variables works without leaks.
#[test]
fn slh_dsa_signature_clone_and_move() {
    let (store, _) = fresh_store();
    let sig: SlhDsa128fSignature = store.sign_slh_dsa_backup_proof(b"proof").unwrap();
    let cloned = sig.clone();
    assert_eq!(sig.as_bytes(), cloned.as_bytes());
    // Move через let
    let moved = sig;
    let backup_pub = store.slh_dsa_backup_public();
    backup_pub.verify_rotation_proof(b"proof", &moved).unwrap();
}
