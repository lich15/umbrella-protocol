//! Multi-witness 3-of-5: 5 независимых witness-серверов подписывают epoch root,
//! клиент принимает эпоху только при threshold валидных подписях от разных witness'ов.
//! Multi-witness 3-of-5: 5 independent witness servers sign the epoch root; the client
//! accepts the epoch only on `threshold` valid signatures from distinct witnesses.
//!
//! ## Модель угрозы
//!
//! Self-monitoring (блок 3.3) защищает от подмены конкретной записи, но не от **split-view**
//! атаки: оператор KT-лога показывает Алисе одну версию root'а, а Бобу — другую. Каждый
//! видит свою запись в «своём» логе, оба довольны, но фактически это два разных лога и
//! атакующий может вставить ghost-устройство в версию Боба а у Алисы оставить честную версию.
//! Self-monitoring не замечает разницы потому что проверяет только свою запись.
//!
//! Решение: 5 независимых witness-серверов в разных юрисдикциях (Германия / США / Швейцария
//! / Сингапур / Бразилия — как пример) каждую эпоху скачивают root, подписывают его своим
//! Ed25519-ключом и публикуют подпись в собственный публичный канал (Twitter / X / RSS /
//! blog / IPFS). Клиент собирает подписи и принимает эпоху только если **≥ threshold
//! разных witness** подписали **один и тот же root** для **одной и той же epoch**. Захват
//! оператора логам не достаточен — нужно захватить threshold из 5 независимых организаций
//! в разных странах одновременно, что для threshold=3 означает скоординированное давление
//! на три независимые юрисдикции. Это резко поднимает стоимость атаки.
//!
//! ## Threat model
//!
//! Self-monitoring (block 3.3) defends against a tampered single record but not against a
//! **split-view** attack: the log operator shows Alice one root and Bob another. Each sees
//! their own record in "their" log and both are happy — but in reality these are two
//! different logs and the attacker can inject a ghost device into Bob's version while
//! leaving Alice's honest. Self-monitoring doesn't spot the difference because it only
//! checks a single record.
//!
//! Solution: 5 independent witness servers in distinct jurisdictions (e.g. Germany / US /
//! Switzerland / Singapore / Brazil) each epoch fetch the root, sign it with their Ed25519
//! key, and publish the signature in their own public channel (Twitter / X / RSS / blog /
//! IPFS). The client collects signatures and only accepts an epoch when **≥ threshold
//! distinct witnesses** signed the **same root** for the **same epoch**. Capturing the log
//! operator is insufficient — an attacker must co-opt `threshold` of 5 independent orgs in
//! different countries simultaneously, which for threshold=3 means coordinated pressure on
//! three independent jurisdictions at once. The cost of attack goes up sharply.

use sha2::{Digest, Sha256};

use umbrella_crypto_primitives::sig::{
    Ed25519Signature, PublicVerifyingKey, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};

use crate::error::{KtError, Result};
use crate::merkle::NODE_HASH_LEN;

/// Версия wire-format witness-подписи. Witness signature wire-format version.
pub const WITNESS_VERSION: u8 = 0x01;

/// Domain separator для witness-подписей. Domain separator for witness signatures.
pub const WITNESS_DOMAIN_SEP: &[u8] = b"umbrellax-kt-witness-v1";

/// Публичный Ed25519-ключ witness'а в наборе.
/// A witness's Ed25519 public key in the witness set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WitnessPublic([u8; PUBLIC_KEY_LEN]);

impl WitnessPublic {
    /// Создаёт WitnessPublic из 32 байт Ed25519 publicKey.
    /// Constructs a WitnessPublic from 32 bytes of Ed25519 publicKey.
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Возвращает байтовое представление.
    /// Returns the byte representation.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0
    }
}

/// Набор известных клиенту witness-серверов.
/// Witness set known to the client.
#[derive(Clone, Debug, Default)]
pub struct WitnessSet {
    witnesses: Vec<WitnessPublic>,
}

impl WitnessSet {
    /// Создаёт пустой набор. Creates an empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Добавляет witness. Добавление дубликата игнорируется.
    /// Adds a witness. Duplicate addition is ignored.
    pub fn add(&mut self, w: WitnessPublic) {
        if !self.witnesses.iter().any(|existing| existing == &w) {
            self.witnesses.push(w);
        }
    }

    /// Возвращает количество уникальных witness'ов в наборе.
    /// Returns the count of unique witnesses in the set.
    pub fn len(&self) -> usize {
        self.witnesses.len()
    }

    /// True если набор пустой. True if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.witnesses.is_empty()
    }

    /// Проверяет что данный witness находится в известном наборе.
    /// Checks whether the given witness is in the known set.
    pub fn contains(&self, w: &WitnessPublic) -> bool {
        self.witnesses.iter().any(|existing| existing == w)
    }

    /// Возвращает срез всех witness'ов.
    /// Returns a slice of all witnesses.
    pub fn as_slice(&self) -> &[WitnessPublic] {
        &self.witnesses
    }
}

/// Подпись witness'а над epoch root. Witness signature over an epoch root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WitnessSignature {
    /// Публичный ключ witness'а (не secret, публикуется в их канале).
    /// Witness public key (not secret, published on their channel).
    pub witness: WitnessPublic,
    /// Ed25519 подпись над canonical_sign_payload (80 bytes per SPEC-09 §5.3).
    /// Ed25519 signature over canonical_sign_payload (80 bytes per SPEC-09 §5.3).
    pub signature: [u8; SIGNATURE_LEN],
}

/// Эпоха + root + размер лога + временная отметка + подписи witness'ов.
///
/// SPEC-09 §5.2 normative shape (session #68d, F-PHD-S68-1 closure):
/// witness подписывает не только `{epoch, root}`, но и
/// `{log_size, timestamp_unix_millis}` для cross-binding защиты от
/// reuse-across-different-log-states атак.
///
/// Epoch + root + log size + timestamp + collected witness signatures.
///
/// Per SPEC-09 §5.2 normative shape (session #68d, F-PHD-S68-1 closure):
/// the witness signs not only `{epoch, root}` but also
/// `{log_size, timestamp_unix_millis}` to provide cross-binding protection
/// against reuse-across-different-log-states attacks.
#[derive(Clone, Debug)]
pub struct SignedEpochRoot {
    /// Номер эпохи. Epoch number.
    pub epoch: u64,
    /// Корень Merkle-дерева для этой эпохи. Merkle root for this epoch.
    pub root: [u8; NODE_HASH_LEN],
    /// Размер лога (количество leaves) на момент подписания. Witness
    /// implicitly attests «я видел ровно столько entries в эту эпоху».
    /// Log size (leaf count) at signing time. The witness implicitly
    /// attests "I have seen exactly this many entries in this epoch."
    pub log_size: u64,
    /// Время подписания, миллисекунды unix epoch. Защита от replay через
    /// distinct timestamps + freshness check на стороне клиента.
    /// Signing timestamp, unix epoch milliseconds. Provides replay
    /// protection via distinct timestamps and a client-side freshness check.
    pub timestamp_unix_millis: u64,
    /// Подписи witness'ов (может содержать дубли / unknown — клиент фильтрует).
    /// Witness signatures (may contain duplicates / unknown — client filters).
    pub signatures: Vec<WitnessSignature>,
}

/// Canonical payload для подписи witness'ом (SPEC-09 §5.3, 80 bytes):
/// `WITNESS_DOMAIN_SEP (23) || WITNESS_VERSION (1) || epoch_BE (8) || root (32) || log_size_BE (8) || timestamp_BE (8)`.
///
/// Canonical payload for a witness signature (SPEC-09 §5.3, 80 bytes):
/// `WITNESS_DOMAIN_SEP (23) || WITNESS_VERSION (1) || epoch_BE (8) || root (32) || log_size_BE (8) || timestamp_BE (8)`.
pub fn canonical_sign_payload(
    epoch: u64,
    root: &[u8; NODE_HASH_LEN],
    log_size: u64,
    timestamp_unix_millis: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(WITNESS_DOMAIN_SEP.len() + 1 + 8 + NODE_HASH_LEN + 8 + 8);
    out.extend_from_slice(WITNESS_DOMAIN_SEP);
    out.push(WITNESS_VERSION);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(root);
    out.extend_from_slice(&log_size.to_be_bytes());
    out.extend_from_slice(&timestamp_unix_millis.to_be_bytes());
    debug_assert_eq!(out.len(), 80);
    out
}

/// Проверяет что эпоха имеет ≥ `threshold` валидных подписей от **разных** witness'ов
/// из `witness_set`.
///
/// Алгоритм:
/// 1. Итерируемся по `signed.signatures`.
/// 2. Пропускаем подписи от witness'ов **не** из `witness_set` (unknown witness).
/// 3. Дедуплицируем по `witness`: каждый уникальный witness может зачесться только один раз.
/// 4. Проверяем Ed25519-подпись над `canonical_sign_payload(epoch, root, TEST_LOG_SIZE, TEST_TIMESTAMP_MS)`.
/// 5. Считаем количество уникальных валидных подписей; если `>= threshold` — Ok.
///
/// Verifies that the epoch has ≥ `threshold` valid signatures from **distinct** witnesses in
/// `witness_set`.
///
/// Algorithm:
/// 1. Iterate `signed.signatures`.
/// 2. Skip signatures from witnesses **not** in `witness_set` (unknown witness).
/// 3. Deduplicate by `witness`: each unique witness counts at most once.
/// 4. Verify the Ed25519 signature over `canonical_sign_payload(epoch, root, TEST_LOG_SIZE, TEST_TIMESTAMP_MS)`.
/// 5. Count unique valid signatures; if `>= threshold` → Ok.
pub fn verify_signed_epoch(
    signed: &SignedEpochRoot,
    witness_set: &WitnessSet,
    threshold: usize,
) -> Result<()> {
    if threshold == 0 {
        return Err(KtError::InsufficientValidSignatures {
            valid: 0,
            required: threshold,
        });
    }

    let payload = canonical_sign_payload(
        signed.epoch,
        &signed.root,
        signed.log_size,
        signed.timestamp_unix_millis,
    );

    // Используем простой linear-search dedup — witness'ов 5, подписей десятки в worst-case.
    // Для production с большим witness_set (100+) можно переключиться на HashSet.
    // Simple linear-search dedup — 5 witnesses, tens of signatures worst-case. For production
    // with a larger witness_set (100+) switch to HashSet.
    let mut counted: Vec<WitnessPublic> = Vec::with_capacity(witness_set.len());

    for sig in &signed.signatures {
        if !witness_set.contains(&sig.witness) {
            continue;
        }
        if counted.contains(&sig.witness) {
            continue;
        }

        let vk = match PublicVerifyingKey::from_bytes(&sig.witness.to_bytes()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ed_sig = Ed25519Signature::from_bytes(&sig.signature);
        if vk.verify(&payload, &ed_sig).is_ok() {
            counted.push(sig.witness);
        }
    }

    let valid = counted.len();
    if valid < threshold {
        return Err(KtError::InsufficientValidSignatures {
            valid,
            required: threshold,
        });
    }
    Ok(())
}

/// Детерминистический хеш canonical sign payload (для observability / audit-loggs).
/// Не используется в verify_signed_epoch, но удобен для serverside auditing.
///
/// Deterministic hash of the canonical sign payload (for observability / audit logs). Not
/// used by verify_signed_epoch but handy for serverside auditing.
pub fn sign_payload_digest(
    epoch: u64,
    root: &[u8; NODE_HASH_LEN],
    log_size: u64,
    timestamp_unix_millis: u64,
) -> [u8; 32] {
    let payload = canonical_sign_payload(epoch, root, log_size, timestamp_unix_millis);
    let digest = Sha256::digest(payload);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use umbrella_crypto_primitives::sig::PrivateSigningKey;

    struct TestWitness {
        sk: PrivateSigningKey,
        pk: WitnessPublic,
    }

    fn fresh_witness() -> TestWitness {
        let mut rng = OsRng;
        let sk = PrivateSigningKey::generate(&mut rng);
        let pk_bytes = sk.verifying_key().to_bytes();
        TestWitness {
            sk,
            pk: WitnessPublic::from_bytes(pk_bytes),
        }
    }

    /// Test constants для F-PHD-S68-1 SPEC-09 §5.3 alignment.
    /// Test constants for the F-PHD-S68-1 SPEC-09 §5.3 alignment.
    const TEST_LOG_SIZE: u64 = 1;
    const TEST_TIMESTAMP_MS: u64 = 1_700_000_000_000;

    fn sign_epoch(
        witness: &TestWitness,
        epoch: u64,
        root: &[u8; NODE_HASH_LEN],
    ) -> WitnessSignature {
        let payload = canonical_sign_payload(epoch, root, TEST_LOG_SIZE, TEST_TIMESTAMP_MS);
        let sig = witness.sk.sign(&payload);
        WitnessSignature {
            witness: witness.pk,
            signature: sig.to_bytes(),
        }
    }

    fn fresh_root() -> [u8; NODE_HASH_LEN] {
        let mut rng = OsRng;
        use rand_core::RngCore;
        let mut out = [0u8; NODE_HASH_LEN];
        rng.fill_bytes(&mut out);
        out
    }

    fn build_set(witnesses: &[&TestWitness]) -> WitnessSet {
        let mut set = WitnessSet::new();
        for w in witnesses {
            set.add(w.pk);
        }
        set
    }

    // === Basic threshold ===

    #[test]
    fn three_of_five_signatures_accepted() {
        let ws: Vec<TestWitness> = (0..5).map(|_| fresh_witness()).collect();
        let set = build_set(&ws.iter().collect::<Vec<_>>());
        let root = fresh_root();
        let epoch = 42;
        let sigs: Vec<_> = ws
            .iter()
            .take(3)
            .map(|w| sign_epoch(w, epoch, &root))
            .collect();
        let signed = SignedEpochRoot {
            epoch,
            root,
            log_size: TEST_LOG_SIZE,
            timestamp_unix_millis: TEST_TIMESTAMP_MS,
            signatures: sigs,
        };
        verify_signed_epoch(&signed, &set, 3).unwrap();
    }

    #[test]
    fn two_of_five_signatures_rejected() {
        let ws: Vec<TestWitness> = (0..5).map(|_| fresh_witness()).collect();
        let set = build_set(&ws.iter().collect::<Vec<_>>());
        let root = fresh_root();
        let epoch = 42;
        let sigs: Vec<_> = ws
            .iter()
            .take(2)
            .map(|w| sign_epoch(w, epoch, &root))
            .collect();
        let signed = SignedEpochRoot {
            epoch,
            root,
            log_size: TEST_LOG_SIZE,
            timestamp_unix_millis: TEST_TIMESTAMP_MS,
            signatures: sigs,
        };
        let result = verify_signed_epoch(&signed, &set, 3);
        assert!(matches!(
            result,
            Err(KtError::InsufficientValidSignatures {
                valid: 2,
                required: 3
            })
        ));
    }

    #[test]
    fn five_of_five_signatures_accepted() {
        let ws: Vec<TestWitness> = (0..5).map(|_| fresh_witness()).collect();
        let set = build_set(&ws.iter().collect::<Vec<_>>());
        let root = fresh_root();
        let epoch = 7;
        let sigs: Vec<_> = ws.iter().map(|w| sign_epoch(w, epoch, &root)).collect();
        let signed = SignedEpochRoot {
            epoch,
            root,
            log_size: TEST_LOG_SIZE,
            timestamp_unix_millis: TEST_TIMESTAMP_MS,
            signatures: sigs,
        };
        verify_signed_epoch(&signed, &set, 3).unwrap();
        verify_signed_epoch(&signed, &set, 5).unwrap();
    }

    // === Dedup ===

    #[test]
    fn duplicate_signature_from_same_witness_counts_once() {
        let ws: Vec<TestWitness> = (0..5).map(|_| fresh_witness()).collect();
        let set = build_set(&ws.iter().collect::<Vec<_>>());
        let root = fresh_root();
        let epoch = 1;
        let sig_a = sign_epoch(&ws[0], epoch, &root);
        let sig_b = sign_epoch(&ws[1], epoch, &root);
        // Три подписи, но только два уникальных witness'а.
        let signed = SignedEpochRoot {
            epoch,
            root,
            log_size: TEST_LOG_SIZE,
            timestamp_unix_millis: TEST_TIMESTAMP_MS,
            signatures: vec![sig_a, sig_b, sig_a],
        };
        let result = verify_signed_epoch(&signed, &set, 3);
        assert!(matches!(
            result,
            Err(KtError::InsufficientValidSignatures {
                valid: 2,
                required: 3
            })
        ));
        // Порог 2 — проходит (два уникальных witness'а).
        verify_signed_epoch(&signed, &set, 2).unwrap();
    }

    // === Unknown witnesses ===

    #[test]
    fn unknown_witness_ignored() {
        let ws: Vec<TestWitness> = (0..5).map(|_| fresh_witness()).collect();
        let set = build_set(&ws.iter().collect::<Vec<_>>());
        let unknown = fresh_witness();
        let root = fresh_root();
        let epoch = 1;
        // 2 известных + 1 неизвестный witness.
        let mut sigs = vec![
            sign_epoch(&ws[0], epoch, &root),
            sign_epoch(&ws[1], epoch, &root),
        ];
        sigs.push(sign_epoch(&unknown, epoch, &root));
        let signed = SignedEpochRoot {
            epoch,
            root,
            log_size: TEST_LOG_SIZE,
            timestamp_unix_millis: TEST_TIMESTAMP_MS,
            signatures: sigs,
        };
        let result = verify_signed_epoch(&signed, &set, 3);
        assert!(matches!(
            result,
            Err(KtError::InsufficientValidSignatures {
                valid: 2,
                required: 3
            })
        ));
        verify_signed_epoch(&signed, &set, 2).unwrap();
    }

    // === Tampering ===

    #[test]
    fn tampered_root_all_signatures_invalid() {
        let ws: Vec<TestWitness> = (0..5).map(|_| fresh_witness()).collect();
        let set = build_set(&ws.iter().collect::<Vec<_>>());
        let root = fresh_root();
        let epoch = 5;
        let sigs: Vec<_> = ws
            .iter()
            .take(3)
            .map(|w| sign_epoch(w, epoch, &root))
            .collect();

        let mut tampered_root = root;
        tampered_root[0] ^= 0x01;
        let signed = SignedEpochRoot {
            epoch,
            root: tampered_root, // подписан старый root, проверка идёт с новым
            log_size: TEST_LOG_SIZE,
            timestamp_unix_millis: TEST_TIMESTAMP_MS,
            signatures: sigs,
        };
        let result = verify_signed_epoch(&signed, &set, 3);
        assert!(matches!(
            result,
            Err(KtError::InsufficientValidSignatures {
                valid: 0,
                required: 3
            })
        ));
    }

    #[test]
    fn tampered_epoch_all_signatures_invalid() {
        let ws: Vec<TestWitness> = (0..5).map(|_| fresh_witness()).collect();
        let set = build_set(&ws.iter().collect::<Vec<_>>());
        let root = fresh_root();
        let epoch = 10;
        let sigs: Vec<_> = ws
            .iter()
            .take(3)
            .map(|w| sign_epoch(w, epoch, &root))
            .collect();

        let signed = SignedEpochRoot {
            epoch: 11, // подпись над epoch=10, но объявлено 11
            root,
            log_size: TEST_LOG_SIZE,
            timestamp_unix_millis: TEST_TIMESTAMP_MS,
            signatures: sigs,
        };
        let result = verify_signed_epoch(&signed, &set, 3);
        assert!(matches!(
            result,
            Err(KtError::InsufficientValidSignatures {
                valid: 0,
                required: 3
            })
        ));
    }

    #[test]
    fn tampered_signature_bit_flip_invalid() {
        let ws: Vec<TestWitness> = (0..5).map(|_| fresh_witness()).collect();
        let set = build_set(&ws.iter().collect::<Vec<_>>());
        let root = fresh_root();
        let epoch = 1;
        let mut sigs: Vec<_> = ws
            .iter()
            .take(3)
            .map(|w| sign_epoch(w, epoch, &root))
            .collect();
        sigs[0].signature[0] ^= 0x01;
        let signed = SignedEpochRoot {
            epoch,
            root,
            log_size: TEST_LOG_SIZE,
            timestamp_unix_millis: TEST_TIMESTAMP_MS,
            signatures: sigs,
        };
        let result = verify_signed_epoch(&signed, &set, 3);
        // Два валидных из трёх — threshold 3 не достигнут.
        assert!(matches!(
            result,
            Err(KtError::InsufficientValidSignatures {
                valid: 2,
                required: 3
            })
        ));
    }

    // === Edge cases ===

    #[test]
    fn empty_witness_set_fails() {
        let empty_set = WitnessSet::new();
        let root = fresh_root();
        let signed = SignedEpochRoot {
            epoch: 1,
            root,
            log_size: TEST_LOG_SIZE,
            timestamp_unix_millis: TEST_TIMESTAMP_MS,
            signatures: vec![],
        };
        let result = verify_signed_epoch(&signed, &empty_set, 3);
        assert!(matches!(
            result,
            Err(KtError::InsufficientValidSignatures {
                valid: 0,
                required: 3
            })
        ));
    }

    #[test]
    fn threshold_zero_returns_error() {
        let ws = fresh_witness();
        let set = build_set(&[&ws]);
        let root = fresh_root();
        let signed = SignedEpochRoot {
            epoch: 0,
            root,
            log_size: TEST_LOG_SIZE,
            timestamp_unix_millis: TEST_TIMESTAMP_MS,
            signatures: vec![sign_epoch(&ws, 0, &root)],
        };
        let result = verify_signed_epoch(&signed, &set, 0);
        assert!(matches!(
            result,
            Err(KtError::InsufficientValidSignatures {
                valid: 0,
                required: 0
            })
        ));
    }

    #[test]
    fn threshold_above_set_size_unreachable() {
        let ws: Vec<TestWitness> = (0..3).map(|_| fresh_witness()).collect();
        let set = build_set(&ws.iter().collect::<Vec<_>>());
        let root = fresh_root();
        let epoch = 1;
        let sigs: Vec<_> = ws.iter().map(|w| sign_epoch(w, epoch, &root)).collect();
        let signed = SignedEpochRoot {
            epoch,
            root,
            log_size: TEST_LOG_SIZE,
            timestamp_unix_millis: TEST_TIMESTAMP_MS,
            signatures: sigs,
        };
        // Только 3 witness'а в set, но запросили порог 5 — невозможно.
        let result = verify_signed_epoch(&signed, &set, 5);
        assert!(matches!(
            result,
            Err(KtError::InsufficientValidSignatures {
                valid: 3,
                required: 5
            })
        ));
    }

    // === Set helpers ===

    #[test]
    fn set_add_deduplicates() {
        let ws = fresh_witness();
        let mut set = WitnessSet::new();
        set.add(ws.pk);
        set.add(ws.pk);
        set.add(ws.pk);
        assert_eq!(set.len(), 1);
        assert!(set.contains(&ws.pk));
    }

    #[test]
    fn set_empty_check() {
        let set = WitnessSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn canonical_payload_has_domain_sep_version_epoch_root() {
        let root = [0xAA; 32];
        let payload = canonical_sign_payload(42, &root, TEST_LOG_SIZE, TEST_TIMESTAMP_MS);
        assert!(payload.starts_with(WITNESS_DOMAIN_SEP));
        let idx = WITNESS_DOMAIN_SEP.len();
        assert_eq!(payload[idx], WITNESS_VERSION);
        assert_eq!(&payload[idx + 1..idx + 9], &42u64.to_be_bytes());
        assert_eq!(&payload[idx + 9..idx + 41], &root);
    }

    #[test]
    fn sign_payload_digest_changes_with_epoch() {
        let root = [0xBB; 32];
        let d1 = sign_payload_digest(1, &root, 1, 1_700_000_000_000);
        let d2 = sign_payload_digest(2, &root, 1, 1_700_000_000_000);
        assert_ne!(d1, d2);
    }

    #[test]
    fn sign_payload_digest_changes_with_root() {
        let d1 = sign_payload_digest(1, &[0xAA; 32], 1, 1_700_000_000_000);
        let d2 = sign_payload_digest(1, &[0xBB; 32], 1, 1_700_000_000_000);
        assert_ne!(d1, d2);
    }
}
