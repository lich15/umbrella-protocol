//! SLIP-0010 BIP-32 derivation для Ed25519 (только hardened индексы).
//! SLIP-0010 BIP-32 derivation for Ed25519 (hardened-only indices).
//!
//! Ed25519 не поддерживает non-hardened derivation из-за scalar clamping mismatch:
//! публичный ключ нельзя пересчитать из родительского публичного ключа без приватного.
//! Поэтому SLIP-0010 для Ed25519 определяет только hardened path.
//!
//! Алгоритм (для каждого шага):
//! ```text
//! Master:  I = HMAC-SHA512("ed25519 seed", seed)
//!          k = I[0..32]   (extended secret)
//!          c = I[32..64]  (chain code)
//!
//! Child:   data = 0x00 || k_parent || ser32_BE(index)
//!          I = HMAC-SHA512(c_parent, data)
//!          k_child = I[0..32]
//!          c_child = I[32..64]
//! ```
//!
//! Source: <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>
//!
//! Ed25519 does not support non-hardened derivation due to scalar clamping mismatch:
//! the public key cannot be recomputed from a parent public key without the private.
//! Therefore SLIP-0010 for Ed25519 defines only hardened paths.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use umbrella_crypto_primitives::sig::PrivateSigningKey;

use crate::error::Result;
use crate::path::{DerivationPath, HardenedIndex, HARDENED_BIT};

/// Длина extended secret (входной seed для Ed25519 SigningKey) в байтах.
/// Length of the extended secret (input seed for Ed25519 SigningKey) in bytes.
pub const EXTENDED_SECRET_LEN: usize = 32;

/// Длина chain code в байтах.
/// Length of the chain code in bytes.
pub const CHAIN_CODE_LEN: usize = 32;

/// Domain separator для master key derivation (SLIP-0010 §1).
/// Domain separator for master key derivation (SLIP-0010 §1).
const MASTER_HMAC_KEY: &[u8] = b"ed25519 seed";

/// Extended secret: 32 байта seed для Ed25519 SigningKey; обнуляется при Drop.
/// Extended secret: 32-byte seed for Ed25519 SigningKey; zeroized on Drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ExtendedSecret([u8; EXTENDED_SECRET_LEN]);

impl ExtendedSecret {
    /// Возвращает байты для использования как Ed25519 seed.
    /// Returns the bytes for use as an Ed25519 seed.
    pub fn as_bytes(&self) -> &[u8; EXTENDED_SECRET_LEN] {
        &self.0
    }

    /// Создаёт Ed25519 SigningKey из этого extended secret.
    /// Constructs an Ed25519 SigningKey from this extended secret.
    pub fn to_signing_key(&self) -> PrivateSigningKey {
        PrivateSigningKey::from_seed(&self.0)
    }
}

impl core::fmt::Debug for ExtendedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ExtendedSecret(<redacted>)")
    }
}

/// Chain code: 32 байта вторичного материала, не секрет в традиционном смысле,
/// но обнуляется при Drop из консервативной осторожности.
/// Chain code: 32 bytes of secondary material, not a secret in the traditional sense,
/// but zeroized on Drop out of conservative caution.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChainCode([u8; CHAIN_CODE_LEN]);

impl ChainCode {
    /// Возвращает байтовое представление.
    /// Returns the byte representation.
    pub fn as_bytes(&self) -> &[u8; CHAIN_CODE_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for ChainCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ChainCode(<redacted>)")
    }
}

/// MasterKey (или extended key любого узла дерева): пара (secret, chain code).
/// Обнуляется при Drop. Никаких Clone — ручное `clone()` через метод.
/// MasterKey (or extended key of any tree node): pair of (secret, chain code).
/// Zeroized on Drop. No Clone — manual `clone()` via method.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    secret: ExtendedSecret,
    chain_code: ChainCode,
}

impl MasterKey {
    /// Конструирует master key из seed по SLIP-0010 алгоритму.
    /// Constructs the master key from a seed via the SLIP-0010 algorithm.
    ///
    /// Стандартный seed — 64 байта PBKDF2 BIP-39 (см. `IdentitySeed::seed()`),
    /// но алгоритм принимает любую ненулевую длину входа.
    /// The standard seed is the 64-byte PBKDF2 BIP-39 (see `IdentitySeed::seed()`),
    /// but the algorithm accepts any non-zero input length.
    pub fn from_seed(seed: &[u8]) -> Self {
        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: HMAC accepts any key length per RFC 2104"
        )]
        let mut mac =
            Hmac::<Sha512>::new_from_slice(MASTER_HMAC_KEY).expect("HMAC accepts any key");
        mac.update(seed);
        let mut i = mac.finalize().into_bytes();

        let mut secret = Zeroizing::new([0u8; EXTENDED_SECRET_LEN]);
        let mut chain_code = Zeroizing::new([0u8; CHAIN_CODE_LEN]);
        secret.copy_from_slice(&i[..EXTENDED_SECRET_LEN]);
        chain_code.copy_from_slice(&i[EXTENDED_SECRET_LEN..EXTENDED_SECRET_LEN + CHAIN_CODE_LEN]);
        i.zeroize();

        Self {
            secret: ExtendedSecret(*secret),
            chain_code: ChainCode(*chain_code),
        }
    }

    /// Derive дочернего hardened ключа по индексу (SLIP-0010 §1).
    /// Derives the hardened child key by index (SLIP-0010 §1).
    ///
    /// `data = 0x00 || k_parent || ser32_BE(index)`
    /// `I = HMAC-SHA512(c_parent, data)`
    pub fn derive_child(&self, index: HardenedIndex) -> Self {
        let raw_index = index.raw();
        // Sanity-check: hardened bit обязан быть установлен (HardenedIndex это гарантирует,
        // но проверяем как defense-in-depth).
        // Sanity-check: hardened bit must be set (HardenedIndex guarantees it,
        // but we check as defense-in-depth).
        debug_assert!(
            raw_index >= HARDENED_BIT,
            "HardenedIndex must always have hardened bit set"
        );

        #[allow(
            unknown_lints,
            no_unwrap_in_lib,
            reason = "infallible: HMAC accepts any key length per RFC 2104"
        )]
        let mut mac = Hmac::<Sha512>::new_from_slice(self.chain_code.as_bytes())
            .expect("HMAC accepts any key");
        mac.update(&[0x00]);
        mac.update(self.secret.as_bytes());
        mac.update(&raw_index.to_be_bytes());
        let mut i = mac.finalize().into_bytes();

        // Явное копирование 64 байт результата HMAC-SHA512 в фиксированный массив
        // защищает от неявных трюков с GenericArray и slicing.
        // Explicit copy of HMAC-SHA512's 64 result bytes into a fixed array
        // guards against subtle GenericArray slicing issues.
        let mut full = Zeroizing::new([0u8; 64]);
        full.copy_from_slice(i.as_slice());
        i.zeroize();

        let mut secret = Zeroizing::new([0u8; EXTENDED_SECRET_LEN]);
        let mut chain_code = Zeroizing::new([0u8; CHAIN_CODE_LEN]);
        secret.copy_from_slice(&full[..EXTENDED_SECRET_LEN]);
        chain_code
            .copy_from_slice(&full[EXTENDED_SECRET_LEN..EXTENDED_SECRET_LEN + CHAIN_CODE_LEN]);

        Self {
            secret: ExtendedSecret(*secret),
            chain_code: ChainCode(*chain_code),
        }
    }

    /// Derive по полному пути от текущего узла.
    /// Эквивалентно последовательному вызову `derive_child` для каждого индекса.
    /// Derives along the full path from the current node.
    /// Equivalent to sequentially calling `derive_child` for each index.
    pub fn derive_path(&self, path: &DerivationPath) -> Self {
        let mut current = self.clone_inner();
        for index in path.as_slice() {
            current = current.derive_child(*index);
        }
        current
    }

    /// Удобство: derive от seed напрямую по полному пути.
    /// Convenience: derive directly from a seed along the full path.
    pub fn derive_from_seed(seed: &[u8], path: &DerivationPath) -> Result<Self> {
        let master = Self::from_seed(seed);
        Ok(master.derive_path(path))
    }

    /// Возвращает ссылку на extended secret.
    /// Returns a reference to the extended secret.
    pub fn secret(&self) -> &ExtendedSecret {
        &self.secret
    }

    /// Возвращает ссылку на chain code.
    /// Returns a reference to the chain code.
    pub fn chain_code(&self) -> &ChainCode {
        &self.chain_code
    }

    /// Создаёт Ed25519 SigningKey из extended secret этого узла.
    /// Constructs an Ed25519 SigningKey from this node's extended secret.
    pub fn to_signing_key(&self) -> PrivateSigningKey {
        self.secret.to_signing_key()
    }

    /// Внутренний clone (SLIP-0010 derive должен принимать ownership корректно).
    /// Internal clone (SLIP-0010 derive must take ownership correctly).
    fn clone_inner(&self) -> Self {
        Self {
            secret: self.secret.clone(),
            chain_code: self.chain_code.clone(),
        }
    }
}

impl core::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MasterKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Хелпер для парсинга hex-строки в Vec<u8>; не используется в production.
    /// Helper to parse hex strings into Vec<u8>; not used in production.
    fn hex(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex(s);
        assert_eq!(v.len(), 32, "expected 32-byte hex");
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    // SLIP-0010 Test Vector 1 for Ed25519
    // Source: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-ed25519
    const TV1_SEED: &str = "000102030405060708090a0b0c0d0e0f";

    #[test]
    fn slip0010_tv1_master() {
        let seed = hex(TV1_SEED);
        let m = MasterKey::from_seed(&seed);
        let expected_chain =
            hex32("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb");
        let expected_secret =
            hex32("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7");
        assert_eq!(m.chain_code().as_bytes(), &expected_chain);
        assert_eq!(m.secret().as_bytes(), &expected_secret);

        // Public key из SLIP-0010 имеет prefix 0x00, поэтому реальный pub = bytes[1..33].
        // The SLIP-0010 public key has a 0x00 prefix, so the real pub = bytes[1..33].
        let pk = m.to_signing_key().verifying_key();
        let expected_pub_with_prefix =
            hex("00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed");
        assert_eq!(pk.to_bytes(), expected_pub_with_prefix[1..33]);
    }

    #[test]
    fn slip0010_tv1_chain_m_0h() {
        let seed = hex(TV1_SEED);
        let m = MasterKey::from_seed(&seed);
        let child = m.derive_child(HardenedIndex::from_human(0));
        let expected_chain =
            hex32("8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69");
        let expected_secret =
            hex32("68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3");
        assert_eq!(child.chain_code().as_bytes(), &expected_chain);
        assert_eq!(child.secret().as_bytes(), &expected_secret);

        let expected_pub =
            hex("008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c");
        let pk = child.to_signing_key().verifying_key();
        assert_eq!(pk.to_bytes(), expected_pub[1..33]);
    }

    #[test]
    fn slip0010_tv1_chain_m_0h_1h() {
        let seed = hex(TV1_SEED);
        let m = MasterKey::from_seed(&seed);
        let child = m
            .derive_child(HardenedIndex::from_human(0))
            .derive_child(HardenedIndex::from_human(1));
        let expected_chain =
            hex32("a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14");
        let expected_secret =
            hex32("b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2");
        assert_eq!(child.chain_code().as_bytes(), &expected_chain);
        assert_eq!(child.secret().as_bytes(), &expected_secret);

        let expected_pub =
            hex("001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187");
        assert_eq!(
            child.to_signing_key().verifying_key().to_bytes(),
            expected_pub[1..33]
        );
    }

    #[test]
    fn slip0010_tv1_chain_m_0h_1h_2h() {
        let seed = hex(TV1_SEED);
        let m = MasterKey::from_seed(&seed);
        let child = m
            .derive_child(HardenedIndex::from_human(0))
            .derive_child(HardenedIndex::from_human(1))
            .derive_child(HardenedIndex::from_human(2));
        let expected_chain =
            hex32("2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c");
        let expected_secret =
            hex32("92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9");
        assert_eq!(child.chain_code().as_bytes(), &expected_chain);
        assert_eq!(child.secret().as_bytes(), &expected_secret);
    }

    #[test]
    fn slip0010_tv1_chain_m_0h_1h_2h_2h() {
        let seed = hex(TV1_SEED);
        let m = MasterKey::from_seed(&seed);
        let child = m
            .derive_child(HardenedIndex::from_human(0))
            .derive_child(HardenedIndex::from_human(1))
            .derive_child(HardenedIndex::from_human(2))
            .derive_child(HardenedIndex::from_human(2));
        let expected_chain =
            hex32("8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc");
        let expected_secret =
            hex32("30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662");
        assert_eq!(child.chain_code().as_bytes(), &expected_chain);
        assert_eq!(child.secret().as_bytes(), &expected_secret);
    }

    #[test]
    fn slip0010_tv1_chain_m_0h_1h_2h_2h_1000000000h() {
        let seed = hex(TV1_SEED);
        let m = MasterKey::from_seed(&seed);
        let child = m
            .derive_child(HardenedIndex::from_human(0))
            .derive_child(HardenedIndex::from_human(1))
            .derive_child(HardenedIndex::from_human(2))
            .derive_child(HardenedIndex::from_human(2))
            .derive_child(HardenedIndex::from_human(1_000_000_000));
        let expected_chain =
            hex32("68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230");
        let expected_secret =
            hex32("8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793");
        assert_eq!(child.chain_code().as_bytes(), &expected_chain);
        assert_eq!(child.secret().as_bytes(), &expected_secret);
    }

    // SLIP-0010 Test Vector 2 for Ed25519
    // Source: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-2-for-ed25519
    const TV2_SEED: &str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2\
                            9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";

    #[test]
    fn slip0010_tv2_master() {
        let seed = hex(TV2_SEED);
        let m = MasterKey::from_seed(&seed);
        let expected_chain =
            hex32("ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b");
        let expected_secret =
            hex32("171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012");
        assert_eq!(m.chain_code().as_bytes(), &expected_chain);
        assert_eq!(m.secret().as_bytes(), &expected_secret);
    }

    #[test]
    fn slip0010_tv2_chain_m_0h() {
        let seed = hex(TV2_SEED);
        let m = MasterKey::from_seed(&seed);
        let child = m.derive_child(HardenedIndex::from_human(0));
        let expected_chain =
            hex32("0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d");
        let expected_secret =
            hex32("1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635");
        assert_eq!(child.chain_code().as_bytes(), &expected_chain);
        assert_eq!(child.secret().as_bytes(), &expected_secret);
    }

    #[test]
    fn slip0010_tv2_chain_m_0h_2147483647h() {
        let seed = hex(TV2_SEED);
        let m = MasterKey::from_seed(&seed);
        let child = m
            .derive_child(HardenedIndex::from_human(0))
            .derive_child(HardenedIndex::from_human(2_147_483_647));
        let expected_chain =
            hex32("138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f");
        let expected_secret =
            hex32("ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4");
        assert_eq!(child.chain_code().as_bytes(), &expected_chain);
        assert_eq!(child.secret().as_bytes(), &expected_secret);
    }

    // PhD-deep session #67 F-PHD-RETRO-4: SLIP-0010 TV2 depth-3 / depth-4 /
    // depth-5 vectors filling RFC coverage gap (previously только TV2 master +
    // depth-1 + depth-2 covered; missing половина RFC test vector set).
    // Source: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-2-for-ed25519
    //
    // PhD-deep session #67 F-PHD-RETRO-4: SLIP-0010 TV2 depth-3 / depth-4 /
    // depth-5 vectors filling RFC coverage gap (previously only TV2 master +
    // depth-1 + depth-2 were covered; the rest of the RFC test vector set was missing).
    #[test]
    fn slip0010_tv2_chain_m_0h_2147483647h_1h() {
        let seed = hex(TV2_SEED);
        let m = MasterKey::from_seed(&seed);
        let child = m
            .derive_child(HardenedIndex::from_human(0))
            .derive_child(HardenedIndex::from_human(2_147_483_647))
            .derive_child(HardenedIndex::from_human(1));
        let expected_chain =
            hex32("73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90");
        let expected_secret =
            hex32("3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c");
        assert_eq!(child.chain_code().as_bytes(), &expected_chain);
        assert_eq!(child.secret().as_bytes(), &expected_secret);
    }

    #[test]
    fn slip0010_tv2_chain_m_0h_2147483647h_1h_2147483646h() {
        let seed = hex(TV2_SEED);
        let m = MasterKey::from_seed(&seed);
        let child = m
            .derive_child(HardenedIndex::from_human(0))
            .derive_child(HardenedIndex::from_human(2_147_483_647))
            .derive_child(HardenedIndex::from_human(1))
            .derive_child(HardenedIndex::from_human(2_147_483_646));
        // SLIP-0010 reference values per official RFC table (verified WebFetch
        // session #67 PhD-deep retrieval): chain code `0902fe8a...`, private
        // key `5837736c...`. Source — https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-2-for-ed25519
        let expected_chain =
            hex32("0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a");
        let expected_secret =
            hex32("5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72");
        assert_eq!(child.chain_code().as_bytes(), &expected_chain);
        assert_eq!(child.secret().as_bytes(), &expected_secret);
    }

    #[test]
    fn slip0010_tv2_chain_m_0h_2147483647h_1h_2147483646h_2h() {
        let seed = hex(TV2_SEED);
        let m = MasterKey::from_seed(&seed);
        let child = m
            .derive_child(HardenedIndex::from_human(0))
            .derive_child(HardenedIndex::from_human(2_147_483_647))
            .derive_child(HardenedIndex::from_human(1))
            .derive_child(HardenedIndex::from_human(2_147_483_646))
            .derive_child(HardenedIndex::from_human(2));
        let expected_chain =
            hex32("5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4");
        let expected_secret =
            hex32("551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d");
        assert_eq!(child.chain_code().as_bytes(), &expected_chain);
        assert_eq!(child.secret().as_bytes(), &expected_secret);
    }

    // ─── Property-based & adversarial ───

    #[test]
    fn derive_path_equivalent_to_sequential_children() {
        let seed = hex(TV1_SEED);
        let m = MasterKey::from_seed(&seed);
        let path = DerivationPath::from_indices(&[
            HardenedIndex::from_human(0),
            HardenedIndex::from_human(1),
            HardenedIndex::from_human(2),
            HardenedIndex::from_human(2),
        ])
        .unwrap();
        let via_path = m.derive_path(&path);
        let via_sequential = m
            .derive_child(HardenedIndex::from_human(0))
            .derive_child(HardenedIndex::from_human(1))
            .derive_child(HardenedIndex::from_human(2))
            .derive_child(HardenedIndex::from_human(2));
        assert_eq!(
            via_path.secret().as_bytes(),
            via_sequential.secret().as_bytes()
        );
        assert_eq!(
            via_path.chain_code().as_bytes(),
            via_sequential.chain_code().as_bytes()
        );
    }

    #[test]
    fn empty_path_returns_master() {
        let seed = hex(TV1_SEED);
        let m = MasterKey::from_seed(&seed);
        let derived = m.derive_path(&DerivationPath::empty());
        assert_eq!(derived.secret().as_bytes(), m.secret().as_bytes());
        assert_eq!(derived.chain_code().as_bytes(), m.chain_code().as_bytes());
    }

    #[test]
    fn derive_is_deterministic() {
        let seed = hex(TV1_SEED);
        let path = DerivationPath::identity(0).unwrap();
        let a = MasterKey::derive_from_seed(&seed, &path).unwrap();
        let b = MasterKey::derive_from_seed(&seed, &path).unwrap();
        assert_eq!(a.secret().as_bytes(), b.secret().as_bytes());
    }

    #[test]
    fn different_seed_different_master() {
        let m1 = MasterKey::from_seed(b"seed-A");
        let m2 = MasterKey::from_seed(b"seed-B");
        assert_ne!(m1.secret().as_bytes(), m2.secret().as_bytes());
        assert_ne!(m1.chain_code().as_bytes(), m2.chain_code().as_bytes());
    }

    #[test]
    fn different_index_different_child() {
        let seed = hex(TV1_SEED);
        let m = MasterKey::from_seed(&seed);
        let c0 = m.derive_child(HardenedIndex::from_human(0));
        let c1 = m.derive_child(HardenedIndex::from_human(1));
        assert_ne!(c0.secret().as_bytes(), c1.secret().as_bytes());
    }

    #[test]
    fn debug_format_redacts() {
        let m = MasterKey::from_seed(&hex(TV1_SEED));
        let s = format!("{m:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("2b4be7f1"));
    }

    #[test]
    fn slip10_derivation_temporaries_are_zeroized() {
        let source = include_str!("derive.rs");
        let hmac_zeroize = ["i.", "zeroize()"].concat();
        let full_zeroizing = ["Zeroizing::new(", "[0u8; 64])"].concat();
        let secret_zeroizing = ["Zeroizing::new(", "[0u8; EXTENDED_SECRET_LEN])"].concat();
        let chain_code_zeroizing = ["Zeroizing::new(", "[0u8; CHAIN_CODE_LEN])"].concat();

        assert!(
            source.contains(&hmac_zeroize),
            "SLIP-0010 HMAC output must be zeroized after copying"
        );
        assert!(
            source.contains(&full_zeroizing),
            "SLIP-0010 fixed 64-byte copy must be zeroizing"
        );
        assert!(
            source.contains(&secret_zeroizing),
            "SLIP-0010 secret temporary must be zeroizing"
        );
        assert!(
            source.contains(&chain_code_zeroizing),
            "SLIP-0010 chain-code temporary must be zeroizing"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 200, .. ProptestConfig::default() })]

        #[test]
        fn prop_derive_deterministic(seed in proptest::collection::vec(any::<u8>(), 16..96), path_indices in proptest::collection::vec(0u32..(HARDENED_BIT - 1), 0..4)) {
            let path_idx: Vec<HardenedIndex> = path_indices.iter().copied().map(HardenedIndex::from_human).collect();
            let path = DerivationPath::from_indices(&path_idx).unwrap();
            let m1 = MasterKey::derive_from_seed(&seed, &path).unwrap();
            let m2 = MasterKey::derive_from_seed(&seed, &path).unwrap();
            prop_assert_eq!(m1.secret().as_bytes(), m2.secret().as_bytes());
        }

        #[test]
        fn prop_path_equiv_sequential(seed in proptest::collection::vec(any::<u8>(), 16..64), idx_a in 0u32..(HARDENED_BIT - 1), idx_b in 0u32..(HARDENED_BIT - 1)) {
            let m = MasterKey::from_seed(&seed);
            let via_path = m.derive_path(&DerivationPath::from_indices(&[
                HardenedIndex::from_human(idx_a),
                HardenedIndex::from_human(idx_b),
            ]).unwrap());
            let via_seq = m
                .derive_child(HardenedIndex::from_human(idx_a))
                .derive_child(HardenedIndex::from_human(idx_b));
            prop_assert_eq!(via_path.secret().as_bytes(), via_seq.secret().as_bytes());
        }

        #[test]
        fn prop_one_bit_seed_change_changes_master(seed_base in proptest::collection::vec(any::<u8>(), 32..=32), bit in 0usize..256) {
            let mut seed_a = seed_base.clone();
            let mut seed_b = seed_base;
            // Гарантируем что флипнули бит ровно в одном месте.
            // Ensure exactly one bit is flipped.
            seed_b[bit / 8] ^= 1 << (bit % 8);
            let m_a = MasterKey::from_seed(&seed_a);
            let m_b = MasterKey::from_seed(&seed_b);
            prop_assert_ne!(m_a.secret().as_bytes(), m_b.secret().as_bytes());
            seed_a.zeroize();
        }
    }
}
