//! Merkle tree RFC 6962-style: domain-separated leaf (0x00) и inner (0x01) хеши, SHA-256.
//! Merkle tree RFC 6962-style: domain-separated leaf (0x00) and inner (0x01) hashes, SHA-256.
//!
//! ## Определения (RFC 6962 §2.1)
//!
//! ```text
//! MTH({})     = SHA-256(empty)
//! MTH({d})    = SHA-256(0x00 || d)
//! MTH(D[n])   = SHA-256(0x01 || MTH(D[0..k]) || MTH(D[k..n]))  где k = largest power of 2 < n
//! ```
//!
//! Domain separators (0x00 для leaf, 0x01 для inner) критичны: без них атакующий мог бы
//! переинтерпретировать inner-hash как leaf (second pre-image attack).
//!
//! ## Definitions (RFC 6962 §2.1)
//!
//! See above. Domain separators (0x00 for leaf, 0x01 for inner) are critical: without them
//! an attacker could reinterpret an inner hash as a leaf (second-preimage attack).

use sha2::{Digest, Sha256};

use crate::error::{KtError, Result};

/// Размер хеша узла (SHA-256 output).
/// Tree node hash size (SHA-256 output).
pub const NODE_HASH_LEN: usize = 32;

/// Префикс leaf hash (RFC 6962).
/// Leaf hash prefix (RFC 6962).
pub const LEAF_PREFIX: u8 = 0x00;

/// Префикс inner hash (RFC 6962).
/// Inner hash prefix (RFC 6962).
pub const INNER_PREFIX: u8 = 0x01;

/// Хеш leaf-узла: `SHA-256(0x00 || data)`.
/// Leaf node hash: `SHA-256(0x00 || data)`.
pub fn leaf_hash(data: &[u8]) -> [u8; NODE_HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; NODE_HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Хеш inner-узла: `SHA-256(0x01 || left || right)`.
/// Inner node hash: `SHA-256(0x01 || left || right)`.
pub fn inner_hash(left: &[u8; NODE_HASH_LEN], right: &[u8; NODE_HASH_LEN]) -> [u8; NODE_HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update([INNER_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    let digest = hasher.finalize();
    let mut out = [0u8; NODE_HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Хеш пустого дерева: `SHA-256(empty)` (RFC 6962 §2.1).
/// Empty tree hash: `SHA-256(empty)` (RFC 6962 §2.1).
pub fn empty_root() -> [u8; NODE_HASH_LEN] {
    let digest = Sha256::digest([]);
    let mut out = [0u8; NODE_HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Вычисляет Merkle Tree Hash (MTH) для последовательности листьев.
/// Computes the Merkle Tree Hash (MTH) for a sequence of leaves.
///
/// `leaves` — уже посчитанные leaf-хеши (не raw данные). Пустой вход → `empty_root()`.
///
/// `leaves` — pre-computed leaf hashes (not raw data). Empty input → `empty_root()`.
pub fn merkle_root(leaves: &[[u8; NODE_HASH_LEN]]) -> [u8; NODE_HASH_LEN] {
    match leaves {
        [] => empty_root(),
        [single] => *single,
        _ => {
            let k = largest_power_of_two_below(leaves.len());
            let left = merkle_root(&leaves[..k]);
            let right = merkle_root(&leaves[k..]);
            inner_hash(&left, &right)
        }
    }
}

/// Возвращает наибольшую степень двойки строго меньшую `n`.
/// Returns the largest power of two strictly less than `n`.
///
/// Инвариант `n >= 2` гарантирован единственным caller'ом
/// `merkle_root` через match-arm перед вызовом (case `[]` →
/// `empty_root()`, `[single]` → `*single`, `_ →` хвост вызывает
/// `largest_power_of_two_below(leaves.len())` с `leaves.len() >= 2`).
/// Поэтому `debug_assert!()` сохраняет проверку контракта в dev/test
/// сборках и no-op в `--release` per ADR-015 §Решение 5 криterio 5
/// «zero panics в lib code» (block 11.8).
/// The `n >= 2` invariant is guaranteed by the sole caller `merkle_root`
/// via the match-arm before invocation (case `[]` → `empty_root()`,
/// `[single]` → `*single`, `_ →` the tail calls
/// `largest_power_of_two_below(leaves.len())` with `leaves.len() >= 2`).
/// Hence `debug_assert!()` retains the contract check in dev/test
/// builds and is a no-op in `--release` per ADR-015 §Decision 5
/// criterion 5 "zero panics in lib code" (block 11.8).
pub(crate) fn largest_power_of_two_below(n: usize) -> usize {
    debug_assert!(n >= 2, "largest_power_of_two_below requires n >= 2");
    let highest_bit = usize::BITS - 1 - (n - 1).leading_zeros();
    1usize << highest_bit
}

/// Audit-path: sibling-хеши снизу вверх для конкретного leaf-index.
/// Audit path: sibling hashes from bottom to top for a specific leaf index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditPath {
    /// Последовательность sibling-хешей от листа к корню.
    /// Sequence of sibling hashes from leaf to root.
    pub siblings: Vec<[u8; NODE_HASH_LEN]>,
}

/// Строит audit-path для `leaf_index` в дереве `leaves`.
/// Builds the audit path for `leaf_index` in the `leaves` tree.
///
/// Возвращает ошибку если `leaf_index >= leaves.len()` или дерево пустое.
/// Returns an error if `leaf_index >= leaves.len()` or the tree is empty.
pub fn build_audit_path(leaves: &[[u8; NODE_HASH_LEN]], leaf_index: usize) -> Result<AuditPath> {
    let n = leaves.len();
    if n == 0 {
        return Err(KtError::EmptyTree);
    }
    if leaf_index >= n {
        return Err(KtError::LeafIndexOutOfRange {
            index: leaf_index as u64,
            tree_size: n as u64,
        });
    }

    let mut siblings = Vec::new();
    build_path_recursive(leaves, leaf_index, &mut siblings);
    Ok(AuditPath { siblings })
}

fn build_path_recursive(
    leaves: &[[u8; NODE_HASH_LEN]],
    index: usize,
    path: &mut Vec<[u8; NODE_HASH_LEN]>,
) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = largest_power_of_two_below(n);
    if index < k {
        build_path_recursive(&leaves[..k], index, path);
        path.push(merkle_root(&leaves[k..]));
    } else {
        build_path_recursive(&leaves[k..], index - k, path);
        path.push(merkle_root(&leaves[..k]));
    }
}

/// Проверяет audit-path: reconstruct root из leaf_hash + siblings, сравнивает с expected.
/// Verifies the audit path: reconstruct the root from leaf_hash + siblings, compare to expected.
///
/// Алгоритм RFC 6962 §2.1.1, адаптирован для произвольного размера дерева.
/// RFC 6962 §2.1.1 algorithm, adapted for arbitrary tree size.
pub fn verify_inclusion(
    leaf_hash: &[u8; NODE_HASH_LEN],
    leaf_index: u64,
    tree_size: u64,
    path: &AuditPath,
    expected_root: &[u8; NODE_HASH_LEN],
) -> Result<()> {
    if tree_size == 0 {
        return Err(KtError::EmptyTree);
    }
    if leaf_index >= tree_size {
        return Err(KtError::LeafIndexOutOfRange {
            index: leaf_index,
            tree_size,
        });
    }

    let expected_path_len = audit_path_length(leaf_index, tree_size);
    if path.siblings.len() != expected_path_len {
        return Err(KtError::InvalidProofLength {
            tree_size,
            index: leaf_index,
            expected: expected_path_len,
            got: path.siblings.len(),
        });
    }

    let mut fn_ = leaf_index;
    let mut sn = tree_size - 1;
    let mut r = *leaf_hash;
    for p in &path.siblings {
        if fn_ & 1 == 1 || fn_ == sn {
            // node is a right-child or last node at this level.
            r = inner_hash(p, &r);
            if fn_ & 1 == 0 {
                // Skip consecutive right shifts for last-node case.
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            // node is a left-child.
            r = inner_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    if sn != 0 {
        return Err(KtError::InvalidProofLength {
            tree_size,
            index: leaf_index,
            expected: expected_path_len,
            got: path.siblings.len(),
        });
    }
    if &r != expected_root {
        return Err(KtError::InclusionRootMismatch);
    }
    Ok(())
}

/// Ожидаемая длина audit-path для `leaf_index` в дереве размером `tree_size`.
/// Expected audit path length for `leaf_index` in a tree of `tree_size`.
pub fn audit_path_length(leaf_index: u64, tree_size: u64) -> usize {
    let mut fn_ = leaf_index;
    let mut sn = tree_size.saturating_sub(1);
    let mut len = 0;
    while sn > 0 {
        if fn_ & 1 == 1 || fn_ != sn {
            len += 1;
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(data: u8) -> [u8; NODE_HASH_LEN] {
        leaf_hash(&[data])
    }

    // === Базовые свойства hash ===

    #[test]
    fn empty_root_is_sha256_of_empty() {
        // SHA-256("") = e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855
        let h = empty_root();
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(h, expected);
    }

    #[test]
    fn leaf_hash_prefixes_with_zero_byte() {
        let data = b"hello";
        let h = leaf_hash(data);
        // Эталон: SHA-256(0x00 || "hello")
        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(data);
        let expected = hasher.finalize();
        assert_eq!(&h, expected.as_slice());
    }

    #[test]
    fn inner_hash_prefixes_with_one_byte() {
        let l = leaf(1);
        let r = leaf(2);
        let h = inner_hash(&l, &r);
        let mut hasher = Sha256::new();
        hasher.update([0x01]);
        hasher.update(l);
        hasher.update(r);
        let expected = hasher.finalize();
        assert_eq!(&h, expected.as_slice());
    }

    #[test]
    fn leaf_and_inner_hashes_differ_for_same_input() {
        // Domain separator важен: H(0x00 || x) != H(0x01 || x || y) для любых x, y.
        let l = leaf(42);
        let fake_inner = inner_hash(&leaf(0), &leaf(0));
        assert_ne!(l, fake_inner);
    }

    // === largest_power_of_two_below ===

    #[test]
    fn largest_power_of_two_below_samples() {
        assert_eq!(largest_power_of_two_below(2), 1);
        assert_eq!(largest_power_of_two_below(3), 2);
        assert_eq!(largest_power_of_two_below(4), 2);
        assert_eq!(largest_power_of_two_below(5), 4);
        assert_eq!(largest_power_of_two_below(8), 4);
        assert_eq!(largest_power_of_two_below(9), 8);
        assert_eq!(largest_power_of_two_below(1000), 512);
    }

    // === merkle_root ===

    #[test]
    fn root_empty() {
        assert_eq!(merkle_root(&[]), empty_root());
    }

    #[test]
    fn root_single_leaf_is_the_leaf() {
        let l = leaf(7);
        assert_eq!(merkle_root(&[l]), l);
    }

    #[test]
    fn root_two_leaves_is_inner_of_both() {
        let a = leaf(1);
        let b = leaf(2);
        let root = merkle_root(&[a, b]);
        assert_eq!(root, inner_hash(&a, &b));
    }

    #[test]
    fn root_three_leaves_splits_two_plus_one() {
        // RFC 6962: для n=3, k=2. MTH(D[0:2]) = inner(l0, l1), MTH(D[2:3]) = l2.
        // root = inner(inner(l0, l1), l2).
        let a = leaf(0);
        let b = leaf(1);
        let c = leaf(2);
        let root = merkle_root(&[a, b, c]);
        let expected = inner_hash(&inner_hash(&a, &b), &c);
        assert_eq!(root, expected);
    }

    #[test]
    fn root_four_leaves_balanced() {
        // n=4, k=2: inner(inner(l0,l1), inner(l2,l3)).
        let a = leaf(0);
        let b = leaf(1);
        let c = leaf(2);
        let d = leaf(3);
        let root = merkle_root(&[a, b, c, d]);
        let expected = inner_hash(&inner_hash(&a, &b), &inner_hash(&c, &d));
        assert_eq!(root, expected);
    }

    #[test]
    fn root_seven_leaves_unbalanced() {
        // n=7, k=4: inner(MTH(D[0:4]), MTH(D[4:7])).
        // MTH(D[0:4]) = inner(inner(l0,l1), inner(l2,l3)).
        // MTH(D[4:7]) = inner(inner(l4,l5), l6) (k=2 for n=3 in right branch).
        let leaves: Vec<_> = (0u8..7).map(leaf).collect();
        let root = merkle_root(&leaves);
        let left = inner_hash(
            &inner_hash(&leaves[0], &leaves[1]),
            &inner_hash(&leaves[2], &leaves[3]),
        );
        let right = inner_hash(&inner_hash(&leaves[4], &leaves[5]), &leaves[6]);
        let expected = inner_hash(&left, &right);
        assert_eq!(root, expected);
    }

    // === Inclusion proof build + verify ===

    #[test]
    fn inclusion_proof_round_trip_two_leaves() {
        let a = leaf(0);
        let b = leaf(1);
        let leaves = [a, b];
        let root = merkle_root(&leaves);
        for idx in 0..2 {
            let path = build_audit_path(&leaves, idx).unwrap();
            assert_eq!(path.siblings.len(), 1);
            verify_inclusion(&leaves[idx], idx as u64, 2, &path, &root).unwrap();
        }
    }

    #[test]
    fn inclusion_proof_round_trip_seven_leaves() {
        let leaves: Vec<_> = (0u8..7).map(leaf).collect();
        let root = merkle_root(&leaves);
        for idx in 0..leaves.len() {
            let path = build_audit_path(&leaves, idx).unwrap();
            verify_inclusion(&leaves[idx], idx as u64, leaves.len() as u64, &path, &root)
                .unwrap_or_else(|e| panic!("idx={idx}: {e:?}"));
        }
    }

    #[test]
    fn inclusion_proof_single_leaf_path_is_empty() {
        let l = leaf(9);
        let leaves = [l];
        let root = merkle_root(&leaves);
        let path = build_audit_path(&leaves, 0).unwrap();
        assert!(path.siblings.is_empty());
        verify_inclusion(&l, 0, 1, &path, &root).unwrap();
    }

    #[test]
    fn inclusion_proof_wrong_root_rejected() {
        let leaves = [leaf(0), leaf(1), leaf(2), leaf(3)];
        let path = build_audit_path(&leaves, 1).unwrap();
        let wrong_root = [0xAA; 32];
        let result = verify_inclusion(&leaves[1], 1, 4, &path, &wrong_root);
        assert_eq!(result.unwrap_err(), KtError::InclusionRootMismatch);
    }

    #[test]
    fn inclusion_proof_tampered_leaf_rejected() {
        let leaves = [leaf(0), leaf(1), leaf(2), leaf(3)];
        let root = merkle_root(&leaves);
        let path = build_audit_path(&leaves, 2).unwrap();
        let tampered = leaf(99);
        let result = verify_inclusion(&tampered, 2, 4, &path, &root);
        assert_eq!(result.unwrap_err(), KtError::InclusionRootMismatch);
    }

    #[test]
    fn inclusion_proof_tampered_sibling_rejected() {
        let leaves = [leaf(0), leaf(1), leaf(2), leaf(3)];
        let root = merkle_root(&leaves);
        let mut path = build_audit_path(&leaves, 0).unwrap();
        path.siblings[0][0] ^= 0x01;
        let result = verify_inclusion(&leaves[0], 0, 4, &path, &root);
        assert_eq!(result.unwrap_err(), KtError::InclusionRootMismatch);
    }

    #[test]
    fn inclusion_proof_wrong_path_length_rejected() {
        let leaves = [leaf(0), leaf(1), leaf(2), leaf(3)];
        let root = merkle_root(&leaves);
        let mut path = build_audit_path(&leaves, 0).unwrap();
        path.siblings.push([0u8; 32]);
        let result = verify_inclusion(&leaves[0], 0, 4, &path, &root);
        assert!(matches!(result, Err(KtError::InvalidProofLength { .. })));
    }

    #[test]
    fn inclusion_index_out_of_range_rejected() {
        let leaves = [leaf(0), leaf(1)];
        let result = build_audit_path(&leaves, 5);
        assert!(matches!(
            result,
            Err(KtError::LeafIndexOutOfRange {
                index: 5,
                tree_size: 2
            })
        ));
    }

    #[test]
    fn inclusion_empty_tree_rejected() {
        let root = empty_root();
        let result = verify_inclusion(&[0u8; 32], 0, 0, &AuditPath { siblings: vec![] }, &root);
        assert_eq!(result.unwrap_err(), KtError::EmptyTree);
    }

    // === Property-based ===

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(64))]

        #[test]
        fn prop_inclusion_proof_verifies(
            size in 1usize..64,
            idx_seed in 0usize..1000,
        ) {
            let leaves: Vec<_> = (0..size).map(|i| leaf(i as u8)).collect();
            let root = merkle_root(&leaves);
            let idx = idx_seed % size;
            let path = build_audit_path(&leaves, idx).unwrap();
            verify_inclusion(&leaves[idx], idx as u64, size as u64, &path, &root).unwrap();
        }

        #[test]
        fn prop_tamper_sibling_detected(
            size in 2usize..32,
            idx_seed in 0usize..1000,
            sib_seed in 0usize..100,
        ) {
            let leaves: Vec<_> = (0..size).map(|i| leaf(i as u8)).collect();
            let root = merkle_root(&leaves);
            let idx = idx_seed % size;
            let mut path = build_audit_path(&leaves, idx).unwrap();
            if !path.siblings.is_empty() {
                let pos = sib_seed % path.siblings.len();
                path.siblings[pos][0] ^= 0xFF;
                let result = verify_inclusion(&leaves[idx], idx as u64, size as u64, &path, &root);
                proptest::prop_assert!(result.is_err());
            }
        }
    }
}
