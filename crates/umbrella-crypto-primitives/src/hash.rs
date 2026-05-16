//! SHA-256 и SHA-512 обёртки с domain-separated transcript hashing.
//! SHA-256 and SHA-512 wrappers with domain-separated transcript hashing.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256, Sha512};

/// Размер выхода SHA-256 в байтах.
/// SHA-256 output size in bytes.
pub const SHA256_LEN: usize = 32;

/// Размер выхода SHA-512 в байтах.
/// SHA-512 output size in bytes.
pub const SHA512_LEN: usize = 64;

/// Один шот SHA-256 над всеми input chunks; никакого состояния не сохраняется.
/// One-shot SHA-256 over all input chunks; no state retained.
pub fn sha256(chunks: &[&[u8]]) -> [u8; SHA256_LEN] {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    let out = hasher.finalize();
    let mut bytes = [0u8; SHA256_LEN];
    bytes.copy_from_slice(&out);
    bytes
}

/// Один шот SHA-512 над всеми input chunks.
/// One-shot SHA-512 over all input chunks.
pub fn sha512(chunks: &[&[u8]]) -> [u8; SHA512_LEN] {
    let mut hasher = Sha512::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    let out = hasher.finalize();
    let mut bytes = [0u8; SHA512_LEN];
    bytes.copy_from_slice(&out);
    bytes
}

/// SHA-256 с domain-separation label: `hash("umbrellax-<purpose>-v1" || 0x00 || data...)`.
///
/// Контракт: `label` ОБЯЗАН быть ASCII-строкой без байта `0x00` — наша конвенция
/// `umbrellax-<purpose>-vN` гарантирует это. Нарушение allows структурную коллизию
/// `(label="ab", data="c\x00xyz")` ↔ `(label="ab\x00c", data="xyz")` через одинаковую
/// concatenation `"ab\x00c\x00xyz"`. `debug_assert!` ловит нарушения в debug-сборках;
/// release полагается на статичную природу `&'static [u8]` labels (compile-time controlled).
///
/// SHA-256 with a domain-separation label: `hash("umbrellax-<purpose>-v1" || 0x00 || data...)`.
///
/// Contract: `label` MUST be an ASCII string without a `0x00` byte — our convention
/// `umbrellax-<purpose>-vN` ensures this. Violation enables a structural collision
/// `(label="ab", data="c\x00xyz")` ↔ `(label="ab\x00c", data="xyz")` via identical
/// concatenation `"ab\x00c\x00xyz"`. `debug_assert!` catches violations in debug
/// builds; release relies on the static nature of `&'static [u8]` labels.
pub fn sha256_with_label(label: &'static [u8], chunks: &[&[u8]]) -> [u8; SHA256_LEN] {
    debug_assert!(
        !label.contains(&0x00),
        "domain-separation label must not contain 0x00 byte"
    );
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update([0x00]); // separator
    for chunk in chunks {
        hasher.update(chunk);
    }
    let out = hasher.finalize();
    let mut bytes = [0u8; SHA256_LEN];
    bytes.copy_from_slice(&out);
    bytes
}

/// SHA-512 с domain-separation label; контракт идентичен `sha256_with_label`.
/// SHA-512 with a domain-separation label; contract identical to `sha256_with_label`.
pub fn sha512_with_label(label: &'static [u8], chunks: &[&[u8]]) -> [u8; SHA512_LEN] {
    debug_assert!(
        !label.contains(&0x00),
        "domain-separation label must not contain 0x00 byte"
    );
    let mut hasher = Sha512::new();
    hasher.update(label);
    hasher.update([0x00]);
    for chunk in chunks {
        hasher.update(chunk);
    }
    let out = hasher.finalize();
    let mut bytes = [0u8; SHA512_LEN];
    bytes.copy_from_slice(&out);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty() {
        // RFC 6234: SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let h = sha256(&[]);
        assert_eq!(
            hex_string(&h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        // RFC 6234: SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let h = sha256(&[b"abc"]);
        assert_eq!(
            hex_string(&h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha512_abc() {
        // RFC 6234: SHA-512("abc") = ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
        let h = sha512(&[b"abc"]);
        assert_eq!(
            hex_string(&h),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn sha256_chunks_concat_equivalent() {
        let single = sha256(&[b"hello world"]);
        let chunked = sha256(&[b"hello", b" ", b"world"]);
        assert_eq!(single, chunked);
    }

    #[test]
    fn label_changes_output() {
        let a = sha256_with_label(b"label-a", &[b"data"]);
        let b = sha256_with_label(b"label-b", &[b"data"]);
        assert_ne!(a, b);
    }

    fn hex_string(bytes: &[u8]) -> String {
        use core::fmt::Write;
        let mut s = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(s, "{byte:02x}").expect("writing to String never fails");
        }
        s
    }
}
