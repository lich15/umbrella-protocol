//! Константы размеров ключей, подписей и ciphertexts для всех PQ примитивов.
//! Constants for key, signature, and ciphertext sizes for all PQ primitives.
//!
//! Размеры зафиксированы NIST FIPS 203/204/205 + draft-connolly-cfrg-xwing-kem-10.
//! Любое изменение upstream draft требует ADR-поправки.
//!
//! Sizes are fixed by NIST FIPS 203/204/205 + draft-connolly-cfrg-xwing-kem-10.
//! Any upstream draft change requires an ADR amendment.

// ——— ML-KEM-768 (NIST FIPS 203) ———
/// Размер public key ML-KEM-768 в байтах.
/// ML-KEM-768 public key length in bytes.
pub const ML_KEM_768_PUBLIC_KEY_LEN: usize = 1184;
/// Размер secret key ML-KEM-768 в байтах.
/// ML-KEM-768 secret key length in bytes.
pub const ML_KEM_768_SECRET_KEY_LEN: usize = 2400;
/// Размер ciphertext ML-KEM-768 в байтах.
/// ML-KEM-768 ciphertext length in bytes.
pub const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
/// Размер shared secret ML-KEM-768 в байтах.
/// ML-KEM-768 shared secret length in bytes.
pub const ML_KEM_768_SHARED_SECRET_LEN: usize = 32;
/// Размер seed для keygen ML-KEM-768 (FIPS 203 §7.1, два 32-byte компонента).
/// Seed length for ML-KEM-768 keygen (FIPS 203 §7.1, two 32-byte components).
pub const ML_KEM_768_KEYGEN_SEED_LEN: usize = 64;
/// Размер seed для encaps ML-KEM-768 (FIPS 203 §7.2).
/// Seed length for ML-KEM-768 encaps (FIPS 203 §7.2).
pub const ML_KEM_768_ENCAPS_SEED_LEN: usize = 32;

// ——— X-Wing (draft-connolly-cfrg-xwing-kem-10) ———
// Combiner = ML-KEM-768 + X25519
/// Размер public key X-Wing в байтах (ML-KEM-768 pk 1184 || X25519 pk 32).
/// X-Wing public key length in bytes (ML-KEM-768 pk 1184 || X25519 pk 32).
pub const XWING_PUBLIC_KEY_LEN: usize = 1216;
/// Размер secret seed X-Wing в байтах (expand internally).
/// X-Wing secret seed length in bytes (expanded internally).
pub const XWING_SECRET_SEED_LEN: usize = 32;
/// Размер ciphertext X-Wing в байтах (ML-KEM-768 ct 1088 || X25519 ct 32).
/// X-Wing ciphertext length in bytes (ML-KEM-768 ct 1088 || X25519 ct 32).
pub const XWING_CIPHERTEXT_LEN: usize = 1120;
/// Размер shared secret X-Wing в байтах (combined через draft-10 KDF).
/// X-Wing shared secret length in bytes (combined via draft-10 KDF).
pub const XWING_SHARED_SECRET_LEN: usize = 32;
/// Размер seed для keygen X-Wing (FIPS 203-style, expand для обоих компонентов).
/// Seed length for X-Wing keygen (FIPS 203-style, expanded for both components).
pub const XWING_KEYGEN_SEED_LEN: usize = 32;
/// Размер seed для encaps X-Wing (32 для ML-KEM || 32 для X25519 ephemeral).
/// Seed length for X-Wing encaps (32 for ML-KEM || 32 for X25519 ephemeral).
pub const XWING_ENCAPS_SEED_LEN: usize = 64;

// ——— ML-DSA-65 (NIST FIPS 204) ———
/// Размер public key (verification key) ML-DSA-65 в байтах.
/// ML-DSA-65 public (verification) key length in bytes.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
/// Размер secret key (signing key) ML-DSA-65 в байтах.
/// ML-DSA-65 secret (signing) key length in bytes.
pub const ML_DSA_65_SECRET_KEY_LEN: usize = 4032;
/// Размер signature ML-DSA-65 в байтах (по FIPS 204 — 3309).
/// ML-DSA-65 signature length in bytes (FIPS 204 — 3309).
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
/// Размер randomness для keygen ML-DSA-65.
/// Randomness length for ML-DSA-65 keygen.
pub const ML_DSA_65_KEYGEN_RANDOMNESS_LEN: usize = 32;
/// Размер randomness для signing ML-DSA-65 (hedged mode).
/// Randomness length for ML-DSA-65 signing (hedged mode).
pub const ML_DSA_65_SIGNING_RANDOMNESS_LEN: usize = 32;

// ——— SLH-DSA-SHA2-128f-simple (NIST FIPS 205) ———
/// Размер public key SLH-DSA-128f в байтах.
/// SLH-DSA-128f public key length in bytes.
pub const SLH_DSA_128F_PUBLIC_KEY_LEN: usize = 32;
/// Размер secret key SLH-DSA-128f в байтах.
/// SLH-DSA-128f secret key length in bytes.
pub const SLH_DSA_128F_SECRET_KEY_LEN: usize = 64;
/// Размер signature SLH-DSA-128f в байтах (FIPS 205 §10.4).
/// SLH-DSA-128f signature length in bytes (FIPS 205 §10.4).
pub const SLH_DSA_128F_SIGNATURE_LEN: usize = 17_088;

// ——— Hybrid signature (Ed25519 + ML-DSA-65) ———
/// Размер Ed25519 signature в байтах.
/// Ed25519 signature length in bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// Размер hybrid signature: Ed25519 (64) || ML-DSA-65 (3309) = 3373 bytes.
/// Hybrid signature length: Ed25519 (64) || ML-DSA-65 (3309) = 3373 bytes.
pub const HYBRID_SIGNATURE_LEN: usize = ED25519_SIGNATURE_LEN + ML_DSA_65_SIGNATURE_LEN;
/// Domain separation context для hybrid sign/verify.
/// Domain separation context for hybrid sign/verify.
pub const HYBRID_CONTEXT: &[u8] = b"umbrellax-hybrid-sig-v1";

#[cfg(test)]
mod tests {
    use super::*;

    /// Проверка что hybrid sig length = Ed25519 (64) + ML-DSA-65 (3309) = 3373.
    /// Verify hybrid sig length = Ed25519 (64) + ML-DSA-65 (3309) = 3373.
    #[test]
    fn hybrid_signature_len_matches_components() {
        assert_eq!(HYBRID_SIGNATURE_LEN, 64 + 3309);
        assert_eq!(HYBRID_SIGNATURE_LEN, 3373);
    }

    /// X-Wing pubkey = ML-KEM-768 pk + X25519 pk = 1184 + 32 = 1216.
    /// X-Wing pubkey = ML-KEM-768 pk + X25519 pk = 1184 + 32 = 1216.
    #[test]
    fn xwing_public_key_len_matches_components() {
        assert_eq!(XWING_PUBLIC_KEY_LEN, ML_KEM_768_PUBLIC_KEY_LEN + 32);
    }

    /// X-Wing ct = ML-KEM-768 ct + X25519 pk = 1088 + 32 = 1120.
    /// X-Wing ct = ML-KEM-768 ct + X25519 pk = 1088 + 32 = 1120.
    #[test]
    fn xwing_ciphertext_len_matches_components() {
        assert_eq!(XWING_CIPHERTEXT_LEN, ML_KEM_768_CIPHERTEXT_LEN + 32);
    }
}
