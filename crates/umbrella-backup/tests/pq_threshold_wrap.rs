//! Integration tests для V2 hybrid wrapping layer + 3-of-5 threshold reconstruction.
//! Integration tests for V2 hybrid wrapping layer + 3-of-5 threshold reconstruction.
//!
//! Этап 8 блок 8.7: end-to-end сценарий V2 backup recovery key:
//! 1. Sender (Alice): V1 wrap → V2 wrap → upload V2 envelope в облако.
//! 2. Recipient (Bob): download V2 envelope → V2 unwrap (X-Wing) → V1 inner →
//!    3-of-5 sealed servers cooperation → message_key.
//!
//! V1 layer полностью сохранён внутри V2 envelope; threshold 3-of-5
//! reconstruction работает unchanged. Server ceremony НЕ меняется.

#![cfg(feature = "pq")]

use rand_core::OsRng;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use umbrella_backup::cloud_wrap::aead::decompress_point;
use umbrella_backup::cloud_wrap::params::{
    ThresholdConfig, WitnessIndex, DEFAULT_TOTAL, MESSAGE_KEY_LEN, POINT_LEN, PROTOCOL_VERSION,
};
use umbrella_backup::cloud_wrap::pq_wrap::{
    unwrap_v2_to_v1, wrap_v1_into_v2, WrappedKeyV2, WRAPPED_KEY_V2_LEN,
};
use umbrella_backup::cloud_wrap::share::ServerUnwrapShare;
use umbrella_backup::cloud_wrap::threshold::shamir_split_for_testing;
use umbrella_backup::cloud_wrap::unwrap::{unwrap_message_key, unwrap_message_key_no_retry};
use umbrella_backup::cloud_wrap::version::WrappingCiphersuite;
use umbrella_backup::cloud_wrap::wire::{CanonicalAad, ED25519_PUB_LEN};
use umbrella_backup::cloud_wrap::wrap::wrap_message_key;
use umbrella_backup::cloud_wrap::WrappingParams;
use umbrella_pq::{xwing_keygen, HedgedWitness};

/// Тестовый `HedgedWitness` (zero-byte; sound только в тестах где RNG honest).
/// Test-only `HedgedWitness` (zero-byte; sound only when test RNG is honest).
fn test_hedged_witness() -> HedgedWitness {
    HedgedWitness::zeroed_for_tests_only()
}

/// Утилита: построить V1 params + Shamir split for testing.
fn make_v1_params_and_shares() -> (WrappingParams, Scalar, Vec<(WitnessIndex, Scalar)>) {
    let config = ThresholdConfig::default();
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let shares = shamir_split_for_testing(k, config, &mut rng);
    let y = RISTRETTO_BASEPOINT_POINT * k;
    let params = WrappingParams {
        version: PROTOCOL_VERSION,
        main_pubkey: y.compress().to_bytes(),
        server_pubkeys: [[0u8; POINT_LEN]; DEFAULT_TOTAL as usize],
        config,
    };
    let shares_vec: Vec<(WitnessIndex, Scalar)> = shares.iter().copied().collect();
    (params, k, shares_vec)
}

fn sample_aad() -> CanonicalAad {
    CanonicalAad {
        sender_identity_pubkey: [0xA1; ED25519_PUB_LEN],
        recipient_device_pubkey: [0xB2; ED25519_PUB_LEN],
        chat_id: [0xC3; 32],
        msg_seq: 7,
    }
}

/// Sealed server side: вычисляет partial unwrap share `partial_i = k_i · R`.
fn server_partial(
    wi: WitnessIndex,
    k_i: Scalar,
    v1_wrapped: &umbrella_backup::cloud_wrap::wire::WrappedKey,
) -> ServerUnwrapShare {
    let r = decompress_point(&v1_wrapped.ephemeral_r).unwrap();
    let partial = (k_i * r).compress().to_bytes();
    ServerUnwrapShare {
        witness_index: wi,
        partial,
    }
}

/// End-to-end: Alice wrap (V1+V2) → Bob unwrap V2 (X-Wing) → Bob unwrap V1
/// через 3-of-5 sealed servers → recovers message_key.
///
/// End-to-end: Alice wraps (V1+V2) → Bob unwraps V2 (X-Wing) → Bob unwraps V1
/// via 3-of-5 sealed servers → recovers message_key.
#[test]
fn v2_full_roundtrip_alice_to_bob_3_of_5() {
    let mut rng = OsRng;
    let (v1_params, _k, shares) = make_v1_params_and_shares();
    let mk = [0xFF; MESSAGE_KEY_LEN];
    let aad = sample_aad();

    // Bob's recovery X-Wing keypair (derived from Bob's BIP-39 mnemonic в production).
    let (bob_xwing_pk, bob_xwing_sk) = xwing_keygen(&mut rng).unwrap();

    // Alice: V1 wrap (under Y = K·G shared by protocol).
    let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();

    // Alice: V2 wrap (X-Wing envelope under Bob's recovery pubkey).
    let v2_wrapped = wrap_v1_into_v2(&bob_xwing_pk, &v1_wrapped, &aad, &test_hedged_witness(), &mut rng).unwrap();

    // ── Wire через облако (1218 bytes) ──
    let wire_bytes = v2_wrapped.to_bytes();
    assert_eq!(wire_bytes.len(), WRAPPED_KEY_V2_LEN);
    assert_eq!(wire_bytes[0], WrappingCiphersuite::V2HybridXWing.as_u8());

    // Bob: parse V2 wire.
    let v2_received = WrappedKeyV2::from_bytes(&wire_bytes).unwrap();

    // Bob: V2 unwrap (X-Wing decaps + AEAD decrypt) → inner V1 wrapped key.
    let v1_recovered = unwrap_v2_to_v1(&bob_xwing_sk, &bob_xwing_pk, &v2_received, &aad).unwrap();

    // V1 inner идентично original V1 wrap.
    assert_eq!(v1_recovered.to_bytes(), v1_wrapped.to_bytes());

    // Bob: 3 sealed server partials (любые 3 из 5).
    let partials: Vec<ServerUnwrapShare> = shares
        .iter()
        .take(3)
        .map(|(wi, ki)| server_partial(*wi, *ki, &v1_recovered))
        .collect();

    // Bob: V1 unwrap (Lagrange combine + AEAD decrypt) → message_key.
    let mk_recovered = unwrap_message_key(&v1_params, &v1_recovered, &aad, &partials).unwrap();
    assert_eq!(mk_recovered, mk);
}

/// Все 10 подмножеств 3-of-5 успешно decrypt после V2 unwrap.
/// All 10 subsets 3-of-5 successfully decrypt after V2 unwrap.
#[test]
fn v2_unwrap_then_all_ten_3_of_5_subsets_succeed() {
    let mut rng = OsRng;
    let (v1_params, _k, shares) = make_v1_params_and_shares();
    let mk = [0xCA; MESSAGE_KEY_LEN];
    let aad = sample_aad();

    let (bob_pk, bob_sk) = xwing_keygen(&mut rng).unwrap();
    let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
    let v2_wrapped = wrap_v1_into_v2(&bob_pk, &v1_wrapped, &aad, &test_hedged_witness(), &mut rng).unwrap();

    let v1_recovered = unwrap_v2_to_v1(&bob_sk, &bob_pk, &v2_wrapped, &aad).unwrap();

    let all_subsets: [[usize; 3]; 10] = [
        [0, 1, 2],
        [0, 1, 3],
        [0, 1, 4],
        [0, 2, 3],
        [0, 2, 4],
        [0, 3, 4],
        [1, 2, 3],
        [1, 2, 4],
        [1, 3, 4],
        [2, 3, 4],
    ];
    for combo in &all_subsets {
        let set: Vec<ServerUnwrapShare> = combo
            .iter()
            .map(|&idx| {
                let (wi, ki) = shares[idx];
                server_partial(wi, ki, &v1_recovered)
            })
            .collect();
        let mk_recovered =
            unwrap_message_key_no_retry(&v1_params, &v1_recovered, &aad, &set).unwrap();
        assert_eq!(mk_recovered, mk, "subset {combo:?} failed reconstruction");
    }
}

/// Below-threshold (< 3 partials) после V2 unwrap → InsufficientUnwrapShares.
/// Below-threshold (< 3 partials) after V2 unwrap → InsufficientUnwrapShares.
#[test]
fn v2_below_threshold_reject() {
    let mut rng = OsRng;
    let (v1_params, _k, shares) = make_v1_params_and_shares();
    let mk = [0u8; MESSAGE_KEY_LEN];
    let aad = sample_aad();

    let (pk, sk) = xwing_keygen(&mut rng).unwrap();
    let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
    let v2_wrapped = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &test_hedged_witness(), &mut rng).unwrap();
    let v1_recovered = unwrap_v2_to_v1(&sk, &pk, &v2_wrapped, &aad).unwrap();

    // 2 < threshold 3 → reject.
    let only_two: Vec<ServerUnwrapShare> = shares
        .iter()
        .take(2)
        .map(|(wi, ki)| server_partial(*wi, *ki, &v1_recovered))
        .collect();

    let result = unwrap_message_key(&v1_params, &v1_recovered, &aad, &only_two);
    assert!(result.is_err(), "below threshold must fail");
}

/// V2 layer rejection не должно leak'ать информации о V1 servers (даже X-Wing
/// fails мы возвращаем XWingDecapsFailed — V1 servers даже не контактируются).
///
/// V2 layer rejection should not leak any info about V1 servers (even on X-Wing
/// failure we return XWingDecapsFailed — V1 servers are not contacted).
#[test]
fn v2_xwing_failure_isolates_v1_layer() {
    let mut rng = OsRng;
    let (v1_params, _k, _shares) = make_v1_params_and_shares();
    let mk = [0u8; MESSAGE_KEY_LEN];
    let aad = sample_aad();

    let (pk, _correct_sk) = xwing_keygen(&mut rng).unwrap();
    let (_, eve_sk) = xwing_keygen(&mut rng).unwrap();
    let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
    let v2_wrapped = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &test_hedged_witness(), &mut rng).unwrap();

    // Eve пытается unwrap своим seed → X-Wing decaps возможно вернёт другой
    // shared, тогда AEAD decrypt fails (либо decaps fails первым).
    // Eve attempts unwrap with her seed → X-Wing decaps may return a different
    // shared, then AEAD decrypt fails (or decaps fails first).
    let result = unwrap_v2_to_v1(&eve_sk, &pk, &v2_wrapped, &aad);
    assert!(result.is_err(), "Eve must not unwrap V2 layer");
    // V1 servers (sealed servers in production) не были контактированы — V1 layer
    // не разворачивался, sealed servers не получили `R` для partial computation.
    // V1 servers (sealed servers in production) were never contacted — V1 layer
    // was not unwrapped, sealed servers did not receive `R` for partial compute.
}

/// Same V1 wrap → multiple V2 envelope wraps дают distinct wire (X-Wing encaps random).
/// Same V1 wrap → multiple V2 envelope wraps yield distinct wire.
#[test]
fn v2_multiple_wraps_distinct_wires() {
    let mut rng = OsRng;
    let (v1_params, _k, _shares) = make_v1_params_and_shares();
    let mk = [0xAB; MESSAGE_KEY_LEN];
    let aad = sample_aad();

    let (pk, _) = xwing_keygen(&mut rng).unwrap();
    let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();

    let w1 = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &test_hedged_witness(), &mut rng).unwrap();
    let w2 = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &test_hedged_witness(), &mut rng).unwrap();

    assert_ne!(
        w1.to_bytes(),
        w2.to_bytes(),
        "V2 wraps for same input must be distinct"
    );
}

/// V2 wire передан через простой byte channel (round-trip serialize/deserialize).
/// V2 wire transmitted through a simple byte channel (round-trip).
#[test]
fn v2_byte_channel_roundtrip_simulated() {
    let mut rng = OsRng;
    let (v1_params, _k, shares) = make_v1_params_and_shares();
    let mk = [0xEF; MESSAGE_KEY_LEN];
    let aad = sample_aad();

    let (bob_pk, bob_sk) = xwing_keygen(&mut rng).unwrap();
    let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
    let v2_wrapped = wrap_v1_into_v2(&bob_pk, &v1_wrapped, &aad, &test_hedged_witness(), &mut rng).unwrap();

    // Wire через some byte channel.
    let wire = v2_wrapped.to_bytes();
    let wire_vec: Vec<u8> = wire.to_vec();

    // Receive side.
    let v2_received = WrappedKeyV2::from_bytes(&wire_vec).unwrap();
    let v1_recovered = unwrap_v2_to_v1(&bob_sk, &bob_pk, &v2_received, &aad).unwrap();

    let partials: Vec<ServerUnwrapShare> = shares
        .iter()
        .take(3)
        .map(|(wi, ki)| server_partial(*wi, *ki, &v1_recovered))
        .collect();
    let recovered = unwrap_message_key(&v1_params, &v1_recovered, &aad, &partials).unwrap();
    assert_eq!(recovered, mk);
}

/// Wire format фиксирован: 1218 bytes для любого V2 envelope (constant size,
/// нет padding).
///
/// Wire format is fixed: 1218 bytes for any V2 envelope (constant size,
/// no padding).
#[test]
fn v2_wire_size_constant_independent_of_v1_state() {
    let mut rng = OsRng;
    let (v1_params, _k, _shares) = make_v1_params_and_shares();
    let aad = sample_aad();

    for mk_byte in [0x00u8, 0x42, 0xFF] {
        let mk = [mk_byte; MESSAGE_KEY_LEN];
        let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
        let (pk, _) = xwing_keygen(&mut rng).unwrap();
        let v2 = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &test_hedged_witness(), &mut rng).unwrap();
        assert_eq!(v2.to_bytes().len(), WRAPPED_KEY_V2_LEN);
        assert_eq!(WRAPPED_KEY_V2_LEN, 1218);
    }
}

/// Different V2 recipients (different X-Wing keypairs) для same V1 wrapped:
/// wrap должен work с любым recipient.
///
/// Different V2 recipients (different X-Wing keypairs) for same V1 wrapped:
/// wrap must work with any recipient.
#[test]
fn v2_works_with_distinct_recipients() {
    let mut rng = OsRng;
    let (v1_params, _k, shares) = make_v1_params_and_shares();
    let mk = [0x77; MESSAGE_KEY_LEN];
    let aad = sample_aad();

    let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();

    // 3 различных recipients.
    for _ in 0..3 {
        let (pk, sk) = xwing_keygen(&mut rng).unwrap();
        let v2 = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &test_hedged_witness(), &mut rng).unwrap();
        let v1_back = unwrap_v2_to_v1(&sk, &pk, &v2, &aad).unwrap();

        let partials: Vec<ServerUnwrapShare> = shares
            .iter()
            .take(3)
            .map(|(wi, ki)| server_partial(*wi, *ki, &v1_back))
            .collect();
        let recovered = unwrap_message_key(&v1_params, &v1_back, &aad, &partials).unwrap();
        assert_eq!(recovered, mk);
    }
}

/// 1-malicious server: V2 + V1 layers всё равно reconstruct'аются через retry
/// alternate subset (existing V1 retry behavior preserved).
///
/// 1 malicious server: V2 + V1 layers still reconstruct via retry of an
/// alternate subset (existing V1 retry behavior preserved).
#[test]
fn v2_then_v1_retry_alternate_subset_on_one_malicious() {
    let mut rng = OsRng;
    let (v1_params, _k, shares) = make_v1_params_and_shares();
    let mk = [0xBE; MESSAGE_KEY_LEN];
    let aad = sample_aad();

    let (pk, sk) = xwing_keygen(&mut rng).unwrap();
    let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
    let v2_wrapped = wrap_v1_into_v2(&pk, &v1_wrapped, &aad, &test_hedged_witness(), &mut rng).unwrap();
    let v1_recovered = unwrap_v2_to_v1(&sk, &pk, &v2_wrapped, &aad).unwrap();

    // 4 valid + 1 malicious (random k').
    let (wi0, k0) = shares[0];
    let (wi1, _k1) = shares[1];
    let (wi2, k2) = shares[2];
    let (wi3, k3) = shares[3];
    let (wi4, k4) = shares[4];
    let wrong_k = Scalar::random(&mut rng);

    let tampered = server_partial(wi1, wrong_k, &v1_recovered);
    let set: Vec<ServerUnwrapShare> = vec![
        server_partial(wi0, k0, &v1_recovered),
        tampered,
        server_partial(wi2, k2, &v1_recovered),
        server_partial(wi3, k3, &v1_recovered),
        server_partial(wi4, k4, &v1_recovered),
    ];

    let recovered = unwrap_message_key(&v1_params, &v1_recovered, &aad, &set).unwrap();
    assert_eq!(recovered, mk);
}

/// V2 layer запечатан под одного recipient → второй recipient не decrypt'ает,
/// даже если V1 layer известен (Y is public).
///
/// V2 layer sealed for one recipient → another recipient cannot decrypt,
/// even if the V1 layer is known (Y is public).
#[test]
fn v2_isolates_recipients_even_with_public_v1() {
    let mut rng = OsRng;
    let (v1_params, _k, _shares) = make_v1_params_and_shares();
    let mk = [0xAB; MESSAGE_KEY_LEN];
    let aad = sample_aad();

    let v1_wrapped = wrap_message_key(&v1_params, &mk, &aad, &mut rng).unwrap();
    // Bob — intended recipient.
    let (bob_pk, _bob_sk) = xwing_keygen(&mut rng).unwrap();
    // Eve — attacker который знает V1 params (public Y).
    let (_eve_pk, eve_sk) = xwing_keygen(&mut rng).unwrap();
    let v2_wrapped = wrap_v1_into_v2(&bob_pk, &v1_wrapped, &aad, &test_hedged_witness(), &mut rng).unwrap();

    let result = unwrap_v2_to_v1(&eve_sk, &bob_pk, &v2_wrapped, &aad);
    assert!(
        result.is_err(),
        "Eve cannot unwrap Bob's V2 even if she knows V1 public params"
    );
}
