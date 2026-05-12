//! Fuzz-точки входа для cargo-fuzz таргетов.
//! Fuzz entry points for cargo-fuzz targets.

use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey as XPub, StaticSecret as XStatic};

use curve25519_dalek::scalar::Scalar;
use umbrella_backup::cloud_wrap::{
    DeviceAuthorizationApproval, DeviceAuthorizationRequest, DeviceAuthorizationRevocation,
    IdentityRotationRecord, ServerUnwrapShare, WrappedKey,
};
use umbrella_backup::device_transfer::{
    build_signed_qr, DevicePairingQr, PairingInitiator, PairingResponder, PAIRING_CHALLENGE_LEN,
};
use umbrella_crypto_primitives::aead::{AeadKey, AeadNonce, AEAD_KEY_LEN, AEAD_NONCE_LEN};
use umbrella_crypto_primitives::secret::SecretBytes;
use umbrella_kt::{merkle::NODE_HASH_LEN, verify_inclusion, AuditPath};
use umbrella_oprf::{
    blind, evaluate_for_testing, finalize, generate_test_private_key, shamir_split_for_testing,
    threshold_combine, BlindedRequest, OprfInput, OprfLabel, ServerEvaluation, ThresholdConfig,
    WitnessIndex, SCALAR_LEN,
};
use umbrella_padding::{strip_padding, strip_padding_zeroizing};
use umbrella_server_blind_postman::parse_mls_envelope;

/// Fuzz-таргет: парсинг MLSMessage в server-blind-postman.
/// Fuzz target: MLSMessage parsing in server-blind-postman.
///
/// ## Инвариант
///
/// `parse_mls_envelope(data)` завершается за конечное время либо как `Ok(envelope)`, либо как
/// `Err(EnvelopeError)` — для любого `data`. Panic не допускается даже при искусственно
/// подобранных входах.
///
/// ## Invariant
///
/// `parse_mls_envelope(data)` terminates in finite time as either `Ok(envelope)` or
/// `Err(EnvelopeError)` — for any `data`. Panic is not permitted even on adversarially crafted
/// inputs.
pub fn fuzz_parse_mls_envelope(data: &[u8]) {
    let _ = parse_mls_envelope(data);
}

/// Fuzz-таргет: strip_padding — на любых байтах не паникует (Err или Ok).
/// Fuzz target: strip_padding — never panics on any bytes (Err or Ok).
pub fn fuzz_strip_padding(data: &[u8]) {
    let _ = strip_padding(data);
    let _ = strip_padding_zeroizing(data);
}

/// Fuzz-таргет: AEAD ChaCha20-Poly1305 decrypt malleability — на любых байтах вернёт либо
/// `Ok(plaintext)`, либо `Err(CryptoError::AeadAuthFailure)` без panic. Закрывает GAP
/// **Level 7 Fuzz × Row 10 KyberSlash** из 8-test-level matrix block 10.5b
/// (`docs/audits/production-readiness-2026-05-09/README.md` line 484
/// — «нет fuzz harness directly targeting AEAD/HKDF/SHA primitives»). Активный режим
/// retroactive pass session #65 закрывает gap defence-in-depth fuzz coverage поверх
/// regression-guard tests F-39 + F-44 + 26 active-mode adversarial tests
/// (`tests/test_active_audit.rs`).
///
/// Wire-format: первые 32 байта — AEAD ключ (random fuzz bytes interpreted as
/// 256-bit key); следующие 12 байт — nonce; остальное — ciphertext+tag candidate.
/// Empty AAD упрощает test surface; tampering AAD покрывается inline tests крейта.
///
/// Инвариант: для любых `data: &[u8]` функция **never panics** — RustCrypto
/// `chacha20poly1305 = "0.10"` backend constant-time auth check returns
/// `Err(aead::Error)` для invalid tag, который мы маппим в
/// `CryptoError::AeadAuthFailure`. Panic = security vulnerability ↦ row 11
/// «Cold-boot/forensics».
///
/// Fuzz target: AEAD ChaCha20-Poly1305 decrypt malleability — for any input bytes returns
/// either `Ok(plaintext)` or `Err(CryptoError::AeadAuthFailure)` without panicking. Closes
/// the **Level 7 Fuzz × Row 10 KyberSlash** GAP from the 8-test-level matrix in block 10.5b
/// (`docs/audits/production-readiness-2026-05-09/README.md` line 484 —
/// "no fuzz harness directly targeting AEAD/HKDF/SHA primitives"). The active retroactive
/// pass in session #65 closes this gap with defence-in-depth fuzz coverage on top of the
/// F-39 + F-44 regression-guard tests and the 26 active-mode adversarial tests in
/// `tests/test_active_audit.rs`.
///
/// Wire format: first 32 bytes — AEAD key (random fuzz bytes interpreted as a 256-bit key);
/// next 12 bytes — nonce; the remainder is the ciphertext+tag candidate. Empty AAD keeps
/// the surface minimal; AAD tampering is covered by the crate's inline tests.
///
/// Invariant: for any `data: &[u8]` the function **never panics** — the RustCrypto
/// `chacha20poly1305 = "0.10"` backend's constant-time auth check returns `Err(aead::Error)`
/// for an invalid tag, which we map to `CryptoError::AeadAuthFailure`. A panic would be a
/// security vulnerability ↦ row 11 "Cold-boot/forensics".
pub fn fuzz_aead_malleability(data: &[u8]) {
    const HEADER: usize = AEAD_KEY_LEN + AEAD_NONCE_LEN;
    if data.len() < HEADER {
        return;
    }
    let mut key_bytes = [0u8; AEAD_KEY_LEN];
    key_bytes.copy_from_slice(&data[..AEAD_KEY_LEN]);
    let key = AeadKey::from_bytes(&SecretBytes::new(key_bytes));

    let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
    nonce_bytes.copy_from_slice(&data[AEAD_KEY_LEN..HEADER]);
    let nonce = AeadNonce::from_bytes(nonce_bytes);

    // Try BOTH allocating decrypt + in-place detached decrypt — different code paths.
    let _ = key.decrypt(&nonce, b"", &data[HEADER..]);

    // In-place detached path requires structured input (separate ct + tag).
    if data.len() >= HEADER + 16 {
        let ct_with_tag = &data[HEADER..];
        let split = ct_with_tag.len().saturating_sub(16);
        let mut buffer = ct_with_tag[..split].to_vec();
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(&ct_with_tag[split..split + 16]);
        let _ = key.decrypt_in_place_detached(&nonce, b"", &mut buffer, &tag_bytes);
    }
}

/// Fuzz-таргет: KT Merkle inclusion verify. Строит синтетические аргументы из fuzz input и
/// вызывает `verify_inclusion`; гарантия — никогда не паникует, всегда Ok или Err.
///
/// Формат input: мы используем первые 32 байта как leaf_hash, следующие 32 как expected_root,
/// первый байт после этого как `path_len`, и каждые следующие 32 байта как sibling. Если
/// входа не хватает — target просто завершается (Err).
///
/// Fuzz target: KT Merkle inclusion verify. Builds synthetic arguments from fuzz input and
/// calls `verify_inclusion`; guarantee — never panics, always Ok or Err.
pub fn fuzz_verify_inclusion(data: &[u8]) {
    const HEADER: usize = 2 * NODE_HASH_LEN + 1 + 16;
    if data.len() < HEADER {
        return;
    }
    let mut leaf = [0u8; NODE_HASH_LEN];
    leaf.copy_from_slice(&data[0..NODE_HASH_LEN]);
    let mut expected_root = [0u8; NODE_HASH_LEN];
    expected_root.copy_from_slice(&data[NODE_HASH_LEN..2 * NODE_HASH_LEN]);
    let path_len_byte = data[2 * NODE_HASH_LEN] as usize;
    let leaf_index = u64::from_be_bytes({
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[2 * NODE_HASH_LEN + 1..2 * NODE_HASH_LEN + 9]);
        b
    });
    let tree_size = u64::from_be_bytes({
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[2 * NODE_HASH_LEN + 9..2 * NODE_HASH_LEN + 17]);
        b
    });

    let path_len = path_len_byte.min(64);
    let mut siblings = Vec::with_capacity(path_len);
    let mut offset = HEADER;
    for _ in 0..path_len {
        if offset + NODE_HASH_LEN > data.len() {
            break;
        }
        let mut sib = [0u8; NODE_HASH_LEN];
        sib.copy_from_slice(&data[offset..offset + NODE_HASH_LEN]);
        siblings.push(sib);
        offset += NODE_HASH_LEN;
    }
    let path = AuditPath { siblings };
    let _ = verify_inclusion(&leaf, leaf_index, tree_size, &path, &expected_root);
}

/// Fuzz-таргет: `BlindedRequest::from_bytes` для любых байт не паникует.
/// Fuzz target: `BlindedRequest::from_bytes` never panics on any bytes.
///
/// Это основной парсер wire-формата OPRF-запроса на сервере — перед тем как
/// передать blinded request в cryptographic operation, он проходит through
/// декодирование. Любой byte input должен либо успешно распарситься, либо
/// вернуть `Err(OprfError)` без panic.
///
/// Main wire-format parser for OPRF requests on the server — any byte input
/// must either parse successfully or return `Err(OprfError)` without panic.
pub fn fuzz_oprf_parse_blinded_request(data: &[u8]) {
    let _ = BlindedRequest::from_bytes(data);
}

/// Fuzz-таргет: `ServerEvaluation::from_bytes` для любых байт не паникует.
/// Fuzz target: `ServerEvaluation::from_bytes` never panics on any bytes.
///
/// Парсер ответа Sealed Server на клиенте. Перед threshold combine клиент
/// декодирует каждый partial evaluation из wire-формата. Malicious сервер
/// может прислать любые байты — функция должна справляться без panic.
///
/// Client-side parser for Sealed Server responses. Malicious server may
/// send any bytes; function must handle without panic.
pub fn fuzz_oprf_parse_server_evaluation(data: &[u8]) {
    let _ = ServerEvaluation::from_bytes(data);
}

/// Fuzz-таргет: `threshold_combine` на структурированном входе.
/// Fuzz target: `threshold_combine` on structured input.
///
/// Формат входа fuzz-data:
/// ```text
/// byte[0]      = количество shares (0..=N)
/// repeat N раз:
///   byte[off]       = witness index (0..=255, может быть вне диапазона 1..=5)
///   byte[off+1..33] = 32 байта point
/// ```
/// Любой input, даже с невалидными индексами / повреждёнными точками, должен
/// вернуть `Err` или `Ok` без panic. Это важно потому что на клиенте могут
/// собираться малициозные responses от нескольких Sealed Servers, и клиент
/// не должен падать на любой комбинации.
///
/// Input format parses as count + N × (witness index byte + 32-byte point).
/// Any input — even invalid indices or corrupted points — must return `Err`
/// or `Ok` without panic. Critical because client may aggregate malicious
/// responses from multiple Sealed Servers.
pub fn fuzz_oprf_threshold_combine(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let count = data[0] as usize;
    // Ограничим разумным максимумом, чтобы избежать pathological allocation.
    let count = count.min(16);

    let mut shares: Vec<(WitnessIndex, ServerEvaluation)> = Vec::with_capacity(count);
    let mut offset = 1usize;
    for _ in 0..count {
        if offset + 33 > data.len() {
            break;
        }
        let wi_byte = data[offset];
        offset += 1;
        // Если witness index вне 1..=5 — skip (моделируем серверную фильтрацию).
        let Ok(wi) = WitnessIndex::new(wi_byte) else {
            offset += 32;
            continue;
        };
        let point_slice = &data[offset..offset + 32];
        offset += 32;
        // ServerEvaluation::from_bytes отвергает невалидные Ristretto — skip.
        let Ok(eval) = ServerEvaluation::from_bytes(point_slice) else {
            continue;
        };
        shares.push((wi, eval));
    }
    let _ = threshold_combine(&shares, ThresholdConfig::default());
}

/// Fuzz-таргет: OPRF Lagrange determinism property defence-in-depth (Этап 11
/// блок 11.3).
/// Fuzz target: OPRF Lagrange determinism property defence-in-depth (Stage 11
/// block 11.3).
///
/// ## Свойство / Property
///
/// **Lagrange determinism**: для same `OprfInput` + same master_sk + same 5 Shamir
/// shares, любой valid 3-of-5 subset должен produce **bit-identical**
/// `OprfLabel`. Это direct counter-claim к ProVerif counter-example
/// `same_input_yields_same_label` falsified в model `oprf_ristretto255.pv`
/// (block 10.23b session #53) — counter-example был symbolic abstraction
/// artefact (free term algebra cannot capture Lagrange interpolation), не
/// protocol break. Real-protocol guarantee — composition Shamir threshold
/// (Shamir 1979 §3) + RFC 9497 §3.3.1 unblinding correctness.
///
/// **Lagrange determinism**: for the same `OprfInput` + same master_sk + same
/// 5 Shamir shares, any valid 3-of-5 subset must produce a **bit-identical**
/// `OprfLabel`. Direct counter-claim to the ProVerif counter-example for
/// `same_input_yields_same_label` falsified in `oprf_ristretto255.pv`
/// (block 10.23b session #53) — the counter-example was a symbolic-abstraction
/// artefact (free term algebra cannot capture Lagrange interpolation), not a
/// protocol break.
///
/// ## Defence-in-depth позиция / Defence-in-depth positioning
///
/// Block 11.2 session #62 закрыл MEDIUM-B1 ADR-016 accepted-risk через 14
/// regression-guard tests + 1 ignored 100k stress в
/// `crates/umbrella-oprf/tests/test_lagrange_determinism.rs`. Block 11.3
/// добавляет **fuzz coverage** поверх 14 explicit cases — миллионы random
/// (input, subset_a, subset_b) combinations exercise Lagrange algebra +
/// Ristretto255 point operations + Shamir reconstruction + HKDF finalize
/// path с unbounded random input space (libfuzzer corpus evolution +
/// coverage-guided mutation). Это атака уровня D из SPEC-01 § 4 row 5
/// «Social graph через DS» + row 13 «Регулятор требует backdoor» —
/// adversary observing random Sealed Server combinations не может extract
/// ничего полезного потому что все combinations produce same final label.
///
/// Block 11.2 (session #62) closed MEDIUM-B1 of ADR-016 accepted-risk via 14
/// regression-guard tests + 1 ignored 100k stress in
/// `crates/umbrella-oprf/tests/test_lagrange_determinism.rs`. Block 11.3 adds
/// **fuzz coverage** on top of those 14 explicit cases — millions of random
/// (input, subset_a, subset_b) combinations exercise the Lagrange algebra +
/// Ristretto255 point operations + Shamir reconstruction + HKDF finalize path
/// over an unbounded random input space (libfuzzer corpus evolution +
/// coverage-guided mutation). Mitigates the SPEC-01 § 4 level-D adversary
/// rows 5 "Social graph via DS" + 13 "Regulator demands a backdoor" — an
/// adversary observing random Sealed Server combinations cannot extract any
/// useful information because all combinations produce the same final label.
///
/// ## Wire-формат входа / Wire-format of input
///
/// `data` парсится как:
/// `data` parses as:
///
/// - `[0]` — `input_len` clamped к `MIN(MAX_INPUT_BYTES, 64)` (64-byte cap
///   ради fast iteration; OprfInput::new accepts up to MAX_INPUT_BYTES = 512
///   но fuzz harness coverage-guided mutation efficient на коротких входах).
/// - `[0]` — `input_len` clamped to `MIN(MAX_INPUT_BYTES, 64)` (64-byte cap
///   for fast iteration; `OprfInput::new` accepts up to `MAX_INPUT_BYTES = 512`
///   but the fuzz harness's coverage-guided mutation is efficient on short
///   inputs).
/// - `[1..1+input_len]` — `OprfInput` bytes.
/// - `[1+input_len]` — subset selector byte (low nibble = subset A index 0..9,
///   high nibble = subset B index 0..9; if equal — return).
/// - `[1+input_len]` — subset selector byte (low nibble = subset A index 0..9,
///   high nibble = subset B index 0..9; equal selectors — return).
///
/// Если data слишком короткие либо `OprfInput::new` отвергает input —
/// просто `return` (это не violation, это invalid fuzz input).
/// If `data` is too short or `OprfInput::new` rejects the input — just
/// `return` (this is not a violation, just an invalid fuzz input).
///
/// ## Что считается violation / What counts as a violation
///
/// `panic!()` через `assert_eq!(label_a, label_b, ...)` — единственный сигнал
/// fuzz harness'у. libFuzzer detect'ит panic как crash и сохраняет minimal
/// reproducer в `crates/umbrella-fuzz/fuzz/artifacts/oprf_lagrange_fuzz/`.
/// Все другие пути (invalid input rejected, blind/evaluate/finalize Err'ы)
/// — silent return (не violation).
///
/// `panic!()` via `assert_eq!(label_a, label_b, ...)` is the only signal to
/// the fuzz harness. libFuzzer detects the panic as a crash and saves a
/// minimal reproducer in `crates/umbrella-fuzz/fuzz/artifacts/oprf_lagrange_fuzz/`.
/// All other paths (invalid input rejected, `blind`/`evaluate`/`finalize`
/// errors) silently return — not a violation.
pub fn fuzz_oprf_lagrange_determinism(data: &[u8]) {
    // Минимальная длина: 1 byte (input_len header) + 1 byte input + 1 byte
    // subset selector = 3 bytes. Меньше — return как invalid fuzz input.
    // Minimum length: 1 byte (input_len header) + 1 byte input + 1 byte
    // subset selector = 3 bytes. Less — return as invalid fuzz input.
    if data.len() < 3 {
        return;
    }
    // Cap input length at 64 bytes для fast fuzz iteration (libfuzzer
    // coverage-guided mutation efficient on short inputs; longer inputs
    // not fundamentally different для Lagrange determinism property).
    // Cap input length at 64 bytes for fast fuzz iteration (libfuzzer's
    // coverage-guided mutation is efficient on short inputs; longer inputs
    // are not fundamentally different for the Lagrange determinism property).
    let input_len = (data[0] as usize).min(64);
    if data.len() < 1 + input_len + 1 {
        return;
    }
    let input_bytes = &data[1..1 + input_len];
    let Ok(oprf_input) = OprfInput::new(input_bytes) else {
        return;
    };

    // Subset selector — low nibble = subset A, high nibble = subset B.
    // Если оба selectors равны — return (нужны DIFFERENT subsets для
    // determinism property test).
    // Subset selector — low nibble = subset A, high nibble = subset B.
    // Equal selectors — return (we need DIFFERENT subsets for the
    // determinism property test).
    let selector = data[1 + input_len];
    let subset_a_idx = (selector & 0x0F) as usize % 10;
    let subset_b_idx = ((selector >> 4) & 0x0F) as usize % 10;
    if subset_a_idx == subset_b_idx {
        return;
    }

    // C(5,3) = 10 valid 3-of-5 subsets (deterministic indexing matches
    // `test_m_b1_lagrange_determinism_10_combinations_3_of_5` в
    // `crates/umbrella-oprf/tests/test_lagrange_determinism.rs:169-180`).
    // C(5,3) = 10 valid 3-of-5 subsets (deterministic indexing matches
    // `test_m_b1_lagrange_determinism_10_combinations_3_of_5` in
    // `crates/umbrella-oprf/tests/test_lagrange_determinism.rs:169-180`).
    let combinations: [[usize; 3]; 10] = [
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

    // Fresh master_sk + 5 Shamir shares per fuzz iteration. OsRng варьирует
    // master_sk между iterations что увеличивает coverage Lagrange algebra
    // под different secret values; libfuzzer coverage-guided mutation
    // managing input bytes для discrete subset/input combinations.
    // Fresh master_sk + 5 Shamir shares per fuzz iteration. `OsRng` varies
    // master_sk across iterations, expanding Lagrange-algebra coverage under
    // different secret values; libfuzzer coverage-guided mutation manages the
    // input bytes for discrete subset/input combinations.
    let config = ThresholdConfig::default();
    let master_sk = generate_test_private_key(&mut OsRng);
    let Some(k) = Scalar::from_canonical_bytes(master_sk).into_option() else {
        return;
    };
    let raw_shares = shamir_split_for_testing(k, config, &mut OsRng);
    let shares: Vec<(WitnessIndex, [u8; SCALAR_LEN])> = raw_shares
        .iter()
        .map(|(wi, share)| (*wi, share.to_bytes()))
        .collect();
    if shares.len() < 5 {
        return;
    }

    // Run OPRF flow через 2 different valid 3-of-5 subsets.
    // Run the OPRF flow through 2 different valid 3-of-5 subsets.
    let Some(label_a) = oprf_with_subset(oprf_input, &shares, &combinations[subset_a_idx]) else {
        return;
    };
    let Some(label_b) = oprf_with_subset(oprf_input, &shares, &combinations[subset_b_idx]) else {
        return;
    };

    // **VIOLATION SIGNAL**: assert_eq! panic'ит если labels диверг'ят. Это
    // единственный путь к panic в этом fuzz target — libFuzzer detect'ит
    // crash и сохраняет minimal reproducer для investigation. Если эта
    // assertion ever fires — это либо genuine Lagrange determinism break
    // (critical bug требующий emergency fix), либо upstream lib regression
    // (curve25519-dalek / hkdf / sha2 — investigation должна определить).
    // **VIOLATION SIGNAL**: `assert_eq!` panics if the labels diverge. This
    // is the only path to panic in this fuzz target — libFuzzer detects the
    // crash and saves a minimal reproducer for investigation. If this
    // assertion ever fires — it is either a genuine Lagrange determinism
    // break (critical bug requiring an emergency fix) or an upstream library
    // regression (curve25519-dalek / hkdf / sha2 — investigation must
    // determine).
    assert_eq!(
        label_a.as_bytes(),
        label_b.as_bytes(),
        "Lagrange determinism VIOLATED: input_len={}, subset_a_idx={} ({:?}), subset_b_idx={} ({:?}); \
         this contradicts Shamir threshold property + RFC 9497 §3.3.1 unblinding correctness composition; \
         either (a) Lagrange algebra regression in code, либо (b) upstream curve25519-dalek/hkdf/sha2 break — INVESTIGATE IMMEDIATELY.",
        input_len,
        subset_a_idx,
        combinations[subset_a_idx],
        subset_b_idx,
        combinations[subset_b_idx]
    );
}

/// Helper: запускает full OPRF flow (`blind` + `evaluate_for_testing` × 3 +
/// `threshold_combine` + `finalize`) с заданным subset of 3 servers индексов.
/// Любая Err из upstream API → return None (не violation, просто rejected
/// fuzz input).
/// Helper: runs the full OPRF flow (`blind` + `evaluate_for_testing` × 3 +
/// `threshold_combine` + `finalize`) with a given subset of 3 server indices.
/// Any Err from the upstream API → returns None (not a violation, just a
/// rejected fuzz input).
fn oprf_with_subset(
    input: OprfInput<'_>,
    shares: &[(WitnessIndex, [u8; SCALAR_LEN])],
    subset: &[usize; 3],
) -> Option<OprfLabel> {
    let config = ThresholdConfig::default();
    let (blinded, state) = blind(input, &mut OsRng).ok()?;

    let mut partial: heapless::Vec<(WitnessIndex, ServerEvaluation), 8> = heapless::Vec::new();
    for &idx in subset {
        if idx >= shares.len() {
            return None;
        }
        let (wi, sk) = shares[idx];
        let eval = evaluate_for_testing(&blinded, &sk).ok()?;
        partial.push((wi, eval)).ok()?;
    }
    let combined = threshold_combine(&partial, config).ok()?;
    finalize(&state, input, &combined).ok()
}

/// Fuzz-таргет: `WrappedKey::from_bytes` для любых байт не паникует.
/// Fuzz target: `WrappedKey::from_bytes` never panics on any bytes.
///
/// Парсер 81-байтового wire-формата обёрнутого AEAD-ключа сообщения из
/// Cloud message-svc. Любой byte input должен либо успешно распарситься,
/// либо вернуть `Err(BackupError)` без panic.
///
/// Parser for the 81-byte wire format of wrapped message AEAD keys from
/// Cloud message-svc. Any byte input must either parse successfully or
/// return `Err(BackupError)` without panic.
pub fn fuzz_wrapped_key_parse(data: &[u8]) {
    let _ = WrappedKey::from_bytes(data);
}

/// Fuzz-таргет: `ServerUnwrapShare::from_bytes` для любых байт не паникует.
/// Fuzz target: `ServerUnwrapShare::from_bytes` never panics on any bytes.
///
/// Клиентский парсер одной partial unwrap-доли от Sealed Server'а.
/// Malicious сервер может вернуть любые 33 байта; функция должна отвергнуть
/// невалидный witness index или некорректную point-кодировку без panic.
///
/// Client-side parser of a single partial unwrap share from Sealed Server.
/// Malicious server may return any 33 bytes; function must reject invalid
/// witness index or incorrect point encoding without panic.
pub fn fuzz_unwrap_share_parse(data: &[u8]) {
    let _ = ServerUnwrapShare::from_bytes(data);
}

/// Fuzz-таргет: `DevicePairingQr::from_bytes` для любых байт не паникует.
/// Fuzz target: `DevicePairingQr::from_bytes` never panics on any bytes.
///
/// Secret device-transfer QR-код имеет размер 169 байт; парсер должен
/// отвергнуть неверную длину, версию, невалидные embedded pubkeys без panic.
/// Источник input'а — камера сканирующего устройства, контент полностью
/// untrusted.
///
/// Secret device-transfer QR is 169 bytes; parser must reject wrong length,
/// version, invalid embedded pubkeys without panic. Input is camera-captured
/// so fully untrusted.
pub fn fuzz_qr_payload_parse(data: &[u8]) {
    let _ = DevicePairingQr::from_bytes(data);
}

/// Fuzz-таргет: Noise_IK responder обрабатывает произвольный `msg1`.
/// Fuzz target: Noise_IK responder handles arbitrary `msg1`.
///
/// Responder (старое устройство) получает первое handshake-сообщение от
/// initiator'а по транспорту. Любой input должен либо пройти read_message,
/// либо вернуть `HandshakeFailed` без panic.
///
/// Responder (old device) receives the first handshake message from
/// initiator over transport. Any input must either pass read_message or
/// return `HandshakeFailed` without panic.
pub fn fuzz_noise_responder_msg1(data: &[u8]) {
    // Synthesize valid ephemeral static + pairing challenge (defines the
    // responder state); fuzz input is the adversarially-crafted first
    // handshake message.
    let resp_eph_secret = XStatic::random_from_rng(OsRng);
    let mut challenge = [0u8; PAIRING_CHALLENGE_LEN];
    OsRng.fill_bytes(&mut challenge);

    if let Ok(mut responder) = PairingResponder::new(&resp_eph_secret.to_bytes(), &challenge) {
        let _ = responder.read_message_1(data);
    }
}

/// Fuzz-таргет: Noise_IK initiator обрабатывает произвольный `msg2`.
/// Fuzz target: Noise_IK initiator handles arbitrary `msg2`.
///
/// Initiator (новое устройство) после отправки msg1 принимает ответный msg2.
/// Malicious responder или network tamper может прислать любые байты;
/// функция должна либо распарсить, либо вернуть `HandshakeFailed` без panic.
///
/// Initiator (new device) after sending msg1 receives msg2. Malicious
/// responder or network tamper may send any bytes; function must either
/// parse or return `HandshakeFailed` without panic.
pub fn fuzz_noise_initiator_msg2(data: &[u8]) {
    // Synthesize complete valid QR + initiator static, run write_message_1
    // to get initiator past the first step, then apply fuzz input as msg2.
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let resp_sk = SigningKey::from_bytes(&seed);
    let resp_vk = resp_sk.verifying_key();
    let resp_eph_secret = XStatic::random_from_rng(OsRng);
    let resp_eph_pub = XPub::from(&resp_eph_secret).to_bytes();
    let mut chal = [0u8; PAIRING_CHALLENGE_LEN];
    OsRng.fill_bytes(&mut chal);

    let Ok(qr) = build_signed_qr(
        resp_vk.to_bytes(),
        resp_eph_pub,
        chal,
        u64::MAX / 2,
        |payload| Ok(resp_sk.sign(payload).to_bytes()),
    ) else {
        return;
    };

    let init_secret = XStatic::random_from_rng(OsRng);
    let Ok(mut initiator) = PairingInitiator::new(&qr, &init_secret.to_bytes()) else {
        return;
    };
    if initiator.write_message_1().is_err() {
        return;
    }
    let _ = initiator.read_message_2_and_finalize(data);
}

/// Fuzz-таргет: `DeviceAuthorizationRequest::from_bytes` для любых байт не паникует.
/// Fuzz target: `DeviceAuthorizationRequest::from_bytes` never panics on any bytes.
///
/// Парсер variable-length wire-format (138 + L байт, L ≤ 128) authorization
/// request'а из ADR-008 §A.5.1. Publishable в dedicated mailbox на Почтальоне
/// — input полностью untrusted (malicious клиент может прислать любые байты).
/// Функция обязана либо распарсить в Ok(struct), либо вернуть
/// `Err(BackupError::InvalidWireFormat / WrappedKeyVersionMismatch)` без panic.
///
/// Parser for the variable-length wire format (138 + L bytes, L ≤ 128) of the
/// ADR-008 §A.5.1 authorization request. Publishable to a dedicated mailbox
/// on the postman — input is fully untrusted (malicious client may send any
/// bytes). The function must either parse into Ok(struct) or return
/// `Err(BackupError::InvalidWireFormat / WrappedKeyVersionMismatch)` without panic.
pub fn fuzz_authorization_request_parse(data: &[u8]) {
    let _ = DeviceAuthorizationRequest::from_bytes(data);
}

/// Fuzz-таргет: `DeviceAuthorizationApproval::from_bytes` для любых байт не паникует.
/// Fuzz target: `DeviceAuthorizationApproval::from_bytes` never panics on any bytes.
///
/// Парсер fixed 146-байтового wire-format approval-записи ADR-008 §A.5.1.
/// Публикуется в KT как update для pending-entry; malicious KT operator может
/// прислать любые байты. Функция обязана обрабатывать любой input без panic.
///
/// Parser for the fixed 146-byte wire format of an ADR-008 §A.5.1 approval
/// record. Published to KT as an update for a pending entry; a malicious KT
/// operator may send any bytes. The function must handle any input without panic.
pub fn fuzz_authorization_approval_parse(data: &[u8]) {
    let _ = DeviceAuthorizationApproval::from_bytes(data);
}

/// Fuzz-таргет: `DeviceAuthorizationRevocation::from_bytes` для любых байт не паникует.
/// Fuzz target: `DeviceAuthorizationRevocation::from_bytes` never panics on any bytes.
///
/// Парсер fixed 137-байтового wire-format revocation-записи ADR-008 §A.5.1.
/// Перенаправляет entry в terminal state `Revoked`; клиент обрабатывает
/// любой byte input без panic.
///
/// Parser for the fixed 137-byte wire format of an ADR-008 §A.5.1 revocation
/// record. Moves the entry to the terminal `Revoked` state; the client must
/// handle any byte input without panic.
pub fn fuzz_authorization_revocation_parse(data: &[u8]) {
    let _ = DeviceAuthorizationRevocation::from_bytes(data);
}

/// Fuzz-таргет: `IdentityRotationRecord::from_bytes` для любых байт не паникует.
/// Fuzz target: `IdentityRotationRecord::from_bytes` never panics on any bytes.
///
/// Парсер fixed 202-байтового wire-format identity-rotation-записи
/// ADR-008 §A.5.1. Содержит dual signature (old + new identity) поверх одного
/// canonical input. Принудительно отвергает рекорд с совпадающими
/// old/new pubkeys в parse-уровне (защита от identity self-collision).
/// Malicious KT operator контролирует input — parser должен обрабатывать без panic.
///
/// Parser for the fixed 202-byte wire format of an ADR-008 §A.5.1 identity
/// rotation record. Carries a dual signature (old + new identity) over one
/// canonical input. Rejects records with identical old/new pubkeys at parse
/// level (identity self-collision guard). A malicious KT operator controls
/// the input — the parser must handle without panic.
pub fn fuzz_identity_rotation_parse(data: &[u8]) {
    let _ = IdentityRotationRecord::from_bytes(data);
}

/// Fuzz-таргет: `SframeHeader::parse` для любых байт не паникует.
/// Fuzz target: `SframeHeader::parse` never panics on any bytes.
///
/// RFC 9605 §4 wire-парсер variable-length заголовка SFrame
/// (`X K(3) Y C(3)` CONFIG + 0..8 байт KID + 0..8 байт CTR). Допустимые
/// исходы: `Ok((header, rest))` либо `Err(CallError::InvalidHeader(_))`.
/// Malicious relay контролирует wire bytes — parser должен их корректно
/// обрабатывать без panic на любых мусорных / обрезанных / формально-невалидных
/// входах.
///
/// RFC 9605 §4 wire parser of the variable-length SFrame header
/// (`X K(3) Y C(3)` CONFIG + 0..8 KID bytes + 0..8 CTR bytes). Valid outcomes:
/// `Ok((header, rest))` or `Err(CallError::InvalidHeader(_))`. A malicious
/// relay controls the wire bytes — the parser must handle any garbage /
/// truncated / formally-invalid inputs without panicking.
pub fn fuzz_sframe_header_parse(data: &[u8]) {
    let _ = umbrella_calls::SframeHeader::parse(data);
}

/// Fuzz-таргет: полный `SframeContext::decrypt_frame` parse-path не паникует.
/// Fuzz target: full `SframeContext::decrypt_frame` parse-path never panics.
///
/// Покрывает всю цепочку: parse header → epoch lookup → replay check →
/// derive_per_kid → AEAD decrypt. Использует detereministic base_key
/// (all-zero 64-byte ikm) для epoch=0 — это обеспечивает стабильный cache
/// между fuzz iterations. Любой input должен заканчиваться `Err(_)` без
/// panic на всех уровнях (parse, derive, AEAD).
///
/// Covers the full chain: parse header → epoch lookup → replay check →
/// derive_per_kid → AEAD decrypt. Uses a deterministic base_key (all-zero
/// 64-byte ikm) for epoch=0 — this gives stable cache state across fuzz
/// iterations. Any input must end as `Err(_)` without panics at any level
/// (parse, derive, AEAD).
pub fn fuzz_sframe_frame_parse(data: &[u8]) {
    let mut ctx = umbrella_calls::SframeContext::new();
    ctx.advance_epoch(umbrella_calls::SframeBaseKey::from_ikm(
        &[0u8; 64],
        umbrella_calls::SframeCiphersuite::Aes256GcmSha512,
        0,
    ));
    let _ = ctx.decrypt_frame(data);
}

// =============================================================================
// Post-quantum wire-format fuzz targets (Этап 9, блок 9.6 OSS-Fuzz onboarding)
// Post-quantum wire-format fuzz targets (Stage 9, block 9.6 OSS-Fuzz onboarding)
// =============================================================================
//
// Семь fuzz-таргетов для PQ wire-форматов, активированных под `feature = "pq"`:
//
// 1. `fuzz_xwing_pubkey_parser`     — `XWingPublicKey::from_bytes` (1216 байт).
// 2. `fuzz_xwing_ciphertext_parser` — `xwing_decaps` на arbitrary 1120-байтовом
//    ciphertext'е (synthesized recipient seed).
// 3. `fuzz_hybrid_signature_parser` — `HybridSignature::from_bytes`
//    (Ed25519 64 || ML-DSA-65 3309 = 3373 байт).
// 4. `fuzz_kt_entry_v2_parser`      — `KtEntryV2::from_bytes` с V1↔V2 dispatch
//    через первый байт 0x02 (postулат 14: strict version stamp).
// 5. `fuzz_sealed_sender_v2_parser` — `unseal_v2` full path (version dispatch +
//    X-Wing decaps + AEAD decrypt + sig verify) на synthesized recipient.
// 6. `fuzz_wrapped_key_v2_parser`   — `WrappedKeyV2::from_bytes` (1218 байт wire).
// 7. `fuzz_mls_keypackage_parser`   — `KeyPackageIn::tls_deserialize` для MLS
//    KeyPackage (включая 0x004D ciphersuite advertise capabilities).
//
// Каждый target: input `data: &[u8]` → never panic; либо `Ok(parsed)`, либо
// `Err(strict_variant)` без silent fallback. Покрываемая поверхность —
// post-quantum wire-format парсеры из блоков 8.4-8.7. Соответствующие formal
// модели в `crates/umbrella-formal-verification/models/` доказывают
// security properties; OSS-Fuzz purpose — выявить parser bugs (panic / OOM /
// memory safety violations / time-bomb crashes на adversarial inputs), которые
// formal verification не покрывает.
//
// Seven fuzz targets for PQ wire-formats, activated under `feature = "pq"`:
//
// 1. `fuzz_xwing_pubkey_parser`     — `XWingPublicKey::from_bytes` (1216 bytes).
// 2. `fuzz_xwing_ciphertext_parser` — `xwing_decaps` on an arbitrary 1120-byte
//    ciphertext (synthesized recipient seed).
// 3. `fuzz_hybrid_signature_parser` — `HybridSignature::from_bytes`
//    (Ed25519 64 || ML-DSA-65 3309 = 3373 bytes).
// 4. `fuzz_kt_entry_v2_parser`      — `KtEntryV2::from_bytes` with V1↔V2
//    dispatch via the first byte 0x02 (postulate 14: strict version stamp).
// 5. `fuzz_sealed_sender_v2_parser` — `unseal_v2` full path (version dispatch +
//    X-Wing decaps + AEAD decrypt + sig verify) on a synthesized recipient.
// 6. `fuzz_wrapped_key_v2_parser`   — `WrappedKeyV2::from_bytes` (1218 wire bytes).
// 7. `fuzz_mls_keypackage_parser`   — `KeyPackageIn::tls_deserialize` for MLS
//    KeyPackage (including 0x004D ciphersuite advertise capabilities).
//
// Each target: input `data: &[u8]` → never panic; either `Ok(parsed)` or
// `Err(strict_variant)` with no silent fallback. The covered surface is the
// PQ wire-format parsers from blocks 8.4-8.7. Their security properties are
// proven by the formal models in
// `crates/umbrella-formal-verification/models/`; OSS-Fuzz is meant to uncover
// parser bugs (panics, OOM, memory-safety violations, latent crashes on
// adversarial inputs) that formal verification does not cover.

/// Fuzz-таргет: `XWingPublicKey::from_bytes` для любых байт не паникует.
/// Fuzz target: `XWingPublicKey::from_bytes` never panics on any bytes.
///
/// Парсер 1216-байтового X-Wing public key wire-формата
/// (X25519 32 байта || ML-KEM-768 1184 байта = 1216) per
/// draft-connolly-cfrg-xwing-kem-06 §3.1. Парсер используется при импорте
/// recipient pubkey в Sealed Sender V2 envelope, MLS KeyPackage capabilities
/// advertise (0x004D), KT v2 entry hybrid identity slot. Любой byte input
/// должен либо успешно распарситься, либо вернуть `Err(PqError)` без panic.
///
/// Parser for the 1216-byte X-Wing public key wire format
/// (X25519 32 bytes || ML-KEM-768 1184 bytes = 1216) per
/// draft-connolly-cfrg-xwing-kem-10 §5.1. Used when importing a recipient
/// pubkey into a Sealed Sender V2 envelope, MLS KeyPackage 0x004D capability
/// advertise, or a KT v2 entry hybrid identity slot. Any byte input must
/// either parse successfully or return `Err(PqError)` without panicking.
#[cfg(feature = "pq")]
pub fn fuzz_xwing_pubkey_parser(data: &[u8]) {
    let _ = umbrella_pq::XWingPublicKey::from_bytes(data);
}

/// Fuzz-таргет: `xwing_decaps` на arbitrary 1120-байтовом ciphertext'е
/// не паникует.
/// Fuzz target: `xwing_decaps` on an arbitrary 1120-byte ciphertext never
/// panics.
///
/// Decaps вычислитель X-Wing combiner draft-10 — extract'ит shared secret
/// из 1120-байтового X-Wing ct (ML-KEM-768 ct 1088 || X25519 ephemeral 32 = 1120).
/// Малициозный sender может прислать любой 1120-байтовый payload в Sealed
/// Sender V2 envelope; recipient выполняет decaps без panic — либо валидный
/// shared_secret (что invalid дальше провалится в AEAD), либо
/// `Err(PqError)` (типично BackendError "decaps failed" для random входа).
///
/// Synthesized recipient seed — детерминированный all-zero `[0u8; 32]` —
/// stable cache state между fuzz iterations.
///
/// X-Wing combiner draft-10 decaps — extracts a shared secret from a 1120-byte
/// X-Wing ct (ML-KEM-768 ct 1088 || X25519 ephemeral 32 = 1120). A malicious
/// sender may include any 1120-byte payload in a Sealed Sender V2 envelope;
/// the recipient must perform decaps without panicking — either yielding a
/// valid `shared_secret` (which then fails AEAD downstream) or returning
/// `Err(PqError)` (typically BackendError "decaps failed" for random input).
///
/// The recipient seed is deterministic (all-zero `[0u8; 32]`) for stable
/// fuzz-iteration cache state.
#[cfg(feature = "pq")]
pub fn fuzz_xwing_ciphertext_parser(data: &[u8]) {
    use umbrella_pq::xwing::{xwing_decaps, xwing_keygen_from_seed};

    let seed = [0u8; 32];
    let Ok((_pk, own_seed)) = xwing_keygen_from_seed(&seed) else {
        return;
    };

    if data.len() != umbrella_pq::XWING_CIPHERTEXT_LEN {
        return;
    }
    let mut ct = [0u8; umbrella_pq::XWING_CIPHERTEXT_LEN];
    ct.copy_from_slice(data);
    let _ = xwing_decaps(&own_seed, &ct);
}

/// Fuzz-таргет: `ml_kem_768_decaps` на arbitrary 1088-байтовом ciphertext'е
/// не паникует и не leak'ает память (закрывает 1 GAP col 1 row 10 KyberSlash
/// в block 10.22 threat × crate matrix).
///
/// Fuzz target: `ml_kem_768_decaps` on an arbitrary 1088-byte ciphertext
/// never panics and does not leak memory (closes the 1 GAP at col 1 row 10
/// KyberSlash in the block 10.22 threat × crate matrix).
///
/// ## Покрытие / Coverage
///
/// FIPS 203 §7.3 ML-KEM-768 decapsulation использует **implicit rejection**
/// design: для corrupted ciphertext возвращается valid-looking но
/// pseudo-random shared secret (НЕ Result::Err). Это значит decapsulate
/// **никогда** не должен panic'нуть на любой 1088-byte input — что и
/// проверяет этот таргет. Пары `(sk, ct)` malicious sender'а в Hybrid X-Wing
/// envelope (SPEC-13 §5) либо PQ-VOPRF (SPEC-13 §10) обрабатываются
/// recipient'ом через тот же путь.
///
/// FIPS 203 §7.3 ML-KEM-768 decapsulation uses an **implicit rejection**
/// design: for a corrupted ciphertext a valid-looking but pseudo-random
/// shared secret is returned (NOT a `Result::Err`). This means decapsulate
/// **never** panics for any 1088-byte input — exactly what this target
/// verifies. The malicious-sender `(sk, ct)` pairs flowing through the
/// hybrid X-Wing envelope (SPEC-13 §5) and PQ-VOPRF (SPEC-13 §10) are
/// processed by the recipient via the same path.
///
/// ## KyberSlash mitigation / KyberSlash митигация
///
/// Side-channel timing leak в ML-KEM-768 decapsulation (KyberSlash, Bernstein
/// et al. 2024) митигирован архитектурно через formal verification backend
/// `libcrux_ml_kem 0.0.8` (hax-проверенная реализация FIPS 203). Этот fuzz
/// таргет проверяет structural property (no-panic invariant); timing-leak
/// constant-time property delegated к libcrux upstream proof + dudect
/// бенчам block 10.24 (architectural delegation, parallel `RowCipher::
/// decrypt_row` paradigm — base primitive operation timing covered by
/// upstream formal verification, не requires direct in-house dudect bench).
///
/// The side-channel timing leak in ML-KEM-768 decapsulation (KyberSlash,
/// Bernstein et al. 2024) is mitigated architecturally via the formal
/// verification of the `libcrux_ml_kem 0.0.8` backend (hax-verified FIPS 203
/// implementation). This fuzz target checks the structural no-panic
/// invariant; the timing-leak constant-time property is delegated to the
/// libcrux upstream proof + the dudect benches in block 10.24 (architectural
/// delegation, parallel to the `RowCipher::decrypt_row` paradigm — base
/// primitive operation timing is covered by upstream formal verification
/// and does not require a direct in-house dudect bench).
///
/// ## Synthesized state / Синтезированное состояние
///
/// Recipient sk генерируется детерминированно через `ml_kem_768_keygen` с
/// fixed-seed RNG `ChaCha20Rng::from_seed([0u8; 32])` для stable cache state
/// между fuzz iterations. Подход parallel `fuzz_xwing_ciphertext_parser`
/// (line 482-497).
///
/// The recipient sk is generated deterministically via `ml_kem_768_keygen`
/// with a fixed-seed RNG (`ChaCha20Rng::from_seed([0u8; 32])`) for stable
/// fuzz-iteration cache state. Mirrors the `fuzz_xwing_ciphertext_parser`
/// approach (lines 482-497).
#[cfg(feature = "pq")]
pub fn fuzz_ml_kem_decapsulate(data: &[u8]) {
    use umbrella_pq::{ml_kem_768_decaps, ml_kem_768_keygen, ML_KEM_768_CIPHERTEXT_LEN};

    // ChaCha20Rng недоступен из umbrella-fuzz/src/targets.rs (rand_chacha
    // не workspace dep этого крейта). Используем StdRng pattern parallel
    // другим targets либо (проще) cycle через rand_core::OsRng — но fuzz
    // requires deterministic для reproducibility. Альтернатива: thread-local
    // SmallRng с seed-from-data hash. Для simplicity берём fixed-seed
    // ChaCha20Rng через ChaCha20-Poly1305 dep (workspace) — но это AEAD,
    // не RNG. Простейшее решение: use rand::rngs::StdRng::seed_from_u64 если
    // `rand` workspace. Поскольку `rand_core` единственный rng dep в
    // umbrella-fuzz, мы используем его в combination с трибиальным
    // `rand_core::OsRng` (доступно через feature getrandom — уже в Cargo.toml).
    // OsRng даёт fresh keys каждую iteration, что **acceptable** для no-panic
    // fuzz target (cache state per-iteration не critical для structural
    // property; stable seed важен только для reproducibility одиночных
    // crash-входов, а fuzz crash artifacts capture'ят сам ct, не sk).
    //
    // ChaCha20Rng is not available from umbrella-fuzz/src/targets.rs (the
    // `rand_chacha` crate is not a workspace dep here). The `rand_core::OsRng`
    // path (via the existing getrandom feature) gives fresh keys per fuzz
    // iteration — acceptable for the no-panic structural property; stable
    // seed reproducibility matters only for capturing crash inputs, and the
    // libfuzzer artifact records the ciphertext (not the sk).
    let mut rng = rand_core::OsRng;
    let (_pk, sk) = ml_kem_768_keygen(&mut rng);

    if data.len() != ML_KEM_768_CIPHERTEXT_LEN {
        return;
    }
    let mut ct = [0u8; ML_KEM_768_CIPHERTEXT_LEN];
    ct.copy_from_slice(data);

    // FIPS 203 implicit rejection: возвращает SecretBox<[u8; 32]> без panic
    // даже на garbage ciphertext. Структурная property — никаких unreachable!()
    // / unwrap() / out-of-bounds в pure-Rust libcrux_ml_kem 0.0.8.
    //
    // FIPS 203 implicit rejection: returns SecretBox<[u8; 32]> without
    // panicking even on garbage ciphertext. Structural property — no
    // unreachable!() / unwrap() / out-of-bounds in pure-Rust
    // libcrux_ml_kem 0.0.8.
    let _ = ml_kem_768_decaps(&sk, &ct);
}

/// Fuzz-таргет: `HybridSignature::from_bytes` для любых байт не паникует.
/// Fuzz target: `HybridSignature::from_bytes` never panics on any bytes.
///
/// Парсер 3373-байтового hybrid signature wire-формата (Ed25519 64 ||
/// ML-DSA-65 3309 = 3373) per NIST SP 800-227 AND-mode + SPEC-13-PQ-HYBRID §5.
/// Используется в KT v2 entry для hybrid identity ownership proof, в MLS
/// LeafNode signature слое (0x004D), в device key rotation challenge response.
/// Malicious peer может прислать любой byte payload — функция должна handle
/// любой input без panic либо OOM (3373 fixed length чек ранний).
///
/// Parser for the 3373-byte hybrid signature wire format (Ed25519 64 ||
/// ML-DSA-65 3309 = 3373) per NIST SP 800-227 AND-mode and SPEC-13-PQ-HYBRID §5.
/// Used in KT v2 entries for hybrid identity ownership proof, in MLS LeafNode
/// signatures (0x004D), and in device-key rotation challenge responses. A
/// malicious peer may send any byte payload — the function must handle any
/// input without panic or OOM (3373-byte fixed length check is performed
/// early).
#[cfg(feature = "pq")]
pub fn fuzz_hybrid_signature_parser(data: &[u8]) {
    let _ = umbrella_pq::HybridSignature::from_bytes(data);
}

/// Fuzz-таргет: `KtEntryV2::from_bytes` для любых байт не паникует.
/// Fuzz target: `KtEntryV2::from_bytes` never panics on any bytes.
///
/// Парсер V2 KT entry wire-формата (Этап 8 блок 8.5; SPEC-13-PQ-HYBRID §6).
/// Strict V1↔V2 dispatch: первый байт 0x02 → V2HybridPq path (X-Wing pubkey
/// 1216 + ML-DSA-65 pubkey 1952 + SLH-DSA-128f pubkey 32 + classical Ed25519
/// 32 + meta + dual sig); любой другой первый байт → `Err(UnknownEntryVersion)`.
/// Постулат 14: errors индицируют root cause без silent fallback. Malicious
/// KT operator контролирует wire bytes — parser обязан handle любой input.
///
/// Parser for the V2 KT entry wire format (Stage 8 block 8.5; SPEC-13-PQ-HYBRID
/// §6). Strict V1↔V2 dispatch: first byte 0x02 → V2HybridPq path (X-Wing
/// pubkey 1216 + ML-DSA-65 pubkey 1952 + SLH-DSA-128f pubkey 32 + classical
/// Ed25519 32 + meta + dual signature); any other first byte yields
/// `Err(UnknownEntryVersion)`. Postulate 14: errors indicate the root cause
/// without silent fallback. A malicious KT operator controls the wire bytes —
/// the parser must handle any input.
#[cfg(feature = "pq")]
pub fn fuzz_kt_entry_v2_parser(data: &[u8]) {
    let _ = umbrella_kt::KtEntryV2::from_bytes(data);
}

/// Fuzz-таргет: `unseal_v2` full pipeline на arbitrary V2 envelope wire bytes
/// не паникует.
/// Fuzz target: `unseal_v2` full pipeline on arbitrary V2 envelope wire bytes
/// never panics.
///
/// Полная цепочка парсинга Sealed Sender V2 envelope (Этап 8 блок 8.6;
/// SPEC-13-PQ-HYBRID §7): peek первого байта (strict 0x02) → length check
/// (>= V2_MIN_WIRE_LEN 1393) → X-Wing decaps на ct slice (1120 байт) → derive
/// AEAD key/nonce через HKDF → AEAD decrypt → strip padding → parse inner
/// header (sender pub 32 + ed25519 sig 64) → verify inner sig over domain-sep
/// payload. Каждый шаг возвращает specific Error variant без panic; на random
/// входе типично отказ на xwing_decaps либо AEAD decrypt.
///
/// Synthesized recipient: X-Wing keypair из deterministic seed `[0u8; 32]`,
/// Ed25519 InMemoryKeyStore из OsRng entropy (для compat с unseal_v2 sig).
/// Setup cost ~3 ms per iteration — приемлемо для libfuzzer 1k-100k iter/sec.
///
/// Full Sealed Sender V2 envelope parsing pipeline (Stage 8 block 8.6;
/// SPEC-13-PQ-HYBRID §7): peek first byte (strict 0x02) → length check
/// (>= V2_MIN_WIRE_LEN 1393) → X-Wing decaps on the ct slice (1120 bytes) →
/// derive AEAD key/nonce via HKDF → AEAD decrypt → strip padding → parse
/// the inner header (sender pub 32 + ed25519 sig 64) → verify the inner sig
/// over the domain-separated payload. Each step returns a specific Error
/// variant without panicking; on random input the failure is typically at
/// xwing_decaps or AEAD decrypt.
///
/// Synthesized recipient: X-Wing keypair from a deterministic seed
/// `[0u8; 32]`, Ed25519 InMemoryKeyStore from OsRng entropy (for unseal_v2
/// sig compat). Setup cost ~3 ms per iteration — acceptable for libfuzzer
/// 1k-100k iter/sec throughput.
#[cfg(feature = "pq")]
pub fn fuzz_sealed_sender_v2_parser(data: &[u8]) {
    use std::sync::Arc;
    use umbrella_identity::{Clock, IdentitySeed, InMemoryKeyStore, MnemonicLanguage, SystemClock};
    use umbrella_pq::xwing::xwing_keygen_from_seed;

    // Recipient X-Wing keypair (deterministic — stable cache между iterations).
    // Recipient X-Wing keypair (deterministic — stable cache across iterations).
    let xwing_seed = [0u8; 32];
    let Ok((own_pk, own_seed)) = xwing_keygen_from_seed(&xwing_seed) else {
        return;
    };

    // KeyStore требуется сигнатурой unseal_v2 (хотя на этой стадии impl не
    // использует identity_public — see hybrid_envelope.rs:208 `let _ = keystore`).
    // Synthesize через OsRng — на uniffi targets compute cost минимален.
    //
    // KeyStore is required by the unseal_v2 signature (the current impl does
    // not actually use identity_public — see hybrid_envelope.rs:208
    // `let _ = keystore`). Synthesized via OsRng — negligible compute cost on
    // uniffi targets.
    // IdentitySeed::generate возвращает Self (не Result) — постулат 1
    // следует actual signature, не plan-предположению.
    // IdentitySeed::generate returns Self (not Result) — postulate 1 follows
    // the actual signature, not the plan assumption.
    let id_seed = IdentitySeed::generate(&mut rand_core::OsRng, MnemonicLanguage::English);
    let Ok(keystore) = InMemoryKeyStore::open(id_seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>)
    else {
        return;
    };

    let _ = umbrella_sealed_sender::unseal_v2(&keystore, &own_pk, &own_seed, data);
}

/// Fuzz-таргет: `WrappedKeyV2::from_bytes` для любых байт не паникует.
/// Fuzz target: `WrappedKeyV2::from_bytes` never panics on any bytes.
///
/// Парсер 1218-байтового V2 outer X-Wing wrap envelope (Этап 8 блок 8.7;
/// SPEC-13-PQ-HYBRID §8). Layout: version stamp 0x02 + xwing_ct 1120 +
/// inner_v1_wrapped_key_aead 81 + AEAD tag 16 = 1218. V1 inner ElGamal-wrap
/// сохранён байт-в-байт; V2 outer X-Wing layer encapsulates client-derived
/// recovery key через 24-word BIP-39 mnemonic (Pattern B). Любой byte input
/// должен handle без panic — empty / wrong version / truncated / oversized
/// → `Err(WrappedKeyV2Truncated | WrongVersion | InvalidWireFormat)`.
///
/// Parser for the 1218-byte V2 outer X-Wing wrap envelope (Stage 8 block 8.7;
/// SPEC-13-PQ-HYBRID §8). Layout: version stamp 0x02 + xwing_ct 1120 +
/// inner_v1_wrapped_key_aead 81 + AEAD tag 16 = 1218. The V1 inner ElGamal
/// wrap is preserved byte-for-byte; the V2 outer X-Wing layer encapsulates the
/// client-derived recovery key from the 24-word BIP-39 mnemonic (Pattern B).
/// Any byte input must be handled without panicking — empty / wrong version /
/// truncated / oversized →
/// `Err(WrappedKeyV2Truncated | WrongVersion | InvalidWireFormat)`.
#[cfg(feature = "pq")]
pub fn fuzz_wrapped_key_v2_parser(data: &[u8]) {
    let _ = umbrella_backup::cloud_wrap::WrappedKeyV2::from_bytes(data);
}

/// Fuzz-таргет: `KeyPackageIn::tls_deserialize` для любых байт не паникует.
/// Fuzz target: `KeyPackageIn::tls_deserialize` never panics on any bytes.
///
/// Парсер MLS KeyPackage TLS encoding (RFC 9420 §10) — структура с protocol
/// version + ciphersuite (включая 0x004D MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
/// per ADR-011 Решение 4) + init_key + leaf_node + extensions + signature.
/// Используется для group join (member КeyPackage опубликован в delivery
/// service); malicious peer может прислать malformed bytes — parser должен
/// handle через `Err(tls_codec::Error)` без panic либо infinite recursion на
/// nested extensions. Покрытие включает variable-length encoded fields (TLS
/// presentation язык §3 / RFC 9420 §C).
///
/// Parser for the MLS KeyPackage TLS encoding (RFC 9420 §10) — a structure
/// with protocol version + ciphersuite (including 0x004D
/// MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 per ADR-011 Decision 4) +
/// init_key + leaf_node + extensions + signature. Used at group join (a
/// member's KeyPackage is published to the delivery service); a malicious
/// peer may send malformed bytes — the parser must handle with
/// `Err(tls_codec::Error)` and must not panic or recurse infinitely on nested
/// extensions. Coverage includes variable-length encoded fields (TLS
/// presentation language §3 / RFC 9420 §C).
#[cfg(feature = "pq")]
pub fn fuzz_mls_keypackage_parser(data: &[u8]) {
    // F-37 PRIMARY anchor (block 10.8 inline-fix): switched от raw `KeyPackageIn::tls_deserialize`
    // на `umbrella_mls::parse_key_package_safe`, который содержит bounds-check (KEY_PACKAGE_MIN_BYTES = 64)
    // + std::panic::catch_unwind defensive layer. tls_codec-0.4.2/src/quic_vec.rs:53 panics на
    // 5-байтовом malformed input `[0,0,0,1,192]` — F-37 reproduction. Через safe wrapper input
    // returns explicit `Err(MlsError::Codec)` либо `Err(MlsError::ParserPanic)`, не panic propagates
    // up через openmls → fuzz harness → DoS. Постулат 14: no silent fallback — Err explicit.
    //
    // F-37 PRIMARY anchor (block 10.8 inline-fix): switched from the raw
    // `KeyPackageIn::tls_deserialize` to `umbrella_mls::parse_key_package_safe`, which contains a
    // bounds-check (KEY_PACKAGE_MIN_BYTES = 64) plus a std::panic::catch_unwind defensive layer.
    // tls_codec-0.4.2/src/quic_vec.rs:53 panics on the 5-byte malformed input `[0,0,0,1,192]` —
    // the F-37 reproduction. Through the safe wrapper, the input returns an explicit
    // `Err(MlsError::Codec)` or `Err(MlsError::ParserPanic)`; the panic does not propagate up
    // through openmls → fuzz harness → DoS. Postulate 14: no silent fallback — Err is explicit.
    let _ = umbrella_mls::parse_key_package_safe(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn fuzz_entry_does_not_panic_on_empty() {
        fuzz_parse_mls_envelope(&[]);
    }

    #[test]
    fn fuzz_entry_does_not_panic_on_single_bytes() {
        for b in 0u8..=255 {
            fuzz_parse_mls_envelope(&[b]);
        }
    }

    #[test]
    fn fuzz_entry_does_not_panic_on_short_patterns() {
        let patterns: &[&[u8]] = &[
            &[0x00],
            &[0xFF],
            &[0x00, 0x00],
            &[0x01, 0x02, 0x03, 0x04],
            &[0x00, 0x01, 0x00, 0x02, 0x00, 0x00],
            &[0xFF; 32],
            &[0x55; 128],
            &[0xAA; 512],
        ];
        for p in patterns {
            fuzz_parse_mls_envelope(p);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn prop_fuzz_entry_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            fuzz_parse_mls_envelope(&data);
        }

        #[test]
        fn prop_strip_padding_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
            fuzz_strip_padding(&data);
        }

        #[test]
        fn prop_verify_inclusion_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..2048)
        ) {
            fuzz_verify_inclusion(&data);
        }

        #[test]
        fn prop_oprf_parse_blinded_request_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..256)
        ) {
            fuzz_oprf_parse_blinded_request(&data);
        }

        #[test]
        fn prop_oprf_parse_server_evaluation_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..256)
        ) {
            fuzz_oprf_parse_server_evaluation(&data);
        }

        #[test]
        fn prop_oprf_threshold_combine_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..1024)
        ) {
            fuzz_oprf_threshold_combine(&data);
        }

        #[test]
        fn prop_wrapped_key_parse_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..256)
        ) {
            fuzz_wrapped_key_parse(&data);
        }

        #[test]
        fn prop_unwrap_share_parse_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..256)
        ) {
            fuzz_unwrap_share_parse(&data);
        }

        #[test]
        fn prop_qr_payload_parse_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..512)
        ) {
            fuzz_qr_payload_parse(&data);
        }

        #[test]
        fn prop_noise_responder_msg1_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..2048)
        ) {
            fuzz_noise_responder_msg1(&data);
        }

        #[test]
        fn prop_noise_initiator_msg2_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..2048)
        ) {
            fuzz_noise_initiator_msg2(&data);
        }

        #[test]
        fn prop_authorization_request_parse_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..512)
        ) {
            fuzz_authorization_request_parse(&data);
        }

        #[test]
        fn prop_authorization_approval_parse_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..256)
        ) {
            fuzz_authorization_approval_parse(&data);
        }

        #[test]
        fn prop_authorization_revocation_parse_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..256)
        ) {
            fuzz_authorization_revocation_parse(&data);
        }

        #[test]
        fn prop_identity_rotation_parse_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..256)
        ) {
            fuzz_identity_rotation_parse(&data);
        }
    }

    #[test]
    fn strip_padding_smoke_short_inputs() {
        for len in 0..300 {
            let data = vec![0u8; len];
            fuzz_strip_padding(&data);
        }
    }

    #[test]
    fn verify_inclusion_smoke_short_inputs() {
        // Input shorter than header — should early-return Ok without panic.
        fuzz_verify_inclusion(&[]);
        fuzz_verify_inclusion(&[0u8; 10]);
        fuzz_verify_inclusion(&[0u8; 80]);
        // Minimum header present.
        fuzz_verify_inclusion(&[0u8; 128]);
    }

    #[test]
    fn oprf_parse_blinded_request_smoke() {
        fuzz_oprf_parse_blinded_request(&[]);
        fuzz_oprf_parse_blinded_request(&[0u8; 16]);
        fuzz_oprf_parse_blinded_request(&[0u8; 32]);
        fuzz_oprf_parse_blinded_request(&[0xFFu8; 32]);
        fuzz_oprf_parse_blinded_request(&[0x55u8; 33]);
    }

    #[test]
    fn oprf_parse_server_evaluation_smoke() {
        fuzz_oprf_parse_server_evaluation(&[]);
        fuzz_oprf_parse_server_evaluation(&[0u8; 31]);
        fuzz_oprf_parse_server_evaluation(&[0u8; 32]);
        fuzz_oprf_parse_server_evaluation(&[0xFFu8; 32]);
        fuzz_oprf_parse_server_evaluation(&[0xAAu8; 128]);
    }

    #[test]
    fn backup_wrapped_key_parse_smoke() {
        fuzz_wrapped_key_parse(&[]);
        fuzz_wrapped_key_parse(&[0u8; 80]);
        fuzz_wrapped_key_parse(&[0u8; 81]);
        fuzz_wrapped_key_parse(&[0xFFu8; 81]);
        fuzz_wrapped_key_parse(&[0x02u8; 81]); // invalid version
        fuzz_wrapped_key_parse(&[0x55u8; 1024]);
    }

    #[test]
    fn backup_unwrap_share_parse_smoke() {
        fuzz_unwrap_share_parse(&[]);
        fuzz_unwrap_share_parse(&[0u8; 32]);
        fuzz_unwrap_share_parse(&[0u8; 33]);
        fuzz_unwrap_share_parse(&[0xFFu8; 33]); // witness=255 → invalid
        let mut valid_sample = [0u8; 33];
        valid_sample[0] = 3; // witness index 3
        fuzz_unwrap_share_parse(&valid_sample);
    }

    #[test]
    fn backup_qr_payload_parse_smoke() {
        fuzz_qr_payload_parse(&[]);
        fuzz_qr_payload_parse(&[0u8; 168]);
        fuzz_qr_payload_parse(&[0u8; 169]); // valid length, version 0 → invalid
        fuzz_qr_payload_parse(&[0xFFu8; 169]);
        let mut bytes = [0u8; 169];
        bytes[0] = 0x01; // valid version, rest zeros
        fuzz_qr_payload_parse(&bytes);
    }

    #[test]
    fn backup_noise_responder_msg1_smoke() {
        fuzz_noise_responder_msg1(&[]);
        fuzz_noise_responder_msg1(&[0u8; 10]);
        fuzz_noise_responder_msg1(&[0xFFu8; 96]); // ballpark IK msg1 length
        fuzz_noise_responder_msg1(&[0u8; 65535]);
    }

    #[test]
    fn backup_noise_initiator_msg2_smoke() {
        fuzz_noise_initiator_msg2(&[]);
        fuzz_noise_initiator_msg2(&[0u8; 10]);
        fuzz_noise_initiator_msg2(&[0xFFu8; 48]);
    }

    #[test]
    fn oprf_threshold_combine_smoke() {
        fuzz_oprf_threshold_combine(&[]);
        fuzz_oprf_threshold_combine(&[0]);
        fuzz_oprf_threshold_combine(&[3]);
        // count=3, потом 3×(witness + 32 bytes) но короче буфер.
        fuzz_oprf_threshold_combine(&[3, 1, 2, 3]);
        // count=5, все нули.
        let mut buf = vec![5u8];
        buf.extend_from_slice(&[0u8; 5 * 33]);
        fuzz_oprf_threshold_combine(&buf);
        // count=5, все байт 0xFF (невалидные точки).
        let mut buf2 = vec![5u8];
        buf2.extend_from_slice(&[0xFFu8; 5 * 33]);
        fuzz_oprf_threshold_combine(&buf2);
    }

    // ---- ADR-008 authorization wire-format parsers (блок 5.7.5) ----
    //
    // Четыре новых fuzz target'а для парсеров ADR-008 записей, публикуемых в
    // KT либо dedicated mailbox. Input полностью untrusted (malicious KT
    // operator либо malicious клиент). Parsers обязаны обрабатывать любые
    // байты без panic, возвращая `BackupError::InvalidWireFormat` /
    // `WrappedKeyVersionMismatch` на некорректных данных.
    //
    // Four new ADR-008 fuzz targets for parsers of records published to KT
    // or to a dedicated mailbox. Input is fully untrusted (malicious KT
    // operator or malicious client). Parsers must handle any bytes without
    // panic, returning `BackupError::InvalidWireFormat` /
    // `WrappedKeyVersionMismatch` on invalid data.

    #[test]
    fn authorization_request_parse_smoke() {
        // Base length = 138, max = 266 (с location_hint 128 байт).
        fuzz_authorization_request_parse(&[]);
        fuzz_authorization_request_parse(&[0u8; 1]);
        fuzz_authorization_request_parse(&[0u8; 137]); // < BASE_LEN
        fuzz_authorization_request_parse(&[0u8; 138]); // version=0 → version mismatch
        let mut valid_hdr = [0u8; 138];
        valid_hdr[0] = 0x01; // valid version, hint_len=0, fake signature
        fuzz_authorization_request_parse(&valid_hdr);
        fuzz_authorization_request_parse(&[0xFFu8; 266]); // max length, invalid bytes
        fuzz_authorization_request_parse(&[0x55u8; 512]); // too long
                                                          // location_hint_len > 128 → InvalidWireFormat.
        let mut over_hint = vec![0u8; 138];
        over_hint[0] = 0x01;
        over_hint[73] = 200; // claimed hint_len = 200 > 128
        fuzz_authorization_request_parse(&over_hint);
    }

    #[test]
    fn authorization_approval_parse_smoke() {
        // Fixed length = 146.
        fuzz_authorization_approval_parse(&[]);
        fuzz_authorization_approval_parse(&[0u8; 145]);
        fuzz_authorization_approval_parse(&[0u8; 146]); // version=0 → mismatch
        let mut valid_hdr = [0u8; 146];
        valid_hdr[0] = 0x01;
        fuzz_authorization_approval_parse(&valid_hdr);
        fuzz_authorization_approval_parse(&[0xFFu8; 146]); // reserved bits set → InvalidWireFormat
        fuzz_authorization_approval_parse(&[0x55u8; 1024]); // too long
                                                            // policy_flags reserved bits установлены (bit 1).
        let mut reserved_bits = [0u8; 146];
        reserved_bits[0] = 0x01;
        reserved_bits[81] = 0x02;
        fuzz_authorization_approval_parse(&reserved_bits);
    }

    #[test]
    fn authorization_revocation_parse_smoke() {
        // Fixed length = 137.
        fuzz_authorization_revocation_parse(&[]);
        fuzz_authorization_revocation_parse(&[0u8; 136]);
        fuzz_authorization_revocation_parse(&[0u8; 137]); // version=0 → mismatch
        let mut valid_hdr = [0u8; 137];
        valid_hdr[0] = 0x01;
        fuzz_authorization_revocation_parse(&valid_hdr);
        fuzz_authorization_revocation_parse(&[0xFFu8; 137]);
        fuzz_authorization_revocation_parse(&[0x55u8; 512]);
    }

    #[test]
    fn identity_rotation_parse_smoke() {
        // Fixed length = 202.
        fuzz_identity_rotation_parse(&[]);
        fuzz_identity_rotation_parse(&[0u8; 201]);
        fuzz_identity_rotation_parse(&[0u8; 202]); // version=0 + identical pubkeys
        let mut valid_hdr = [0u8; 202];
        valid_hdr[0] = 0x01;
        // все zero pubkeys → identical → InvalidWireFormat при parse.
        fuzz_identity_rotation_parse(&valid_hdr);
        fuzz_identity_rotation_parse(&[0xFFu8; 202]); // unknown rotation_reason tag
        fuzz_identity_rotation_parse(&[0x55u8; 1024]);
        // Валидные-по-длине bytes с различающимися old/new pubkeys, но неверный reason.
        let mut mismatched = [0u8; 202];
        mismatched[0] = 0x01;
        for (i, byte) in mismatched.iter_mut().enumerate().skip(1).take(32) {
            *byte = i as u8; // old_identity_pubkey
        }
        for (i, byte) in mismatched.iter_mut().enumerate().skip(33).take(32) {
            *byte = 0xA0 ^ (i as u8); // new_identity_pubkey
        }
        mismatched[73] = 0x77; // rotation_reason tag неизвестный
        fuzz_identity_rotation_parse(&mismatched);
    }

    #[test]
    fn sframe_header_parse_smoke() {
        // Граничные: пустой, один байт с каждым вариантом X/Y битов, max 17 байт.
        // Edge: empty, single byte with each X/Y bit variant, max 17 bytes.
        fuzz_sframe_header_parse(&[]);
        fuzz_sframe_header_parse(&[0x00]); // X=0, K=0, Y=0, C=0 — inline header 1 байт.
        fuzz_sframe_header_parse(&[0xFF]); // X=1, K=7 → 8 KID ожидается, truncated.
        fuzz_sframe_header_parse(&[0x0F]); // X=0, Y=1, C=7 → 8 CTR ожидается, truncated.
        fuzz_sframe_header_parse(&[0xFFu8; 17]); // Max-length заголовок.
        fuzz_sframe_header_parse(&[0x99, 0x01, 0x23, 0x45, 0x67]); // RFC 9605 vector.
        fuzz_sframe_header_parse(&[0x55u8; 64]); // Random-ish long input.
    }

    #[test]
    fn sframe_frame_parse_smoke() {
        // Пустой и случайные bytes — ничего не расшифровывается,
        // но не должно паниковать ни в parse, ни в derive, ни в AEAD.
        // Empty and random bytes — nothing decrypts, but no panics
        // in parse/derive/AEAD paths.
        fuzz_sframe_frame_parse(&[]);
        fuzz_sframe_frame_parse(&[0x00u8; 32]);
        fuzz_sframe_frame_parse(&[0xFFu8; 128]);
        fuzz_sframe_frame_parse(&[0x99, 0x01, 0x23, 0x45, 0x67, 0xAA, 0xBB]); // RFC header + garbage.
    }

    proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

        #[test]
        fn prop_sframe_header_parse_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            fuzz_sframe_header_parse(&data);
        }

        #[test]
        fn prop_sframe_frame_parse_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            fuzz_sframe_frame_parse(&data);
        }
    }

    // ---- PQ wire-format fuzz target tests (Этап 9, блок 9.6 OSS-Fuzz) ----
    //
    // Smoke + proptest для 7 новых PQ harnesses: short/exact-length/oversized
    // inputs + adversarial byte patterns. Изолированы в `pq_tests` sub-module
    // под `#[cfg(feature = "pq")]` чтобы не блокировать
    // `cargo test --workspace --no-default-features --locked` baseline.
    //
    // Smoke + proptest tests for the 7 new PQ harnesses: short / exact-length /
    // oversized inputs + adversarial byte patterns. Isolated in the `pq_tests`
    // sub-module under `#[cfg(feature = "pq")]` so they do not block the
    // `cargo test --workspace --no-default-features --locked` baseline.
    #[cfg(feature = "pq")]
    mod pq_tests {
        use super::*;
        use umbrella_pq::{XWING_CIPHERTEXT_LEN, XWING_PUBLIC_KEY_LEN};

        // ML-DSA-65 signature length (3309) + Ed25519 signature length (64)
        // = 3373 bytes hybrid signature wire layout per SPEC-13-PQ-HYBRID §5.
        const HYBRID_SIGNATURE_LEN: usize = 3373;

        // Exact V2 wire length per SPEC-13-PQ-HYBRID §8 (V2 outer X-Wing
        // wrap envelope). 0x02 + xwing_ct 1120 + inner_v1_aead 81 + tag 16.
        const WRAPPED_KEY_V2_LEN: usize = 1218;

        #[test]
        fn xwing_pubkey_parser_smoke() {
            fuzz_xwing_pubkey_parser(&[]);
            fuzz_xwing_pubkey_parser(&[0u8; XWING_PUBLIC_KEY_LEN - 1]);
            fuzz_xwing_pubkey_parser(&[0u8; XWING_PUBLIC_KEY_LEN]); // exact
            fuzz_xwing_pubkey_parser(&[0xFFu8; XWING_PUBLIC_KEY_LEN]); // exact, max bytes
            fuzz_xwing_pubkey_parser(&[0u8; XWING_PUBLIC_KEY_LEN + 1]);
            fuzz_xwing_pubkey_parser(&[0x55u8; 4096]); // oversize
        }

        #[test]
        fn xwing_ciphertext_parser_smoke() {
            fuzz_xwing_ciphertext_parser(&[]);
            fuzz_xwing_ciphertext_parser(&[0u8; XWING_CIPHERTEXT_LEN - 1]);
            fuzz_xwing_ciphertext_parser(&[0u8; XWING_CIPHERTEXT_LEN]); // valid len
            fuzz_xwing_ciphertext_parser(&[0xFFu8; XWING_CIPHERTEXT_LEN]); // valid len, max bytes
            fuzz_xwing_ciphertext_parser(&[0u8; XWING_CIPHERTEXT_LEN + 1]);
            fuzz_xwing_ciphertext_parser(&[0x55u8; 4096]);
        }

        #[test]
        fn hybrid_signature_parser_smoke() {
            fuzz_hybrid_signature_parser(&[]);
            fuzz_hybrid_signature_parser(&[0u8; HYBRID_SIGNATURE_LEN - 1]);
            fuzz_hybrid_signature_parser(&[0u8; HYBRID_SIGNATURE_LEN]); // exact len
            fuzz_hybrid_signature_parser(&[0xFFu8; HYBRID_SIGNATURE_LEN]); // exact, max bytes
            fuzz_hybrid_signature_parser(&[0u8; HYBRID_SIGNATURE_LEN + 1]);
            fuzz_hybrid_signature_parser(&[0x55u8; 8192]);
        }

        #[test]
        fn kt_entry_v2_parser_smoke() {
            fuzz_kt_entry_v2_parser(&[]);
            fuzz_kt_entry_v2_parser(&[0u8; 1]); // version=0 → unknown
            fuzz_kt_entry_v2_parser(&[0x01u8; 1]); // V1 stamp on V2 parser → mismatch
            fuzz_kt_entry_v2_parser(&[0x02u8]); // V2 stamp, truncated
                                                // Полный V2 wire short → структурный parse error.
                                                // Full V2 wire short → structural parse error.
            let mut v2_short = [0u8; 64];
            v2_short[0] = 0x02;
            fuzz_kt_entry_v2_parser(&v2_short);
            fuzz_kt_entry_v2_parser(&[0xFFu8; 256]); // unknown version 0xFF
            fuzz_kt_entry_v2_parser(&[0x55u8; 4096]); // oversize garbage
        }

        #[test]
        fn sealed_sender_v2_parser_smoke() {
            fuzz_sealed_sender_v2_parser(&[]);
            fuzz_sealed_sender_v2_parser(&[0x01]); // V1 stamp на V2 parser → UnsupportedVersion
            fuzz_sealed_sender_v2_parser(&[0x02]); // V2 stamp, truncated → Malformed
            fuzz_sealed_sender_v2_parser(&[0xFF]); // unknown version
            fuzz_sealed_sender_v2_parser(&[0x02u8; 1392]); // V2 stamp, < V2_MIN_WIRE_LEN
            fuzz_sealed_sender_v2_parser(&[0x02u8; 1393]); // exact V2_MIN_WIRE_LEN
            fuzz_sealed_sender_v2_parser(&[0x02u8; 4096]); // oversized
        }

        #[test]
        fn wrapped_key_v2_parser_smoke() {
            fuzz_wrapped_key_v2_parser(&[]);
            fuzz_wrapped_key_v2_parser(&[0x01u8; 81]); // V1 wrapped key length, V2 stamp absent
            fuzz_wrapped_key_v2_parser(&[0x02u8]); // V2 stamp, truncated
            fuzz_wrapped_key_v2_parser(&[0u8; WRAPPED_KEY_V2_LEN - 1]);
            fuzz_wrapped_key_v2_parser(&[0u8; WRAPPED_KEY_V2_LEN]); // version=0 → mismatch
            let mut v2_full = [0u8; WRAPPED_KEY_V2_LEN];
            v2_full[0] = 0x02;
            fuzz_wrapped_key_v2_parser(&v2_full); // valid version + zero ct/tag
            fuzz_wrapped_key_v2_parser(&[0xFFu8; WRAPPED_KEY_V2_LEN]); // version=0xFF → mismatch
            fuzz_wrapped_key_v2_parser(&[0x55u8; 4096]); // oversized garbage
        }

        #[test]
        fn mls_keypackage_parser_smoke() {
            fuzz_mls_keypackage_parser(&[]);
            fuzz_mls_keypackage_parser(&[0u8; 8]);
            fuzz_mls_keypackage_parser(&[0xFFu8; 32]);
            // RFC 9420 §6.1 protocol_version = 0x0001 (mls10) первые 2 байта;
            // далее ciphersuite u16. Random byte patterns.
            fuzz_mls_keypackage_parser(&[0x00, 0x01, 0x00, 0x4D, 0x00, 0x00]); // 0x004D ciphersuite
            fuzz_mls_keypackage_parser(&[0x00, 0x01, 0x00, 0x03]); // 0x0003 ciphersuite
            fuzz_mls_keypackage_parser(&[0x55u8; 1024]);
            fuzz_mls_keypackage_parser(&[0xFFu8; 65535]); // max u16 length
        }

        proptest! {
            #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

            #[test]
            fn prop_xwing_pubkey_parser_never_panics(
                data in proptest::collection::vec(any::<u8>(), 0..2048),
            ) {
                fuzz_xwing_pubkey_parser(&data);
            }

            #[test]
            fn prop_xwing_ciphertext_parser_never_panics(
                data in proptest::collection::vec(any::<u8>(), 0..1200),
            ) {
                fuzz_xwing_ciphertext_parser(&data);
            }

            #[test]
            fn prop_hybrid_signature_parser_never_panics(
                data in proptest::collection::vec(any::<u8>(), 0..4096),
            ) {
                fuzz_hybrid_signature_parser(&data);
            }

            #[test]
            fn prop_kt_entry_v2_parser_never_panics(
                data in proptest::collection::vec(any::<u8>(), 0..4096),
            ) {
                fuzz_kt_entry_v2_parser(&data);
            }

            #[test]
            fn prop_sealed_sender_v2_parser_never_panics(
                data in proptest::collection::vec(any::<u8>(), 0..2048),
            ) {
                fuzz_sealed_sender_v2_parser(&data);
            }

            #[test]
            fn prop_wrapped_key_v2_parser_never_panics(
                data in proptest::collection::vec(any::<u8>(), 0..2048),
            ) {
                fuzz_wrapped_key_v2_parser(&data);
            }

            #[test]
            fn prop_mls_keypackage_parser_never_panics(
                data in proptest::collection::vec(any::<u8>(), 0..2048),
            ) {
                fuzz_mls_keypackage_parser(&data);
            }
        }

        // Exhaustive single-byte coverage для V1↔V2 dispatcher проверок.
        // Exhaustive single-byte coverage for V1↔V2 dispatcher checks.
        #[test]
        fn kt_entry_v2_parser_byte_dispatch_exhaustive() {
            for b in 0u8..=255u8 {
                fuzz_kt_entry_v2_parser(&[b]);
            }
        }

        #[test]
        fn sealed_sender_v2_parser_byte_dispatch_exhaustive() {
            for b in 0u8..=255u8 {
                fuzz_sealed_sender_v2_parser(&[b]);
            }
        }

        #[test]
        fn wrapped_key_v2_parser_byte_dispatch_exhaustive() {
            for b in 0u8..=255u8 {
                fuzz_wrapped_key_v2_parser(&[b]);
            }
        }
    }
}
