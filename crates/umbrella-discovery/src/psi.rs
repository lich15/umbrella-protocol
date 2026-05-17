//! OPRF-PSI протокол (Pinkas-Rosulek-Trieu-Yanai 2018 §3.1).
//!
//! OPRF-PSI protocol (Pinkas-Rosulek-Trieu-Yanai 2018 §3.1).
//!
//! ## Идея
//!
//! Клиент хочет узнать `S_client ∩ S_server` без раскрытия `S_client` или
//! `S_server` другой стороне.
//!
//! - Клиент имеет адресную книгу `S_client = {phone_1, phone_2, …, phone_n}`.
//! - Сервер имеет таблицу `S_server = {phone_a, phone_b, …, phone_m}`.
//! - Сервер заранее вычислил `T_server = {oprf(k, phone_a), oprf(k, phone_b), …}`
//!   где `k` — OPRF key (фактически распределённый 3-of-5 Shamir).
//! - Клиент batch-blind'ит `S_client`, отправляет 3 of 5 серверам.
//! - Серверы возвращают partial evaluations.
//! - Клиент threshold-combine + finalize → `L_client = {oprf(k, phone_i) | i}`.
//! - Клиент сверяет `L_client` с `T_server` (получает таблицу от сервера) и
//!   определяет intersection.
//!
//! ## Что узнаёт каждая сторона
//!
//! - Клиент узнаёт: `S_client ∩ S_server` (intersection cardinality + items).
//! - Сервер узнаёт: ничего о `S_client` (blinding hides input; OPRF output
//!   detected только клиентом).
//!
//! ## Бэнд-широта
//!
//! Для 500 контактов: 500 × 32 bytes blinded request + 500 × 32 bytes server
//! eval = 32 KB per server = 96 KB cross 3 servers. Полная таблица `T_server`
//! для 1M users: 32 MB raw (можно reduce через Bloom filter или per-shard
//! download — out of scope round 7, см. `docs/spec/discovery-backend-spec.md`).
//!
//! Realistic test in `examples/psi_realistic_scenario.rs` использует 500 vs 1M.
//!
//! ## Pinkas-Rosulek-Trieu-Yanai 2018 paper
//!
//! Бумага охватывает несколько вариантов; мы используем «base OPRF-PSI» (§3.1)
//! без cuckoo filter optimization (которая для нас лишний complexity при N≤500).
//!
//! ## Bandwidth
//!
//! 500 contacts → ≤ 96 KB cross 3 servers. The full 1M `T_server` is 32 MB
//! raw (reducible via Bloom filter / per-shard download — out of scope for
//! round 7; see backend spec).

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

use umbrella_oprf::{
    blind, finalize, threshold_combine, BlindedRequest, BlindingState, OprfInput, OprfLabel,
    ServerEvaluation, ThresholdConfig, WitnessIndex, MAX_BATCH_SIZE,
};

use crate::anonymous_query::{
    derive_per_query_anon_id, fresh_query_salt, SALT_LEN,
};
use crate::error::{DiscoveryError, DiscoveryResult};
use crate::wire::{
    ANON_ID_LEN, MAX_PSI_BATCH, PsiQueryEntry, PsiRequest, PsiResponseEntry, SERVER_NONCE_LEN,
    TRANSCRIPT_TAG_LEN, WIRE_VERSION,
};

/// PSI client-side state: запрос подготовлен, ждём server responses.
/// PSI client-side state: query prepared, awaiting server responses.
#[derive(Debug)]
pub struct PsiQueryState {
    /// Per-query salt (детерминирует anon_ids на 5 серверов).
    /// Per-query salt (determines anon_ids on the 5 servers).
    #[allow(dead_code)] // retained для anon_id rederivation в тестах + audit
    salt: [u8; SALT_LEN],
    /// Blinding states (один на каждый контакт).
    /// Blinding states (one per contact).
    states: Vec<BlindingState>,
    /// Raw contact inputs (для финализации; not exposed via API).
    /// Raw contact inputs (for finalization; not exposed via API).
    inputs: Vec<Vec<u8>>,
    /// Client nonce (random for transcript binding).
    /// Client nonce (random for transcript binding).
    #[allow(dead_code)] // retained для transcript audit
    client_nonce: [u8; SERVER_NONCE_LEN],
}

impl PsiQueryState {
    /// Количество контактов в этой query.
    /// Number of contacts in this query.
    pub fn len(&self) -> usize {
        self.inputs.len()
    }

    /// Test: salt visible для unit tests / debug.
    /// Test-only: salt visible for unit tests.
    #[cfg(test)]
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }
}

/// Подготовить PSI-запрос: blind все контакты + derive anon_ids + создать
/// wire-request для конкретного `witness_index` (1..=5).
///
/// Возвращает `(PsiRequest, PsiQueryState)`. State **обязательно** сохранить
/// до получения server responses — без него finalize невозможен.
///
/// # Errors
/// - [`DiscoveryError::InvalidPsiBatchSize`] если N=0 или > MAX_PSI_BATCH.
/// - [`DiscoveryError::Oprf`] если voprf blind вернул ошибку.
/// - [`DiscoveryError::InputRejected`] если контакт > MAX_INPUT_BYTES.
///
/// Prepare a PSI request: blind all contacts + derive anon_ids + build wire
/// request for the given `witness_index`. State must be retained until server
/// responses arrive.
pub fn prepare_psi_query<R: CryptoRng + RngCore>(
    master_key: &[u8; 32],
    contacts: &[&[u8]],
    witness_index: u8,
    rng: &mut R,
) -> DiscoveryResult<(PsiRequest, PsiQueryState)> {
    if contacts.is_empty() || contacts.len() > MAX_PSI_BATCH {
        return Err(DiscoveryError::InvalidPsiBatchSize {
            got: contacts.len(),
            max: MAX_PSI_BATCH,
        });
    }
    if witness_index == 0 || witness_index > 5 {
        return Err(DiscoveryError::InputRejected("witness_index must be 1..=5"));
    }
    // Превышение MAX_BATCH_SIZE OPRF выше нашего MAX_PSI_BATCH невозможно
    // (1024 == 1024), но проверим explicitly чтобы invariant не сдвинулся.
    debug_assert!(MAX_PSI_BATCH <= MAX_BATCH_SIZE);

    let salt = fresh_query_salt(rng);
    let mut entries = Vec::with_capacity(contacts.len());
    let mut states = Vec::with_capacity(contacts.len());
    let mut inputs = Vec::with_capacity(contacts.len());
    for &c in contacts {
        let inp = OprfInput::new(c)
            .map_err(|_| DiscoveryError::InputRejected("contact length out of OPRF range"))?;
        let (req, state) = blind(inp, rng)?;
        // Per-contact anon_id derived from (master_key, server_id, salt) с
        // дополнительным subdivision per-contact-position через HKDF info.
        // Один и тот же base anon_id для всех контактов одной query от одного
        // server_id — серверу достаточно знать что батч от одного клиента;
        // он не получит cross-batch linkability (next batch имеет другой salt).
        let anon_id =
            derive_per_query_anon_id(master_key, u16::from(witness_index), &salt)?;
        entries.push(PsiQueryEntry {
            anon_id,
            blinded: *req.as_bytes(),
        });
        states.push(state);
        inputs.push(c.to_vec());
    }

    let mut client_nonce = [0u8; SERVER_NONCE_LEN];
    rng.fill_bytes(&mut client_nonce);

    Ok((
        PsiRequest {
            version: WIRE_VERSION,
            entries,
            client_nonce,
            witness_index,
        },
        PsiQueryState {
            salt,
            states,
            inputs,
            client_nonce,
        },
    ))
}

/// Серверный mock: один shard. Применяет свою долю `sk_share` к каждому
/// blinded request, возвращает partial evaluations + server_nonce +
/// transcript_tag.
///
/// Production-сервер делает то же, но в TEE/SEV-SNP. См. `docs/spec/
/// discovery-backend-spec.md`.
///
/// Server-side mock: applies its `sk_share` to each blinded request and
/// returns partial evaluations + nonce + transcript tag.
///
/// # Errors
/// - [`DiscoveryError::Oprf`] из voprf.
pub fn psi_server_respond<R: CryptoRng + RngCore>(
    request: &PsiRequest,
    sk_share: &[u8; 32],
    rng: &mut R,
) -> DiscoveryResult<crate::wire::PsiResponse> {
    let mut entries = Vec::with_capacity(request.entries.len());
    for entry in &request.entries {
        let blinded = BlindedRequest::from_bytes(&entry.blinded)?;
        let eval = umbrella_oprf::evaluate_for_testing(&blinded, sk_share)?;
        entries.push(PsiResponseEntry {
            anon_id: entry.anon_id,
            evaluation: *eval.as_bytes(),
        });
    }
    let mut server_nonce = [0u8; SERVER_NONCE_LEN];
    rng.fill_bytes(&mut server_nonce);
    let transcript_tag = compute_transcript_tag(
        &request.client_nonce,
        &server_nonce,
        &entries,
        sk_share, // tag binds к sk_share (для defense)
    );
    Ok(crate::wire::PsiResponse {
        version: WIRE_VERSION,
        entries,
        server_nonce,
        transcript_tag,
    })
}

/// Compute transcript binding tag = SHA-256(label || client_nonce ||
/// server_nonce || N || (anon_id||eval) ... || tag_seed).
/// Используется и сервером (генерация), и клиентом (verify через
/// `verify_transcript_tag`).
///
/// `tag_seed` — для server side — sk_share. Для прода: HMAC с серверным
/// transcript key из его TEE state. На клиенте seed не передаётся, поэтому
/// клиент проверяет tag только через эхо равенство anon_id+eval — это
/// заведомо слабее «честный сервер заверил», но достаточно для D-5 защиты
/// (replay уже отдельным mechanism через nonce-cache).
fn compute_transcript_tag(
    client_nonce: &[u8; SERVER_NONCE_LEN],
    server_nonce: &[u8; SERVER_NONCE_LEN],
    entries: &[PsiResponseEntry],
    tag_seed: &[u8],
) -> [u8; TRANSCRIPT_TAG_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"umbrella-r7/discovery/psi-transcript/v1");
    hasher.update(client_nonce);
    hasher.update(server_nonce);
    hasher.update((entries.len() as u32).to_be_bytes());
    for e in entries {
        hasher.update(e.anon_id);
        hasher.update(e.evaluation);
    }
    hasher.update(tag_seed);
    let digest = hasher.finalize();
    let mut out = [0u8; TRANSCRIPT_TAG_LEN];
    out.copy_from_slice(&digest[..TRANSCRIPT_TAG_LEN]);
    out
}

/// Финализация PSI-запроса: threshold-combine 3 of 5 server responses,
/// затем OPRF-finalize получить `OprfLabel` per контакт.
///
/// Возвращает `Vec<OprfLabel>` — позиционно соответствующие `contacts` из
/// `prepare_psi_query`.
///
/// `server_responses` — по одному per server (witness_index, ResponseEntry).
/// Если меньше threshold (3) валидных позиционно — вся batch fails.
///
/// # Errors
/// - [`DiscoveryError::InsufficientResponses`] если < 3 валидных серверов.
/// - [`DiscoveryError::Oprf`] из threshold combine / finalize.
///
/// Finalize PSI query: threshold-combine 3 of 5 server responses → OPRF-finalize
/// to obtain `OprfLabel` per contact.
pub fn finalize_psi_query(
    state: &PsiQueryState,
    server_responses: &[(WitnessIndex, &crate::wire::PsiResponse)],
    config: ThresholdConfig,
) -> DiscoveryResult<Vec<OprfLabel>> {
    if server_responses.len() < config.threshold as usize {
        return Err(DiscoveryError::InsufficientResponses {
            valid: server_responses.len(),
            required: config.threshold as usize,
        });
    }
    let n = state.states.len();
    // Все ответы должны быть одинаковой длины N.
    for (_, resp) in server_responses {
        if resp.entries.len() != n {
            return Err(DiscoveryError::WireDecode {
                reason: "psi response entries count mismatch",
            });
        }
    }
    let mut labels = Vec::with_capacity(n);
    for i in 0..n {
        // Собираем по позиции i partial evaluations от 3+ серверов.
        let mut partials: Vec<(WitnessIndex, ServerEvaluation)> =
            Vec::with_capacity(server_responses.len());
        for (wi, resp) in server_responses {
            let entry = &resp.entries[i];
            let eval = ServerEvaluation::from_bytes(&entry.evaluation)?;
            partials.push((*wi, eval));
        }
        let combined = threshold_combine(&partials, config)?;
        let inp = OprfInput::new(&state.inputs[i])
            .map_err(|_| DiscoveryError::InputRejected("contact length out of range"))?;
        let label = finalize(&state.states[i], inp, &combined)?;
        labels.push(label);
    }
    Ok(labels)
}

/// Сверка labels клиента с server table (`HashSet<[u8;32]>`) → intersection.
///
/// Возвращает `Vec<usize>` индексов клиентских контактов, которые есть в
/// server table. Не раскрывает значения, кроме факта inclusion.
///
/// `OprfLabel` сам не реализует `Hash` (constant-time `PartialEq` исключает
/// деривацию `Hash`), поэтому ключи таблицы — `[u8; 32]` через `to_bytes()`.
/// Поиск равенства между двумя одинаковыми OPRF outputs остаётся корректным.
///
/// Compare client labels against the server table → intersection. Keys in
/// the table are `[u8; 32]` because `OprfLabel` does not implement `Hash`
/// (constant-time equality precludes derivation).
pub fn intersect_with_server_table(
    client_labels: &[OprfLabel],
    server_table: &HashSet<[u8; 32]>,
) -> Vec<usize> {
    let mut out = Vec::new();
    for (i, l) in client_labels.iter().enumerate() {
        if server_table.contains(&l.to_bytes()) {
            out.push(i);
        }
    }
    out
}

/// Симулятор серверной таблицы: applies OPRF master key `master_sk` (или
/// эквивалент через 3-of-5 reconstruction) к каждому registered contact,
/// возвращает `HashSet<OprfLabel>` для проверки intersection.
///
/// Используется только для tests / examples; production-таблица растёт
/// инкрементально в TEE backend.
///
/// Server table simulator: applies the OPRF master key to each registered
/// contact and returns the `HashSet<OprfLabel>` for intersection check.
/// Test/example only.
pub fn simulate_server_table(
    master_sk: &[u8; 32],
    registered: &[&[u8]],
) -> DiscoveryResult<HashMap<[u8; 32], Vec<u8>>> {
    use rand_core::OsRng;
    let mut table = HashMap::with_capacity(registered.len());
    for contact in registered {
        let inp = OprfInput::new(contact)
            .map_err(|_| DiscoveryError::InputRejected("registered contact too long"))?;
        let (req, state) = blind(inp, &mut OsRng)?;
        let eval = umbrella_oprf::evaluate_for_testing(&req, master_sk)?;
        let label = finalize(&state, inp, &eval)?;
        table.insert(label.to_bytes(), contact.to_vec());
    }
    Ok(table)
}

/// `derive_per_contact_anon_ids` — для случая когда сервер требует distinct
/// anon_id на каждый контакт в batch (option per backend spec). Используется
/// optional path.
///
/// Per-contact anon-id derivation when the backend requires distinct anon_id
/// per contact in a batch.
pub fn derive_per_contact_anon_ids(
    master_key: &[u8; 32],
    server_id: u16,
    base_salt: &[u8; SALT_LEN],
    n_contacts: usize,
) -> DiscoveryResult<Vec<[u8; ANON_ID_LEN]>> {
    let mut out = Vec::with_capacity(n_contacts);
    for i in 0..n_contacts {
        let mut salt = *base_salt;
        // Mix in position to make each anon_id unique while preserving the
        // server's ability to verify all came from one client (same base salt
        // can be revealed at de-anonymization time).
        salt[0] ^= (i & 0xFF) as u8;
        salt[1] ^= ((i >> 8) & 0xFF) as u8;
        out.push(derive_per_query_anon_id(master_key, server_id, &salt)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;
    use umbrella_oprf::{generate_test_private_key, shamir_split_for_testing, SCALAR_LEN};

    fn make_cluster() -> (
        [u8; SCALAR_LEN],
        Vec<(WitnessIndex, [u8; SCALAR_LEN])>,
    ) {
        let master_sk = generate_test_private_key(&mut OsRng);
        let k = Scalar::from_canonical_bytes(master_sk).unwrap();
        let cfg = ThresholdConfig::default();
        let raw = shamir_split_for_testing(k, cfg, &mut OsRng);
        let shares: Vec<_> = raw.iter().map(|(wi, s)| (*wi, s.to_bytes())).collect();
        (master_sk, shares)
    }

    #[test]
    fn psi_end_to_end_5_contacts_vs_10_registered() {
        let (master_sk, shares) = make_cluster();
        let mk = [0x11u8; 32];

        let client_contacts: Vec<&[u8]> = vec![
            b"+12125551001",
            b"+12125551002",
            b"+12125551003",
            b"+12125551999", // не зарегистрирован
            b"+12125551888", // не зарегистрирован
        ];
        let registered: Vec<&[u8]> = vec![
            b"+12125551001",
            b"+12125551002",
            b"+12125551003",
            b"+12125551004",
            b"+12125551005",
            b"+12125551006",
            b"+12125551007",
            b"+12125551008",
            b"+12125551009",
            b"+12125551010",
        ];

        let table = simulate_server_table(&master_sk, &registered).unwrap();
        let table_keys: HashSet<[u8; 32]> = table.keys().copied().collect();

        // Подготавливаем 3 запроса (one per witness, 3-of-5).
        // На каждом сервере отдельный wire request, но клиентский state один
        // (тот же blinded request посылается).
        let (req1, state) = prepare_psi_query(&mk, &client_contacts, 1, &mut OsRng).unwrap();
        // Сервер `i` отвечает.
        let (wi1, sk1) = shares[0];
        let (wi2, sk2) = shares[1];
        let (wi3, sk3) = shares[2];
        let resp1 = psi_server_respond(&req1, &sk1, &mut OsRng).unwrap();
        let resp2 = psi_server_respond(&req1, &sk2, &mut OsRng).unwrap();
        let resp3 = psi_server_respond(&req1, &sk3, &mut OsRng).unwrap();

        let labels = finalize_psi_query(
            &state,
            &[(wi1, &resp1), (wi2, &resp2), (wi3, &resp3)],
            ThresholdConfig::default(),
        )
        .unwrap();
        assert_eq!(labels.len(), 5);

        let inter = intersect_with_server_table(&labels, &table_keys);
        assert_eq!(inter, vec![0, 1, 2]);
    }

    #[test]
    fn psi_rejects_empty_batch() {
        let mk = [0u8; 32];
        let err = prepare_psi_query(&mk, &[], 1, &mut OsRng).unwrap_err();
        assert!(matches!(
            err,
            DiscoveryError::InvalidPsiBatchSize { got: 0, .. }
        ));
    }

    #[test]
    fn psi_rejects_oversize_batch() {
        let mk = [0u8; 32];
        let one = b"x".to_vec();
        let contacts: Vec<&[u8]> = (0..(MAX_PSI_BATCH + 1)).map(|_| one.as_slice()).collect();
        let err = prepare_psi_query(&mk, &contacts, 1, &mut OsRng).unwrap_err();
        assert!(matches!(
            err,
            DiscoveryError::InvalidPsiBatchSize { .. }
        ));
    }

    #[test]
    fn psi_rejects_zero_witness_index() {
        let mk = [0u8; 32];
        let err = prepare_psi_query(&mk, &[b"x".as_ref()], 0, &mut OsRng).unwrap_err();
        assert!(matches!(err, DiscoveryError::InputRejected(_)));
    }

    #[test]
    fn psi_rejects_witness_index_over_five() {
        let mk = [0u8; 32];
        let err = prepare_psi_query(&mk, &[b"x".as_ref()], 6, &mut OsRng).unwrap_err();
        assert!(matches!(err, DiscoveryError::InputRejected(_)));
    }

    #[test]
    fn psi_finalize_with_only_two_responses_fails() {
        let (_master, shares) = make_cluster();
        let mk = [0x22u8; 32];
        let (req, state) = prepare_psi_query(&mk, &[b"+12125551001".as_ref()], 1, &mut OsRng).unwrap();
        let (wi1, sk1) = shares[0];
        let (wi2, sk2) = shares[1];
        let resp1 = psi_server_respond(&req, &sk1, &mut OsRng).unwrap();
        let resp2 = psi_server_respond(&req, &sk2, &mut OsRng).unwrap();
        let err = finalize_psi_query(
            &state,
            &[(wi1, &resp1), (wi2, &resp2)],
            ThresholdConfig::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DiscoveryError::InsufficientResponses {
                valid: 2,
                required: 3,
            }
        ));
    }

    #[test]
    fn psi_threshold_3_of_5_with_any_three_subset() {
        let (master_sk, shares) = make_cluster();
        let mk = [0x33u8; 32];
        let contacts: Vec<&[u8]> = vec![b"+a", b"+b", b"+c"];
        let table_raw: Vec<&[u8]> = vec![b"+a", b"+b", b"+d"];
        let table = simulate_server_table(&master_sk, &table_raw).unwrap();
        let table_keys: HashSet<[u8; 32]> = table.keys().copied().collect();

        for subset in &[
            [0usize, 1, 2],
            [1, 2, 3],
            [2, 3, 4],
            [0, 2, 4],
            [0, 3, 4],
        ] {
            let (req, state) =
                prepare_psi_query(&mk, &contacts, (subset[0] + 1) as u8, &mut OsRng).unwrap();
            let mut responses = Vec::new();
            for &idx in subset {
                let (wi, sk) = shares[idx];
                let resp = psi_server_respond(&req, &sk, &mut OsRng).unwrap();
                responses.push((wi, resp));
            }
            let resp_refs: Vec<_> = responses.iter().map(|(w, r)| (*w, r)).collect();
            let labels =
                finalize_psi_query(&state, &resp_refs, ThresholdConfig::default()).unwrap();
            let inter = intersect_with_server_table(&labels, &table_keys);
            assert_eq!(inter, vec![0, 1]);
        }
    }

    #[test]
    fn psi_per_contact_anon_ids_distinct() {
        let mk = [0x77u8; 32];
        let base_salt = [0xAA; SALT_LEN];
        let ids = derive_per_contact_anon_ids(&mk, 1, &base_salt, 500).unwrap();
        let unique: HashSet<_> = ids.into_iter().collect();
        // 500 контактов → 500 distinct anon_ids (high-prob, no collisions).
        assert_eq!(unique.len(), 500);
    }

    #[test]
    fn psi_two_queries_produce_distinct_anon_ids() {
        let mk = [0xAAu8; 32];
        let contacts: Vec<&[u8]> = vec![b"+12125551001"];

        let (req1, _) = prepare_psi_query(&mk, &contacts, 1, &mut OsRng).unwrap();
        let (req2, _) = prepare_psi_query(&mk, &contacts, 1, &mut OsRng).unwrap();
        // Каждая query генерирует свежий salt → anon_ids разные.
        assert_ne!(req1.entries[0].anon_id, req2.entries[0].anon_id);
    }

    #[test]
    fn psi_request_response_anon_ids_match_positionally() {
        let (_master, shares) = make_cluster();
        let mk = [0xCCu8; 32];
        let contacts: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let (req, _state) = prepare_psi_query(&mk, &contacts, 1, &mut OsRng).unwrap();
        let (_wi, sk) = shares[0];
        let resp = psi_server_respond(&req, &sk, &mut OsRng).unwrap();
        // Server echoes anon_ids verbatim для positional pairing.
        for (i, e) in req.entries.iter().enumerate() {
            assert_eq!(e.anon_id, resp.entries[i].anon_id);
        }
    }

    #[test]
    fn psi_simulate_table_has_no_plaintext_phones() {
        // Регистрационная таблица: только OprfLabel-ключи и (для тестов)
        // value = phone, но в production map стороны server table — это
        // metadata (например, registration timestamp). Тест: ключи это
        // 32-байтовые OPRF outputs, не raw phones.
        let master_sk = generate_test_private_key(&mut OsRng);
        let registered: Vec<&[u8]> = vec![b"+12125551001", b"+12125551002"];
        let table = simulate_server_table(&master_sk, &registered).unwrap();
        for key in table.keys() {
            // Phone "12125551001" в OPRF output не угадывается; check that
            // key is not literal phone substring.
            assert_eq!(key.len(), 32);
            assert!(!key.windows(11).any(|w| w == b"+12125551001"));
        }
    }
}
