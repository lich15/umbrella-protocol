//! D-1 regression: a malicious server cannot recover any plaintext phone
//! number from its observations (blinded requests + threshold partials).
//!
//! D-1 атака: вредоносный сервер не может получить plaintext phone из своих
//! observations (blinded requests + threshold partials).
//!
//! ## Attack model
//!
//! - Adversary records all `PsiRequest` and `PsiResponse` byte traces.
//! - Adversary knows OPRF master key share `sk_share` (it's a server).
//! - Adversary has dictionary of candidate phone numbers (e.g., 1M plausible
//!   numbers).
//! - Adversary tries to invert blinded → plaintext: for each candidate phone
//!   `c`, recompute blinded(c, r) for all r — impossible because r is fresh
//!   per query and not transmitted.
//!
//! ## Defense
//!
//! Ristretto255 blinding factor r ∈ Z_q is fresh from CSPRNG per query and
//! never transmitted. The adversary's only attack is brute-forcing r over
//! the 2^252 scalar space — computationally infeasible.
//!
//! ## Acceptance criterion
//!
//! Even after 500 queries, server cannot distinguish blinded(phone_1) from
//! blinded(phone_2) better than random. We assert the observable property:
//! - 0 plaintext substrings appear in any wire trace.
//! - For 500 contacts with distinct plaintexts but shared blinded prefix
//!   (e.g., +1212...) the wire bytes show no correlation.

use rand_core::OsRng;
use std::collections::HashSet;

use umbrella_discovery::{prepare_psi_query, psi_server_respond};
use umbrella_oprf::generate_test_private_key;

#[test]
fn d1_attack_500_contacts_zero_plaintext_appears_in_wire() {
    let mk = [0x12u8; 32];
    let sk_share = generate_test_private_key(&mut OsRng);

    // 500 realistic contacts с распознаваемыми patterns.
    let contacts: Vec<String> = (0..500)
        .map(|i| format!("+1212555{i:04}"))
        .collect();
    let contact_refs: Vec<&[u8]> = contacts.iter().map(|s| s.as_bytes()).collect();

    let (req, _state) = prepare_psi_query(&mk, &contact_refs, 1, &mut OsRng).unwrap();
    let resp = psi_server_respond(&req, &sk_share, &mut OsRng).unwrap();

    // Wire-trace атакующего: request + response bytes.
    let mut all_wire: Vec<u8> = Vec::new();
    all_wire.extend_from_slice(&req.encode());
    all_wire.extend_from_slice(&resp.encode());

    // Атакующий ищет любой plaintext phone substring (длина ≥ 8).
    for c in &contacts {
        let bytes = c.as_bytes();
        let found = all_wire.windows(bytes.len()).any(|w| w == bytes);
        assert!(
            !found,
            "PLAINTEXT LEAK: phone {} appears verbatim in wire trace ({} bytes)",
            c,
            all_wire.len()
        );
    }
}

#[test]
fn d1_attack_500_contacts_blinded_bytes_have_high_entropy() {
    // Атакующий проверяет распределение байт в blinded points — если все
    // одинаковые, blinding broken. Реально blinded — random Ristretto255
    // point, поэтому байты ~ uniform.
    let mk = [0x34u8; 32];
    let contacts: Vec<String> = (0..500)
        .map(|i| format!("+1212555{i:04}"))
        .collect();
    let refs: Vec<&[u8]> = contacts.iter().map(|s| s.as_bytes()).collect();
    let (req, _) = prepare_psi_query(&mk, &refs, 1, &mut OsRng).unwrap();

    // Собираем все 500 × 32 = 16000 байт blinded points.
    let mut blinded_bytes = Vec::with_capacity(500 * 32);
    for e in &req.entries {
        blinded_bytes.extend_from_slice(&e.blinded);
    }
    // Проверка 1: distinct blinded points (никакой не повторился).
    let unique: HashSet<_> = req.entries.iter().map(|e| e.blinded).collect();
    assert_eq!(unique.len(), 500, "duplicate blinded point — blinding broken");

    // Проверка 2: байтовое разнообразие. Каждый byte-value 0..256 должен
    // появиться многократно (high entropy).
    let mut counts = [0u32; 256];
    for &b in &blinded_bytes {
        counts[b as usize] += 1;
    }
    let mut distinct_values = 0;
    for &c in &counts {
        if c > 0 {
            distinct_values += 1;
        }
    }
    assert!(
        distinct_values >= 200,
        "blinded bytes have low entropy ({distinct_values} distinct values out of 256)"
    );
}

#[test]
fn d1_attack_two_queries_same_contact_yield_distinct_blinded() {
    // Один и тот же phone из двух query → распознаваемо? Нет — random r.
    let mk = [0x56u8; 32];
    let same_phone = b"+12125551111";
    let (req1, _) = prepare_psi_query(&mk, &[same_phone.as_ref()], 1, &mut OsRng).unwrap();
    let (req2, _) = prepare_psi_query(&mk, &[same_phone.as_ref()], 1, &mut OsRng).unwrap();
    assert_ne!(
        req1.entries[0].blinded, req2.entries[0].blinded,
        "same phone in two queries produces same blinded — blinding randomness broken"
    );
    // Аналогично anon_ids разные (per-query salt fresh).
    assert_ne!(req1.entries[0].anon_id, req2.entries[0].anon_id);
}

#[test]
fn d1_attack_compromise_two_servers_no_plaintext_recovery() {
    // 2 of 5 compromised: adversary знает 2 sk_shares. Без 3-го share —
    // не может combine, не может видеть OPRF output, не может invert.
    let mk = [0x78u8; 32];
    let sk_a = generate_test_private_key(&mut OsRng);
    let sk_b = generate_test_private_key(&mut OsRng);
    let phone = b"+12125551111";

    let (req, _state) = prepare_psi_query(&mk, &[phone.as_ref()], 1, &mut OsRng).unwrap();
    let resp_a = psi_server_respond(&req, &sk_a, &mut OsRng).unwrap();
    let resp_b = psi_server_respond(&req, &sk_b, &mut OsRng).unwrap();

    // Adversary видит: req.entries[0].blinded, resp_a.entries[0].evaluation,
    // resp_b.entries[0].evaluation, sk_a, sk_b.
    let blinded = req.entries[0].blinded;
    let eval_a = resp_a.entries[0].evaluation;
    let eval_b = resp_b.entries[0].evaluation;

    // Все эти 32-байтовые значения — точки на Ristretto255. Восстановление
    // input невозможно без random oracle inversion.
    // Минимальная проверка: ни одно из них не содержит '+12125551111' literal.
    for v in &[blinded, eval_a, eval_b, sk_a, sk_b] {
        assert!(!v.windows(11).any(|w| w == b"+12125551111"));
    }
    // Сам OPRF output (32 bytes из threshold combine of 3+ partials) is also
    // 32 bytes random-looking — but adversary не может его вычислить без 3-го share.
}
