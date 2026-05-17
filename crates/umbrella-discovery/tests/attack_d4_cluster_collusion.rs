//! D-4 regression: 4-of-5 server cluster collusion still cannot recover
//! the address book OR fabricate a discovery answer that the client accepts.
//!
//! D-4 атака: 4 of 5 серверов скомпрометированы — всё равно нельзя
//! восстановить адресную книгу либо сфабриковать accept'ный ответ.
//!
//! ## Attack model
//!
//! - Adversary controls 4 of 5 Sealed Servers (sk shares 1, 2, 3, 4).
//! - Adversary хочет: (a) восстановить input из transcripts; (b) подменить
//!   discovery answer.
//!
//! ## Defense
//!
//! (a) Несмотря на 4 sk shares, blinding factor `r` ∈ Z_q всё ещё CSPRNG
//!     на клиенте. Адверсарь может evaluate(blinded, k_combined), но
//!     получит k_combined·B, что для адверсаря — известный OPRF output.
//!     Однако invert не может: hash_to_curve preimage по-прежнему unknown.
//!     В этой угрозе: 4-of-5 colluding server group MAY learn the OPRF
//!     label per-input (since with 3 of 5 shares they reconstruct combined
//!     key), но это всё ещё **только labels, not plaintext inputs**.
//!     Plaintext input recovery требует hash_to_curve inversion ИЛИ
//!     знание самого input apriori.
//!
//! (b) Подмена requires forged KT inclusion proof. KT log публичный,
//!     append-only; server вне TEE не может вставить leaf без public
//!     ledger insertion. Client checks pinned_root → fail.
//!
//! ## Acceptance criterion
//!
//! 4-of-5 collusion: server learns N labels (for N inputs in batch) — но
//! не plaintext inputs. Это inherent property OPRF Strong Unlinkability per
//! RFC 9497 §3.

use rand_core::OsRng;
use umbrella_discovery::{
    canonical_leaf_payload, prepare_psi_query, psi_server_respond, simulate_server_table,
    verify_discovery_bind, DiscoveryBindExpectation, DiscoveryError, KtBindKind, KtInclusionProof,
    DEVICE_PUBKEY_LEN, NODE_HASH_LEN,
};
use umbrella_kt::{build_audit_path, leaf_hash, merkle_root};
use umbrella_oprf::generate_test_private_key;

#[test]
fn d4_attack_four_of_five_collusion_no_plaintext_recovery() {
    // Симуляция: 4 colluding servers со своими sk_shares. Они могут
    // reconstruct combined OPRF key через 3 of 5. Затем applying ко всем
    // observed blinded requests → получают labels.
    let master_sk = generate_test_private_key(&mut OsRng);
    let mk = [0xCC; 32];
    let phones = vec![
        b"+12125551001".as_ref(),
        b"+12125551002".as_ref(),
        b"+12125551003".as_ref(),
    ];

    let (req, _state) = prepare_psi_query(&mk, &phones, 1, &mut OsRng).unwrap();

    // Server uses combined OPRF key to evaluate (simulating that 4 colluding
    // servers reconstructed it from their 4 shares). This is the
    // worst-case adversarial scenario — adversary now sees labels.
    let resp = psi_server_respond(&req, &master_sk, &mut OsRng).unwrap();

    // Adversary видит labels (server eval), но НЕ plaintext.
    // Проверка: labels не содержат plaintext substring.
    let wire = resp.encode();
    for p in &phones {
        let found = wire.windows(p.len()).any(|w| w == *p);
        assert!(
            !found,
            "PLAINTEXT LEAK under 4-of-5 collusion: {} appears in resp wire",
            std::str::from_utf8(p).unwrap_or("<binary>")
        );
    }

    // Now: даже если adversary brute-force checks "is OPRF(candidate) ==
    // observed_label?", это работает только для известных candidates. Для
    // arbitrary phone из 10^10 пространства — adversary должен enumerate
    // all candidates (offline attack, defended by rate limit + observable).
    // Это accepted residual property of OPRF; documented в integration spec.

    // Дополнительная sanity: server table simulation для известных registered
    // contacts shows label for known input — этот test показывает что adversary
    // СО ЗНАНИЕМ input может получить label, что в принципе ОК. Но не наоборот.
    let registered: Vec<&[u8]> = vec![b"+12125551001".as_ref()];
    let table = simulate_server_table(&master_sk, &registered).unwrap();
    assert_eq!(table.len(), 1);
}

#[test]
fn d4_attack_four_compromised_servers_cannot_forge_kt_bind() {
    // Сервер cluster contemplates подменить discovery answer для @alice.
    // Чтобы клиент принял: нужен valid KT inclusion proof в pinned epoch root.
    // Pinned root — это публичный value, observe-able from KT witnesses.
    // Сервер не может вставить fake leaf в KT log без публичной insertion.

    let handle = b"@alice";
    let real_pk = [0xAAu8; DEVICE_PUBKEY_LEN];
    let mallory_pk = [0xBBu8; DEVICE_PUBKEY_LEN];
    let epoch = 99;

    // Real KT log с real_pk.
    let real_payload = canonical_leaf_payload(1, handle, &real_pk, epoch);
    let real_leaves = vec![leaf_hash(&real_payload)];
    let real_root = merkle_root(&real_leaves);
    let real_audit = build_audit_path(&real_leaves, 0).unwrap();
    let real_proof = KtInclusionProof {
        epoch_root: real_root,
        tree_size: 1,
        leaf_index: 0,
        leaf_payload: real_payload,
        siblings: real_audit.siblings,
    };

    // Server-controlled fake KT log с mallory_pk.
    let fake_payload = canonical_leaf_payload(1, handle, &mallory_pk, epoch);
    let fake_leaves = vec![leaf_hash(&fake_payload)];
    let fake_root = merkle_root(&fake_leaves);
    let fake_audit = build_audit_path(&fake_leaves, 0).unwrap();
    let fake_proof = KtInclusionProof {
        epoch_root: fake_root,
        tree_size: 1,
        leaf_index: 0,
        leaf_payload: fake_payload,
        siblings: fake_audit.siblings,
    };

    // Клиент pinned real_root. Получает fake_proof — несовпадение по
    // epoch_root.
    let exp = DiscoveryBindExpectation {
        epoch,
        pinned_epoch_root: &real_root,
        expected_device_pubkey: None,
        handle_kind: 1,
        handle,
    };
    let err = verify_discovery_bind(&fake_proof, &exp).unwrap_err();
    assert!(matches!(
        err,
        DiscoveryError::KtBindFailed {
            kind: KtBindKind::RootForked
        }
    ));

    // А реальная proof (с real_pk) проходит:
    let real_pk_out = verify_discovery_bind(&real_proof, &exp).unwrap();
    assert_eq!(real_pk_out, real_pk);
}

#[test]
fn d4_attack_compromised_servers_cannot_inject_fake_leaf_into_real_root() {
    // Атакующий: пытается выдать fake_pk но reuse real_root (просто
    // выставить fake leaf при real merkle root). Это требует second-preimage
    // attack на SHA-256 — computationally infeasible.
    let handle = b"@alice";
    let real_pk = [0x11u8; DEVICE_PUBKEY_LEN];
    let fake_pk = [0x22u8; DEVICE_PUBKEY_LEN];
    let epoch = 5;

    let real_payload = canonical_leaf_payload(1, handle, &real_pk, epoch);
    let real_leaves = vec![leaf_hash(&real_payload)];
    let real_root = merkle_root(&real_leaves);
    let real_audit = build_audit_path(&real_leaves, 0).unwrap();

    // Server constructs proof с fake leaf_payload BUT siblings из real audit
    // path. Это аттакующий хочет показать: "вот leaf для (handle, fake_pk,
    // epoch), audit path = real". Но recomputed root от fake leaf ≠ real_root.
    let fake_payload = canonical_leaf_payload(1, handle, &fake_pk, epoch);
    let forged_proof = KtInclusionProof {
        epoch_root: real_root, // unchanged
        tree_size: 1,
        leaf_index: 0,
        leaf_payload: fake_payload,
        siblings: real_audit.siblings,
    };
    let exp = DiscoveryBindExpectation {
        epoch,
        pinned_epoch_root: &real_root,
        expected_device_pubkey: None,
        handle_kind: 1,
        handle,
    };
    let err = verify_discovery_bind(&forged_proof, &exp).unwrap_err();
    // Forged leaf reconstructs different root → KtBindFailed.
    let _ = NODE_HASH_LEN;
    assert!(matches!(
        err,
        DiscoveryError::KtBindFailed {
            kind: KtBindKind::ProofMismatch
        }
    ));
}
