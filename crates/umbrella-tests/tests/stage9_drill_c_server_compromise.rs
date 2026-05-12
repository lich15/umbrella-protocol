//! Drill C — Server compromise recovery: симуляция utterly compromised
//! delivery service, переключение клиентов на redundant region, проверка
//! что sealed-sender V2 X-Wing envelopes остаются confidential под
//! compromise (PQ confidentiality invariant блока 9.4 sealed-sender V2),
//! проверка KT log integrity через 3-of-5 multi-witness consensus,
//! контроль end-to-end timing внутри 24-часового бюджета.
//!
//! Drill C — Server compromise recovery: simulates an utterly compromised
//! delivery service, switches clients to a redundant region, verifies that
//! sealed-sender V2 X-Wing envelopes remain confidential under compromise
//! (PQ confidentiality invariant of block 9.4 sealed-sender V2), verifies
//! KT log integrity via 3-of-5 multi-witness consensus, and asserts
//! end-to-end timing within the 24-hour budget.
//!
//! ## Сценарий
//!
//! Single delivery service region полностью compromise. Adversary имеет full
//! read access к sealed-sender envelopes + KT log + user metadata. Production
//! decision: switch к redundant region за < 24 часа.
//!
//! Privacy invariant блока 9.4 (sealed-sender V2 X-Wing): даже при server
//! compromise content envelope'а остаётся confidential — adversary видит
//! только metadata-stripped wire (recipient_id, timestamp), но не plaintext.
//! V2 envelope использует X-Wing combiner KEM (X25519 + ML-KEM-768) на
//! ephemeral basis; для расшифровки требуется recipient X-Wing secret seed,
//! которого у скомпрометированного сервера нет (sealed-sender hides sender
//! identity AND content from delivery service).
//!
//! KT log integrity: после switch к redundant region клиенты проверяют
//! log root через 3-of-5 multi-witness consensus (witness servers расположены
//! в разных юрисдикциях; capture одного региона недостаточен для split-view
//! attack — adversary должен co-opt'ить 3 из 5 jurisdictions).
//!
//! Target timing: < 24 часа end-to-end.
//!
//! ## Scenario
//!
//! A single delivery service region is utterly compromised. The adversary
//! has full read access to sealed-sender envelopes + KT log + user metadata.
//! Production decision: switch to a redundant region within 24 hours.
//!
//! Privacy invariant of block 9.4 (sealed-sender V2 X-Wing): even under
//! server compromise the envelope content stays confidential — the adversary
//! sees only metadata-stripped wire (recipient_id, timestamp), not the
//! plaintext. The V2 envelope uses an X-Wing combiner KEM (X25519 +
//! ML-KEM-768) on an ephemeral basis; decryption requires the recipient's
//! X-Wing secret seed, which the compromised server does not have
//! (sealed-sender hides sender identity AND content from the delivery
//! service).
//!
//! KT log integrity: after switching to the redundant region, clients verify
//! the log root via 3-of-5 multi-witness consensus (witness servers are in
//! distinct jurisdictions; capturing one region is insufficient for a
//! split-view attack — the adversary must co-opt 3 of 5 jurisdictions).
//!
//! Target timing: < 24 hours end-to-end.
//!
//! ## Связанные документы / Related documents
//!
//! - Operational runbook — `docs/operations/drill_c_server_compromise.md`.
//! - Design reference — `docs/adr/ADR-012-hardening.md` §7.4.3.
//! - Implementation plan — `docs/adr/ADR-012-hardening.md` §9.9.3.
//! - Sealed-sender V2 X-Wing — `crates/umbrella-sealed-sender/src/hybrid_envelope.rs`.
//! - Multi-witness 3-of-5 — `crates/umbrella-kt/src/witness.rs`.

#![cfg(feature = "pq")]

use std::sync::Arc;

use rand_core::OsRng;

use umbrella_crypto_primitives::sig::PrivateSigningKey;
use umbrella_identity::{Clock, IdentitySeed, InMemoryKeyStore, MnemonicLanguage, SystemClock};
use umbrella_kt::{
    canonical_sign_payload, verify_signed_epoch, KtError, SignedEpochRoot, WitnessPublic,
    WitnessSet, WitnessSignature,
};
use umbrella_pq::{xwing_keygen, XWingPublicKey, XWingSecretSeed};
use umbrella_sealed_sender::{seal_v2, unseal_v2, V2_MIN_WIRE_LEN};

// ─────────────────────────────────────────────────────────────────────────
// Drill timing + topology constants.
// Drill timing + topology constants.
// ─────────────────────────────────────────────────────────────────────────

const DRILL_USER_COUNT: usize = 5;
const SECS_PER_HOUR: u64 = 3600;
const TARGET_RECOVERY_BUDGET_SECS: u64 = 24 * SECS_PER_HOUR;

const T_COMPROMISE_DETECTED: u64 = 1_700_000_000;
const T_REGION_SWITCH_DELAY: u64 = 4 * SECS_PER_HOUR;
const T_DNS_PROPAGATION_DELAY: u64 = 8 * SECS_PER_HOUR;
const T_USER_NOTIFICATION_DELAY: u64 = 16 * SECS_PER_HOUR;
const T_FULL_RECOVERY_DELAY: u64 = 24 * SECS_PER_HOUR;

const WITNESS_TOTAL: usize = 5;
const WITNESS_THRESHOLD: usize = 3;

const PRIMARY_REGION: &str = "https://delivery-eu-fra.umbrellax.example/v1";
const SECONDARY_REGION: &str = "https://delivery-us-iad.umbrellax.example/v1";

/// Контрольное сообщение для V2 envelope test'ов — короткий plaintext,
/// помещается в minimum padding bucket (256 bytes).
/// Control message for V2 envelope tests — short plaintext, fits the minimum
/// padding bucket (256 bytes).
const SECRET_PLAINTEXT: &[u8] = b"highly-confidential-payload-drill-c";

// ─────────────────────────────────────────────────────────────────────────
// Test types — region config, witness, drill user, helpers.
// Test types — region config, witness, drill user, helpers.
// ─────────────────────────────────────────────────────────────────────────

/// Состояние delivery service region (один из двух регионов в drill).
/// Compromised region помечается явно — operator switches client config
/// на secondary до DNS propagation.
///
/// Delivery service region state (one of the two regions in the drill).
/// A compromised region is explicitly flagged — the operator switches client
/// config to the secondary while DNS propagates.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DeliveryRegion {
    name: &'static str,
    url: &'static str,
    compromised: bool,
}

/// Test witness — Ed25519 keypair + jurisdiction tag для tracking где witness
/// расположен (в production они в Германии, США, Швейцарии, Сингапуре,
/// Бразилии — здесь stub-метки).
///
/// Test witness — Ed25519 keypair + jurisdiction tag for tracking where the
/// witness lives (in production they are in Germany, US, Switzerland,
/// Singapore, Brazil — here we use stub tags).
struct TestWitness {
    sk: PrivateSigningKey,
    pk: WitnessPublic,
    jurisdiction: &'static str,
}

fn fresh_witness(jurisdiction: &'static str) -> TestWitness {
    let mut rng = OsRng;
    let sk = PrivateSigningKey::generate(&mut rng);
    let pk_bytes = sk.verifying_key().to_bytes();
    TestWitness {
        sk,
        pk: WitnessPublic::from_bytes(pk_bytes),
        jurisdiction,
    }
}

/// Drill user — full keystore (для sealed-sender inner sig + recipient
/// identity) + dedicated X-Wing keypair (recipient X-Wing pubkey + secret
/// seed для sealed-sender V2). В production X-Wing keypair derived от
/// IdentitySeed через `umbrella-identity::cloud_wrap_recovery`; здесь
/// используется fresh `xwing_keygen` для test isolation.
///
/// Drill user — full keystore (for sealed-sender inner sig + recipient
/// identity) + dedicated X-Wing keypair (recipient X-Wing pubkey + secret
/// seed for sealed-sender V2). In production the X-Wing keypair is derived
/// from IdentitySeed via `umbrella-identity::cloud_wrap_recovery`; here we
/// use fresh `xwing_keygen` for test isolation.
struct DrillUser {
    keystore: Arc<InMemoryKeyStore>,
    xwing_pubkey: XWingPublicKey,
    xwing_seed: XWingSecretSeed,
}

fn fresh_drill_user() -> DrillUser {
    let mut rng = OsRng;
    let seed = IdentitySeed::generate(&mut rng, MnemonicLanguage::English);
    let keystore = Arc::new(
        InMemoryKeyStore::open(seed, 0, Arc::new(SystemClock) as Arc<dyn Clock>)
            .expect("keystore open"),
    );
    let (xwing_pubkey, xwing_seed) = xwing_keygen(&mut rng).expect("xwing keygen");
    DrillUser {
        keystore,
        xwing_pubkey,
        xwing_seed,
    }
}

fn build_witness_set(witnesses: &[&TestWitness]) -> WitnessSet {
    let mut set = WitnessSet::new();
    for w in witnesses {
        set.add(w.pk);
    }
    set
}

fn sign_epoch_with_witnesses(
    witnesses: &[&TestWitness],
    epoch: u64,
    root: &[u8; 32],
) -> Vec<WitnessSignature> {
    let payload = canonical_sign_payload(epoch, root, 1, 1_700_000_000_000);
    witnesses
        .iter()
        .map(|w| WitnessSignature {
            witness: w.pk,
            signature: w.sk.sign(&payload).to_bytes(),
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────
// Drill scenarios.
// Drill scenarios.
// ─────────────────────────────────────────────────────────────────────────

/// Pre-compromise baseline: primary region active, V2 envelopes пересылаются
/// нормально, KT log epoch имеет 5-of-5 valid witness signatures.
///
/// Pre-compromise baseline: primary region active, V2 envelopes flow
/// normally, the KT log epoch has 5-of-5 valid witness signatures.
#[test]
fn c1_baseline_pre_compromise_state() {
    let primary = DeliveryRegion {
        name: "EU-FRA",
        url: PRIMARY_REGION,
        compromised: false,
    };
    let secondary = DeliveryRegion {
        name: "US-IAD",
        url: SECONDARY_REGION,
        compromised: false,
    };
    assert_ne!(primary.url, secondary.url);
    assert!(!primary.compromised);

    let alice = fresh_drill_user();
    let bob = fresh_drill_user();
    let mut rng = OsRng;

    let envelope = seal_v2(
        alice.keystore.as_ref(),
        &bob.xwing_pubkey,
        SECRET_PLAINTEXT,
        &mut rng,
    )
    .expect("seal V2");
    assert!(envelope.len() >= V2_MIN_WIRE_LEN);
    assert_eq!(envelope[0], 0x02, "V2 wire starts с version byte 0x02");

    let opened = unseal_v2(
        bob.keystore.as_ref(),
        &bob.xwing_pubkey,
        &bob.xwing_seed,
        &envelope,
    )
    .expect("recipient unseal");
    assert_eq!(opened.message, SECRET_PLAINTEXT);
}

/// Compromise detected → operator switches client config с primary на
/// secondary region. После switch primary marked compromised; новые
/// envelope sends идут через secondary.
///
/// Compromise detected → operator switches client config from primary to
/// secondary region. After the switch, primary is marked compromised; new
/// envelope sends go through secondary.
#[test]
fn c2_region_switch_after_compromise() {
    let mut primary = DeliveryRegion {
        name: "EU-FRA",
        url: PRIMARY_REGION,
        compromised: false,
    };
    let secondary = DeliveryRegion {
        name: "US-IAD",
        url: SECONDARY_REGION,
        compromised: false,
    };

    // T+0: compromise detected.
    primary.compromised = true;
    assert!(primary.compromised);

    // T+4h: operator switches client config к secondary.
    let active_region = if primary.compromised {
        &secondary
    } else {
        &primary
    };
    assert_eq!(active_region.url, SECONDARY_REGION);
    assert!(!active_region.compromised);

    // Smoke: new envelope sent через secondary.
    let alice = fresh_drill_user();
    let bob = fresh_drill_user();
    let mut rng = OsRng;
    let envelope = seal_v2(
        alice.keystore.as_ref(),
        &bob.xwing_pubkey,
        SECRET_PLAINTEXT,
        &mut rng,
    )
    .expect("seal V2 на secondary");
    let opened = unseal_v2(
        bob.keystore.as_ref(),
        &bob.xwing_pubkey,
        &bob.xwing_seed,
        &envelope,
    )
    .expect("unseal V2");
    assert_eq!(opened.message, SECRET_PLAINTEXT);
}

/// Privacy invariant блока 9.4: даже если adversary имеет full read access
/// к envelope wire bytes (compromise delivery service), он не может
/// расшифровать content без recipient's X-Wing secret seed. Test simulates
/// adversary holding wire bytes + recipient's X-Wing pubkey (public info)
/// но не secret seed — все попытки unseal fail.
///
/// Privacy invariant of block 9.4: even if the adversary has full read
/// access to envelope wire bytes (compromised delivery service), they
/// cannot decrypt the content without the recipient's X-Wing secret seed.
/// The test simulates an adversary holding wire bytes + recipient's X-Wing
/// pubkey (public info) but not the secret seed — all unseal attempts fail.
#[test]
fn c3_v2_envelope_confidential_under_compromise() {
    let alice = fresh_drill_user();
    let bob = fresh_drill_user();
    let mut rng = OsRng;

    // Alice sends sealed-sender V2 envelope к Bob через primary (compromised).
    let envelope = seal_v2(
        alice.keystore.as_ref(),
        &bob.xwing_pubkey,
        SECRET_PLAINTEXT,
        &mut rng,
    )
    .expect("seal V2");

    // Adversary получает full wire bytes (compromise) + Bob's public X-Wing
    // pubkey (public info из KT log). Но adversary не имеет Bob's X-Wing
    // secret seed — он защищён в Bob's secure enclave.
    // Adversary creates own X-Wing keypair (как stand-in для попыток).
    let (_adversary_pk, adversary_seed) = xwing_keygen(&mut rng).expect("adversary keygen");

    // Adversary пытается unseal с собственным seed → fails (different shared secret).
    let result = unseal_v2(
        bob.keystore.as_ref(),
        &bob.xwing_pubkey,
        &adversary_seed,
        &envelope,
    );
    assert!(
        result.is_err(),
        "adversary с own X-Wing seed не может unseal — privacy preserved"
    );

    // Bob с correct seed — успешно unseal.
    let opened = unseal_v2(
        bob.keystore.as_ref(),
        &bob.xwing_pubkey,
        &bob.xwing_seed,
        &envelope,
    )
    .expect("Bob unseal");
    assert_eq!(opened.message, SECRET_PLAINTEXT);
}

/// Adversary не может tamper envelope без detection: bit flip → AEAD
/// decrypt fails (ChaCha20-Poly1305 integrity); replace recipient pubkey
/// в AAD → decrypt fails. Это закрывает active adversary path (compromise
/// delivery service может modify wire bytes на лету).
///
/// Adversary cannot tamper the envelope without detection: bit flip → AEAD
/// decrypt fails (ChaCha20-Poly1305 integrity); replacing the recipient
/// pubkey in AAD → decrypt fails. Closes the active adversary path
/// (compromised delivery service can modify wire bytes on the fly).
#[test]
fn c4_v2_envelope_tamper_detected_under_compromise() {
    let alice = fresh_drill_user();
    let bob = fresh_drill_user();
    let mut rng = OsRng;

    let mut envelope = seal_v2(
        alice.keystore.as_ref(),
        &bob.xwing_pubkey,
        SECRET_PLAINTEXT,
        &mut rng,
    )
    .expect("seal V2");

    // Adversary меняет 1 bit в last byte (часть AEAD ciphertext).
    let last = envelope.len() - 1;
    envelope[last] ^= 0x01;

    let result = unseal_v2(
        bob.keystore.as_ref(),
        &bob.xwing_pubkey,
        &bob.xwing_seed,
        &envelope,
    );
    assert!(
        result.is_err(),
        "tampered envelope rejected — AEAD integrity"
    );
}

/// 5 Sealed Servers с witness signatures — 3-of-5 consensus passes, KT log
/// integrity verified после switch к redundant region.
///
/// 5 Sealed Servers with witness signatures — 3-of-5 consensus passes, KT
/// log integrity verified after the switch to the redundant region.
#[test]
fn c5_kt_log_integrity_via_three_of_five_witness_consensus() {
    let witnesses: Vec<TestWitness> = vec![
        fresh_witness("DE"),
        fresh_witness("US"),
        fresh_witness("CH"),
        fresh_witness("SG"),
        fresh_witness("BR"),
    ];
    let witness_refs: Vec<&TestWitness> = witnesses.iter().collect();
    let set = build_witness_set(&witness_refs);
    assert_eq!(set.len(), WITNESS_TOTAL);

    let epoch = 42;
    let root = [0xAB; 32];

    // 3-of-5 подписей: DE + US + CH (2 jurisdictions потеряны / compromised
    // — SG и BR не доступны после switch).
    let signing_witnesses: Vec<&TestWitness> = witness_refs.iter().take(3).copied().collect();
    let sigs = sign_epoch_with_witnesses(&signing_witnesses, epoch, &root);
    let signed = SignedEpochRoot {
        epoch,
        root,
        log_size: 1,
        timestamp_unix_millis: 1_700_000_000_000,
        signatures: sigs,
    };

    verify_signed_epoch(&signed, &set, WITNESS_THRESHOLD).expect("3-of-5 consensus passes");

    // 2-of-5 — fails (только DE + US доступны).
    let only_two: Vec<&TestWitness> = witness_refs.iter().take(2).copied().collect();
    let sigs_two = sign_epoch_with_witnesses(&only_two, epoch, &root);
    let signed_two = SignedEpochRoot {
        epoch,
        root,
        log_size: 1,
        timestamp_unix_millis: 1_700_000_000_000,
        signatures: sigs_two,
    };
    let err = verify_signed_epoch(&signed_two, &set, WITNESS_THRESHOLD).expect_err("2-of-5 fails");
    assert!(matches!(
        err,
        KtError::InsufficientValidSignatures {
            valid: 2,
            required: 3
        }
    ));
}

/// Split-view attack: compromised delivery service shows divergent log
/// roots для разных users. Multi-witness 3-of-5 consensus защищает —
/// witnesses подписывают only one root per epoch; signed entries для
/// разных roots не получают threshold консенсус одновременно.
///
/// Split-view attack: a compromised delivery service shows divergent log
/// roots to different users. Multi-witness 3-of-5 consensus protects —
/// witnesses sign only one root per epoch; signed entries for different
/// roots cannot reach threshold consensus simultaneously.
#[test]
fn c6_split_view_defeated_by_witness_consensus() {
    let witnesses: Vec<TestWitness> = vec![
        fresh_witness("DE"),
        fresh_witness("US"),
        fresh_witness("CH"),
        fresh_witness("SG"),
        fresh_witness("BR"),
    ];
    let witness_refs: Vec<&TestWitness> = witnesses.iter().collect();
    let set = build_witness_set(&witness_refs);

    let epoch = 100;
    let root_a = [0xAA; 32];
    let root_b = [0xBB; 32];

    // Witnesses подписывают root_a (canonical).
    let sigs_a = sign_epoch_with_witnesses(&witness_refs, epoch, &root_a);

    // Compromise delivery service представляет root_b пользователю с
    // подписями над root_a — verify падает (signatures не verify над root_b).
    let signed_split = SignedEpochRoot {
        epoch,
        root: root_b,
        log_size: 1,
        timestamp_unix_millis: 1_700_000_000_000,
        signatures: sigs_a,
    };
    let err = verify_signed_epoch(&signed_split, &set, WITNESS_THRESHOLD)
        .expect_err("split-view detected");
    assert!(matches!(
        err,
        KtError::InsufficientValidSignatures { valid: 0, .. }
    ));
}

/// Timing budget: каждый шаг operator timeline ≥ предыдущего; общий elapsed
/// time ≤ 24h budget.
///
/// Timing budget: each operator timeline step is ≥ the previous; total
/// elapsed time ≤ 24h budget.
#[test]
fn c7_recovery_timing_within_24h_budget() {
    let detected_ts = T_COMPROMISE_DETECTED;
    let switch_ts = detected_ts + T_REGION_SWITCH_DELAY;
    let dns_ts = detected_ts + T_DNS_PROPAGATION_DELAY;
    let notification_ts = detected_ts + T_USER_NOTIFICATION_DELAY;
    let full_ts = detected_ts + T_FULL_RECOVERY_DELAY;

    assert!(switch_ts >= detected_ts);
    assert!(dns_ts >= switch_ts);
    assert!(notification_ts >= dns_ts);
    assert!(full_ts >= notification_ts);

    let elapsed = full_ts - detected_ts;
    assert!(
        elapsed <= TARGET_RECOVERY_BUDGET_SECS,
        "recovery took {elapsed}s, budget {TARGET_RECOVERY_BUDGET_SECS}s"
    );
    assert_eq!(elapsed, 24 * SECS_PER_HOUR);
}

/// 5-user drill end-to-end: каждый пользователь имеет independent X-Wing
/// keypair, отправляет/получает confidential V2 envelope через post-switch
/// secondary region; никаких cross-user envelope cross-decryption (privacy
/// isolation).
///
/// 5-user drill end-to-end: every user has an independent X-Wing keypair,
/// sends/receives a confidential V2 envelope through the post-switch
/// secondary region; no cross-user envelope cross-decryption (privacy
/// isolation).
#[test]
fn c8_five_user_drill_end_to_end() {
    let users: Vec<DrillUser> = (0..DRILL_USER_COUNT).map(|_| fresh_drill_user()).collect();
    let mut rng = OsRng;

    // Pairwise: каждая пара (sender, recipient) sends V2 envelope.
    for i in 0..users.len() {
        for j in 0..users.len() {
            if i == j {
                continue;
            }
            let sender = &users[i];
            let recipient = &users[j];

            let envelope = seal_v2(
                sender.keystore.as_ref(),
                &recipient.xwing_pubkey,
                SECRET_PLAINTEXT,
                &mut rng,
            )
            .expect("seal V2");

            // Recipient успешно unseal.
            let opened = unseal_v2(
                recipient.keystore.as_ref(),
                &recipient.xwing_pubkey,
                &recipient.xwing_seed,
                &envelope,
            )
            .expect("recipient unseal");
            assert_eq!(opened.message, SECRET_PLAINTEXT);

            // Cross-user: другой пользователь не может unseal (privacy isolation).
            let other_idx = (j + 1) % users.len();
            if other_idx != j {
                let other = &users[other_idx];
                let result = unseal_v2(
                    other.keystore.as_ref(),
                    &other.xwing_pubkey,
                    &other.xwing_seed,
                    &envelope,
                );
                assert!(
                    result.is_err(),
                    "user {other_idx} не должен unseal envelope для user {j}"
                );
            }
        }
    }
}

/// Verify witness jurisdictions diversity: 5 witnesses в 5 разных
/// jurisdictions (DE/US/CH/SG/BR) — no single jurisdiction has threshold
/// influence. Это soft assertion (jurisdiction tags только в test'ах,
/// не enforced в protocol layer).
///
/// Verify witness jurisdictions diversity: 5 witnesses across 5 distinct
/// jurisdictions (DE/US/CH/SG/BR) — no single jurisdiction has threshold
/// influence. This is a soft assertion (jurisdiction tags exist in tests
/// only, not enforced at the protocol layer).
#[test]
fn c9_witness_set_jurisdiction_diversity() {
    let witnesses: Vec<TestWitness> = vec![
        fresh_witness("DE"),
        fresh_witness("US"),
        fresh_witness("CH"),
        fresh_witness("SG"),
        fresh_witness("BR"),
    ];

    let mut jurisdictions: Vec<&str> = witnesses.iter().map(|w| w.jurisdiction).collect();
    jurisdictions.sort();
    jurisdictions.dedup();
    assert_eq!(
        jurisdictions.len(),
        WITNESS_TOTAL,
        "5 witnesses в 5 distinct jurisdictions"
    );

    // Threshold = 3: adversary must coordinate pressure на 3 jurisdictions.
    // Const compile-time invariants — design contract enforcement (постулат 14):
    // - threshold < total (фактический threshold, не unanimous);
    // - threshold * 2 > total (majority — Byzantine fault tolerance).
    // Const compile-time invariants — design contract enforcement (postulate 14):
    // - threshold < total (an actual threshold, not unanimous);
    // - threshold * 2 > total (majority — Byzantine fault tolerance).
    const _: () = assert!(WITNESS_THRESHOLD < WITNESS_TOTAL);
    const _: () = assert!(WITNESS_THRESHOLD * 2 > WITNESS_TOTAL);
    assert_eq!(WITNESS_THRESHOLD, 3);
}
