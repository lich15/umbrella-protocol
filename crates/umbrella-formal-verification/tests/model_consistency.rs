//! Model consistency tests для Tamarin / ProVerif моделей.
//!
//! Pattern H lessons (WORKING_RULES.md): «Tamarin model =
//! private protocol citation + property + axioms». Эти tests верифицируют что
//! `spec_reference` + `spec_version` в metadata согласованы между собой, и что
//! `properties` list совпадает с lemma names в .spthy / .pv файлах. Запускаются
//! на каждом push (не только weekly), потому что они гораздо дешевле полной
//! Tamarin / ProVerif верификации (~миллисекунды vs ~30 минут per model).
//!
//! # Module: model_consistency tests (English)
//!
//! Pattern H lessons (WORKING_RULES.md): "Tamarin model =
//! private protocol citation + property + axioms". These tests verify that
//! `spec_reference` + `spec_version` in metadata are internally consistent, and
//! that the `properties` list matches the lemma names in the .spthy / .pv files.
//! They run on every push (not only weekly) because they are far cheaper than a
//! full Tamarin / ProVerif verification (~milliseconds vs ~30 minutes per model).

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use umbrella_formal_verification::{
    ModelMetadata, ProtocolType, VerificationStatus, ALL_MODELS, BACKUP_WRAP_V2, DISCOVERY,
    DOWNGRADE_RESISTANCE, HYBRID_SIGNATURE_AND_MODE, KT_V1_SELF_MONITORING, KT_V2_SELF_MONITORING,
    MLS_ED25519, MULTI_DEVICE_AUTHORIZATION, OPRF_RISTRETTO255, SEALED_SENDER_V1, SEALED_SENDER_V2,
    SFRAME_RFC9605, TYPE_SAFE_ENFORCEMENT, XWING_COMBINER,
};

/// Корень крейта (`crates/umbrella-formal-verification`) — set Cargo при build.
/// Crate root (`crates/umbrella-formal-verification`) — set by Cargo at build.
const CRATE_ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Чтение файла модели (panics на error для clear test failure).
/// Read a model file (panics on error for a clear test failure).
fn read_model(meta: &ModelMetadata) -> String {
    let path = Path::new(CRATE_ROOT).join(meta.model_path);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read model {path:?}: {e}"))
}

/// Extract a single ProVerif `let NAME = ...` process block.
/// Извлекает один ProVerif `let NAME = ...` process block.
fn pv_let_block<'a>(body: &'a str, name: &str) -> &'a str {
    let marker = format!("let {name}");
    let start = body
        .find(&marker)
        .unwrap_or_else(|| panic!("ProVerif process {name:?} not found"));
    let tail = &body[start..];
    let end = tail
        .find("\n\n(* ----------------------------------------------------------------------------")
        .unwrap_or(tail.len());
    &tail[..end]
}

/// XWing combiner model file существует на ожидаемом пути.
/// XWing combiner model file exists at the expected path.
#[test]
fn xwing_combiner_model_file_exists() {
    let path = Path::new(CRATE_ROOT).join(XWING_COMBINER.model_path);
    assert!(path.is_file(), "Tamarin model file not found: {path:?}");
}

/// `theory NAME` header в .spthy совпадает с `metadata.name`.
/// `theory NAME` header in .spthy matches `metadata.name`.
#[test]
fn xwing_combiner_theory_header_matches_metadata() {
    let body = read_model(&XWING_COMBINER);
    let needle = format!("theory {}", XWING_COMBINER.name);
    assert!(
        body.contains(&needle),
        "Tamarin theory header does not match metadata.name = {:?} \
         (model {:?})",
        XWING_COMBINER.name,
        XWING_COMBINER.model_path
    );
}

/// Каждое property из metadata имеет соответствующую `lemma NAME:` в .spthy.
/// Each property in metadata has a matching `lemma NAME:` in .spthy.
#[test]
fn xwing_combiner_lemma_names_match_metadata_properties() {
    let body = read_model(&XWING_COMBINER);
    for prop in XWING_COMBINER.properties {
        let needle = format!("lemma {prop}:");
        assert!(
            body.contains(&needle),
            "lemma {:?} declared in metadata.properties but not found in {:?}",
            prop,
            XWING_COMBINER.model_path
        );
    }
}

/// SPEC version cited в metadata должна быть отражена в `spec_reference`.
/// SPEC version cited in metadata must be reflected in `spec_reference`.
#[test]
fn xwing_combiner_spec_reference_matches_metadata_version() {
    assert_spec_reference_matches_metadata_version(&XWING_COMBINER);
}

/// XWing combiner header документирует все required axiom markers.
/// XWing combiner header documents all required axiom markers.
#[test]
fn xwing_combiner_header_documents_axioms() {
    let body = read_model(&XWING_COMBINER);
    // Limit search к первым 100 строкам — header section.
    // Limit search to the first 100 lines — the header section.
    let header: String = body.lines().take(100).collect::<Vec<_>>().join("\n");
    for needle in &["libcrux-kem", "HKDF-SHA256", "X25519", "ML-KEM-768"] {
        assert!(
            header.contains(needle),
            "axiom marker {needle:?} missing from xwing_combiner.spthy header"
        );
    }
}

/// X-Wing model must not rely on the old ML-KEM rewrite equation that makes
/// Maude variant generation fail during `tamarin-prover --prove`.
///
/// X-Wing модель не должна зависеть от старого ML-KEM rewrite-уравнения,
/// из-за которого Maude падает на генерации variants при `tamarin-prover --prove`.
#[test]
fn xwing_combiner_models_mlkem_reveal_as_rule_not_equation() {
    let body = read_model(&XWING_COMBINER);
    assert!(
        !body.contains("equations: mlkem_decaps"),
        "X-Wing model must not use the Maude-fragile ML-KEM decapsulation equation"
    );
    assert!(
        body.contains("rule attacker_decaps_revealed_mlkem"),
        "X-Wing model must expose ML-KEM decapsulation through an explicit reveal rule"
    );
}

/// Все модели в ALL_MODELS существуют на disk.
/// All models in ALL_MODELS exist on disk.
#[test]
fn all_models_files_exist() {
    for meta in ALL_MODELS {
        let path = Path::new(CRATE_ROOT).join(meta.model_path);
        assert!(
            path.is_file(),
            "model file missing for {} (tool {:?}): {:?}",
            meta.name,
            meta.tool,
            path
        );
    }
}

/// Все имена моделей различны.
/// All model names are distinct.
#[test]
fn all_models_have_distinct_names() {
    let names: Vec<&str> = ALL_MODELS.iter().map(|m| m.name).collect();
    let unique: HashSet<&str> = names.iter().copied().collect();
    assert_eq!(
        names.len(),
        unique.len(),
        "duplicate model name in ALL_MODELS: {names:?}"
    );
}

/// Все пути моделей различны.
/// All model paths are distinct.
#[test]
fn all_models_have_distinct_paths() {
    let paths: Vec<&str> = ALL_MODELS.iter().map(|m| m.model_path).collect();
    let unique: HashSet<&str> = paths.iter().copied().collect();
    assert_eq!(
        paths.len(),
        unique.len(),
        "duplicate model_path in ALL_MODELS: {paths:?}"
    );
}

/// Tamarin модели имеют расширение `.spthy`; ProVerif — `.pv`.
/// Tamarin models have the `.spthy` extension; ProVerif — `.pv`.
#[test]
fn all_models_have_correct_extension_for_tool() {
    for meta in ALL_MODELS {
        let expected_ext = meta.tool.file_extension();
        let expected_suffix = format!(".{expected_ext}");
        assert!(
            meta.model_path.ends_with(&expected_suffix),
            "model {} (tool {:?}) should have .{} extension, got {:?}",
            meta.name,
            meta.tool,
            expected_ext,
            meta.model_path
        );
    }
}

/// Метаданные XWING_COMBINER содержат block reference 9.2 (этот блок).
/// XWING_COMBINER metadata carries block reference 9.2 (this block).
#[test]
fn xwing_combiner_metadata_block_reference_is_9_2() {
    assert_eq!(XWING_COMBINER.block_reference, "9.2");
}

/// X-Wing combiner has a fresh completed Tamarin proof run.
/// X-Wing combiner имеет свежий завершённый Tamarin proof run.
///
/// 2026-05-19: re-run после round-3 hedged-encaps closure
/// (Bellare-Hoang-Keelveedhi 2015 extension); all 11 lemmas verified.
/// 2026-05-19: re-run after round-3 hedged-encaps closure
/// (Bellare-Hoang-Keelveedhi 2015 extension); all 11 lemmas verified.
#[test]
fn xwing_combiner_status_is_verified_after_fresh_tamarin_run() {
    assert_eq!(
        XWING_COMBINER.status,
        VerificationStatus::Verified {
            last_run: "2026-05-19"
        }
    );
}

// ---------------------------------------------------------------------------
// Block 9.3 — hybrid signature AND-mode model consistency tests.
// Block 9.3 — hybrid signature AND-mode model consistency tests.
// ---------------------------------------------------------------------------

/// `theory NAME` header в hybrid_signature_and_mode.spthy совпадает с metadata.
/// `theory NAME` header in hybrid_signature_and_mode.spthy matches metadata.
#[test]
fn hybrid_signature_and_mode_theory_header_matches_metadata() {
    let body = read_model(&HYBRID_SIGNATURE_AND_MODE);
    let needle = format!("theory {}", HYBRID_SIGNATURE_AND_MODE.name);
    assert!(
        body.contains(&needle),
        "Tamarin theory header does not match metadata.name = {:?} \
         (model {:?})",
        HYBRID_SIGNATURE_AND_MODE.name,
        HYBRID_SIGNATURE_AND_MODE.model_path
    );
}

/// Каждое property из metadata имеет соответствующую `lemma NAME:` в spthy.
/// Each property in metadata has a matching `lemma NAME:` in spthy.
#[test]
fn hybrid_signature_and_mode_lemma_names_match_metadata_properties() {
    let body = read_model(&HYBRID_SIGNATURE_AND_MODE);
    for prop in HYBRID_SIGNATURE_AND_MODE.properties {
        let needle = format!("lemma {prop}:");
        assert!(
            body.contains(&needle),
            "lemma {:?} declared in metadata.properties but not found in {:?}",
            prop,
            HYBRID_SIGNATURE_AND_MODE.model_path
        );
    }
}

/// Header документирует все required axiom markers для AND-mode hybrid sig.
/// Header documents all required axiom markers for AND-mode hybrid sig.
#[test]
fn hybrid_signature_and_mode_header_documents_axioms() {
    let body = read_model(&HYBRID_SIGNATURE_AND_MODE);
    // Limit search к первым 100 строкам — header section.
    // Limit search to the first 100 lines — the header section.
    let header: String = body.lines().take(100).collect::<Vec<_>>().join("\n");
    for needle in &["Ed25519", "ML-DSA-65", "AND-mode", "HYBRID_CONTEXT"] {
        assert!(
            header.contains(needle),
            "axiom marker {needle:?} missing from hybrid_signature_and_mode.spthy header"
        );
    }
}

/// Метаданные HYBRID_SIGNATURE_AND_MODE содержат block reference 9.3.
/// HYBRID_SIGNATURE_AND_MODE metadata carries block reference 9.3.
#[test]
fn hybrid_signature_and_mode_metadata_block_reference_is_9_3() {
    assert_eq!(HYBRID_SIGNATURE_AND_MODE.block_reference, "9.3");
}

/// Pending status — допустимый стартовый state для свежедобавленной модели.
/// Pending status is the valid initial state for a freshly added model.
#[test]
fn hybrid_signature_and_mode_status_is_pending_until_first_weekly_run() {
    assert_eq!(
        HYBRID_SIGNATURE_AND_MODE.status,
        VerificationStatus::Pending
    );
}

// ---------------------------------------------------------------------------
// Block 9.3 — KT v2 self-monitoring model consistency tests.
// Block 9.3 — KT v2 self-monitoring model consistency tests.
// ---------------------------------------------------------------------------

/// `theory NAME` header в kt_v2_self_monitoring.spthy совпадает с metadata.
/// `theory NAME` header in kt_v2_self_monitoring.spthy matches metadata.
#[test]
fn kt_v2_self_monitoring_theory_header_matches_metadata() {
    let body = read_model(&KT_V2_SELF_MONITORING);
    let needle = format!("theory {}", KT_V2_SELF_MONITORING.name);
    assert!(
        body.contains(&needle),
        "Tamarin theory header does not match metadata.name = {:?} \
         (model {:?})",
        KT_V2_SELF_MONITORING.name,
        KT_V2_SELF_MONITORING.model_path
    );
}

/// Каждое property из metadata имеет соответствующую `lemma NAME:` в spthy.
/// Each property in metadata has a matching `lemma NAME:` in spthy.
#[test]
fn kt_v2_self_monitoring_lemma_names_match_metadata_properties() {
    let body = read_model(&KT_V2_SELF_MONITORING);
    for prop in KT_V2_SELF_MONITORING.properties {
        let needle = format!("lemma {prop}:");
        assert!(
            body.contains(&needle),
            "lemma {:?} declared in metadata.properties but not found in {:?}",
            prop,
            KT_V2_SELF_MONITORING.model_path
        );
    }
}

/// Header документирует axiom markers для KT v2 self-monitoring модели.
/// Header documents axiom markers for the KT v2 self-monitoring model.
#[test]
fn kt_v2_self_monitoring_header_documents_axioms() {
    let body = read_model(&KT_V2_SELF_MONITORING);
    let header: String = body.lines().take(100).collect::<Vec<_>>().join("\n");
    for needle in &["SHA-256", "KT log", "SLH-DSA", "self-monitoring"] {
        assert!(
            header.contains(needle),
            "axiom marker {needle:?} missing from kt_v2_self_monitoring.spthy header"
        );
    }
}

/// Метаданные KT_V2_SELF_MONITORING содержат block reference 9.3.
/// KT_V2_SELF_MONITORING metadata carries block reference 9.3.
#[test]
fn kt_v2_self_monitoring_metadata_block_reference_is_9_3() {
    assert_eq!(KT_V2_SELF_MONITORING.block_reference, "9.3");
}

/// Verified status — KT V2 self-monitoring model verified locally on
/// 2026-05-19 via F-KT-V2-MODEL-1 closure (PhD-B Pass 5 remediation).
/// 3 tautologies refactored to 4 substantive correspondence claims
/// (bidirectional 'absent'≠'present' lemma split into 2 direction-
/// specific lemmas); 4 new exists-trace lemmas anchor non-vacuity.
/// All 9 lemmas verify in 0.40s via tamarin-prover 1.12.0.
///
/// Verified status — the KT V2 self-monitoring model was verified
/// locally on 2026-05-19 via the F-KT-V2-MODEL-1 closure (PhD-B Pass 5
/// remediation). 3 tautologies refactored to 4 substantive
/// correspondence claims (the bidirectional `'absent' ≠ 'present'`
/// lemma was split into 2 direction-specific lemmas); 4 new
/// exists-trace lemmas anchor non-vacuity. All 9 lemmas verify in
/// 0.40 s via tamarin-prover 1.12.0.
#[test]
fn kt_v2_self_monitoring_status_is_verified_post_f_kt_v2_model_1_closure() {
    assert!(
        matches!(
            KT_V2_SELF_MONITORING.status,
            VerificationStatus::Verified { .. }
        ),
        "F-KT-V2-MODEL-1 closure (2026-05-19): KT_V2_SELF_MONITORING must transition Pending → \
         Verified after local Tamarin run; status now = {:?}",
        KT_V2_SELF_MONITORING.status
    );
}

// ---------------------------------------------------------------------------
// Block 9.4 — sealed-sender V2 ProVerif model consistency tests.
// Block 9.4 — sealed-sender V2 ProVerif model consistency tests.
// ---------------------------------------------------------------------------

/// `(* process: NAME *)` header marker в sealed_sender_v2.pv совпадает с
/// metadata.name (ProVerif analog Tamarin theory header).
/// `(* process: NAME *)` header marker in sealed_sender_v2.pv matches
/// metadata.name (the ProVerif analog of the Tamarin theory header).
#[test]
fn sealed_sender_v2_process_header_matches_metadata() {
    let body = read_model(&SEALED_SENDER_V2);
    let needle = format!("process: {}", SEALED_SENDER_V2.name);
    assert!(
        body.contains(&needle),
        "ProVerif process header does not match metadata.name = {:?} \
         (model {:?})",
        SEALED_SENDER_V2.name,
        SEALED_SENDER_V2.model_path
    );
}

/// Каждое property из metadata имеет соответствующий `(* lemma: NAME *)`
/// comment marker в .pv файле (ProVerif analog Tamarin `lemma NAME:`).
/// Each property in metadata has a matching `(* lemma: NAME *)` comment
/// marker in the .pv file (the ProVerif analog of Tamarin `lemma NAME:`).
#[test]
fn sealed_sender_v2_query_names_match_metadata_properties() {
    let body = read_model(&SEALED_SENDER_V2);
    for prop in SEALED_SENDER_V2.properties {
        let needle = format!("(* lemma: {prop} *)");
        assert!(
            body.contains(&needle),
            "property {:?} declared in metadata but {:?} marker not found in {:?}",
            prop,
            needle,
            SEALED_SENDER_V2.model_path
        );
    }
}

/// Header документирует все required axiom markers для sealed-sender V2.
/// Header documents all required axiom markers for sealed-sender V2.
#[test]
fn sealed_sender_v2_header_documents_axioms() {
    let body = read_model(&SEALED_SENDER_V2);
    let header: String = body.lines().take(100).collect::<Vec<_>>().join("\n");
    for needle in &[
        "X-Wing combiner",
        "ChaCha20-Poly1305",
        "HKDF-SHA256",
        "DOMAIN_SEP",
    ] {
        assert!(
            header.contains(needle),
            "axiom marker {needle:?} missing from sealed_sender_v2.pv header"
        );
    }
}

/// Метаданные SEALED_SENDER_V2 содержат block reference 9.4.
/// SEALED_SENDER_V2 metadata carries block reference 9.4.
#[test]
fn sealed_sender_v2_metadata_block_reference_is_9_4() {
    assert_eq!(SEALED_SENDER_V2.block_reference, "9.4");
}

/// Pending status — допустимый стартовый state для свежедобавленной модели.
/// Pending status is the valid initial state for a freshly added model.
#[test]
fn sealed_sender_v2_status_is_pending_until_first_weekly_run() {
    assert_eq!(SEALED_SENDER_V2.status, VerificationStatus::Pending);
}

/// Parallel V1 process внутри sealed_sender_v2.pv обязан моделировать production
/// V1: X25519 ECDH envelope, not another X-Wing envelope with another label.
/// The parallel V1 process inside sealed_sender_v2.pv must model production V1:
/// an X25519 ECDH envelope, not another X-Wing envelope with another label.
#[test]
fn sealed_sender_v2_parallel_v1_process_uses_classical_x25519_wire() {
    let body = read_model(&SEALED_SENDER_V2);
    let v1_send = pv_let_block(&body, "sealed_sender_v1_send");
    let v1_recv = pv_let_block(&body, "sealed_sender_v1_recv");

    assert!(
        v1_send.contains("x25519_pub(eph_sk)"),
        "parallel V1 send must publish a fresh X25519 ephemeral key"
    );
    assert!(
        v1_send.contains("x25519_ecdh(recip_pk, eph_sk)"),
        "parallel V1 send must derive the V1 shared secret with X25519 ECDH"
    );
    assert!(
        v1_recv.contains("x25519_ecdh(eph_pub, sk)"),
        "parallel V1 receive must decapsulate via X25519 ECDH"
    );
    assert!(
        !v1_send.contains("xwing_ct(") && !v1_send.contains("xwing_ss("),
        "parallel V1 send must not use X-Wing primitives"
    );
    assert!(
        !v1_recv.contains("xwing_decaps("),
        "parallel V1 receive must not use X-Wing decapsulation"
    );
}

/// Sealed-sender HKDF info binds both the transcript material and recipient
/// public key. This guards against formal models accidentally proving a weaker
/// KDF context than production uses.
/// Sealed-sender HKDF info binds both transcript material and recipient public
/// key, preventing the models from proving a weaker KDF context than production.
#[test]
fn sealed_sender_models_hkdf_info_bind_recipient_pubkey() {
    for meta in [&SEALED_SENDER_V1, &SEALED_SENDER_V2] {
        let body = read_model(meta);
        assert!(
            body.contains("fun v1_hkdf_info(pubkey, pubkey): bitstring."),
            "{} must declare V1 HKDF info as eph_pub || recipient_pk",
            meta.model_path
        );
        assert!(
            body.contains("fun v2_hkdf_info(bitstring, pubkey): bitstring."),
            "{} must declare V2 HKDF info as ct || recipient_pk",
            meta.model_path
        );
        for process in [
            "sealed_sender_v1_send",
            "sealed_sender_v1_recv",
            "sealed_sender_v2_send",
            "sealed_sender_v2_recv",
        ] {
            let block = pv_let_block(&body, process);
            let expected = if process.contains("_v1_") {
                "v1_hkdf_info(eph_pub, recip_pk)"
            } else {
                "v2_hkdf_info(ct, recip_pk)"
            };
            assert!(
                block.contains(expected),
                "{}::{process} must derive HKDF with {expected}",
                meta.model_path
            );
        }
    }
}

/// The ProVerif models do not model compromise/reveal epochs, so they must not
/// advertise a KDF-context or transcript-authenticity invariant as forward
/// secrecy. ProVerif модели без reveal/compromise epochs не должны называть
/// KDF-context или transcript-authenticity invariant forward secrecy.
#[test]
fn sealed_sender_models_do_not_label_freshness_as_forward_secrecy() {
    for meta in [&SEALED_SENDER_V1, &SEALED_SENDER_V2] {
        assert!(
            !meta.properties.contains(&"ephemeral_forward_secrecy"),
            "{} metadata must not claim forward secrecy without reveal modeling",
            meta.model_path
        );
        assert!(
            meta.properties.contains(&"recipient_bound_hkdf_info"),
            "{} metadata must expose the narrower recipient_bound_hkdf_info property",
            meta.model_path
        );

        let body = read_model(meta);
        assert!(
            !body.contains("(* lemma: ephemeral_forward_secrecy *)"),
            "{} must not label a query as ephemeral_forward_secrecy",
            meta.model_path
        );
        assert!(
            body.contains("(* lemma: recipient_bound_hkdf_info *)"),
            "{} must contain a recipient_bound_hkdf_info marker",
            meta.model_path
        );
    }
}

/// Sealed-sender ProVerif processes do not model an anti-replay cache. They
/// may prove non-injective origin/authentication correspondences, but must not
/// claim injective receive correspondences that ProVerif falsifies by replaying
/// the same valid envelope twice.
#[test]
fn sealed_sender_models_do_not_claim_injective_receive_without_replay_state() {
    for meta in [&SEALED_SENDER_V1, &SEALED_SENDER_V2] {
        let body = read_model(meta);
        assert!(
            !body.contains("inj-event(ReceiveV1(") && !body.contains("inj-event(ReceiveV2("),
            "{} must not use injective receive correspondences without replay state",
            meta.model_path
        );
        assert!(
            !body.contains("anti-replay") || body.contains("replay cache"),
            "{} should mention anti-replay only when replay-cache state is modeled",
            meta.model_path
        );
    }
}

// ---------------------------------------------------------------------------
// Block 9.4 — backup wrap V2 ProVerif model consistency tests.
// Block 9.4 — backup wrap V2 ProVerif model consistency tests.
// ---------------------------------------------------------------------------

/// `(* process: NAME *)` header marker в backup_wrap_v2.pv совпадает с metadata.
/// `(* process: NAME *)` header marker in backup_wrap_v2.pv matches metadata.
#[test]
fn backup_wrap_v2_process_header_matches_metadata() {
    let body = read_model(&BACKUP_WRAP_V2);
    let needle = format!("process: {}", BACKUP_WRAP_V2.name);
    assert!(
        body.contains(&needle),
        "ProVerif process header does not match metadata.name = {:?} \
         (model {:?})",
        BACKUP_WRAP_V2.name,
        BACKUP_WRAP_V2.model_path
    );
}

/// Каждое property из metadata имеет соответствующий `(* lemma: NAME *)` marker.
/// Each property in metadata has a matching `(* lemma: NAME *)` marker.
#[test]
fn backup_wrap_v2_query_names_match_metadata_properties() {
    let body = read_model(&BACKUP_WRAP_V2);
    for prop in BACKUP_WRAP_V2.properties {
        let needle = format!("(* lemma: {prop} *)");
        assert!(
            body.contains(&needle),
            "property {:?} declared in metadata but {:?} marker not found in {:?}",
            prop,
            needle,
            BACKUP_WRAP_V2.model_path
        );
    }
}

/// Header документирует все required axiom markers для backup wrap V2.
/// Header documents all required axiom markers for backup wrap V2.
#[test]
fn backup_wrap_v2_header_documents_axioms() {
    let body = read_model(&BACKUP_WRAP_V2);
    let header: String = body.lines().take(100).collect::<Vec<_>>().join("\n");
    for needle in &[
        "X-Wing combiner",
        "BIP-39",
        "ChaCha20-Poly1305",
        "threshold-wrap",
    ] {
        assert!(
            header.contains(needle),
            "axiom marker {needle:?} missing from backup_wrap_v2.pv header"
        );
    }
}

/// Backup wrap V2 HKDF info mirrors production `pq_wrap.rs`: the AEAD key
/// context includes the X-Wing ciphertext and recipient X-Wing public key.
/// Backup wrap V2 HKDF info должен совпадать с production `pq_wrap.rs`:
/// AEAD key context включает X-Wing ciphertext и recipient public key.
#[test]
fn backup_wrap_v2_hkdf_info_binds_ciphertext_and_recipient_pubkey() {
    let body = read_model(&BACKUP_WRAP_V2);
    assert!(
        body.contains("fun v2_hkdf_info(bitstring, pubkey): bitstring."),
        "{} must declare V2 HKDF info as xwing_ct || recipient_pk",
        BACKUP_WRAP_V2.model_path
    );
    for process in ["backup_wrap_v2_send", "backup_wrap_v2_recv"] {
        let block = pv_let_block(&body, process);
        assert!(
            block.contains("hkdf(ss, DOMAIN_SEP_V2, v2_hkdf_info(ct, recip_pk))"),
            "{}::{process} must derive HKDF with xwing_ct and recipient public key",
            BACKUP_WRAP_V2.model_path
        );
        assert!(
            !block.contains("hkdf(ss, DOMAIN_SEP_V2, recip_pk)"),
            "{}::{process} must not pass a pubkey directly where ProVerif expects bitstring info",
            BACKUP_WRAP_V2.model_path
        );
    }
}

/// Backup wrap V2 has no anti-replay cache in this ProVerif model. It can
/// prove origin/preservation correspondences, but not injective unwrap
/// correspondences because a valid V2 envelope may be replayed.
/// Backup wrap V2 ProVerif модель не содержит replay-cache state, поэтому не
/// должна claims injective unwrap correspondences.
#[test]
fn backup_wrap_v2_does_not_claim_injective_unwrap_without_replay_state() {
    let body = read_model(&BACKUP_WRAP_V2);
    assert!(
        !body.contains("inj-event(UnwrapV2("),
        "{} must not claim injective unwrap correspondence without replay state",
        BACKUP_WRAP_V2.model_path
    );
}

/// Метаданные BACKUP_WRAP_V2 содержат block reference 9.4.
/// BACKUP_WRAP_V2 metadata carries block reference 9.4.
#[test]
fn backup_wrap_v2_metadata_block_reference_is_9_4() {
    assert_eq!(BACKUP_WRAP_V2.block_reference, "9.4");
}

/// Pending status — допустимый стартовый state для свежедобавленной модели.
/// Pending status is the valid initial state for a freshly added model.
#[test]
fn backup_wrap_v2_status_is_pending_until_first_weekly_run() {
    assert_eq!(BACKUP_WRAP_V2.status, VerificationStatus::Pending);
}

// ---------------------------------------------------------------------------
// Block 9.4 — downgrade resistance Tamarin model consistency tests.
// Block 9.4 — downgrade resistance Tamarin model consistency tests.
// ---------------------------------------------------------------------------

/// `theory NAME` header в downgrade_resistance.spthy совпадает с metadata.name.
/// `theory NAME` header in downgrade_resistance.spthy matches metadata.name.
#[test]
fn downgrade_resistance_theory_header_matches_metadata() {
    let body = read_model(&DOWNGRADE_RESISTANCE);
    let needle = format!("theory {}", DOWNGRADE_RESISTANCE.name);
    assert!(
        body.contains(&needle),
        "Tamarin theory header does not match metadata.name = {:?} \
         (model {:?})",
        DOWNGRADE_RESISTANCE.name,
        DOWNGRADE_RESISTANCE.model_path
    );
}

/// Каждое property из metadata имеет соответствующую `lemma NAME:` в spthy.
/// Each property in metadata has a matching `lemma NAME:` in spthy.
#[test]
fn downgrade_resistance_lemma_names_match_metadata_properties() {
    let body = read_model(&DOWNGRADE_RESISTANCE);
    for prop in DOWNGRADE_RESISTANCE.properties {
        let needle = format!("lemma {prop}:");
        assert!(
            body.contains(&needle),
            "lemma {:?} declared in metadata.properties but not found in {:?}",
            prop,
            DOWNGRADE_RESISTANCE.model_path
        );
    }
}

/// Header документирует все required axiom markers для downgrade resistance.
/// Header documents all required axiom markers for downgrade resistance.
#[test]
fn downgrade_resistance_header_documents_axioms() {
    let body = read_model(&DOWNGRADE_RESISTANCE);
    let header: String = body.lines().take(100).collect::<Vec<_>>().join("\n");
    for needle in &["RFC 9420", "ChatSettings", "0x004D", "MlsError"] {
        assert!(
            header.contains(needle),
            "axiom marker {needle:?} missing from downgrade_resistance.spthy header"
        );
    }
}

/// Метаданные DOWNGRADE_RESISTANCE содержат block reference 9.4.
/// DOWNGRADE_RESISTANCE metadata carries block reference 9.4.
#[test]
fn downgrade_resistance_metadata_block_reference_is_9_4() {
    assert_eq!(DOWNGRADE_RESISTANCE.block_reference, "9.4");
}

/// Verified status — downgrade-resistance model verified locally on
/// 2026-05-19 via F-DOWNGRADE-MODEL-1 closure (PhD-B Pass 5
/// remediation). 3 tautologies (constant-read + vacuously-true +
/// sibling-implied) refactored to substantive multi-rule
/// correspondence; 2 new exists-trace anchors. All 8 lemmas verify
/// in 0.15s via tamarin-prover 1.12.0 — substantially faster than the
/// production-readiness 2026-05-09 bounded run that hit the 180s
/// alarm (the refactored lemmas have tighter quantifier scopes and
/// avoid the search-space explosion of the original formulation).
///
/// Verified status — the downgrade-resistance model was verified
/// locally on 2026-05-19 via the F-DOWNGRADE-MODEL-1 closure (PhD-B
/// Pass 5 remediation). 3 tautologies (constant-read +
/// vacuously-true + sibling-implied) refactored to substantive
/// multi-rule correspondence; 2 new exists-trace anchors. All 8
/// lemmas verify in 0.15 s via tamarin-prover 1.12.0 — substantially
/// faster than the production-readiness 2026-05-09 bounded run that
/// hit the 180 s alarm (the refactored lemmas have tighter
/// quantifier scopes and avoid the search-space explosion of the
/// original formulation).
#[test]
fn downgrade_resistance_status_is_verified_post_f_downgrade_model_1_closure() {
    assert!(
        matches!(
            DOWNGRADE_RESISTANCE.status,
            VerificationStatus::Verified { .. }
        ),
        "F-DOWNGRADE-MODEL-1 closure (2026-05-19): DOWNGRADE_RESISTANCE must transition \
         Failed (180s alarm 2026-05-09) → Verified after local Tamarin run on refactored \
         model; status now = {:?}",
        DOWNGRADE_RESISTANCE.status
    );
}

/// ProVerif models есть в ALL_MODELS — block 9.4 added first 2 (sealed_sender_v2 + backup_wrap_v2).
/// ProVerif models exist in ALL_MODELS — block 9.4 added the first 2 (sealed_sender_v2 + backup_wrap_v2).
#[test]
fn proverif_models_present_after_block_9_4() {
    let proverif_names: Vec<&str> = ALL_MODELS
        .iter()
        .filter(|m| m.tool == ProtocolType::ProVerif)
        .map(|m| m.name)
        .collect();
    assert!(
        proverif_names.contains(&"umbrella_sealed_sender_v2"),
        "expected umbrella_sealed_sender_v2 (block 9.4) в ProVerif models, найдены: {proverif_names:?}"
    );
    assert!(
        proverif_names.contains(&"umbrella_backup_wrap_v2"),
        "expected umbrella_backup_wrap_v2 (block 9.4) в ProVerif models, найдены: {proverif_names:?}"
    );
}

/// Все block-9.4 модели имеют block_reference = "9.4" (sanity).
/// All block-9.4 models have block_reference = "9.4" (sanity).
#[test]
fn block_9_4_models_have_correct_block_reference() {
    let block_9_4_names = [
        "umbrella_sealed_sender_v2",
        "umbrella_backup_wrap_v2",
        "umbrella_downgrade_resistance",
    ];
    for meta in ALL_MODELS {
        if block_9_4_names.contains(&meta.name) {
            assert_eq!(
                meta.block_reference, "9.4",
                "model {} should have block_reference = \"9.4\"",
                meta.name
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Block 9.5 — KT V1 self-monitoring Tamarin model consistency tests.
// Block 9.5 — KT V1 self-monitoring Tamarin model consistency tests.
// ---------------------------------------------------------------------------

/// `theory NAME` header в kt_v1_self_monitoring.spthy совпадает с metadata.
/// `theory NAME` header in kt_v1_self_monitoring.spthy matches metadata.
#[test]
fn kt_v1_self_monitoring_theory_header_matches_metadata() {
    let body = read_model(&KT_V1_SELF_MONITORING);
    let needle = format!("theory {}", KT_V1_SELF_MONITORING.name);
    assert!(
        body.contains(&needle),
        "Tamarin theory header does not match metadata.name = {:?} (model {:?})",
        KT_V1_SELF_MONITORING.name,
        KT_V1_SELF_MONITORING.model_path
    );
}

/// Каждое property из metadata имеет соответствующую `lemma NAME:` в spthy.
/// Each property in metadata has a matching `lemma NAME:` in spthy.
#[test]
fn kt_v1_self_monitoring_lemma_names_match_metadata_properties() {
    let body = read_model(&KT_V1_SELF_MONITORING);
    for prop in KT_V1_SELF_MONITORING.properties {
        let needle = format!("lemma {prop}:");
        assert!(
            body.contains(&needle),
            "lemma {:?} declared in metadata.properties but not found in {:?}",
            prop,
            KT_V1_SELF_MONITORING.model_path
        );
    }
}

/// Header документирует все required axiom markers для KT V1.
/// Header documents all required axiom markers for KT V1.
#[test]
fn kt_v1_self_monitoring_header_documents_axioms() {
    let body = read_model(&KT_V1_SELF_MONITORING);
    let header: String = body.lines().take(100).collect::<Vec<_>>().join("\n");
    for needle in &["SHA-256", "KT V1", "Ed25519", "self-monitor"] {
        assert!(
            header.contains(needle),
            "axiom marker {needle:?} missing from kt_v1_self_monitoring.spthy header"
        );
    }
}

/// Метаданные KT_V1_SELF_MONITORING содержат block reference 9.5.
/// KT_V1_SELF_MONITORING metadata carries block reference 9.5.
#[test]
fn kt_v1_self_monitoring_metadata_block_reference_is_9_5() {
    assert_eq!(KT_V1_SELF_MONITORING.block_reference, "9.5");
}

/// Verified status — KT V1 self-monitoring model verified locally on
/// 2026-05-19 via F-KT-V1-MODEL-1 closure (PhD-B Pass 5 remediation).
/// 3 commutativity tautologies refactored to substantive correspondence
/// claims; 3 new exists-trace lemmas (`*_admits_detection`) anchor
/// non-vacuity. All 7 lemmas verify in 0.44s via tamarin-prover 1.12.0.
///
/// Verified status — the KT V1 self-monitoring model was verified
/// locally on 2026-05-19 via the F-KT-V1-MODEL-1 closure (PhD-B Pass 5
/// remediation). 3 commutativity tautologies were refactored to
/// substantive correspondence claims; 3 new exists-trace lemmas
/// (`*_admits_detection`) anchor non-vacuity. All 7 lemmas verify in
/// 0.44 s via tamarin-prover 1.12.0.
#[test]
fn kt_v1_self_monitoring_status_is_verified_post_f_kt_v1_model_1_closure() {
    assert!(
        matches!(
            KT_V1_SELF_MONITORING.status,
            VerificationStatus::Verified { .. }
        ),
        "F-KT-V1-MODEL-1 closure (2026-05-19): KT_V1_SELF_MONITORING must transition Pending → \
         Verified after local Tamarin run; status now = {:?}",
        KT_V1_SELF_MONITORING.status
    );
}

// ---------------------------------------------------------------------------
// Block 9.5 — sealed-sender V1 ProVerif model consistency tests.
// Block 9.5 — sealed-sender V1 ProVerif model consistency tests.
// ---------------------------------------------------------------------------

/// `(* process: NAME *)` header marker в sealed_sender_v1.pv совпадает с metadata.
/// `(* process: NAME *)` header marker in sealed_sender_v1.pv matches metadata.
#[test]
fn sealed_sender_v1_process_header_matches_metadata() {
    let body = read_model(&SEALED_SENDER_V1);
    let needle = format!("process: {}", SEALED_SENDER_V1.name);
    assert!(
        body.contains(&needle),
        "ProVerif process header does not match metadata.name = {:?} (model {:?})",
        SEALED_SENDER_V1.name,
        SEALED_SENDER_V1.model_path
    );
}

/// Каждое property из metadata имеет соответствующий `(* lemma: NAME *)` marker.
/// Each property in metadata has a matching `(* lemma: NAME *)` marker.
#[test]
fn sealed_sender_v1_query_names_match_metadata_properties() {
    let body = read_model(&SEALED_SENDER_V1);
    for prop in SEALED_SENDER_V1.properties {
        let needle = format!("(* lemma: {prop} *)");
        assert!(
            body.contains(&needle),
            "property {:?} declared in metadata but {:?} marker not found in {:?}",
            prop,
            needle,
            SEALED_SENDER_V1.model_path
        );
    }
}

/// Header документирует все required axiom markers для sealed-sender V1.
/// Header documents all required axiom markers for sealed-sender V1.
#[test]
fn sealed_sender_v1_header_documents_axioms() {
    let body = read_model(&SEALED_SENDER_V1);
    let header: String = body.lines().take(100).collect::<Vec<_>>().join("\n");
    for needle in &["X25519", "ChaCha20-Poly1305", "HKDF-SHA256", "DOMAIN_SEP"] {
        assert!(
            header.contains(needle),
            "axiom marker {needle:?} missing from sealed_sender_v1.pv header"
        );
    }
}

/// Метаданные SEALED_SENDER_V1 содержат block reference 9.5.
/// SEALED_SENDER_V1 metadata carries block reference 9.5.
#[test]
fn sealed_sender_v1_metadata_block_reference_is_9_5() {
    assert_eq!(SEALED_SENDER_V1.block_reference, "9.5");
}

/// Pending status — допустимый стартовый state для свежедобавленной модели.
/// Pending status is the valid initial state for a freshly added model.
#[test]
fn sealed_sender_v1_status_is_pending_until_first_weekly_run() {
    assert_eq!(SEALED_SENDER_V1.status, VerificationStatus::Pending);
}

// ---------------------------------------------------------------------------
// Block 9.5 — MLS Ed25519-only Tamarin model consistency tests.
// Block 9.5 — MLS Ed25519-only Tamarin model consistency tests.
// ---------------------------------------------------------------------------

/// `theory NAME` header в mls_ed25519.spthy совпадает с metadata.
/// `theory NAME` header in mls_ed25519.spthy matches metadata.
#[test]
fn mls_ed25519_theory_header_matches_metadata() {
    let body = read_model(&MLS_ED25519);
    let needle = format!("theory {}", MLS_ED25519.name);
    assert!(
        body.contains(&needle),
        "Tamarin theory header does not match metadata.name = {:?} (model {:?})",
        MLS_ED25519.name,
        MLS_ED25519.model_path
    );
}

/// Каждое property из metadata имеет соответствующую `lemma NAME:` в spthy.
/// Each property in metadata has a matching `lemma NAME:` in spthy.
#[test]
fn mls_ed25519_lemma_names_match_metadata_properties() {
    let body = read_model(&MLS_ED25519);
    for prop in MLS_ED25519.properties {
        let needle = format!("lemma {prop}:");
        assert!(
            body.contains(&needle),
            "lemma {:?} declared in metadata.properties but not found in {:?}",
            prop,
            MLS_ED25519.model_path
        );
    }
}

/// Header документирует все required axiom markers для MLS Ed25519.
/// Header documents all required axiom markers for MLS Ed25519.
#[test]
fn mls_ed25519_header_documents_axioms() {
    let body = read_model(&MLS_ED25519);
    let header: String = body.lines().take(100).collect::<Vec<_>>().join("\n");
    for needle in &["Ed25519", "SUF-CMA", "SPEC-03", "ETK"] {
        assert!(
            header.contains(needle),
            "axiom marker {needle:?} missing from mls_ed25519.spthy header"
        );
    }
}

/// Метаданные MLS_ED25519 содержат block reference 9.5.
/// MLS_ED25519 metadata carries block reference 9.5.
#[test]
fn mls_ed25519_metadata_block_reference_is_9_5() {
    assert_eq!(MLS_ED25519.block_reference, "9.5");
}

/// Verified status — MLS Ed25519 model verified locally on 2026-05-19
/// via F-MLS-MODEL-1 closure (PhD-B Pass 5 remediation). 3 primary
/// lemmas refactored from tautologies to substantive claims; 2 new
/// exists-trace lemmas (public_group_admits_external_commit,
/// ecdsa_malleability_admits_distinct_verifying_signatures) anchor
/// model non-vacuity and ECDSA contrast. All 6 lemmas verify in
/// 3.53s via tamarin-prover 1.12.0 (etk_split_brain_prevented in
/// 172 steps — non-trivial proof).
///
/// Verified status — the MLS Ed25519 model was verified locally on
/// 2026-05-19 via the F-MLS-MODEL-1 closure (PhD-B Pass 5
/// remediation). The 3 primary lemmas were refactored from
/// tautologies to substantive claims; 2 new exists-trace lemmas
/// (public_group_admits_external_commit,
/// ecdsa_malleability_admits_distinct_verifying_signatures) anchor
/// the model's non-vacuity and demonstrate the ECDSA contrast. All
/// 6 lemmas verify in 3.53 s via tamarin-prover 1.12.0
/// (etk_split_brain_prevented in 172 steps — non-trivial proof).
#[test]
fn mls_ed25519_status_is_verified_post_f_mls_model_1_closure() {
    assert!(
        matches!(MLS_ED25519.status, VerificationStatus::Verified { .. }),
        "F-MLS-MODEL-1 closure (2026-05-19): MLS_ED25519 must transition Pending → Verified \
         after local Tamarin run; status now = {:?}",
        MLS_ED25519.status
    );
}

/// Все block-9.5 модели имеют block_reference = "9.5" (sanity).
/// All block-9.5 models have block_reference = "9.5" (sanity).
#[test]
fn block_9_5_models_have_correct_block_reference() {
    let block_9_5_names = [
        "umbrella_kt_v1_self_monitoring",
        "umbrella_sealed_sender_v1",
        "umbrella_mls_ed25519",
    ];
    for meta in ALL_MODELS {
        if block_9_5_names.contains(&meta.name) {
            assert_eq!(
                meta.block_reference, "9.5",
                "model {} should have block_reference = \"9.5\"",
                meta.name
            );
        }
    }
}

/// ALL_MODELS после round 7 имеет 14 моделей (10 Tamarin + 4 ProVerif).
/// ALL_MODELS after round 7 has 14 models (10 Tamarin + 4 ProVerif).
#[test]
fn all_models_count_after_block_9_5() {
    assert_eq!(
        ALL_MODELS.len(),
        14,
        "expected 14 models after round 7 (10 Tamarin + 4 ProVerif)"
    );
    let tamarin = ALL_MODELS
        .iter()
        .filter(|m| m.tool == ProtocolType::Tamarin)
        .count();
    let proverif = ALL_MODELS
        .iter()
        .filter(|m| m.tool == ProtocolType::ProVerif)
        .count();
    assert_eq!(tamarin, 10, "expected 10 Tamarin models after round 7");
    assert_eq!(proverif, 4, "expected 4 ProVerif models after round 7");
}

// ---------------------------------------------------------------------------
// Block 10.18 (Stage 10 Phase 2 audit) — comprehensive spec_version drift
// detection (F-59 closure: SPEC-08 v0.0.1 → v0.0.2 SEALED_SENDER_V1 metadata
// propagation gap inline-fixed; defence-in-depth regression-guard tests
// добавлены для всех 8 not-yet-tested моделей, mirror existing
// xwing_combiner_spec_version_matches_current_spec pattern). Предотвращает
// future F-47 + F-59 cross-cutting cleanup-class regression — bump любой
// SPEC версии вынудит обновление metadata либо упадёт regression-guard test.
// Block 10.18 (Stage 10 Phase 2 audit) — comprehensive spec_version metadata
// consistency checks. Prevents future cross-cutting cleanup-class regressions:
// a metadata version bump must also be reflected in the public model citation.
// ---------------------------------------------------------------------------

/// Helper: проверяет, что публичная ссылка модели содержит ту же версию, что и
/// отдельное поле `spec_version`. Приватные спецификации не являются частью
/// опубликованного репозитория, поэтому тест не читает документы с диска.
///
/// Helper: verifies that the public model citation contains the same version
/// as the dedicated `spec_version` field. Private specifications are not part
/// of the published repository, so this test does not read documents from disk.
fn assert_spec_reference_matches_metadata_version(metadata: &ModelMetadata) {
    let version_marker = format!("v{}", metadata.spec_version);
    assert!(
        metadata.spec_reference.contains(&version_marker),
        "SPEC version {:?} for model {:?} is not reflected in spec_reference {:?}",
        metadata.spec_version,
        metadata.name,
        metadata.spec_reference
    );
}

/// SEALED_SENDER_V1 spec_version совпадает с актуальной версией SPEC-08
/// (F-59 closure block 10.18 — SPEC-08 v0.0.1 → v0.0.2 propagation gap).
/// SEALED_SENDER_V1 spec_version matches the current SPEC-08 version (F-59
/// closure block 10.18 — SPEC-08 v0.0.1 → v0.0.2 propagation gap).
#[test]
fn sealed_sender_v1_spec_version_matches_current_spec() {
    assert_spec_reference_matches_metadata_version(&SEALED_SENDER_V1);
}

/// SEALED_SENDER_V2 spec_version совпадает с актуальной версией SPEC-13.
/// SEALED_SENDER_V2 spec_version matches the current SPEC-13 version.
#[test]
fn sealed_sender_v2_spec_version_matches_current_spec() {
    assert_spec_reference_matches_metadata_version(&SEALED_SENDER_V2);
}

/// BACKUP_WRAP_V2 spec_version совпадает с актуальной версией SPEC-13.
/// BACKUP_WRAP_V2 spec_version matches the current SPEC-13 version.
#[test]
fn backup_wrap_v2_spec_version_matches_current_spec() {
    assert_spec_reference_matches_metadata_version(&BACKUP_WRAP_V2);
}

/// DOWNGRADE_RESISTANCE spec_version совпадает с актуальной версией SPEC-13.
/// DOWNGRADE_RESISTANCE spec_version matches the current SPEC-13 version.
#[test]
fn downgrade_resistance_spec_version_matches_current_spec() {
    assert_spec_reference_matches_metadata_version(&DOWNGRADE_RESISTANCE);
}

/// HYBRID_SIGNATURE_AND_MODE spec_version совпадает с актуальной версией SPEC-13.
/// HYBRID_SIGNATURE_AND_MODE spec_version matches the current SPEC-13 version.
#[test]
fn hybrid_signature_and_mode_spec_version_matches_current_spec() {
    assert_spec_reference_matches_metadata_version(&HYBRID_SIGNATURE_AND_MODE);
}

/// KT_V2_SELF_MONITORING spec_version совпадает с актуальной версией SPEC-13
/// (primary spec; SPEC-09 §3 цитируется без version qualifier и проверяется
/// отдельным KT_V1_SELF_MONITORING тестом для SPEC-09 baseline).
/// KT_V2_SELF_MONITORING spec_version matches the current SPEC-13 version
/// (primary spec; SPEC-09 §3 is cited without a version qualifier and is
/// covered by the separate KT_V1_SELF_MONITORING test for the SPEC-09
/// baseline).
#[test]
fn kt_v2_self_monitoring_spec_version_matches_current_spec() {
    assert_spec_reference_matches_metadata_version(&KT_V2_SELF_MONITORING);
}

/// KT_V1_SELF_MONITORING spec_version совпадает с актуальной версией SPEC-09
/// (primary spec; SPEC-13 §6.1 цитируется без version qualifier и
/// проверяется через KT_V2_SELF_MONITORING / прочие SPEC-13 цитирующие
/// тесты).
/// KT_V1_SELF_MONITORING spec_version matches the current SPEC-09 version
/// (primary spec; SPEC-13 §6.1 is cited without a version qualifier and is
/// covered through KT_V2_SELF_MONITORING / other SPEC-13-citing tests).
#[test]
fn kt_v1_self_monitoring_spec_version_matches_current_spec() {
    assert_spec_reference_matches_metadata_version(&KT_V1_SELF_MONITORING);
}

/// MLS_ED25519 spec_version совпадает с актуальной версией SPEC-03.
/// MLS_ED25519 spec_version matches the current SPEC-03 version.
#[test]
fn mls_ed25519_spec_version_matches_current_spec() {
    assert_spec_reference_matches_metadata_version(&MLS_ED25519);
}

// ---------------------------------------------------------------------------
// Block 10.23 (Stage 10 Phase 3 cross-cutting formal models expansion) —
// per-model spec_version regression-guard tests для 4 новых моделей.
// Mirror existing block 10.18 F-59 closure pattern.
// Block 10.23 (Stage 10 Phase 3 cross-cutting formal models expansion) —
// per-model spec_version regression-guard tests for the 4 new models.
// Mirrors the existing block 10.18 F-59 closure pattern.
// ---------------------------------------------------------------------------

/// MULTI_DEVICE_AUTHORIZATION spec_version совпадает с актуальной версией
/// SPEC-09 (primary spec; SPEC-11 + ADR-008 цитируются без version qualifier
/// и проверяются через SPEC-09 baseline assertion).
/// MULTI_DEVICE_AUTHORIZATION spec_version matches the current SPEC-09
/// version (primary spec; SPEC-11 + ADR-008 are cited without a version
/// qualifier and are covered through the SPEC-09 baseline assertion).
#[test]
fn multi_device_authorization_spec_version_matches_current_spec() {
    assert_spec_reference_matches_metadata_version(&MULTI_DEVICE_AUTHORIZATION);
}

/// SFRAME_RFC9605 spec_version совпадает с актуальной версией SPEC-06.
/// SFRAME_RFC9605 spec_version matches the current SPEC-06 version.
#[test]
fn sframe_rfc9605_spec_version_matches_current_spec() {
    assert_spec_reference_matches_metadata_version(&SFRAME_RFC9605);
}

/// TYPE_SAFE_ENFORCEMENT spec_version согласован с публичной citation.
/// TYPE_SAFE_ENFORCEMENT spec_version is consistent with the public citation.
#[test]
fn type_safe_enforcement_spec_version_matches_current_spec() {
    assert_spec_reference_matches_metadata_version(&TYPE_SAFE_ENFORCEMENT);
}

/// OPRF_RISTRETTO255 spec_version совпадает с актуальной версией SPEC-05.
/// OPRF_RISTRETTO255 spec_version matches the current SPEC-05 version.
#[test]
fn oprf_ristretto255_spec_version_matches_current_spec() {
    assert_spec_reference_matches_metadata_version(&OPRF_RISTRETTO255);
}

/// ALL_MODELS block 10.23 entries имеют block_reference = "10.23".
/// ALL_MODELS block 10.23 entries have block_reference = "10.23".
#[test]
fn block_10_23_entries_have_correct_block_reference() {
    let block_10_23_names = [
        "umbrella_multi_device_authorization",
        "umbrella_sframe_rfc9605",
        "umbrella_type_safe_enforcement",
        "umbrella_oprf_ristretto255",
    ];
    for meta in ALL_MODELS {
        if block_10_23_names.contains(&meta.name) {
            assert_eq!(
                meta.block_reference, "10.23",
                "model {} should have block_reference = \"10.23\"",
                meta.name
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Round-7 — discovery model consistency tests.
// Round-7 — discovery model consistency tests.
// ---------------------------------------------------------------------------

/// `theory NAME` header in discovery.spthy matches metadata.
#[test]
fn discovery_theory_header_matches_metadata() {
    let body = read_model(&DISCOVERY);
    let needle = format!("theory {}", DISCOVERY.name);
    assert!(
        body.contains(&needle),
        "Tamarin theory header does not match metadata.name = {:?} (model {:?})",
        DISCOVERY.name,
        DISCOVERY.model_path
    );
}

/// Each property in DISCOVERY metadata has a matching `lemma NAME:`.
#[test]
fn discovery_lemma_names_match_metadata_properties() {
    let body = read_model(&DISCOVERY);
    for prop in DISCOVERY.properties {
        let needle = format!("lemma {prop}:");
        assert!(
            body.contains(&needle),
            "lemma {:?} declared in metadata.properties but not found in {:?}",
            prop,
            DISCOVERY.model_path
        );
    }
}

/// Discovery model status is Verified after fresh 2026-05-18 Tamarin run.
#[test]
fn discovery_status_is_verified_2026_05_18() {
    assert_eq!(
        DISCOVERY.status,
        VerificationStatus::Verified {
            last_run: "2026-05-18"
        }
    );
}

/// Discovery model is a Tamarin (`spthy`) model.
#[test]
fn discovery_tool_is_tamarin() {
    assert_eq!(DISCOVERY.tool, ProtocolType::Tamarin);
    assert!(DISCOVERY.model_path.ends_with(".spthy"));
}

/// Discovery model has block_reference = "round-7".
#[test]
fn discovery_block_reference_is_round_7() {
    assert_eq!(DISCOVERY.block_reference, "round-7");
}

/// Discovery model exposes all 5 D-series lemmas + 1 sanity.
#[test]
fn discovery_has_all_five_d_series_lemmas_plus_sanity() {
    let names: Vec<&str> = DISCOVERY.properties.iter().copied().collect();
    let expected = [
        "server_never_learns_plaintext_phone",
        "intersection_cardinality_only_disclosed",
        "kt_bind_prevents_silent_swap",
        "anon_id_unlinkable_across_queries",
        "replay_protection_enforced",
        "honest_discovery_executable",
    ];
    for e in &expected {
        assert!(
            names.contains(e),
            "missing lemma {e:?} in DISCOVERY.properties"
        );
    }
    assert_eq!(names.len(), expected.len());
}

/// Json round-trip metadata через serde_json — sanity check для serialization
/// shape (используется когда weekly CI отчёт PR'ит обновлённый status).
/// JSON round-trip of metadata via serde_json — sanity check for the
/// serialization shape (used when the weekly CI report PRs an updated
/// status).
#[test]
fn metadata_can_be_described_as_json_blob() {
    // Шаг ручной — поля строки, не automatic Serialize derive (struct const).
    // Manual step — fields are strings, not an automatic Serialize derive
    // (struct const).
    let json = serde_json::json!({
        "name": XWING_COMBINER.name,
        "spec_reference": XWING_COMBINER.spec_reference,
        "spec_version": XWING_COMBINER.spec_version,
        "block_reference": XWING_COMBINER.block_reference,
        "tool": match XWING_COMBINER.tool {
            ProtocolType::Tamarin => "tamarin",
            ProtocolType::ProVerif => "proverif",
        },
        "model_path": XWING_COMBINER.model_path,
        "properties": XWING_COMBINER.properties,
    });
    let s = serde_json::to_string(&json).expect("serialize");
    assert!(s.contains("umbrella_xwing_combiner"));
    assert!(s.contains("SPEC-13-PQ-HYBRID"));
    assert!(s.contains("tamarin"));
}
