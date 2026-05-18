//! Metadata для Tamarin / ProVerif моделей крейта.
//!
//! Каждая модель хранит ссылку на SPEC document (поле `spec_reference`) +
//! version (`spec_version`), список свойств (`properties`) и текущий статус
//! верификации (`status`). Consistency tests в `tests/model_consistency.rs`
//! верифицируют что цитаты актуальны на каждом push (Pattern H — модель =
//! SPEC цитата + property + axioms; Pattern K — full Tamarin/ProVerif
//! верификация запускается weekly cron job).
//!
//! Все поля `&'static str` либо `&'static [&'static str]` — compile-time
//! const, нулевые runtime allocations, нулевая state mutation. Status
//! обновляется через PR после weekly CI run (atomic update метаданных +
//! lemma proofs одной commit'ом).
//!
//! # Module: model_metadata (English)
//!
//! Metadata for the Tamarin / ProVerif models of this crate.
//!
//! Each model carries a SPEC document reference (`spec_reference`) +
//! version (`spec_version`), a list of properties (`properties`), and the
//! current verification status (`status`). Consistency tests in
//! `tests/model_consistency.rs` verify the citations stay current on every
//! push (Pattern H — model = SPEC citation + property + axioms; Pattern K
//! — full Tamarin/ProVerif verification runs as a weekly cron job).
//!
//! All fields are `&'static str` or `&'static [&'static str]` —
//! compile-time const, zero runtime allocations, zero state mutation. The
//! status is updated through a PR after the weekly CI run (atomic update
//! of metadata + lemma proofs in a single commit).

/// Тип формального инструмента, верифицирующего модель.
///
/// `Tamarin` — Tamarin Prover (<https://tamarin-prover.com/>), symbolic
/// protocol verifier (Haskell, multiset rewriting). Используется для group
/// operations / counter-based protocols / authenticated key exchange /
/// hybrid signatures (X-Wing combiner блок 9.2, AND-mode signature 9.3,
/// KT v2 self-monitoring 9.3, downgrade resistance 9.4, classical protocols
/// 9.5).
///
/// `ProVerif` — ProVerif (<https://bblanche.gitlabpages.inria.fr/proverif/>),
/// cryptographic protocol verifier (OCaml, applied pi calculus). Используется
/// для confidentiality / authentication queries в protocols с chaining
/// encryptions / sender privacy (sealed-sender V2 блок 9.4, backup wrap V2
/// 9.4).
///
/// # Type: ProtocolType (English)
///
/// Type of formal verifier consuming the model.
///
/// `Tamarin` — Tamarin Prover (<https://tamarin-prover.com/>), a symbolic
/// protocol verifier (Haskell, multiset rewriting). Used for group
/// operations / counter-based protocols / authenticated key exchange /
/// hybrid signatures (X-Wing combiner block 9.2, AND-mode signature 9.3,
/// KT v2 self-monitoring 9.3, downgrade resistance 9.4, classical
/// protocols 9.5).
///
/// `ProVerif` — ProVerif (<https://bblanche.gitlabpages.inria.fr/proverif/>),
/// a cryptographic protocol verifier (OCaml, applied pi calculus). Used
/// for confidentiality / authentication queries in protocols with chaining
/// encryptions / sender privacy (sealed-sender V2 block 9.4, backup wrap
/// V2 9.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    /// Tamarin Prover, формат `.spthy`.
    /// Tamarin Prover, `.spthy` format.
    Tamarin,
    /// ProVerif, формат `.pv`.
    /// ProVerif, `.pv` format.
    ProVerif,
}

impl ProtocolType {
    /// Файл расширение для модели (без точки).
    /// File extension for the model (without the leading dot).
    pub const fn file_extension(self) -> &'static str {
        match self {
            ProtocolType::Tamarin => "spthy",
            ProtocolType::ProVerif => "pv",
        }
    }

    /// Имя CLI binary для запуска верификатора.
    /// CLI binary name used to launch the verifier.
    pub const fn cli_binary(self) -> &'static str {
        match self {
            ProtocolType::Tamarin => "tamarin-prover",
            ProtocolType::ProVerif => "proverif",
        }
    }
}

/// Статус верификации модели в последнем weekly CI run.
///
/// `Pending` — модель ещё не верифицировалась после публикации либо после
/// последнего SPEC update. Допустимый стартовый state для свежедобавленной
/// модели; weekly CI job обновит до `Verified` либо `Failed` через PR.
///
/// `Verified { last_run }` — last successful verification timestamp в формате
/// ISO-8601 date string (UTC). Updated через PR после каждого weekly CI run.
///
/// `Failed { reason }` — последний run обнаружил counter-example либо
/// timeout. `reason` — однострочное описание (lemma name + ошибка) для
/// quick triage.
///
/// # Type: VerificationStatus (English)
///
/// Verification status of the model in the latest weekly CI run.
///
/// `Pending` — the model has not been verified yet after publication or
/// after the latest SPEC update. A valid initial state for a freshly added
/// model; the weekly CI job will update it to `Verified` or `Failed`
/// through a PR.
///
/// `Verified { last_run }` — last successful verification timestamp in
/// ISO-8601 date string format (UTC). Updated through a PR after each
/// weekly CI run.
///
/// `Failed { reason }` — the latest run found a counter-example or timed
/// out. `reason` — a one-line description (lemma name + error) for quick
/// triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// Модель ещё не верифицировалась.
    /// The model has not been verified yet.
    Pending,
    /// Последняя верификация успешна.
    /// The latest verification succeeded.
    Verified {
        /// ISO-8601 date string (UTC) последнего успешного run.
        /// ISO-8601 date string (UTC) of the latest successful run.
        last_run: &'static str,
    },
    /// Последняя верификация провалилась.
    /// The latest verification failed.
    Failed {
        /// Однострочное описание (lemma + ошибка).
        /// One-line description (lemma + error).
        reason: &'static str,
    },
}

/// Метаданные одной формальной модели.
///
/// Pattern H обеспечивается полями `spec_reference` + `spec_version`:
/// каждая модель ссылается на конкретную секцию приватной спецификации, и tests
/// в `tests/model_consistency.rs` верифицируют согласованность citation с
/// отдельным version-полем.
///
/// # Type: ModelMetadata (English)
///
/// Metadata for a single formal model.
///
/// Pattern H is ensured by the `spec_reference` + `spec_version` fields:
/// each model references a specific private specification section, and tests
/// in `tests/model_consistency.rs` verify the citation is consistent with the
/// dedicated version field.
#[derive(Debug, Clone, Copy)]
pub struct ModelMetadata {
    /// Имя `theory` в `.spthy` либо имя процесса в `.pv`.
    /// `theory` name in `.spthy` or process name in `.pv`.
    pub name: &'static str,
    /// Цитата SPEC document (например, "SPEC-13-PQ-HYBRID v1.0.0 §4.3 + §7.1").
    /// SPEC document citation (e.g., "SPEC-13-PQ-HYBRID v1.0.0 §4.3 + §7.1").
    pub spec_reference: &'static str,
    /// Версия SPEC (например, "0.0.1").
    /// SPEC version (e.g., "0.0.1").
    pub spec_version: &'static str,
    /// Reference на этап / блок (например, "9.2").
    /// Stage / block reference (e.g., "9.2").
    pub block_reference: &'static str,
    /// Какой инструмент верифицирует модель.
    /// Which tool verifies the model.
    pub tool: ProtocolType,
    /// Путь к файлу модели от корня крейта (`crates/umbrella-formal-verification`).
    /// Model file path relative to the crate root (`crates/umbrella-formal-verification`).
    pub model_path: &'static str,
    /// Список свойств / lemma names проверяемых моделью.
    /// List of properties / lemma names the model proves.
    pub properties: &'static [&'static str],
    /// Текущий статус верификации.
    /// Current verification status.
    pub status: VerificationStatus,
}

/// Модель X-Wing combiner security (block 9.2).
///
/// Моделирует intended joint security X-Wing combiner = X25519 ⊕
/// ML-KEM-768 per draft-connolly-cfrg-xwing-kem-06 §3 +
/// SPEC-13-PQ-HYBRID v1.0.0 §4.3 (HPKE base mode для MLS ciphersuite
/// 0x004D) + §7.1 (sealed-sender V2 envelope ephemeral KEM). Fresh
/// Tamarin proof run completed 2026-05-09.
///
/// Свойства:
/// - `joint_security_classical_break_x25519`: shared secret K остаётся
///   секретным даже если adversary получил X25519 private key (ML-KEM-768
///   IND-CCA2 защищает).
/// - `joint_security_quantum_break_mlkem`: shared secret K остаётся
///   секретным даже если adversary получил ML-KEM-768 private key (X25519
///   DDH защищает в classical model).
/// - `domain_separation`: KDF input включает оба pkx и pkm, что исключает
///   related-key attacks.
///
/// Threat model: passive adversary с access к public keys + ciphertexts;
/// classical либо quantum capabilities. Active interference outside scope
/// (covered ciphertext integrity через AEAD на следующем layer).
///
/// # Constant: XWING_COMBINER (English)
///
/// X-Wing combiner security model (block 9.2).
///
/// Models the intended joint security of the X-Wing combiner = X25519 ⊕
/// ML-KEM-768 per draft-connolly-cfrg-xwing-kem-06 §3 +
/// SPEC-13-PQ-HYBRID v1.0.0 §4.3 (HPKE base mode for MLS ciphersuite
/// 0x004D) + §7.1 (sealed-sender V2 envelope ephemeral KEM). A fresh
/// Tamarin proof run completed on 2026-05-09.
///
/// Properties:
/// - `joint_security_classical_break_x25519`: the shared secret K stays
///   secret even if the adversary obtains the X25519 private key
///   (ML-KEM-768 IND-CCA2 protects it).
/// - `joint_security_quantum_break_mlkem`: the shared secret K stays
///   secret even if the adversary obtains the ML-KEM-768 private key
///   (X25519 DDH protects it under the classical model).
/// - `domain_separation`: the KDF input includes both pkx and pkm, ruling
///   out related-key attacks.
///
/// Threat model: a passive adversary with access to public keys +
/// ciphertexts; classical or quantum capabilities. Active interference is
/// out of scope (covered by ciphertext integrity via AEAD at the next
/// layer).
pub const XWING_COMBINER: ModelMetadata = ModelMetadata {
    name: "umbrella_xwing_combiner",
    spec_reference: "SPEC-13-PQ-HYBRID v1.0.0 §4.3 + §7.1",
    spec_version: "1.0.0",
    block_reference: "9.2",
    tool: ProtocolType::Tamarin,
    model_path: "models/xwing_combiner.spthy",
    properties: &[
        "joint_security_classical_break_x25519",
        "joint_security_quantum_break_mlkem",
        "domain_separation_label_simultaneity",
        "kdf_transcript_binding",
        "adversarial_encaps_quantum_break_cannot_recover_K",
        "honest_setup_executable",
        // Round-3 hedged-encaps closure (2026-05-19,
        // Bellare-Hoang-Keelveedhi 2015).
        "hedged_encaps_unbreakable_with_partial_compromise",
        "rng_only_compromise_preserves_secrecy",
        "witness_only_compromise_preserves_secrecy",
        "hedged_encaps_executable",
        "hedged_lemma_is_tight_under_double_compromise",
    ],
    status: VerificationStatus::Verified {
        last_run: "2026-05-19",
    },
};

/// Модель AND-mode hybrid signature security (block 9.3).
///
/// Доказывает что compromise одного из двух signature семейств
/// (classical Ed25519 либо post-quantum ML-DSA-65) сам по себе НЕ
/// позволяет forge AND-mode hybrid signature; для forgery нужны оба
/// секрета. Per NIST SP 800-227 hybrid signature scheme guidelines +
/// SPEC-13-PQ-HYBRID v1.0.0 §5 (Identity hybrid layer).
///
/// Свойства:
/// - `and_mode_security_classical_break_ed25519`: Ed25519 reveal сам
///   по себе не позволяет forge hybrid подпись (ML-DSA-65 EUF-CMA
///   защищает оставшийся компонент).
/// - `and_mode_security_quantum_break_mldsa`: симметрично для ML-DSA-65
///   reveal (Ed25519 EUF-CMA защищает в classical model).
/// - `domain_separation`: hybrid signature accept под non-canonical
///   context label требует compromise обоих секретов; cross-protocol
///   replay blocked если хотя бы один секрет intact.
///
/// Threat model: active Dolev–Yao adversary с individual reveal
/// capabilities на каждый component. AND-mode requires both secrets
/// для forgery — это conservative hybrid policy per NIST SP 800-227
/// рекомендации.
///
/// # Constant: HYBRID_SIGNATURE_AND_MODE (English)
///
/// AND-mode hybrid signature security model (block 9.3).
///
/// Proves that a compromise of one of the two signature families
/// (classical Ed25519 or post-quantum ML-DSA-65) is not sufficient to
/// forge an AND-mode hybrid signature; forgery requires both secrets.
/// Per NIST SP 800-227 hybrid signature scheme guidelines +
/// SPEC-13-PQ-HYBRID v1.0.0 §5 (Identity hybrid layer).
///
/// Properties:
/// - `and_mode_security_classical_break_ed25519`: an Ed25519 reveal
///   alone cannot forge a hybrid signature (ML-DSA-65 EUF-CMA protects
///   the remaining component).
/// - `and_mode_security_quantum_break_mldsa`: symmetric for an ML-DSA-65
///   reveal (Ed25519 EUF-CMA protects under the classical model).
/// - `domain_separation`: a hybrid signature accept under a non-canonical
///   context label requires compromise of both secrets; cross-protocol
///   replay is blocked if at least one secret stays intact.
///
/// Threat model: an active Dolev–Yao adversary with individual reveal
/// capabilities for each component. AND-mode requires both secrets for
/// forgery — this is the conservative hybrid policy per the NIST
/// SP 800-227 recommendation.
pub const HYBRID_SIGNATURE_AND_MODE: ModelMetadata = ModelMetadata {
    name: "umbrella_hybrid_signature_and_mode",
    spec_reference: "SPEC-13-PQ-HYBRID v1.0.0 §5",
    spec_version: "1.0.0",
    block_reference: "9.3",
    tool: ProtocolType::Tamarin,
    model_path: "models/hybrid_signature_and_mode.spthy",
    properties: &[
        "and_mode_security_classical_break_ed25519",
        "and_mode_security_quantum_break_mldsa",
        "domain_separation",
    ],
    status: VerificationStatus::Pending,
};

/// Модель KT v2 self-monitoring ghost participant detection (block 9.3).
///
/// Доказывает что любая substitution содержимого V2 entry в KT log
/// (substituted hybrid pubkey, substituted SLH-DSA backup pubkey,
/// omitted backup, либо unexpected backup) обнаруживается self-monitoring
/// через byte-equal сравнение observed entry vs local user state.
/// Per SPEC-13-PQ-HYBRID v1.0.0 §6 (KT log schema v2) +
/// SPEC-09-KEY-TRANSPARENCY §3 (self-monitoring доктрина no silent
/// acceptance).
///
/// Свойства:
/// - `ghost_participant_substitution_detected`: substituted hybrid
///   pubkey detectable через self-monitor; field tag в monitor.rs
///   `v2_identity_hybrid_pubkey`.
/// - `slh_dsa_backup_substitution_detected`: substituted SLH-DSA backup
///   pubkey detectable; field tag `v2_slh_dsa_backup_pubkey`.
/// - `slh_dsa_backup_unexpected_missing_detected`: omitted backup
///   (когда expected 'present') либо unexpected backup (когда expected
///   'absent') detectable; field tags `v2_slh_dsa_backup_missing` /
///   `v2_slh_dsa_backup_unexpected`.
///
/// Threat model: active Dolev–Yao adversary с control над DS log
/// content (insider attack на log delivery service). Self-monitoring
/// user iterates available entries и проверяет каждый byte-equal
/// против local state — non-deterministic choice абстрагируется в
/// модели через persistent multiset KtEntry facts.
///
/// # Constant: KT_V2_SELF_MONITORING (English)
///
/// KT v2 self-monitoring ghost participant detection model (block 9.3).
///
/// Proves that any substitution of V2 entry content in the KT log
/// (substituted hybrid pubkey, substituted SLH-DSA backup pubkey,
/// omitted backup, or unexpected backup) is detected by self-monitoring
/// via a byte-equal comparison of the observed entry vs the local user
/// state. Per SPEC-13-PQ-HYBRID v1.0.0 §6 (KT log schema v2) +
/// SPEC-09-KEY-TRANSPARENCY §3 (self-monitoring doctrine: no silent
/// acceptance).
///
/// Properties:
/// - `ghost_participant_substitution_detected`: a substituted hybrid
///   pubkey is detectable via self-monitor; field tag in monitor.rs is
///   `v2_identity_hybrid_pubkey`.
/// - `slh_dsa_backup_substitution_detected`: a substituted SLH-DSA
///   backup pubkey is detectable; field tag `v2_slh_dsa_backup_pubkey`.
/// - `slh_dsa_backup_unexpected_missing_detected`: an omitted backup
///   (when expected `present`) or an unexpected backup (when expected
///   `absent`) is detectable; field tags `v2_slh_dsa_backup_missing` /
///   `v2_slh_dsa_backup_unexpected`.
///
/// Threat model: an active Dolev–Yao adversary with control over the
/// DS log content (insider attack on the log delivery service). The
/// self-monitoring user iterates available entries and checks each
/// byte-equal against the local state — the non-deterministic choice
/// is abstracted in the model via persistent multiset KtEntry facts.
pub const KT_V2_SELF_MONITORING: ModelMetadata = ModelMetadata {
    name: "umbrella_kt_v2_self_monitoring",
    // spec_reference + spec_version synchronously bumped 1.0.0 → 1.0.1
    // per F-KT-V2-MODEL-1 closure (PhD-B Pass 5 remediation 2026-05-19,
    // F-59 sync pattern). The 3 primary lemmas were structural-truth
    // tautologies: 2 were tuple-inequality tautologies
    // `not(<sub,f,s> = <orig,f,s>)` (different tuple components →
    // different tuples by Tamarin term algebra), and 1 was a
    // bidirectional literal-disjointness tautology over `'absent' ≠
    // 'present'` atoms. All 3 refactored to substantive correspondence
    // claims: SelfMonitor mismatch ⇒ exists earlier Adversary* event.
    // The bidirectional `unexpected_missing` lemma was SPLIT into 2
    // direction-specific lemmas (`omission_detected_v2` +
    // `unexpected_addition_detected_v2`) for clarity. 4 new exists-
    // trace lemmas (`*_admits_detection`) anchor non-vacuity. Test
    // `kt_v2_self_monitoring_spec_version_matches_current_spec`
    // enforces continued sync between `spec_reference` and
    // `spec_version` fields.
    spec_reference: "SPEC-13-PQ-HYBRID v1.0.1 §6 + SPEC-09 §3",
    spec_version: "1.0.1",
    block_reference: "9.3",
    tool: ProtocolType::Tamarin,
    model_path: "models/kt_v2_self_monitoring.spthy",
    properties: &[
        "ghost_participant_substitution_detected",
        "slh_dsa_backup_substitution_detected",
        "slh_dsa_backup_omission_detected_v2",
        "slh_dsa_backup_unexpected_addition_detected_v2",
        "ghost_substitution_admits_detection",
        "slh_backup_substitution_admits_detection",
        "slh_backup_omission_admits_detection",
        "slh_backup_unexpected_addition_admits_detection",
        "honest_setup_executable",
    ],
    status: VerificationStatus::Verified {
        last_run: "2026-05-19",
    },
};

/// Модель sealed-sender V2 envelope sender privacy в quantum threat model
/// (block 9.4).
///
/// Доказывает что adversary observing public sealed-sender V2 wire bytes
/// (xwing_ct + aead_ct + version stamp) не может recover sender identity.
/// X25519 ephemeral pubkey не expose'ен — он встроен внутри xwing_ct per
/// draft-connolly-cfrg-xwing-kem-06 §3 X-Wing combiner; combiner joint
/// security is axiomatized here and backed by the verified
/// xwing_combiner.spthy block 9.2 model.
///
/// Свойства:
/// - `sender_privacy_under_quantum_adversary`: free private secret
///   `sender_id_v2` не достижим adversary через observation public канала.
/// - `cross_protocol_replay_v1_v2_blocked`: V1 envelope не может быть
///   replay'ен как V2 (или наоборот) — distinct domain separators yield
///   independent HKDF outputs + AEAD AAD includes version stamp.
/// - `aead_aad_binding`: AEAD AAD = version || xwing_ct ||
///   recipient_xwing_pubkey binds ciphertext к specific envelope version
///   + recipient.
/// - `recipient_bound_hkdf_info`: HKDF info явно включает transcript
///   material + recipient public key; это model-shape invariant, не
///   forward-secrecy claim.
///
/// Threat model: active Dolev–Yao adversary через standard ProVerif
/// `attacker` semantics; quantum capability моделируется implicitly через
/// X-Wing combiner axiom (joint security holds против passive adversary).
///
/// # Constant: SEALED_SENDER_V2 (English)
///
/// Sealed-sender V2 envelope sender-privacy model in the quantum threat
/// model (block 9.4).
///
/// Proves that an adversary observing public sealed-sender V2 wire bytes
/// (xwing_ct + aead_ct + version stamp) cannot recover the sender
/// identity. The X25519 ephemeral pubkey is not exposed — it is embedded
/// inside xwing_ct per draft-connolly-cfrg-xwing-kem-06 §3 X-Wing
/// combiner; the combiner joint security is axiomatized here and backed by
/// the verified xwing_combiner.spthy block 9.2 model.
///
/// Properties:
/// - `sender_privacy_under_quantum_adversary`: the free private secret
///   `sender_id_v2` is not reachable by the adversary through observation
///   of the public channel.
/// - `cross_protocol_replay_v1_v2_blocked`: a V1 envelope cannot be
///   replayed as V2 (or vice versa) — distinct domain separators yield
///   independent HKDF outputs + AEAD AAD includes the version stamp.
/// - `aead_aad_binding`: the AEAD AAD = version || xwing_ct ||
///   recipient_xwing_pubkey binds the ciphertext to a specific envelope
///   version + recipient.
/// - `recipient_bound_hkdf_info`: HKDF info explicitly includes transcript
///   material + recipient public key; this is a model-shape invariant, not
///   a forward-secrecy claim.
///
/// Threat model: an active Dolev–Yao adversary through the standard
/// ProVerif `attacker` semantics; quantum capability is modelled
/// implicitly via the X-Wing combiner axiom (joint security holds
/// against a passive adversary).
pub const SEALED_SENDER_V2: ModelMetadata = ModelMetadata {
    name: "umbrella_sealed_sender_v2",
    spec_reference: "SPEC-13-PQ-HYBRID v1.0.0 §7",
    spec_version: "1.0.0",
    block_reference: "9.4",
    tool: ProtocolType::ProVerif,
    model_path: "models/sealed_sender_v2.pv",
    properties: &[
        "sender_privacy_under_quantum_adversary",
        "cross_protocol_replay_v1_v2_blocked",
        "aead_aad_binding",
        "recipient_bound_hkdf_info",
    ],
    status: VerificationStatus::Pending,
};

/// Модель backup wrap V2 outer X-Wing PQ confidentiality (block 9.4).
///
/// Доказывает что V2 outer X-Wing layer над V1 ElGamal threshold-wrap
/// protects recovery key против quantum harvest-now-decrypt-later (h-n-d-l)
/// без recipient X-Wing private key. V1 81-byte WrappedKey bytes сохранены
/// байт-в-байт inside V2 outer aead_payload (97 bytes = 81 V1 + 16
/// Poly1305 tag). Recipient X-Wing keypair derive детерминистически из
/// 24-word BIP-39 mnemonic через HKDF info-context
/// "umbrellax-cloud-wrap-recovery-xwing-v1" (Pattern B reuse).
///
/// Свойства:
/// - `quantum_adversary_cannot_recover_recovery_key`: outer X-Wing layer
///   защищает V1 inner bytes от h-n-d-l даже при future quantum
///   cryptanalysis V1 ElGamal.
/// - `v1_inner_layer_preserved`: V1 wrapped key bytes сохранены inside
///   V2; server ceremony unchanged. This is a non-injective
///   preservation correspondence because replay-cache state is not modeled.
/// - `bip39_single_derivation_source`: same 24-word mnemonic + same HKDF
///   info-context yields same X-Wing keypair (deterministic Pattern B).
/// - `cross_protocol_replay_v1_v2_blocked`: V1 wrapped key bytes не могут
///   быть presented как V2 (или наоборот) — distinct domain separators +
///   AEAD AAD binding.
///
/// Threat model: active Dolev–Yao adversary; quantum capability через
/// verified X-Wing combiner axiom; adversary не имеет access ни к
/// recipient X-Wing private key, ни к 24-word BIP-39 mnemonic.
///
/// # Constant: BACKUP_WRAP_V2 (English)
///
/// Backup wrap V2 outer X-Wing PQ-confidentiality model (block 9.4).
///
/// Proves that the V2 outer X-Wing layer over the V1 ElGamal
/// threshold-wrap protects the recovery key against quantum
/// harvest-now-decrypt-later (h-n-d-l) without the recipient X-Wing
/// private key. The V1 81-byte WrappedKey bytes are preserved
/// byte-for-byte inside the V2 outer aead_payload (97 bytes = 81 V1 + 16
/// Poly1305 tag). The recipient X-Wing keypair is derived deterministically
/// from a 24-word BIP-39 mnemonic via the HKDF info-context
/// "umbrellax-cloud-wrap-recovery-xwing-v1" (Pattern B reuse).
///
/// Properties:
/// - `quantum_adversary_cannot_recover_recovery_key`: the outer X-Wing
///   layer protects the V1 inner bytes from h-n-d-l even under future
///   quantum cryptanalysis of V1 ElGamal.
/// - `v1_inner_layer_preserved`: the V1 wrapped key bytes are preserved
///   inside V2; the server ceremony is unchanged. This is a
///   non-injective preservation correspondence because replay-cache state
///   is not modeled.
/// - `bip39_single_derivation_source`: the same 24-word mnemonic + the
///   same HKDF info-context yields the same X-Wing keypair (deterministic
///   Pattern B).
/// - `cross_protocol_replay_v1_v2_blocked`: V1 wrapped key bytes cannot be
///   presented as V2 (or vice versa) — distinct domain separators + AEAD
///   AAD binding.
///
/// Threat model: an active Dolev–Yao adversary; quantum capability via
/// the verified X-Wing combiner axiom; the adversary has access to neither the
/// recipient X-Wing private key nor the 24-word BIP-39 mnemonic.
pub const BACKUP_WRAP_V2: ModelMetadata = ModelMetadata {
    name: "umbrella_backup_wrap_v2",
    spec_reference: "SPEC-13-PQ-HYBRID v1.0.0 §8",
    spec_version: "1.0.0",
    block_reference: "9.4",
    tool: ProtocolType::ProVerif,
    model_path: "models/backup_wrap_v2.pv",
    properties: &[
        "quantum_adversary_cannot_recover_recovery_key",
        "v1_inner_layer_preserved",
        "bip39_single_derivation_source",
        "cross_protocol_replay_v1_v2_blocked",
    ],
    status: VerificationStatus::Pending,
};

/// Модель downgrade resistance — capability negotiation no-silent-fallback
/// (block 9.4).
///
/// Моделирует intended no-silent-fallback invariant: active Dolev–Yao
/// adversary не должен force PQ-aware peer silently downgrade на classical
/// ciphersuite (0x0003) без explicit user override через
/// `ChatSettings.ciphersuite = Some(0x0003)` ИЛИ explicit capability
/// mismatch (mixed group с classical-only peer). Production-readiness focused
/// run 2026-05-09 did not complete within the bounded Tamarin proof window;
/// status is `Failed` until a successful proof run replaces this evidence.
/// Per SPEC-13-PQ-HYBRID v1.0.0 §9 + ADR-013 (Stage 1 default switch на
/// 0x004D) + ADR-011 Решение 7 (feature flag иерархия).
///
/// Свойства:
/// - `adversary_cannot_force_silent_downgrade`: PQ-aware Alice + PQ-aware
///   Bob negotiate suite — обязательно 0x004D без prior ExplicitOverride
///   event. Active MITM не может force fallback на 0x0003.
/// - `explicit_chatsettings_override_allowed`: caller может explicit set
///   `ChatSettings.ciphersuite = Some(0x0003)` (legitimate user choice
///   для mixed group); такой override accepted (sanity exists-trace).
/// - `default_ciphersuite_respected`: ChatSettings.ciphersuite = None →
///   uses ClientConfig::default_ciphersuite (0x004D под cfg pq).
/// - `no_silent_fallback_under_capability_mismatch`: caller sets
///   `Some(0x004D)` на classical-only client → MlsError::Capabilities
///   event fires; ни один Group fact не создаётся.
///
/// Threat model: active Dolev–Yao через standard Tamarin semantics;
/// adversary не может modify peer's local persistent state
/// (`!ClientPq` / `!ClientClassical` / `!ChatSettingsExplicit`); только
/// network-level interception.
///
/// # Constant: DOWNGRADE_RESISTANCE (English)
///
/// Downgrade resistance — capability negotiation no-silent-fallback model
/// (block 9.4).
///
/// Models the intended no-silent-fallback invariant: an active Dolev–Yao
/// adversary should not force a PQ-aware peer to silently downgrade to a
/// classical ciphersuite (0x0003) without an explicit user override via
/// `ChatSettings.ciphersuite = Some(0x0003)` OR explicit capability
/// mismatch (a mixed group with a classical-only peer). The
/// production-readiness focused run on 2026-05-09 did not complete within
/// the bounded Tamarin proof window; status is `Failed` until a successful
/// proof run replaces this evidence. Per SPEC-13-PQ-HYBRID v1.0.0 §9 +
/// ADR-013 (Stage 1 default switch to 0x004D) + ADR-011 Decision 7
/// (feature flag hierarchy).
///
/// Properties:
/// - `adversary_cannot_force_silent_downgrade`: a PQ-aware Alice +
///   PQ-aware Bob negotiate a suite — necessarily 0x004D without a prior
///   ExplicitOverride event. An active MITM cannot force a fallback to
///   0x0003.
/// - `explicit_chatsettings_override_allowed`: a caller can explicitly
///   set `ChatSettings.ciphersuite = Some(0x0003)` (a legitimate user
///   choice for a mixed group); such an override is accepted (sanity
///   exists-trace).
/// - `default_ciphersuite_respected`: ChatSettings.ciphersuite = None →
///   uses ClientConfig::default_ciphersuite (0x004D under cfg pq).
/// - `no_silent_fallback_under_capability_mismatch`: a caller sets
///   `Some(0x004D)` on a classical-only client → an MlsError::Capabilities
///   event fires; no Group fact is created.
///
/// Threat model: active Dolev–Yao through standard Tamarin semantics; the
/// adversary cannot modify the peer's local persistent state (`!ClientPq`
/// / `!ClientClassical` / `!ChatSettingsExplicit`); only network-level
/// interception.
pub const DOWNGRADE_RESISTANCE: ModelMetadata = ModelMetadata {
    name: "umbrella_downgrade_resistance",
    spec_reference: "SPEC-13-PQ-HYBRID v1.0.0 §9",
    spec_version: "1.0.0",
    block_reference: "9.4",
    tool: ProtocolType::Tamarin,
    model_path: "models/downgrade_resistance.spthy",
    properties: &[
        "adversary_cannot_force_silent_downgrade",
        "explicit_chatsettings_override_allowed",
        "default_ciphersuite_respected",
        "no_silent_fallback_under_capability_mismatch",
    ],
    status: VerificationStatus::Failed {
        reason: "production-readiness 2026-05-09 bounded Tamarin run hit 180s alarm; see docs/audits/production-readiness-2026-05-09/residual-risks.md"
    },
};

/// Модель KT V1 self-monitoring ghost participant detection (block 9.5).
///
/// Analogue к KT V2 self-monitoring (block 9.3) но для V1 entries
/// (Ed25519-only identity_pubkey + device_pubkey list; без hybrid pubkey;
/// без SLH-DSA backup). Per SPEC-09 §6 (Self-monitoring) + SPEC-13 §6.1
/// (V1 entries baseline). Любая substitution V1 entry (substituted
/// identity_pubkey либо substituted device_pubkey либо foreign rotation
/// attempt) обнаруживается self-monitoring через byte-equal сравнение.
///
/// Свойства:
/// - `identity_substitution_detected_v1`: substituted identity_pubkey
///   detectable через self-monitor; field check `KtError::IdentityMismatch`
///   alert.
/// - `device_substitution_detected_v1`: substituted device_pubkey не из
///   expected active list — `KtError::UnknownDevice` alert.
/// - `foreign_identity_detected_v1`: IdentityRotationRecord с foreign
///   old_identity_pubkey — `KtError::ForeignIdentity` alert.
///
/// Threat model: active Dolev–Yao adversary с control над DS log content
/// (insider attack); self-monitoring user iterates available entries и
/// проверяет каждый byte-equal против local state.
///
/// # Constant: KT_V1_SELF_MONITORING (English)
///
/// KT V1 self-monitoring ghost participant detection model (block 9.5).
///
/// Analogue to KT V2 self-monitoring (block 9.3) but for V1 entries
/// (Ed25519-only identity_pubkey + device_pubkey list; no hybrid pubkey;
/// no SLH-DSA backup). Per SPEC-09 §6 (Self-monitoring) + SPEC-13 §6.1
/// (V1 entries baseline). Any V1 entry substitution (substituted
/// identity_pubkey, substituted device_pubkey, or foreign rotation
/// attempt) is detected by self-monitoring through byte-equal comparison.
///
/// Properties:
/// - `identity_substitution_detected_v1`: a substituted identity_pubkey
///   is detectable via self-monitor; field check `KtError::IdentityMismatch`
///   alert.
/// - `device_substitution_detected_v1`: a substituted device_pubkey not
///   in the expected active list — `KtError::UnknownDevice` alert.
/// - `foreign_identity_detected_v1`: an IdentityRotationRecord with a
///   foreign old_identity_pubkey — `KtError::ForeignIdentity` alert.
///
/// Threat model: an active Dolev–Yao adversary with control over the DS
/// log content (insider attack); the self-monitoring user iterates over
/// available entries and verifies each byte-equal against the local state.
pub const KT_V1_SELF_MONITORING: ModelMetadata = ModelMetadata {
    name: "umbrella_kt_v1_self_monitoring",
    // spec_reference + spec_version synchronously bumped 0.0.1 → 0.0.2
    // per F-KT-V1-MODEL-1 closure (PhD-B Pass 5 remediation 2026-05-19,
    // F-59 sync pattern). The three primary lemmas (identity / device /
    // foreign_identity substitution_detected_v1) были тавтологиями вида
    // `not(A=B) ⇒ not(B=A)` (commutativity of `=`), provable without
    // touching any protocol rule. Closure restates as substantive
    // correspondence claims: SelfMonitor with mismatch ⇒ exists earlier
    // AdversarySubstitute event. Three new exists-trace lemmas
    // (`*_admits_detection`) anchor non-vacuity. Test
    // `kt_v1_self_monitoring_spec_version_matches_current_spec` enforces
    // continued sync between `spec_reference` and `spec_version` fields.
    spec_reference: "SPEC-09-KEY-TRANSPARENCY v0.0.2 §6 + SPEC-13 §6.1",
    spec_version: "0.0.2",
    block_reference: "9.5",
    tool: ProtocolType::Tamarin,
    model_path: "models/kt_v1_self_monitoring.spthy",
    properties: &[
        "identity_substitution_detected_v1",
        "device_substitution_detected_v1",
        "foreign_identity_detected_v1",
        "identity_substitution_admits_detection",
        "device_substitution_admits_detection",
        "foreign_rotation_admits_detection",
        "honest_setup_executable",
    ],
    status: VerificationStatus::Verified {
        last_run: "2026-05-19",
    },
};

/// Модель sealed-sender V1 envelope sender privacy в classical threat
/// model (block 9.5).
///
/// Analogue к sealed-sender V2 (block 9.4) но для V1 envelope (X25519
/// ECDH only, no X-Wing combiner). V1 не provides post-quantum protection
/// (это V2 только); V1 secure только против classical Dolev–Yao adversary
/// без quantum capabilities (pre-CRQC threat model). Per SPEC-08 §3-§5
/// (V1 envelope wire format + protocol seal/unseal).
///
/// Свойства:
/// - `sender_privacy_classical`: classical adversary observing public
///   канал не может recover sender_id_v1; X25519 DDH assumption holds.
/// - `cross_protocol_replay_v1_v2_blocked`: V1 envelope не может быть
///   replay'ен как V2 (или наоборот) — distinct domain separators.
/// - `aead_aad_binding`: AEAD AAD = version || eph_pub || recipient_pk
///   binds ciphertext к specific envelope version + recipient.
/// - `recipient_bound_hkdf_info`: HKDF info явно включает transcript
///   material + recipient public key; это model-shape invariant, не
///   forward-secrecy claim.
///
/// Threat model: active Dolev–Yao adversary через standard ProVerif
/// `attacker` semantics; classical capability — V1 не provides h-n-d-l
/// protection.
///
/// # Constant: SEALED_SENDER_V1 (English)
///
/// Sealed-sender V1 envelope sender-privacy model in the classical threat
/// model (block 9.5).
///
/// Analogue to sealed-sender V2 (block 9.4) but for the V1 envelope
/// (X25519 ECDH only, no X-Wing combiner). V1 does not provide
/// post-quantum protection (only V2 does); V1 is secure only against a
/// classical Dolev–Yao adversary without quantum capabilities (pre-CRQC
/// threat model). Per SPEC-08 §3-§5 (V1 envelope wire format + protocol
/// seal/unseal).
///
/// Properties:
/// - `sender_privacy_classical`: a classical adversary observing the
///   public channel cannot recover sender_id_v1; the X25519 DDH
///   assumption holds.
/// - `cross_protocol_replay_v1_v2_blocked`: a V1 envelope cannot be
///   replayed as V2 (or vice versa) — distinct domain separators.
/// - `aead_aad_binding`: the AEAD AAD = version || eph_pub ||
///   recipient_pk binds the ciphertext to a specific envelope version
///   + recipient.
/// - `recipient_bound_hkdf_info`: HKDF info explicitly includes transcript
///   material + recipient public key; this is a model-shape invariant, not
///   a forward-secrecy claim.
///
/// Threat model: an active Dolev–Yao adversary through the standard
/// ProVerif `attacker` semantics; classical capability — V1 does not
/// provide h-n-d-l protection.
pub const SEALED_SENDER_V1: ModelMetadata = ModelMetadata {
    name: "umbrella_sealed_sender_v1",
    spec_reference: "SPEC-08-SEALED-SENDER v0.0.2 §3-§5",
    spec_version: "0.0.2",
    block_reference: "9.5",
    tool: ProtocolType::ProVerif,
    model_path: "models/sealed_sender_v1.pv",
    properties: &[
        "sender_privacy_classical",
        "cross_protocol_replay_v1_v2_blocked",
        "aead_aad_binding",
        "recipient_bound_hkdf_info",
    ],
    status: VerificationStatus::Pending,
};

/// Модель MLS Ed25519-only profile + disabled external operations + ETK
/// split-brain attack prevention (block 9.5).
///
/// ETK split-brain attack (Cremers et al. eprint 2025/229 «ETK:
/// External-Operations TreeKEM and the Security of MLS in RFC 9420»):
/// MLS TreeKEM с non-SUF-CMA подписями (ECDSA) уязвим к split-view
/// атаке через ECDSA malleability; receivers Alice + Bob расходятся в
/// transcript hash chain. С Ed25519 (SUF-CMA по построению) этой атаки
/// нет. Защита: SPEC-03 §4.1 whitelists только Ed25519-based
/// ciphersuites; SPEC-03 §5.1 Private group default — no external
/// commits + no external proposals + no external PSK injection.
///
/// Свойства:
/// - `external_operations_disabled`: для private group (ext_ops_enabled =
///   false) никакие external operations не accepted.
/// - `etk_split_brain_prevented`: Alice и Bob members одной группы видят
///   same epoch state — Ed25519 SUF-CMA prevents ECDSA malleability
///   split-view attack.
/// - `ed25519_only_whitelist`: любая Negotiated ciphersuite обязательно
///   из whitelist Ed25519-based; ECDSA-based ciphersuites не появляются.
///
/// Threat model: active Dolev–Yao adversary через standard Tamarin
/// semantics; adversary не может modify peer's local persistent state
/// (`!Member` / `!Group`); ETK split-brain via ECDSA malleability blocked
/// через Tamarin signing builtin (Ed25519-modelling).
///
/// # Constant: MLS_ED25519 (English)
///
/// MLS Ed25519-only profile + disabled external operations + ETK
/// split-brain attack prevention model (block 9.5).
///
/// ETK split-brain attack (Cremers et al. eprint 2025/229 "ETK:
/// External-Operations TreeKEM and the Security of MLS in RFC 9420"):
/// MLS TreeKEM with non-SUF-CMA signatures (ECDSA) is vulnerable to a
/// split-view attack via ECDSA malleability; receivers Alice + Bob
/// diverge in the transcript hash chain. With Ed25519 (SUF-CMA by
/// construction), this attack does not exist. Defence: SPEC-03 §4.1
/// whitelists only Ed25519-based ciphersuites; SPEC-03 §5.1 Private
/// group default — no external commits + no external proposals + no
/// external PSK injection.
///
/// Properties:
/// - `external_operations_disabled`: for a private group
///   (ext_ops_enabled = false), no external operations are accepted.
/// - `etk_split_brain_prevented`: Alice and Bob, members of the same
///   group, see the same epoch state — Ed25519 SUF-CMA prevents the
///   ECDSA malleability split-view attack.
/// - `ed25519_only_whitelist`: any Negotiated ciphersuite must come from
///   the Ed25519-based whitelist; ECDSA-based ciphersuites do not appear.
///
/// Threat model: an active Dolev–Yao adversary through the standard
/// Tamarin semantics; the adversary cannot modify the peer's local
/// persistent state (`!Member` / `!Group`); ETK split-brain via ECDSA
/// malleability is blocked through the Tamarin signing builtin
/// (Ed25519-modelling).
pub const MLS_ED25519: ModelMetadata = ModelMetadata {
    name: "umbrella_mls_ed25519",
    // spec_reference + spec_version synchronously bumped 0.0.1 → 0.0.2
    // per F-MLS-MODEL-1 closure (PhD-B Pass 5 remediation 2026-05-19,
    // F-59 closure pattern). The three primary lemmas
    // (external_operations_disabled, etk_split_brain_prevented,
    // ed25519_only_whitelist) were tautological pre-closure and have
    // been re-stated as substantive claims. Two new exists-trace
    // lemmas (public_group_admits_external_commit,
    // ecdsa_malleability_admits_distinct_verifying_signatures) make
    // the model non-vacuous and demonstrate the contrasting ECDSA
    // attack surface that Tamarin's `signing` builtin (Ed25519
    // SUF-CMA) closes. Test
    // `mls_ed25519_spec_version_matches_current_spec` enforces both
    // fields stay in sync.
    spec_reference: "SPEC-03-MLS-PROFILE v0.0.2 §4.1 + §4.3 + §5.1",
    spec_version: "0.0.2",
    block_reference: "9.5",
    tool: ProtocolType::Tamarin,
    model_path: "models/mls_ed25519.spthy",
    properties: &[
        "external_operations_disabled",
        "public_group_admits_external_commit",
        "etk_split_brain_prevented",
        "ecdsa_malleability_admits_distinct_verifying_signatures",
        "ed25519_only_whitelist",
        "honest_setup_executable",
    ],
    status: VerificationStatus::Verified {
        last_run: "2026-05-19",
    },
};

/// Модель multi-device authorization flow + identity rotation per ADR-008
/// (block 10.23).
///
/// Доказывает что 24-words leak attack (SPEC-01 § 4 row 8 multi-device
/// leakage) НЕ дёт adversary доступа к unwrap shares без compromise existing
/// active device — pending → active state transition требует валидной
/// `DeviceAuthorizationApproval` signed существующим active device-key.
/// Identity rotation через `IdentityRotationRecord` обязательно signed и
/// старым и новым identity-sk (atomic dual signature).
///
/// Свойства:
/// - `pending_state_required_before_active`: state-machine pending → active
///   обязательна для всех non-bootstrap devices.
/// - `active_device_signs_authorization`: approval signature от existing
///   active device обязательна (Ed25519 SUF-CMA).
/// - `unauthorized_device_rejected_by_sealed_servers`: Sealed Server unwrap
///   shares только для active devices.
/// - `twentyfour_words_leak_alone_insufficient`: PRIMARY threat-model claim
///   — 24-words leak без active device-sk не достаточно для unwrap.
/// - `identity_rotation_atomic_dual_signature`: rotation требует both old
///   и new identity signatures.
/// - `revocation_terminal_state`: revoked device cannot be re-activated.
///
/// Threat model: active Dolev–Yao adversary с access к 24-словам через
/// `reveal_identity_sk` rule (24-words leak attack simulation); cannot
/// modify peer's local persistent state; cannot leak active device-sk
/// (physical phone protection assumption).
///
/// # Constant: MULTI_DEVICE_AUTHORIZATION (English)
///
/// Multi-device authorization + identity rotation model per ADR-008 (block
/// 10.23).
///
/// Proves that the 24-words leak attack (SPEC-01 § 4 row 8 multi-device
/// leakage) does NOT grant the adversary access to unwrap shares without
/// compromise of an existing active device — the pending → active state
/// transition requires a valid `DeviceAuthorizationApproval` signed by the
/// existing active device-key. Identity rotation via
/// `IdentityRotationRecord` requires signatures by both the old and new
/// identity-sk (atomic dual signature).
///
/// Properties:
/// - `pending_state_required_before_active`: pending → active state machine
///   is required for all non-bootstrap devices.
/// - `active_device_signs_authorization`: approval signature from an
///   existing active device is required (Ed25519 SUF-CMA).
/// - `unauthorized_device_rejected_by_sealed_servers`: Sealed Server unwrap
///   shares are only released for active devices.
/// - `twentyfour_words_leak_alone_insufficient`: PRIMARY threat-model
///   claim — a 24-words leak without an active device-sk is insufficient
///   for unwrap.
/// - `identity_rotation_atomic_dual_signature`: rotation requires both old
///   and new identity signatures.
/// - `revocation_terminal_state`: a revoked device cannot be re-activated.
///
/// Threat model: an active Dolev–Yao adversary with access to the
/// 24-words through the `reveal_identity_sk` rule (24-words leak attack
/// simulation); cannot modify the peer's local persistent state; cannot
/// leak an active device-sk (physical phone protection assumption).
pub const MULTI_DEVICE_AUTHORIZATION: ModelMetadata = ModelMetadata {
    name: "umbrella_multi_device_authorization",
    spec_reference:
        "SPEC-09-KEY-TRANSPARENCY v0.0.1 §3 + SPEC-11-MULTI-DEVICE v0.0.1 + ADR-008 §1+§3+§5+§6",
    spec_version: "0.0.1",
    block_reference: "10.23",
    tool: ProtocolType::Tamarin,
    model_path: "models/multi_device_authorization.spthy",
    properties: &[
        "pending_state_required_before_active",
        "active_device_signs_authorization",
        "unauthorized_device_rejected_by_sealed_servers",
        "twentyfour_words_leak_alone_insufficient",
        "identity_rotation_atomic_dual_signature",
        "revocation_terminal_state",
    ],
    status: VerificationStatus::Verified {
        last_run: "2026-05-07",
    },
};

/// Модель SFrame RFC 9605 key schedule + per-frame anti-replay + AEAD AAD
/// binding для групповых видеозвонков (block 10.23).
///
/// Доказывает SFrame key schedule integrity property: MLS exporter →
/// base_key (Nh=64) → HKDF-Extract → per-KID (sframe_key, sframe_salt) →
/// per-frame nonce XOR counter → AES-256-GCM с sframe_header bytes как
/// AAD. Anti-replay window per RFC 9605 §5.5: каждая (kid, counter) tuple
/// consumed at most once per recipient. AEAD AAD binding: подмена header
/// fields → decryption fails.
///
/// Cold-boot scope (SPEC-01 § 4 row 11) partial closure — formal
/// verification key schedule integrity property; полная row 11 защита
/// также включает Secure Enclave + zeroize layers (block 9.13 + Stage 7
/// keystore) которые out-of-scope этой model.
///
/// Свойства:
/// - `per_kid_counter_anti_replay`: replay rejected per RFC 9605 §5.5.
/// - `frame_decrypt_authentic`: AEAD AAD binding к kid + counter.
/// - `dtls_identity_binding_consistent`: deterministic fingerprint per
///   identity-pk + session_nonce.
/// - `kid_uniqueness_per_epoch`: unique (sender, epoch, kid) tuple per
///   draft-ietf-mls-sframe.
///
/// Threat model: active Dolev–Yao adversary через standard Tamarin
/// semantics; can attempt frame replay; cannot recover MLS group key
/// (out-of-scope; covered upstream `mls_ed25519.spthy`); cannot leak
/// identity-sk (covered separately `multi_device_authorization.spthy`).
///
/// # Constant: SFRAME_RFC9605 (English)
///
/// SFrame RFC 9605 key schedule + per-frame anti-replay + AEAD AAD
/// binding model for group video calls (block 10.23).
///
/// Proves the SFrame key schedule integrity property: MLS exporter →
/// base_key (Nh=64) → HKDF-Extract → per-KID (sframe_key, sframe_salt) →
/// per-frame nonce XOR counter → AES-256-GCM with sframe_header bytes as
/// AAD. Anti-replay window per RFC 9605 §5.5: each (kid, counter) tuple
/// is consumed at most once per recipient. AEAD AAD binding: substituting
/// header fields → decryption fails.
///
/// Properties:
/// - `per_kid_counter_anti_replay`: replay is rejected per RFC 9605 §5.5.
/// - `frame_decrypt_authentic`: AEAD AAD binds the ciphertext to kid +
///   counter.
/// - `dtls_identity_binding_consistent`: deterministic fingerprint per
///   identity-pk + session_nonce.
/// - `kid_uniqueness_per_epoch`: unique (sender, epoch, kid) tuple per
///   draft-ietf-mls-sframe.
///
/// Threat model: an active Dolev–Yao adversary through standard Tamarin
/// semantics; can attempt a frame replay; cannot recover the MLS group
/// key (out-of-scope; covered upstream by `mls_ed25519.spthy`); cannot
/// leak the identity-sk (covered separately by
/// `multi_device_authorization.spthy`).
pub const SFRAME_RFC9605: ModelMetadata = ModelMetadata {
    name: "umbrella_sframe_rfc9605",
    // spec_reference + spec_version synchronously bumped 0.0.3 → 0.0.4
    // per F-SFRAME-MODEL-1 closure (PhD-B Pass 5 remediation 2026-05-19,
    // F-59 sync pattern). 2 of 4 primary lemmas
    // (dtls_identity_binding_consistent + kid_uniqueness_per_epoch) were
    // hash-determinism tautologies — proved «same inputs ⇒ same outputs»
    // which trivially follows from `h/1` being a function, without
    // touching protocol rules. Refactored to substantive CONVERSE
    // claims: collision resistance / KID injectivity — «same fingerprint
    // ⇒ same inputs», «same kid ⇒ same (sender, epoch)». 2 new exists-
    // trace anchors (`*_admits_distinct_*`) prove the converse claims
    // are non-vacuous (model admits distinct outputs for distinct
    // inputs).
    spec_reference: "SPEC-06-CALLS-AND-IP-PRIVACY v0.0.4 §5+§6+§4.1 + ADR-009 + RFC 9605",
    spec_version: "0.0.4",
    block_reference: "10.23",
    tool: ProtocolType::Tamarin,
    model_path: "models/sframe_rfc9605.spthy",
    properties: &[
        "per_kid_counter_anti_replay",
        "frame_decrypt_authentic",
        "dtls_identity_binding_consistent",
        "dtls_binding_distinct_inputs_admit_distinct_fingerprints",
        "kid_uniqueness_per_epoch",
        "kid_distinct_per_sender_or_epoch_admits_distinct_kid",
        "honest_setup_executable",
    ],
    status: VerificationStatus::Verified {
        last_run: "2026-05-19",
    },
};

/// Модель ADR-006 Вариант C type-safe разграничения Cloud vs Secret режимов
/// (block 10.23).
///
/// Symbolically captures invariant что: Cloud-mode требует обязательного
/// Sealed Servers 3-of-5 unwrap (E2E undelivery без сервер-side participation
/// impossible); Secret-mode полностью bypass'ит Sealed Servers (pure MLS
/// ratchet); mode separation invariant — невозможно случайно cloud-sync
/// на SecretChatHandle через type-system. Compile-time enforcement
/// проверяется compile-fail E0599 doctest в umbrella-client crate.
///
/// Multi-device leakage row 8 closure (different from ADR-008 authorization
/// flow): focus здесь на mode-level enforcement что Sealed Servers
/// participation only для Cloud chats; Secret chats полностью isolated от
/// Sealed Server attack surface.
///
/// Свойства:
/// - `cloud_chat_requires_sealed_servers`: ReadCloudHistory требует
///   prior SealedServerUnwrap.
/// - `secret_chat_no_cloud_unwrap`: ReadSecretMessage никогда не
///   связан с SealedServerUnwrap.
/// - `mode_separation_invariant`: chat имеет fixed mode permanently.
/// - `secret_chat_three_of_five_servers_compromise_irrelevant`:
///   compromise of 3+ Sealed Servers does NOT affect Secret content.
///
/// Threat model: passive Dolev–Yao adversary; can compromise up to 2 of
/// 5 Sealed Servers через `compromise_sealed_server` rule; cannot access
/// user device либо MLS group key.
///
/// # Constant: TYPE_SAFE_ENFORCEMENT (English)
///
/// ADR-006 Variant C type-safe Cloud vs Secret modes separation model
/// (block 10.23).
///
/// Symbolically captures the invariant that: Cloud-mode requires Sealed
/// Servers 3-of-5 unwrap (no E2E delivery without server-side
/// participation); Secret-mode completely bypasses Sealed Servers (pure
/// MLS ratchet); mode separation invariant — cloud-sync on a
/// SecretChatHandle is impossible through the type-system.
/// Compile-time enforcement is verified by a compile-fail E0599 doctest
/// in the umbrella-client crate.
///
/// Multi-device leakage row 8 closure (different from ADR-008
/// authorization flow): the focus here is on mode-level enforcement that
/// Sealed Servers participation is for Cloud chats only; Secret chats are
/// completely isolated from the Sealed Server attack surface.
///
/// Properties:
/// - `cloud_chat_requires_sealed_servers`: ReadCloudHistory requires a
///   prior SealedServerUnwrap.
/// - `secret_chat_no_cloud_unwrap`: ReadSecretMessage is never related
///   to SealedServerUnwrap.
/// - `mode_separation_invariant`: a chat has a fixed mode permanently.
/// - `secret_chat_three_of_five_servers_compromise_irrelevant`:
///   compromise of 3+ Sealed Servers does NOT affect Secret content.
///
/// Threat model: a passive Dolev–Yao adversary; can compromise up to 2 of
/// 5 Sealed Servers via the `compromise_sealed_server` rule; cannot
/// access the user device or the MLS group key.
pub const TYPE_SAFE_ENFORCEMENT: ModelMetadata = ModelMetadata {
    name: "umbrella_type_safe_enforcement",
    spec_reference: "Private protocol overview v1.0.0 §4.1",
    spec_version: "1.0.0",
    block_reference: "10.23",
    tool: ProtocolType::Tamarin,
    model_path: "models/type_safe_enforcement.spthy",
    properties: &[
        "cloud_chat_requires_sealed_servers",
        "secret_chat_no_cloud_unwrap",
        "mode_separation_invariant",
        "secret_chat_three_of_five_servers_compromise_irrelevant",
    ],
    status: VerificationStatus::Verified {
        last_run: "2026-05-07",
    },
};

/// Модель Ristretto255 OPRF + 3-of-5 Shamir threshold reconstruction
/// (block 10.23).
///
/// Threat scope: SPEC-01 § 4 row 13 «регулятор требует backdoor» primary
/// defence. Even при compromise 2 of 5 Sealed Servers (sub-threshold),
/// adversary не может recover client's input from blinded request —
/// Shamir threshold preserves privacy. Recovery требует ≥3 servers
/// cooperation. Privacy invariants per RFC 9497 §3 SUF (Strong
/// Unlinkability): server learns nothing about client's input — blinding
/// hides input под random scalar r ∈ Z_q.
///
/// Свойства:
/// - `oprf_blinding_oblivious`: client_input не достижим adversary через
///   public канал + ≤2 server reveals.
/// - `same_input_yields_same_label`: determinism — same input + same OPRF
///   setup yields same OprfLabel.
/// - `device_attestation_required_for_evaluation`: ServerEvaluate event
///   требует prior valid signed request.
///
/// Threat model: active Dolev–Yao adversary; может compromise до 2 of 5
/// Sealed Servers; не имеет client device-sk; не может compute
/// hash_to_curve preimage (random oracle).
///
/// # Constant: OPRF_RISTRETTO255 (English)
///
/// Ristretto255 OPRF + 3-of-5 Shamir threshold reconstruction model
/// (block 10.23).
///
/// Threat scope: SPEC-01 § 4 row 13 "regulator demands backdoor" primary
/// defence. Even under compromise of 2 of 5 Sealed Servers
/// (sub-threshold), the adversary cannot recover the client's input from
/// the blinded request — the Shamir threshold preserves privacy. Recovery
/// requires ≥3 servers cooperating. Privacy invariants per RFC 9497 §3
/// SUF (Strong Unlinkability): the server learns nothing about the
/// client's input — blinding hides the input under a random scalar r ∈
/// Z_q.
///
/// Properties:
/// - `oprf_blinding_oblivious`: client_input is not reachable by the
///   adversary through the public channel + ≤2 server reveals.
/// - `same_input_yields_same_label`: determinism — the same input + the
///   same OPRF setup yields the same OprfLabel.
/// - `device_attestation_required_for_evaluation`: a ServerEvaluate
///   event requires a prior valid signed request.
///
/// Threat model: an active Dolev–Yao adversary; may compromise up to 2 of
/// 5 Sealed Servers; does not have the client device-sk; cannot compute
/// the hash_to_curve preimage (random oracle).
pub const OPRF_RISTRETTO255: ModelMetadata = ModelMetadata {
    name: "umbrella_oprf_ristretto255",
    spec_reference: "SPEC-05-OPRF-CONTACT-DISCOVERY v0.0.2 §3+§4+§5+§6+§7 + ADR-005 + RFC 9497",
    spec_version: "0.0.2",
    block_reference: "10.23",
    tool: ProtocolType::ProVerif,
    model_path: "models/oprf_ristretto255.pv",
    properties: &[
        "oprf_blinding_oblivious",
        "same_input_yields_same_label",
        "device_attestation_required_for_evaluation",
    ],
    status: VerificationStatus::Failed {
        reason: "same_input_yields_same_label remains outside the ProVerif symbolic abstraction; production-readiness 2026-05-09 local rerun also lacked proverif in PATH; see docs/audits/production-readiness-2026-05-09/residual-risks.md"
    },
};

/// Round-7 discovery model: PSI + @username lookup + KT-bind security.
///
/// Доказывает 5 lemma + 1 sanity (всё 6/6 verified локально 2026-05-18):
/// - `server_never_learns_plaintext_phone` (D-1): сервер не получает
///   plaintext input.
/// - `intersection_cardinality_only_disclosed` (D-8): server learns
///   intersection cardinality only (а не сам plaintext).
/// - `kt_bind_prevents_silent_swap` (D-3): KT inclusion proof обязательно
///   совпадает с claimed_root → silent swap impossible.
/// - `anon_id_unlinkable_across_queries` (D-2 / D-6): два запроса одного
///   клиента имеют distinct anon_ids.
/// - `replay_protection_enforced` (D-5): один и тот же server response
///   не появляется дважды.
/// - `honest_discovery_executable`: existence-trace.
///
/// # Constant: DISCOVERY (English)
///
/// Round-7 discovery model: PSI + @username lookup + KT-bind security.
/// Proves 5 lemmas + 1 sanity (all 6/6 verified locally on 2026-05-18).
pub const DISCOVERY: ModelMetadata = ModelMetadata {
    name: "umbrella_discovery",
    spec_reference:
        "Round-7 design `docs/superpowers/specs/2026-05-18-phd-b-discovery-design.md` + RFC 9497 + RFC 6962",
    spec_version: "0.0.1",
    block_reference: "round-7",
    tool: ProtocolType::Tamarin,
    model_path: "models/discovery.spthy",
    properties: &[
        "server_never_learns_plaintext_phone",
        "intersection_cardinality_only_disclosed",
        "kt_bind_prevents_silent_swap",
        "anon_id_unlinkable_across_queries",
        "replay_protection_enforced",
        "honest_discovery_executable",
    ],
    status: VerificationStatus::Verified {
        last_run: "2026-05-18",
    },
};

/// Полный список всех моделей в крейте.
///
/// Updated при добавлении каждой новой модели в blocks 9.3 / 9.4 / 9.5.
/// Tests в `tests/model_consistency.rs` итерируют этот список для bulk
/// проверок (file existence + SPEC version match + lemma names match).
///
/// # Constant: ALL_MODELS (English)
///
/// Full list of all models in the crate.
///
/// Updated when each new model is added in blocks 9.3 / 9.4 / 9.5. Tests
/// in `tests/model_consistency.rs` iterate over this list for bulk checks
/// (file existence + SPEC version match + lemma name match).
pub const ALL_MODELS: &[ModelMetadata] = &[
    XWING_COMBINER,
    HYBRID_SIGNATURE_AND_MODE,
    KT_V2_SELF_MONITORING,
    SEALED_SENDER_V2,
    BACKUP_WRAP_V2,
    DOWNGRADE_RESISTANCE,
    KT_V1_SELF_MONITORING,
    SEALED_SENDER_V1,
    MLS_ED25519,
    MULTI_DEVICE_AUTHORIZATION,
    SFRAME_RFC9605,
    TYPE_SAFE_ENFORCEMENT,
    OPRF_RISTRETTO255,
    DISCOVERY,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke: ProtocolType variants distinct.
    /// Smoke: ProtocolType variants are distinct.
    #[test]
    fn protocol_type_variants_distinct() {
        assert_ne!(ProtocolType::Tamarin, ProtocolType::ProVerif);
    }

    /// Smoke: file extensions correct.
    /// Smoke: file extensions are correct.
    #[test]
    fn protocol_type_file_extensions() {
        assert_eq!(ProtocolType::Tamarin.file_extension(), "spthy");
        assert_eq!(ProtocolType::ProVerif.file_extension(), "pv");
    }

    /// Smoke: cli binary names correct.
    /// Smoke: CLI binary names are correct.
    #[test]
    fn protocol_type_cli_binaries() {
        assert_eq!(ProtocolType::Tamarin.cli_binary(), "tamarin-prover");
        assert_eq!(ProtocolType::ProVerif.cli_binary(), "proverif");
    }

    /// Smoke: VerificationStatus variants distinct.
    /// Smoke: VerificationStatus variants are distinct.
    #[test]
    fn verification_status_variants_distinct() {
        let p = VerificationStatus::Pending;
        let v = VerificationStatus::Verified {
            last_run: "2026-04-25",
        };
        let f = VerificationStatus::Failed { reason: "timeout" };
        assert_ne!(p, v);
        assert_ne!(p, f);
        assert_ne!(v, f);
    }

    /// XWING_COMBINER metadata имеет ожидаемую форму.
    /// XWING_COMBINER metadata has the expected shape.
    #[test]
    fn xwing_combiner_metadata_shape() {
        assert_eq!(XWING_COMBINER.name, "umbrella_xwing_combiner");
        assert_eq!(XWING_COMBINER.tool, ProtocolType::Tamarin);
        assert_eq!(XWING_COMBINER.model_path, "models/xwing_combiner.spthy");
        assert_eq!(XWING_COMBINER.spec_version, "1.0.0");
        assert_eq!(XWING_COMBINER.block_reference, "9.2");
        // 2026-05-19: extended с round-3 hedged-encaps lemmas
        // (Bellare-Hoang-Keelveedhi 2015 closure of R5.A/R5.C).
        // 2026-05-19: extended with round-3 hedged-encaps lemmas
        // (Bellare-Hoang-Keelveedhi 2015 closure of R5.A/R5.C).
        assert_eq!(
            XWING_COMBINER.status,
            VerificationStatus::Verified {
                last_run: "2026-05-19"
            }
        );
        // 5 base lemmas (joint_security_classical, joint_security_quantum,
        // domain_separation_label_simultaneity, kdf_transcript_binding,
        // adversarial_encaps_quantum_break_cannot_recover_K) + honest_setup
        // + 5 round-3 hedged lemmas = 11 properties.
        assert_eq!(XWING_COMBINER.properties.len(), 11);
    }

    /// ALL_MODELS содержит XWING_COMBINER.
    /// ALL_MODELS contains XWING_COMBINER.
    #[test]
    fn all_models_contains_xwing_combiner() {
        let names: Vec<&str> = ALL_MODELS.iter().map(|m| m.name).collect();
        assert!(names.contains(&"umbrella_xwing_combiner"));
    }

    /// HYBRID_SIGNATURE_AND_MODE metadata имеет ожидаемую форму.
    /// HYBRID_SIGNATURE_AND_MODE metadata has the expected shape.
    #[test]
    fn hybrid_signature_and_mode_metadata_shape() {
        assert_eq!(
            HYBRID_SIGNATURE_AND_MODE.name,
            "umbrella_hybrid_signature_and_mode"
        );
        assert_eq!(HYBRID_SIGNATURE_AND_MODE.tool, ProtocolType::Tamarin);
        assert_eq!(
            HYBRID_SIGNATURE_AND_MODE.model_path,
            "models/hybrid_signature_and_mode.spthy"
        );
        assert_eq!(HYBRID_SIGNATURE_AND_MODE.spec_version, "1.0.0");
        assert_eq!(HYBRID_SIGNATURE_AND_MODE.block_reference, "9.3");
        assert_eq!(
            HYBRID_SIGNATURE_AND_MODE.status,
            VerificationStatus::Pending
        );
        assert_eq!(HYBRID_SIGNATURE_AND_MODE.properties.len(), 3);
    }

    /// KT_V2_SELF_MONITORING metadata имеет ожидаемую форму. Updated
    /// 2026-05-19 (F-KT-V2-MODEL-1 closure): spec_version 1.0.0 →
    /// 1.0.1; 3 tautological lemmas refactored к 4 substantive
    /// correspondence (bidirectional 'absent'≠'present' split в 2
    /// direction-specific lemmas) + 4 new exists-trace anchors + 1
    /// sanity = 9 properties; status Pending → Verified.
    ///
    /// KT_V2_SELF_MONITORING metadata has the expected shape. Updated
    /// 2026-05-19 (F-KT-V2-MODEL-1 closure): spec_version 1.0.0 →
    /// 1.0.1; 3 tautologies refactored to 4 substantive correspondence
    /// claims (bidirectional `'absent' ≠ 'present'` lemma split into 2
    /// direction-specific lemmas) + 4 new exists-trace anchors + 1
    /// sanity = 9 properties; status Pending → Verified.
    #[test]
    fn kt_v2_self_monitoring_metadata_shape() {
        assert_eq!(KT_V2_SELF_MONITORING.name, "umbrella_kt_v2_self_monitoring");
        assert_eq!(KT_V2_SELF_MONITORING.tool, ProtocolType::Tamarin);
        assert_eq!(
            KT_V2_SELF_MONITORING.model_path,
            "models/kt_v2_self_monitoring.spthy"
        );
        assert_eq!(KT_V2_SELF_MONITORING.spec_version, "1.0.1");
        assert_eq!(KT_V2_SELF_MONITORING.block_reference, "9.3");
        assert!(matches!(
            KT_V2_SELF_MONITORING.status,
            VerificationStatus::Verified { .. }
        ));
        assert_eq!(KT_V2_SELF_MONITORING.properties.len(), 9);
    }

    /// ALL_MODELS содержит обе block-9.3 модели в дополнение к XWing.
    /// ALL_MODELS contains both block-9.3 models in addition to XWing.
    #[test]
    fn all_models_contains_block_9_3_models() {
        let names: Vec<&str> = ALL_MODELS.iter().map(|m| m.name).collect();
        assert!(names.contains(&"umbrella_hybrid_signature_and_mode"));
        assert!(names.contains(&"umbrella_kt_v2_self_monitoring"));
    }

    /// SEALED_SENDER_V2 metadata имеет ожидаемую форму (block 9.4 ProVerif).
    /// SEALED_SENDER_V2 metadata has the expected shape (block 9.4 ProVerif).
    #[test]
    fn sealed_sender_v2_metadata_shape() {
        assert_eq!(SEALED_SENDER_V2.name, "umbrella_sealed_sender_v2");
        assert_eq!(SEALED_SENDER_V2.tool, ProtocolType::ProVerif);
        assert_eq!(SEALED_SENDER_V2.model_path, "models/sealed_sender_v2.pv");
        assert_eq!(SEALED_SENDER_V2.spec_version, "1.0.0");
        assert_eq!(SEALED_SENDER_V2.block_reference, "9.4");
        assert_eq!(SEALED_SENDER_V2.status, VerificationStatus::Pending);
        assert_eq!(SEALED_SENDER_V2.properties.len(), 4);
    }

    /// BACKUP_WRAP_V2 metadata имеет ожидаемую форму (block 9.4 ProVerif).
    /// BACKUP_WRAP_V2 metadata has the expected shape (block 9.4 ProVerif).
    #[test]
    fn backup_wrap_v2_metadata_shape() {
        assert_eq!(BACKUP_WRAP_V2.name, "umbrella_backup_wrap_v2");
        assert_eq!(BACKUP_WRAP_V2.tool, ProtocolType::ProVerif);
        assert_eq!(BACKUP_WRAP_V2.model_path, "models/backup_wrap_v2.pv");
        assert_eq!(BACKUP_WRAP_V2.spec_version, "1.0.0");
        assert_eq!(BACKUP_WRAP_V2.block_reference, "9.4");
        assert_eq!(BACKUP_WRAP_V2.status, VerificationStatus::Pending);
        assert_eq!(BACKUP_WRAP_V2.properties.len(), 4);
    }

    /// DOWNGRADE_RESISTANCE metadata имеет ожидаемую форму (block 9.4 Tamarin).
    /// DOWNGRADE_RESISTANCE metadata has the expected shape (block 9.4 Tamarin).
    #[test]
    fn downgrade_resistance_metadata_shape() {
        assert_eq!(DOWNGRADE_RESISTANCE.name, "umbrella_downgrade_resistance");
        assert_eq!(DOWNGRADE_RESISTANCE.tool, ProtocolType::Tamarin);
        assert_eq!(
            DOWNGRADE_RESISTANCE.model_path,
            "models/downgrade_resistance.spthy"
        );
        assert_eq!(DOWNGRADE_RESISTANCE.spec_version, "1.0.0");
        assert_eq!(DOWNGRADE_RESISTANCE.block_reference, "9.4");
        assert!(matches!(
            DOWNGRADE_RESISTANCE.status,
            VerificationStatus::Failed { .. }
        ));
        assert_eq!(DOWNGRADE_RESISTANCE.properties.len(), 4);
    }

    /// ALL_MODELS содержит все три block-9.4 модели (snapshot — block 9.5 добавит 3 ещё).
    /// ALL_MODELS contains all three block-9.4 models (snapshot — block 9.5 will add 3 more).
    #[test]
    fn all_models_contains_block_9_4_models() {
        let names: Vec<&str> = ALL_MODELS.iter().map(|m| m.name).collect();
        assert!(names.contains(&"umbrella_sealed_sender_v2"));
        assert!(names.contains(&"umbrella_backup_wrap_v2"));
        assert!(names.contains(&"umbrella_downgrade_resistance"));
    }

    /// Tamarin/ProVerif counts в ALL_MODELS после block 10.23 (snapshot).
    /// Tamarin/ProVerif counts in ALL_MODELS after block 10.23 (snapshot).
    /// After round 7 discovery model added: 10 Tamarin + 4 ProVerif.
    #[test]
    fn all_models_tool_counts_after_block_9_4_snapshot() {
        // Snapshot test — after round 7 discovery model added: 10 Tamarin +
        // 4 ProVerif.
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

    /// KT_V1_SELF_MONITORING metadata имеет ожидаемую форму (block 9.5
    /// Tamarin). Updated 2026-05-19 (F-KT-V1-MODEL-1 closure): spec_version
    /// 0.0.1 → 0.0.2; 3 commutativity tautologies refactored to substantive
    /// correspondence + 3 new exists-trace anchors + 1 sanity = 7
    /// properties; status Pending → Verified after local tamarin-prover
    /// 1.12.0 run.
    ///
    /// KT_V1_SELF_MONITORING metadata has the expected shape (block 9.5
    /// Tamarin). Updated 2026-05-19 (F-KT-V1-MODEL-1 closure): spec_version
    /// 0.0.1 → 0.0.2; 3 commutativity tautologies refactored to substantive
    /// correspondence + 3 new exists-trace anchors + 1 sanity = 7
    /// properties; status Pending → Verified after a local
    /// tamarin-prover 1.12.0 run.
    #[test]
    fn kt_v1_self_monitoring_metadata_shape() {
        assert_eq!(KT_V1_SELF_MONITORING.name, "umbrella_kt_v1_self_monitoring");
        assert_eq!(KT_V1_SELF_MONITORING.tool, ProtocolType::Tamarin);
        assert_eq!(
            KT_V1_SELF_MONITORING.model_path,
            "models/kt_v1_self_monitoring.spthy"
        );
        assert_eq!(KT_V1_SELF_MONITORING.spec_version, "0.0.2");
        assert_eq!(KT_V1_SELF_MONITORING.block_reference, "9.5");
        assert!(matches!(
            KT_V1_SELF_MONITORING.status,
            VerificationStatus::Verified { .. }
        ));
        assert_eq!(KT_V1_SELF_MONITORING.properties.len(), 7);
    }

    /// SEALED_SENDER_V1 metadata имеет ожидаемую форму (block 9.5 ProVerif).
    /// SEALED_SENDER_V1 metadata has the expected shape (block 9.5 ProVerif).
    #[test]
    fn sealed_sender_v1_metadata_shape() {
        assert_eq!(SEALED_SENDER_V1.name, "umbrella_sealed_sender_v1");
        assert_eq!(SEALED_SENDER_V1.tool, ProtocolType::ProVerif);
        assert_eq!(SEALED_SENDER_V1.model_path, "models/sealed_sender_v1.pv");
        assert_eq!(SEALED_SENDER_V1.spec_version, "0.0.2");
        assert_eq!(SEALED_SENDER_V1.block_reference, "9.5");
        assert_eq!(SEALED_SENDER_V1.status, VerificationStatus::Pending);
        assert_eq!(SEALED_SENDER_V1.properties.len(), 4);
    }

    /// MLS_ED25519 metadata имеет ожидаемую форму (block 9.5 Tamarin).
    /// Updated 2026-05-19 (F-MLS-MODEL-1 closure): spec_version 0.0.1 →
    /// 0.0.2; 3 tautological lemmas refactored to 6 substantive +
    /// counterexample lemmas; status Pending → Verified after local
    /// tamarin-prover 1.12.0 run.
    ///
    /// MLS_ED25519 metadata has the expected shape (block 9.5 Tamarin).
    /// Updated 2026-05-19 (F-MLS-MODEL-1 closure): spec_version 0.0.1 →
    /// 0.0.2; 3 tautological lemmas refactored to 6 substantive +
    /// counterexample lemmas; status Pending → Verified after a local
    /// tamarin-prover 1.12.0 run.
    #[test]
    fn mls_ed25519_metadata_shape() {
        assert_eq!(MLS_ED25519.name, "umbrella_mls_ed25519");
        assert_eq!(MLS_ED25519.tool, ProtocolType::Tamarin);
        assert_eq!(MLS_ED25519.model_path, "models/mls_ed25519.spthy");
        assert_eq!(MLS_ED25519.spec_version, "0.0.2");
        assert_eq!(MLS_ED25519.block_reference, "9.5");
        assert!(matches!(MLS_ED25519.status, VerificationStatus::Verified { .. }));
        assert_eq!(MLS_ED25519.properties.len(), 6);
    }

    /// ALL_MODELS содержит все три block-9.5 модели и итого имеет 14 элементов
    /// после round 7 discovery model addition.
    /// ALL_MODELS contains all three block-9.5 models and has 14 elements
    /// total after round 7 discovery model addition.
    #[test]
    fn all_models_contains_block_9_5_models() {
        let names: Vec<&str> = ALL_MODELS.iter().map(|m| m.name).collect();
        assert!(names.contains(&"umbrella_kt_v1_self_monitoring"));
        assert!(names.contains(&"umbrella_sealed_sender_v1"));
        assert!(names.contains(&"umbrella_mls_ed25519"));
        assert!(names.contains(&"umbrella_discovery"));
        assert_eq!(ALL_MODELS.len(), 14);
    }

    /// MULTI_DEVICE_AUTHORIZATION metadata имеет ожидаемую форму (block 10.23
    /// Tamarin).
    /// MULTI_DEVICE_AUTHORIZATION metadata has the expected shape (block
    /// 10.23 Tamarin).
    #[test]
    fn multi_device_authorization_metadata_shape() {
        assert_eq!(
            MULTI_DEVICE_AUTHORIZATION.name,
            "umbrella_multi_device_authorization"
        );
        assert_eq!(MULTI_DEVICE_AUTHORIZATION.tool, ProtocolType::Tamarin);
        assert_eq!(
            MULTI_DEVICE_AUTHORIZATION.model_path,
            "models/multi_device_authorization.spthy"
        );
        assert_eq!(MULTI_DEVICE_AUTHORIZATION.spec_version, "0.0.1");
        assert_eq!(MULTI_DEVICE_AUTHORIZATION.block_reference, "10.23");
        assert_eq!(
            MULTI_DEVICE_AUTHORIZATION.status,
            VerificationStatus::Verified {
                last_run: "2026-05-07"
            }
        );
        assert_eq!(MULTI_DEVICE_AUTHORIZATION.properties.len(), 6);
    }

    /// SFRAME_RFC9605 metadata имеет ожидаемую форму (block 10.23 Tamarin).
    /// Updated 2026-05-19 (F-SFRAME-MODEL-1 closure): spec_version 0.0.3 →
    /// 0.0.4; 2 hash-determinism tautologies refactored к substantive
    /// converse (collision resistance + KID injectivity) + 2 exists-trace
    /// anchors; total 4 → 7 properties; last_run 2026-05-07 → 2026-05-19.
    ///
    /// SFRAME_RFC9605 metadata has the expected shape (block 10.23
    /// Tamarin). Updated 2026-05-19 (F-SFRAME-MODEL-1 closure):
    /// spec_version 0.0.3 → 0.0.4; 2 hash-determinism tautologies
    /// refactored to substantive converse (collision resistance + KID
    /// injectivity) + 2 exists-trace anchors; total 4 → 7 properties;
    /// last_run 2026-05-07 → 2026-05-19.
    #[test]
    fn sframe_rfc9605_metadata_shape() {
        assert_eq!(SFRAME_RFC9605.name, "umbrella_sframe_rfc9605");
        assert_eq!(SFRAME_RFC9605.tool, ProtocolType::Tamarin);
        assert_eq!(SFRAME_RFC9605.model_path, "models/sframe_rfc9605.spthy");
        assert_eq!(SFRAME_RFC9605.spec_version, "0.0.4");
        assert_eq!(SFRAME_RFC9605.block_reference, "10.23");
        assert_eq!(
            SFRAME_RFC9605.status,
            VerificationStatus::Verified {
                last_run: "2026-05-19"
            }
        );
        assert_eq!(SFRAME_RFC9605.properties.len(), 7);
    }

    /// TYPE_SAFE_ENFORCEMENT metadata имеет ожидаемую форму (block 10.23
    /// Tamarin).
    /// TYPE_SAFE_ENFORCEMENT metadata has the expected shape (block 10.23
    /// Tamarin).
    #[test]
    fn type_safe_enforcement_metadata_shape() {
        assert_eq!(TYPE_SAFE_ENFORCEMENT.name, "umbrella_type_safe_enforcement");
        assert_eq!(TYPE_SAFE_ENFORCEMENT.tool, ProtocolType::Tamarin);
        assert_eq!(
            TYPE_SAFE_ENFORCEMENT.model_path,
            "models/type_safe_enforcement.spthy"
        );
        assert_eq!(TYPE_SAFE_ENFORCEMENT.spec_version, "1.0.0");
        assert_eq!(TYPE_SAFE_ENFORCEMENT.block_reference, "10.23");
        assert_eq!(
            TYPE_SAFE_ENFORCEMENT.status,
            VerificationStatus::Verified {
                last_run: "2026-05-07"
            }
        );
        assert_eq!(TYPE_SAFE_ENFORCEMENT.properties.len(), 4);
    }

    /// OPRF_RISTRETTO255 metadata имеет ожидаемую форму (block 10.23
    /// ProVerif).
    /// OPRF_RISTRETTO255 metadata has the expected shape (block 10.23
    /// ProVerif).
    #[test]
    fn oprf_ristretto255_metadata_shape() {
        assert_eq!(OPRF_RISTRETTO255.name, "umbrella_oprf_ristretto255");
        assert_eq!(OPRF_RISTRETTO255.tool, ProtocolType::ProVerif);
        assert_eq!(OPRF_RISTRETTO255.model_path, "models/oprf_ristretto255.pv");
        assert_eq!(OPRF_RISTRETTO255.spec_version, "0.0.2");
        assert_eq!(OPRF_RISTRETTO255.block_reference, "10.23");
        // Status: Failed { reason: "..." } — same_input_yields_same_label
        // falsified due to Shamir Lagrange algebra not captured в symbolic
        // combine_3 equation. PRIMARY claims (oprf_blinding_oblivious +
        // device_attestation_required_for_evaluation) verified. Real-protocol
        // determinism guaranteed by RFC 9497 §3.3.1 unblinding correctness.
        assert!(matches!(
            OPRF_RISTRETTO255.status,
            VerificationStatus::Failed { .. }
        ));
        assert_eq!(OPRF_RISTRETTO255.properties.len(), 3);
    }

    /// ALL_MODELS содержит все четыре block-10.23 модели.
    /// ALL_MODELS contains all four block-10.23 models.
    #[test]
    fn all_models_contains_block_10_23_models() {
        let names: Vec<&str> = ALL_MODELS.iter().map(|m| m.name).collect();
        assert!(names.contains(&"umbrella_multi_device_authorization"));
        assert!(names.contains(&"umbrella_sframe_rfc9605"));
        assert!(names.contains(&"umbrella_type_safe_enforcement"));
        assert!(names.contains(&"umbrella_oprf_ristretto255"));
    }
}
