//! # umbrella-formal-verification
//!
//! Метакрейт с Tamarin / ProVerif моделями для UmbrellaX криптографических
//! протоколов и расширений.
//!
//! Модели лежат в директории `models/` как текстовые файлы:
//! - `*.spthy` — Tamarin Prover (<https://tamarin-prover.com/>), symbolic
//!   protocol verifier (Haskell, multiset rewriting). Используется для group
//!   operations / counter-based protocols / authenticated key exchange /
//!   hybrid signatures.
//! - `*.pv` — ProVerif (<https://bblanche.gitlabpages.inria.fr/proverif/>),
//!   cryptographic protocol verifier (OCaml, applied pi calculus).
//!   Используется для confidentiality / authentication queries в protocols
//!   с chaining encryptions / sender privacy.
//!
//! Модели верифицируются external tools weekly через CI job
//! `.github/workflows/formal-verification.yml` (cron Sunday 00:00 UTC +
//! workflow_dispatch). Pattern K «Formal verification как separate cargo
//! target» из WORKING_RULES.md применён — verification
//! не привязана к каждому push, потому что full proof для одной модели
//! может занимать ~30 минут CPU time.
//!
//! Постулат 5 «только Rust для нашего кода» соблюдён: model files —
//! текстовые спецификации в нашем репо, верификаторы (Tamarin Prover binary,
//! ProVerif binary) — допустимое external tooling per ADR-012 Решение 3
//! (in-house авторинг моделей + INRIA Cryspen / CISPA академический peer
//! review первых моделей).
//!
//! Pattern H «Tamarin model = SPEC-13 §X цитата + property + axioms»
//! формализован: каждая модель имеет header с явной ссылкой на SPEC,
//! ADR, block reference, list properties и axioms; consistency tests в
//! `tests/model_consistency.rs` верифицируют что эти ссылки актуальны.
//!
//! # umbrella-formal-verification (English)
//!
//! Meta-crate with Tamarin / ProVerif models for UmbrellaX cryptographic
//! protocols and extensions.
//!
//! Models live in the `models/` directory as text files:
//! - `*.spthy` — Tamarin Prover (<https://tamarin-prover.com/>), a symbolic
//!   protocol verifier (Haskell, multiset rewriting). Used for group
//!   operations / counter-based protocols / authenticated key exchange /
//!   hybrid signatures.
//! - `*.pv` — ProVerif (<https://bblanche.gitlabpages.inria.fr/proverif/>), a
//!   cryptographic protocol verifier (OCaml, applied pi calculus). Used for
//!   confidentiality / authentication queries in protocols with chaining
//!   encryptions / sender privacy.
//!
//! Models are verified by external tools weekly via the CI job
//! `.github/workflows/formal-verification.yml` (cron Sunday 00:00 UTC +
//! workflow_dispatch). Pattern K "Formal verification as a separate cargo
//! target" from WORKING_RULES.md applies — verification is
//! not tied to every push because a full proof for a single model may take
//! ~30 minutes of CPU time.
//!
//! Postulate 5 ("only Rust for our code") is preserved: model files are text
//! specifications in our repo; the verifiers (Tamarin Prover binary,
//! ProVerif binary) are permitted external tooling per ADR-012 Decision 3
//! (in-house authoring of models + INRIA Cryspen / CISPA academic peer
//! review of the first models).
//!
//! Pattern H "Tamarin model = SPEC-13 §X citation + property + axioms" is
//! formalised: each model has a header with explicit references to SPEC,
//! ADR, block, list of properties and axioms; consistency tests in
//! `tests/model_consistency.rs` verify those references stay current.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod model_metadata;

pub use model_metadata::{
    ModelMetadata, ProtocolType, VerificationStatus, ALL_MODELS, BACKUP_WRAP_V2,
    DOWNGRADE_RESISTANCE, HYBRID_SIGNATURE_AND_MODE, KT_V1_SELF_MONITORING, KT_V2_SELF_MONITORING,
    MLS_ED25519, MULTI_DEVICE_AUTHORIZATION, OPRF_RISTRETTO255, SEALED_SENDER_V1, SEALED_SENDER_V2,
    SFRAME_RFC9605, TYPE_SAFE_ENFORCEMENT, XWING_COMBINER,
};
