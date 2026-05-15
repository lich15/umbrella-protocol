# KT Split View Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a production `umbrella-kt` layer that turns same-epoch split-view roots into verifiable evidence, rejects broken epoch chains, and keeps public observations free of private user data.

**Architecture:** Add two focused modules: `observation.rs` for public epoch observations, evidence, history decisions, and safe wire encoding; `witness_state.rs` for the per-witness memory model that refuses a second different root for the same log epoch. Existing witness signature verification remains the cryptographic primitive, while the new modules compose it into a fail-closed trust decision.

**Tech Stack:** Rust, existing `umbrella-kt`, Ed25519 witness signatures, SHA-256 Merkle roots, manual fixed-width public encoding, existing shell audit gates.

---

## File Map

- Create: `crates/umbrella-kt/src/observation.rs`
  - Owns public KT observations, split-view evidence, trust decisions, local observation history, and public encode/decode.
- Create: `crates/umbrella-kt/src/witness_state.rs`
  - Owns the local witness signing ledger that refuses equivocation for `log_id + epoch`.
- Modify: `crates/umbrella-kt/src/error.rs`
  - Adds a stable observation-level error variant.
- Modify: `crates/umbrella-kt/src/lib.rs`
  - Exports new modules and corrects over-strong documentation.
- Modify: `crates/umbrella-kt/tests/split_view_exchange.rs`
  - Replaces the private helper with production API tests.
- Modify: `scripts/audit-protocol-core-attack-gates.sh`
  - Requires the new production API tests and docs.
- Modify: `scripts/audit-local-release-hardening.sh`
  - Requires the new production API tests.
- Modify: `docs/security/protocol-core-attack-gates.md`
  - Records the new evidence API and strict chain checks.
- Modify: `docs/security/kt-witness-operator-policy.md`
  - Explains witness memory and the remaining live deployment boundary.
- Modify: `docs/security/production-readiness-boundaries.md`
  - Clarifies what is local and what still needs live services.
- Modify: `docs/security/current-status.md`
  - Updates current KT status.
- Create: `docs/security/external-crypto-attack-ledger-2026-05-15.md`
  - Records the external split-view research used for this hardening.

## Task 1: Add Production Observation And Evidence API

**Files:**
- Create: `crates/umbrella-kt/src/observation.rs`
- Modify: `crates/umbrella-kt/src/error.rs`
- Modify: `crates/umbrella-kt/src/lib.rs`
- Modify: `crates/umbrella-kt/tests/split_view_exchange.rs`

- [ ] **Step 1: Replace the test helper with failing production API tests**

Replace `crates/umbrella-kt/tests/split_view_exchange.rs` with:

```rust
use rand_core::{OsRng, RngCore};
use umbrella_crypto_primitives::sig::PrivateSigningKey;
use umbrella_kt::{
    canonical_sign_payload, compare_observations, verify_signed_epoch, EquivocationEvidence,
    KtLogId, KtObservation, KtTrustDecision, SignedEpochRoot, WitnessPublic, WitnessSet,
    WitnessSignature, NODE_HASH_LEN,
};

fn make_witnesses() -> Vec<(PrivateSigningKey, WitnessPublic)> {
    (0..5)
        .map(|_| {
            let mut rng = OsRng;
            let sk = PrivateSigningKey::generate(&mut rng);
            let pk = WitnessPublic::from_bytes(sk.verifying_key().to_bytes());
            (sk, pk)
        })
        .collect()
}

fn witness_set(witnesses: &[(PrivateSigningKey, WitnessPublic)]) -> WitnessSet {
    let mut set = WitnessSet::new();
    for (_, public) in witnesses {
        set.add(*public);
    }
    set
}

fn signed_view(
    witnesses: &[(PrivateSigningKey, WitnessPublic)],
    signer_indices: &[usize],
    epoch: u64,
    root: [u8; NODE_HASH_LEN],
    log_size: u64,
    timestamp_unix_millis: u64,
) -> SignedEpochRoot {
    let payload = canonical_sign_payload(epoch, &root, log_size, timestamp_unix_millis);
    let signatures = signer_indices
        .iter()
        .map(|idx| {
            let (sk, public) = &witnesses[*idx];
            WitnessSignature {
                witness: *public,
                signature: sk.sign(&payload).to_bytes(),
            }
        })
        .collect();
    SignedEpochRoot {
        epoch,
        root,
        log_size,
        timestamp_unix_millis,
        signatures,
    }
}

fn random_root() -> [u8; NODE_HASH_LEN] {
    let mut root = [0u8; NODE_HASH_LEN];
    OsRng.fill_bytes(&mut root);
    root
}

#[test]
fn threshold_signed_split_views_verify_locally_but_production_api_detects_divergence() {
    let witnesses = make_witnesses();
    let set = witness_set(&witnesses);
    let log_id = KtLogId::from_bytes([7u8; 32]);
    let previous_root = random_root();
    let honest_root = random_root();
    let evil_root = random_root();
    assert_ne!(honest_root, evil_root);

    let alice_view = signed_view(
        &witnesses,
        &[0, 1, 2],
        42,
        honest_root,
        50_000,
        1_700_000_100,
    );
    let bob_view = signed_view(&witnesses, &[0, 1, 2], 42, evil_root, 50_001, 1_700_000_101);

    verify_signed_epoch(&alice_view, &set, 3).expect("alice sees a locally valid 3-of-5 epoch");
    verify_signed_epoch(&bob_view, &set, 3).expect("bob sees a locally valid 3-of-5 epoch");

    let alice = KtObservation::new(log_id, previous_root, alice_view);
    let bob = KtObservation::new(log_id, previous_root, bob_view);

    let decision = compare_observations(&alice, &bob, &set, 3).expect("comparison must run");
    let evidence = match decision {
        KtTrustDecision::EquivocationDetected(evidence) => evidence,
        other => panic!("expected equivocation evidence, got {other:?}"),
    };

    evidence
        .verify(&set, 3)
        .expect("evidence must be independently verifiable");
    assert_eq!(evidence.first().signed.epoch, 42);
    assert_eq!(evidence.second().signed.epoch, 42);
    assert_ne!(evidence.first().signed.root, evidence.second().signed.root);
}

#[test]
fn invalid_second_view_does_not_become_equivocation_evidence() {
    let witnesses = make_witnesses();
    let set = witness_set(&witnesses);
    let log_id = KtLogId::from_bytes([9u8; 32]);
    let previous_root = random_root();
    let root_a = random_root();
    let root_b = random_root();

    let valid = signed_view(&witnesses, &[0, 1, 2], 7, root_a, 99, 1_700_000_200);
    let invalid = signed_view(&witnesses, &[0, 1], 7, root_b, 100, 1_700_000_201);

    let a = KtObservation::new(log_id, previous_root, valid);
    let b = KtObservation::new(log_id, previous_root, invalid);

    let err = EquivocationEvidence::try_new(a, b, &set, 3).unwrap_err();
    assert!(
        format!("{err}").contains("insufficient valid witness signatures"),
        "bad second view must reject as invalid proof, got {err}"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbrella-kt --test split_view_exchange --all-features --locked
```

Expected: FAIL with unresolved imports for `KtLogId`, `KtObservation`, `KtTrustDecision`, `EquivocationEvidence`, and `compare_observations`.

- [ ] **Step 3: Add the observation error variant**

In `crates/umbrella-kt/src/error.rs`, add this variant inside `KtError` after `InsufficientValidSignatures`:

```rust
    /// Public KT observation is malformed or cannot represent a valid trust decision.
    /// Публичное KT-наблюдение испорчено или не может дать валидное решение доверия.
    #[error("invalid KT observation: {0}")]
    InvalidObservation(&'static str),
```

- [ ] **Step 4: Create the production observation module**

Create `crates/umbrella-kt/src/observation.rs` with:

```rust
//! Public KT epoch observations and split-view evidence.
//! Публичные наблюдения эпох KT и доказательства раздвоения журнала.
//!
//! This module intentionally stores only public epoch-head data: log id,
//! previous root, current signed root, log size, timestamp, and witness
//! signatures. It does not store account id, phone number, contact graph,
//! chat id, or a raw device list.
//! Модуль намеренно хранит только публичные данные головы эпохи: id журнала,
//! предыдущий корень, текущий подписанный корень, размер журнала, время и
//! подписи свидетелей. Здесь нет account_id, телефона, графа контактов,
//! chat_id или сырого списка устройств.

use umbrella_crypto_primitives::sig::{PUBLIC_KEY_LEN, SIGNATURE_LEN};

use crate::error::{KtError, Result};
use crate::merkle::NODE_HASH_LEN;
use crate::witness::{verify_signed_epoch, SignedEpochRoot, WitnessSet, WitnessSignature};

/// Current public observation wire-format version.
/// Текущая версия публичного формата наблюдения.
pub const KT_OBSERVATION_VERSION: u8 = 0x01;

/// Maximum witness signatures accepted in one public observation.
/// Максимум подписей свидетелей в одном публичном наблюдении.
pub const MAX_OBSERVATION_SIGNATURES: usize = 64;

/// Public id of a KT log. It must not encode a user identifier.
/// Публичный id KT-журнала. Он не должен кодировать пользователя.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KtLogId([u8; 32]);

impl KtLogId {
    /// Builds a log id from public bytes.
    /// Создаёт id журнала из публичных байтов.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the public bytes.
    /// Возвращает публичные байты.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Public observation of one signed KT epoch head.
/// Публичное наблюдение одной подписанной головы эпохи KT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KtObservation {
    /// Wire-format version. Версия формата.
    pub version: u8,
    /// Public log id. Публичный id журнала.
    pub log_id: KtLogId,
    /// Previous epoch root claimed by this observation.
    /// Предыдущий корень эпохи, заявленный этим наблюдением.
    pub previous_root: [u8; NODE_HASH_LEN],
    /// Signed current epoch root.
    /// Подписанный текущий корень эпохи.
    pub signed: SignedEpochRoot,
}

impl KtObservation {
    /// Creates a current-version public observation.
    /// Создаёт публичное наблюдение текущей версии.
    #[must_use]
    pub fn new(
        log_id: KtLogId,
        previous_root: [u8; NODE_HASH_LEN],
        signed: SignedEpochRoot,
    ) -> Self {
        Self {
            version: KT_OBSERVATION_VERSION,
            log_id,
            previous_root,
            signed,
        }
    }

    /// Verifies version and witness threshold.
    /// Проверяет версию и порог подписей свидетелей.
    pub fn validate(&self, witness_set: &WitnessSet, threshold: usize) -> Result<()> {
        if self.version != KT_OBSERVATION_VERSION {
            return Err(KtError::InvalidObservation("unsupported observation version"));
        }
        verify_signed_epoch(&self.signed, witness_set, threshold)
    }

    /// True when two observations describe the same log epoch.
    /// True, если два наблюдения описывают одну эпоху одного журнала.
    #[must_use]
    pub fn same_log_epoch(&self, other: &Self) -> bool {
        self.log_id == other.log_id && self.signed.epoch == other.signed.epoch
    }

    /// True when two same-epoch observations cannot both be the same view.
    /// True, если два наблюдения одной эпохи не могут быть одной и той же версией.
    #[must_use]
    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.same_log_epoch(other)
            && (self.previous_root != other.previous_root
                || self.signed.root != other.signed.root
                || self.signed.log_size != other.signed.log_size)
    }

    /// Encodes only public observation data.
    /// Кодирует только публичные данные наблюдения.
    #[must_use]
    pub fn encode_public(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            1 + 32 + NODE_HASH_LEN + 8 + NODE_HASH_LEN + 8 + 8 + 2
                + self.signed.signatures.len() * (PUBLIC_KEY_LEN + SIGNATURE_LEN),
        );
        out.push(self.version);
        out.extend_from_slice(&self.log_id.to_bytes());
        out.extend_from_slice(&self.previous_root);
        out.extend_from_slice(&self.signed.epoch.to_be_bytes());
        out.extend_from_slice(&self.signed.root);
        out.extend_from_slice(&self.signed.log_size.to_be_bytes());
        out.extend_from_slice(&self.signed.timestamp_unix_millis.to_be_bytes());
        let count = u16::try_from(self.signed.signatures.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&count.to_be_bytes());
        for sig in &self.signed.signatures {
            out.extend_from_slice(&sig.witness.to_bytes());
            out.extend_from_slice(&sig.signature);
        }
        out
    }

    /// Decodes public observation data.
    /// Декодирует публичные данные наблюдения.
    pub fn decode_public(bytes: &[u8]) -> Result<Self> {
        let mut offset = 0usize;
        let version = take::<1>(bytes, &mut offset)?[0];
        if version != KT_OBSERVATION_VERSION {
            return Err(KtError::InvalidObservation("unsupported observation version"));
        }
        let log_id = KtLogId::from_bytes(take::<32>(bytes, &mut offset)?);
        let previous_root = take::<NODE_HASH_LEN>(bytes, &mut offset)?;
        let epoch = u64::from_be_bytes(take::<8>(bytes, &mut offset)?);
        let root = take::<NODE_HASH_LEN>(bytes, &mut offset)?;
        let log_size = u64::from_be_bytes(take::<8>(bytes, &mut offset)?);
        let timestamp_unix_millis = u64::from_be_bytes(take::<8>(bytes, &mut offset)?);
        let signature_count = u16::from_be_bytes(take::<2>(bytes, &mut offset)?) as usize;
        if signature_count > MAX_OBSERVATION_SIGNATURES {
            return Err(KtError::InvalidObservation("too many observation signatures"));
        }
        let mut signatures = Vec::with_capacity(signature_count);
        for _ in 0..signature_count {
            let witness = crate::witness::WitnessPublic::from_bytes(take::<PUBLIC_KEY_LEN>(
                bytes,
                &mut offset,
            )?);
            let signature = take::<SIGNATURE_LEN>(bytes, &mut offset)?;
            signatures.push(WitnessSignature { witness, signature });
        }
        if offset != bytes.len() {
            return Err(KtError::InvalidObservation("trailing observation bytes"));
        }
        Ok(Self {
            version,
            log_id,
            previous_root,
            signed: SignedEpochRoot {
                epoch,
                root,
                log_size,
                timestamp_unix_millis,
                signatures,
            },
        })
    }
}

/// Verifiable proof that a KT log showed two signed views for one epoch.
/// Проверяемое доказательство, что KT-журнал показал две подписанные версии одной эпохи.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquivocationEvidence {
    first: KtObservation,
    second: KtObservation,
}

impl EquivocationEvidence {
    /// Builds evidence only when both observations are valid and conflicting.
    /// Создаёт доказательство только когда оба наблюдения валидны и конфликтуют.
    pub fn try_new(
        first: KtObservation,
        second: KtObservation,
        witness_set: &WitnessSet,
        threshold: usize,
    ) -> Result<Self> {
        first.validate(witness_set, threshold)?;
        second.validate(witness_set, threshold)?;
        if first.log_id != second.log_id {
            return Err(KtError::InvalidObservation("different log id"));
        }
        if first.signed.epoch != second.signed.epoch {
            return Err(KtError::InvalidObservation("different epoch"));
        }
        if !first.conflicts_with(&second) {
            return Err(KtError::InvalidObservation("observations do not conflict"));
        }
        Ok(Self { first, second })
    }

    /// Re-verifies the evidence.
    /// Повторно проверяет доказательство.
    pub fn verify(&self, witness_set: &WitnessSet, threshold: usize) -> Result<()> {
        Self::try_new(
            self.first.clone(),
            self.second.clone(),
            witness_set,
            threshold,
        )
        .map(|_| ())
    }

    /// First conflicting observation.
    /// Первое конфликтующее наблюдение.
    #[must_use]
    pub const fn first(&self) -> &KtObservation {
        &self.first
    }

    /// Second conflicting observation.
    /// Второе конфликтующее наблюдение.
    #[must_use]
    pub const fn second(&self) -> &KtObservation {
        &self.second
    }
}

/// Trust decision after comparing KT observations.
/// Решение доверия после сравнения KT-наблюдений.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KtTrustDecision {
    /// The observations are valid and consistent.
    /// Наблюдения валидны и согласованы.
    Accepted,
    /// One valid observation is not enough to prove global consistency.
    /// Одного валидного наблюдения мало для доказательства общей согласованности.
    NeedsObservation,
    /// Same log epoch has two valid conflicting views.
    /// У одной эпохи журнала есть две валидные конфликтующие версии.
    EquivocationDetected(EquivocationEvidence),
}

/// Compares two public observations.
/// Сравнивает два публичных наблюдения.
pub fn compare_observations(
    first: &KtObservation,
    second: &KtObservation,
    witness_set: &WitnessSet,
    threshold: usize,
) -> Result<KtTrustDecision> {
    first.validate(witness_set, threshold)?;
    second.validate(witness_set, threshold)?;
    if first.log_id != second.log_id {
        return Err(KtError::InvalidObservation("different log id"));
    }
    if first.conflicts_with(second) {
        return Ok(KtTrustDecision::EquivocationDetected(
            EquivocationEvidence::try_new(first.clone(), second.clone(), witness_set, threshold)?,
        ));
    }
    if first.same_log_epoch(second) {
        return Ok(KtTrustDecision::Accepted);
    }
    Ok(KtTrustDecision::NeedsObservation)
}

fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or(KtError::InvalidObservation("observation offset overflow"))?;
    if end > bytes.len() {
        return Err(KtError::InvalidObservation("truncated observation"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*offset..end]);
    *offset = end;
    Ok(out)
}
```

- [ ] **Step 5: Export the new API and correct the strong doc claim**

In `crates/umbrella-kt/src/lib.rs`, add the module and exports:

```rust
pub mod observation;
```

```rust
pub use observation::{
    compare_observations, EquivocationEvidence, KtLogId, KtObservation, KtTrustDecision,
    KT_OBSERVATION_VERSION, MAX_OBSERVATION_SIGNATURES,
};
```

Change the sentence that currently says witness signatures “guarantee the log is not forked” to this exact wording:

```rust
//! log, clients **self-monitor** that their own record is unchanged, and independent witness
//! signatures on the log root (block 3.4) raise the cost of split-view attacks. Same-epoch
//! fork detection requires comparing public observations or safety numbers; see
//! `observation` for verifiable split-view evidence.
```

- [ ] **Step 6: Run test to verify it passes**

Run:

```bash
cargo test -p umbrella-kt --test split_view_exchange --all-features --locked
```

Expected: PASS for both split-view tests.

- [ ] **Step 7: Commit**

```bash
git add crates/umbrella-kt/src/observation.rs crates/umbrella-kt/src/error.rs crates/umbrella-kt/src/lib.rs crates/umbrella-kt/tests/split_view_exchange.rs
git commit -m "kt: add split view observation evidence"
```

## Task 2: Add Public Encoding Privacy Guard

**Files:**
- Modify: `crates/umbrella-kt/tests/split_view_exchange.rs`
- Modify: `crates/umbrella-kt/src/observation.rs`

- [ ] **Step 1: Add redaction and round-trip tests**

Append to `crates/umbrella-kt/tests/split_view_exchange.rs`:

```rust
#[test]
fn public_observation_encoding_round_trips_without_private_account_data() {
    let witnesses = make_witnesses();
    let set = witness_set(&witnesses);
    let log_id = KtLogId::from_bytes([0xA5; 32]);
    let previous_root = [0x11; NODE_HASH_LEN];
    let private_account_marker = [0x44; 32];
    let signed = signed_view(
        &witnesses,
        &[0, 1, 2],
        77,
        [0x22; NODE_HASH_LEN],
        1234,
        1_700_000_300,
    );
    let observation = KtObservation::new(log_id, previous_root, signed);

    let encoded = observation.encode_public();
    assert!(
        !encoded.windows(private_account_marker.len()).any(|w| w == private_account_marker),
        "public KT observation must not contain account_id or private account marker"
    );

    let decoded = KtObservation::decode_public(&encoded).expect("public observation decodes");
    assert_eq!(decoded, observation);
    decoded.validate(&set, 3).expect("decoded observation remains valid");
}

#[test]
fn public_observation_decoder_rejects_truncated_and_trailing_bytes() {
    let witnesses = make_witnesses();
    let signed = signed_view(
        &witnesses,
        &[0, 1, 2],
        78,
        [0x33; NODE_HASH_LEN],
        99,
        1_700_000_301,
    );
    let observation = KtObservation::new(KtLogId::from_bytes([0xB6; 32]), [0x10; 32], signed);
    let encoded = observation.encode_public();

    let truncated = &encoded[..encoded.len() - 1];
    assert!(KtObservation::decode_public(truncated).is_err());

    let mut trailing = encoded;
    trailing.push(0x99);
    assert!(KtObservation::decode_public(&trailing).is_err());
}
```

- [ ] **Step 2: Run tests**

Run:

```bash
cargo test -p umbrella-kt --test split_view_exchange --all-features --locked
```

Expected: PASS if Task 1 included encode/decode exactly. If it fails, the error identifies the encoding bug to fix in `observation.rs`.

- [ ] **Step 3: Commit**

```bash
git add crates/umbrella-kt/src/observation.rs crates/umbrella-kt/tests/split_view_exchange.rs
git commit -m "kt: encode public observations without private data"
```

## Task 3: Add Witness Non-Equivocation Ledger

**Files:**
- Create: `crates/umbrella-kt/src/witness_state.rs`
- Modify: `crates/umbrella-kt/src/lib.rs`
- Modify: `crates/umbrella-kt/tests/split_view_exchange.rs`

- [ ] **Step 1: Add failing witness memory test**

Append to `crates/umbrella-kt/tests/split_view_exchange.rs`:

```rust
#[test]
fn witness_signing_ledger_rejects_second_different_root_for_same_epoch() {
    let witnesses = make_witnesses();
    let log_id = KtLogId::from_bytes([0xC7; 32]);
    let first = signed_view(
        &witnesses,
        &[0],
        88,
        [0x41; NODE_HASH_LEN],
        500,
        1_700_000_400,
    );
    let same = signed_view(
        &witnesses,
        &[0],
        88,
        [0x41; NODE_HASH_LEN],
        500,
        1_700_000_401,
    );
    let fork = signed_view(
        &witnesses,
        &[0],
        88,
        [0x42; NODE_HASH_LEN],
        501,
        1_700_000_402,
    );

    let mut ledger = umbrella_kt::WitnessSigningLedger::new();
    assert_eq!(
        ledger.record_or_reject(log_id, &first).unwrap(),
        umbrella_kt::WitnessSigningDecision::FirstSignature
    );
    assert_eq!(
        ledger.record_or_reject(log_id, &same).unwrap(),
        umbrella_kt::WitnessSigningDecision::RepeatedSameHead
    );

    let err = ledger.record_or_reject(log_id, &fork).unwrap_err();
    assert!(
        format!("{err}").contains("witness equivocation attempt"),
        "same witness must refuse second different root for same log epoch, got {err}"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cargo test -p umbrella-kt --test split_view_exchange witness_signing_ledger --all-features --locked
```

Expected: FAIL with unresolved `WitnessSigningLedger` and `WitnessSigningDecision`.

- [ ] **Step 3: Create witness state module**

Create `crates/umbrella-kt/src/witness_state.rs` with:

```rust
//! Local witness non-equivocation state.
//! Локальное состояние свидетеля против двойной подписи.

use crate::error::{KtError, Result};
use crate::merkle::NODE_HASH_LEN;
use crate::observation::KtLogId;
use crate::witness::SignedEpochRoot;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WitnessLedgerEntry {
    log_id: KtLogId,
    epoch: u64,
    root: [u8; NODE_HASH_LEN],
    log_size: u64,
}

/// Decision returned by witness signing memory.
/// Решение памяти свидетеля перед подписью.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessSigningDecision {
    /// First head recorded for this log epoch.
    /// Первая голова для этой эпохи журнала.
    FirstSignature,
    /// Same root and size were already recorded.
    /// Такой же корень и размер уже были записаны.
    RepeatedSameHead,
}

/// Small local ledger preventing a witness from signing two heads for one epoch.
/// Малый локальный журнал, который не даёт свидетелю подписать две головы одной эпохи.
#[derive(Clone, Debug, Default)]
pub struct WitnessSigningLedger {
    entries: Vec<WitnessLedgerEntry>,
}

impl WitnessSigningLedger {
    /// Creates an empty ledger.
    /// Создаёт пустой журнал.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a head or rejects a same-epoch fork.
    /// Записывает голову или отвергает раздвоение той же эпохи.
    pub fn record_or_reject(
        &mut self,
        log_id: KtLogId,
        signed: &SignedEpochRoot,
    ) -> Result<WitnessSigningDecision> {
        for entry in &self.entries {
            if entry.log_id == log_id && entry.epoch == signed.epoch {
                if entry.root == signed.root && entry.log_size == signed.log_size {
                    return Ok(WitnessSigningDecision::RepeatedSameHead);
                }
                return Err(KtError::InvalidEntry("witness equivocation attempt"));
            }
        }
        self.entries.push(WitnessLedgerEntry {
            log_id,
            epoch: signed.epoch,
            root: signed.root,
            log_size: signed.log_size,
        });
        Ok(WitnessSigningDecision::FirstSignature)
    }

    /// Number of recorded log epochs.
    /// Количество записанных эпох журнала.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no head was recorded.
    /// True, если ещё нет записей.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
```

- [ ] **Step 4: Export witness state**

In `crates/umbrella-kt/src/lib.rs` add:

```rust
pub mod witness_state;
```

```rust
pub use witness_state::{WitnessSigningDecision, WitnessSigningLedger};
```

- [ ] **Step 5: Run test to verify it passes**

Run:

```bash
cargo test -p umbrella-kt --test split_view_exchange witness_signing_ledger --all-features --locked
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbrella-kt/src/witness_state.rs crates/umbrella-kt/src/lib.rs crates/umbrella-kt/tests/split_view_exchange.rs
git commit -m "kt: add witness non-equivocation memory"
```

## Task 4: Add Strict Observation History

**Files:**
- Modify: `crates/umbrella-kt/src/observation.rs`
- Modify: `crates/umbrella-kt/tests/split_view_exchange.rs`

- [ ] **Step 1: Add failing history tests**

Append to `crates/umbrella-kt/tests/split_view_exchange.rs`:

```rust
#[test]
fn observation_history_rejects_epoch_regression_and_broken_chain() {
    let witnesses = make_witnesses();
    let set = witness_set(&witnesses);
    let log_id = KtLogId::from_bytes([0xD8; 32]);
    let genesis = [0x00; NODE_HASH_LEN];
    let root_10 = [0x10; NODE_HASH_LEN];
    let root_11 = [0x11; NODE_HASH_LEN];
    let wrong_previous = [0x99; NODE_HASH_LEN];

    let epoch_10 = KtObservation::new(
        log_id,
        genesis,
        signed_view(&witnesses, &[0, 1, 2], 10, root_10, 10_000, 1_700_000_500),
    );
    let epoch_9 = KtObservation::new(
        log_id,
        genesis,
        signed_view(&witnesses, &[0, 1, 2], 9, [0x09; NODE_HASH_LEN], 9_000, 1_700_000_501),
    );
    let broken_11 = KtObservation::new(
        log_id,
        wrong_previous,
        signed_view(&witnesses, &[0, 1, 2], 11, root_11, 11_000, 1_700_000_502),
    );

    let mut history = umbrella_kt::KtObservationHistory::new();
    assert_eq!(
        history.observe(epoch_10, &set, 3).unwrap(),
        KtTrustDecision::NeedsObservation
    );

    let regression = history.observe(epoch_9, &set, 3).unwrap_err();
    assert!(format!("{regression}").contains("epoch regression"));

    let broken = history.observe(broken_11, &set, 3).unwrap_err();
    assert!(format!("{broken}").contains("epoch chain broken"));
}

#[test]
fn observation_history_returns_evidence_for_same_epoch_conflict() {
    let witnesses = make_witnesses();
    let set = witness_set(&witnesses);
    let log_id = KtLogId::from_bytes([0xE9; 32]);
    let previous = [0x33; NODE_HASH_LEN];

    let first = KtObservation::new(
        log_id,
        previous,
        signed_view(&witnesses, &[0, 1, 2], 50, [0x50; NODE_HASH_LEN], 50, 1_700_000_600),
    );
    let second = KtObservation::new(
        log_id,
        previous,
        signed_view(&witnesses, &[0, 1, 2], 50, [0x51; NODE_HASH_LEN], 51, 1_700_000_601),
    );

    let mut history = umbrella_kt::KtObservationHistory::new();
    history.observe(first, &set, 3).unwrap();
    let decision = history.observe(second, &set, 3).unwrap();
    assert!(matches!(decision, KtTrustDecision::EquivocationDetected(_)));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
cargo test -p umbrella-kt --test split_view_exchange observation_history --all-features --locked
```

Expected: FAIL with unresolved `KtObservationHistory`.

- [ ] **Step 3: Add history type to `observation.rs`**

Append this code before `fn take` in `crates/umbrella-kt/src/observation.rs`:

```rust
/// Local history of public KT observations for one log.
/// Локальная история публичных KT-наблюдений одного журнала.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KtObservationHistory {
    log_id: Option<KtLogId>,
    last: Option<KtObservation>,
}

impl KtObservationHistory {
    /// Creates an empty observation history.
    /// Создаёт пустую историю наблюдений.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Observes a signed epoch head and returns a trust decision.
    /// Запоминает подписанную голову эпохи и возвращает решение доверия.
    pub fn observe(
        &mut self,
        observation: KtObservation,
        witness_set: &WitnessSet,
        threshold: usize,
    ) -> Result<KtTrustDecision> {
        observation.validate(witness_set, threshold)?;
        match self.log_id {
            Some(existing) if existing != observation.log_id => {
                return Err(KtError::InvalidObservation("different log id"));
            }
            None => self.log_id = Some(observation.log_id),
            Some(_) => {}
        }

        let Some(last) = self.last.clone() else {
            self.last = Some(observation);
            return Ok(KtTrustDecision::NeedsObservation);
        };

        if observation.signed.epoch < last.signed.epoch {
            return Err(KtError::InvalidEntry("epoch regression"));
        }

        if observation.signed.epoch == last.signed.epoch {
            if observation.conflicts_with(&last) {
                return Ok(KtTrustDecision::EquivocationDetected(
                    EquivocationEvidence::try_new(last, observation, witness_set, threshold)?,
                ));
            }
            self.last = Some(observation);
            return Ok(KtTrustDecision::Accepted);
        }

        if observation.previous_root != last.signed.root {
            return Err(KtError::InvalidEntry("epoch chain broken"));
        }

        self.last = Some(observation);
        Ok(KtTrustDecision::Accepted)
    }

    /// Returns the last accepted observation.
    /// Возвращает последнее принятое наблюдение.
    #[must_use]
    pub const fn last(&self) -> Option<&KtObservation> {
        self.last.as_ref()
    }
}
```

- [ ] **Step 4: Export history**

In `crates/umbrella-kt/src/lib.rs`, extend the observation export block:

```rust
pub use observation::{
    compare_observations, EquivocationEvidence, KtLogId, KtObservation, KtObservationHistory,
    KtTrustDecision, KT_OBSERVATION_VERSION, MAX_OBSERVATION_SIGNATURES,
};
```

- [ ] **Step 5: Run tests**

Run:

```bash
cargo test -p umbrella-kt --test split_view_exchange --all-features --locked
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/umbrella-kt/src/observation.rs crates/umbrella-kt/src/lib.rs crates/umbrella-kt/tests/split_view_exchange.rs
git commit -m "kt: enforce public observation history"
```

## Task 5: Update Existing KT Claims And Audit Gates

**Files:**
- Modify: `scripts/audit-protocol-core-attack-gates.sh`
- Modify: `scripts/audit-local-release-hardening.sh`
- Modify: `docs/security/protocol-core-attack-gates.md`
- Modify: `docs/security/kt-witness-operator-policy.md`
- Modify: `docs/security/production-readiness-boundaries.md`
- Modify: `docs/security/current-status.md`
- Create: `docs/security/external-crypto-attack-ledger-2026-05-15.md`

- [ ] **Step 1: Update audit scripts**

In `scripts/audit-protocol-core-attack-gates.sh`, add these required patterns after the existing split-view requirements:

```bash
require_pattern "crates/umbrella-kt/src/observation.rs" "EquivocationEvidence"
require_pattern "crates/umbrella-kt/src/observation.rs" "KtObservationHistory"
require_pattern "crates/umbrella-kt/src/witness_state.rs" "witness equivocation attempt"
require_pattern "crates/umbrella-kt/tests/split_view_exchange.rs" "production_api_detects_divergence"
require_pattern "crates/umbrella-kt/tests/split_view_exchange.rs" "public_observation_encoding_round_trips_without_private_account_data"
require_pattern "crates/umbrella-kt/tests/split_view_exchange.rs" "observation_history_rejects_epoch_regression_and_broken_chain"
require_pattern "docs/security/external-crypto-attack-ledger-2026-05-15.md" "split-view"
```

In `scripts/audit-local-release-hardening.sh`, add:

```bash
require_pattern "crates/umbrella-kt/src/observation.rs" "does not store account id"
require_pattern "crates/umbrella-kt/tests/split_view_exchange.rs" "public_observation_encoding_round_trips_without_private_account_data"
require_pattern "crates/umbrella-kt/tests/split_view_exchange.rs" "witness_signing_ledger_rejects_second_different_root_for_same_epoch"
```

- [ ] **Step 2: Update `protocol-core-attack-gates.md`**

Replace the two KT split-view rows with:

```markdown
| KT | split-view при трёх злых свидетелях | честная граница одиночного клиента | `threshold_compromised_views_can_verify_but_safety_numbers_diverge`: одна валидная голова не доказывает, что другой голове не дали другой root |
| KT | split-view обнаруживается при обмене наблюдениями | закрыто библиотечным тестом | `threshold_signed_split_views_verify_locally_but_production_api_detects_divergence`: `EquivocationEvidence` создаётся только из двух валидно подписанных конфликтующих наблюдений |
| KT | публичное наблюдение раскрывает личные данные | закрыто тестом | `public_observation_encoding_round_trips_without_private_account_data`: wire-формат содержит только log_id, roots, epoch, log_size, timestamp и подписи |
| KT | свидетель подписывает второй другой root для той же эпохи | закрыто локальной моделью | `witness_signing_ledger_rejects_second_different_root_for_same_epoch` |
| KT | откат или разрыв цепочки эпох | закрыто тестом | `observation_history_rejects_epoch_regression_and_broken_chain` |
```

- [ ] **Step 3: Update `kt-witness-operator-policy.md`**

In the Russian section under “Обязательный мониторинг”, add:

```markdown
- Каждый свидетель обязан хранить локальную память `журнал + эпоха -> root + размер`.
  Повтор той же головы разрешён, но второй другой root для той же эпохи должен
  отвергаться как попытка раздвоения.
- Публичные наблюдения содержат только технические головы эпох: log_id,
  предыдущий root, текущий root, размер, время и подписи. Они не содержат
  телефон, account_id, список устройств, контакты или чаты.
```

In the English section under “Required Monitoring”, add:

```markdown
- Every witness must keep local memory of `log + epoch -> root + size`.
  Repeating the same head is allowed, but a second different root for the same
  epoch must be rejected as an equivocation attempt.
- Public observations contain only technical epoch heads: log_id, previous
  root, current root, size, timestamp, and signatures. They do not contain
  phone number, account_id, device list, contacts, or chats.
```

- [ ] **Step 4: Add external ledger for 2026-05-15**

Create `docs/security/external-crypto-attack-ledger-2026-05-15.md`:

```markdown
# Внешний реестр KT split-view атак

Дата: 2026-05-15

## Русский

Этот файл фиксирует внешний ресерч для усиления Umbrella KT против раздвоения
журнала. Вывод один: одиночная валидная подпись головы дерева не доказывает, что
другим клиентам не показали другой корень. Нужны цепочка эпох, проверка
неизменности, свидетели с памятью и обмен публичными наблюдениями.

| Источник | Что взяли | Как закрыто локально |
|---|---|---|
| RFC 9162 Certificate Transparency | signed tree head, inclusion и consistency proof | `KtObservation`, `KtObservationHistory` |
| CONIKS | пользователи и наблюдатели ловят расхождение корней | `EquivocationEvidence` |
| IETF Key Transparency draft | клиент хранит увиденные корни и проверяет движение вперёд | `observation_history_rejects_epoch_regression_and_broken_chain` |
| Trillian | клиент хранит головы дерева и требует продолжения истории | `KtObservationHistory` |
| WhatsApp AKD + Cloudflare Auditor | эпоха связывает previous/current root, аудитор проверяет уникальность | `WitnessSigningLedger` и публичные наблюдения |
| Consistency-or-Die | при недоказанной согласованности клиент останавливается | `KtTrustDecision::NeedsObservation` и `EquivocationDetected` |

## Остаток перед боем

Локально реализовано ядро доказательства и отказа. Живая гарантия требует
настоящих серверов, настоящих независимых свидетелей, публичного канала
наблюдений и клиентского обмена наблюдениями.
```

- [ ] **Step 5: Update readiness/status docs**

In `docs/security/production-readiness-boundaries.md` and `docs/security/current-status.md`, replace old KT boundary wording with:

```markdown
- KT split-view: локально добавляется библиотечное доказательство раздвоения,
  строгая история наблюдений и память свидетеля. Полная живая гарантия всё ещё
  требует настоящих независимых свидетелей, публичного канала наблюдений и
  обмена наблюдениями между клиентами.
```

- [ ] **Step 6: Run audit scripts**

Run:

```bash
bash scripts/audit-protocol-core-attack-gates.sh
bash scripts/audit-local-release-hardening.sh target/audit-evidence/kt-split-view-hardening/manual
```

Expected: both scripts print OK.

- [ ] **Step 7: Commit**

```bash
git add scripts/audit-protocol-core-attack-gates.sh scripts/audit-local-release-hardening.sh docs/security/protocol-core-attack-gates.md docs/security/kt-witness-operator-policy.md docs/security/production-readiness-boundaries.md docs/security/current-status.md docs/security/external-crypto-attack-ledger-2026-05-15.md
git commit -m "docs: record kt split view hardening gates"
```

## Task 6: Full Verification

**Files:**
- Verify all changed files.

- [ ] **Step 1: Format**

Run:

```bash
cargo fmt --all -- --check
```

Expected: PASS. If formatting fails, run `cargo fmt --all`, inspect the diff, and rerun the check.

- [ ] **Step 2: Focused KT tests**

Run:

```bash
cargo test -p umbrella-kt --all-features --locked
```

Expected: PASS.

- [ ] **Step 3: Audit gates**

Run:

```bash
bash scripts/audit-protocol-core-attack-gates.sh
bash scripts/audit-local-release-hardening.sh target/audit-evidence/kt-split-view-hardening/manual
```

Expected: both scripts print OK.

- [ ] **Step 4: Workspace check if focused gates are clean**

Run:

```bash
cargo test --workspace --all-features --locked
```

Expected: PASS. If the workspace test exposes unrelated pre-existing failures, capture the exact failing package and test name in the final handoff and do not hide it.

- [ ] **Step 5: Final commit only if verification changed docs or formatting**

If verification required formatting or document corrections, commit them:

```bash
git add crates/umbrella-kt/src/observation.rs crates/umbrella-kt/src/witness_state.rs crates/umbrella-kt/src/error.rs crates/umbrella-kt/src/lib.rs crates/umbrella-kt/tests/split_view_exchange.rs scripts/audit-protocol-core-attack-gates.sh scripts/audit-local-release-hardening.sh docs/security/protocol-core-attack-gates.md docs/security/kt-witness-operator-policy.md docs/security/production-readiness-boundaries.md docs/security/current-status.md docs/security/external-crypto-attack-ledger-2026-05-15.md
git diff --cached --quiet || git commit -m "kt: finalize split view hardening verification"
```

Expected: either no staged diff or one final verification commit.

## Self-Review Checklist

- Spec coverage: observation privacy, evidence, chain state, witness memory, docs, and tests are covered by Tasks 1-6.
- Placeholders: this plan uses exact file paths, exact commands, and concrete snippets.
- Type consistency: exported names are `KtLogId`, `KtObservation`, `EquivocationEvidence`, `KtTrustDecision`, `KtObservationHistory`, `WitnessSigningLedger`, and `WitnessSigningDecision`.
- Scope: server integration, real devices, and `rust_1mlrd` are outside this plan.
