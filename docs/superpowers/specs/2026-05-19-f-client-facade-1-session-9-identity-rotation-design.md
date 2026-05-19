# F-CLIENT-FACADE-1 session 9 — identity rotation facade wire-up design

**Date**: 2026-05-19
**Pipeline**: F-CLIENT-FACADE-1 Block 7.4 engineering milestone, session 9/10
**Predecessors**: sessions 1–8c3 closed (transport + MLS create/add_member +
Cloud-wrap end-to-end + Cloud at-rest send + Secret sealed-sender V1 +
KT self-monitor + KT 3-of-5 witness threshold + production-path wire
codec + KtSignedRootsFetcher trait). See memory
`project_phd_b_pass5_complete.md` for the full session ladder.

**Status**: **DESIGN PROPOSAL — awaits user approval before any code work**.

---

## 1. Goal of session 9 (per memory annotation)

Memory entry `project_phd_b_pass5_complete.md` line 231 (post-8c3 update)
records the F-CLIENT-FACADE-1 pipeline tail as:

> Sessions 9/10 pending: identity rotation BIP-39 + dual sig + SLH-DSA (9);
> calls DTLS-SRTP + SFrame + device transfer (10).

«Identity rotation BIP-39 + dual sig + SLH-DSA» captures three composable
ingredients but **does not pin scope**. The codebase already implements all
three at primitive level; what is missing is the **facade-level method** that
threads them end-to-end through `ClientCore`. This spec proposes one
tractable scope choice and bounds the rest as deferred work.

---

## 2. Existing primitives inventory (reconnaissance results)

### 2.1 `umbrella-backup::cloud_wrap::identity_rotation`

- `IdentityRotationRecord` struct (234-byte fixed wire layout):
  - `version: u8` (= `AUTHORIZATION_WIRE_VERSION = 0x01`)
  - `old_identity_pubkey: [u8; 32]` — Ed25519
  - `new_identity_pubkey: [u8; 32]` — Ed25519
  - `rotation_timestamp: u64` (unix millis)
  - `rotation_reason: RotationReason` (1 byte: `CatastrophicRecovery` =
    `0x01` / `PlannedRotation` = `0x02` / `IdentityCompromise` = `0x03`)
  - `old_identity_signature: [u8; 64]` — Ed25519 over canonical input
  - `new_identity_signature: [u8; 64]` — Ed25519 over **same** canonical input
  - `code_recovery_public_half_proof: [u8; 32]` — HKDF-SHA512 from 12-word
    entropy (F-PHD-RETRO-3-E binding against 24-word leak)

- `canonical_signing_input_rotation(version, old_pk, new_pk, ts, reason,
  proof) -> Vec<u8>` (115 bytes: 30 domain sep `"umbrellax-identity-rotation-v1"`
  || version(1) || old_pk(32) || new_pk(32) || ts_BE(8) || reason_tag(1) ||
  proof(32)).

- `seal_identity_rotation_record(old_pk, new_pk, ts, reason, proof,
  old_signer: FOld, new_signer: FNew) -> Result<IdentityRotationRecord,
  BackupError>` — generic over signer closures `Fn(&[u8]) ->
  Result<[u8;64], BackupError>`. Refuses `old_pk == new_pk` at construction
  via `BackupError::InvalidWireFormat`.

- `IdentityRotationRecord::encode() -> [u8; 234]` deterministic + matching
  `from_bytes(&[u8]) -> Result<Self, BackupError>` strict decoder.

- `IdentityRotationRecord::verify() -> Result<(), BackupError>` — recomputes
  canonical input, verifies both Ed25519 signatures.

### 2.2 `umbrella-identity::code_recovery`

- `CodeRecoveryMnemonic` — 12-word BIP-39-style mnemonic. Holds 16-byte
  entropy.

- `CodeRecoveryMnemonic::public_half_proof(account: &[u8; 32]) -> [u8;32]`
  — HKDF-SHA512 of 12-word entropy salted by account; stable across
  rotations of the same 12-word phrase, published in KT at first bootstrap
  (F-PHD-RETRO-3-E). This is the value that goes into
  `IdentityRotationRecord::code_recovery_public_half_proof`.

- `derive_rotated_identity_material(old_identity_pubkey, recovery, account)
  -> Result<RotatedIdentityMaterial, IdentityError>` — produces new
  `SigningKey` + `EncryptionKey` + `IdentityPublic` via HKDF-SHA512
  domain-separated by `"umbrellax-identity-rotation-v1"`. Verifies that
  caller actually holds the old identity (sanity check; if `old_identity_pubkey`
  doesn't match what the recovery + account derive to, returns
  `IdentityError::RotatedSeedOldIdentityMismatch`).

### 2.3 `umbrella-kt::authorization_entries`

- `apply_identity_rotation(log_state: &mut KtLogState, record:
  &IdentityRotationRecord) -> Result<(), KtError>` — client-side log mirror
  application: verifies dual signatures, checks `code_recovery_public_half_proof`
  matches stored value (F-PHD-RETRO-3-E), updates
  `current_identity_pubkey`, cascade-revokes all device-entries under old
  identity (SPEC-09 §7.2 rule). Throws on `RotationDualSignatureFailed`,
  `RotationOldIdentityMismatch`, `RotationIdenticalPubkeys`,
  `CodeRecoveryProofMismatch` (all already in `KtError` since stage 8).

- `EntryType::IdentityRotation = 0x06` — wire-format tag, set by callers
  before publishing.

### 2.4 `umbrella-client::core::ClientCore`

- `mls_keystore: Arc<dyn KeyStore>` — trait object exposing
  `identity_public()`, `identity_x25519_public()`, `device_public(index)`,
  `sign_identity(&[u8])`, etc. Backing impl: `InMemoryKeyStore` (test) либо
  hw-backed (production via `hw_callback`).

- `hw_callback: Option<Arc<dyn PersistentKeyStoreCallback>>` — when present,
  identity signing routes through `callback.sign_identity(&[u8])` rather
  than direct ed25519. Critical for production rotation path: the new
  identity SK lives only in HW Keystore, so signing the rotation record
  with the *new* identity requires the HW-backed signer attached to the
  new identity material.

- `kt_transport: Arc<StubKtTransport>` — already has `publish` (counter
  stub) and `publish_*` API; production `Http2KtTransport::publish(Vec<u8>)`
  exists (used by session 1–3 sends).

- **No CodeRecoveryMnemonic field yet.** Round-6 distributed identity
  model (`feedback_real_not_paperwork` memory + `project_phd_b_6_rounds_complete`
  memory: «24+12 слов **никогда** на устройстве через FROST DKG 3-of-5»)
  implies CodeRecoveryMnemonic is **threshold-shared across Sealed
  Servers**, not held in plaintext locally. Rotation may therefore need
  a distributed signing protocol rather than direct mnemonic-derive on
  device.

### 2.5 Round-6/7 distributed identity model implications

Per memory file `project_phd_b_6_rounds_complete.md`:

- 24-word identity mnemonic + 12-word recovery mnemonic **never** reach
  the device. Both are FROST-DKG-3-of-5 threshold-shared via Sealed Servers.
- At normal use the device holds only an ephemeral key derived per-session
  through PIN re-entry; Sealed Servers serve threshold shares only on
  PIN-verified requests.
- Identity rotation in this model would require **distributed signing** by
  3-of-5 Sealed Servers (old identity sig + new identity sig) — neither
  signing operation can happen purely on-device since the relevant private
  scalars are not on the device.

**This is a fundamental architectural question** for session 9 scope.

---

## 3. Open design questions (require user decision)

### Q1. Distributed signing vs local signing for rotation

- **Option A (local-signing facade-only path)**: assume rotation is invoked
  with `CodeRecoveryMnemonic` already in hand (user typed 12 words into
  native UI), derive new identity material locally via
  `derive_rotated_identity_material`, sign both old + new sigs locally
  using direct `ed25519` SigningKey. This **violates** the Round-6 «never on
  device» invariant for the 12-word entropy.

- **Option B (threshold-distributed-signing path)**: rotation routes through
  Sealed Servers — device sends rotation request with PIN proof; servers
  threshold-cooperate to derive new identity material, threshold-sign both
  old + new sigs, return signed `IdentityRotationRecord` bytes to device
  for KT publish. Requires server-side primitives that do not yet exist in
  `rust_1mlrd` backend.

- **Option C (HW-Keystore path with `hw_callback`)**: 24/12-word entropy
  stays in OS HW Keystore (iOS Secure Enclave / Android StrongBox); facade
  asks `hw_callback.sign_identity_rotation(...)` для obtain both
  signatures. Requires extending `PersistentKeyStoreCallback` trait + native
  layer. This was the path for legacy identity (memory `F-CLIENT-HW-2`).

**Recommendation**: defer Q1 to **explicit user decision**. Each option
re-shapes the entire session 9 scope; without picking one, code work
risks throwing rest.

### Q2. Where does `code_recovery_public_half_proof` come from at facade level?

- **Option α**: ClientCore stores the proof on disk after bootstrap (KT
  publish stores it server-side per F-PHD-RETRO-3-E; local copy is just
  cache). Rotation reads cached proof. Risk: cache poisoning under
  adversary with device access.

- **Option β**: ClientCore queries kt_transport for current
  `code_recovery_public_half_proof` of account before constructing
  rotation record. Risk: server can lie; would require KT inclusion proof
  to be safe.

- **Option γ**: User-provided per call — facade method takes proof as
  parameter; UX layer is responsible (UI prompts 12 words and computes
  proof). Cleanest but pushes complexity to native layer.

**Recommendation**: Option γ — proof is a parameter, facade does not
hold/derive it. Aligns with «12 words never on device by default» rule:
if user wants to rotate, they explicitly provide 12 words at that moment;
they are not stored locally between rotations.

### Q3. What happens to MLS groups after identity rotation?

Identity rotation cascades revocation of all device-entries under the old
identity (SPEC-09 §7.2). This invalidates the MLS leaf node credential of
every group the old identity participates in. Options:

- **Option I**: out-of-scope for session 9. Facade method only publishes
  rotation record + updates local identity material; MLS group repair is
  separate session.

- **Option II**: facade method also iterates MLS groups Alice is in and
  leaves/rejoins each as part of rotation. Hugely larger scope.

**Recommendation**: Option I, defer MLS group repair to session 9c либо
post-1.0.0.

### Q4. New identity material generation

- **Option K1**: re-use existing IdentityKey from a freshly-generated new
  `IdentitySeed` (24-word BIP-39 on device). Violates Round-6 «never on
  device».

- **Option K2**: HKDF-derive new identity from 24-word entropy via
  `derive_rotated_identity_material` — but 24 words also «never on device»
  per Round-6.

- **Option K3**: distributed protocol via Sealed Servers (matches Q1
  Option B). Out of scope without backend.

**Recommendation**: tied to Q1 — depends on chosen signing path.

### Q5. SLH-DSA-128f optional backup signature

Memory annotation mentions SLH-DSA. The existing
`IdentityRotationRecord` does **not** carry SLH-DSA signature field — only
two Ed25519 sigs. SLH-DSA backup is a property of KT V2 entries
(`KtEntryV2` under `feature = "pq"`). To wire SLH-DSA backup signature into
rotation flow we'd need either:

- Extend `IdentityRotationRecord` wire format to V2 (breaking change,
  affects backend).
- Issue a separate companion entry (V2 identity-announce + V1 rotation
  side-by-side, server enforces correlation).

**Recommendation**: defer SLH-DSA backup signature for rotation to session
9b либо post-1.0.0 — the existing dual-Ed25519 sig is adequate threat
coverage for current 1.1.0 release scope.

---

## 4. Proposed minimum viable session 9 scope (subject to user approval)

Assuming **Q1 = Option C (HW-Keystore via `hw_callback`)**, **Q2 = Option
γ (proof as parameter)**, **Q3 = Option I (defer MLS repair)**, **Q4 tied
to Q1 = C (HW Keystore generates new material)**, **Q5 deferred**:

### 4.1 New `PersistentKeyStoreCallback` trait method

Extend the trait in `crates/umbrella-client/src/keystore/hw_callback.rs`:

```rust
#[async_trait]
pub trait PersistentKeyStoreCallback: Send + Sync {
    // ... existing ...

    /// Initiate identity rotation. Native side:
    /// 1. Generates new identity SK + EK + 32-byte HKDF derived from
    ///    new 24-word entropy (or whatever HW path) — material lives in
    ///    HW Keystore; only public key returned to Rust.
    /// 2. Computes both signatures over `canonical_signing_input` using
    ///    old identity SK (currently active in HW) and new identity SK
    ///    (just-generated).
    /// 3. Returns new pubkey + both sigs to facade.
    async fn rotate_identity(
        &self,
        canonical_input_old: &[u8],   // input for old sig
        canonical_input_new: &[u8],   // input for new sig (== same bytes)
        reason: RotationReason,
    ) -> Result<RotatedIdentityArtifact, ClientError>;
}

pub struct RotatedIdentityArtifact {
    pub new_identity_pubkey: [u8; 32],
    pub old_identity_signature: [u8; 64],
    pub new_identity_signature: [u8; 64],
}
```

### 4.2 New facade method

`crates/umbrella-client/src/facade/identity.rs` (NEW file):

```rust
pub async fn rotate_identity(
    core: &Arc<ClientCore>,
    reason: RotationReason,
    code_recovery_public_half_proof: [u8; 32],
) -> Result<RotationOutcome>;

pub struct RotationOutcome {
    pub old_identity_pubkey: [u8; 32],
    pub new_identity_pubkey: [u8; 32],
    pub rotation_timestamp: u64,
}
```

Flow:
1. Read `old_identity_pubkey = core.mls_keystore.identity_public()`.
2. Build `canonical_signing_input_rotation(...)` using **stub** new pubkey
   `[0; 32]` first — to ask HW callback for actual sigs (returns the new
   pubkey).
3. Re-build canonical input with the returned new pubkey.
4. Re-call HW callback to sign with both keys over the corrected input.

*(Round-trip nature is awkward — alternative: HW callback designs the input
itself given old + reason + proof. Сleaner API. Need refactor of
`canonical_signing_input_rotation` invariant либо HW callback must
re-implement it. Decision deferred.)*

5. Construct `IdentityRotationRecord` from returned sigs + metadata.
6. Encode → 234 bytes; prepend `EntryType::IdentityRotation = 0x06` byte
   и invoke `core.kt_transport().publish(prefixed_bytes)`.
7. Local state update: replace `core.mls_keystore` with one bound to new
   identity. Requires ClientCore mutation API that doesn't exist today —
   needs design (Arc<Mutex<dyn KeyStore>> либо similar).

### 4.3 Integration tests

10 contract tests in
`tests/facade_session9_identity_rotation.rs`:
1. Happy path: rotation succeeds, kt_transport receives 235-byte payload,
   record decodes + verifies, local mls_keystore now reports new pubkey.
2. Fail-closed: `old_pk == new_pk` (refuses identical rotation).
3. Fail-closed: HW callback returns invalid (zero) signature.
4. Fail-closed: HW callback returns wrong-length signature.
5. Fail-closed: proof bytes all-zero (defence — server-side will reject,
   facade can pre-check либо not, decision pending).
6. Idempotency: invoking rotation twice in flight (mock callback fails
   second time — facade serialises).
7. KT transport error propagates as `ClientError::Network`.
8. Round-trip: encoded bytes decode back to same record.
9. After rotation: `core.mls_keystore.identity_public()` returns new pubkey.
10. After rotation: `core.kt_witness_set()` and other ClientCore state
    unchanged (rotation is identity-scoped, not infra-scoped).

### 4.4 Out-of-scope deferrals

- **MLS group repair** (Q3 Option II): leave / rejoin all groups after
  rotation. Session 9c либо separate stage.
- **SLH-DSA backup sig**: V2 entry coupling — session 9b либо post-1.0.0.
- **Distributed-signing path** (Q1 Option B): requires backend kt-svc +
  Sealed Server protocol; entire separate phase.
- **PIN re-verification**: rotation should perhaps require fresh PIN
  proof to authorise; protocol-level decision.

---

## 5. Estimated session 9 budget

- Q&A clarification cycle (assuming user approves Option A1/Q1=C, Q2=γ,
  etc.): ~10–15 min.
- HW callback trait extension + stub impl: ~30 min.
- Facade method scaffold + canonical input handling: ~45 min.
- Local state mutation API design + impl: ~60 min (largest unknown).
- 10 integration tests: ~90 min.
- Verify + commit + memory: ~30 min.

Total ~4–5 hours. Probably fits one fresh session with budget headroom if
above design choices are accepted up front. If user picks a more ambitious
combination (e.g., Q1=B distributed signing), session 9 needs to be split
across 2–3 sub-sessions, ideally with backend coordination.

---

## 6. Suggested user response shape

To move forward, user picks one row per question:

| ID | Question                        | Recommended option | Effect                  |
|----|---------------------------------|--------------------|-------------------------|
| Q1 | Signing path                    | C (HW-Keystore)    | Most aligned with Round-6 device-isolation; needs trait extension. |
| Q2 | `public_half_proof` source      | γ (parameter)      | Cleanest; pushes UX to native layer. |
| Q3 | MLS group repair                | I (defer)          | Keeps session 9 tractable. |
| Q4 | New identity material gen       | C (HW Keystore)    | Same as Q1. |
| Q5 | SLH-DSA backup sig              | defer to 9b/post   | Avoids V2-entry coupling for 1.1.0. |

Any divergence is fine; just be explicit so session 9 starts with a
locked-in plan rather than discovering scope mid-flight.

---

## 7. Why this is a design spec, not a code commit

Session 8c3 closed cleanly with all primitives stable. Session 9 has
multiple architectural decision points (Q1–Q5) that re-shape scope
fundamentally. Per memory file
`feedback_phd_no_partial.md` and the broader F-CLIENT-FACADE-1 pattern
(each session entered with a detailed plan from user), starting session 9
without explicit scope decisions risks producing «partial» work
contradicting the pre-planned-per-session pattern.

This spec therefore proposes scope, identifies open questions, and waits
for user OK before any `crates/` change. The previous 8 sessions follow
the same model — user gives plan, executor delivers.
