# Discovery Integration Spec — Round 7 (Client ↔ Backend)

**Date:** 2026-05-18
**Branch:** `audit/phd-b-discovery-2026-05-18`
**Authority level:** authoritative wire-contract between Umbrella client and
Umbrella server implementation (`rust_1mlrd`) for the discovery layer.

This document is the public-facing protocol contract. The companion document
`rust_1mlrd/docs/specs/2026-05-18-discovery-backend-spec.md` describes the
server-side implementation obligations that satisfy this contract.

---

## 1. Scope

Two discovery primitives:

1. **Phone-number PSI** — `umbrella-discovery::psi`. Client learns
   `S_client ∩ S_server` without revealing `S_client`.
2. **Username lookup** — `umbrella-discovery::username_lookup`. Client looks
   up `@handle → device_pubkey` without revealing handle.

Both bind to KT (Key Transparency) inclusion proofs (`umbrella-discovery::
kt_bind`) so that the server cannot silently swap a discovery answer.

Out of scope (round-7): real-jurisdiction deployment of 5 servers,
SMS-provider integration, `@username` squatting policy, federation with
non-Umbrella discovery servers (round 8+), group discovery by name.

## 2. Cryptographic foundations

### 2.1 OPRF base — RFC 9497 Ristretto255 + Shamir 3-of-5

Reused from `umbrella-oprf` (round 2 attack-tested). Each contact /
handle is blinded under a per-query CSPRNG scalar `r`; client unblinds
via Lagrange combine over any 3 of 5 server partial evaluations.

### 2.2 Per-query anonymous IDs

```
anon_id_i = HKDF-SHA-256(master_key, info_i, 32)
info_i    = u16_be(server_id) || salt || "umbrella-r7/discovery/per-query-anon-id/v1"
salt      = CSPRNG(32)  // fresh per query
```

Server `i ∈ {1..5}` sees a different `anon_id` for the same client; cross-server
correlation requires `master_key`, which is never on the network. Per-query
salt rotation gives within-server unlinkability.

### 2.3 KT bind

Client maintains a pinned KT root per epoch (sourced from witness-cosigned
roots à la round 5/round 6). Discovery answer carries `KtInclusionProof`
binding `(handle, device_pubkey, epoch)` to a leaf in the pinned epoch's
Merkle log (RFC 6962 audit-path verification via `umbrella-kt::
verify_inclusion`).

### 2.4 Replay protection

Each server response carries a fresh `server_nonce` (CSPRNG 32 bytes) and
HMAC-style transcript tag. Client maintains a rolling-window
`NonceReplayGuard` (default 1000 nonces). A duplicate server nonce → fail
stop. Server-side independently maintains its own non-replay register
(see backend spec §6).

## 3. Wire format (canonical, big-endian)

### 3.1 PSI request

```
u8                 version  = 0x01
u8                 witness_index ∈ 1..=5
u16_be             N (entries count, 1..=1024)
N × {
   [u8; 32]        anon_id
   [u8; 32]        blinded (compressed Ristretto255)
}
[u8; 32]           client_nonce
```

Total: `4 + N * 64 + 32` bytes. For `N=500`: 32 036 bytes.

### 3.2 PSI response

```
u8                 version  = 0x01
u16_be             N (must equal request N)
N × {
   [u8; 32]        anon_id (echo)
   [u8; 32]        evaluation (compressed Ristretto255)
}
[u8; 32]           server_nonce
[u8; 32]           transcript_tag (SHA-256-based domain-separated, see psi.rs)
```

Total: `3 + N * 64 + 64` bytes. For `N=500`: 32 067 bytes.

### 3.3 Username request

```
u8                 version  = 0x01
u8                 witness_index ∈ 1..=5
[u8; 32]           anon_id
[u8; 32]           blinded
[u8; 32]           client_nonce
```

Total: 98 bytes.

### 3.4 Username response

```
u8                 version  = 0x01
[u8; 32]           anon_id (echo)
[u8; 32]           evaluation
u16_be             encrypted_record_len  (≤256)
[u8]               encrypted_record       (ChaCha20-Poly1305: nonce(12) || ciphertext)
[u8; 32]           epoch_root
u64_be             tree_size
u64_be             leaf_index
u16_be             leaf_payload_len
[u8]               leaf_payload            (canonical_leaf_payload, see kt_bind.rs)
u16_be             siblings_count          (≤64)
siblings_count × [u8; 32]                  // audit path
[u8; 32]           server_nonce
[u8; 32]           transcript_tag
```

Approximate size: 350-500 bytes per server response (depends on KT tree depth).

## 4. RPC endpoints (proposed; backend specifies binding)

| RPC                       | Direction        | Request format         | Response format        |
|---------------------------|------------------|------------------------|------------------------|
| `discovery.psi.batch`     | client → server  | `PsiRequest`           | `PsiResponse`          |
| `discovery.username.lookup` | client → server  | `UsernameRequest`      | `UsernameResponse`     |
| `discovery.kt.witness`    | client ↔ servers | (out of scope: round 5/6 KT witness signing API) | (signed epoch roots) |

The exact transport (HTTP/2, QUIC, message-pack envelope) is decided by
backend per `rust_1mlrd/docs/specs/2026-05-18-discovery-backend-spec.md`.

## 5. Threshold cluster model

- Five Sealed Servers, each with its own Shamir share `k_i` of the OPRF
  master key.
- Client picks any three of five for a discovery query (round-robin /
  failure-driven).
- 2-of-5 server compromise preserves privacy (formally verified via
  `discovery.spthy` lemma `server_never_learns_plaintext_phone`).
- 3-of-5 server collusion observes labels (OPRF outputs) but not plaintext
  inputs (RFC 9497 SUF; brute force is the only attack, bounded by
  rate-limit + key rotation).

## 6. Rate limit policy

| Window | Default Limit | Rationale |
|--------|--------------|-----------|
| 1 h    | 100 lookups  | Typical address book refresh < 100/h |
| 24 h   | 5 000 lookups | Cap on a single account's total daily quota |

Exponential backoff after burst (`MIN_BACKOFF_SECS * 2^attempt`). Server-side
must coordinate budgets across the cluster — see backend spec §7.

## 7. Threat model rows closed by this contract

| Row | Threat | Closure |
|-----|--------|---------|
| D-1 | Server learns plaintext phone | OPRF blinding (RFC 9497 SUF) |
| D-2 | Server correlates @username queries | Per-query anon-id derivation |
| D-3 | Silent swap of (handle → pubkey) | KT inclusion proof + pinned root |
| D-4 | 4-of-5 cluster collusion | 3-of-5 threshold; KT log public |
| D-5 | OPRF response replay | Server nonce + replay guard |
| D-6 | Anon-id reuse across queries | Fresh per-query salt (CSPRNG) |
| D-7 | Rate-limit bypass via sibling devices | Server-coordinated budget (backend §7) |
| D-8 | Cardinality-timing side channel | Constant-size batches + padding policy (§8) |

## 8. Padding policy (D-8 mitigation)

To bound the cardinality-timing leak, the client SHOULD pad each PSI batch to
the nearest multiple of 100 with dummy contacts (random 32-byte blobs).
The server applies the same OPRF evaluation to dummies as to real entries;
no functional difference. Padding policy is recommended but optional; the
client may opt out by accepting the documented residual leak.

## 9. Versioning policy

All wire objects carry a `version` byte (`0x01` initial). Any future
incompatible change MUST cause decode to fail with
`DiscoveryError::WireDecode { reason }` — no silent fallback.

## 10. Test vectors

Reference test vectors for cross-implementation testing live in
`crates/umbrella-discovery/tests/psi_correctness.rs`. A realistic-scenario
runner (`examples/psi_realistic_scenario.rs`) reports wire sizes + latencies
on the local host.

Round-7 acceptance numbers (verified on macOS arm64 dev host on 2026-05-18):

| Metric | Value |
|--------|-------|
| 500 contacts vs 1M registered | 73/500 intersection correct |
| PSI request wire size (N=500) | 32 036 bytes |
| PSI response wire size (N=500, per server) | 32 067 bytes |
| Three-server PSI response total | 96 201 bytes |
| `prepare_psi_query(500)` time | 23 ms |
| 3-server evaluation total | 59 ms |
| `finalize_psi_query(500)` time | 104 ms |
| Intersection lookup | 0.097 ms |
| Full discovery (excl. pre-built table) | ~187 ms |

## 11. References

- Round-7 design spec: `docs/superpowers/specs/2026-05-18-phd-b-discovery-design.md`.
- Pinkas, Rosulek, Trieu, Yanai 2018 — *SpOT-Light: Lightweight Private
  Set Intersection from Sparse OT Extension*, CRYPTO 2018.
- Kales, Rindal, Rosulek, Trieu, Yanai 2019 — *Mobile Private Contact
  Discovery at Scale*, USENIX Security 2019.
- Lindell 2017 — *How to Simulate It — A Tutorial on the Simulation Proof
  Technique*.
- Hazay, Lindell 2010 — *Efficient Protocols for Set Intersection and
  Pattern Matching with Security Against Malicious and Covert Adversaries*.
- Kissner, Song 2005 — *Privacy-Preserving Set Operations*.
- RFC 9497 — *Oblivious Pseudorandom Functions (OPRFs) using Prime-Order
  Groups*.
- RFC 6962 — *Certificate Transparency* (Merkle inclusion proof construction).
- Signal Blog 2017 — *Private Contact Discovery for Signal* (SGX-based;
  not used here).
- Apple Engineering 2021 — *Apple PSI System* (CSAM detection PSI).
