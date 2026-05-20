# R12 — Live Ratchet-State Capture Attempt

> **CLOSURE BANNER (2026-05-20 reconciliation):** F-PHD-DC-R12-1 + F-PHD-DC-R12-2 documented в этом artifact are **CLOSED** as of Round 5 closure + Pass 5 remediation. `Key::from_slice` stack-copy hardened via `Box<[u8; N]>` heap refactor + `MlockedSecret<T>` wrapping; application_secret live extraction prevented through HW keystore wire-up (R10-1 closure). This file remains as an archive of the round-4 audit findings at the time of writing.

**Date:** 2026-05-19 (round-4 PhD-B device-capture audit)
**Status:** CRITICAL — application_secret extractable while session live;
**HIGH** — stack copy survives drop.

## Method

Binary: `crates/umbrella-client/examples/r12_ratchet_lldb_target.rs`.

The binary structurally models an MLS active session:

1. Synthesize an `epoch_secret = [0xAB; 32]` (in real MLS this comes from
   the joiner_secret + commit_secret + path_secret KEM-derived ratchet
   step, RFC 9420 §8.1).
2. Derive `application_secret` via `Hkdf::<Sha512>::new(None,
   &epoch_secret).expand(b"application", &mut buf)`. The output is
   deterministic from `[0xAB; 32]`: `5233fc1d9e582bc2…f4e4` (32 bytes,
   first 8 prefixed below).
3. Wrap into `SecretBox<[u8; 32]>::new(Box::new(application_secret))`
   — identical pattern to `umbrella-mls::UmbrellaGroup::exporter_secret`
   (`crates/umbrella-mls/src/group.rs:687` returns
   `SecretBox<[u8; MAX_EXPORTER_LEN]>`).
4. Use the secret via `ChaCha20Poly1305::new(Key::from_slice(...))` +
   `encrypt_in_place_detached` on a 60-byte plaintext — identical
   pattern to `UmbrellaGroup::encrypt_application`.
5. Pause for `lldb -p <pid>` attach (R12_PAUSE=1).
6. Resume, `drop(app_secret_box)`, pause again — second attach window.

### Why this models MLS faithfully

- `application_secret` is the 32-byte HKDF-Expand output that MLS rotates
  per epoch (RFC 9420 §8.1, §9). The HKDF input differs (real MLS uses
  `epoch_secret = HKDF-Extract(joiner_secret, commit_secret_or_psk)`),
  but the **output type** and **storage type** are identical:
  `[u8; 32]` in a `SecretBox`.
- The AEAD encrypt path is byte-identical: `ChaCha20Poly1305::new(Key::
  from_slice(secret_bytes))` is what `openmls` calls under the hood for
  ciphersuite 0x0003 / 0x004D.
- The lldb scanner walks every writable region; the secret bytes are
  byte-pattern unique enough (random HKDF output) to disambiguate from
  general heap fill.

## Outcomes

### LIVE phase

```
[R12 lldb] MATCH SESSION_LIVE base=0x16f0a0000 abs=0x16f895e30 name=
[R12 lldb]   prev16=a7260100000000003f00000000000000  match=5233fc1d9e582bc2f156c56eb40ef303ca2f8700da68063b1f5aa653be72f4e4
[R12 lldb] MATCH SESSION_LIVE base=0x600000000000 abs=0x600003d68000 name=
[R12 lldb]   prev16=00000000000000000000000000000000  match=5233fc1d9e582bc2f156c56eb40ef303ca2f8700da68063b1f5aa653be72f4e4
[R12 lldb] SUMMARY SESSION_LIVE: regions=72 chunks=665 bytes=685916160 app_secret_hits=2
```

- `0x16f895e30` — stack region (0x16f0a0000 base). Match preceded by
  16 bytes that include a stack-frame pointer. This is `Key::from_slice`
  return slice or the ChaCha20Poly1305 cipher's internal key block on
  stack.
- `0x600003d68000` — heap, `name=` empty. Prev-16 = zeros (heap block
  header). This is the `SecretBox<[u8; 32]>::new(Box::new(...))`
  allocation — exactly the heap-resident `application_secret`.

### AFTER_DROP phase

```
[R12 lldb] MATCH AFTER_DROP base=0x16f0a0000 abs=0x16f895e30 name=
[R12 lldb]   prev16=00000000000000003f00000000000000  match=5233fc1d9e582bc2f156c56eb40ef303ca2f8700da68063b1f5aa653be72f4e4
[R12 lldb] SUMMARY AFTER_DROP: regions=72 chunks=665 bytes=685916160 app_secret_hits=1
```

- Heap match (0x600003d68000) **GONE** — `SecretBox::drop` zeroize fired.
- Stack match (0x16f895e30) **STILL PRESENT**. The stack-resident copy
  from `ChaCha20Poly1305::new(Key::from_slice(secret_bytes))` is NOT
  zeroized — the cipher is dropped but its constructor's argument-marshal
  spill bytes are not in any zeroize scope.

## Implication for MLS forward secrecy

RFC 9420 §9 forward secrecy guarantees state that **once an epoch is
rotated**, prior application_secrets are unrecoverable. This requires
the secret to be **wiped** at rotation. Result:

- Heap (`SecretBox`) wiping works → if attacker captures device AFTER
  ratchet rotation but BEFORE prior epoch_secret was on stack at
  rotation moment, prior epoch keys are gone.
- Stack copies surviving drop **break this guarantee** for the time
  window between drop and the next stack-frame overwrite (function
  return + new function call). For long-lived programs this overlap is
  small (microseconds), but a state-level adversary can engineer the
  capture window precisely via `task_for_pid` racing.

## Findings

### F-PHD-DC-R12-1 — application_secret extractable while session live (CRITICAL)

While an MLS session is alive, the 32-byte application_secret is
present in both heap (`SecretBox`) and stack (cipher constructor).
Adversary with debugger access on the captured device reads either
location → captures the AEAD key → decrypts every application message
on the wire for that epoch. Forward secrecy holds for **prior** epochs
(provided their keys were already dropped + stack overwritten); it
does NOT protect the current epoch.

This is the expected baseline for any in-software cryptographic
session. The mitigation is the same as R7: move the AEAD key into a
TEE-resident object (Apple `kSecAttrTokenIDSecureEnclave`-backed
symmetric key via CryptoKit `SymmetricKey` plus
`AES.GCM.SealedBox` operation; Android `KeyGenParameterSpec` with
PURPOSE_ENCRYPT/DECRYPT and `setIsStrongBoxBacked(true)`).

### F-PHD-DC-R12-2 — Stack copy survives `drop(SecretBox)` (HIGH)

After `drop(SecretBox<[u8; 32]>)`, the heap was wiped but a stack copy
remained. **Window of exposure** = "time between SecretBox drop and
stack-frame overwrite". For RFC 9420 forward-secrecy claim this is the
crack. Same vector as R7 stack-entropy finding — endemic across all
crypto primitives that take `&[u8]` by `from_slice` then construct
internal `[u8; N]` state.

Remediation: prefer `Zeroizing<[u8; 32]>` wrapper over raw `&[u8]` at
every cipher-constructor call site. Audit pattern: `rg "Key::from_slice"
crates/ --type rust`.

## Severity

- F-PHD-DC-R12-1: **CRITICAL** (current-epoch decryption on live
  device).
- F-PHD-DC-R12-2: **HIGH** (forward-secrecy window).

Both closed by F-PHD-DC-R7-1 (hardware-back identity) + F-PHD-DC-R7-3
(stack-spill audit) + F-PHD-DC-R11-1 (mlock).
