# Round 6 — Distributed Identity + PIN Model Design Spec

**Date:** 2026-05-19 (round 6, comprehensive scope)
**Predecessors:** rounds 1-5 (algorithmic + hedged + device-capture closure)

**Goal:** Fundamental architectural change — 24+12 words **never** present on device (created via distributed key generation on 5 servers), PIN-based daily unlock with re-derived device-key, anti-OS clipboard/keyboard/assistant restrictions, real attack regression tests.

## Threat model upgrade

State-level adversary with:
- Physical access to device
- Cooperation of Apple/Google (via NSL/legal coercion)
- Compromised chip vendor (Secure Enclave / StrongBox vendor)
- Network adversary
- Coercion of user
- 1-2 of our 5 servers compromised

User goal: continue using Umbrella with Telegram-grade UX, but with secrets distributed such that no single point of compromise leaks identity.

## Core architectural change

**Old (current, post-round-5):**
- 24+12 words generated **on device** via OsRng at first registration
- Identity-secret materializes on device for milliseconds-seconds
- Distributed to 5 servers via existing Sealed Servers recovery flow
- Master_key encrypted in `row_cipher` on disk
- Master_key + identity in RAM via `mlock` + `Box` during active use
- Recovery via 24 words direct entry on new device

**New (this round):**
- 24+12 words generated **distributedly on 5 servers** via FROST-based DKG protocol
- Identity-secret **never materializes** in one place
- On device: only public identity key + account ID
- Master_key + device-key **re-derived** on each unlock from `PIN + server_share + device_randomness`
- No persistent master/device keys on device
- Recovery via threshold servers (24 words + time-lock 24h + push to primary device)
- 12 words = "святой Грааль" — last-resort emergency factor after 3 failed 24-word entries; also unlocks old cloud-chat history

## Universal entry rule

Single rule applied everywhere:
```
PIN → 24 words + OTP → 12 words (final emergency) → permanent delete
```

Detailed:
- Logged-in device daily unlock: **PIN**
- 3 wrong PIN attempts → **24 words + OTP** (if OTP enabled)
- New device or logged out: **24 words + OTP**
- 3 wrong 24-word attempts → **12 words** (emergency last chance)
- 5 wrong 12-word attempts → permanent account delete
- Reverse PIN → permanent delete (duress)

Phone number used **only once** at registration for friend discovery (like Telegram username). Never used for recovery. OTP optional 2FA app.

## Five implementation stages

### Stage 1 — Server-side infrastructure (~6h subagent work)

**Files (new + modified):**
- New crate `umbrella-threshold-identity` or extend `umbrella-server-blind-postman`
- FROST-Ed25519 DKG protocol implementation (use `frost-ed25519` crate from ZF, formally audited)
- 3-round handshake between 5 servers
- Threshold signing protocol (any 3 of 5 sign)
- Server state: encrypted PIN-derived shares, account anonymous IDs, attempt counters, time-lock states, push channels

**Components:**
1. **DKG bootstrap protocol** — 5 servers generate distributed identity shares via Pedersen DKG. Output: each server holds one share, no server holds full secret. Public key derivable by anyone.
2. **Threshold signing** — for rare operations: rotate device-key, add new device, revoke device-key, account recovery confirmation.
3. **Time-locked recovery** — recovery requests held 24h with push to primary device. Primary device can cancel. Optional acceleration via old PIN (→ 1h time-lock).
4. **Attempt counters with lock-out** — 3 wrong PIN → freeze, 3 wrong 24-word → escalate to 12-word, 5 wrong 12-word → permanent delete.
5. **Duress mechanism** — reverse PIN triggers `UNRECOVERABLE_DELETE` across 5 servers in parallel.
6. **Dead-man switch (optional per user setting)** — if no heartbeat for N days, automatically wipe shares.
7. **Resilient transport** — Tor / mixnet / alternative IPs as fallback to TLS.
8. **24h offline ticket** — server issues short-lived offline auth token after successful unlock; device works offline 24h with cached token.
9. **Zero-knowledge account IDs** — each of 5 servers has different anonymous ID for same user, cross-server correlation impossible.

### Stage 2 — Client backend rewiring (~6h subagent work)

**Files modified:**
- `crates/umbrella-identity/src/seed.rs` — `IdentitySeed::generate` → deprecated for production use, only `cfg(test)`
- `crates/umbrella-identity/src/code_recovery.rs` — same
- `crates/umbrella-identity/src/keystore.rs` — bootstrap path replaced with DKG flow
- New `crates/umbrella-identity/src/distributed_identity.rs` — DKG client-side participant
- `crates/umbrella-client/src/keystore/master_key.rs` (new) — re-derive master_key from PIN
- `crates/umbrella-client/src/keystore/device_key.rs` (new) — re-derive device-key from PIN + server share
- `crates/umbrella-client/src/lifecycle.rs` (new) — wipe-on-background, wipe-on-screen-lock, wipe-on-debugger

**Components:**
1. DKG client side — participant in 3-round protocol with 5 servers
2. Device-key derivation: `device_key = HKDF(PIN_KDF || server_share || device_random || transcript)`
3. Master-key derivation: `master_key = HKDF(PIN_KDF || account_local_salt)`
4. PIN-KDF: Argon2id with memory=64MB, iterations=3, parallelism=4 (mobile-friendly but expensive for brute-force)
5. Lifecycle integration:
   - App goes to background → 2-min timer → wipe device-key + master-key
   - App goes inactive → immediate wipe of session-keys, keep device-key
   - Screen lock detected → immediate full wipe
   - Debugger / jailbreak / root detected → emergency wipe + close
   - Heartbeat thread sends ping to servers every 30 sec while active
   - On 2-min heartbeat loss → servers mark device-key suspicious → revocation
6. Reject work on jailbroken/rooted devices (configurable: hard refuse vs warning)
7. 5-registry integrity check on startup (our + Sigstore + CT + p2p + alternative jurisdiction)
8. 24h offline cached auth ticket in `MlockedSecret`

### Stage 3 — UI/UX (~5h subagent work)

**Files (FFI exports + new UI tests):**
- `crates/umbrella-ffi/src/export/onboarding.rs` (new) — new bootstrap flow
- `crates/umbrella-ffi/src/export/pin.rs` (new) — PIN entry exports
- `crates/umbrella-ffi/src/export/recovery.rs` (new) — recovery flow
- iOS harness `examples/ios-harness/.../Onboarding.swift` (new)
- Android harness `examples/android-harness/.../Onboarding.kt` (new)
- Existing UI bridges updated

**Components:**
1. Registration flow:
   - Open app → "Create account"
   - Set PIN (6 digits, optionally 4 digits chosen at setup)
   - Optional phone number (one-time SMS verification, for friend discovery only, NOT for recovery)
   - Optional OTP setup (Google Authenticator, 1Password, etc.)
   - DKG with servers ~2-3 seconds with progress bar
   - **No 24/12 words shown ever** (unless explicitly exported later)
2. PIN entry screen:
   - 10 digits in 4x3 grid, **shuffled each time**
   - Visual noise overlay (anti-camera): flickering pattern that humans see through, cameras capture as noise
   - Blind tap: buttons don't highlight on press
   - System flag for screen capture prohibition (FLAG_SECURE / iOS secureCapture)
   - System service restrictions:
     - Disable Siri / Google Assistant
     - Disable Smart Reply / autocorrect / auto-suggest
     - Disable clipboard (no copy/paste)
     - Disable share sheet
     - Disable AutoFill API
     - Detect active accessibility services → warn + refuse
3. New device entry screen (two paths):
   - **Path A**: QR scan with primary device → primary device confirms with PIN → planned device gets new PIN setup
   - **Path B**: "Restore from recovery code" → enter 24 words → optionally enter old PIN for acceleration → set new PIN → 24h time-lock (or 1h with acceleration)
4. Recovery flow UI:
   - Time-lock display "восстановление через 23:59:42"
   - Push to primary device "Дмитрий, начат процесс восстановления. Отменить?"
   - Cancel button on primary device
5. Settings → Security:
   - Export recovery code (24 words) — with FLAG_SECURE, 60s timer, scroll-to-confirm
   - Export emergency code (12 words) — same protections
   - Connect OTP authenticator
   - Verify phone number (optional, one-time SMS)
   - Wipe-on-background timing (2 min default, configurable 1-30 min)
   - Block screenshots for all chats (toggle)
   - Self-destruct dead-man switch (toggle + days)
6. Duress feedback: reverse PIN visually identical to normal entry → "loading" 3 sec → "no account" screen (indistinguishable from never-registered)

### Stage 4 — Anti-forensic in chats (~3h subagent work)

**Files:**
- `crates/umbrella-mls/src/screenshot_policy.rs` (new) — per-chat screenshot policy
- `crates/umbrella-sealed-sender/src/self_destruct.rs` (new) — TTL messages
- Existing chat handlers extended

**Components:**
1. FLAG_SECURE per-chat opt-in (settings toggle)
2. Screen recording detection via system APIs:
   - iOS: `UIScreen.main.isCaptured`
   - Android: `MediaProjection` active detection
3. On screen recording detected: messages replaced with "(скрыто)" overlay
4. Screenshot notification: when receiver takes screenshot of secret chat, sender notified via push
5. Self-destruct TTL messages (sender-side specified, receiver-side wiped after view+timer)
6. One-time view media (photos/videos with FLAG_SECURE + auto-wipe after view)
7. Optional: invisible watermark with anonymous account ID for tracing leaks
8. Disable copy/paste in secret chats (long-press doesn't show "copy")

### Stage 5 — Real attack regression tests (~4h subagent work)

**Test files (new):**
- `crates/umbrella-pq/tests/attack_r20_lldb_no_identity_on_device.rs`
- `crates/umbrella-client/tests/attack_r21_duress_pin_deletes_account.rs`
- `crates/umbrella-client/tests/attack_r22_time_lock_recovery.rs`
- `crates/umbrella-client/tests/attack_r23_5_registry_detects_fake_version.rs`
- `crates/umbrella-mls/tests/attack_r24_screen_recording_detected.rs`
- `crates/umbrella-client/tests/attack_r25_system_services_disabled.rs`
- `crates/umbrella-client/tests/attack_r26_dos_fallback_channels.rs`
- `crates/umbrella-client/tests/attack_r27_speed_local_operations.rs`

**Attack scenarios:**
- **R20**: build process bootstraps identity via DKG, attach lldb during registration, grep for 32-byte identity_sk in process memory → must be **0 hits** (identity never on device).
- **R21**: register account, set normal PIN `123456`, set duress as reverse `654321`. Enter duress PIN → assert servers received `UNRECOVERABLE_DELETE` command + 5 shares wiped → assert subsequent normal PIN entry returns "account does not exist".
- **R22**: simulate new device entering 24 words → assert time-lock 24h initiates → assert push sent to mock primary device → primary device cancel → assert recovery cancelled. Repeat with no cancel → assert recovery completes after 24h.
- **R23**: substitute app binary with modified version, run startup integrity check → assert 5-registry check fails on at least 4 of 5 sources → app refuses to start.
- **R24**: start screen recording (mocked), open secret chat → assert messages replaced with "(скрыто)" overlay.
- **R25**: open PIN entry screen, attempt invoke Siri/Google Assistant programmatically → assert services disabled. Attempt clipboard read → empty. Attempt screen capture → blocked.
- **R26**: register account, simulate primary network channel blocked → assert Tor fallback activates → assert successful unlock via Tor.
- **R27**: send 1000 messages in cloud chat, measure server interactions → assert servers participated only in initial unlock + heartbeat (not in message send). Assert end-to-end message latency < 50ms (local operation).

### Universal acceptance gate

All 5 stages must pass:
1. Stage 1: FROST DKG protocol works between 5 mock servers, threshold sign passes Ed25519 verification.
2. Stage 2: `cargo test --release --workspace --all-features` green. Existing tests unbroken.
3. Stage 3: FFI exports compile-green, UI harnesses (iOS Swift typecheck, Android Kotlin static review) pass.
4. Stage 4: chat anti-screenshot tests pass.
5. Stage 5: all 8 R20-R27 tests pass with measured numerical results.

## Branch

Continue on `audit/phd-b-hybrid-pq-2026-05-19`. Single big PR at end (all 4 rounds + this round 6 in one PR).

## Stop / handoff per memory `feedback_phd_no_partial`

Each stage delivered atomically. If context budget runs short in middle of stage:
- Document partial state in stage-specific intermediate report
- Commit what's done
- Hand off to fresh agent with explicit "Stage N partially done, remaining: X, Y, Z"
- Do NOT claim closure of stage with partial implementation

## What does NOT count (anti-paperwork)

- Tamarin lemma about distributed identity without paired real DKG implementation
- "Skeleton" Swift/Kotlin native bridges that don't compile
- FROST signing claims without runnable test producing valid Ed25519 signature
- PIN screen UI without actual system service disablement verified
- R20-R27 tests without numerical results recorded (bytes scanned, time taken, hit counts)
- "Carry-over to next round" for stages that should be implemented here

## No backwards compatibility burden

Per memory and earlier conversation: "реальных пользователей нет поэтому переходы и вопрос по ним снимаются, версию поднимать не стоит просто сделаем как фикс на текущей версии". Direct replacement of `IdentitySeed::generate` production path, no migration logic needed.

## Literature for citations in final report

- Pedersen 1991 — "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing" (DKG foundation)
- Komlo, Goldberg 2020 — "FROST: Flexible Round-Optimized Schnorr Threshold Signatures"
- Krawczyk 2010 — "HKDF" (for re-derive)
- Biryukov, Khovratovich 2016 — "Argon2: the memory-hard function for password hashing and other applications"
- Apple Platform Security Guide May 2024
- Android Keystore + StrongBox developer docs
- NIST SP 800-57 Part 1 Rev. 5
- RFC 9420 (MLS) — for forward secrecy preservation
- Bellare-Hoang-Keelveedhi 2015 — "Cryptography from Compromised Randomness" (hedged inherited from round 3)
- USENIX 2009 Halderman — "Lest We Remember: Cold-Boot Attacks"
