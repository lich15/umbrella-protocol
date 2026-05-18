# PhD-B Full Sweep Audit — Pass 4 Supplemental (call/ICE + FFI handles + WebAuthn + HTTP/2 + lifecycle + attestation/unwrap_sealing)

**Date:** 2026-05-18
**Session:** PhD-B full sweep, pass #4 supplemental (extends Pass 4 main report with additional file coverage)
**Scope additions over Pass 4 main:**
- `crates/umbrella-client/src/call/session.rs` (422 LoC)
- `crates/umbrella-client/src/call/ice_agent.rs` (284 LoC)
- `crates/umbrella-client/src/transport/http2_client.rs` (635 LoC)
- `crates/umbrella-client/src/lifecycle.rs` (329 LoC)
- `crates/umbrella-client/src/attestation/unwrap_sealing.rs` (253 LoC)
- `crates/umbrella-platform-verifier/src/web.rs` (398 LoC) — WebAuthn verifier
- `crates/umbrella-ffi/src/export/{secret_chat,cloud_chat,call}.rs` (~250 LoC total)
**Predecessors:**
- `docs/audits/phd-b-full-sweep-pass4-2026-05-18.md` (main Pass 4 report)
- `docs/audits/phd-b-full-sweep-pass3-2026-05-18.md` + Pass 2/1 chain
**Auditor:** Claude Opus 4.7 (PhD-B level continuation)
**Status:** **5 NEW PASS+ exemplars + 1 confirmation of F-CLIENT-FACADE-1 boundary**. No new severity findings; Pass 4 main report finding totals stand.

---

## Why supplemental?

Pass 4 main report committed with ~22K LoC coverage (umbrella-client core + facade + keystore subset + FFI export/{client,onboarding}.rs + platform-verifier {types,apple,android}.rs + server-blind-postman boundary check). Pass 4 supplemental closes remaining Pass 4 scope files identified in Pass 4 handoff as priority-3:

- Call session + ICE agent — SPEC-06 §3 no-P2P compliance gate
- Production HTTP/2 transport configuration
- Round-6 lifecycle (wipe-on-background / wipe-on-lock / wipe-on-debugger)
- async attestation sealing
- WebAuthn platform verifier (3rd platform path)
- FFI handles for chat facades + call session

All five new findings are **PASS+ exemplars** — no severity escalation, no new HIGH/CRITICAL, no carry-over re-opens. Pass 4 main report severity table stands unchanged.

---

## NEW PASS+ exemplars — Pass 4 supplemental

### F-CALLSESSION-1 PASS+ — SPEC-06 §3 no-P2P compliance gate two-layer enforcement

**Files:**
- `crates/umbrella-client/src/call/session.rs` (422 LoC + 7 tests)
- `crates/umbrella-client/src/call/ice_agent.rs` (284 LoC + 5 tests)

**Two-layer enforcement:**

1. **Layer 1 (`ModeEnforcement::apply` strips DirectP2P from CallPolicy):** `CallSession::start_with_enforcement` calls `enforcement.apply(user_policy)` → `effective_policy`. For `ModeEnforcement::SecretMode`, `effective_policy.allow_p2p_global` is forced to `false` + `default_routing = RoutingMode::SingleRelay` even if user set `allow_p2p_global = true`.

2. **Layer 2 (`IceAgent::new_no_p2p` builds webrtc-ice Agent with `candidate_types = [Relay]`):** `AgentConfig.candidate_types = vec![CandidateType::Relay]` (line 151) restricts webrtc-ice at the **gathering layer** — webrtc-ice **never asks OS for Host or ServerReflexive candidates**. Direct P2P is **physically impossible**, not a runtime check.

**Adversarial test exemplar:**

```rust
#[tokio::test]
async fn secret_mode_always_uses_no_p2p_agent() {
    let policy = CallPolicy {
        default_routing: RoutingMode::DirectP2P,
        allow_p2p_global: true, // user asked for P2P — ignored.
        ..Default::default()
    };
    let session = start(ModeEnforcement::SecretMode, policy).await;
    assert!(session.ice_agent().is_no_p2p());
}
```

Adversary's user explicitly sets `allow_p2p_global = true` + `default_routing = DirectP2P`; SecretMode override **forces** no-P2P at both layers. Real-vs-paperwork verdict: adversary state-modeled (user demanding P2P), measurement explicit (`is_no_p2p()` returns true), outcome quantified (ICE candidate list excludes Host/ServerReflexive at gathering time).

**TurnConfig Debug** redacts password (line 60-67); test `turn_config_debug_redacts_password` verifies «turn-password-material» does not appear in `format!("{turn:?}")`.

**Real-vs-paperwork verdict:** PhD-B A+ grade. Defense-in-depth via two independent layers, both adversarially tested.

### F-HTTP2-1 PASS+ — Production HTTP/2 transport with TLS 1.3 + comprehensive forbidden-host blocklist

**File:** `crates/umbrella-client/src/transport/http2_client.rs` (635 LoC + 12 tests)

**Protocol-level defenses:**

- **TLS 1.3 only** — `tls_version_min(tls::Version::TLS_1_3)` (line 336) + `with_protocol_versions(&[&rustls::version::TLS13])` (line 380). Rejects TLS 1.2 / 1.1 downgrades.
- **HTTP/2 prior knowledge** — `http2_prior_knowledge()` (line 345). No ALPN negotiation, no protocol downgrade attacks.
- **rustls** stack (not OpenSSL).
- **https_only(true)** — no plaintext HTTP allowed.
- **HTTP/2 keep-alive PING every 30s** + 10s pong timeout — defends mobile NAT stale connections.
- **TCP_NODELAY** — low latency for short-header MLS/SFrame frames.

**`is_forbidden_production_host` blocklist (lines 238-295):**

- DNS test names: `localhost`, `*.localhost`, `*.local`, `*.test`, `*.example`, `*.example.com`, `*.example.net`, `*.example.org`, `*.invalid`, `*.example.invalid`
- IPv4 reserved: loopback (127.0.0.0/8), private (RFC 1918), link-local (169.254.0.0/16), broadcast (255.255.255.255), CGNAT (100.64.0.0/10), TEST-NET-1 (192.0.2.0/24), TEST-NET-2 (198.51.100.0/24), TEST-NET-3 (203.0.113.0/24)
- IPv6 reserved: loopback (::1), unique-local (fc00::/7), link-local (fe80::/10), documentation prefix (2001:0db8::/32)
- **IPv4-mapped IPv6 bypass defense** (`mapped_ipv4_from_v6`, line 297-307): `::ffff:127.0.0.1` / `::ffff:10.0.0.1` / `::ffff:192.0.2.10` all rejected. Prevents `localhost` smuggled via IPv4-mapped IPv6 notation.

**12 adversarial tests** including:
- `production_transport_rejects_http_url` — non-HTTPS scheme rejected.
- `production_transport_rejects_test_hosts` — `https://localhost` rejected.
- `production_transport_rejects_reserved_dns_test_names` — 6 reserved-name examples (umbrella.example, .test, .local, example.com, example.net, example.org).
- `production_transport_rejects_ip_literal_hosts` — `https://192.0.2.10` (TEST-NET-1) rejected.
- `production_transport_rejects_link_local_and_cgnat_hosts` — `https://169.254.169.254` (AWS metadata!) + `https://100.64.0.10` (CGNAT) rejected.
- `production_transport_rejects_ipv6_local_hosts` — `https://[::1]` + `https://[fd00::1]` + `https://[fe80::1]` rejected.
- `production_transport_rejects_ipv4_mapped_ipv6_forbidden_hosts` — **bypass defense test** — `https://[::ffff:127.0.0.1]` + 3 others rejected via IPv4-mapped IPv6 mapping detection.
- `production_transport_rejects_wrong_sealed_server_count` — exactly 5 required.
- `production_pin_map_rejects_conflicting_pins_for_same_host` — pin conflict rejected.

**Critical observation:** `build_production_http2_client(config, &production)` (line 369) is **fully functional** — builds real TLS 1.3 + SPKI pinning + adversarially-validated production config. However, `ClientCore::new_with_http2` (core.rs:483-489) is still fail-closed (returns `Err` always) — the **glue between ClientCore and build_production_http2_client is not yet wired** (Block 7.4 milestone).

**Real-vs-paperwork verdict:** PhD-B A+ grade. Even AWS instance metadata endpoint (169.254.169.254) explicitly blocked — defense against SSRF / metadata exfiltration. IPv4-mapped IPv6 bypass defense shows adversarial thinking.

### F-LIFECYCLE-1 PASS+ — Round-6 wipe-on-background / wipe-on-lock / wipe-on-debugger lifecycle

**File:** `crates/umbrella-client/src/lifecycle.rs` (329 LoC + 7 tests)

**Round-6 design §«Stage 2 — Client backend rewiring» Component 5 implementation:**

| Event | Action |
|-------|--------|
| App → Background | 2-min timer → wipe device_key + master_key |
| App → Inactive | Immediate wipe of session keys |
| Screen lock | Immediate full wipe of all session secrets |
| Debugger / jailbreak / root | Emergency wipe + close app |
| Heartbeat tick (active foreground) | Update last_heartbeat; check pending wipe |

**`SessionState::on_event(event, now, background_grace)`** dispatches to per-event handler. `wipe()` is idempotent (line 73-80) — releases `Option<UnlockSession>` which triggers `MlockedSecret` Drop chain (zeroize-on-drop).

**`debugger_detected()` (lines 145-170)** best-effort detection:
- macOS: `MallocStackLogging` env (set by Xcode Instruments) + `DYLD_INSERT_LIBRARIES` (library injection)
- Linux: `/proc/self/status` `TracerPid:` line parse + check non-zero

**Honest disclosure (lines 142-144):**
> **Note**: this is best-effort, not a security guarantee. A sophisticated adversary with kernel access can bypass. Round-6 design accepts this: debug-detect is one layer of defense-in-depth, not the only one.

**7 tests** including adversarial:
- `screen_lock_immediately_wipes` — immediate wipe path.
- `background_2min_timer_wipes_after_grace` — 119s tick keeps live, 121s tick wipes.
- `foreground_cancels_pending_wipe` — Background then Foreground cancels timer; 200s later tick still live.
- `debugger_event_emergency_wipes` — Debugger event triggers immediate wipe.
- `wipe_is_idempotent` — double-wipe safe.

**Reduced effectiveness due to F-FFI-2 (carry-over from Pass 4 main):** Lifecycle wipe targets `UnlockSession.device_key + master_key` (`MlockedSecret`). But **F-FFI-2 leak** exposes them as hex strings across FFI boundary in `OnboardingHandle::unlock_with_pin` — hex copies live in Swift/Kotlin native heap, NOT in Rust `SessionState`. Lifecycle wipe **does not zeroize the hex copies** because they don't go through `MlockedSecret`. F-FFI-2 closure is prerequisite for full lifecycle wipe effectiveness.

**Real-vs-paperwork verdict:** PhD-B A grade (would be A+ with F-FFI-2 closed). Honest disclosure of debugger-detect limitations; idempotent wipe; 7 adversarial tests.

### F-ATTEST-UNWRAP-1 PASS+ — async attestation sealing with honest tokio-runtime safety rationale

**File:** `crates/umbrella-client/src/attestation/unwrap_sealing.rs` (253 LoC + 3 tests)

**`seal_unwrap_request_with_async_attestation`** — async-aware bridge to sync `umbrella_backup::cloud_wrap::signed_request::seal_unwrap_request`. Documents reasoning:

> `tokio::task::block_in_place` + `runtime_handle.block_on` is unsafe:
> 1. Panics on single-threaded `tokio::runtime` (Postulate 14 forbids library panics).
> 2. Possible deadlock on nested runtime activations.
>
> Instead we provide a symmetric async version: obtaining the token is `await`, signing and wire assembly are sync.

**Algorithm:**
1. `provider.fresh_token(server_nonce).await` → `PlatformAttestation`
2. `canonical_signing_input(...)` (sync) — domain separator + wire version + fields + token
3. `signer(canonical_pre_image)` (sync) — Ed25519 64-byte signature
4. Return `SignedUnwrapRequest` ready for serialization + dispatch

**3 adversarial tests:**
- `seal_with_async_attestation_produces_verifiable_request` — end-to-end sign + `verify_signed_unwrap_request` round-trip.
- `seal_with_async_attestation_propagates_provider_error` — `AlwaysUnavailable` adversarial provider returns `ServiceUnavailable`; test verifies signer is **not called** when provider fails (`panic!("signer must not be called when provider fails")`).
- `seal_with_async_attestation_propagates_signer_error` — signer returns `ClientError::Platform("enclave unavailable")`; test verifies error propagates unchanged.

**Real-vs-paperwork verdict:** PhD-B A+ grade. Honest disclosure of unsafe tokio bridge patterns; defensive test that signer not called on provider failure (prevents partial leak via incomplete request).

### F-WEBAUTHN-1 PASS+ — Fully-implemented WebAuthn verifier (3rd platform path, unlike Apple/Android honest-fail-closed)

**File:** `crates/umbrella-platform-verifier/src/web.rs` (398 LoC + 7 tests)

**Implementation completeness contrast with Apple/Android (F-PLAT-VER-1 honest-fail-closed):** WebAuthn verifier is **fully implemented end-to-end** — it can actually verify a WebAuthn assertion. Unlike Apple App Attest / Android Play Integrity (which require platform-vendor root chains not present in this codebase), WebAuthn uses Ed25519 with parameters known at registration time, so full implementation fits inside this crate without external trust material.

**Verification pipeline (lines 64-145):**

1. `ctx.platform == PlatformKind::WebAuthn` check
2. `validate_token_size(ctx.token, MAX_PLATFORM_TOKEN_BYTES)` (4096 byte cap)
3. `ctx.registered_key.public_key == ctx.device_pubkey` (registered key continuity)
4. Parse `WebAuthnToken { client_data_json, authenticator_data, signature }` (Base64UrlUnpadded decoded)
5. `auth_data.len() >= 37` + `sig_bytes.len() == 64` shape checks
6. `client.kind == "webauthn.get"` (assertion type)
7. **Challenge binding** — `challenge.as_slice() == ctx.server_nonce` (`ServerNonceMismatch` on fail) — **replay defense**
8. **Origin binding** — `client.origin == format!("https://{}", ctx.app_or_site)` (`AppOrSiteMismatch` on fail)
9. **RP ID hash binding** — `auth_data[0..32] == SHA-256(app_or_site)` (RFC 8829 §6.1 Relying Party ID)
10. **User-present flag** — `flags & 0x01 != 0` (`InvalidTokenShape` if not present)
11. **Counter rollback defense** — `counter > registered.last_counter` (`CounterDidNotIncrease` on equal-or-rollback)
12. Ed25519 verify: `vk.verify(auth_data || SHA-256(client_data), sig)` (`SignatureFailed` on fail)
13. Return `PlatformVerifierOutput { new_counter: Some(counter) }` for server-side storage

**7 adversarial tests:**
- `webauthn_accepts_matching_site_challenge_signature_and_counter` — baseline accept
- `webauthn_rejects_context_device_key_not_registered_key` — adversary key substitution rejected (`DeviceKeyMismatch`)
- `webauthn_rejects_wrong_challenge` — replay defense via challenge mismatch (`ServerNonceMismatch`)
- `webauthn_rejects_wrong_site` — phishing defense via origin mismatch (`AppOrSiteMismatch`)
- `webauthn_rejects_bad_signature` — signature from different key rejected (`SignatureFailed`)
- `webauthn_rejects_counter_rollback` — counter rollback rejected (`CounterDidNotIncrease`)
- `webauthn_debug_redacts_assertion_material` — Debug redacts client_data_json + authenticator_data + signature + challenge + origin

**Real-vs-paperwork verdict:** PhD-B A+ grade. Full end-to-end verifier with 6 substantive adversarial defenses + 1 Debug redaction test. Adversary state explicitly constructed (key substitution, challenge mismatch, origin spoof, signature forge, counter rollback) — not silent passes.

### F-FFI-FACADE-1 PASS+ — uniffi handles enforce ADR-006 Variant C at FFI boundary

**Files:** `crates/umbrella-ffi/src/export/secret_chat.rs` (104 LoC) + `cloud_chat.rs` (97 LoC) + `call.rs` (145 LoC)

**Compile-time type-safe API split:**

- `SecretChatHandle` (secret_chat.rs:42-93) — `#[uniffi::export] impl` exposes: `send_text`, `fetch_inbox`, `add_participant`, `remove_participant`, `chat_id`. **Does NOT expose** `cloud_sync_history` or `add_bot` — physically not in the impl block. Comment at line 89-92:
  > ADR-006 Вариант C — следующих методов намеренно НЕТ:
  >   cloud_sync_history(...)  — Cloud-only.
  >   add_bot(...)             — Cloud-only.
  > Swift / Kotlin биндинги их физически не увидят.

- `CloudChatHandle` (cloud_chat.rs:32-86) — exposes the same shared methods PLUS `cloud_sync_history`. uniffi generates per-impl bindings, so Swift/Kotlin sees `CloudChatHandle::cloudSyncHistory` but no `SecretChatHandle::cloudSyncHistory`.

**`CallStateFfi` flat enum (call.rs:38-76)** — ABI-stable representation. `CallState::Terminated(CallTerminationReason::LocalHangup)` unfolds to `CallStateFfi::TerminatedLocalHangup` — flat enum without nested payloads. Rationale: uniffi 0.28+ does not support associated values on enum variants for Swift binding generation; flat enum preserves ABI stability across binding regenerations.

**`CallSessionHandle` (call.rs:106-144)** — Block 7.7 minimal surface (only `state` / `hangup` / `call_id_bytes`). Full lifecycle (FFI `start_call`, ICE/DTLS event callbacks) deferred to Block 7.10 milestone.

**No secrets cross FFI in these handles:** All methods route through `umbrella_client::{CloudChat,SecretChat,CallSession}` and return only `Vec<u8>` of public identifiers (MessageId, ChatId) or `MessageFfi` with public timestamp + sender + plaintext message text. **Unlike F-FFI-2 (`OnboardingHandle::unlock_with_pin`)**, these handles never expose session keys.

**Real-vs-paperwork verdict:** PhD-B A grade. Compile-time type-safe enforcement via uniffi proc-macro impl-block isolation; flat enum ABI stability; minimal-surface Block 7.7.

---

## F-CLIENT-FACADE-1 confirmation through FFI handle wiring

**F-CLIENT-FACADE-1 (Pass 4 main HIGH/HONEST GAP)** finding restated: all `umbrella_client::{CloudChat,SecretChat}` facade methods return Block 7.2 stubs (`Ok(MessageId([0u8; 16]))`, `Ok(Vec::new())`, `Ok(())`).

Pass 4 supplemental confirms via FFI handle reading: **FFI handles route 1:1 to facade methods.** `SecretChatHandle::send_text` → `self.inner.send_text(text).await` → `send_mls_text` stub → `Ok(MessageId([0u8; 16]))`. The FFI surface is **not exposing real cryptographic operations** — it correctly routes to facade, but the facade is Block 7.2 stub.

This is **consistent with the F-FFI-1 PASS+ pattern** from Pass 4 main: `production_bootstrap_unavailable()` fail-closed in `bootstrap()` / `bootstrap_pq()` / `bootstrap_classical()`. The full production wire-up plan:

- Block 7.2 (current): facade stubs + FFI handles route to stubs + bootstrap fail-closed
- Block 7.4 (planned): facade real impl + ClientCore::new_with_http2 wire-up to build_production_http2_client + Postman/Sealed-Server/KT transport instantiation
- Block 7.10 (planned): FFI start_call wire-up + ICE/DTLS event callbacks + MediaSource/MediaSink uniffi callback_interfaces

**F-CLIENT-FACADE-1 severity reaffirmed:** HIGH/HONEST GAP — documented transitional state with fail-closed production paths; ship-blocking for v1.0.0 but acceptable for staged rollout.

---

## Pass 4 supplemental severity tracking

| Finding | Severity | Crate / File | Status |
|---------|----------|--------------|--------|
| F-CALLSESSION-1 | PASS+ | umbrella-client/src/call/{session,ice_agent}.rs | Pass 4 supplemental exemplar |
| F-HTTP2-1 | PASS+ | umbrella-client/src/transport/http2_client.rs | Pass 4 supplemental exemplar |
| F-LIFECYCLE-1 | PASS+ | umbrella-client/src/lifecycle.rs | Pass 4 supplemental exemplar |
| F-ATTEST-UNWRAP-1 | PASS+ | umbrella-client/src/attestation/unwrap_sealing.rs | Pass 4 supplemental exemplar |
| F-WEBAUTHN-1 | PASS+ | umbrella-platform-verifier/src/web.rs | Pass 4 supplemental exemplar |
| F-FFI-FACADE-1 | PASS+ | umbrella-ffi/src/export/{secret_chat,cloud_chat,call}.rs | Pass 4 supplemental exemplar |

**Totals new in Pass 4 supplemental:** 6 PASS+ exemplars, 0 severity findings.

**Cumulative Pass 4 totals (main + supplemental):** 1 CRITICAL NEW + 2 HIGH/HONEST GAP NEW + 1 MEDIUM NEW + 3 carry-over + **12 PASS+ exemplars** = 19 distinct entries.

The Pass 4 supplemental reading dramatically increased PASS+ exemplar count (from 6 in Pass 4 main to 12 total). The umbrella-client crate's lower-layer primitives (call session, transport, lifecycle, attestation, FFI handle isolation) are at PhD-B A+ grade; the facade integration glue (chat_common::send_mls_text stub, ClientCore::new_with_http2 placeholder, OnboardingHandle::unlock_with_pin hex leak) is what gets the CRITICAL/HIGH severity hits.

---

## 6-question self-check application

Same as Pass 4 main: 5/6 fully passed + 1/6 (dudect) deferred Pass 5 cross-cutting.

Supplemental adds three significant adversarial test patterns to the catalogue:

- **F-HTTP2-1**: IPv4-mapped IPv6 bypass defense — `https://[::ffff:127.0.0.1]` rejected via mapped-IP detection. Adversary state: attempt to smuggle localhost via IPv4-mapped IPv6 notation. Measurement: explicit rejection. **Real attack pattern, not paperwork.**
- **F-CALLSESSION-1**: user asks for P2P + SecretMode overrides — adversary state: user explicit `allow_p2p_global = true`; outcome quantified: `is_no_p2p()` true regardless.
- **F-WEBAUTHN-1**: counter rollback rejection — `counter <= registered.last_counter` rejected; adversary state: replay of older authenticator counter; outcome: `CounterDidNotIncrease`.

---

## Pre-commit decisions

Pass 4 supplemental committed directly to `main` per `feedback_direct_to_main`. Findings are PASS+ exemplars — no code modifications, audit-only commit.

This supplemental commit **does not alter** Pass 4 main report's severity findings or carry-over status. F-FFI-2 + F-CLIENT-FACADE-1 + F-CLIENT-HW-1 + F-CLIENT-HW-2 stand as-found in main report.

---

## References

Same reference set as Pass 4 main report, plus:

- WebAuthn Authentication Assertion format (W3C Recommendation §5.2.2)
- RFC 8829 §6.1 (WebRTC Relying Party Identification)
- WebAuthn Level 2 (W3C) — counter rollback defense semantics
- RFC 1918 (IPv4 private address space)
- RFC 5735 (IPv4 special-use addresses — TEST-NET-1/2/3, link-local, CGNAT)
- RFC 4291 §2.5 (IPv6 IPv4-mapped notation `::ffff:0:0/96`)
- RFC 6890 (Special-Purpose Address Registries IPv4 + IPv6)
- AWS EC2 instance metadata service (169.254.169.254 — SSRF target reference)
- Round-6 design §«Stage 2 Component 5» (wipe-on-background lifecycle)
