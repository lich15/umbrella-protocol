# Gateway-svc Integration Contract

**Status:** Draft v0.0.1 (2026-05-19, sourced via read-only
inspection of `rust_1mlrd` HEAD).
**Source repositories:** `Umbrella Protocol` (client side, this
repo) ↔ `rust_1mlrd` (backend, separate repo).
**Audience:** authors of `crates/umbrella-client/src/transport/`
HTTP transports + F-CLIENT-FACADE-1 closure session leads.
**Reading direction:** read-only from `rust_1mlrd`; this contract
extracts what the client side needs to know to interoperate. No
backend changes proposed in this document.

---

## 1. Topology

The backend runs as a Kubernetes cluster with the following
gateway shape (per `rust_1mlrd/docs/adr/2026-05-09-36-gateway-edge-only-deployment.md`):

- **3 cloud edge nodes** host all `gateway-svc-edge` Pods.
  Production names: `ux-edge-v2-eu-nbg1`,
  `ux-edge-v2-eu-hel1c`, `ux-edge-v2-us-hil`.
- **3 dedicated nodes** host databases + control plane only;
  they do NOT accept client traffic.
- **NodePort Service** named `gateway-svc` owns ports 31535
  (TCP) and 30292 (UDP). Selector targets `gateway-svc-edge`
  Pods exclusively.
- **Helm chart**: shared chart at
  `rust_1mlrd/crates/gateway-svc/deploy/helm-values-edge.yaml`.

Production-side topology is documented in
`rust_1mlrd/docs/adr/2026-04-17-startup-infrastructure.md` (6
nodes: 3 dedicated + 3 cloud edge across DE/FI/US-East/US-West).

## 2. Transports

The gateway exposes two transport modes in parallel:

### 2.1 QUIC (preferred, primary)

- **Protocol family**: HTTP/3 over QUIC over UDP.
- **Library**: `quiche` 0.x (Cloudflare).
- **ALPN identifier**: `umx-quic-v1` (literal bytes
  `b"umx-quic-v1"`).
- **Listen port**: UDP 443 in production
  (`config.rs:default_quic_listen_addr = 0.0.0.0:443`); via
  NodePort 30292 in cluster-internal addressing.
- **Connection-ID length**: 20 bytes (`SERVER_CONN_ID_LEN =
  quiche::MAX_CONN_ID_LEN`).
- **UDP datagram size**: 1500 bytes
  (`QUIC_UDP_BUFFER_BYTES = 1500`, matches Ethernet MTU).
- **Wire codec**: configurable via
  `GATEWAY_QUIC_WIRE_PROTOCOL` env var; defaults to Protobuf
  (`umx.pb.v1` shape) per session 138.

### 2.2 WebSocket (fallback)

- **Protocol family**: WebSocket 13 over TLS 1.3 over TCP, or
  cleartext WebSocket over kTLS (kernel TLS, RFC 8446).
- **Library**: WebSocket frame handling lives in
  `rust_1mlrd/crates/gateway-svc/src/ws/`; kTLS handshake in
  `transport/ktls.rs`.
- **Subprotocol identifiers**: client MUST request via
  `Sec-WebSocket-Protocol` header:
  - `umx.pb.v1` (preferred, Protobuf wire format)
  - `umx.v1` (fallback, MessagePack wire format)
  The first supported entry from the client's
  comma-separated list is selected. Unknown subprotocols are
  rejected with HTTP 400 + an error message that names
  `umx.v1 or umx.pb.v1`.
- **Listen port**: TCP 8443 in production
  (`config.rs:listen_addr`); via NodePort 31535 in
  cluster-internal addressing.

### 2.3 Recommended client behaviour

The client SHOULD attempt QUIC first, falling back to WebSocket
when QUIC is blocked (corporate firewalls, certain mobile
carriers in restrictive jurisdictions). Suggested fallback
timeout: 500 ms. If QUIC handshake does not complete within
that window, open a WebSocket connection in parallel.

## 3. TLS

- **TLS version**: 1.3 only (no 1.2 negotiation).
- **Cipher suites**: ChaCha20-Poly1305 + AES-256-GCM
  (per Umbrella postulate; matches gateway-svc rustls config).
- **0-RTT resumption**: supported on QUIC.
- **Certificate verification**: standard system trust store
  with **SPKI pinning** for the production endpoint. The
  client crate's existing `transport::http2_client` module
  already implements SPKI-pinned `reqwest` + `rustls`
  builders; the QUIC and WebSocket transports SHOULD reuse the
  same SPKI-pin set.

## 4. Wire format (Protobuf, `umx.pb.v1`)

The canonical Protobuf definitions are at
`rust_1mlrd/proto/umbrellax/`. The four `.proto` files visible
to the client side:

- `umbrellax/common/v1/types.proto` — shared types (`UserId`,
  `CellId`, etc.).
- `umbrellax/auth/v1/auth.proto` — `AuthService` (register,
  login, refresh, validate).
- `umbrellax/identity/v1/identity.proto` — `IdentityService`
  (get profile, update username, search).
- `umbrellax/gateway/v1/ws.proto` — `ClientEnvelope` /
  `ServerEnvelope` for real-time WebSocket / QUIC streams.

### 4.1 Real-time envelope (`umbrellax.gateway.v1.ws.proto`)

The client sends `ClientEnvelope`; the gateway sends
`ServerEnvelope`. Both are serialised as Protobuf messages over
the chosen transport (one envelope per WebSocket frame or one
envelope per QUIC stream).

```protobuf
message ClientEnvelope {
  uint64 seq = 1;
  oneof payload {
    ClientPing           ping           = 10;
    PresenceUpdate       presence       = 11;
    SendMessageRequest   send_message   = 12;
    DeliveryProbe        delivery_probe = 13;
    ClientAuth           auth           = 14;
    ClientClose          close          = 15;
  }
}

message ServerEnvelope {
  uint64 seq = 1;
  oneof payload {
    ServerPong         pong           = 10;
    SendMessageAck     send_ack       = 11;
    DeliveryProbe      delivery_probe = 12;
    ErrorEnvelope      error          = 13;
    AuthOk             auth_ok        = 14;
  }
}
```

Message shapes (selected):

- `ClientAuth { string token; bytes device_id }` — JWT
  authentication; `token` is the Ed25519-issued access token
  from `AuthService.Login`; `device_id` identifies the device
  family slot per SPEC-11 §4.
- `SendMessageRequest { bytes to_user_id; bytes ciphertext }` —
  client-encrypted MLS/sealed-sender envelope; the gateway
  routes it to the recipient's inbox without decrypting.
- `SendMessageAck { string msg_id }` — server-issued message
  identifier (16 bytes formatted as hex).
- `ClientPing { uint64 client_ts_ms }` / `ServerPong { uint64
  client_ts_ms; uint64 server_ts_ms }` — RTT probe.
- `DeliveryProbe { bytes probe_id; uint64 sent_ts_ms }` —
  delivery liveness check.
- `ErrorEnvelope { string code }` — server-side rejection;
  `code` follows internal taxonomy (e.g. `"auth.expired"`,
  `"rate.exceeded"`, `"protocol.unknown"`).

### 4.2 Service-level RPCs (gRPC over TCP, internal)

The gateway exposes `AuthService` and `IdentityService` for
operations that do not fit the real-time envelope model:

`AuthService.Register(RegisterRequest) → RegisterResponse`:
- `public_key: bytes(32)` — Ed25519 verifying-key from
  client identity.
- `pow_nonce: uint64` — proof-of-work nonce (abuse
  resistance).
- `attestation_token: bytes` — Apple App Attest or Google
  Play Integrity token.
- Returns `(user_id, username, access_token, refresh_token)`.

`AuthService.Login(LoginRequest) → LoginResponse`:
- `public_key: bytes(32)`.
- `challenge: bytes` — server-issued nonce from a prior call.
- `challenge_signature: bytes` — Ed25519 signature over the
  challenge using the client's identity_sk (routed through
  `KeyStore::sign_with_identity`).
- Returns `(user_id, access_token, refresh_token)`.

`AuthService.RefreshToken(RefreshTokenRequest) →
RefreshTokenResponse` — token rotation (24 h access / 30 d
refresh).

`AuthService.ValidateToken(ValidateTokenRequest) →
ValidateTokenResponse` — inter-service validation; not
typically called from the client (handled at the gateway
boundary).

`IdentityService.GetProfile(GetProfileRequest) →
GetProfileResponse`:
- Query by `username` or `user_id`; returns the user's public
  profile (`public_key`, `cell_id`, `created_at`).

`IdentityService.UpdateUsername(UpdateUsernameRequest) →
UpdateUsernameResponse` — rate-limited to once per 30 days.

`IdentityService.SearchByUsername(SearchByUsernameRequest) →
SearchByUsernameResponse` — prefix search, max 20 results.

## 5. Authentication flow

The client authenticates once per session:

1. **Register** (first launch only): hold the Ed25519 identity
   key, perform proof-of-work, attach App Attest / Play
   Integrity token, call `AuthService.Register`. Receive
   `access_token` (JWT, 24 h TTL) + `refresh_token` (30 d).
2. **Login** (subsequent launches): receive a challenge nonce
   from the gateway (out-of-band protocol omitted here), sign
   it with `identity_sk` via `KeyStore::sign_with_identity`,
   call `AuthService.Login`. Receive `access_token` +
   `refresh_token`.
3. **Refresh**: when the access token approaches expiry, call
   `AuthService.RefreshToken` to rotate.
4. **WebSocket / QUIC connect**: open the transport with
   `Sec-WebSocket-Protocol: umx.pb.v1, umx.v1` (or ALPN
   `umx-quic-v1`). Once the transport is established, send
   `ClientEnvelope { auth: ClientAuth { token, device_id } }`
   as the first envelope. The gateway responds with
   `ServerEnvelope { auth_ok: AuthOk {} }` on success or
   `ErrorEnvelope { code: "auth.<reason>" }` on failure.

The client SHOULD route the Ed25519 signing operation through
`HwBackedKeyStore` when available (production hardware backing)
or `InMemoryKeyStore` (legacy/test). Both implement the
`umbrella_identity::KeyStore` trait; the choice is selected at
`ClientCore` construction time.

## 6. Endpoint discovery

The MVP 0 plan (`rust_1mlrd/docs/services/MVP0_SERVICES.md`)
describes an `endpoint-registry-svc` that distributes encrypted
IP lists of entry-proxy nodes to clients. For now, the client
crate SHOULD treat the endpoint set as a configuration input
(static list of edge gateway addresses with SPKI pins,
populated via native app bootstrap).

Future closure of F-CLIENT-FACADE-1 may include an explicit
`crates/umbrella-client/src/transport/endpoint_registry.rs`
module that consumes the registry payload; this is out of
scope for the initial transport implementation.

## 7. Anti-DPI / fallback behaviour

Per MVP 0 strategic priority (Russia / Kazakhstan / Iran / China
as primary market), the client transport stack will eventually
sit behind a multi-protocol obfuscation layer (GotaTun
WireGuard, AmneziaWG v2.0, Xray Reality-Vision, NaiveProxy,
Shadowsocks-2022, Hysteria 2, Trojan, Tor Snowflake,
WebTunnel). The QUIC + WebSocket transports documented here
operate INSIDE that tunnel — the gateway itself does not need
to know which tunnel the client used.

Initial F-CLIENT-FACADE-1 closure sessions focus on the
QUIC + WebSocket transports against a directly-reachable
gateway. Tunnel integration is a later milestone.

## 8. Versioning and evolution

- Wire-format identifiers (`umx-quic-v1`, `umx.pb.v1`,
  `umx.v1`) carry an explicit `v1` suffix. Breaking changes
  bump to `v2`; minor additions to the `oneof` fields in
  `ClientEnvelope` / `ServerEnvelope` use new field numbers
  (Protobuf-compatible) and stay on `v1`.
- The `umx.v1` MessagePack subprotocol is retained as a
  fallback for legacy clients but is NOT recommended for new
  implementations; client-side transports SHOULD prefer
  `umx.pb.v1`.
- The `*.proto` definitions in `rust_1mlrd/proto/umbrellax/`
  are the canonical source of truth. The client crate
  generates Rust bindings via `tonic-build` / `prost-build`
  (already used in `rust_1mlrd/crates/proto-gen` — same
  artifact should be re-used by the client side).

## 9. Mock server harness (planned)

The F-CLIENT-FACADE-1 closure will add a `wiremock`-driven mock
gateway at
`crates/umbrella-client/tests/mock_gateway/` simulating the
endpoints described above. Tests will exercise:

- Subprotocol negotiation (offer `umx.pb.v1, umx.v1`;
  verify gateway selects `umx.pb.v1`).
- TLS handshake with the same SPKI-pin set used by
  `transport::http2_client`.
- Authentication round-trip (`ClientAuth` → `AuthOk`).
- One full envelope round-trip (`SendMessageRequest` →
  `SendMessageAck`).
- Error envelope handling (`ErrorEnvelope { code }`).
- Reconnection / retry / backoff on transport failures.

The mock server is **client-side test infrastructure**; it does
NOT replace the real backend. It exists to make the client
crate buildable + testable in isolation. Real integration tests
against the running `rust_1mlrd` cluster are a separate
milestone with its own setup requirements (local
`docker-compose` from `rust_1mlrd/deploy/docker-compose-aux`
or a dev cluster).

## 10. Sources

All contract details in this document are extracted from
`rust_1mlrd` HEAD as of 2026-05-19 via read-only inspection.
No modifications to `rust_1mlrd` are proposed or required.

Key files inspected:

- `rust_1mlrd/proto/umbrellax/auth/v1/auth.proto`
- `rust_1mlrd/proto/umbrellax/identity/v1/identity.proto`
- `rust_1mlrd/proto/umbrellax/gateway/v1/ws.proto`
- `rust_1mlrd/crates/gateway-svc/src/quic/mod.rs`
  (`ALPN_UMX_QUIC_V1`)
- `rust_1mlrd/crates/gateway-svc/src/quic/listener.rs`
  (UDP listener + connection routing)
- `rust_1mlrd/crates/gateway-svc/src/quic/config.rs`
  (TLS 1.3 + ALPN + memory/DoS limits)
- `rust_1mlrd/crates/gateway-svc/src/ws/protocol.rs`
  (subprotocol negotiation)
- `rust_1mlrd/crates/gateway-svc/src/ws/accept.rs`
  (HTTP 101 upgrade handler)
- `rust_1mlrd/crates/gateway-svc/src/auth/jwt.rs`
  (JWT + JWKS validation)
- `rust_1mlrd/crates/gateway-svc/src/config.rs`
  (listen addresses + worker config)
- `rust_1mlrd/crates/gateway-svc/deploy/helm-values-edge.yaml`
  (production deployment shape)
- `rust_1mlrd/docs/adr/2026-04-17-startup-infrastructure.md`
  (6-node topology)
- `rust_1mlrd/docs/adr/2026-05-09-36-gateway-edge-only-deployment.md`
  (edge-only directive)
- `rust_1mlrd/docs/services/MVP0_SERVICES.md`
  (service catalogue + cell architecture)

If any of the above contract details drift between this
document and `rust_1mlrd` HEAD, the source repository is
authoritative — update this document to match.
