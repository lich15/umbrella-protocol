//! Generated Protobuf types for the gateway `umx.pb.v1` subprotocol.
//!
//! The actual code is produced by `build.rs` (prost-build) from
//! `proto/ws.proto`, which is a verbatim client-side copy of
//! `rust_1mlrd/proto/umbrellax/gateway/v1/ws.proto`. Wire-format compatibility
//! is enforced by the consumer-driven contract tests in
//! `tests/transport_websocket_contract.rs`, which round-trip every envelope
//! shape against a `tokio-tungstenite`-driven mock gateway.
//!
//! `include!` of the prost output into this module places the generated types
//! under `crate::transport::proto_ws` (e.g.
//! `crate::transport::proto_ws::ClientEnvelope`), which keeps the public
//! `WebSocketTransport` API free of generated symbols leaking from the
//! per-crate `$OUT_DIR`.

include!(concat!(env!("OUT_DIR"), "/umbrellax.gateway.v1.rs"));
