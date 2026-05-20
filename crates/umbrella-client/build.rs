//! F-CLIENT-FACADE-1 closure session 1 (2026-05-19): compile the gateway
//! WebSocket Protobuf wire format (`proto/ws.proto`) into Rust via prost-build.
//!
//! The generated module appears as `$OUT_DIR/umbrellax.gateway.v1.rs` and is
//! `include!`'d from `src/transport/proto_ws.rs`. Keeping the include hand-
//! written (rather than using prost-build's `compile_protos` magic file paths)
//! makes the dependency from source code to generated code explicit and
//! survives Cargo's per-crate `OUT_DIR` isolation.
//!
//! Source-of-truth note: `proto/ws.proto` is a verbatim client-side copy of
//! `rust_1mlrd/proto/umbrellax/gateway/v1/ws.proto`. Backend updates require
//! manual lockstep update of this file; see
//! `docs/integration/gateway-svc-contract.md §4.1`.

fn main() {
    let proto_root = "proto";
    let proto_file = "proto/ws.proto";

    println!("cargo:rerun-if-changed={proto_file}");
    println!("cargo:rerun-if-changed={proto_root}");

    // Указываем prost-build путь к vendored бинарю `protoc` через
    // `protoc-bin-vendored`. Это устраняет зависимость от системного
    // protoc в CI runner'ах (GitHub Actions macOS / Ubuntu без
    // preinstalled protobuf-compiler). Пользовательский PROTOC env
    // имеет приоритет, если задан явно.
    // Point prost-build at the vendored `protoc` binary via
    // `protoc-bin-vendored`. Removes the system-`protoc` dependency
    // in CI runners (GitHub Actions macOS / Ubuntu without
    // preinstalled protobuf-compiler). A user-supplied PROTOC env
    // takes priority if explicitly set.
    if std::env::var_os("PROTOC").is_none() {
        let protoc_path = protoc_bin_vendored::protoc_bin_path()
            .expect("protoc-bin-vendored: no prebuilt protoc для текущей платформы");
        // build script запускается single-threaded до основной
        // компиляции — set_var здесь безопасен и канонически
        // используется prost-build users.
        // build scripts run single-threaded before the main compile;
        // set_var here is safe and is the canonical way to point
        // prost-build at a custom tool path.
        std::env::set_var("PROTOC", protoc_path);
    }

    let mut cfg = prost_build::Config::new();
    cfg.compile_protos(&[proto_file], &[proto_root])
        .expect("prost-build: failed to compile proto/ws.proto");
}
