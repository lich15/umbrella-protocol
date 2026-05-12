//! `uniffi-bindgen-swift` CLI — generate Swift biding code из скомпилированного
//! static/dylib. Обёртка над [`uniffi::uniffi_bindgen_main`] (uniffi 0.28+ —
//! `cli` feature).
//!
//! Usage (через `build-xcframework.sh`):
//! ```text
//! cargo run -p umbrella-ffi-swift --bin uniffi-bindgen-swift --locked -- \
//!     generate \
//!     --library target/aarch64-apple-ios/release/libumbrella_ffi_swift.a \
//!     --language swift \
//!     --out-dir target/xcframework-build/Sources/UmbrellaFFI
//! ```
//!
//! `uniffi-bindgen-swift` CLI — generates Swift binding code from the
//! compiled static/dylib. Wraps [`uniffi::uniffi_bindgen_main`]
//! (uniffi 0.28+, `cli` feature).

fn main() {
    uniffi::uniffi_bindgen_main()
}
