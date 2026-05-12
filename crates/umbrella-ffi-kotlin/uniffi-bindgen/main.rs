//! `uniffi-bindgen-kotlin` CLI — generate Kotlin binding code из
//! скомпилированного `.so`. Обёртка над [`uniffi::uniffi_bindgen_main`]
//! (uniffi 0.28+ `cli` feature).
//!
//! Usage (через `build-aar.sh`):
//! ```text
//! cargo run -p umbrella-ffi-kotlin --bin uniffi-bindgen-kotlin --locked -- \
//!     generate \
//!     --library target/aarch64-linux-android/release/libumbrella_ffi_kotlin.so \
//!     --language kotlin \
//!     --out-dir target/aar-build/kotlin-bindings
//! ```
//!
//! `uniffi-bindgen-kotlin` CLI — generates Kotlin binding code from the
//! compiled `.so`. Wraps [`uniffi::uniffi_bindgen_main`] (uniffi 0.28+
//! `cli` feature).

fn main() {
    uniffi::uniffi_bindgen_main()
}
