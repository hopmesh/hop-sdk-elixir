//! Generates the foreign-language bindings (Swift/Kotlin) for the `hop` crate.
//!
//! Usage (library mode, after building the cdylib):
//!   cargo run -p hop --features cli --bin uniffi-bindgen -- \
//!     generate --library target/debug/libhop.dylib \
//!     --language swift --out-dir target/bindings/swift

fn main() {
    uniffi::uniffi_bindgen_main()
}
