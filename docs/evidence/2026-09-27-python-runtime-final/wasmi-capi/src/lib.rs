//! Spike only (2026-09-27, round 11): Wasmi 2.0.0's official WebAssembly C
//! API (wasm.h + wasmi.h, crate wasmi_c_api_impl) built as one shared
//! library, the same artifact upstream's CMake produces as libwasmi.so.
//! Nothing is added: the re-export links the crate so its #[no_mangle]
//! functions are exported.
pub use wasmi_c_api::*;
