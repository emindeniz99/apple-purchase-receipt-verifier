//! Spike only. Links the unchanged C ABI (rust/ffi) into a wasm module and
//! adds what a host needs: `aprv_alloc`/`aprv_dealloc` to hand it bytes and
//! `aprv_init` to install the host clock. No verification logic lives here.
#![allow(clippy::missing_safety_doc)]

// Forces the ffi crate to link, so its #[no_mangle] aprv_* functions are
// exported from this module.
extern crate apple_purchase_receipt_verifier_ffi;

use std::alloc::{alloc, dealloc, Layout};

fn layout(len: usize) -> Layout {
    Layout::from_size_align(len.max(1), 8).expect("allocation size")
}

/// Returns `len` bytes of guest memory, 8-byte aligned. Never null on success.
#[no_mangle]
pub extern "C" fn aprv_alloc(len: usize) -> *mut u8 {
    unsafe { alloc(layout(len)) }
}

/// Releases memory from `aprv_alloc`. `len` must be the value passed to it.
#[no_mangle]
pub unsafe extern "C" fn aprv_dealloc(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        dealloc(ptr, layout(len));
    }
}

#[cfg(all(feature = "clock-seam", target_arch = "wasm32", any(target_os = "unknown", aprv_host_clock)))]
mod host_clock {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[link(wasm_import_module = "aprv")]
    extern "C" {
        /// Host wall clock, milliseconds since the Unix epoch (Date.now()).
        fn clock_now_ms() -> f64;
    }

    pub fn now() -> SystemTime {
        // SAFETY: an import with no arguments and a plain f64 result.
        let ms = unsafe { clock_now_ms() };
        if ms.is_finite() && ms >= 0.0 {
            UNIX_EPOCH + Duration::from_millis(ms as u64)
        } else {
            // A host clock that is not a finite instant after 1970 judges
            // every chain at 1970-01-01, where no Apple chain is valid:
            // it fails closed, never open.
            UNIX_EPOCH
        }
    }
}

/// Installs the host clock (the core's `platform::install_clock`). Hosts
/// call it once after instantiation. A module built without the clock seam
/// exports it as a no-op, so every runner can call it unconditionally.
#[no_mangle]
pub extern "C" fn aprv_init() {
    #[cfg(all(feature = "clock-seam", target_arch = "wasm32", any(target_os = "unknown", aprv_host_clock)))]
    let _ = aprv::platform::install_clock(host_clock::now);
}
