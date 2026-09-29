//! Spike only. Links the unchanged C ABI (rust/ffi) into a wasm module and
//! adds the two exports a host needs to hand it bytes. No verification
//! logic lives here.
#![allow(clippy::missing_safety_doc)]

// Forces the ffi crate to link, so its #[no_mangle] aprv_* functions are
// exported from this cdylib.
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
