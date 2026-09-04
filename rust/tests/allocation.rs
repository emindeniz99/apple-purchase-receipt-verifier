//! How much this library allocates to answer a question.
//!
//! This binary installs a counting global allocator, so it holds exactly one
//! test: any other test in the same binary would perturb the count.
//!
//! The bound is the Rust analogue of the other ports' memory tests, and the
//! thing it catches is an accidental `to_vec()` in the hot path — the kind of
//! change that is invisible in a verdict and turns a 79 KB receipt into
//! megabytes of copying.

mod common;

use apple_purchase_receipt_verifier::{apple_receipt_roots, ReceiptVerifier};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATED.fetch_add(new_size.saturating_sub(layout.size()), Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn measure<T>(body: impl FnOnce() -> T) -> (T, usize) {
    let before = ALLOCATED.load(Ordering::Relaxed);
    let value = body();
    (value, ALLOCATED.load(Ordering::Relaxed) - before)
}

#[test]
fn verification_allocates_a_bounded_multiple_of_the_input() {
    // Warm every lazily initialised thing first — the anchors are parsed
    // once behind a OnceLock, and that cost belongs to neither verification.
    let legacy = common::read_base64_fixture("public-receipts/receipt-sandbox-legacy.b64");
    let verifier = ReceiptVerifier::builder()
        .trusted_roots(apple_receipt_roots().iter().cloned())
        .bundle_id("com.nutcall.alert")
        .build()
        .unwrap();
    verifier.verify(&legacy).unwrap();

    // The largest genuine receipt in the corpus: 79 KB, 187 in-app
    // purchases, 208 attributes.
    let (receipt, bytes) = measure(|| verifier.verify(&legacy).unwrap());
    assert_eq!(receipt.in_app_purchases.len(), 187);
    // Measured: 2,149,060 bytes for a 79,104-byte receipt — 27 times the
    // input, which is what a tree parser costs on 208 attributes and 187
    // nested purchases. The ceiling is set just above it, so a regression
    // shows up as a failure rather than as a slow leak.
    let ceiling = legacy.len() * 32;
    assert!(
        bytes < ceiling,
        "verifying a {}-byte receipt allocated {bytes} bytes, over the {ceiling}-byte ceiling",
        legacy.len()
    );

    // And rejecting junk must cost far less than verifying something real:
    // a megabyte of zeros is refused by the reader, not decoded.
    let junk = vec![0u8; 1024 * 1024];
    let (_, junk_bytes) = measure(|| verifier.verify(&junk).unwrap_err());
    assert!(
        junk_bytes < 64 * 1024,
        "rejecting a megabyte of junk allocated {junk_bytes} bytes"
    );

    // Repeating a verification must not grow: nothing is cached per input.
    let (_, second) = measure(|| verifier.verify(&legacy).unwrap());
    assert!(
        second <= bytes + bytes / 8,
        "second verification allocated {second} against {bytes}"
    );
}
