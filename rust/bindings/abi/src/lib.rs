//! `aprv.wasm`: the canonical-ABI exports of the verifier
//! (docs/rust-core/ARCHITECTURE.md §4).
//!
//! wit-bindgen generates the four exports, `cabi_realloc` and the
//! post-return functions from `wit/aprv.wit`. The four bodies below read
//! their arguments, call `aprv-surface` and answer `aprv-wire`'s JSON. They
//! hold no parsing, no cryptography and no trust decision: that is the
//! core's, below the surface.
//!
//! **Traps.** Each is `core::arch::wasm32::unreachable()`, reached directly,
//! with no panic path and no message formatting:
//!
//! - a verify before a successful `init`, and an `init` after one;
//! - an `env` other than 0 (production) or 1 (sandbox);
//! - a `random-get` answer that is not exactly the length asked for;
//! - a `list<u8>` argument, or a `random-get` answer, whose range runs past
//!   the end of linear memory.
//!
//! The module is built with `panic = "abort"`, so a panic anywhere below
//! (none is expected: the core denies `unwrap`, `expect`, indexing and
//! `panic!`) ends the call in a trap too, never in a value.
//!
//! **What the module takes from its host.** One import, `random-get`, for
//! OpenSSL's EC blinding and random generator. `wasi-none.c`, linked into
//! the module, defines every WASI function wasi-libc would otherwise
//! import: `random_get` forwards to [`random_source`], which asks the host
//! through `random-get`; `clock_time_get` answers the `now-ms` of the call
//! in progress (0 during `init`); every other one traps. This side hands
//! both over through two C setters, so no Rust symbol has to be visible to
//! the C file and the module exports nothing but the interface
//! (the round-13 stand-in exported two such symbols).
//!
//! **State.** One instance serves one call at a time (a hand-rolled host
//! reads the return area of the call it made before the next one starts),
//! so the state is a `thread_local`, the only thread there is.

#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

/// wit-bindgen's glue for `wit/aprv.wit`: the export trait, the `random-get`
/// import, `cabi_realloc` and the post-return functions.
#[allow(missing_docs, clippy::pedantic)]
mod bindings {
    wit_bindgen::generate!({ path: "wit", world: "aprv" });
}

use aprv_surface::{Environment, Verifier};
use bindings::exports::aprv::verifier::verify::Guest;
use std::cell::RefCell;

/// Stops the call: a guest trap, which every host reports as one and
/// after which it discards the instance.
#[cold]
fn trap() -> ! {
    #[cfg(target_arch = "wasm32")]
    {
        core::arch::wasm32::unreachable()
    }
    // Only aprv.wasm runs these bodies; a native build (the workspace's
    // tests and lints) compiles them and never calls them.
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::process::abort()
    }
}

/// Traps unless `bytes` lies inside linear memory. The canonical ABI has
/// the host place each `list<u8>` it lowers, and wit-bindgen builds the
/// `Vec` from that range without looking at it; a range past the end of
/// memory would otherwise be answered on its length alone and then freed
/// by the allocator, which corrupts the heap. Checked before anything
/// reads the bytes or drops the `Vec`. A range inside memory that
/// `cabi_realloc` never returned is not caught (rust/bindings/abi/README.md).
fn in_memory(bytes: &[u8]) {
    #[cfg(target_arch = "wasm32")]
    {
        let start = u64::try_from(bytes.as_ptr().addr()).unwrap_or(u64::MAX);
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let pages = u64::try_from(core::arch::wasm32::memory_size(0)).unwrap_or(0);
        if start.saturating_add(length) > pages.saturating_mul(65_536) {
            trap();
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = bytes;
}

thread_local! {
    /// The verifier `init` made, or `None` before a successful `init`.
    static VERIFIER: RefCell<Option<Verifier>> = const { RefCell::new(None) };
}

/// The randomness `wasi-none.c`'s `random_get` forwards to: it asks the host
/// through the one import. An answer that is not exactly `len` bytes traps:
/// OpenSSL would otherwise go on with bytes it did not get.
///
/// # Safety
/// `buf` must be writable for `len` bytes. wasi-libc's `random_get`
/// contract gives exactly that, and nothing else calls this.
unsafe extern "C" fn random_source(buf: *mut u8, len: usize) -> i32 {
    let Ok(wanted) = u32::try_from(len) else {
        trap()
    };
    let bytes = bindings::aprv::verifier::host::random_get(wanted);
    in_memory(&bytes);
    if bytes.len() != len {
        trap();
    }
    // SAFETY: the caller hands a buffer writable for `len` bytes, and
    // `bytes` holds exactly `len`; a fresh Vec never overlaps it.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, len) };
    0
}

/// The two setters `wasi-none.c` defines. Only aprv.wasm links that file.
#[cfg(target_arch = "wasm32")]
mod wasi_none {
    extern "C" {
        pub fn aprv_wasi_set_now_ms(ms: u64);
        pub fn aprv_wasi_set_random_source(source: unsafe extern "C" fn(*mut u8, usize) -> i32);
    }
}

/// The instant `clock_time_get` answers until the next call.
fn set_c_clock(now_ms: u64) {
    #[cfg(target_arch = "wasm32")]
    // SAFETY: a plain store into a C static; one call runs at a time.
    unsafe {
        wasi_none::aprv_wasi_set_now_ms(now_ms);
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = now_ms;
}

/// Where `random_get` forwards from now on.
fn set_c_random_source() {
    #[cfg(target_arch = "wasm32")]
    // SAFETY: a plain store of a function pointer into a C static; the
    // function lives as long as the module.
    unsafe {
        wasi_none::aprv_wasi_set_random_source(random_source);
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = random_source;
}

/// Runs `call` with the verifier `init` made, and with `now_ms` as the
/// instant the C side's clock answers meanwhile. Before a successful `init`
/// it traps.
fn with_verifier(now_ms: u64, call: impl FnOnce(&Verifier) -> String) -> String {
    VERIFIER.with(|slot| {
        let slot = slot.borrow();
        let Some(verifier) = slot.as_ref() else {
            trap()
        };
        set_c_clock(now_ms);
        let answer = call(verifier);
        set_c_clock(0);
        answer
    })
}

struct Aprv;

impl Guest for Aprv {
    fn init(config_json: Vec<u8>) -> String {
        in_memory(&config_json);
        VERIFIER.with(|slot| {
            if slot.borrow().is_some() {
                trap();
            }
            set_c_random_source();
            set_c_clock(0);
            let made = aprv_wire::read_init_config(&config_json)
                .and_then(|roots| Verifier::new(&roots).map_err(|error| error.message));
            let answer = aprv_wire::init_result(&made.as_ref().map(|_| ()).map_err(Clone::clone));
            if let Ok(verifier) = made {
                *slot.borrow_mut() = Some(verifier);
            }
            answer
        })
    }

    fn verify_receipt(now_ms: u64, receipt_base64: Vec<u8>) -> String {
        in_memory(&receipt_base64);
        with_verifier(now_ms, |verifier| {
            let result = aprv_surface::now_ms_from_u64(now_ms)
                .and_then(|now| verifier.verify_receipt(&receipt_base64, now));
            aprv_wire::verify_receipt_result(&result)
        })
    }

    fn verify_signed_data(now_ms: u64, jws: Vec<u8>) -> String {
        in_memory(&jws);
        with_verifier(now_ms, |verifier| {
            let result = aprv_surface::now_ms_from_u64(now_ms)
                .and_then(|now| verifier.verify_signed_data(&jws, now));
            aprv_wire::verify_signed_data_result(&result)
        })
    }

    fn verify_receipt_endpoint(env: u32, now_ms: u64, request_json: Vec<u8>) -> String {
        in_memory(&request_json);
        // Matched before anything else: jco and wasmtime-py do not range-check
        // a u32, and a value that names no environment is a caller's bug.
        let environment = match env {
            0 => Environment::Production,
            1 => Environment::Sandbox,
            _ => trap(),
        };
        with_verifier(now_ms, |verifier| {
            match aprv_surface::now_ms_from_u64(now_ms) {
                Ok(now) => verifier.verify_receipt_endpoint(environment, &request_json, now),
                Err(_) => aprv_surface::endpoint_internal_error(),
            }
        })
    }
}

bindings::export!(Aprv with_types_in bindings);
