//! The OpenSSL adapter under `apple-purchase-receipt-verifier`
//! (docs/rust-core/DECISIONS.md R21).
//!
//! OpenSSL parses the attacker's ASN.1, CMS and X.509 and does the
//! signature arithmetic; the core above this crate keeps Apple's policy:
//! which roots, which marker OIDs, which instant, which reason. This crate
//! answers narrow questions ("is this one certificate", "does this
//! `SignerInfo` verify under this certificate", "which problems does a path
//! from this certificate to these anchors have at this second") and never
//! decides a verdict. It knows nothing about JSON, the C ABI or Wasm.
//!
//! Rules this crate keeps:
//!
//! - **No ambient OpenSSL state.** [`init`] runs
//!   `OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG)` before any other
//!   OpenSSL call, which claims OpenSSL's one-time config initialisation,
//!   so neither `OPENSSL_CONF` nor the build's `openssl.cnf` is ever read.
//!   No store is built from anything but the caller's anchors:
//!   `X509_STORE_set_default_paths` and lookup methods are never called, so
//!   `SSL_CERT_FILE`, `SSL_CERT_DIR` and the default certificate paths are
//!   never consulted. `tests/isolation.rs` plants all of them and checks.
//! - **No raw pointer leaves the crate.** Callers get owned values
//!   ([`Certificate`], [`SignedData`]) or plain Rust data.
//! - **Every raw call sits in a small safe function** with a `// SAFETY:`
//!   comment; rust-openssl's safe wrappers are used wherever they exist.
//! - **Every failure drains the thread's OpenSSL error queue**, so one
//!   call's errors never leak into the next.
//! - **Nothing panics.** Every fallible step is a `None`, a `false` or an
//!   error value.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::mem_forget
)]

mod certificate;
mod cms;
mod envelope;
mod item;
#[cfg(feature = "test-seams")]
mod keys;
mod path;
pub mod payload;
mod signature;
mod sys;
mod walk;

pub use certificate::Certificate;
#[cfg(feature = "test-seams")]
pub use cms::full_decodes_during;
pub use cms::{CmsError, EnvelopeLimits, SignedData};
#[cfg(feature = "test-seams")]
pub use keys::keys_used_during;
pub use path::{verify_path, PathOutcome, PathProblem, PathProblemKind};
pub use signature::{sha256, verify_es256};
pub use walk::Budget;

use std::sync::Once;

static INIT: Once = Once::new();

/// Initialises OpenSSL without its configuration file. Idempotent; every
/// public entry point of this crate calls it before any other OpenSSL call.
pub fn init() {
    INIT.call_once(|| {
        // SAFETY: OPENSSL_init_crypto is the documented initialisation
        // call; a null settings pointer is allowed. Passing
        // NO_LOAD_CONFIG first runs OpenSSL's config RUN_ONCE in its
        // "no config" form, so a later implicit initialisation (rust-openssl
        // calls OPENSSL_init_ssl, which asks for LOAD_CONFIG) finds it done
        // and cannot load openssl.cnf or OPENSSL_CONF.
        unsafe {
            sys::OPENSSL_init_crypto(sys::OPENSSL_INIT_NO_LOAD_CONFIG, std::ptr::null());
        }
        openssl_sys::init();
    });
}

/// Empties the calling thread's OpenSSL error queue.
fn drain_errors() {
    let _ = openssl::error::ErrorStack::get();
}

/// The linked OpenSSL, as it reports itself (`OpenSSL 4.0.2 ...`).
#[must_use]
pub fn library_version() -> &'static str {
    init();
    openssl::version::version()
}

/// Reads one DER or BER value from the start of `der` with `d2i`.
/// Returns the new value and whether it took every byte of `der`; the
/// caller takes ownership of the value first and refuses it second, so a
/// value with bytes left over is still freed.
///
/// `d2i` gets a cursor over `der` and its length; it is the closure that
/// holds the `unsafe` call to an OpenSSL `d2i_*`-style decoder, which reads
/// at most that many bytes, advances the cursor past what it read, and
/// returns a newly allocated value the caller owns, or null.
fn d2i_whole<T>(
    der: &[u8],
    d2i: impl FnOnce(*mut *const u8, libc::c_long) -> *mut T,
) -> Option<(*mut T, bool)> {
    let len = libc::c_long::try_from(der.len()).ok()?;
    let start = der.as_ptr();
    let mut cursor = start;
    let raw = d2i(&raw mut cursor, len);
    if raw.is_null() {
        drain_errors();
        return None;
    }
    // Both pointers are into `der`, and the decoder only moves the cursor
    // forward within it.
    let consumed = (cursor as usize).wrapping_sub(start as usize);
    Some((raw, consumed == der.len()))
}
