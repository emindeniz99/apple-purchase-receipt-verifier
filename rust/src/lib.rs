//! Offline verification of what Apple signs, against pinned Apple roots.
//!
//! The library answers one question: did Apple sign this data, under a
//! pinned Apple root? If so, it returns the data. Bundle id, environment,
//! product id, device binding, refunds and idempotency are the caller's
//! decisions, and no method takes a parameter for any of them.
//!
//! One [`Verifier`], three methods:
//!
//! - [`Verifier::verify_receipt`]: a legacy PKCS#7 app receipt, as the base64
//!   string a client sends, decoded into a [`ReceiptPayload`];
//! - [`Verifier::verify_signed_data`]: any Apple-signed JWS (transactions,
//!   renewal info, app transactions, Server Notifications V2), returned as
//!   the [`JsonPayload`] Apple signed;
//! - [`Verifier::verify_receipt_endpoint`]: the response body Apple's
//!   deprecated `verifyReceipt` endpoint would return, status codes included.
//!
//! ```no_run
//! use apple_purchase_receipt_verifier::{Config, Environment, Reason, Verifier};
//!
//! let verifier = Verifier::new(Config::defaults());
//! match verifier.verify_receipt("MIIT...") {
//!     Ok(receipt) => {
//!         // The caller's checks: bundle id, environment, product id.
//!         assert_eq!(receipt.bundle_id.as_deref(), Some("com.example.app"));
//!         let _ = Environment::from_receipt_type(receipt.receipt_type.as_deref());
//!     }
//!     Err(failure) if failure.reason() == Reason::UnreadablePayload => {
//!         // Apple signed it, but this library cannot read it: alert.
//!     }
//!     Err(failure) => eprintln!("rejected: {failure}"),
//! }
//! ```
//!
//! # What this crate will never do
//!
//! - **Read the operating system's trust store.** Anchors come only from the
//!   [`Config`], whose default is the three Apple roots embedded with
//!   `include_bytes!`.
//! - **Touch the network.** No OCSP, no CRL, no AIA fetch, no root download.
//! - **Judge a payload by its age.** How old a signed payload may be is the
//!   caller's decision, made on its signing date.
//! - **Return anything partial.** A failure returns a [`Failure`] and
//!   nothing else; a success returns only data that passed every check.
//! - **Log, meter or call back.** [`Reason`] is the whole observability
//!   surface, and a message never contains receipt bytes, claims or key
//!   material.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// The panic-free contract, mechanised. An early probe of this crate found a
// real out-of-bounds panic in a CMS walk by mutating a genuine
// receipt; `indexing_slicing` is the lint that would have caught it at
// compile time. These apply to the library crate only; the test crates
// index and unwrap freely.
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
#![doc(html_root_url = "https://docs.rs/apple-purchase-receipt-verifier")]

mod base64;
mod config;
mod datetime;
mod endpoint;
mod environment;
mod error;
mod json;
mod jws;
mod path;
mod receipt;
mod receipt_payload;
mod roots;
mod verifier;

pub use config::{Config, ConfigBuilder};
pub use endpoint::AppleStatus;
pub use environment::Environment;
pub use error::{ConfigError, Failure, Reason, UnknownReason};
pub use jws::JsonPayload;
pub use receipt_payload::{InAppPurchase, ReceiptPayload, UnknownAttributes};
pub use roots::TrustAnchor;
pub use verifier::Verifier;

/// This library's version, for startup logs.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Not part of the public API, and not covered by semver.
///
/// The internals this crate's own tests, fuzz targets and benchmark reach
/// directly: the date reader, the key-use seam, and the two base64
/// decoders the shared decodeBase64 cases call. The shared cases name them
/// as an internal hook; 0.7 exposes no decoder.
#[doc(hidden)]
pub mod __internal {
    /// Calendar arithmetic and Apple's date renderings.
    pub mod datetime {
        pub use crate::datetime::*;
    }

    /// Runs `body` and returns, beside its result, the
    /// `SubjectPublicKeyInfo` DER of every key the OpenSSL adapter used to
    /// check a signature on this thread meanwhile.
    pub fn keys_used_during<R>(body: impl FnOnce() -> R) -> (R, Vec<Vec<u8>>) {
        aprv_openssl::keys_used_during(body)
    }

    /// The linked OpenSSL, as it reports itself.
    #[must_use]
    pub fn openssl_version() -> &'static str {
        aprv_openssl::library_version()
    }

    /// Standard base64 with padding.
    #[must_use]
    pub fn base64_encode(bytes: &[u8]) -> String {
        crate::base64::encode(bytes)
    }

    /// Base64 or base64url, skipping every character outside both alphabets.
    #[must_use]
    pub fn base64_decode_lenient(text: &str) -> Vec<u8> {
        crate::base64::decode_lenient(text)
    }

    /// The `receipt-data` decoder. A refusal is `MALFORMED`.
    ///
    /// # Errors
    /// [`Failure`](crate::Failure) with [`Reason::Malformed`](crate::Reason::Malformed).
    pub fn decode_receipt_data(text: &str) -> Result<Vec<u8>, crate::Failure> {
        crate::base64::decode_receipt_base64(text).ok_or_else(|| {
            crate::Failure::new(crate::Reason::Malformed, "receipt is not valid base64")
        })
    }

    /// The `x5c` entry decoder. A refusal is `INVALID_CERTIFICATE`.
    ///
    /// # Errors
    /// [`Failure`](crate::Failure) with
    /// [`Reason::InvalidCertificate`](crate::Reason::InvalidCertificate).
    pub fn decode_x5c_entry(text: &str) -> Result<Vec<u8>, crate::Failure> {
        crate::jws::decode_x5c_entry(text)
    }
}
