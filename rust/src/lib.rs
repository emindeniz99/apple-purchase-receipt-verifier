//! Offline verification of Apple App Store purchases.
//!
//! Two things Apple signs, verified without calling Apple:
//!
//! - **`StoreKit` 2 / App Store Server JWS payloads** —
//!   [`JwsVerifier`] handles `jwsRepresentation`,
//!   `signedTransactionInfo` / `signedRenewalInfo` and Server Notifications
//!   V2;
//! - **legacy PKCS#7 app receipts** — [`ReceiptVerifier`] handles the exact
//!   blob apps send to the deprecated `verifyReceipt` endpoint, and
//!   [`VerifyReceiptEndpoint`] reproduces that endpoint's wire contract
//!   locally, status codes included.
//!
//! # What this crate will never do
//!
//! - **Read the operating system's trust store.** Anchors come only from the
//!   caller's argument or from [`apple_jws_roots`] / [`apple_receipt_roots`],
//!   which are `include_bytes!`-embedded copies of Apple's three published
//!   roots. There is no code path to a system store, so there is no switch
//!   to get wrong.
//! - **Touch the network.** No OCSP, no CRL, no AIA fetch, no root download.
//!   Revocation checking is disabled by design (`PLAN.md` D12); an
//!   integrator who needs it must layer it on top.
//! - **Judge a certificate at a clock the caller controls.** Validity is
//!   judged at the payload's `signedDate` / `receiptCreationDate`, or at the
//!   receipt's attribute-12 creation date, and where the input states no
//!   date the fallback reads the system clock. The injected [`Clock`] moves
//!   exactly two things: the `STALE_PAYLOAD` rule and the endpoint's
//!   `request_date`.
//! - **Return anything partial.** A failure returns a [`VerificationError`]
//!   and nothing else; a success returns only data that passed every check.
//! - **Log, meter or call back.** [`Reason`] is the whole observability
//!   surface (`PLAN.md` D11), and a detail string never contains receipt
//!   bytes, claims or key material.
//!
//! # Verifying a transaction
//!
//! ```no_run
//! use apple_purchase_receipt_verifier::{apple_jws_roots, Environment, JwsVerifier};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let jws: &str = "eyJhbGciOiJFUzI1NiIsIng1YyI6W119.e30.AA";
//! let verifier = JwsVerifier::builder()
//!     .trusted_roots(apple_jws_roots().iter().cloned())
//!     .bundle_id("com.example.app")
//!     .accepted_environments([Environment::Production, Environment::Sandbox])
//!     .build()?;
//!
//! let payload = verifier.verify_transaction(jws)?;
//! assert_eq!(payload.bundle_id.as_deref(), Some("com.example.app"));
//! # Ok(())
//! # }
//! ```
//!
//! # Errors
//!
//! Every verification entry point returns [`VerificationError`], whose
//! [`reason`](VerificationError::reason) is one of eleven [`Reason`] values.
//! Match on the value; never parse the message.
//!
//! Configuration mistakes are a different type, [`ConfigError`], because
//! misconfiguration is a programming error and not a verification verdict.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// The panic-free contract, mechanised. The probe that preceded this port
// found a real out-of-bounds panic in a CMS walk by mutating a genuine
// receipt; `indexing_slicing` is the lint that would have caught it at
// compile time. These apply to the library crate only — the test crates
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

pub mod asn1;
pub mod base64;
pub mod chain;
pub mod clock;
pub mod cms;
pub mod crypto;
pub mod datetime;
mod environment;
mod error;
mod jws;
mod receipt;
mod receipt_payload;
mod roots;
pub mod x509;

#[cfg(feature = "endpoint")]
mod endpoint;

pub use clock::{Clock, FixedClock, SystemClock};
pub use environment::Environment;
pub use error::{ConfigError, CoreError, Reason, UnknownReason, VerificationError};
pub use jws::{
    AppTransactionPayload, Claims, JwsVerifier, JwsVerifierBuilder, TransactionPayload,
    INTERMEDIATE_OID, LEAF_OID,
};
pub use receipt::{
    verify_receipt_core, AppReceipt, InAppPurchase, ReceiptVerifier, ReceiptVerifierBuilder,
    MAX_EMBEDDED_CERTIFICATES, MAX_RECEIPT_BYTES, RECEIPT_SIGNER_OID,
};
pub use roots::{apple_jws_roots, apple_receipt_roots, apple_root_der, TrustAnchor};

#[cfg(feature = "endpoint")]
pub use endpoint::{
    status, VerifyReceiptEndpoint, VerifyReceiptEndpointBuilder, VerifyReceiptRequest,
    VerifyReceiptResponse,
};

/// `serde_json`, re-exported so a consumer cannot end up with a different
/// major version than the one [`Claims`] is built from.
pub use serde_json;
