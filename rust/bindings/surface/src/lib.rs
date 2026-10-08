//! The 0.7 API of apple-purchase-receipt-verifier as plain Rust values: the
//! model every binding boundary shares.
//!
//! The core (`apple-purchase-receipt-verifier`) parses, verifies and
//! decides. This crate names the 0.7 concepts once, for the code that
//! carries them across a boundary: the C ABI (`rust/ffi`), `aprv.wasm`
//! (`aprv-abi`) and the JSON both of them write (`aprv-wire`). It holds no
//! cryptography, no parsing and no policy; every verdict it returns is the
//! core's.
//!
//! What a boundary sees here that the core's own API shapes differently:
//!
//! - **Inputs are bytes.** A binding receives bytes, and bytes that are not
//!   UTF-8 are input like any other: the core judges them by the same rules
//!   (they can never be base64, base64url or JSON).
//! - **The instant is an argument.** The wrapper reads its `Config` clock
//!   once per call and passes the value as `now_ms`, epoch milliseconds.
//!   The core uses it for two things only: the certificate-validity instant
//!   when the receipt or JWS carries no usable signing date, and
//!   `request_date` in the endpoint response.
//! - **No unsigned integers.** Ids are `i64`, since an ASN.1 INTEGER in
//!   hostile input can be negative, and attribute types are `i64` too.
//! - **A failure is a reason and a message.** The core's `source()` chain is
//!   Rust-only and does not cross a boundary.
//!
//! These doc comments are the reference text every wrapper's API
//! documentation is written from (ARCHITECTURE.md §8).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use apple_purchase_receipt_verifier as core_api;
use std::cell::Cell;

/// The library's version, for startup logs: the core's own.
pub const VERSION: &str = core_api::VERSION;

// ---------------------------------------------------------------- Reason

/// Why a verification failed: the eight 0.7 reasons, the whole contract.
///
/// Match on the reason, never on a message. Adding a value is a breaking
/// change in every language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// The base64, ASN.1, CMS or JWS structure is broken, or a structural
    /// bound (JSON depth, embedded certificates, `SignerInfo`s) is exceeded.
    Malformed,
    /// The input is over one of the fixed size caps: 3,145,728 UTF-8 bytes
    /// of receipt base64 or endpoint body, 262,144 of JWS.
    TooLarge,
    /// The signature does not match the content.
    InvalidSignature,
    /// The chain does not reach a pinned root.
    UntrustedChain,
    /// A certificate does not decode, or is outside its validity window at
    /// the chain instant.
    InvalidCertificate,
    /// A valid Apple certificate of the wrong kind: an Apple marker OID is
    /// missing on the leaf or the intermediate.
    InvalidCertificatePurpose,
    /// Apple signed it, but the content does not parse. Alert; do not retry.
    UnreadablePayload,
    /// The library failed before it could decide. Alert; do not retry.
    InternalError,
}

impl Reason {
    /// Every reason, in the order the contract lists them.
    pub const ALL: [Reason; 8] = [
        Reason::Malformed,
        Reason::TooLarge,
        Reason::InvalidSignature,
        Reason::UntrustedChain,
        Reason::InvalidCertificate,
        Reason::InvalidCertificatePurpose,
        Reason::UnreadablePayload,
        Reason::InternalError,
    ];

    /// The `SCREAMING_SNAKE` token every port and the wire spell the reason
    /// with, such as `UNTRUSTED_CHAIN`.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Reason::Malformed => "MALFORMED",
            Reason::TooLarge => "TOO_LARGE",
            Reason::InvalidSignature => "INVALID_SIGNATURE",
            Reason::UntrustedChain => "UNTRUSTED_CHAIN",
            Reason::InvalidCertificate => "INVALID_CERTIFICATE",
            Reason::InvalidCertificatePurpose => "INVALID_CERTIFICATE_PURPOSE",
            Reason::UnreadablePayload => "UNREADABLE_PAYLOAD",
            Reason::InternalError => "INTERNAL_ERROR",
        }
    }

    /// The reason a token spells, or `None` for anything outside the eight.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Reason> {
        Reason::ALL
            .into_iter()
            .find(|reason| reason.token() == token)
    }
}

impl From<core_api::Reason> for Reason {
    fn from(reason: core_api::Reason) -> Reason {
        // Exhaustive on purpose: a ninth core reason fails to compile here
        // instead of crossing a boundary under another name.
        match reason {
            core_api::Reason::Malformed => Reason::Malformed,
            core_api::Reason::TooLarge => Reason::TooLarge,
            core_api::Reason::InvalidSignature => Reason::InvalidSignature,
            core_api::Reason::UntrustedChain => Reason::UntrustedChain,
            core_api::Reason::InvalidCertificate => Reason::InvalidCertificate,
            core_api::Reason::InvalidCertificatePurpose => Reason::InvalidCertificatePurpose,
            core_api::Reason::UnreadablePayload => Reason::UnreadablePayload,
            core_api::Reason::InternalError => Reason::InternalError,
        }
    }
}

// --------------------------------------------------------------- Failure

/// A verification verdict of "no": a [`Reason`] and a message.
///
/// The message is safe to log (it never embeds raw input, claims or key
/// material) and not meant to be parsed; it may change between releases.
/// Two messages are a stable hook, because the shared `decodeBase64` cases
/// tell the two base64 decoders apart by them: a refused `receipt-data`
/// text is `MALFORMED` with a message containing `receipt is not valid
/// base64`, a refused `x5c` entry `INVALID_CERTIFICATE` with one containing
/// `x5c entry is not valid base64`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// Why verification failed. Match on this.
    pub reason: Reason,
    /// A short description, safe to log, not meant to be parsed.
    pub message: String,
}

impl Failure {
    fn internal(message: &str) -> Failure {
        Failure {
            reason: Reason::InternalError,
            message: message.to_owned(),
        }
    }
}

impl From<core_api::Failure> for Failure {
    fn from(failure: core_api::Failure) -> Failure {
        Failure {
            reason: failure.reason().into(),
            message: failure.message().to_owned(),
        }
    }
}

// ----------------------------------------------------------- Environment

/// Apple's two environments: which of Apple's two `verifyReceipt` URLs
/// [`Verifier::verify_receipt_endpoint`] imitates, and the environment a
/// verified receipt or JWS names ([`ReceiptPayload::environment`],
/// [`JsonPayload::environment`]). A sandbox receipt on `Production` answers
/// 21007 and a production receipt on `Sandbox` 21008, as Apple's endpoints
/// do; it filters nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Environment {
    /// `https://buy.itunes.apple.com/verifyReceipt`
    Production,
    /// `https://sandbox.itunes.apple.com/verifyReceipt`
    Sandbox,
}

impl From<Environment> for core_api::Environment {
    fn from(environment: Environment) -> core_api::Environment {
        match environment {
            Environment::Production => core_api::Environment::Production,
            Environment::Sandbox => core_api::Environment::Sandbox,
        }
    }
}

impl From<core_api::Environment> for Environment {
    fn from(environment: core_api::Environment) -> Environment {
        match environment {
            core_api::Environment::Production => Environment::Production,
            core_api::Environment::Sandbox => Environment::Sandbox,
        }
    }
}

/// The most bytes of one input a host needs to hand the module: one over
/// the core's largest size cap. A longer input may be cut to this length,
/// and the module answers `TOO_LARGE` for it (21002 at the endpoint), as for
/// the whole input. `init`'s answer states it as `max_input_bytes`, so no
/// host keeps a copy (DECISIONS.md R42).
pub const MAX_INPUT_BYTES: usize = core_api::__internal::MAX_INPUT_BYTES;

// -------------------------------------------------------------- payloads

/// The attributes of a receipt or purchase that did not end up in a typed
/// field: each attribute type once, in ascending order, with its raw value
/// octets in receipt order. That covers an attribute type the library does
/// not model, the second and later copies of a known attribute, and a known
/// attribute whose value does not parse (its typed field is then `None`).
/// Nothing Apple signed is lost.
pub type UnknownAttributes = Vec<(i64, Vec<Vec<u8>>)>;

/// A verified legacy app receipt (0.7-api.md §1).
///
/// Field names are Apple's own words from the `verifyReceipt` response. A
/// missing attribute is `None`; the library invents no values. Dates are
/// epoch milliseconds, UTC. The first copy of a known attribute fills its
/// field.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReceiptPayload {
    /// Attribute 0, such as `Production` or `ProductionSandbox`.
    pub receipt_type: Option<String>,
    /// Attribute 1, the app's App Store item id. Zero in sandbox receipts.
    pub app_item_id: Option<i64>,
    /// Attribute 2, decoded.
    pub bundle_id: Option<String>,
    /// Attribute 2, the value octets as they sit in the receipt: one input
    /// of Apple's device-hash formula.
    pub bundle_id_bytes: Option<Vec<u8>>,
    /// Attribute 3.
    pub application_version: Option<String>,
    /// Attribute 4, an input of the device-hash formula.
    pub opaque_value: Option<Vec<u8>>,
    /// Attribute 5, the SHA-1 device hash.
    pub sha1_hash: Option<Vec<u8>>,
    /// Attribute 12, the receipt's creation date; the instant the chain is
    /// judged at.
    pub receipt_creation_date_ms: Option<i64>,
    /// Attribute 15. Genuine values run to eighteen digits.
    pub download_id: Option<i64>,
    /// Attribute 16.
    pub version_external_identifier: Option<i64>,
    /// Attribute 17, one entry per copy, in receipt order.
    pub in_app: Vec<InAppPurchase>,
    /// Attribute 18.
    pub original_purchase_date_ms: Option<i64>,
    /// Attribute 32, the pre-order date.
    pub preorder_date_ms: Option<i64>,
    /// Attribute 19.
    pub original_application_version: Option<String>,
    /// Attribute 21.
    pub expiration_date_ms: Option<i64>,
    /// Every attribute that did not end up in a field above.
    pub unknown_attributes: UnknownAttributes,
    /// The environment `receipt_type` names, by the core's rule:
    /// `Production` and `ProductionVPP` are `Production`,
    /// `ProductionSandbox` and `ProductionVPPSandbox` are `Sandbox`,
    /// anything else (`Xcode`, a missing value) is `None`. Not part of the
    /// payload's JSON; the answer carries it beside the payload.
    pub environment: Option<Environment>,
}

/// One in-app purchase (attribute 17) of a [`ReceiptPayload`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InAppPurchase {
    /// 1701
    pub quantity: Option<i64>,
    /// 1702
    pub product_id: Option<String>,
    /// 1703
    pub transaction_id: Option<String>,
    /// 1704
    pub purchase_date_ms: Option<i64>,
    /// 1705
    pub original_transaction_id: Option<String>,
    /// 1706
    pub original_purchase_date_ms: Option<i64>,
    /// 1708
    pub expires_date_ms: Option<i64>,
    /// 1711
    pub web_order_line_item_id: Option<i64>,
    /// 1712
    pub cancellation_date_ms: Option<i64>,
    /// 1713: 0 is `false`, any other value `true`.
    pub is_trial_period: Option<bool>,
    /// 1719: 0 is `false`, any other value `true`.
    pub is_in_intro_offer_period: Option<bool>,
    /// Every attribute of this purchase that did not end up in a field.
    pub unknown_attributes: UnknownAttributes,
}

/// A verified JWS payload (0.7-api.md §2): the JSON Apple signed, exactly as
/// signed. Callers parse it with their own JSON library; the library
/// returns no header and no typed claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonPayload {
    /// The signed payload's JSON text.
    pub json: String,
    /// The environment the payload names, by the core's rule: the first of
    /// the top-level `environment`, `data.environment` and
    /// `summary.environment` that is present decides, `Production` and
    /// `Sandbox` map and anything else is `None`; `None` when none is
    /// present.
    pub environment: Option<Environment>,
}

fn unknown_attributes(attributes: core_api::UnknownAttributes) -> UnknownAttributes {
    attributes
        .into_iter()
        .map(|(attribute_type, values)| (i64::from(attribute_type), values))
        .collect()
}

impl From<core_api::InAppPurchase> for InAppPurchase {
    fn from(purchase: core_api::InAppPurchase) -> InAppPurchase {
        InAppPurchase {
            quantity: purchase.quantity,
            product_id: purchase.product_id,
            transaction_id: purchase.transaction_id,
            purchase_date_ms: purchase.purchase_date_ms,
            original_transaction_id: purchase.original_transaction_id,
            original_purchase_date_ms: purchase.original_purchase_date_ms,
            expires_date_ms: purchase.expires_date_ms,
            web_order_line_item_id: purchase.web_order_line_item_id,
            cancellation_date_ms: purchase.cancellation_date_ms,
            is_trial_period: purchase.is_trial_period,
            is_in_intro_offer_period: purchase.is_in_intro_offer_period,
            unknown_attributes: unknown_attributes(purchase.unknown_attributes),
        }
    }
}

impl From<core_api::ReceiptPayload> for ReceiptPayload {
    fn from(receipt: core_api::ReceiptPayload) -> ReceiptPayload {
        let environment = receipt.environment().map(Environment::from);
        ReceiptPayload {
            receipt_type: receipt.receipt_type,
            app_item_id: receipt.app_item_id,
            bundle_id: receipt.bundle_id,
            bundle_id_bytes: receipt.bundle_id_bytes,
            application_version: receipt.application_version,
            opaque_value: receipt.opaque_value,
            sha1_hash: receipt.sha1_hash,
            receipt_creation_date_ms: receipt.receipt_creation_date_ms,
            download_id: receipt.download_id,
            version_external_identifier: receipt.version_external_identifier,
            in_app: receipt
                .in_app
                .into_iter()
                .map(InAppPurchase::from)
                .collect(),
            original_purchase_date_ms: receipt.original_purchase_date_ms,
            preorder_date_ms: receipt.preorder_date_ms,
            original_application_version: receipt.original_application_version,
            expiration_date_ms: receipt.expiration_date_ms,
            unknown_attributes: unknown_attributes(receipt.unknown_attributes),
            environment,
        }
    }
}

// --------------------------------------------------------------- config

/// A configuration that cannot make a verifier: a root that is not a
/// certificate, or bundled roots that did not load. Not a verdict about any
/// input; it happens once, when the verifier is made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// What was wrong, safe to show.
    pub message: String,
}

/// Decodes base64 text by the core's `receipt-data` rule (non-empty
/// standard base64 with exactly its canonical padding, nothing else). The
/// bindings read the roots of a configuration with it. The core keeps the
/// decoder out of its public API; this crate is built with it in lockstep
/// and reaches it through the core's internal hook.
#[must_use]
pub fn decode_base64(text: &[u8]) -> Option<Vec<u8>> {
    core_api::__internal::decode_receipt_data(text).ok()
}

// -------------------------------------------------------------- verifier

thread_local! {
    /// The instant of the call in progress on this thread. Every call sets
    /// it before the core runs, and the core's clock reads nothing else.
    static NOW_MS: Cell<i64> = const { Cell::new(0) };
}

/// Verifies what Apple signed, offline, against a fixed set of roots. Made
/// once; share it, or make one per thread.
#[derive(Debug, Clone)]
pub struct Verifier {
    inner: core_api::Verifier,
}

impl Verifier {
    /// A verifier that trusts `roots`, each one DER certificate or PEM text
    /// holding one or more certificates; the core tells them apart by the
    /// bytes ([`core_api::TrustAnchor::from_der_or_pem`]). An empty list
    /// means the three Apple roots compiled into the library.
    ///
    /// A wrapper never passes an empty list for a caller's own empty root
    /// set: 0.7's `Verifier.create` refuses that before a boundary is
    /// crossed, because a verifier with no roots would answer
    /// `UNTRUSTED_CHAIN` to everything.
    ///
    /// # Errors
    /// [`ConfigError`] naming the first root that is not a certificate (by
    /// its index), or saying the bundled roots did not load.
    pub fn new(roots: &[Vec<u8>]) -> Result<Verifier, ConfigError> {
        let mut builder = core_api::Config::builder().clock(|| NOW_MS.with(Cell::get));
        if !roots.is_empty() {
            let mut anchors = Vec::with_capacity(roots.len());
            for (index, root) in roots.iter().enumerate() {
                let read =
                    core_api::TrustAnchor::from_der_or_pem(root).map_err(|err| ConfigError {
                        message: format!("roots[{index}]: {}", err.detail()),
                    })?;
                anchors.extend(read);
            }
            builder = builder.roots(anchors);
        }
        let config = builder.build().map_err(|_| ConfigError {
            message: "the bundled Apple roots did not load".to_owned(),
        })?;
        Ok(Verifier {
            inner: core_api::Verifier::new(config),
        })
    }

    fn at<R>(&self, now_ms: i64, call: impl FnOnce(&core_api::Verifier) -> R) -> R {
        NOW_MS.with(|now| now.set(now_ms));
        call(&self.inner)
    }

    /// Verifies a legacy PKCS#7 app receipt, given as the bytes of the
    /// base64 `receipt-data` string a client sends, and decodes its payload.
    ///
    /// The order of checks (0.7-api.md §1): the size cap and strict base64,
    /// the CMS envelope and its bounds, the chain to a pinned root with every
    /// certificate valid at the receipt's creation date (`now_ms` when the
    /// receipt carries none that parses), Apple's marker OIDs on the leaf and
    /// the intermediate, the signature, then the payload.
    ///
    /// # Errors
    /// A [`Failure`] naming the first check that failed.
    pub fn verify_receipt(
        &self,
        receipt_base64: &[u8],
        now_ms: i64,
    ) -> Result<ReceiptPayload, Failure> {
        self.at(now_ms, |verifier| {
            verifier.verify_receipt_bytes(receipt_base64)
        })
        .map(ReceiptPayload::from)
        .map_err(Failure::from)
    }

    /// Verifies an Apple-signed compact JWS (a transaction, renewal info, app
    /// transaction or App Store Server Notification V2) and returns its
    /// payload as signed.
    ///
    /// The order of checks (0.7-api.md §2): the size cap and the compact
    /// structure, `alg` equal to `ES256`, the `x5c` chain to a pinned root
    /// with every certificate valid at the payload's `signedDate` (else its
    /// `receiptCreationDate`, then `now_ms`, when it is missing or not a
    /// representable instant), the marker OIDs,
    /// then the signature.
    ///
    /// # Errors
    /// A [`Failure`] naming the first check that failed.
    pub fn verify_signed_data(&self, jws: &[u8], now_ms: i64) -> Result<JsonPayload, Failure> {
        self.at(now_ms, |verifier| verifier.verify_signed_data_bytes(jws))
            .map(|payload| {
                let environment = payload.environment().map(Environment::from);
                JsonPayload {
                    json: payload.into_json(),
                    environment,
                }
            })
            .map_err(Failure::from)
    }

    /// The response body Apple's `verifyReceipt` at `environment` would
    /// return for the request body `request_json`, byte for byte where the
    /// receipt allows it; `request_date` is `now_ms`. Never fails: every
    /// verdict is the `status` inside the body (0.7-api.md §3).
    #[must_use]
    pub fn verify_receipt_endpoint(
        &self,
        environment: Environment,
        request_json: &[u8],
        now_ms: i64,
    ) -> String {
        self.at(now_ms, |verifier| {
            verifier.verify_receipt_endpoint_bytes(environment.into(), request_json)
        })
    }
}

/// The instant a boundary received, as the surface's `now_ms`.
///
/// The canonical ABI carries `now-ms` as a `u64`, and the core's instant is
/// an `i64`: a value above `i64::MAX` names no instant the core can judge
/// at, and is refused rather than narrowed.
///
/// # Errors
/// An `INTERNAL_ERROR` [`Failure`]: the caller's clock, not the input, is
/// broken.
pub fn now_ms_from_u64(now_ms: u64) -> Result<i64, Failure> {
    i64::try_from(now_ms).map_err(|_| Failure::internal("the clock is outside the range of an i64"))
}

/// The endpoint's answer for a call that failed before the core could run
/// it, with a clock beyond `i64` ([`now_ms_from_u64`]): the status-only body
/// `{"status":21009}` the core answers for every `INTERNAL_ERROR`
/// (`AppleStatus::INTERNAL_DATA_ACCESS_ERROR`), as a clock that throws is
/// answered in 0.7.
#[must_use]
pub fn endpoint_internal_error() -> String {
    format!(
        "{{\"status\":{}}}",
        core_api::AppleStatus::INTERNAL_DATA_ACCESS_ERROR
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::{
        core_api, now_ms_from_u64, Environment, Failure, Reason, ReceiptPayload, Verifier,
    };
    use std::path::PathBuf;

    fn fixture(relative: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../fixtures")
            .join(relative);
        std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
    }

    fn g5() -> Vec<u8> {
        let text = String::from_utf8(fixture("public-receipts/receipt-sandbox-g5.b64")).unwrap();
        text.split_whitespace().collect::<String>().into_bytes()
    }

    #[test]
    fn the_eight_reasons_are_the_cores_eight_in_the_same_order() {
        let core: Vec<&str> = core_api::Reason::all().iter().map(|r| r.as_str()).collect();
        let ours: Vec<&str> = Reason::ALL.iter().map(|r| r.token()).collect();
        assert_eq!(ours, core);
        for reason in core_api::Reason::all() {
            assert_eq!(Reason::from(*reason).token(), reason.as_str());
        }
        for reason in Reason::ALL {
            assert_eq!(Reason::from_token(reason.token()), Some(reason));
        }
        assert_eq!(Reason::from_token("INVALID_CHAIN"), None);
        assert_eq!(Reason::from_token("malformed"), None);
    }

    #[test]
    fn an_empty_root_list_means_the_three_apple_roots() {
        let verifier = Verifier::new(&[]).unwrap();
        let receipt = verifier.verify_receipt(&g5(), 0).unwrap();
        assert_eq!(receipt.receipt_type.as_deref(), Some("ProductionSandbox"));
    }

    #[test]
    fn a_root_that_is_not_a_certificate_is_named_by_its_index() {
        let root = fixture("../certs/AppleIncRootCertificate.cer");
        let error = Verifier::new(&[root, b"not a certificate".to_vec()]).unwrap_err();
        assert!(error.message.starts_with("roots[1]: "), "{}", error.message);
    }

    /// PEM as certificate tools print it: base64 in 64-column lines between
    /// `CERTIFICATE` lines.
    fn pem(der: &[u8]) -> Vec<u8> {
        let body = core_api::__internal::base64_encode(der);
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in body.as_bytes().chunks(64) {
            out.push_str(core::str::from_utf8(line).unwrap());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out.into_bytes()
    }

    #[test]
    fn a_root_reaches_the_core_as_der_or_pem_bytes_and_verifies_the_same() {
        // `init` hands each decoded root to the core as it came; the core
        // reads DER or PEM. A PEM bundle is one entry holding every root.
        let ders: Vec<Vec<u8>> = [
            "AppleIncRootCertificate.cer",
            "AppleRootCA-G2.cer",
            "AppleRootCA-G3.cer",
        ]
        .iter()
        .map(|name| fixture(&format!("../certs/{name}")))
        .collect();
        let pems: Vec<Vec<u8>> = ders.iter().map(|der| pem(der)).collect();
        let bundle = vec![pems.concat()];
        let expected = Verifier::new(&ders)
            .unwrap()
            .verify_receipt(&g5(), 0)
            .unwrap();
        for roots in [&pems, &bundle] {
            let verifier = Verifier::new(roots).unwrap();
            assert_eq!(verifier.verify_receipt(&g5(), 0).unwrap(), expected);
        }
        let empty = b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----".to_vec();
        let error = Verifier::new(&[pems[0].clone(), empty]).unwrap_err();
        assert!(error.message.starts_with("roots[1]: "), "{}", error.message);
    }

    #[test]
    fn bytes_that_are_not_utf8_are_input_and_fail_as_the_core_says() {
        let verifier = Verifier::new(&[]).unwrap();
        let failure = verifier
            .verify_receipt(&[0x4d, 0xff, 0xfe, 0x3d], 0)
            .unwrap_err();
        assert_eq!(failure.reason, Reason::Malformed);
        assert!(failure.message.contains("receipt is not valid base64"));
        let failure = verifier.verify_signed_data(b"e\xff.e.e", 0).unwrap_err();
        assert_eq!(failure.reason, Reason::Malformed);
        let answer = verifier.verify_receipt_endpoint(Environment::Sandbox, b"{\xff}", 0);
        assert_eq!(answer, "{\"status\":21002}");
    }

    #[test]
    fn the_instant_of_each_call_is_its_own_argument() {
        // The endpoint's request_date is the one output that shows now_ms.
        let verifier = Verifier::new(&[]).unwrap();
        let body = format!(
            "{{\"receipt-data\":\"{}\"}}",
            String::from_utf8(g5()).unwrap()
        );
        for now in [1_600_000_000_000_i64, 1_700_000_000_000] {
            let answer =
                verifier.verify_receipt_endpoint(Environment::Sandbox, body.as_bytes(), now);
            assert!(
                answer.contains(&format!("\"request_date_ms\":\"{now}\"")),
                "{answer}"
            );
        }
        // Each thread its own instant.
        let handles: Vec<_> = (0..4_i64)
            .map(|i| {
                let verifier = verifier.clone();
                let body = body.clone();
                std::thread::spawn(move || {
                    let now = 1_650_000_000_000 + i * 1_000;
                    for _ in 0..3 {
                        let answer = verifier.verify_receipt_endpoint(
                            Environment::Sandbox,
                            body.as_bytes(),
                            now,
                        );
                        assert!(answer.contains(&format!("\"request_date_ms\":\"{now}\"")));
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn attribute_types_cross_as_signed_integers_in_ascending_order() {
        let mut core = core_api::ReceiptPayload::default();
        core.unknown_attributes.insert(19_999, vec![vec![1]]);
        core.unknown_attributes.insert(13, vec![vec![2], vec![3]]);
        let ours = ReceiptPayload::from(core);
        assert_eq!(
            ours.unknown_attributes,
            vec![(13, vec![vec![2], vec![3]]), (19_999, vec![vec![1]])]
        );
    }

    /// The environment is the core's answer, carried across unchanged.
    #[test]
    fn the_environment_crosses_as_the_core_states_it() {
        for (receipt_type, expected) in [
            (Some("ProductionVPP"), Some(Environment::Production)),
            (Some("ProductionSandbox"), Some(Environment::Sandbox)),
            (Some("Xcode"), None),
            (None, None),
        ] {
            let core = core_api::ReceiptPayload {
                receipt_type: receipt_type.map(str::to_owned),
                ..core_api::ReceiptPayload::default()
            };
            assert_eq!(ReceiptPayload::from(core).environment, expected);
        }
    }

    #[test]
    fn a_clock_beyond_i64_is_an_internal_error_never_an_instant() {
        assert_eq!(now_ms_from_u64(0), Ok(0));
        assert_eq!(now_ms_from_u64(i64::MAX as u64), Ok(i64::MAX));
        let failure: Failure = now_ms_from_u64(i64::MAX as u64 + 1).unwrap_err();
        assert_eq!(failure.reason, Reason::InternalError);
        assert_eq!(now_ms_from_u64(u64::MAX).unwrap_err(), failure);
    }
}
