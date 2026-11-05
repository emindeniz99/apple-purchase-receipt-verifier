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
//!   once per call and passes the value as `now_ms`, epoch milliseconds,
//!   which reaches the core's `_at` methods unchanged. A caller with no
//!   clock to read (the C ABI given a null clock) uses the `_by_clock`
//!   calls instead, and the core reads the system clock, only when the
//!   call needs the time. The core uses the instant
//!   for three things only: the certificate-validity instant when the
//!   receipt or JWS carries no usable signing date, `request_date` in the
//!   endpoint response, and whether a revocation list whose
//!   `certificateHold` entry names a certificate on the path is still
//!   fresh.
//! - **No unsigned integers, but for one.** Ids are `i64`, since an ASN.1
//!   INTEGER in hostile input can be negative. The receipt types are the
//!   core's own, so an unknown attribute's type is the core's `u32`, which
//!   the core bounds to the `i32` range; on the wire it is a decimal key.
//! - **A failure crosses as a reason and a message.** The verdict types
//!   are the core's own, `Failure` included; its `source()` chain is
//!   Rust-only, and no writer at a boundary carries it.
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

/// The library's version, for startup logs: the core's own.
pub const VERSION: &str = core_api::VERSION;

// ----------------------------------------------------------- the verdicts

/// The core's verdict and environment types, handed out as the core returns
/// them, so each is defined once; their doc comments are in the core.
///
/// - [`Reason`]: the nine reasons (the eight of 0.7 and
///   `CERTIFICATE_REVOKED`, 0.14), spelled on the wire by
///   [`Reason::as_str`], read back with `str::parse`.
/// - [`Failure`]: a [`Reason`] and a message. Its `source()` chain is
///   Rust-only: `aprv-wire` and the C ABI write the reason and the message
///   and nothing else, so the chain never crosses a boundary.
/// - [`Environment`]: what [`Verifier::verify_receipt_endpoint`] imitates,
///   and what [`ReceiptPayload::environment`] and
///   [`JsonPayload::environment`] state.
/// - [`JsonPayload`]: a verified JWS payload, exactly as signed.
pub use core_api::{Environment, Failure, JsonPayload, Reason};

/// The most bytes of one input a host needs to hand the module: one over
/// the core's largest size cap. A longer input may be cut to this length,
/// and the module answers `TOO_LARGE` for it (21002 at the endpoint), as for
/// the whole input. `init`'s answer states it as `max_input_bytes`, so no
/// host keeps a copy (DECISIONS.md R42).
pub const MAX_INPUT_BYTES: usize = core_api::__internal::MAX_INPUT_BYTES;

// -------------------------------------------------------------- payloads

/// A verified legacy app receipt (0.7-api.md §1), its in-app purchases and
/// the attributes no typed field holds: the core's own types, handed out
/// as the core returns them, so a receipt is modelled once. Their doc
/// comments are in the core. The environment a receipt names is the core's
/// [`ReceiptPayload::environment`], which a verified answer carries beside
/// the payload.
pub use core_api::{InAppPurchase, ReceiptPayload, UnknownAttributes};

// --------------------------------------------------------------- config

/// Each of `entries` read as the core reads a root, DER or PEM, every
/// certificate of a PEM bundle in its place; the first that is not a
/// certificate is named as `member[index]`. Beside them, for each
/// certificate, the index of the entry it came from and its place in that
/// entry, so a refusal the core makes by certificate can name the entry.
fn certificates(
    member: &str,
    entries: &[Vec<u8>],
) -> Result<(Vec<core_api::TrustAnchor>, Vec<(usize, usize)>), ConfigError> {
    let mut read = Vec::with_capacity(entries.len());
    let mut origin = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let anchors = core_api::TrustAnchor::from_der_or_pem(entry).map_err(|err| ConfigError {
            message: format!("{member}[{index}]: {}", err.detail()),
        })?;
        origin.extend((0..anchors.len()).map(|place| (index, place)));
        read.extend(anchors);
    }
    Ok((read, origin))
}

/// The core's refusal, with a `revocation_issuers[i]` index, which counts
/// certificates, turned into the index of the entry given (and the
/// certificate's place when that entry is a PEM bundle of several).
fn entry_named(detail: &str, origin: &[(usize, usize)], counts: &[usize]) -> String {
    const PREFIX: &str = "revocation_issuers[";
    let Some(rest) = detail.strip_prefix(PREFIX) else {
        return detail.to_owned();
    };
    let Some((digits, tail)) = rest.split_once(']') else {
        return detail.to_owned();
    };
    let Some(&(index, place)) = digits.parse::<usize>().ok().and_then(|i| origin.get(i)) else {
        return detail.to_owned();
    };
    if counts.get(index).copied().unwrap_or(1) > 1 {
        format!(
            "{PREFIX}{index}] (certificate {} of its PEM text){tail}",
            place + 1
        )
    } else {
        format!("{PREFIX}{index}]{tail}")
    }
}

/// A configuration that cannot make a verifier: a root that is not a
/// certificate, a revocation setting the core refuses, or bundled roots or
/// a built-in revocation list that did not load. Not a verdict about any
/// input; it happens once, when the verifier is made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// What was wrong, safe to show.
    pub message: String,
}

/// The revocation settings of a configuration (docs/design/revocation.md
/// §4), as bytes and text. Every member is empty by default, and the core
/// judges all of it when the verifier is made.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Revocation {
    /// Certificate revocation lists exactly as downloaded (DER), any order.
    /// At most 16, each at most 1 MiB, 100,000 entries in all.
    pub lists: Vec<Vec<u8>>,
    /// CA certificates that sign lists, each one DER certificate or PEM
    /// text, as a root is given.
    pub issuers: Vec<Vec<u8>>,
    /// Revocation keys to refuse: an issuer id (64 hex digits) and a
    /// serial in hex. At most 1,000.
    pub distrust: Vec<(String, String)>,
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
    /// its index), or saying the bundled roots or the built-in revocation
    /// list did not load.
    pub fn new(roots: &[Vec<u8>]) -> Result<Verifier, ConfigError> {
        Verifier::with_revocation(roots, &Revocation::default())
    }

    /// [`new`](Verifier::new) with revocation settings
    /// (docs/design/revocation.md §4). The core reads every list, judges
    /// every issuer and every `distrust` entry here, once.
    ///
    /// # Errors
    /// [`ConfigError`] naming the first root or issuer that is not a
    /// certificate (by its index), or the first revocation setting the
    /// core refuses, with its index; or saying the bundled roots or the
    /// built-in revocation list did not load.
    pub fn with_revocation(
        roots: &[Vec<u8>],
        revocation: &Revocation,
    ) -> Result<Verifier, ConfigError> {
        // The core's default clock, the system clock: the `_by_clock`
        // calls read it, lazily; the others pass their instant to the
        // core's `_at` methods, which never read it.
        let mut builder = core_api::Config::builder();
        if !roots.is_empty() {
            builder = builder.roots(certificates("roots", roots)?.0);
        }
        let (issuers, origin) = certificates("revocation_issuers", &revocation.issuers)?;
        let mut counts = vec![0_usize; revocation.issuers.len()];
        for &(index, _) in &origin {
            if let Some(count) = counts.get_mut(index) {
                *count += 1;
            }
        }
        let config = builder
            .revocation_lists(revocation.lists.iter().cloned())
            .revocation_issuers(issuers)
            .distrust(revocation.distrust.iter().cloned())
            .build()
            .map_err(|err| ConfigError {
                message: entry_named(err.detail(), &origin, &counts),
            })?;
        Ok(Verifier {
            inner: core_api::Verifier::new(config),
        })
    }

    /// The URLs of the revocation lists this verifier would use, for the
    /// host to download (docs/design/revocation.md §7): the core's
    /// `Verifier::revocation_urls`.
    #[must_use]
    pub fn revocation_urls(&self) -> &[String] {
        self.inner.revocation_urls()
    }

    /// The earliest `nextUpdate` among the lists the verifier holds for the
    /// issuers it expects lists from, epoch milliseconds, or `None` when one
    /// of them has none: the core's `Verifier::revocation_valid_until`.
    #[must_use]
    pub fn revocation_valid_until_ms(&self) -> Option<i64> {
        self.inner.revocation_valid_until()
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
        self.inner.verify_receipt_bytes_at(receipt_base64, now_ms)
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
        self.inner.verify_signed_data_bytes_at(jws, now_ms)
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
        self.inner
            .verify_receipt_endpoint_bytes_at(environment, request_json, now_ms)
    }

    // The same three calls without an instant, for a caller that has no
    // clock of its own to read (the C ABI given a null clock): the core
    // reads the system clock, only when the call needs the time.

    /// [`verify_receipt`](Verifier::verify_receipt) at the system clock's
    /// time, read only when the receipt carries no usable creation date.
    ///
    /// # Errors
    /// A [`Failure`] naming the first check that failed.
    pub fn verify_receipt_by_clock(
        &self,
        receipt_base64: &[u8],
    ) -> Result<ReceiptPayload, Failure> {
        self.inner.verify_receipt_bytes(receipt_base64)
    }

    /// [`verify_signed_data`](Verifier::verify_signed_data) at the system
    /// clock's time, read only when the payload carries no usable date.
    ///
    /// # Errors
    /// A [`Failure`] naming the first check that failed.
    pub fn verify_signed_data_by_clock(&self, jws: &[u8]) -> Result<JsonPayload, Failure> {
        self.inner.verify_signed_data_bytes(jws)
    }

    /// [`verify_receipt_endpoint`](Verifier::verify_receipt_endpoint) at
    /// the system clock's time, read only when the answer needs it
    /// (`request_date`, or a receipt with no usable creation date).
    #[must_use]
    pub fn verify_receipt_endpoint_by_clock(
        &self,
        environment: Environment,
        request_json: &[u8],
    ) -> String {
        self.inner
            .verify_receipt_endpoint_bytes(environment, request_json)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::{core_api, Environment, Reason, Verifier};
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
    fn a_refused_issuer_is_named_by_the_entry_given_not_the_certificate() {
        // The core counts certificates; a PEM bundle is one entry holding
        // several, so its index must be mapped back to the entry.
        let read = |name: &str| fixture(&format!("generated-0.7/revocation/{name}.der"));
        let roots = [read("root")];
        let refused = |issuers: Vec<Vec<u8>>| {
            let revocation = super::Revocation {
                issuers,
                ..super::Revocation::default()
            };
            Verifier::with_revocation(&roots, &revocation)
                .unwrap_err()
                .message
        };
        let bundle = [
            pem(&read("intermediate")),
            pem(&read("intermediate-second")),
        ]
        .concat();
        let message = refused(vec![bundle, read("intermediate-without-crl-sign")]);
        assert!(message.starts_with("revocation_issuers[1]: "), "{message}");
        let bundle = [
            pem(&read("intermediate")),
            pem(&read("intermediate-without-crl-sign")),
        ]
        .concat();
        let message = refused(vec![read("intermediate-second"), bundle]);
        assert!(
            message.starts_with("revocation_issuers[1] (certificate 2 of its PEM text): "),
            "{message}"
        );
    }

    #[test]
    fn revocation_settings_reach_the_core_and_its_answers_come_back() {
        // Apple's roots by default: the four built-in lists, none held.
        let verifier = Verifier::new(&[]).unwrap();
        assert_eq!(verifier.revocation_urls().len(), 4);
        assert_eq!(verifier.revocation_valid_until_ms(), None);
        // A distrusted signer: the genuine sandbox receipt is revoked.
        let revoked = Verifier::with_revocation(
            &[],
            &super::Revocation {
                distrust: vec![(
                    "c4c7a18465d55f4f7d20ff2a525bceafb55d860fc3b59a1981b04783fd74f96b".to_owned(),
                    "7D3920094EBEF3F8EFCA6C10EA8E4303".to_owned(),
                )],
                ..super::Revocation::default()
            },
        )
        .unwrap();
        let failure = revoked.verify_receipt(&g5(), 0).unwrap_err();
        assert_eq!(failure.reason(), Reason::CertificateRevoked);
        // The core's refusal, with its index.
        let error = Verifier::with_revocation(
            &[],
            &super::Revocation {
                lists: vec![b"not a list".to_vec()],
                ..super::Revocation::default()
            },
        )
        .unwrap_err();
        assert!(
            error.message.starts_with("revocation_lists[0]: "),
            "{}",
            error.message
        );
        let error = Verifier::with_revocation(
            &[],
            &super::Revocation {
                issuers: vec![b"not a certificate".to_vec()],
                ..super::Revocation::default()
            },
        )
        .unwrap_err();
        assert!(
            error.message.starts_with("revocation_issuers[0]: "),
            "{}",
            error.message
        );
    }

    #[test]
    fn bytes_that_are_not_utf8_are_input_and_fail_as_the_core_says() {
        let verifier = Verifier::new(&[]).unwrap();
        let failure = verifier
            .verify_receipt(&[0x4d, 0xff, 0xfe, 0x3d], 0)
            .unwrap_err();
        assert_eq!(failure.reason(), Reason::Malformed);
        assert!(failure.message().contains("receipt is not valid base64"));
        let failure = verifier.verify_signed_data(b"e\xff.e.e", 0).unwrap_err();
        assert_eq!(failure.reason(), Reason::Malformed);
        let answer = verifier.verify_receipt_endpoint(Environment::Sandbox, b"{\xff}", 0);
        assert_eq!(answer, "{\"status\":21002}");
    }

    #[test]
    fn a_call_by_clock_answers_as_a_call_at_an_instant_for_dated_input() {
        // A dated receipt and a JWS with its signedDate never need the
        // clock, so the system clock's path and a pinned instant agree.
        let verifier = Verifier::new(&[]).unwrap();
        assert_eq!(
            verifier.verify_receipt_by_clock(&g5()),
            verifier.verify_receipt(&g5(), 0)
        );
        assert_eq!(
            verifier.verify_signed_data_by_clock(b"a.b"),
            verifier.verify_signed_data(b"a.b", 0)
        );
        let answer = verifier.verify_receipt_endpoint_by_clock(Environment::Sandbox, b"{}");
        assert_eq!(answer, "{\"status\":21002}");
    }

    fn system_now() -> i64 {
        let since_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        i64::try_from(since_epoch.as_millis()).unwrap()
    }

    #[test]
    fn a_call_by_clock_reads_the_system_clock_when_the_input_needs_the_time() {
        // A receipt with no creation date is judged at the system clock.
        // Its chain is valid from 2024-01-01 to 2050-01-01, so this expects
        // a verified receipt only until then; a stand-in such as the epoch
        // falls outside it.
        let root = fixture("generated-0.7/divergence-receipt-root.der");
        let verifier = Verifier::new(&[root]).unwrap();
        let receipt = core_api::__internal::base64_encode(&fixture(
            "generated-0.7/receipt-no-creation-date.der",
        ));
        assert!(verifier.verify_receipt_by_clock(receipt.as_bytes()).is_ok());

        // A valid body's request_date is the system clock's time during the
        // call.
        let body = format!("{{\"receipt-data\":\"{receipt}\"}}");
        let before = system_now();
        let answer =
            verifier.verify_receipt_endpoint_by_clock(Environment::Sandbox, body.as_bytes());
        let after = system_now();
        assert!(answer.contains("\"status\":0"), "{answer}");
        let marker = "\"request_date_ms\":\"";
        let start = answer.find(marker).unwrap() + marker.len();
        let length = answer[start..].find('"').unwrap();
        let request_date: i64 = answer[start..start + length].parse().unwrap();
        assert!(
            (before..=after).contains(&request_date),
            "{before} <= {request_date} <= {after}"
        );
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
}
