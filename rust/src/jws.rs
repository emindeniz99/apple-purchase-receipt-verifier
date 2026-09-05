//! Verification of Apple-signed JWS payloads: `StoreKit` 2
//! `jwsRepresentation`, `signedTransactionInfo` / `signedRenewalInfo`, and
//! App Store Server Notifications V2.
//!
//! The order of the checks is observable and normative — a payload that
//! fails an early check must report that check's reason, not a later one.
//! `PLAN.md` §2.1 and `fixtures/cases.json` pin it.

use crate::base64::{decode_base64url_strict, decode_lenient};
use crate::chain::validate_pair;
use crate::clock::{default_clock, unix_millis, Clock};
use crate::crypto::{curve_field_size, verify_es256};
use crate::environment::Environment;
use crate::error::{ConfigError, Reason, Result, VerificationError};
use crate::roots::{normalize_anchors, TrustAnchor};
use crate::x509::{Certificate, OID_EC_PUBLIC_KEY};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Apple marker OID: a leaf certificate used for App Store signing.
pub const LEAF_OID: &str = "1.2.840.113635.100.6.11.1";
/// Apple marker OID: the Worldwide Developer Relations intermediate CA.
pub const INTERMEDIATE_OID: &str = "1.2.840.113635.100.6.2.1";

/// The raw claim set of a verified payload.
///
/// Apple's payloads are JSON objects, and every claim — modelled or not —
/// is reachable here.
pub type Claims = Map<String, Value>;

fn string_claim(claims: &Claims, key: &str) -> Option<String> {
    claims.get(key)?.as_str().map(str::to_owned)
}

/// An integer-valued claim.
///
/// Apple ships its date claims as JSON integers, and `as_i64` alone reads
/// those. It is deliberately not the whole rule: `as_i64` answers `None` for
/// a JSON number spelled `1.0` or `1.7e12`, which is the *same value*
/// differently written, and all four shipped ports read those as numbers —
/// Java `canConvertToLong()` (true for a `DoubleNode` in long range), Node
/// `typeof === 'number'`, Python `isinstance(x, (int, float))`, Swift
/// `as? Double`. Rust reading them as absent made two things go wrong in the
/// open direction: the certificate-validity instant fell back to the system
/// clock instead of the stated signing time, and
/// [`TransactionPayload::is_active_at`] reported a revoked or expired
/// transaction as still entitling.
///
/// A number outside `i64` stays `None`, which is what Java's
/// `canConvertToLong()` also answers, rather than being clamped to a
/// sentinel this crate would then act on.
fn int_claim(claims: &Claims, key: &str) -> Option<i64> {
    let value = claims.get(key)?;
    if let Some(exact) = value.as_i64() {
        return Some(exact);
    }
    let number = value.as_f64()?;
    if !number.is_finite() {
        return None;
    }
    // The bounds are exclusive because i64::MIN/MAX are not exactly
    // representable as f64; the neighbouring powers of two are.
    if number < -(2f64.powi(63)) || number >= 2f64.powi(63) {
        return None;
    }
    #[allow(clippy::cast_possible_truncation)]
    Some(number.trunc() as i64)
}

/// A verified `JWSTransactionDecodedPayload`.
///
/// **Apple's date claims stay epoch-millisecond integers**, exactly as Apple
/// ships them. This is contractual across all nine ports, and it is not an
/// oversight to be "improved" into a date type: converting loses the raw
/// claim, invites a timezone bug, and makes two ports disagree about what
/// the same payload says. Only *receipt attribute* dates become
/// [`SystemTime`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct TransactionPayload {
    /// Every claim in the payload, including the ones modelled below.
    pub claims: Claims,
    /// `bundleId`
    pub bundle_id: Option<String>,
    /// `environment`
    pub environment: Option<String>,
    /// `productId`
    pub product_id: Option<String>,
    /// `transactionId`
    pub transaction_id: Option<String>,
    /// `originalTransactionId`
    pub original_transaction_id: Option<String>,
    /// `webOrderLineItemId`
    pub web_order_line_item_id: Option<String>,
    /// `subscriptionGroupIdentifier`
    pub subscription_group_identifier: Option<String>,
    /// `appAccountToken`
    pub app_account_token: Option<String>,
    /// `inAppOwnershipType`
    pub in_app_ownership_type: Option<String>,
    /// `type`
    pub transaction_type: Option<String>,
    /// `transactionReason`
    pub transaction_reason: Option<String>,
    /// `storefront`
    pub storefront: Option<String>,
    /// `currency`
    pub currency: Option<String>,
    /// `offerIdentifier`
    pub offer_identifier: Option<String>,
    /// `signedDate`, epoch milliseconds.
    pub signed_date: Option<i64>,
    /// `purchaseDate`, epoch milliseconds.
    pub purchase_date: Option<i64>,
    /// `originalPurchaseDate`, epoch milliseconds.
    pub original_purchase_date: Option<i64>,
    /// `expiresDate`, epoch milliseconds.
    pub expires_date: Option<i64>,
    /// `revocationDate`, epoch milliseconds.
    pub revocation_date: Option<i64>,
    /// `price`
    pub price: Option<i64>,
    /// `quantity`
    pub quantity: Option<i64>,
    /// `offerType`
    pub offer_type: Option<i64>,
    /// `revocationReason`
    pub revocation_reason: Option<i64>,
}

impl TransactionPayload {
    /// The modelled view of a claim set.
    ///
    /// **Verifies nothing.** It is for claims that were *already* verified
    /// and came back untyped — [`JwsVerifier::verify_raw`] returns
    /// [`Claims`] for notification envelopes and renewal info, and the
    /// transaction inside one of those is an ordinary transaction claim set
    /// that a caller then wants the modelled fields of. Passing it claims
    /// that no verifier produced models an unverified payload, which is
    /// exactly as meaningful as the JSON was.
    #[must_use]
    pub fn from_claims(claims: Claims) -> Self {
        TransactionPayload {
            bundle_id: string_claim(&claims, "bundleId"),
            environment: string_claim(&claims, "environment"),
            product_id: string_claim(&claims, "productId"),
            transaction_id: string_claim(&claims, "transactionId"),
            original_transaction_id: string_claim(&claims, "originalTransactionId"),
            web_order_line_item_id: string_claim(&claims, "webOrderLineItemId"),
            subscription_group_identifier: string_claim(&claims, "subscriptionGroupIdentifier"),
            app_account_token: string_claim(&claims, "appAccountToken"),
            in_app_ownership_type: string_claim(&claims, "inAppOwnershipType"),
            transaction_type: string_claim(&claims, "type"),
            transaction_reason: string_claim(&claims, "transactionReason"),
            storefront: string_claim(&claims, "storefront"),
            currency: string_claim(&claims, "currency"),
            offer_identifier: string_claim(&claims, "offerIdentifier"),
            signed_date: int_claim(&claims, "signedDate"),
            purchase_date: int_claim(&claims, "purchaseDate"),
            original_purchase_date: int_claim(&claims, "originalPurchaseDate"),
            expires_date: int_claim(&claims, "expiresDate"),
            revocation_date: int_claim(&claims, "revocationDate"),
            price: int_claim(&claims, "price"),
            quantity: int_claim(&claims, "quantity"),
            offer_type: int_claim(&claims, "offerType"),
            revocation_reason: int_claim(&claims, "revocationReason"),
            claims,
        }
    }

    /// Whether this transaction still entitles the user at `now`: not
    /// revoked, and — for a subscription — not expired.
    ///
    /// Point-in-time on the *signed claims only*. A refund or a renewal that
    /// happened after this payload was signed is invisible to it; callers
    /// that need current state must ask Apple's server API.
    #[must_use]
    pub fn is_active_at(&self, now: SystemTime) -> bool {
        let now_millis = unix_millis(now);
        if let Some(revoked) = self.revocation_date {
            if now_millis >= revoked {
                return false;
            }
        }
        match self.expires_date {
            Some(expires) => now_millis < expires,
            None => true,
        }
    }
}

/// A verified `AppTransaction`.
///
/// Its environment lives in `receiptType`, and its date claims are epoch
/// milliseconds for the same reason [`TransactionPayload`]'s are.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct AppTransactionPayload {
    /// Every claim in the payload.
    pub claims: Claims,
    /// `bundleId`
    pub bundle_id: Option<String>,
    /// `receiptType` — the environment, spelled as an environment is.
    pub receipt_type: Option<String>,
    /// `applicationVersion`
    pub application_version: Option<String>,
    /// `originalApplicationVersion`
    pub original_application_version: Option<String>,
    /// `deviceVerification`
    pub device_verification: Option<String>,
    /// `deviceVerificationNonce`
    pub device_verification_nonce: Option<String>,
    /// `appTransactionId`
    pub app_transaction_id: Option<String>,
    /// `appAppleId`
    pub app_apple_id: Option<i64>,
    /// `receiptCreationDate`, epoch milliseconds.
    pub receipt_creation_date: Option<i64>,
    /// `originalPurchaseDate`, epoch milliseconds.
    pub original_purchase_date: Option<i64>,
    /// `preorderDate`, epoch milliseconds.
    pub preorder_date: Option<i64>,
    /// `versionExternalIdentifier`
    pub version_external_identifier: Option<i64>,
}

impl AppTransactionPayload {
    /// The modelled view of a claim set. Verifies nothing; see
    /// [`TransactionPayload::from_claims`].
    #[must_use]
    pub fn from_claims(claims: Claims) -> Self {
        AppTransactionPayload {
            bundle_id: string_claim(&claims, "bundleId"),
            receipt_type: string_claim(&claims, "receiptType"),
            application_version: string_claim(&claims, "applicationVersion"),
            original_application_version: string_claim(&claims, "originalApplicationVersion"),
            device_verification: string_claim(&claims, "deviceVerification"),
            device_verification_nonce: string_claim(&claims, "deviceVerificationNonce"),
            app_transaction_id: string_claim(&claims, "appTransactionId"),
            app_apple_id: int_claim(&claims, "appAppleId"),
            receipt_creation_date: int_claim(&claims, "receiptCreationDate"),
            original_purchase_date: int_claim(&claims, "originalPurchaseDate"),
            preorder_date: int_claim(&claims, "preorderDate"),
            version_external_identifier: int_claim(&claims, "versionExternalIdentifier"),
            claims,
        }
    }
}

/// Builds a [`JwsVerifier`].
#[derive(Debug, Default, Clone)]
pub struct JwsVerifierBuilder {
    trusted_roots: Vec<TrustAnchor>,
    bundle_id: Option<String>,
    accepted_environments: BTreeSet<Environment>,
    app_apple_id: Option<u64>,
    max_signed_age: Option<Duration>,
    clock: Option<Arc<dyn Clock>>,
}

impl JwsVerifierBuilder {
    /// The pinned trust anchors. In production, [`apple_jws_roots`].
    ///
    /// [`apple_jws_roots`]: crate::apple_jws_roots
    #[must_use]
    pub fn trusted_roots(mut self, roots: impl IntoIterator<Item = TrustAnchor>) -> Self {
        self.trusted_roots.extend(roots);
        self
    }

    /// The bundle id every payload must carry.
    #[must_use]
    pub fn bundle_id(mut self, bundle_id: impl Into<String>) -> Self {
        self.bundle_id = Some(bundle_id.into());
        self
    }

    /// The environments a payload may name.
    ///
    /// Include [`Environment::Sandbox`] on endpoints App Review can reach:
    /// App Review runs production builds against sandbox (`PLAN.md` D3).
    #[must_use]
    pub fn accepted_environments(
        mut self,
        environments: impl IntoIterator<Item = Environment>,
    ) -> Self {
        self.accepted_environments.extend(environments);
        self
    }

    /// The app's Apple id — required to accept a Production `AppTransaction`.
    #[must_use]
    pub fn app_apple_id(mut self, app_apple_id: u64) -> Self {
        self.app_apple_id = Some(app_apple_id);
        self
    }

    /// Reject payloads signed longer ago than this (`PLAN.md` D5).
    #[must_use]
    pub fn max_signed_age(mut self, max_signed_age: Duration) -> Self {
        self.max_signed_age = Some(max_signed_age);
        self
    }

    /// The source of "now" for the staleness rule — and for nothing else.
    ///
    /// Certificate validity is never judged at this clock.
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Builds the verifier.
    ///
    /// # Errors
    /// [`ConfigError`] for empty trust anchors, an empty bundle id or an
    /// empty accepted-environment set. Misconfiguration is a programming
    /// mistake, not a verification verdict, so it is never a
    /// [`VerificationError`].
    pub fn build(self) -> core::result::Result<JwsVerifier, ConfigError> {
        let anchors = normalize_anchors(self.trusted_roots)?;
        let bundle_id = self
            .bundle_id
            .filter(|id| !id.is_empty())
            .ok_or_else(|| ConfigError::new("bundleId is required"))?;
        if self.accepted_environments.is_empty() {
            return Err(ConfigError::new("acceptedEnvironments must not be empty"));
        }
        Ok(JwsVerifier {
            anchors,
            bundle_id,
            accepted_environments: self.accepted_environments,
            app_apple_id: self.app_apple_id,
            max_signed_age: self.max_signed_age,
            clock: self.clock.unwrap_or_else(default_clock),
        })
    }
}

/// Verifies Apple-signed JWS payloads, entirely offline, against pinned
/// trust anchors.
///
/// ```no_run
/// use apple_purchase_receipt_verifier::{apple_jws_roots, Environment, JwsVerifier};
///
/// let verifier = JwsVerifier::builder()
///     .trusted_roots(apple_jws_roots().iter().cloned())
///     .bundle_id("com.example.app")
///     .accepted_environments([Environment::Production, Environment::Sandbox])
///     .build()?;
/// let payload = verifier.verify_transaction("eyJhbGci...")?;
/// println!("{:?}", payload.product_id);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct JwsVerifier {
    anchors: Arc<[TrustAnchor]>,
    bundle_id: String,
    accepted_environments: BTreeSet<Environment>,
    app_apple_id: Option<u64>,
    max_signed_age: Option<Duration>,
    clock: Arc<dyn Clock>,
}

struct Segments<'a> {
    header_b64: &'a str,
    payload_b64: &'a str,
    signature_b64: &'a str,
    x5c: Vec<String>,
}

impl JwsVerifier {
    /// A builder.
    #[must_use]
    pub fn builder() -> JwsVerifierBuilder {
        JwsVerifierBuilder::default()
    }

    /// Verifies a signed transaction, then checks bundle id and environment.
    ///
    /// # Errors
    /// A [`VerificationError`] whose [`reason`](VerificationError::reason)
    /// names the first check that failed.
    pub fn verify_transaction(&self, jws: &str) -> Result<TransactionPayload> {
        let claims = self.verify_signature(jws)?;
        let payload = TransactionPayload::from_claims(claims);
        self.require_bundle_id(payload.bundle_id.as_deref())?;
        self.require_accepted_environment(payload.environment.as_deref())?;
        Ok(payload)
    }

    /// Verifies a signed `AppTransaction`, then checks bundle id,
    /// environment (`receiptType`) and — in Production — the app Apple id.
    ///
    /// # Errors
    /// As [`JwsVerifier::verify_transaction`].
    pub fn verify_app_transaction(&self, jws: &str) -> Result<AppTransactionPayload> {
        let claims = self.verify_signature(jws)?;
        let payload = AppTransactionPayload::from_claims(claims);
        self.require_bundle_id(payload.bundle_id.as_deref())?;
        let environment = self.require_accepted_environment(payload.receipt_type.as_deref())?;
        self.require_app_apple_id(environment, payload.app_apple_id)?;
        Ok(payload)
    }

    /// Verifies the chain and signature only, and returns every claim.
    ///
    /// For payload types with no dedicated model — renewal info,
    /// notification envelopes. **No claim is enforced**: the caller must
    /// check bundle id, environment and app Apple id itself.
    ///
    /// # Errors
    /// A [`VerificationError`] for a format, certificate, chain, signature
    /// or staleness failure. Never a claim failure.
    pub fn verify_raw(&self, jws: &str) -> Result<Claims> {
        self.verify_signature(jws)
    }

    fn verify_signature(&self, jws: &str) -> Result<Claims> {
        let segments = split_jws(jws)?;
        let leaf = parse_x5c_certificate(segments.x5c.first())?;
        let intermediate = parse_x5c_certificate(segments.x5c.get(1))?;
        // Parsed and then dropped: the third entry is trusted by nobody, and
        // reading it decides only whether it IS a certificate.
        parse_x5c_certificate(segments.x5c.get(2))?;
        // The marker OIDs are checked BEFORE the chain on the JWS path.
        // `cases.json` uses roots under which the chain would otherwise
        // validate, so the order is what the reason depends on.
        if !leaf.has_extension(LEAF_OID) {
            return Err(VerificationError::new(
                Reason::InvalidCertificatePurpose,
                format!("leaf certificate lacks Apple marker OID {LEAF_OID}"),
            ));
        }
        if !intermediate.has_extension(INTERMEDIATE_OID) {
            return Err(VerificationError::new(
                Reason::InvalidCertificatePurpose,
                format!("intermediate certificate lacks Apple marker OID {INTERMEDIATE_OID}"),
            ));
        }

        let payload = parse_json_segment(segments.payload_b64, "payload")?;
        // Chain validity is judged at the payload's signing date, so a
        // payload signed with a since-rotated certificate keeps verifying.
        // Where the payload states no date, the fallback reads the SYSTEM
        // clock — never `self.clock`, which a caller controls.
        let signed_at_millis = signed_at_millis_of(&payload)?;
        let effective = signed_at_millis.unwrap_or_else(|| unix_millis(SystemTime::now()));
        validate_pair(&leaf, &intermediate, &self.anchors, effective)?;

        if leaf.public_key_algorithm_oid() != OID_EC_PUBLIC_KEY {
            return Err(VerificationError::new(
                Reason::InvalidSignature,
                "leaf key is not EC",
            ));
        }
        // Strict, not lenient: see `base64`. Node and Python decode this
        // segment leniently and so accept junk appended to it; Java and
        // Swift reject it. The lenient reading makes one Apple-signed
        // transaction have unboundedly many accepted wire forms, so an
        // integrator deduping on the JWS string is defeated by one
        // character.
        //
        // A segment that isn't canonical base64url is a *format* failure,
        // decided before any cryptography runs — the same class as a header
        // that isn't base64url JSON, not a cryptographic verdict on a
        // signature that was actually checked.
        let Some(signature) = decode_base64url_strict(segments.signature_b64) else {
            return Err(invalid_jws("signature segment is not canonical base64url"));
        };
        if signature.len() != 64 {
            return Err(VerificationError::new(
                Reason::InvalidSignature,
                format!("ES256 signature must be 64 bytes, got {}", signature.len()),
            ));
        }
        let mut signing_input =
            Vec::with_capacity(segments.header_b64.len() + 1 + segments.payload_b64.len());
        signing_input.extend_from_slice(segments.header_b64.as_bytes());
        signing_input.push(b'.');
        signing_input.extend_from_slice(segments.payload_b64.as_bytes());
        if !verify_es256(leaf.public_key_bits(), &signature, &signing_input) {
            return Err(VerificationError::new(
                Reason::InvalidSignature,
                "ES256 signature check failed",
            ));
        }

        self.require_fresh(signed_at_millis)?;
        Ok(payload)
    }

    fn require_bundle_id(&self, actual: Option<&str>) -> Result<()> {
        if actual == Some(self.bundle_id.as_str()) {
            return Ok(());
        }
        Err(VerificationError::new(
            Reason::WrongBundleId,
            format!(
                "expected {} but payload has {}",
                self.bundle_id,
                actual.unwrap_or("none")
            ),
        ))
    }

    fn require_accepted_environment(&self, claim: Option<&str>) -> Result<Environment> {
        let environment = claim.and_then(Environment::from_claim);
        match environment {
            Some(environment) if self.accepted_environments.contains(&environment) => {
                Ok(environment)
            }
            _ => Err(VerificationError::new(
                Reason::WrongEnvironment,
                format!(
                    "payload environment {} not in accepted set",
                    claim.unwrap_or("none")
                ),
            )),
        }
    }

    fn require_app_apple_id(&self, environment: Environment, actual: Option<i64>) -> Result<()> {
        if environment != Environment::Production {
            return Ok(());
        }
        let expected = self.app_apple_id.and_then(|id| i64::try_from(id).ok());
        if expected.is_some() && expected == actual {
            return Ok(());
        }
        Err(VerificationError::new(
            Reason::WrongAppAppleId,
            "production payload does not name the configured app Apple id",
        ))
    }

    /// The one check that legitimately moves with wall-clock time, and so
    /// the one the injected clock drives.
    fn require_fresh(&self, signed_at_millis: Option<i64>) -> Result<()> {
        let (Some(max_age), Some(signed_at)) = (self.max_signed_age, signed_at_millis) else {
            return Ok(());
        };
        let now = unix_millis(self.clock.now());
        let max_millis = i64::try_from(max_age.as_millis()).unwrap_or(i64::MAX);
        if now.saturating_sub(signed_at) > max_millis {
            return Err(VerificationError::new(
                Reason::StalePayload,
                "payload was signed longer ago than the configured maximum",
            ));
        }
        Ok(())
    }
}

/// When the payload says it was signed, in epoch milliseconds:
/// `signedDate` for transactions, `receiptCreationDate` for
/// `AppTransaction`s, `None` when it says neither.
///
/// A claim that IS a number but does not fit an `i64` — `1e300`, say — is an
/// error rather than a `None`: reporting it absent falls through to the
/// current-time anchor in the caller, which hands an attacker the instant the
/// certificate windows are judged at. An instant no calendar can express is
/// inside no window, so it is a chain failure.
fn signed_at_millis_of(claims: &Claims) -> Result<Option<i64>> {
    for key in ["signedDate", "receiptCreationDate"] {
        let Some(value) = claims.get(key) else {
            continue;
        };
        if !value.is_number() {
            continue;
        }
        return int_claim(claims, key).map(Some).ok_or_else(|| {
            VerificationError::new(
                Reason::InvalidChain,
                format!("payload signing date {value} is not a valid instant"),
            )
        });
    }
    Ok(None)
}

fn invalid_jws(detail: impl Into<String>) -> VerificationError {
    VerificationError::new(Reason::InvalidJwsFormat, detail)
}

fn split_jws(jws: &str) -> Result<Segments<'_>> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid_jws(format!(
            "expected 3 dot-separated segments, got {}",
            parts.len()
        )));
    }
    let (Some(header_b64), Some(payload_b64), Some(signature_b64)) =
        (parts.first(), parts.get(1), parts.get(2))
    else {
        return Err(invalid_jws("expected 3 dot-separated segments"));
    };
    let header = parse_json_segment(header_b64, "header")?;
    if header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err(invalid_jws("alg must be ES256"));
    }
    let x5c = match header.get("x5c").and_then(Value::as_array) {
        Some(entries) if entries.len() == 3 => {
            let strings: Vec<String> = entries
                .iter()
                .filter_map(|e| e.as_str().map(str::to_owned))
                .collect();
            if strings.len() != 3 {
                return Err(invalid_jws("x5c must contain exactly 3 certificates"));
            }
            strings
        }
        _ => return Err(invalid_jws("x5c must contain exactly 3 certificates")),
    };
    Ok(Segments {
        header_b64,
        payload_b64,
        signature_b64,
        x5c,
    })
}

fn parse_json_segment(segment: &str, what: &str) -> Result<Claims> {
    let error = || invalid_jws(format!("{what} is not valid base64url JSON"));
    let bytes = decode_base64url_strict(segment).ok_or_else(error)?;
    // `from_utf8_lossy` rather than a UTF-8 error: a replacement character
    // is not valid JSON either, so the input is refused all the same, and
    // this keeps one failure path instead of two.
    let text = String::from_utf8_lossy(&bytes);
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(error()),
    }
}

/// `x5c[2]` is parsed like the other two and then discarded: it is never
/// compared to an anchor and never trusted, so swapping in a stranger's
/// root still changes nothing. Reading it settles only whether the entry is
/// a certificate at all — the differential the ports carried until
/// `transaction/reject-x5c-root-that-is-not-a-certificate` pinned java's
/// answer for all nine.
///
/// The entry itself is decoded leniently, not strictly: it is a certificate
/// container, the same input Java hands to its MIME decoder and Swift to
/// `.ignoreUnknownCharacters`, and it is not part of the signing input.
fn parse_x5c_certificate(entry: Option<&String>) -> Result<Certificate> {
    let Some(entry) = entry else {
        return Err(VerificationError::new(
            Reason::InvalidCertificate,
            "x5c entry is not a valid certificate",
        ));
    };
    let certificate = Certificate::from_der(&decode_lenient(entry)).map_err(|_| {
        VerificationError::new(
            Reason::InvalidCertificate,
            "x5c entry is not a valid certificate",
        )
    })?;
    // An EC key on a curve this crate does not implement is a defect of the
    // certificate, not of the path it sits on: there is no key to check an
    // issuance against. Left to the chain it reads as INVALID_CHAIN, while
    // java, swift and go refuse the certificate in their decoders — the
    // reading the shared vector pins, so that no port defers a rejection
    // another already makes.
    if certificate.public_key_algorithm_oid() == OID_EC_PUBLIC_KEY
        && certificate
            .public_key_curve_oid()
            .and_then(curve_field_size)
            .is_none()
    {
        return Err(VerificationError::new(
            Reason::InvalidCertificate,
            "x5c entry uses an unimplemented elliptic curve",
        ));
    }
    Ok(certificate)
}
