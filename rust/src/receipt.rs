//! Verification of legacy PKCS#7 app receipts — the server-side port of
//! Apple's "Validating receipts on the device" procedure (`PLAN.md` §2.2).

use crate::base64::decode_lenient;
use crate::chain::build_and_validate_path;
use crate::cms::{find_message_digest_attribute, parse_cms, signed_attrs_signed_bytes, ParsedCms};
use crate::crypto::{constant_time_eq, verify_rsa_pkcs1, DigestAlgorithm};
use crate::datetime::unix_millis_of;
use crate::error::{ConfigError, CoreError, Reason, Result, VerificationError};
use crate::receipt_payload::parse_receipt_payload;
use crate::roots::{normalize_anchors, TrustAnchor};
use crate::x509::{Certificate, OID_RSA_ENCRYPTION};
use std::sync::Arc;
use std::time::SystemTime;

pub use crate::receipt_payload::{AppReceipt, InAppPurchase};

/// The Apple marker OID a receipt-signing leaf must carry.
///
/// Without this purpose check, **any** developer certificate chaining to the
/// same pinned root — every "Apple Distribution" and "Apple Development"
/// leaf goes through the same WWDR intermediate — could sign a fully forged
/// receipt. The chain check alone does not distinguish signer purpose
/// (`PLAN.md` D13).
pub const RECEIPT_SIGNER_OID: &str = "1.2.840.113635.100.6.11.1";

/// How many certificates a receipt may embed.
///
/// Genuine receipts carry one to three. Every embedded certificate is parsed
/// and then signature-checked as a candidate issuer *before* anything about
/// the receipt has been verified, so the bound is enforced before a single
/// certificate is decoded — it is a bound on parsing, not on the walk.
pub const MAX_EMBEDDED_CERTIFICATES: usize = 10;

/// The largest receipt this crate will look at.
///
/// A port-local defensive bound. The largest genuine receipt in the shared
/// fixture corpus is 79 KB with 187 in-app purchases, so this sits four
/// orders of magnitude above anything real and moves no verdict.
pub const MAX_RECEIPT_BYTES: usize = 8 * 1024 * 1024;

fn malformed(detail: impl Into<String>) -> VerificationError {
    VerificationError::new(Reason::InvalidReceiptFormat, detail)
}

/// Chain and signature verification **without** the bundle-id claim check.
///
/// This is the primitive under both [`ReceiptVerifier`] and the
/// `verifyReceipt`-compatible endpoint, which — like Apple's endpoint —
/// accepts a receipt from any bundle.
///
/// **You must check `bundle_id` yourself.** A caller that unlocks a product
/// on the strength of this function without comparing
/// [`AppReceipt::bundle_id`] will accept a genuine, correctly signed receipt
/// from a different app. Use [`ReceiptVerifier`] unless you have a reason
/// not to.
///
/// # Errors
/// [`CoreError::Verification`] naming the first check that failed, or
/// [`CoreError::Config`] when `trusted_roots` is empty.
///
/// An empty anchor set is a **configuration** failure, not a verdict: no
/// check ran, and reporting it as `INVALID_CHAIN` would make an
/// anchor-loading bug indistinguishable from a forgery. The builder-backed
/// [`ReceiptVerifier`] and the endpoint refuse it at construction instead,
/// so this arm is reachable only from this free function.
pub fn verify_receipt_core(
    der: &[u8],
    trusted_roots: &[TrustAnchor],
) -> core::result::Result<AppReceipt, CoreError> {
    if trusted_roots.is_empty() {
        return Err(CoreError::Config(ConfigError::new(
            "trustedRoots must not be empty",
        )));
    }
    Ok(verify_receipt_core_unchecked(der, trusted_roots)?)
}

/// [`verify_receipt_core`] with the anchor-set precondition already
/// established by the caller — the shape both verifier types use, and the
/// reason they can keep a plain [`VerificationError`] result.
pub(crate) fn verify_receipt_core_unchecked(
    der: &[u8],
    trusted_roots: &[TrustAnchor],
) -> Result<AppReceipt> {
    if der.is_empty() {
        return Err(malformed("receipt is empty"));
    }
    if der.len() > MAX_RECEIPT_BYTES {
        return Err(malformed("receipt exceeds the maximum accepted size"));
    }
    let cms = parse_cms(der).map_err(|err| malformed(format!("malformed CMS structure: {err}")))?;

    // Parsed before the signature is checked, and only to learn the creation
    // date: chain validity anchors at signing time. Nothing from it is
    // returned or acted on until every check below has passed.
    let fields = parse_receipt_payload(&cms.content)?;
    // A receipt with no creation date falls back to the SYSTEM clock, never
    // to an injected one: a caller injecting a clock — to test staleness, or
    // to work around skew — must not thereby accept an expired chain. That
    // is why the receipt path takes no clock option at all.
    let at_millis = fields
        .creation_date
        .map_or_else(|| unix_millis_of(SystemTime::now()), unix_millis_of);

    // The embedded certificates are attacker-supplied and are walked into a
    // path below, so a receipt carrying more of them than a chain can hold
    // is rejected here rather than decoded and searched.
    if cms.certificates.len() > MAX_EMBEDDED_CERTIFICATES {
        return Err(VerificationError::new(
            Reason::InvalidChain,
            format!("receipt embeds more than {MAX_EMBEDDED_CERTIFICATES} certificates"),
        ));
    }
    let mut embedded = Vec::with_capacity(cms.certificates.len());
    for raw in &cms.certificates {
        embedded.push(
            Certificate::from_der(raw)
                .map_err(|err| malformed(format!("embedded certificate is malformed: {err}")))?,
        );
    }
    let signer = embedded
        .iter()
        .find(|cert| {
            cert.serial_number() == cms.signer_info.serial_contents.as_slice()
                && cert.issuer_der() == cms.signer_info.issuer_raw.as_slice()
        })
        .ok_or_else(|| malformed("signer certificate not embedded"))?;

    build_and_validate_path(signer, &embedded, trusted_roots, at_millis)?;
    // Checked AFTER the chain, so a foreign chain still reports
    // INVALID_CHAIN rather than INVALID_CERTIFICATE_PURPOSE (`PLAN.md` D13).
    if !signer.has_extension(RECEIPT_SIGNER_OID) {
        return Err(VerificationError::new(
            Reason::InvalidCertificatePurpose,
            format!("receipt signer certificate lacks Apple receipt-signing marker OID {RECEIPT_SIGNER_OID}"),
        ));
    }
    verify_cms_signature(&cms, signer)?;
    Ok(fields)
}

fn verify_cms_signature(cms: &ParsedCms, signer: &Certificate) -> Result<()> {
    if signer.public_key_algorithm_oid() != OID_RSA_ENCRYPTION {
        return Err(VerificationError::new(
            Reason::InvalidSignature,
            "receipt signer key is not RSA",
        ));
    }
    let digest = cms.signer_info.digest;
    let valid = match &cms.signer_info.signed_attrs {
        Some(signed_attrs) => {
            let content_digest = digest.digest(&cms.content);
            let message_digest = find_message_digest_attribute(signed_attrs)
                .map_err(|err| malformed(format!("malformed CMS structure: {err}")))?;
            if !constant_time_eq(&message_digest, &content_digest) {
                return Err(VerificationError::new(
                    Reason::InvalidSignature,
                    "messageDigest attribute does not match content",
                ));
            }
            verify_rsa_pkcs1(
                signer.public_key_bits(),
                digest,
                &cms.signer_info.signature,
                &signed_attrs_signed_bytes(signed_attrs),
            )
        }
        None => verify_rsa_pkcs1(
            signer.public_key_bits(),
            digest,
            &cms.signer_info.signature,
            &cms.content,
        ),
    };
    if valid {
        Ok(())
    } else {
        Err(VerificationError::new(
            Reason::InvalidSignature,
            "CMS signature check failed",
        ))
    }
}

/// Builds a [`ReceiptVerifier`].
///
/// There is deliberately **no clock option**. The only "now" the receipt
/// path has is the certificate-validity instant a receipt without a creation
/// date falls back to, and an injected clock must never be able to move
/// that.
#[derive(Debug, Default, Clone)]
pub struct ReceiptVerifierBuilder {
    trusted_roots: Vec<TrustAnchor>,
    bundle_id: Option<String>,
}

impl ReceiptVerifierBuilder {
    /// The pinned trust anchors. In production, [`apple_receipt_roots`].
    ///
    /// [`apple_receipt_roots`]: crate::apple_receipt_roots
    #[must_use]
    pub fn trusted_roots(mut self, roots: impl IntoIterator<Item = TrustAnchor>) -> Self {
        self.trusted_roots.extend(roots);
        self
    }

    /// The bundle id the receipt must carry.
    #[must_use]
    pub fn bundle_id(mut self, bundle_id: impl Into<String>) -> Self {
        self.bundle_id = Some(bundle_id.into());
        self
    }

    /// Builds the verifier.
    ///
    /// # Errors
    /// [`ConfigError`] for empty trust anchors or an empty bundle id.
    pub fn build(self) -> core::result::Result<ReceiptVerifier, ConfigError> {
        let anchors = normalize_anchors(self.trusted_roots)?;
        let bundle_id = self
            .bundle_id
            .filter(|id| !id.is_empty())
            .ok_or_else(|| ConfigError::new("bundleId is required"))?;
        Ok(ReceiptVerifier { anchors, bundle_id })
    }
}

/// Verifies legacy PKCS#7 app receipts offline against pinned trust anchors.
///
/// ```no_run
/// use apple_purchase_receipt_verifier::{apple_receipt_roots, ReceiptVerifier};
///
/// let verifier = ReceiptVerifier::builder()
///     .trusted_roots(apple_receipt_roots().iter().cloned())
///     .bundle_id("com.example.app")
///     .build()?;
/// let receipt = verifier.verify_base64("MIIT...")?;
/// println!("{} purchases", receipt.in_app_purchases.len());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct ReceiptVerifier {
    anchors: Arc<[TrustAnchor]>,
    bundle_id: String,
}

impl ReceiptVerifier {
    /// A builder.
    #[must_use]
    pub fn builder() -> ReceiptVerifierBuilder {
        ReceiptVerifierBuilder::default()
    }

    /// Verifies a receipt in its DER form.
    ///
    /// # Errors
    /// A [`VerificationError`] naming the first check that failed.
    pub fn verify(&self, receipt: &[u8]) -> Result<AppReceipt> {
        let fields = verify_receipt_core_unchecked(receipt, &self.anchors)?;
        self.require_bundle_id(&fields)?;
        Ok(fields)
    }

    /// Verifies a receipt in its base64 form — the shape a client sends.
    ///
    /// # Errors
    /// As [`ReceiptVerifier::verify`].
    pub fn verify_base64(&self, receipt: &str) -> Result<AppReceipt> {
        self.verify(&decode_lenient(receipt))
    }

    /// Verifies a DER receipt and additionally enforces the device binding:
    /// `SHA1(guid ‖ opaqueValue ‖ bundleIdBytes)` must equal attribute 5
    /// (optional by design — `PLAN.md` D4).
    ///
    /// # Errors
    /// As [`ReceiptVerifier::verify`], plus
    /// [`Reason::DeviceHashMismatch`].
    pub fn verify_with_device_guid(
        &self,
        receipt: &[u8],
        device_guid: &[u8],
    ) -> Result<AppReceipt> {
        let fields = self.verify(receipt)?;
        verify_device_hash(&fields, device_guid)?;
        Ok(fields)
    }

    /// [`ReceiptVerifier::verify_with_device_guid`] for a base64 receipt.
    ///
    /// # Errors
    /// As [`ReceiptVerifier::verify_with_device_guid`].
    pub fn verify_base64_with_device_guid(
        &self,
        receipt: &str,
        device_guid: &[u8],
    ) -> Result<AppReceipt> {
        self.verify_with_device_guid(&decode_lenient(receipt), device_guid)
    }

    fn require_bundle_id(&self, fields: &AppReceipt) -> Result<()> {
        if fields.bundle_id.as_deref() == Some(self.bundle_id.as_str()) {
            return Ok(());
        }
        Err(VerificationError::new(
            Reason::WrongBundleId,
            format!(
                "expected {} but receipt has {}",
                self.bundle_id,
                fields.bundle_id.as_deref().unwrap_or("none")
            ),
        ))
    }
}

fn verify_device_hash(fields: &AppReceipt, device_guid: &[u8]) -> Result<()> {
    let (Some(opaque), Some(sha1), Some(bundle_id_bytes)) = (
        fields.opaque_value.as_deref(),
        fields.sha1_hash.as_deref(),
        fields.bundle_id_bytes.as_deref(),
    ) else {
        return Err(VerificationError::new(
            Reason::DeviceHashMismatch,
            "receipt lacks the attributes needed for the device-hash check",
        ));
    };
    let mut input = Vec::with_capacity(device_guid.len() + opaque.len() + bundle_id_bytes.len());
    input.extend_from_slice(device_guid);
    input.extend_from_slice(opaque);
    input.extend_from_slice(bundle_id_bytes);
    let computed = DigestAlgorithm::Sha1.digest(&input);
    if constant_time_eq(&computed, sha1) {
        Ok(())
    } else {
        Err(VerificationError::new(
            Reason::DeviceHashMismatch,
            "computed device hash does not match attribute 5",
        ))
    }
}
