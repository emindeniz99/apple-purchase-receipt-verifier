//! Spike only: the APRV receipt and JWS policy over the
//! `aprv-security-openssl` adapter. Copied into a scratch copy of the core
//! crate as `src/substrate.rs` by `scripts/build-variant.sh`, with
//! `core.patch` routing the two verification cores here when the
//! `substrate` feature is on. Nothing here is `unsafe` (the crate root
//! keeps `#![forbid(unsafe_code)]`).
//!
//! The order of checks and the Reason for each follow the Java verifier
//! (the semantic reference, and R20's policy): the library answers "is this
//! structurally a signedData / a certificate / a valid path / a valid
//! signature"; this file decides what that means for APRV.

use crate::datetime::unix_millis_of;
use crate::error::{Reason, Result, VerificationError};
use crate::jws::{invalid_jws, parse_json_segment, signed_at_millis_of, split_jws, Claims, INTERMEDIATE_OID, LEAF_OID};
use crate::receipt::{MAX_EMBEDDED_CERTIFICATES, RECEIPT_SIGNER_OID};
use crate::receipt_payload::{parse_receipt_payload, read_creation_date, AppReceipt};
use crate::roots::TrustAnchor;
use aprv_security_openssl as sub;
use std::time::SystemTime;

/// Anchor excluded: the target plus at most five intermediates.
const MAX_PATH_LENGTH: u32 = 6;

fn fail(reason: Reason, detail: impl Into<String>) -> VerificationError {
    VerificationError::new(reason, detail)
}

fn anchors_of(anchors: &[TrustAnchor]) -> Vec<sub::Certificate> {
    anchors
        .iter()
        .filter_map(|anchor| sub::Certificate::from_der(anchor.certificate().der()))
        .collect()
}

/// Path validation at a millisecond instant. The library judges validity
/// in whole seconds, so the path is validated at floor(ms) (which decides
/// notBefore exactly) and every non-anchor certificate's notAfter is then
/// held to ceil(ms).
fn validate_path(
    target: &sub::Certificate,
    untrusted: &[sub::Certificate],
    anchors: &[sub::Certificate],
    at_millis: i64,
    max_intermediates: u32,
) -> core::result::Result<Vec<sub::Certificate>, i32> {
    let floor = at_millis.div_euclid(1000);
    let ceil = floor + i64::from(at_millis.rem_euclid(1000) != 0);
    let chain = sub::verify_path(target, untrusted, anchors, floor, max_intermediates).map_err(|e| e.0)?;
    // The libraries count depth differently; the length is checked here too.
    if chain.len() > max_intermediates as usize + 2 {
        return Err(22);
    }
    let non_anchor = chain.len().saturating_sub(1);
    if chain.iter().take(non_anchor).any(|cert| !cert.not_after_at_least(ceil)) {
        return Err(10);
    }
    Ok(chain)
}

/// Java's `authenticatedTopDown`: the embedded certificates whose
/// signature verifies under a pinned anchor, or under a certificate already
/// accepted this way, walking down from the anchors for at most
/// `MAX_PATH_LENGTH` rounds. Only these reach path validation, so a bag
/// padded with look-alike issuers cannot steer the library's path builder
/// (OpenSSL takes the first issuer that matches by name and does not
/// backtrack).
fn authenticated_top_down(embedded: &[sub::Certificate], anchors: &[sub::Certificate]) -> Vec<sub::Certificate> {
    let mut issuers: Vec<sub::Certificate> = anchors.to_vec();
    let mut pending: Vec<sub::Certificate> = embedded.to_vec();
    let mut accepted = Vec::new();
    for _ in 0..MAX_PATH_LENGTH {
        if pending.is_empty() {
            break;
        }
        let (this_round, rest): (Vec<_>, Vec<_>) = pending
            .into_iter()
            .partition(|cert| issuers.iter().any(|issuer| cert.issued_by(issuer) == sub::Issued::Yes));
        pending = rest;
        if this_round.is_empty() {
            break;
        }
        accepted.extend(this_round.iter().cloned());
        issuers = this_round;
    }
    accepted
}

/// The legacy receipt core, after the size checks of
/// `verify_receipt_core_unchecked`.
pub(crate) fn verify_receipt(der: &[u8], trusted_roots: &[TrustAnchor]) -> Result<AppReceipt> {
    #[cfg(feature = "substrate-prescan")]
    crate::asn1::parse_exact(der)
        .map_err(|err| fail(Reason::InvalidReceiptFormat, format!("malformed CMS structure: {err}")))?;

    let mut cms = sub::SignedData::parse(der)
        .map_err(|err| fail(Reason::InvalidReceiptFormat, format!("not a PKCS#7 signedData: {err:?}")))?;
    // Java (Bouncy Castle) and the Rust core both refuse a SignerInfo
    // digest they cannot name while reading the structure.
    if !cms.signer_digest_known() {
        return Err(fail(Reason::InvalidReceiptFormat, "unsupported SignerInfo digest algorithm"));
    }
    let content = cms.content();
    let at_millis = read_creation_date(&content)
        .map_or_else(|| unix_millis_of(SystemTime::now()), unix_millis_of);

    let certificates = cms.certificates();
    if certificates.len() > MAX_EMBEDDED_CERTIFICATES {
        return Err(fail(
            Reason::InvalidChain,
            format!("receipt embeds more than {MAX_EMBEDDED_CERTIFICATES} certificates"),
        ));
    }
    // Java's decodeEmbeddedAndFindSigner: an unreadable signer is a
    // certificate defect, any other unreadable entry a receipt defect.
    let signer_index = cms.signer_index();
    let mut unreadable_signer = false;
    let mut unreadable_other = false;
    for (index, cert) in certificates.iter().enumerate() {
        if !cert.is_readable() {
            if Some(index) == signer_index {
                unreadable_signer = true;
            } else {
                unreadable_other = true;
            }
        }
    }
    if unreadable_signer {
        return Err(fail(Reason::InvalidCertificate, "receipt signer certificate does not decode"));
    }
    if unreadable_other {
        return Err(fail(Reason::InvalidReceiptFormat, "an embedded certificate is not a valid certificate"));
    }
    let signer = signer_index
        .and_then(|index| certificates.get(index))
        .cloned()
        .ok_or_else(|| fail(Reason::InvalidReceiptFormat, "signer certificate not embedded"))?;

    let anchors = anchors_of(trusted_roots);
    let authenticated = authenticated_top_down(&certificates, &anchors);
    // A signer a pinned root vouched for has its key decoded now (Java's
    // signerCert.getPublicKey() after authenticatedTopDown).
    if authenticated.iter().any(|c| c.same_as(&signer)) && signer.key_kind() == sub::KeyKind::Undecodable {
        return Err(fail(Reason::InvalidCertificate, "receipt signer certificate does not decode"));
    }
    // An issuer whose key does not decode vouches for nothing, so every
    // path failure is INVALID_CHAIN.
    validate_path(&signer, &authenticated, &anchors, at_millis, MAX_PATH_LENGTH - 1).map_err(|code| {
        fail(Reason::InvalidChain, format!("signer chain does not validate to a pinned root (X509_V_ERR {code})"))
    })?;
    if !signer.has_extension(RECEIPT_SIGNER_OID) {
        return Err(fail(
            Reason::InvalidCertificatePurpose,
            format!("receipt signer certificate lacks Apple receipt-signing marker OID {RECEIPT_SIGNER_OID}"),
        ));
    }

    // Bouncy Castle's RFC 5652 rules for signed attributes: both
    // contentType and messageDigest, each once and single-valued, and
    // contentType equal to eContentType. OpenSSL's own check reads only the
    // first messageDigest and does not require contentType.
    let attributes = cms.signed_attributes();
    if attributes.present
        && (attributes.content_type != (1, 1)
            || !attributes.content_type_matches
            || attributes.message_digest != (1, 1))
    {
        return Err(fail(Reason::InvalidSignature, "signed attributes break RFC 5652 section 5.3"));
    }
    if !cms.verify_first_signer(&signer) {
        return Err(fail(Reason::InvalidSignature, "CMS signature check failed"));
    }
    parse_receipt_payload(&content).map_err(|err| {
        fail(Reason::InternalError, format!("signed receipt content could not be read: {}", err.detail()))
    })
}

fn parse_x5c(entry: Option<&String>, index: usize) -> Result<sub::Certificate> {
    entry
        .and_then(|text| crate::base64::decode_receipt_base64(text))
        .and_then(|der| sub::Certificate::from_der(&der))
        .filter(sub::Certificate::is_readable)
        .ok_or_else(|| fail(Reason::InvalidCertificate, format!("x5c[{index}] does not decode")))
}

/// The JWS core: everything `JwsVerifier::verify_signature` does.
pub(crate) fn verify_jws(jws: &str, trusted_roots: &[TrustAnchor]) -> Result<Claims> {
    let segments = split_jws(jws)?;
    let leaf = parse_x5c(segments.x5c.first(), 0)?;
    let intermediate = parse_x5c(segments.x5c.get(1), 1)?;
    parse_x5c(segments.x5c.get(2), 2)?;
    if !leaf.has_extension(LEAF_OID) {
        return Err(fail(Reason::InvalidCertificatePurpose, format!("leaf certificate lacks Apple marker OID {LEAF_OID}")));
    }
    if !intermediate.has_extension(INTERMEDIATE_OID) {
        return Err(fail(
            Reason::InvalidCertificatePurpose,
            format!("intermediate certificate lacks Apple marker OID {INTERMEDIATE_OID}"),
        ));
    }
    let payload = parse_json_segment(segments.payload_b64, "payload")?;
    let signed_at = signed_at_millis_of(&payload)?;
    let at_millis = signed_at.unwrap_or_else(|| unix_millis_of(SystemTime::now()));

    // Java's authenticateTopDown: x5c[1] under a pinned root, its key,
    // x5c[0] under x5c[1], its key. Each key is decoded only once the
    // certificate above has vouched for it.
    let anchors = anchors_of(trusted_roots);
    if !anchors.iter().any(|root| intermediate.issued_by(root) == sub::Issued::Yes) {
        return Err(fail(Reason::InvalidChain, "intermediate certificate is not signed by a pinned root"));
    }
    match leaf.issued_by(&intermediate) {
        sub::Issued::Yes => {}
        sub::Issued::IssuerKeyUndecodable => return Err(fail(Reason::InvalidCertificate, "x5c[1] does not decode")),
        sub::Issued::No => return Err(fail(Reason::InvalidChain, "leaf certificate is not signed by the intermediate")),
    }
    if leaf.key_kind() == sub::KeyKind::Undecodable {
        return Err(fail(Reason::InvalidCertificate, "x5c[0] does not decode"));
    }
    let chain = validate_path(&leaf, std::slice::from_ref(&intermediate), &anchors, at_millis, 1).map_err(|code| {
        fail(Reason::InvalidChain, format!("certificate chain does not validate to a pinned root (X509_V_ERR {code})"))
    })?;
    // Exactly leaf -> x5c[1] -> anchor, the path Java validates.
    if chain.len() != 3 || !chain.get(1).is_some_and(|c| c.same_as(&intermediate)) {
        return Err(fail(Reason::InvalidChain, "path is not leaf, x5c[1], pinned root"));
    }
    let Some(signature) = crate::base64::decode_base64url_strict(segments.signature_b64) else {
        return Err(invalid_jws("signature segment is not canonical base64url"));
    };
    if signature.len() != 64 {
        return Err(fail(Reason::InvalidSignature, format!("ES256 signature must be 64 bytes, got {}", signature.len())));
    }
    let mut signing_input = Vec::with_capacity(segments.header_b64.len() + 1 + segments.payload_b64.len());
    signing_input.extend_from_slice(segments.header_b64.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(segments.payload_b64.as_bytes());
    if !sub::verify_es256(&leaf, &signature, &signing_input) {
        return Err(fail(Reason::InvalidSignature, "ES256 signature check failed"));
    }
    Ok(payload)
}
