//! [`Verifier::verify_receipt`](crate::Verifier::verify_receipt): legacy
//! PKCS#7 app receipts, verified offline.

use crate::base64::decode_receipt_base64;
use crate::error::{malformed, Failure, Reason};
use crate::path::{authenticated_top_down, receipt_path};
use crate::receipt_payload::{
    parse_receipt_payload, read_creation_date, ReceiptPayload, MAX_ASN1_DEPTH,
};
use crate::roots::{TrustAnchor, SIGNING_LEAF_OID, WWDR_INTERMEDIATE_OID};
use crate::verifier::{self, Clock, Stage};
use aprv_openssl::{envelope_members, Certificate, SignedData};

/// How many certificates a receipt may embed. Every embedded certificate is
/// parsed and then tried as an issuer before anything about the receipt is
/// verified, so the bound is enforced before a single one is decoded.
pub(crate) const MAX_EMBEDDED_CERTIFICATES: usize = 10;

/// How many `SignerInfo`s a receipt may carry. A fifth is refused before any
/// signature is checked.
pub(crate) const MAX_SIGNER_INFOS: usize = 4;

/// The depth of a `SignerInfo`'s attribute values in the CMS envelope,
/// counting the `ContentInfo` as 1: `ContentInfo`, `[0]`, `SignedData`,
/// the `signerInfos` SET, the `SignerInfo`, the `[0]` or `[1]` attribute
/// set, the attribute SEQUENCE and its SET of values are 1 to 8.
const ATTRIBUTE_VALUE_BASE: usize = 8;

/// The depth of a `SignerInfo`'s algorithm parameters: its
/// `AlgorithmIdentifier` SEQUENCE is 6.
const ALGORITHM_PARAMETER_BASE: usize = 6;

/// The largest receipt string, in UTF-8 bytes: 3 MiB, Apple's own request
/// limit, checked before anything is decoded. No receipt Apple accepts can
/// be larger than the request that carries it.
pub(crate) const MAX_RECEIPT_BYTES: usize = 3_145_728;

/// Verifies a receipt in its base64 form, the shape a client sends, and
/// decodes its payload.
///
/// `clock` gives the chain instant when the receipt's first attribute 12
/// is missing or does not parse, and is read only then, once a signer has
/// been found.
pub(crate) fn verify(
    base64: &str,
    anchors: &[TrustAnchor],
    clock: &Clock<'_>,
) -> Result<ReceiptPayload, Failure> {
    if base64.is_empty() {
        return Err(malformed("receipt is empty"));
    }
    // Before the decode, which would otherwise allocate the bytes it decodes
    // to.
    if base64.len() > MAX_RECEIPT_BYTES {
        return Err(Failure::new(
            Reason::TooLarge,
            format!("receipt exceeds the maximum accepted size of {MAX_RECEIPT_BYTES} bytes"),
        ));
    }
    let der =
        decode_receipt_base64(base64).ok_or_else(|| malformed("receipt is not valid base64"))?;
    let content = verify_signature(&der, anchors, clock)?;
    verifier::enter(Stage::PayloadParse);
    // A trusted signer signed these bytes, so a payload this crate cannot
    // read is the library's failure or a format Apple added, not the
    // client's: UNREADABLE_PAYLOAD, never MALFORMED, which the endpoint
    // answers as 21002 and an app server reads as "deny".
    let payload = parse_receipt_payload(&content).map_err(|err| {
        Failure::new(
            Reason::UnreadablePayload,
            "signed receipt content could not be read",
        )
        .with_source(err)
    });
    verifier::enter(Stage::AfterSignature);
    payload
}

/// The `SignerInfo` and embedded-certificate bounds.
fn within_member_bounds(signer_infos: usize, certificates: usize) -> Result<(), Failure> {
    if signer_infos > MAX_SIGNER_INFOS {
        return Err(malformed(format!(
            "receipt carries {signer_infos} SignerInfos, more than the maximum of {MAX_SIGNER_INFOS}"
        )));
    }
    if certificates > MAX_EMBEDDED_CERTIFICATES {
        return Err(malformed(format!(
            "receipt embeds {certificates} certificates, more than the maximum of {MAX_EMBEDDED_CERTIFICATES}"
        )));
    }
    Ok(())
}

/// Every check up to and including a signature; returns the signed payload,
/// not yet decoded.
fn verify_signature(
    der: &[u8],
    anchors: &[TrustAnchor],
    clock: &Clock<'_>,
) -> Result<Vec<u8>, Failure> {
    // Bounded first, from a shallow decode that keeps every member as its
    // raw bytes: the full decode below builds each embedded certificate's
    // public key, and an unverified receipt would otherwise get to make the
    // caller pay for a thousand of them before a single one is judged or
    // tried as an issuer. A blob without that shape is left to the full
    // decode to name, and the bounds are checked again on what it found.
    if let Some(members) = envelope_members(der) {
        within_member_bounds(members.signer_infos, members.certificates)?;
    }
    let mut cms = SignedData::parse(der)
        .map_err(|err| malformed(format!("malformed CMS structure: {err}")))?;
    let signer_count = cms.signer_count();
    let certificates = cms.certificates();
    within_member_bounds(signer_count, certificates.len())?;

    // The ASN.1 depth bound, for the values OpenSSL keeps whole without
    // looking inside (attribute values, algorithm parameters): unsigned
    // attributes are outside every signature, so deep nesting there is
    // refused as a broken envelope before any cryptography.
    for index in 0..signer_count {
        let within = cms
            .signer_nesting(index, MAX_ASN1_DEPTH)
            .is_some_and(|nesting| {
                ATTRIBUTE_VALUE_BASE.saturating_add(nesting.attribute_values) <= MAX_ASN1_DEPTH
                    && ALGORITHM_PARAMETER_BASE.saturating_add(nesting.algorithm_parameters)
                        <= MAX_ASN1_DEPTH
            });
        if !within {
            return Err(malformed(format!(
                "malformed CMS structure: a SignerInfo value is not ASN.1 nested at most {MAX_ASN1_DEPTH} deep"
            )));
        }
    }

    // Only the creation date is read before trust is established, because
    // chain validity is anchored at signing time; nothing else in the payload
    // is decoded until the chain and a signature have passed. A date that is
    // missing or unreadable cannot blame anyone yet, so it only moves the
    // chain instant to the clock and never rejects by itself.
    let creation_date = read_creation_date(cms.content());

    let embedded = Embedded::sort(certificates);
    // Signer-independent, so walked once for all SignerInfos, and only once
    // one of them has named an embedded certificate that decodes.
    let mut authenticated: Option<Vec<Certificate>> = None;
    let mut first_failure: Option<Failure> = None;
    for index in 0..signer_count {
        let verdict = signer_certificates(&cms, index, &embedded).and_then(|matches| {
            let at_millis = match creation_date {
                Some(millis) => millis,
                None => clock.now()?,
            };
            let authenticated = authenticated
                .get_or_insert_with(|| authenticated_top_down(&embedded.readable, anchors));
            // The bag is unsigned, so a certificate carrying the signer's
            // identity on another key can sit ahead of the genuine one. Each
            // match is tried as the SignerInfos are: one passing is enough,
            // and only when none does is the first one's failure the verdict.
            // No match's key is used before its chain has passed.
            let mut first_match_failure: Option<Failure> = None;
            for signer in matches {
                match verify_signer(&mut cms, index, &signer, authenticated, anchors, at_millis) {
                    Ok(()) => return Ok(()),
                    Err(failure) => {
                        first_match_failure.get_or_insert(failure);
                    }
                }
            }
            Err(first_match_failure.unwrap_or_else(|| malformed("signer certificate not embedded")))
        });
        match verdict {
            Ok(()) => return Ok(cms.content().to_vec()),
            // Every SignerInfo signs the same content, so another one
            // passing proves the same bytes; only when none does is the
            // first one's failure the verdict.
            Err(failure) => {
                first_failure.get_or_insert(failure);
            }
        }
    }
    Err(first_failure.unwrap_or_else(|| malformed("no signer info")))
}

/// The embedded certificates, judged once for every `SignerInfo`: the ones
/// a strict reader decodes, and the ones it does not. OpenSSL has parsed
/// all of them, or the envelope would not have parsed.
struct Embedded {
    readable: Vec<Certificate>,
    unreadable: Vec<Certificate>,
}

impl Embedded {
    fn sort(certificates: Vec<Certificate>) -> Embedded {
        let (readable, unreadable) = certificates.into_iter().partition(Certificate::is_readable);
        Embedded {
            readable,
            unreadable,
        }
    }
}

fn verify_signer(
    cms: &mut SignedData,
    index: usize,
    signer: &Certificate,
    authenticated: &[Certificate],
    anchors: &[TrustAnchor],
    at_millis: i64,
) -> Result<(), Failure> {
    let path = receipt_path(signer, authenticated, anchors, at_millis)?;
    // Checked after the chain, so a foreign chain still reports
    // UNTRUSTED_CHAIN rather than INVALID_CERTIFICATE_PURPOSE.
    if !signer.has_extension(SIGNING_LEAF_OID) {
        return Err(Failure::new(
            Reason::InvalidCertificatePurpose,
            format!("receipt signer certificate lacks Apple receipt-signing marker OID {SIGNING_LEAF_OID}"),
        ));
    }
    // The certificate after the signer on the path. A signer issued straight
    // by a root has no WWDR certificate to carry the marker.
    if !path
        .get(1)
        .is_some_and(|intermediate| intermediate.has_extension(WWDR_INTERMEDIATE_OID))
    {
        return Err(Failure::new(
            Reason::InvalidCertificatePurpose,
            format!("receipt intermediate certificate lacks Apple WWDR marker OID {WWDR_INTERMEDIATE_OID}"),
        ));
    }
    // The signer's key is used to check the CMS signature, so a key OpenSSL
    // cannot build is a defect of the certificate rather than of the
    // signature it carries, the reading the JWS path applies to x5c. Judged
    // only once the chain has vouched for the certificate.
    if !signer.has_usable_key() {
        return Err(Failure::new(
            Reason::InvalidCertificate,
            "receipt signer certificate has a public key this library cannot use",
        ));
    }
    // The chain is checked BEFORE the signature on purpose: checking the
    // signature first would run the attacker's own key (their choice of RSA
    // size and exponent) before anything about it is trusted.
    verify_cms_signature(cms, index, signer)
}

/// The certificates `SignerInfo` `index` names as its signer, never empty,
/// or the verdict for the bag. The signer's own entry not decoding is
/// `INVALID_CERTIFICATE`, as an unreadable `x5c` entry is on the JWS path;
/// any other entry not decoding is `MALFORMED`, because the bag is unsigned
/// and bytes that cannot be read there are a defect of the receipt, not of a
/// certificate. A broken signer outranks a broken stranger.
fn signer_certificates(
    cms: &SignedData,
    index: usize,
    embedded: &Embedded,
) -> Result<Vec<Certificate>, Failure> {
    if embedded
        .unreadable
        .iter()
        .any(|certificate| cms.names_signer(index, certificate))
    {
        return Err(Failure::new(
            Reason::InvalidCertificate,
            "receipt signer certificate does not decode",
        ));
    }
    if !embedded.unreadable.is_empty() {
        return Err(malformed(
            "an embedded certificate is not a valid certificate",
        ));
    }
    let matches: Vec<Certificate> = embedded
        .readable
        .iter()
        .filter(|certificate| cms.names_signer(index, certificate))
        .cloned()
        .collect();
    if matches.is_empty() {
        return Err(malformed("signer certificate not embedded"));
    }
    Ok(matches)
}

fn invalid_signature(detail: &'static str) -> Failure {
    Failure::new(Reason::InvalidSignature, detail)
}

/// No algorithm or key-type allowlist beyond what OpenSSL implements: the
/// signer is already pinned to an Apple root and carries Apple's
/// receipt-signing marker, so a change of algorithm on Apple's side does
/// not reject genuine receipts (DECISIONS.md R20).
///
/// With signed attributes, RFC 5652 section 5.3 makes `contentType` and
/// `messageDigest` mandatory, each once and single-valued, and section 11.1
/// makes `contentType` name the content the signature covers. A set that
/// breaks either cannot be checked, so it fails as a signature. The
/// separation is a real control: genuine receipts carry no signed
/// attributes, so their signature covers the payload SET itself, and a
/// forger who re-labelled that SET as signed attributes would reuse
/// Apple's signature over content of their own; that SET has neither
/// attribute.
fn verify_cms_signature(
    cms: &mut SignedData,
    index: usize,
    signer: &Certificate,
) -> Result<(), Failure> {
    if !cms.signer_digest_known(index) {
        return Err(invalid_signature("unsupported digest algorithm"));
    }
    let attributes = cms.signed_attributes(index);
    if attributes.present {
        if attributes.content_type_count != 1
            || attributes.content_type_values != 1
            || attributes.message_digest_count != 1
            || attributes.message_digest_values != 1
        {
            return Err(invalid_signature(
                "signedAttrs lack a contentType or messageDigest attribute, or carry one twice",
            ));
        }
        if !attributes.content_type_matches {
            return Err(invalid_signature(
                "contentType attribute differs from the eContentType",
            ));
        }
    }
    if cms.verify_signer(index, signer) {
        Ok(())
    } else {
        Err(invalid_signature("CMS signature check failed"))
    }
}
