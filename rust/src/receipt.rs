//! [`Verifier::verify_receipt`](crate::Verifier::verify_receipt): legacy
//! PKCS#7 app receipts, verified offline.

use crate::asn1::{parse_exact, tag};
use crate::base64::decode_receipt_base64;
use crate::chain::{authenticated_top_down, build_and_validate_path, Authenticated};
use crate::cms::{
    find_message_digest_attribute, parse_cms, signed_attrs_signed_bytes, CmsSignerInfo, ParsedCms,
    MISSING_CONTENT_TYPE, MISSING_MESSAGE_DIGEST,
};
use crate::crypto::{constant_time_eq, curve_field_size, verify_signer_signature};
use crate::error::{Failure, Reason};
use crate::receipt_payload::{parse_receipt_payload, read_creation_date, ReceiptPayload};
use crate::roots::TrustAnchor;
use crate::x509::{Certificate, OID_EC_PUBLIC_KEY};

/// The Apple marker OID a receipt-signing leaf must carry.
///
/// Without this purpose check, any developer certificate chaining to the same
/// pinned root (every "Apple Distribution" and "Apple Development" leaf goes
/// through the same WWDR intermediate) could sign a fully forged receipt.
pub(crate) const RECEIPT_SIGNER_OID: &str = "1.2.840.113635.100.6.11.1";

/// Apple marker OID: the Worldwide Developer Relations intermediate CA,
/// checked on the certificate that issued the receipt signer.
pub(crate) const WWDR_INTERMEDIATE_OID: &str = "1.2.840.113635.100.6.2.1";

/// How many certificates a receipt may embed. Every embedded certificate is
/// parsed and then tried as an issuer before anything about the receipt is
/// verified, so the bound is enforced before a single one is decoded.
pub(crate) const MAX_EMBEDDED_CERTIFICATES: usize = 10;

/// How many `SignerInfo`s a receipt may carry. A fifth is refused before any
/// signature is checked.
pub(crate) const MAX_SIGNER_INFOS: usize = 4;

/// The largest receipt string, in UTF-8 bytes: 3 MiB, Apple's own request
/// limit, checked before anything is decoded. No receipt Apple accepts can
/// be larger than the request that carries it.
pub(crate) const MAX_RECEIPT_BYTES: usize = 3_145_728;

fn malformed(detail: impl Into<String>) -> Failure {
    Failure::new(Reason::Malformed, detail)
}

/// Verifies a receipt in its base64 form, the shape a client sends, and
/// decodes its payload.
///
/// `now_millis` is the chain instant when the receipt's first attribute 12
/// is missing or does not parse.
pub(crate) fn verify(
    base64: &str,
    anchors: &[TrustAnchor],
    now_millis: i64,
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
    let content = verify_signature(&der, anchors, now_millis)?;
    // A trusted signer signed these bytes, so a payload this crate cannot
    // read is the library's failure or a format Apple added, not the
    // client's: UNREADABLE_PAYLOAD, never MALFORMED, which the endpoint
    // answers as 21002 and an app server reads as "deny".
    parse_receipt_payload(&content).map_err(|err| {
        Failure::new(
            Reason::UnreadablePayload,
            "signed receipt content could not be read",
        )
        .with_source(err)
    })
}

/// Every check up to and including a signature; returns the signed payload,
/// not yet decoded.
fn verify_signature(
    der: &[u8],
    anchors: &[TrustAnchor],
    now_millis: i64,
) -> Result<Vec<u8>, Failure> {
    let cms = parse_cms(der).map_err(|err| malformed(format!("malformed CMS structure: {err}")))?;
    if cms.signer_infos.len() > MAX_SIGNER_INFOS {
        return Err(malformed(format!(
            "receipt carries {} SignerInfos, more than the maximum of {MAX_SIGNER_INFOS}",
            cms.signer_infos.len()
        )));
    }
    // Bounded here, before a single embedded certificate is decoded or tried
    // as an issuer, all of which an unverified receipt would otherwise get to
    // pay for out of the caller's CPU.
    if cms.certificates.len() > MAX_EMBEDDED_CERTIFICATES {
        return Err(malformed(format!(
            "receipt embeds {} certificates, more than the maximum of {MAX_EMBEDDED_CERTIFICATES}",
            cms.certificates.len()
        )));
    }

    // Only the creation date is read before trust is established, because
    // chain validity is anchored at signing time; nothing else in the payload
    // is decoded until the chain and a signature have passed. A date that is
    // missing or unreadable cannot blame anyone yet, so it only moves the
    // chain instant to the clock and never rejects by itself.
    let at_millis = read_creation_date(&cms.content).unwrap_or(now_millis);

    let embedded = decode_embedded(&cms);
    // Signer-independent, so walked once for all SignerInfos, and only once
    // one of them has named an embedded certificate that decodes.
    let mut authenticated: Option<Authenticated<'_>> = None;
    let mut first_failure: Option<Failure> = None;
    for info in &cms.signer_infos {
        let verdict = signer_certificate(info, &embedded).and_then(|signer| {
            let authenticated = authenticated
                .get_or_insert_with(|| authenticated_top_down(&embedded.decoded, anchors));
            verify_signer(&cms, info, signer, authenticated, anchors, at_millis)
        });
        match verdict {
            Ok(()) => return Ok(cms.content),
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

/// The embedded certificates, decoded once for every `SignerInfo`: the ones
/// that decoded, and the raw bytes of the ones that did not.
struct Embedded<'a> {
    decoded: Vec<Certificate>,
    unreadable: Vec<&'a [u8]>,
}

fn decode_embedded(cms: &ParsedCms) -> Embedded<'_> {
    let mut embedded = Embedded {
        decoded: Vec::with_capacity(cms.certificates.len()),
        unreadable: Vec::new(),
    };
    for raw in &cms.certificates {
        match Certificate::from_der(raw) {
            Ok(certificate) => embedded.decoded.push(certificate),
            Err(_) => embedded.unreadable.push(raw),
        }
    }
    embedded
}

fn verify_signer<'a>(
    cms: &ParsedCms,
    info: &CmsSignerInfo,
    signer: &'a Certificate,
    authenticated: &Authenticated<'a>,
    anchors: &[TrustAnchor],
    at_millis: i64,
) -> Result<(), Failure> {
    let path = build_and_validate_path(signer, authenticated, anchors, at_millis)?;
    // Checked after the chain, so a foreign chain still reports
    // UNTRUSTED_CHAIN rather than INVALID_CERTIFICATE_PURPOSE.
    if !signer.has_extension(RECEIPT_SIGNER_OID) {
        return Err(Failure::new(
            Reason::InvalidCertificatePurpose,
            format!("receipt signer certificate lacks Apple receipt-signing marker OID {RECEIPT_SIGNER_OID}"),
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
    // The chain is checked BEFORE the signature on purpose: checking the
    // signature first would run the attacker's own key (their choice of RSA
    // size and exponent) before anything about it is trusted.
    verify_cms_signature(cms, info, signer)
}

/// The certificate `info` names, or the verdict for the bag. The signer's
/// own entry not decoding is `INVALID_CERTIFICATE`, as an unreadable `x5c`
/// entry is on the JWS path; any other entry not decoding is `MALFORMED`,
/// because the bag is unsigned and bytes that cannot be read there are a
/// defect of the receipt, not of a certificate. A broken signer outranks a
/// broken stranger.
fn signer_certificate<'e>(
    info: &CmsSignerInfo,
    embedded: &'e Embedded<'_>,
) -> Result<&'e Certificate, Failure> {
    // Which entry an unreadable one is has to be read out of the entry
    // itself: an identity is still legible in bytes that are not a
    // certificate all the way down.
    if embedded
        .unreadable
        .iter()
        .any(|raw| names_the_signer(raw, info))
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
    let signer = embedded
        .decoded
        .iter()
        .find(|cert| {
            cert.serial_number() == info.serial_contents.as_slice()
                && cert.issuer_der() == info.issuer_raw.as_slice()
        })
        .ok_or_else(|| malformed("signer certificate not embedded"))?;
    // The signer's key is used to check the CMS signature, so a key this
    // crate cannot build is a defect of the certificate rather than of the
    // signature it carries, the reading the JWS path applies to x5c.
    if signer.public_key_algorithm_oid() == OID_EC_PUBLIC_KEY
        && signer
            .public_key_curve_oid()
            .and_then(curve_field_size)
            .is_none()
    {
        return Err(Failure::new(
            Reason::InvalidCertificate,
            "receipt signer certificate uses an unimplemented elliptic curve",
        ));
    }
    Ok(signer)
}

/// Whether `raw` carries the issuer Name and serialNumber the `SignerInfo`
/// names, read as generic ASN.1 rather than as an X.509 certificate, since
/// the entries asked about are the ones [`Certificate::from_der`] refused.
///
/// `TBSCertificate ::= SEQUENCE { [0] version DEFAULT v1, serialNumber
/// INTEGER, signature AlgorithmIdentifier, issuer Name, ... }`: anything
/// without that shape is not an identity and cannot match.
fn names_the_signer(raw: &[u8], info: &CmsSignerInfo) -> bool {
    let Ok(certificate) = parse_exact(raw) else {
        return false;
    };
    if certificate.tag != tag::SEQUENCE {
        return false;
    }
    let Some(tbs) = certificate
        .child(0)
        .filter(|node| node.tag == tag::SEQUENCE)
    else {
        return false;
    };
    let fields = tbs.children();
    let index = usize::from(matches!(fields.first(), Some(f) if f.tag == tag::CONTEXT_0));
    let (Some(serial), Some(issuer)) = (fields.get(index), fields.get(index + 2)) else {
        return false;
    };
    serial.tag == tag::INTEGER
        && issuer.tag == tag::SEQUENCE
        && serial.contents == info.serial_contents.as_slice()
        && issuer.full == info.issuer_raw.as_slice()
}

fn invalid_signature(detail: &'static str) -> Failure {
    Failure::new(Reason::InvalidSignature, detail)
}

/// No algorithm or key-type allowlist beyond what this crate's crypto
/// crates implement (RSASSA-PKCS1-v1_5, RSASSA-PSS, and ECDSA on P-256 and
/// P-384; SHA-1, SHA-224, SHA-256, SHA-384, SHA-512): the
/// signer is already pinned to an Apple root and carries Apple's
/// receipt-signing marker, so a change of algorithm on Apple's side does not
/// reject genuine receipts. An RSA signature binds its hash algorithm in the
/// `DigestInfo`, so relabelling the field fails.
fn verify_cms_signature(
    cms: &ParsedCms,
    info: &CmsSignerInfo,
    signer: &Certificate,
) -> Result<(), Failure> {
    let Some(digest) = info.digest else {
        return Err(invalid_signature("unsupported digest algorithm"));
    };
    let algorithm = (
        info.signature_algorithm_oid.as_str(),
        info.signature_algorithm_params.as_deref(),
    );
    let valid = match &info.signed_attrs {
        Some(signed_attrs) => {
            let content_digest = digest.digest(&cms.content);
            // RFC 5652 5.3 makes contentType and messageDigest mandatory
            // whenever signedAttrs are present: a set without one of them
            // cannot be checked, so it fails as a signature. A set that is
            // not an attribute set at all is a broken structure. That
            // separation is a real control, not an accident of Apple's
            // grammar: genuine receipts carry no signedAttrs, so their
            // signature covers `0x31 || payload[1..]`, the very bytes the
            // signedAttrs branch would sign for `0xA0 || payload[1..]`, and
            // only the attribute walk refuses that forgery.
            let message_digest = match find_message_digest_attribute(signed_attrs) {
                Ok(digest) => digest,
                Err(err) if err == MISSING_CONTENT_TYPE || err == MISSING_MESSAGE_DIGEST => {
                    return Err(invalid_signature(
                        "signedAttrs lack a contentType or messageDigest attribute",
                    ));
                }
                Err(err) => return Err(malformed(format!("malformed signedAttrs: {err}"))),
            };
            if !constant_time_eq(&message_digest, &content_digest) {
                return Err(invalid_signature(
                    "messageDigest attribute does not match content",
                ));
            }
            verify_signer_signature(
                signer,
                digest,
                algorithm,
                &info.signature,
                &signed_attrs_signed_bytes(signed_attrs),
            )
        }
        None => verify_signer_signature(signer, digest, algorithm, &info.signature, &cms.content),
    };
    if valid {
        Ok(())
    } else {
        Err(invalid_signature("CMS signature check failed"))
    }
}
