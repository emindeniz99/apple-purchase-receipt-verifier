//! CMS / PKCS#7 `SignedData` structure walking for legacy app receipts.
//!
//! Bytes in, bytes out: this module decides what a receipt *says*, and the
//! crypto lives in [`crate::receipt`]. Both definite and indefinite (BER)
//! lengths occur in genuine receipts — BouncyCastle-generated fixtures and
//! Apple's own Xcode receipts use indefinite lengths, the two real Apple
//! receipts use definite ones — so the reader accepts both and this module
//! never assumes either.

use crate::asn1::{encode_oid, parse_exact, tag, Asn1Error, Tlv};
use crate::crypto::DigestAlgorithm;

/// The one `SignerInfo` a receipt carries.
#[derive(Debug, Clone)]
pub struct CmsSignerInfo {
    /// The issuer `Name` TLV named by `issuerAndSerialNumber`.
    pub issuer_raw: Vec<u8>,
    /// The serial number content octets named by `issuerAndSerialNumber`.
    pub serial_contents: Vec<u8>,
    /// The digest the signature is over.
    pub digest: DigestAlgorithm,
    /// The `signedAttrs [0]` TLV, when present.
    pub signed_attrs: Option<Vec<u8>>,
    /// The signature octets.
    pub signature: Vec<u8>,
}

/// A decoded CMS `SignedData`.
#[derive(Debug, Clone)]
pub struct ParsedCms {
    /// The encapsulated content — the receipt payload.
    pub content: Vec<u8>,
    /// The embedded certificates, as their original DER.
    pub certificates: Vec<Vec<u8>>,
    /// The first (and only) `SignerInfo`.
    pub signer_info: CmsSignerInfo,
}

fn oid_signed_data() -> Vec<u8> {
    encode_oid("1.2.840.113549.1.7.2").unwrap_or_default()
}

fn oid_message_digest() -> Vec<u8> {
    encode_oid("1.2.840.113549.1.9.4").unwrap_or_default()
}

fn oid_content_type() -> Vec<u8> {
    encode_oid("1.2.840.113549.1.9.3").unwrap_or_default()
}

/// Only the digests Apple uses for receipts. Anything else is a receipt this
/// library refuses to interpret rather than one it guesses at.
fn digest_for(oid_contents: &[u8]) -> Option<DigestAlgorithm> {
    let sha1 = encode_oid("1.3.14.3.2.26")?;
    let sha256 = encode_oid("2.16.840.1.101.3.4.2.1")?;
    if oid_contents == sha1.as_slice() {
        Some(DigestAlgorithm::Sha1)
    } else if oid_contents == sha256.as_slice() {
        Some(DigestAlgorithm::Sha256)
    } else {
        None
    }
}

const BAD: Asn1Error = Asn1Error("malformed CMS structure");

/// Parses a CMS `SignedData` blob.
///
/// # Errors
/// [`Asn1Error`] for anything that is not a `SignedData` carrying content
/// and exactly one usable `SignerInfo` — including trailing bytes after the
/// outer value, which [`parse_exact`] refuses.
pub fn parse_cms(der: &[u8]) -> Result<ParsedCms, Asn1Error> {
    let content_info = parse_exact(der)?;
    if content_info.tag != tag::SEQUENCE {
        return Err(Asn1Error("not a CMS SignedData"));
    }
    let info = content_info.children();
    let content_type = info.first().ok_or(BAD)?;
    let wrapper = info.get(1).ok_or(BAD)?;
    // The tag is checked as well as the contents: an OBJECT IDENTIFIER that
    // is not tagged as one is a structure this reader cannot represent, and
    // the rule is reject rather than repair.
    if content_type.tag != tag::OID
        || content_type.contents != oid_signed_data().as_slice()
        || wrapper.tag != tag::CONTEXT_0
    {
        return Err(Asn1Error("not a CMS SignedData"));
    }
    let signed_data_node = wrapper.child(0).ok_or(BAD)?;
    let signed_data = signed_data_node.children();
    let encap_node = signed_data.get(2).ok_or(BAD)?;
    let encap = encap_node.children();
    if encap.first().map(|n| n.tag) != Some(tag::OID) {
        return Err(Asn1Error("encapContentInfo has no content type"));
    }
    let content_wrapper = encap.get(1).filter(|n| n.tag == tag::CONTEXT_0);
    let Some(content_wrapper) = content_wrapper else {
        return Err(Asn1Error("no encapsulated payload"));
    };
    let content_node = content_wrapper.child(0).ok_or(BAD)?;
    let content = content_node
        .octet_string_value()
        .ok_or(Asn1Error("encapsulated payload is not an OCTET STRING"))?
        .into_owned();

    let mut certificates: Vec<Vec<u8>> = Vec::new();
    let upper = signed_data.len().saturating_sub(1);
    for child in signed_data.get(3..upper).unwrap_or(&[]) {
        if child.tag == tag::CONTEXT_0 {
            certificates = child.children().iter().map(|c| c.full.to_vec()).collect();
        }
    }

    let signer_infos = signed_data.last().ok_or(BAD)?;
    if signer_infos.tag != tag::SET || signer_infos.children().is_empty() {
        return Err(Asn1Error("no signer info"));
    }
    let signer_info = parse_signer_info(signer_infos.child(0).ok_or(BAD)?)?;
    Ok(ParsedCms {
        content,
        certificates,
        signer_info,
    })
}

fn parse_signer_info(node: &Tlv<'_>) -> Result<CmsSignerInfo, Asn1Error> {
    let fields = node.children();
    let sid = fields.get(1).ok_or(BAD)?.children();
    let issuer_raw = sid.first().ok_or(BAD)?.full.to_vec();
    let serial_contents = sid.get(1).ok_or(BAD)?.contents.to_vec();
    let digest_oid_node = fields.get(2).ok_or(BAD)?.child(0).ok_or(BAD)?;
    if digest_oid_node.tag != tag::OID {
        return Err(Asn1Error("digestAlgorithm is not an OBJECT IDENTIFIER"));
    }
    let digest_oid = digest_oid_node.contents;
    let mut index = 3;
    let mut signed_attrs = None;
    if fields.get(index).ok_or(BAD)?.tag == tag::CONTEXT_0 {
        signed_attrs = Some(fields.get(index).ok_or(BAD)?.full.to_vec());
        index += 1;
    }
    index += 1; // signatureAlgorithm — the digest drives the hash.
    let signature = fields.get(index).ok_or(BAD)?.contents.to_vec();
    let digest = digest_for(digest_oid).ok_or(Asn1Error("unsupported digest algorithm"))?;
    Ok(CmsSignerInfo {
        issuer_raw,
        serial_contents,
        digest,
        signed_attrs,
        signature,
    })
}

/// The `messageDigest` signed attribute, after checking that the
/// `signedAttrs` are a well-formed RFC 5652 §5.3 attribute set.
///
/// RFC 5652 §5.3 makes `contentType` and `messageDigest` mandatory whenever
/// `signedAttrs` are present, and both are required here. That is a real
/// separation between the two `SignerInfo` branches rather than an accident
/// of Apple's grammar, and the difference matters:
///
/// Genuine Apple receipts carry **no** `signedAttrs`, so their RSA signature
/// is taken directly over `cms.content`, which is a DER `SET` beginning
/// `31 …`. [`signed_attrs_signed_bytes`] derives the other branch's signing
/// input by swapping one octet, `0x31 || signedAttrs[1..]`. Compose the two
/// and a forger can set `signedAttrs = 0xA0 || <genuine payload SET>[1..]`,
/// reproduce byte for byte the bytes Apple signed, and reuse a genuine
/// Apple signature while `cms.content` becomes entirely theirs. What stops
/// that is this function: the genuine payload's attributes are
/// `SEQUENCE { INTEGER, INTEGER, OCTET STRING }`, whose second field is
/// primitive, so the walk below fails — and before this check was written
/// down it failed only because Apple's receipt grammar happens not to look
/// like a CMS attribute. Requiring `contentType` and `messageDigest` states
/// the control instead of relying on that coincidence.
///
/// # Errors
/// [`Asn1Error`] when an attribute is not `SEQUENCE { OID, SET OF value }`,
/// or when `contentType` or `messageDigest` is missing.
pub fn find_message_digest_attribute(signed_attrs: &[u8]) -> Result<Vec<u8>, Asn1Error> {
    let node = parse_exact(signed_attrs)?;
    let wanted = oid_message_digest();
    let content_type = oid_content_type();
    let mut message_digest: Option<Vec<u8>> = None;
    let mut has_content_type = false;
    for attribute in node.children() {
        let children = attribute.children();
        let attribute_type = children
            .first()
            .filter(|node| node.tag == tag::OID)
            .ok_or(Asn1Error("malformed signed attribute"))?;
        let value = children
            .get(1)
            .filter(|values| values.tag == tag::SET)
            .and_then(|values| values.child(0))
            .ok_or(Asn1Error("malformed signed attribute"))?;
        if attribute_type.contents == content_type.as_slice() {
            has_content_type = true;
        }
        if attribute_type.contents == wanted.as_slice() && message_digest.is_none() {
            message_digest = Some(value.contents.to_vec());
        }
    }
    if !has_content_type {
        return Err(Asn1Error("signedAttrs without a contentType attribute"));
    }
    message_digest.ok_or(Asn1Error("signedAttrs without a messageDigest attribute"))
}

/// The bytes a `SignerInfo` signature covers when `signedAttrs` are present:
/// the attributes re-encoded as an explicit `SET` (RFC 5652 §5.4), which is
/// the implicit `[0]` tag octet swapped for `SET` and nothing else.
///
/// Swapping one octet rather than re-encoding the structure is deliberate:
/// the signature covers the original length and content octets, and a
/// re-encode could produce different ones.
#[must_use]
pub fn signed_attrs_signed_bytes(signed_attrs: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(signed_attrs.len());
    out.push(tag::SET);
    out.extend_from_slice(signed_attrs.get(1..).unwrap_or(&[]));
    out
}
