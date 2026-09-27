//! CMS / PKCS#7 `SignedData` structure walking for legacy app receipts.
//!
//! Bytes in, bytes out: this module decides what a receipt *says*, and the
//! crypto lives in [`crate::receipt`]. Both definite and indefinite (BER)
//! lengths occur in genuine receipts — BouncyCastle-generated fixtures and
//! Apple's own Xcode receipts use indefinite lengths, the two real Apple
//! receipts use definite ones — so the reader accepts both and this module
//! never assumes either.

// Every length and offset here comes from attacker bytes: no silent wrap.
#![deny(clippy::arithmetic_side_effects)]

use crate::asn1::{decode_oid, encode_oid, parse_exact, tag, Asn1Error, Tlv};
use crate::crypto::DigestAlgorithm;

/// One `SignerInfo` of a receipt.
#[derive(Debug, Clone)]
pub struct CmsSignerInfo {
    /// The issuer `Name` TLV named by `issuerAndSerialNumber`.
    pub issuer_raw: Vec<u8>,
    /// The serial number content octets named by `issuerAndSerialNumber`.
    pub serial_contents: Vec<u8>,
    /// The digest the signature is over, or `None` for one this crate does
    /// not implement, which that signer then fails as a signature that
    /// cannot be checked.
    pub digest: Option<DigestAlgorithm>,
    /// The `signatureAlgorithm` OID, dotted.
    pub signature_algorithm_oid: String,
    /// The `signatureAlgorithm` parameters TLV, when present.
    pub signature_algorithm_params: Option<Vec<u8>>,
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
    /// Every `SignerInfo`, in order. Never empty.
    pub signer_infos: Vec<CmsSignerInfo>,
    /// The `eContentType` OID's content octets.
    pub content_type: Vec<u8>,
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

/// The digests this crate implements. Anything else leaves that signer
/// uncheckable rather than guessed at.
pub(crate) fn digest_for(oid_contents: &[u8]) -> Option<DigestAlgorithm> {
    [
        ("1.2.840.113549.2.5", DigestAlgorithm::Md5),
        ("1.3.14.3.2.26", DigestAlgorithm::Sha1),
        ("2.16.840.1.101.3.4.2.4", DigestAlgorithm::Sha224),
        ("2.16.840.1.101.3.4.2.1", DigestAlgorithm::Sha256),
        ("2.16.840.1.101.3.4.2.2", DigestAlgorithm::Sha384),
        ("2.16.840.1.101.3.4.2.3", DigestAlgorithm::Sha512),
    ]
    .into_iter()
    .find(|(oid, _)| encode_oid(oid).is_some_and(|encoded| encoded == oid_contents))
    .map(|(_, digest)| digest)
}

const BAD: Asn1Error = Asn1Error("malformed CMS structure");

/// [`find_message_digest_attribute`]'s answer for a well-formed attribute
/// set without a `contentType` attribute.
pub const MISSING_CONTENT_TYPE: Asn1Error =
    Asn1Error("signedAttrs without a contentType attribute");

/// [`find_message_digest_attribute`]'s answer for a well-formed attribute
/// set without a `messageDigest` attribute.
pub const MISSING_MESSAGE_DIGEST: Asn1Error =
    Asn1Error("signedAttrs without a messageDigest attribute");

/// [`find_message_digest_attribute`]'s answer for a well-formed attribute
/// set that carries `contentType` or `messageDigest` more than once: which
/// copy the signer meant is not the reader's to choose.
pub const DUPLICATE_ATTRIBUTE: Asn1Error =
    Asn1Error("signedAttrs carry contentType or messageDigest twice");

/// Whether `err` is one of [`find_message_digest_attribute`]'s answers for
/// a well-formed attribute set whose signature cannot be checked, rather
/// than for one that is not an attribute set at all.
#[must_use]
pub fn is_unverifiable_attribute_set(err: &Asn1Error) -> bool {
    *err == MISSING_CONTENT_TYPE || *err == MISSING_MESSAGE_DIGEST || *err == DUPLICATE_ATTRIBUTE
}

/// Parses a CMS `SignedData` blob.
///
/// # Errors
/// [`Asn1Error`] for anything that is not a `SignedData` carrying content
/// and at least one readable `SignerInfo`, including trailing bytes after
/// the outer value, which [`parse_exact`] refuses, and a `signedAttrs` in
/// any `SignerInfo` that is not an attribute set.
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
    let content_type = encap
        .first()
        .filter(|node| node.tag == tag::OID)
        .ok_or(Asn1Error("encapContentInfo has no content type"))?
        .contents
        .to_vec();
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
    let signer_infos = signer_infos
        .children()
        .iter()
        .map(parse_signer_info)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ParsedCms {
        content,
        certificates,
        signer_infos,
        content_type,
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
        let attrs = fields.get(index).ok_or(BAD)?.full;
        // The syntax of every SignerInfo's set is judged here, before any
        // key is used, so a broken one is MALFORMED whichever position it
        // holds; a well-formed set lacking a mandatory attribute is left to
        // the signature check, as INVALID_SIGNATURE for that signer.
        match find_message_digest_attribute(attrs) {
            Ok(_) => {}
            Err(err) if is_unverifiable_attribute_set(&err) => {}
            Err(err) => return Err(err),
        }
        signed_attrs = Some(attrs.to_vec());
        index = index.saturating_add(1);
    }
    // The digest drives the hash, except for an algorithm whose parameters
    // name their own (RSASSA-PSS).
    let signature_algorithm = fields.get(index).ok_or(BAD)?;
    let signature_algorithm_oid = signature_algorithm
        .child(0)
        .filter(|node| signature_algorithm.tag == tag::SEQUENCE && node.tag == tag::OID)
        .and_then(|node| decode_oid(node.contents))
        .ok_or(Asn1Error(
            "signatureAlgorithm is not an AlgorithmIdentifier",
        ))?;
    let signature_algorithm_params = signature_algorithm.child(1).map(|node| node.full.to_vec());
    index = index.saturating_add(1);
    let signature = fields.get(index).ok_or(BAD)?.contents.to_vec();
    let digest = digest_for(digest_oid);
    Ok(CmsSignerInfo {
        issuer_raw,
        serial_contents,
        digest,
        signature_algorithm_oid,
        signature_algorithm_params,
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
    signed_attribute_values(signed_attrs).map(|(digest, _)| digest)
}

/// The `messageDigest` value and the `contentType` value's OID content
/// octets, with the checks of [`find_message_digest_attribute`]. A
/// `contentType` value that is not an OID reads as empty, which no
/// `eContentType` matches.
///
/// # Errors
/// As [`find_message_digest_attribute`].
pub fn signed_attribute_values(signed_attrs: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Asn1Error> {
    let node = parse_exact(signed_attrs)?;
    let wanted = oid_message_digest();
    let content_type = oid_content_type();
    let mut message_digest: Option<Vec<u8>> = None;
    let mut content_type_value: Option<Vec<u8>> = None;
    let mut duplicate = false;
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
            let oid = if value.tag == tag::OID {
                value.contents.to_vec()
            } else {
                Vec::new()
            };
            duplicate |= content_type_value.replace(oid).is_some();
        }
        if attribute_type.contents == wanted.as_slice() {
            duplicate |= message_digest.replace(value.contents.to_vec()).is_some();
        }
    }
    let Some(content_type_value) = content_type_value else {
        return Err(MISSING_CONTENT_TYPE);
    };
    let message_digest = message_digest.ok_or(MISSING_MESSAGE_DIGEST)?;
    if duplicate {
        return Err(DUPLICATE_ATTRIBUTE);
    }
    Ok((message_digest, content_type_value))
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        find_message_digest_attribute, signed_attribute_values, DUPLICATE_ATTRIBUTE,
        MISSING_MESSAGE_DIGEST,
    };
    use crate::asn1::{encode_oid, tag};

    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, u8::try_from(contents.len()).unwrap()];
        out.extend_from_slice(contents);
        out
    }

    fn attribute(oid: &str, value: &[u8]) -> Vec<u8> {
        let oid = tlv(tag::OID, &encode_oid(oid).unwrap());
        tlv(tag::SEQUENCE, &[oid, tlv(tag::SET, value)].concat())
    }

    fn attrs(attributes: &[Vec<u8>]) -> Vec<u8> {
        tlv(tag::CONTEXT_0, &attributes.concat())
    }

    const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
    const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";

    #[test]
    fn a_second_content_type_or_message_digest_leaves_nothing_to_check() {
        let data = tlv(tag::OID, &encode_oid("1.2.840.113549.1.7.1").unwrap());
        let digest = tlv(tag::OCTET_STRING, &[1, 2, 3]);
        let one = attrs(&[
            attribute(CONTENT_TYPE, &data),
            attribute(MESSAGE_DIGEST, &digest),
        ]);
        let (value, content_type) = signed_attribute_values(&one).unwrap();
        assert_eq!(value, [1, 2, 3]);
        assert_eq!(content_type, encode_oid("1.2.840.113549.1.7.1").unwrap());
        for twice in [
            attrs(&[
                attribute(CONTENT_TYPE, &data),
                attribute(MESSAGE_DIGEST, &digest),
                attribute(MESSAGE_DIGEST, &digest),
            ]),
            attrs(&[
                attribute(CONTENT_TYPE, &data),
                attribute(CONTENT_TYPE, &data),
                attribute(MESSAGE_DIGEST, &digest),
            ]),
        ] {
            assert_eq!(
                find_message_digest_attribute(&twice),
                Err(DUPLICATE_ATTRIBUTE)
            );
        }
        assert_eq!(
            find_message_digest_attribute(&attrs(&[attribute(CONTENT_TYPE, &data)])),
            Err(MISSING_MESSAGE_DIGEST)
        );
    }
}
