//! A test-only walk of a CMS `SignedData`, over the test BER reader, for
//! taking a fixture apart so a test can rebuild it with one thing changed.
//! The library does not use it.

use super::ber::{parse_exact, Tlv};
use super::tag;
use asn1_rs::Error as Asn1Error;

/// One `SignerInfo`, as the test rebuilds it.
#[derive(Debug, Clone)]
pub struct CmsSignerInfo {
    /// The issuer `Name` TLV named by `issuerAndSerialNumber`.
    pub issuer_raw: Vec<u8>,
    /// The serial number content octets named by `issuerAndSerialNumber`.
    pub serial_contents: Vec<u8>,
    /// The `signedAttrs [0]` TLV, when present.
    pub signed_attrs: Option<Vec<u8>>,
    /// The signature octets.
    pub signature: Vec<u8>,
}

/// A `SignedData`, taken apart.
#[derive(Debug, Clone)]
pub struct ParsedCms {
    /// The encapsulated content.
    pub content: Vec<u8>,
    /// The embedded certificates, as their original encodings.
    pub certificates: Vec<Vec<u8>>,
    /// Every `SignerInfo`, in order.
    pub signer_infos: Vec<CmsSignerInfo>,
}

/// Not the shape of a `ContentInfo` holding a `SignedData`.
const BAD: Asn1Error = Asn1Error::BerTypeError;

/// Takes a `ContentInfo` holding a `SignedData` apart.
pub fn parse_cms(der: &[u8]) -> Result<ParsedCms, Asn1Error> {
    let content_info = parse_exact(der)?;
    let wrapper = content_info.child(1).ok_or(BAD)?;
    let signed_data = wrapper.child(0).ok_or(BAD)?.children();
    let encap = signed_data.get(2).ok_or(BAD)?;
    let content = encap
        .child(1)
        .and_then(|wrapper| wrapper.child(0))
        .and_then(Tlv::octet_string_value)
        .ok_or(BAD)?
        .into_owned();
    let mut certificates = Vec::new();
    let upper = signed_data.len().saturating_sub(1);
    for child in signed_data.get(3..upper).unwrap_or(&[]) {
        if child.tag == tag::CONTEXT_0 {
            certificates = child.children().iter().map(|c| c.full.to_vec()).collect();
        }
    }
    let signer_infos = signed_data
        .last()
        .ok_or(BAD)?
        .children()
        .iter()
        .map(signer_info)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ParsedCms {
        content,
        certificates,
        signer_infos,
    })
}

fn signer_info(node: &Tlv<'_>) -> Result<CmsSignerInfo, Asn1Error> {
    let fields = node.children();
    let sid = fields.get(1).ok_or(BAD)?.children();
    let mut index = 3;
    let mut signed_attrs = None;
    if fields.get(index).ok_or(BAD)?.tag == tag::CONTEXT_0 {
        signed_attrs = Some(fields.get(index).ok_or(BAD)?.full.to_vec());
        index += 1;
    }
    Ok(CmsSignerInfo {
        issuer_raw: sid.first().ok_or(BAD)?.full.to_vec(),
        serial_contents: sid.get(1).ok_or(BAD)?.contents.to_vec(),
        signed_attrs,
        signature: fields.get(index + 1).ok_or(BAD)?.contents.to_vec(),
    })
}
