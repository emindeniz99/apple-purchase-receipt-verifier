//! The tests' BER reader, for taking apart the fixtures the tests mutate
//! and rebuild. The library reads nothing with it: OpenSSL parses every
//! byte the library sees.
//!
//! `asn1-rs` reads every identifier, length and end-of-contents marker,
//! definite and indefinite (Apple's and Xcode's receipts are BER, which
//! the `der` crate refuses; docs/rust-core/DECISIONS.md R43). This file
//! only keeps the slices the tests rebuild from: `tag` is the identifier
//! octet as it appears in the input, `full` the exact TLV consumed and
//! `contents` the value octets inside it, and every constructed value is
//! read into its children.
//!
//! One piece of BER stays hand-written: joining a constructed `OCTET
//! STRING`'s segments, because `asn1-rs` 0.7 hands back the raw content
//! of the constructed form. 0.8's `OctetString` joins the segments
//! itself, so the join goes when the dependency moves to 0.8. Nothing
//! else is decoded here. `read` adds two refusals on top of `asn1-rs`
//! 0.7.2, both of which the reader before it made:
//!
//! - An identifier longer than one octet. `asn1-rs` reads `1f 05` as tag
//!   5, which a one-octet `tag` would misreport; no fixture has one.
//! - An indefinite value that does not end in `00 00`. `asn1-rs` ends one
//!   at any zero-length header with tag number 0, whatever its class and
//!   constructed bit, where X.690 8.1.5 allows only the universal
//!   primitive `00 00`.

use asn1_rs::{Any, Err, Error, FromBer, Length};
use std::borrow::Cow;

/// One decoded ASN.1 value.
#[derive(Debug, Clone)]
pub struct Tlv<'a> {
    /// The identifier octet (e.g. `0x30` for `SEQUENCE`).
    pub tag: u8,
    /// Whether the constructed bit is set.
    pub constructed: bool,
    /// The complete TLV as it appears in the input.
    pub full: &'a [u8],
    /// The value octets; for an indefinite length, without the
    /// end-of-contents marker.
    pub contents: &'a [u8],
    children: Vec<Tlv<'a>>,
}

impl<'a> Tlv<'a> {
    /// The decoded children, or an empty slice for a primitive value.
    #[must_use]
    pub fn children(&self) -> &[Tlv<'a>] {
        &self.children
    }

    /// The `n`th child, if there is one.
    #[must_use]
    pub fn child(&self, n: usize) -> Option<&Tlv<'a>> {
        self.children.get(n)
    }

    /// Whether this is an `OCTET STRING` in either encoding.
    #[must_use]
    pub fn is_octet_string(&self) -> bool {
        self.tag & !0x20 == super::tag::OCTET_STRING
    }

    /// The value of an `OCTET STRING`, joining BER constructed chunks, or
    /// `None` when this value is not one. A constructed `OCTET STRING` may
    /// hold only `OCTET STRING`s (X.690 §8.21). `asn1-rs` 0.7 hands back
    /// the raw content of the constructed form, so the join is here.
    #[must_use]
    pub fn octet_string_value(&self) -> Option<Cow<'a, [u8]>> {
        if !self.is_octet_string() {
            return None;
        }
        if !self.constructed {
            return Some(Cow::Borrowed(self.contents));
        }
        let mut out = Vec::new();
        for child in &self.children {
            out.extend_from_slice(&child.octet_string_value()?);
        }
        Some(Cow::Owned(out))
    }
}

/// Parses exactly one value, refusing any trailing bytes.
///
/// # Errors
/// What `asn1-rs` refuses, an identifier longer than one octet
/// (`Unsupported`), an indefinite value not closed by `00 00`, or bytes
/// after the value (both `BerValueError`).
pub fn parse_exact(input: &[u8]) -> Result<Tlv<'_>, Error> {
    let (rest, node) = read(input)?;
    if !rest.is_empty() {
        return Err(Error::BerValueError);
    }
    Ok(node)
}

fn read(input: &[u8]) -> Result<(&[u8], Tlv<'_>), Error> {
    let (rest, any) = Any::from_ber(input).map_err(|err| match err {
        Err::Error(err) | Err::Failure(err) => err,
        Err::Incomplete(needed) => Error::Incomplete(needed),
    })?;
    let tag = match any.header.raw_tag() {
        Some(&[octet]) => octet,
        _ => return Err(Error::Unsupported),
    };
    let constructed = any.header.is_constructed();
    let full = &input[..input.len() - rest.len()];
    if any.header.length() == Length::Indefinite && !full.ends_with(&[0, 0]) {
        return Err(Error::BerValueError);
    }
    let mut children = Vec::new();
    let mut inner = any.data;
    while constructed && !inner.is_empty() {
        let (next, child) = read(inner)?;
        children.push(child);
        inner = next;
    }
    let node = Tlv {
        tag,
        constructed,
        full,
        contents: any.data,
        children,
    };
    Ok((rest, node))
}
