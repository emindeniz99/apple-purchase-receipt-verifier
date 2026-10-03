//! The tests' BER reader, for taking apart the fixtures the tests mutate
//! and rebuild. The library reads nothing with it: OpenSSL parses every
//! byte the library sees.
//!
//! `asn1-rs` reads every identifier, length and end-of-contents marker,
//! definite and indefinite (Apple's and Xcode's receipts are BER, which
//! the `der` crate refuses; docs/rust-core/DECISIONS.md R43). This file
//! only keeps the slices the tests rebuild from: `full` is the exact TLV
//! consumed and `contents` the value octets inside it, and every
//! constructed value is read into its children.

use asn1_rs::{Any, Err, Error, FromBer};
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
/// What `asn1-rs` refuses, an identifier longer than one octet, or bytes
/// after the value (`BerValueError`).
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
    let constructed = any.header.is_constructed();
    let number = u8::try_from(any.tag().0)
        .ok()
        .filter(|number| *number < 0x1f)
        .ok_or(Error::Unsupported)?;
    let tag = (any.class() as u8) << 6 | u8::from(constructed) << 5 | number;
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
        full: &input[..input.len() - rest.len()],
        contents: any.data,
        children,
    };
    Ok((rest, node))
}
