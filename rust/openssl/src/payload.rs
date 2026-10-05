//! Apple's receipt payload, decoded by OpenSSL's ASN.1 template decoder.
//!
//! The grammar lives in `payload.c` as an OpenSSL template:
//!
//! ```text
//! Payload           ::= SET OF ReceiptAttribute
//! ReceiptAttribute  ::= SEQUENCE { type INTEGER, version INTEGER, value OCTET STRING, ... }
//! ```
//!
//! One `ASN1_item_d2i` call decodes every tag and length of it, BER
//! (indefinite lengths, constructed strings) included. Before it, the header
//! walk (`walk.rs`) bounds the input and restores what 0.7's reader refused
//! and OpenSSL reads: a tag in high-tag-number form, a length of more than
//! four octets, and a constructed `OCTET STRING` value (or Xcode wrap) with
//! a chunk that is not an `OCTET STRING`. This module checks the types
//! OpenSSL reports for the three known fields and copies them out. What the
//! fields mean (which types exist, which value is a date) is the core's
//! business.

use crate::cms::string_octets;
use crate::item::{decode_exact, decodes_as_any, elements, typed};
use crate::walk::{self, Budget, ChunkError, Headers, WalkError};
use crate::{drain_errors, sys};
use libc::c_int;
use openssl_sys as ffi;

/// One `ReceiptAttribute`: its `type` (sign kept, so the core can refuse a
/// negative one) and the content octets of its `value`, constructed chunks
/// already joined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// `type`.
    pub attribute_type: i64,
    /// `value`: the encoding of the attribute's own value.
    pub value: Vec<u8>,
}

/// Why a decode failed. Detail only: the core decides what it means.
pub type PayloadError = &'static str;

/// An INTEGER's value, or `None` when it does not fit in 64 signed bits.
fn int64(integer: *const ffi::ASN1_INTEGER) -> Option<i64> {
    let mut value: i64 = 0;
    // SAFETY: `integer` is a live ASN1_INTEGER owned by a `Decoded` the
    // caller holds; `value` is a valid out-pointer.
    let fits = unsafe { sys::ASN1_INTEGER_get_int64(&raw mut value, integer) } == 1;
    if fits {
        Some(value)
    } else {
        drain_errors();
        None
    }
}

/// One attribute from its decoded fields, or `None` when the first three
/// are not INTEGER, anything, OCTET STRING.
fn attribute(fields: &[*mut ffi::ASN1_TYPE]) -> Option<Attribute> {
    let (&type_field, &value_field) = (fields.first()?, fields.get(2)?);
    let (type_kind, type_value) = typed(type_field);
    let (value_kind, value) = typed(value_field);
    if type_kind != ffi::V_ASN1_INTEGER || value_kind != ffi::V_ASN1_OCTET_STRING {
        return None;
    }
    Some(Attribute {
        attribute_type: int64(type_value.cast())?,
        value: string_octets(value),
    })
}

/// Why the walk refused a payload, as the detail the core reports.
fn walk_error(err: WalkError) -> PayloadError {
    match err {
        WalkError::TooDeep => "payload nests deeper than the ASN.1 depth bound",
        WalkError::TooManyNodes => "payload holds more values than the ASN.1 node budget",
        WalkError::Malformed | WalkError::Trailing => "payload is not one well-formed value",
    }
}

/// Whether every attribute's `value`, when it is a constructed
/// `OCTET STRING`, has only `OCTET STRING` chunks. A SET entry or a field of another shape is left to the template
/// decode to refuse.
fn values_are_octet_strings(set: &[u8]) -> Result<(), ChunkError> {
    let Some(entries) = walk::children(set) else {
        return Ok(());
    };
    entries.into_iter().try_for_each(|entry| {
        let Some(value) = walk::children(entry).and_then(|fields| fields.get(2).copied()) else {
            return Ok(());
        };
        match walk::header(value) {
            Some(header)
                if header.constructed
                    && header.class == sys::V_ASN1_UNIVERSAL
                    && header.tag == ffi::V_ASN1_OCTET_STRING =>
            {
                walk::octet_string_exact(value)
            }
            _ => Ok(()),
        }
    })
}

/// The attributes of a payload SET, in encoding order.
fn attribute_set(der: &[u8], budget: Budget) -> Result<Vec<Attribute>, PayloadError> {
    walk::walk_exact(der, budget, Headers::Short, Some(decodes_as_any)).map_err(walk_error)?;
    values_are_octet_strings(der)
        .map_err(|_| "an attribute value has a chunk that is not an OCTET STRING")?;
    // SAFETY: an item getter payload.c defines; it returns a static.
    let set = decode_exact(der, unsafe { sys::APRV_RECEIPT_PAYLOAD_it() })
        .ok_or("payload is not a SET OF ReceiptAttribute")?;
    // A SET OF (SEQUENCE OF ANY) decodes to a stack of stacks of
    // ASN1_TYPE, all owned by `set`.
    elements::<ffi::OPENSSL_STACK>(set.value().cast_const().cast())
        .into_iter()
        .map(|fields| attribute(&elements::<ffi::ASN1_TYPE>(fields)))
        .collect::<Option<Vec<Attribute>>>()
        .ok_or("payload is not a SET OF ReceiptAttribute")
}

/// The attribute SET of a receipt payload, in encoding order, read within
/// `budget`: constructed values nest at most `budget.depth` deep, the SET
/// counted as 1, and there are at most `budget.nodes` values.
///
/// Xcode receipts wrap the SET in one more OCTET STRING, so an input that
/// is exactly one OCTET STRING is unwrapped once and its content must then
/// be the SET, read within a budget of its own.
///
/// # Errors
/// When the input is neither shape, is over the budget, uses a header form
/// 0.7 refused, has a constructed `OCTET STRING` value or wrap with a
/// chunk that is not an `OCTET STRING`, a byte is left over, an
/// attribute's fields are not INTEGER, anything, OCTET STRING, or its type
/// does not fit in 64 signed bits.
pub fn receipt_attributes(der: &[u8], budget: Budget) -> Result<Vec<Attribute>, PayloadError> {
    let is_octet_string = walk::header(der).is_some_and(|header| {
        header.class == sys::V_ASN1_UNIVERSAL && header.tag == ffi::V_ASN1_OCTET_STRING
    });
    if !is_octet_string {
        return attribute_set(der, budget);
    }
    walk::walk_exact(der, budget, Headers::Short, Some(decodes_as_any)).map_err(walk_error)?;
    walk::octet_string_exact(der).map_err(|err| match err {
        ChunkError::Foreign => "double-wrapped payload has a chunk that is not an OCTET STRING",
        ChunkError::Malformed => "double-wrapped payload does not decode",
    })?;
    // SAFETY: a libcrypto item getter; it returns a static.
    let wrapped = decode_exact(der, unsafe { sys::ASN1_OCTET_STRING_it() })
        .ok_or("double-wrapped payload does not decode")?;
    let inner = string_octets(wrapped.value().cast_const().cast());
    attribute_set(&inner, budget)
        .map_err(|_| "double-wrapped payload is not a SET OF ReceiptAttribute")
}

/// The header of a value, when it is one 0.7's reader read: no
/// high-tag-number form and no length of more than four octets.
fn short_header(der: &[u8]) -> Option<walk::Header> {
    walk::header(der).filter(|header| !header.is_long_form())
}

/// An attribute value that must be exactly one INTEGER that fits in 64
/// signed bits. OpenSSL refuses an INTEGER that is empty, constructed or
/// not minimally encoded; a tag in high-tag-number form or a length of more
/// than four octets is refused before it, as 0.7 did.
///
/// # Errors
/// When it is not.
pub fn attribute_integer(der: &[u8]) -> Result<i64, PayloadError> {
    const NOT: PayloadError = "attribute value is not an INTEGER within 64 bits";
    if short_header(der).is_none() {
        return Err(NOT);
    }
    // SAFETY: a libcrypto item getter; it returns a static.
    decode_exact(der, unsafe { sys::ASN1_INTEGER_it() })
        .and_then(|integer| int64(integer.value().cast_const().cast()))
        .ok_or(NOT)
}

/// Which of the two string types a string value is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringKind {
    /// `UTF8String`.
    Utf8,
    /// `IA5String`.
    Ia5,
}

/// An attribute value that must be exactly one primitive `UTF8String` or
/// `IA5String`: its type and its content octets, not validated as text
/// (the core does that). A constructed string, which OpenSSL would join
/// whatever its chunks, a tag in high-tag-number form and a length of more
/// than four octets are refused, as 0.7 did.
///
/// # Errors
/// When it is anything else.
pub fn attribute_string(der: &[u8]) -> Result<(StringKind, Vec<u8>), PayloadError> {
    if short_header(der).is_none_or(|header| header.constructed) {
        return Err("attribute value is not a primitive string");
    }
    // DISPLAYTEXT is libcrypto's CHOICE of IA5String, VisibleString,
    // BMPString and UTF8String; it decodes to an ASN1_STRING that carries
    // the type it found.
    // SAFETY: a libcrypto item getter; it returns a static.
    let text = decode_exact(der, unsafe { sys::DISPLAYTEXT_it() })
        .ok_or("attribute value is not a string")?;
    let string: *const ffi::ASN1_STRING = text.value().cast_const().cast();
    // SAFETY: `string` is the live ASN1_STRING `text` owns.
    let kind: c_int = unsafe { ffi::ASN1_STRING_type(string) };
    match kind {
        sys::V_ASN1_UTF8STRING => Ok((StringKind::Utf8, string_octets(string))),
        sys::V_ASN1_IA5STRING => Ok((StringKind::Ia5, string_octets(string))),
        _ => Err("attribute value is not a UTF8String or IA5String"),
    }
}
