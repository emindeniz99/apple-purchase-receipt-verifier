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
//! (indefinite lengths, constructed strings) included; this module reads no
//! tag and no length itself. It checks the types OpenSSL reports for the
//! three known fields and copies them out. What the fields mean (which types
//! exist, which value is a date) is the core's business.

use crate::cms::string_octets;
use crate::item::{decode_exact, elements, nesting_depth, typed};
use crate::{drain_errors, sys};
use libc::c_int;
use openssl_sys as ffi;

/// One `ReceiptAttribute`: its `type` (sign kept, so the core can refuse a
/// negative one), the content octets of its `value`, constructed chunks
/// already joined, and how deep SEQUENCEs and SETs nest in its fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// `type`.
    pub attribute_type: i64,
    /// `value`: the encoding of the attribute's own value.
    pub value: Vec<u8>,
    /// The deepest nesting of SEQUENCEs and SETs in any field (the
    /// `version` and any field after `value`), capped as
    /// [`receipt_attributes`] was asked to: 0 when no field is one.
    pub nesting: usize,
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
/// are not INTEGER, anything, OCTET STRING, or a field's nesting cannot be
/// measured.
fn attribute(fields: &[*mut ffi::ASN1_TYPE], cap: usize) -> Option<Attribute> {
    let (&type_field, &value_field) = (fields.first()?, fields.get(2)?);
    let (type_kind, type_value) = typed(type_field);
    let (value_kind, value) = typed(value_field);
    if type_kind != ffi::V_ASN1_INTEGER || value_kind != ffi::V_ASN1_OCTET_STRING {
        return None;
    }
    let mut nesting = 0;
    for &field in fields {
        nesting = nesting.max(nesting_depth(field, cap)?);
    }
    Some(Attribute {
        attribute_type: int64(type_value.cast())?,
        value: string_octets(value),
        nesting,
    })
}

/// The attributes of a payload SET, in encoding order.
fn attribute_set(der: &[u8], cap: usize) -> Option<Vec<Attribute>> {
    // SAFETY: an item getter payload.c defines; it returns a static.
    let set = decode_exact(der, unsafe { sys::APRV_RECEIPT_PAYLOAD_it() })?;
    // A SET OF (SEQUENCE OF ANY) decodes to a stack of stacks of
    // ASN1_TYPE, all owned by `set`.
    elements::<ffi::OPENSSL_STACK>(set.value().cast_const().cast())
        .into_iter()
        .map(|fields| attribute(&elements::<ffi::ASN1_TYPE>(fields), cap))
        .collect()
}

/// The attribute SET of a receipt payload, in encoding order. `cap` bounds
/// how far each attribute's [`Attribute::nesting`] is measured.
///
/// Xcode receipts wrap the SET in one more OCTET STRING, so an input that
/// decodes as exactly one OCTET STRING is unwrapped once and its content
/// must then be the SET.
///
/// # Errors
/// When the input is neither shape, a byte is left over, an attribute's
/// fields are not INTEGER, anything, OCTET STRING, or its type does not fit
/// in 64 signed bits.
pub fn receipt_attributes(der: &[u8], cap: usize) -> Result<Vec<Attribute>, PayloadError> {
    // SAFETY: a libcrypto item getter; it returns a static.
    if let Some(wrapped) = decode_exact(der, unsafe { sys::ASN1_OCTET_STRING_it() }) {
        let inner = string_octets(wrapped.value().cast_const().cast());
        return attribute_set(&inner, cap)
            .ok_or("double-wrapped payload is not a SET OF ReceiptAttribute");
    }
    attribute_set(der, cap).ok_or("payload is not a SET OF ReceiptAttribute")
}

/// An attribute value that must be exactly one INTEGER that fits in 64
/// signed bits. OpenSSL refuses an INTEGER that is empty or not minimally
/// encoded.
///
/// # Errors
/// When it is not.
pub fn attribute_integer(der: &[u8]) -> Result<i64, PayloadError> {
    // SAFETY: a libcrypto item getter; it returns a static.
    decode_exact(der, unsafe { sys::ASN1_INTEGER_it() })
        .and_then(|integer| int64(integer.value().cast_const().cast()))
        .ok_or("attribute value is not an INTEGER within 64 bits")
}

/// Which of the two string types a string value is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringKind {
    /// `UTF8String`.
    Utf8,
    /// `IA5String`.
    Ia5,
}

/// An attribute value that must be exactly one `UTF8String` or
/// `IA5String`: its type and its content octets, not validated as text
/// (the core does that).
///
/// # Errors
/// When it is anything else.
pub fn attribute_string(der: &[u8]) -> Result<(StringKind, Vec<u8>), PayloadError> {
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
