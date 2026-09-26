//! Option (a): the grammar lives in `payload.c` as OpenSSL templates, so
//! one `ASN1_item_d2i` call checks every tag of
//! `SET OF SEQUENCE { INTEGER, ANY, OCTET STRING }` and this file only
//! copies fields out of the typed result.

use super::{decode_exact, int64, string_bytes, sys, Attribute};
use openssl_sys as ffi;

/// `APRV_RECEIPT_ATTRIBUTE` from payload.c, field for field.
#[repr(C)]
struct RawAttribute {
    attribute_type: *mut ffi::ASN1_INTEGER,
    version: *mut ffi::ASN1_TYPE,
    value: *mut ffi::ASN1_OCTET_STRING,
}

pub(super) fn attribute_set(der: &[u8]) -> Option<Vec<Attribute>> {
    // SAFETY: an item getter payload.c defines; returns a static.
    let set = decode_exact(der, unsafe { sys::APRV_RECEIPT_PAYLOAD_it() })?;
    let stack: *const ffi::OPENSSL_STACK = set.val.cast();
    // SAFETY: a SET OF template decodes to a STACK_OF(APRV_RECEIPT_ATTRIBUTE)
    // that `set` owns.
    let count = unsafe { ffi::OPENSSL_sk_num(stack) };
    let mut out = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for index in 0..count {
        // SAFETY: `index` is in range; every element is a non-null
        // APRV_RECEIPT_ATTRIBUTE whose three fields the template decoder
        // filled (none is OPTIONAL), all owned by `set`.
        let raw = unsafe { &*ffi::OPENSSL_sk_value(stack, index).cast::<RawAttribute>() };
        out.push(Attribute {
            attribute_type: int64(raw.attribute_type)?,
            value: string_bytes(raw.value.cast()),
        });
    }
    Some(out)
}

pub(super) fn integer(der: &[u8]) -> Option<i64> {
    // SAFETY: a libcrypto item getter; returns a static.
    let value = decode_exact(der, unsafe { sys::ASN1_INTEGER_it() })?;
    int64(value.val.cast())
}

const V_ASN1_UTF8STRING: i32 = 12;
const V_ASN1_IA5STRING: i32 = 22;

pub(super) fn string(der: &[u8]) -> Option<Vec<u8>> {
    // SAFETY: a libcrypto item getter; returns a static. DISPLAYTEXT is an
    // MSTRING of IA5String, VisibleString, BMPString and UTF8String, and
    // decodes to an ASN1_STRING carrying the type it found.
    let value = decode_exact(der, unsafe { sys::DISPLAYTEXT_it() })?;
    let text: *const ffi::ASN1_STRING = value.val.cast();
    // SAFETY: `text` is the live ASN1_STRING `value` owns.
    match unsafe { ffi::ASN1_STRING_type(text) } {
        V_ASN1_UTF8STRING | V_ASN1_IA5STRING => Some(string_bytes(text)),
        _ => None,
    }
}
