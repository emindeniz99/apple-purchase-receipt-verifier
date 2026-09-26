//! Option (b): no C. OpenSSL's generic `SET OF ANY` and `SEQUENCE OF ANY`
//! items, from Rust through openssl-sys. OpenSSL still decodes every TLV,
//! but the grammar (which field is which, what type each must be) is
//! checked here, by reading `ASN1_TYPE::type_`.

use super::{decode_exact, int64, string_bytes, sys, Attribute};
use openssl_sys as ffi;

const V_ASN1_INTEGER: i32 = 2;
const V_ASN1_OCTET_STRING: i32 = 4;
const V_ASN1_UTF8STRING: i32 = 12;
const V_ASN1_SEQUENCE: i32 = 16;
const V_ASN1_IA5STRING: i32 = 22;

/// The elements of a decoded `STACK_OF(ASN1_TYPE)`, borrowed from its owner.
fn elements(stack: *const ffi::OPENSSL_STACK) -> Vec<*const ffi::ASN1_TYPE> {
    // SAFETY: `stack` is a STACK_OF(ASN1_TYPE) a `Decoded` the caller holds
    // owns; every index below `count` holds a non-null ASN1_TYPE.
    let count = unsafe { ffi::OPENSSL_sk_num(stack) };
    (0..count)
        // SAFETY: as above.
        .map(|index| unsafe { ffi::OPENSSL_sk_value(stack, index) }.cast_const().cast())
        .collect()
}

/// `(type_, value pointer)` of one `ASN1_TYPE`.
fn typed(t: *const ffi::ASN1_TYPE) -> (i32, *mut ffi::ASN1_STRING) {
    // SAFETY: `t` is a live ASN1_TYPE (see `elements`); for every type this
    // file accepts, the union member is an ASN1_STRING pointer (INTEGER and
    // OCTET STRING are ASN1_STRINGs; SEQUENCE is held as its encoding).
    unsafe { ((*t).type_, (*t).value.asn1_string) }
}

pub(super) fn attribute_set(der: &[u8]) -> Option<Vec<Attribute>> {
    // SAFETY: libcrypto item getters; return statics.
    let (set_any, sequence_any) = unsafe { (sys::ASN1_SET_ANY_it(), sys::ASN1_SEQUENCE_ANY_it()) };
    let set = decode_exact(der, set_any)?;
    let mut out = Vec::new();
    for element in elements(set.val.cast()) {
        let (kind, encoding) = typed(element);
        if kind != V_ASN1_SEQUENCE {
            return None;
        }
        // A SEQUENCE inside ANY is kept as its full encoding; decode it again
        // as SEQUENCE OF ANY to reach the fields.
        let fields = decode_exact(&string_bytes(encoding), sequence_any)?;
        let fields = elements(fields.val.cast());
        let (Some(&first), Some(&third)) = (fields.first(), fields.get(2)) else {
            return None;
        };
        let (type_kind, type_value) = typed(first);
        let (value_kind, value) = typed(third);
        if type_kind != V_ASN1_INTEGER || value_kind != V_ASN1_OCTET_STRING {
            return None;
        }
        out.push(Attribute { attribute_type: int64(type_value.cast())?, value: string_bytes(value) });
    }
    Some(out)
}

fn any(der: &[u8]) -> Option<super::Decoded> {
    // SAFETY: a libcrypto item getter; returns a static.
    decode_exact(der, unsafe { sys::ASN1_ANY_it() })
}

pub(super) fn integer(der: &[u8]) -> Option<i64> {
    let value = any(der)?;
    match typed(value.val.cast()) {
        (V_ASN1_INTEGER, integer) => int64(integer.cast()),
        _ => None,
    }
}

pub(super) fn string(der: &[u8]) -> Option<Vec<u8>> {
    let value = any(der)?;
    match typed(value.val.cast()) {
        (V_ASN1_UTF8STRING | V_ASN1_IA5STRING, text) => Some(string_bytes(text)),
        _ => None,
    }
}
