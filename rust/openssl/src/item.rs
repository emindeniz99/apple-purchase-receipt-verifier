//! Values decoded by OpenSSL's generic template decoder (`ASN1_item_d2i`),
//! and the nesting depth of the values OpenSSL keeps whole.

use crate::cms::string_octets;
use crate::{d2i_whole, drain_errors, init, sys};
use libc::{c_int, c_long};
use openssl_sys as ffi;
use std::ptr;

/// A value OpenSSL decoded as one item, freed with that item's own free
/// routine (which frees the whole tree under it) when dropped.
pub(crate) struct Decoded {
    value: *mut ffi::ASN1_VALUE,
    item: *const sys::ASN1_ITEM,
}

impl Decoded {
    /// The decoded value, owned by `self`.
    pub(crate) fn value(&self) -> *mut ffi::ASN1_VALUE {
        self.value
    }
}

impl Drop for Decoded {
    fn drop(&mut self) {
        // SAFETY: `value` came from ASN1_item_d2i for exactly `item`, is
        // owned by this value alone, and is freed once, here.
        unsafe { sys::ASN1_item_free(self.value, self.item) }
    }
}

/// Exactly one value of `item` from `der`: `None` when OpenSSL refuses it
/// or a byte is left over. `item` is one of the static item getters' results.
pub(crate) fn decode_exact(der: &[u8], item: *const sys::ASN1_ITEM) -> Option<Decoded> {
    init();
    let (value, whole) = d2i_whole(der, |cursor, len: c_long| {
        // SAFETY: `cursor` points at `len` readable bytes of `der`;
        // ASN1_item_d2i reads at most `len` of them, advances the cursor
        // within them and returns a new value of `item` the caller owns, or
        // null. `item` is a static ASN1_ITEM.
        unsafe { sys::ASN1_item_d2i(ptr::null_mut(), cursor, len, item) }
    })?;
    let decoded = Decoded { value, item };
    whole.then_some(decoded)
}

/// The elements of a decoded `STACK_OF(T)`, borrowed from its owner.
pub(crate) fn elements<T>(stack: *const ffi::OPENSSL_STACK) -> Vec<*mut T> {
    // SAFETY: `stack` is a live stack a `Decoded` the caller holds owns.
    let count = unsafe { ffi::OPENSSL_sk_num(stack) };
    (0..count)
        // SAFETY: every index below the count is in range.
        .map(|index| unsafe { ffi::OPENSSL_sk_value(stack, index) }.cast::<T>())
        .filter(|element| !element.is_null())
        .collect()
}

/// An `ASN1_TYPE`'s type, and its value when that is held as a string
/// (every universal type but BOOLEAN, OBJECT and NULL; a SEQUENCE, a SET or
/// a value of another class as its whole encoding).
pub(crate) fn typed(value: *const ffi::ASN1_TYPE) -> (c_int, *const ffi::ASN1_STRING) {
    // SAFETY: `value` is a live ASN1_TYPE its owner keeps. The union member
    // is read as a string pointer only for the types that store one.
    unsafe {
        let kind = (*value).type_;
        let string = match kind {
            ffi::V_ASN1_BOOLEAN | ffi::V_ASN1_OBJECT | ffi::V_ASN1_NULL => ptr::null(),
            _ => (*value).value.asn1_string.cast_const(),
        };
        (kind, string)
    }
}

/// How deep SEQUENCEs and SETs nest in `value`: 0 for a value that is
/// neither, 1 more than its deepest element for one that is. OpenSSL keeps
/// a SEQUENCE or SET inside an `ANY` whole, without looking inside; this
/// decodes each level with the generic `SEQUENCE OF ANY` and `SET OF ANY`
/// items to measure it. It stops descending past `cap` and answers
/// `cap + 1` then, so the work is bounded. `None` when a level does not
/// decode.
pub(crate) fn nesting_depth(value: *const ffi::ASN1_TYPE, cap: usize) -> Option<usize> {
    let (kind, string) = typed(value);
    nesting_depth_of(kind, string, cap)
}

/// [`nesting_depth`] of a value given as its type and, for a SEQUENCE or a
/// SET, the string holding its whole encoding.
pub(crate) fn nesting_depth_of(
    kind: c_int,
    string: *const ffi::ASN1_STRING,
    cap: usize,
) -> Option<usize> {
    let item = match kind {
        // SAFETY: libcrypto item getters; they return statics.
        ffi::V_ASN1_SEQUENCE => unsafe { sys::ASN1_SEQUENCE_ANY_it() },
        // SAFETY: as above.
        ffi::V_ASN1_SET => unsafe { sys::ASN1_SET_ANY_it() },
        _ => return Some(0),
    };
    if cap == 0 {
        return Some(1);
    }
    let decoded = decode_exact(&string_octets(string), item);
    let Some(decoded) = decoded else {
        drain_errors();
        return None;
    };
    let mut deepest = 0;
    for element in elements::<ffi::ASN1_TYPE>(decoded.value().cast_const().cast()) {
        deepest = deepest.max(nesting_depth(element, cap - 1)?);
    }
    Some(deepest + 1)
}
