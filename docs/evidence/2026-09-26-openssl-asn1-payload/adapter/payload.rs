//! Spike only (round 4): the legacy receipt payload read with OpenSSL's
//! ASN.1 decoder instead of the core's hand-written `asn1.rs`.
//!
//! Two walks sit behind one API, so the core does not know which is built:
//! - default, `payload_templates.rs`: the grammar is declared as OpenSSL
//!   templates in `payload.c` and decoded with one `ASN1_item_d2i` call
//!   (option (a) of the round-4 comparison);
//! - feature `payload-any`, `payload_any.rs`: no C; the generic
//!   `SET OF ANY` / `SEQUENCE OF ANY` items, walked here (option (b)).
//!
//! Neither walk reads a tag or a length. OpenSSL decodes every TLV (BER,
//! indefinite lengths and constructed strings included); this crate only
//! asks it for one typed item at a time and copies out the fields.
//! Nothing decoded here is trusted: the same rules as the rest of the
//! adapter hold (no pointer leaves the crate, every failure drains the
//! error queue, every `unsafe` block has a SAFETY comment).

use crate::{drain_errors, init};
use libc::{c_int, c_long};
use openssl_sys as ffi;
use std::ptr;

/// One `ReceiptAttribute`: its `type` INTEGER (sign kept, so the core can
/// refuse a negative one) and the content octets of its `value`
/// OCTET STRING, constructed chunks already joined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// `type`
    pub attribute_type: i64,
    /// `value`, the DER of the attribute's own value.
    pub value: Vec<u8>,
}

/// Why a decode failed. Detail only: the core maps every one of these to
/// `INVALID_RECEIPT_FORMAT`.
pub type PayloadError = &'static str;

pub(crate) mod sys {
    //! Declarations openssl-sys does not carry. All are public libcrypto
    //! API (asn1.h, asn1t.h, x509v3.h), except `APRV_RECEIPT_PAYLOAD_it`,
    //! which `payload.c` defines.
    #![allow(non_camel_case_types, non_snake_case)]
    use super::ffi;
    use libc::{c_int, c_long};

    /// Opaque `ASN1_ITEM` (asn1t.h).
    pub enum ASN1_ITEM {}

    extern "C" {
        pub fn ASN1_item_d2i(
            val: *mut *mut ffi::ASN1_VALUE,
            input: *mut *const u8,
            len: c_long,
            it: *const ASN1_ITEM,
        ) -> *mut ffi::ASN1_VALUE;
        pub fn ASN1_item_free(val: *mut ffi::ASN1_VALUE, it: *const ASN1_ITEM);
        pub fn ASN1_INTEGER_get_int64(out: *mut i64, a: *const ffi::ASN1_INTEGER) -> c_int;
        pub fn ASN1_OCTET_STRING_it() -> *const ASN1_ITEM;
        #[cfg(not(feature = "payload-any"))]
        pub fn ASN1_INTEGER_it() -> *const ASN1_ITEM;
        #[cfg(feature = "payload-any")]
        pub fn ASN1_ANY_it() -> *const ASN1_ITEM;
        #[cfg(feature = "payload-any")]
        pub fn ASN1_SET_ANY_it() -> *const ASN1_ITEM;
        #[cfg(feature = "payload-any")]
        pub fn ASN1_SEQUENCE_ANY_it() -> *const ASN1_ITEM;
        #[cfg(not(feature = "payload-any"))]
        pub fn APRV_RECEIPT_PAYLOAD_it() -> *const ASN1_ITEM;
        #[cfg(not(feature = "payload-any"))]
        pub fn DISPLAYTEXT_it() -> *const ASN1_ITEM;
    }
}

/// A value OpenSSL decoded for one item, freed with that item's own free
/// routine (which frees the whole tree under it) when dropped.
pub(crate) struct Decoded {
    pub(crate) val: *mut ffi::ASN1_VALUE,
    it: *const sys::ASN1_ITEM,
}

impl Drop for Decoded {
    fn drop(&mut self) {
        // SAFETY: `val` came from ASN1_item_d2i for exactly `it`, is owned
        // by this value alone, and is freed once, here.
        unsafe { sys::ASN1_item_free(self.val, self.it) }
    }
}

/// Decodes exactly one `it` from `der`: `None` when OpenSSL refuses it or
/// when any byte is left over.
pub(crate) fn decode_exact(der: &[u8], it: *const sys::ASN1_ITEM) -> Option<Decoded> {
    init();
    let len = c_long::try_from(der.len()).ok()?;
    let start = der.as_ptr();
    let mut cursor = start;
    // SAFETY: `cursor` points at `len` readable bytes owned by `der`;
    // ASN1_item_d2i reads at most `len` of them and advances `cursor`
    // within them. The result is a new value we own, or null.
    let val = unsafe { sys::ASN1_item_d2i(ptr::null_mut(), &raw mut cursor, len, it) };
    if val.is_null() {
        refused(None);
        return None;
    }
    let decoded = Decoded { val, it };
    if cursor as usize - start as usize != der.len() {
        refused(Some("trailing bytes"));
        return None;
    }
    Some(decoded)
}

/// Drains the error queue. With the spike-only `payload-diagnostics`
/// feature (the differential fuzz build) it also keeps OpenSSL's reason
/// codes for [`last_refusal`]; no default build carries it.
fn refused(ours: Option<&str>) {
    #[cfg(feature = "payload-diagnostics")]
    {
        let reasons: Vec<String> = openssl::error::ErrorStack::get()
            .errors()
            .iter()
            .map(|e| e.reason().unwrap_or("?").to_owned())
            .chain(ours.map(str::to_owned))
            .collect();
        LAST_REFUSAL.with(|last| *last.borrow_mut() = reasons.join(","));
    }
    #[cfg(not(feature = "payload-diagnostics"))]
    {
        let _ = ours;
        drain_errors();
    }
}

#[cfg(feature = "payload-diagnostics")]
thread_local! {
    static LAST_REFUSAL: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

/// Spike diagnostics only: OpenSSL's reasons for the most recent refused
/// decode on this thread (then cleared).
#[cfg(feature = "payload-diagnostics")]
#[must_use]
pub fn last_refusal() -> String {
    LAST_REFUSAL.with(|last| std::mem::take(&mut *last.borrow_mut()))
}

/// The content octets of any `ASN1_STRING` (OCTET STRING, `UTF8String`,
/// `IA5String`, or the raw encoding of a SEQUENCE held in an `ASN1_TYPE`).
pub(crate) fn string_bytes(s: *const ffi::ASN1_STRING) -> Vec<u8> {
    if s.is_null() {
        return Vec::new();
    }
    // SAFETY: `s` is a live ASN1_STRING owned by a `Decoded` the caller
    // holds; OpenSSL keeps `length` bytes at `data`.
    let (data, len) = unsafe { (ffi::ASN1_STRING_get0_data(s), ffi::ASN1_STRING_length(s)) };
    match usize::try_from(len) {
        // SAFETY: as above; the slice is copied before the owner is freed.
        Ok(len) if len > 0 && !data.is_null() => unsafe { std::slice::from_raw_parts(data, len) }.to_vec(),
        _ => Vec::new(),
    }
}

/// An INTEGER's value, or `None` when it does not fit in 64 signed bits.
pub(crate) fn int64(a: *const ffi::ASN1_INTEGER) -> Option<i64> {
    let mut value: i64 = 0;
    // SAFETY: `a` is a live ASN1_INTEGER owned by a `Decoded` the caller
    // holds; `value` is a valid out-pointer.
    let ok: c_int = unsafe { sys::ASN1_INTEGER_get_int64(&raw mut value, a) };
    if ok == 1 {
        Some(value)
    } else {
        refused(Some("INTEGER wider than 64 bits"));
        None
    }
}

/// The attribute SET of a receipt payload, in encoding order.
///
/// Xcode receipts wrap the SET in one extra OCTET STRING, so an input that
/// decodes as exactly one OCTET STRING is unwrapped once and its content
/// must then be the SET.
///
/// # Errors
/// When the input is neither shape, or anything is left over.
pub fn receipt_attributes(der: &[u8]) -> Result<Vec<Attribute>, PayloadError> {
    // SAFETY: a libcrypto item getter; no arguments, returns a static.
    let octet_string = unsafe { sys::ASN1_OCTET_STRING_it() };
    if let Some(wrapped) = decode_exact(der, octet_string) {
        let inner = string_bytes(wrapped.val.cast());
        return walk::attribute_set(&inner).ok_or("double-wrapped payload is not a SET OF ReceiptAttribute");
    }
    // Not the Xcode shape: that refusal is expected, so it is not reported.
    #[cfg(feature = "payload-diagnostics")]
    let _ = last_refusal();
    walk::attribute_set(der).ok_or("payload is not a SET OF ReceiptAttribute")
}

/// An attribute value that must be exactly one INTEGER.
///
/// # Errors
/// When it is not, or its value does not fit in 64 signed bits.
pub fn attribute_integer(der: &[u8]) -> Result<i64, PayloadError> {
    walk::integer(der).ok_or("attribute value is not an INTEGER within 64 bits")
}

/// An attribute value that must be exactly one `UTF8String` or `IA5String`:
/// its content octets, unvalidated (the core reads them lossily, as before).
///
/// # Errors
/// When it is anything else.
pub fn attribute_string(der: &[u8]) -> Result<Vec<u8>, PayloadError> {
    walk::string(der).ok_or("attribute value is not a UTF8String or IA5String")
}

#[cfg(not(feature = "payload-any"))]
#[path = "payload_templates.rs"]
mod walk;
#[cfg(feature = "payload-any")]
#[path = "payload_any.rs"]
mod walk;
