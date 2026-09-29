//! Declarations of public libcrypto functions that openssl-sys does not
//! carry, and of the template items `payload.c` and `envelope.c` define. Nothing here
//! is called from outside this crate, and nothing outside the small safe
//! wrappers in the sibling modules calls these.

#![allow(non_camel_case_types, non_snake_case)]

use libc::{c_int, c_long, c_void};
use openssl_sys as ffi;

/// `OPENSSL_INIT_NO_LOAD_CONFIG` (crypto.h).
pub(crate) const OPENSSL_INIT_NO_LOAD_CONFIG: u64 = 0x0000_0080;

/// `BIO_set_md` is a macro over `BIO_ctrl` with this command (bio.h).
pub(crate) const BIO_C_SET_MD: c_int = 111;

/// `V_ASN1_UTF8STRING` and `V_ASN1_IA5STRING` (asn1.h).
pub(crate) const V_ASN1_UTF8STRING: c_int = 12;
pub(crate) const V_ASN1_IA5STRING: c_int = 22;

/// `V_ASN1_UNIVERSAL`, the class value `ASN1_get_object` reports for a
/// universal tag (asn1.h).
pub(crate) const V_ASN1_UNIVERSAL: c_int = 0x00;
/// The bits of `ASN1_get_object`'s answer: a constructed encoding, an
/// indefinite length, an error (`asn1.h`, `asn1_lib.c`).
pub(crate) const V_ASN1_CONSTRUCTED: c_int = 0x20;
pub(crate) const ASN1_GET_OBJECT_INDEFINITE: c_int = 0x01;
pub(crate) const ASN1_GET_OBJECT_ERROR: c_int = 0x80;

/// Opaque `ASN1_ITEM` (asn1t.h).
pub(crate) enum ASN1_ITEM {}
/// Opaque `CMS_SignerInfo` (cms.h).
pub(crate) enum CMS_SignerInfo {}
/// Opaque `STACK_OF(CMS_SignerInfo)`.
pub(crate) enum stack_st_CMS_SignerInfo {}

/// `APRV_SIGNED_DATA` as `envelope.c` declares it: six pointers, in
/// declaration order. Only the encapsulated content and the three stacks
/// are read. The assertions below and `envelope.c`'s own pin the layout
/// both sides assume.
#[repr(C)]
pub(crate) struct APRV_SIGNED_DATA {
    pub(crate) version: *mut ffi::ASN1_TYPE,
    pub(crate) digest_algorithms: *mut ffi::ASN1_TYPE,
    pub(crate) encapsulated_content: *mut ffi::ASN1_TYPE,
    pub(crate) certificates: *mut ffi::OPENSSL_STACK,
    pub(crate) crls: *mut ffi::OPENSSL_STACK,
    pub(crate) signer_infos: *mut ffi::OPENSSL_STACK,
}

/// `APRV_CONTENT_INFO` as `envelope.c` declares it: two pointers.
#[repr(C)]
pub(crate) struct APRV_CONTENT_INFO {
    pub(crate) content_type: *mut ffi::ASN1_OBJECT,
    pub(crate) content: *mut ffi::ASN1_TYPE,
}

const POINTER: usize = core::mem::size_of::<*mut c_void>();
const _: () = {
    assert!(core::mem::size_of::<APRV_CONTENT_INFO>() == 2 * POINTER);
    assert!(core::mem::offset_of!(APRV_CONTENT_INFO, content) == POINTER);
    assert!(core::mem::size_of::<APRV_SIGNED_DATA>() == 6 * POINTER);
    assert!(core::mem::offset_of!(APRV_SIGNED_DATA, encapsulated_content) == 2 * POINTER);
    assert!(core::mem::offset_of!(APRV_SIGNED_DATA, certificates) == 3 * POINTER);
    assert!(core::mem::offset_of!(APRV_SIGNED_DATA, crls) == 4 * POINTER);
    assert!(core::mem::offset_of!(APRV_SIGNED_DATA, signer_infos) == 5 * POINTER);
};

/// The verify callback of an `X509_STORE_CTX`.
pub(crate) type VerifyCallback =
    Option<unsafe extern "C" fn(c_int, *mut ffi::X509_STORE_CTX) -> c_int>;

extern "C" {
    pub(crate) fn OPENSSL_init_crypto(opts: u64, settings: *const c_void) -> c_int;

    pub(crate) fn X509_STORE_CTX_set_verify_cb(ctx: *mut ffi::X509_STORE_CTX, cb: VerifyCallback);
    pub(crate) fn BASIC_CONSTRAINTS_free(bc: *mut c_void);
    pub(crate) fn X509_check_ca(x: *mut ffi::X509) -> c_int;
    /// New in OpenSSL 4.0, which made `ASN1_STRING` opaque.
    pub(crate) fn ASN1_BIT_STRING_get_length(
        abs: *const ffi::ASN1_BIT_STRING,
        length: *mut libc::size_t,
        unused_bits: *mut c_int,
    ) -> c_int;

    pub(crate) fn BIO_f_md() -> *const ffi::BIO_METHOD;
    pub(crate) fn BIO_push(b: *mut ffi::BIO, append: *mut ffi::BIO) -> *mut ffi::BIO;

    pub(crate) fn CMS_get0_type(cms: *const ffi::CMS_ContentInfo) -> *const ffi::ASN1_OBJECT;
    pub(crate) fn CMS_get0_eContentType(cms: *mut ffi::CMS_ContentInfo) -> *const ffi::ASN1_OBJECT;
    pub(crate) fn CMS_get0_content(
        cms: *mut ffi::CMS_ContentInfo,
    ) -> *mut *mut ffi::ASN1_OCTET_STRING;
    pub(crate) fn CMS_get1_certs(cms: *mut ffi::CMS_ContentInfo) -> *mut ffi::stack_st_X509;
    pub(crate) fn CMS_get0_SignerInfos(
        cms: *mut ffi::CMS_ContentInfo,
    ) -> *mut stack_st_CMS_SignerInfo;
    pub(crate) fn CMS_SignerInfo_cert_cmp(si: *mut CMS_SignerInfo, cert: *mut ffi::X509) -> c_int;
    pub(crate) fn CMS_SignerInfo_get0_algs(
        si: *mut CMS_SignerInfo,
        pk: *mut *mut ffi::EVP_PKEY,
        signer: *mut *mut ffi::X509,
        pdig: *mut *mut ffi::X509_ALGOR,
        psig: *mut *mut ffi::X509_ALGOR,
    );
    pub(crate) fn CMS_SignerInfo_set1_signer_cert(si: *mut CMS_SignerInfo, signer: *mut ffi::X509);
    pub(crate) fn CMS_SignerInfo_verify(si: *mut CMS_SignerInfo) -> c_int;
    pub(crate) fn CMS_SignerInfo_verify_content(
        si: *mut CMS_SignerInfo,
        chain: *mut ffi::BIO,
    ) -> c_int;
    pub(crate) fn CMS_signed_get_attr_count(si: *const CMS_SignerInfo) -> c_int;
    pub(crate) fn CMS_signed_get_attr(
        si: *const CMS_SignerInfo,
        loc: c_int,
    ) -> *mut ffi::X509_ATTRIBUTE;

    pub(crate) fn ASN1_item_d2i(
        val: *mut *mut ffi::ASN1_VALUE,
        input: *mut *const u8,
        len: c_long,
        it: *const ASN1_ITEM,
    ) -> *mut ffi::ASN1_VALUE;
    pub(crate) fn ASN1_item_free(val: *mut ffi::ASN1_VALUE, it: *const ASN1_ITEM);
    pub(crate) fn ASN1_get_object(
        pp: *mut *const u8,
        plength: *mut c_long,
        ptag: *mut c_int,
        pclass: *mut c_int,
        omax: c_long,
    ) -> c_int;
    pub(crate) fn ASN1_INTEGER_get_int64(out: *mut i64, a: *const ffi::ASN1_INTEGER) -> c_int;
    pub(crate) fn ASN1_OCTET_STRING_it() -> *const ASN1_ITEM;
    pub(crate) fn ASN1_INTEGER_it() -> *const ASN1_ITEM;
    pub(crate) fn DISPLAYTEXT_it() -> *const ASN1_ITEM;
    /// Defined by `payload.c`.
    pub(crate) fn APRV_RECEIPT_PAYLOAD_it() -> *const ASN1_ITEM;
    /// Defined by `envelope.c`.
    pub(crate) fn APRV_CONTENT_INFO_it() -> *const ASN1_ITEM;
    /// Defined by `envelope.c`.
    pub(crate) fn APRV_SIGNED_DATA_it() -> *const ASN1_ITEM;
}
