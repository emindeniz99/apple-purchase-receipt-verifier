//! Declarations of public libcrypto functions that openssl-sys does not
//! carry, and of the two template items `payload.c` defines. Nothing here
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

/// Opaque `ASN1_ITEM` (asn1t.h).
pub(crate) enum ASN1_ITEM {}
/// Opaque `CMS_SignerInfo` (cms.h).
pub(crate) enum CMS_SignerInfo {}
/// Opaque `STACK_OF(CMS_SignerInfo)`.
pub(crate) enum stack_st_CMS_SignerInfo {}

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
    pub(crate) fn CMS_unsigned_get_attr_count(si: *const CMS_SignerInfo) -> c_int;
    pub(crate) fn CMS_unsigned_get_attr(
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
    pub(crate) fn ASN1_INTEGER_get_int64(out: *mut i64, a: *const ffi::ASN1_INTEGER) -> c_int;
    pub(crate) fn ASN1_OCTET_STRING_it() -> *const ASN1_ITEM;
    pub(crate) fn ASN1_INTEGER_it() -> *const ASN1_ITEM;
    pub(crate) fn DISPLAYTEXT_it() -> *const ASN1_ITEM;
    pub(crate) fn ASN1_SEQUENCE_ANY_it() -> *const ASN1_ITEM;
    pub(crate) fn ASN1_SET_ANY_it() -> *const ASN1_ITEM;
    /// Defined by `payload.c`.
    pub(crate) fn APRV_RECEIPT_PAYLOAD_it() -> *const ASN1_ITEM;
}
