//! Follow-up spike: the same `SignedData` API as the PKCS7 path, over
//! OpenSSL's CMS API (RFC 5652). The PKCS7 API predates three things the
//! Java oracle accepts: a SignerInfo that names its signer by
//! subjectKeyIdentifier (CMS version 3), RSA-PSS signatureAlgorithms and
//! Ed25519 (RFC 8419). The CMS API models all three.
//!
//! What stays exactly as on the PKCS7 path: the policy (substrate.rs) picks
//! the signer certificate, validates its path against the pinned anchors
//! only, at the receipt's own instant, through `verify_path` and its
//! callback; this module never builds a store and never calls CMS_verify.
//! Only the FIRST SignerInfo is judged, digested with its OWN
//! digestAlgorithm (not the SignedData-level digestAlgorithms set), as Java
//! does.

use super::{algor_oid, drain_errors, ffi, init, sk_num, sk_value, Certificate, CmsError, SignedAttributes};
use foreign_types::ForeignType;
use libc::{c_int, c_long};
use openssl::stack::Stack;
use openssl::x509::X509;
use std::ptr;

mod sys {
    #![allow(non_camel_case_types, clippy::missing_safety_doc)]
    use super::ffi;
    use libc::c_int;
    pub enum CMS_SignerInfo {}
    pub enum stack_st_CMS_SignerInfo {}
    extern "C" {
        pub fn CMS_get0_type(cms: *const ffi::CMS_ContentInfo) -> *const ffi::ASN1_OBJECT;
        pub fn CMS_get0_eContentType(cms: *mut ffi::CMS_ContentInfo) -> *const ffi::ASN1_OBJECT;
        pub fn CMS_get0_content(cms: *mut ffi::CMS_ContentInfo) -> *mut *mut ffi::ASN1_OCTET_STRING;
        pub fn CMS_get1_certs(cms: *mut ffi::CMS_ContentInfo) -> *mut ffi::stack_st_X509;
        pub fn CMS_get0_SignerInfos(cms: *mut ffi::CMS_ContentInfo) -> *mut stack_st_CMS_SignerInfo;
        pub fn CMS_SignerInfo_cert_cmp(si: *mut CMS_SignerInfo, cert: *mut ffi::X509) -> c_int;
        pub fn CMS_SignerInfo_get0_algs(
            si: *mut CMS_SignerInfo,
            pk: *mut *mut ffi::EVP_PKEY,
            signer: *mut *mut ffi::X509,
            pdig: *mut *mut ffi::X509_ALGOR,
            psig: *mut *mut ffi::X509_ALGOR,
        );
        pub fn CMS_SignerInfo_set1_signer_cert(si: *mut CMS_SignerInfo, signer: *mut ffi::X509);
        pub fn CMS_SignerInfo_verify(si: *mut CMS_SignerInfo) -> c_int;
        pub fn CMS_SignerInfo_verify_content(si: *mut CMS_SignerInfo, chain: *mut ffi::BIO) -> c_int;
        pub fn CMS_signed_get_attr_count(si: *const CMS_SignerInfo) -> c_int;
        pub fn CMS_signed_get_attr(si: *const CMS_SignerInfo, loc: c_int) -> *mut ffi::X509_ATTRIBUTE;
        pub fn BIO_f_md() -> *const ffi::BIO_METHOD;
        pub fn BIO_push(b: *mut ffi::BIO, append: *mut ffi::BIO) -> *mut ffi::BIO;
    }
    pub const BIO_C_SET_MD: c_int = 111;
}

/// A parsed CMS signedData. Owns its `CMS_ContentInfo`.
pub struct SignedData {
    cms: *mut ffi::CMS_ContentInfo,
}

impl Drop for SignedData {
    fn drop(&mut self) {
        // SAFETY: `cms` came from d2i_CMS_ContentInfo, is owned by this
        // value and is freed exactly once.
        unsafe { ffi::CMS_ContentInfo_free(self.cms) };
    }
}

// SAFETY: as for the PKCS7 path: read-only after parsing except through
// `&mut self`; no thread-affine state.
unsafe impl Send for SignedData {}

impl SignedData {
    /// Parses a DER/BER CMS ContentInfo and checks its outer shape.
    ///
    /// # Errors
    /// [`CmsError`] for anything that is not one signedData with attached
    /// content and at least one SignerInfo.
    pub fn parse(der: &[u8]) -> Result<SignedData, CmsError> {
        init();
        let len = c_long::try_from(der.len()).map_err(|_| CmsError::Malformed)?;
        let start = der.as_ptr();
        let mut cursor = start;
        // SAFETY: as in Certificate::from_der.
        let raw = unsafe { ffi::d2i_CMS_ContentInfo(ptr::null_mut(), &mut cursor, len) };
        if raw.is_null() {
            drain_errors();
            return Err(CmsError::Malformed);
        }
        let parsed = SignedData { cms: raw };
        if cursor as usize - start as usize != der.len() {
            return Err(CmsError::Trailing);
        }
        // SAFETY: reads the content type of the live structure.
        if unsafe { ffi::OBJ_obj2nid(sys::CMS_get0_type(parsed.cms)) } != ffi::NID_pkcs7_signed {
            return Err(CmsError::NotSignedData);
        }
        parsed.content_octets().ok_or(CmsError::NoContent)?;
        if parsed.signer_info_count() == 0 {
            return Err(CmsError::NoSignerInfo);
        }
        Ok(parsed)
    }

    fn content_octets(&self) -> Option<&[u8]> {
        // SAFETY: CMS_get0_content returns a pointer into the live
        // structure (or null); the octets outlive the slice (tied to &self).
        unsafe {
            let slot = sys::CMS_get0_content(self.cms);
            if slot.is_null() || (*slot).is_null() {
                drain_errors();
                return None;
            }
            let octets = *slot;
            let data = ffi::ASN1_STRING_get0_data(octets.cast());
            let length = usize::try_from(ffi::ASN1_STRING_length(octets.cast())).ok()?;
            if length == 0 {
                return Some(&[]);
            }
            if data.is_null() {
                return None;
            }
            Some(std::slice::from_raw_parts(data, length))
        }
    }

    /// The encapsulated content octets.
    #[must_use]
    pub fn content(&self) -> Vec<u8> {
        self.content_octets().map(<[u8]>::to_vec).unwrap_or_default()
    }

    /// The embedded certificates (CertificateChoices of type certificate),
    /// in order.
    #[must_use]
    pub fn certificates(&self) -> Vec<Certificate> {
        // SAFETY: CMS_get1_certs returns a new stack holding new references
        // (or null when there are none); Stack::from_ptr takes ownership and
        // frees both when dropped; `to_owned` takes one more reference each.
        unsafe {
            let raw = sys::CMS_get1_certs(self.cms);
            if raw.is_null() {
                drain_errors();
                return Vec::new();
            }
            let stack: Stack<X509> = Stack::from_ptr(raw);
            stack.iter().map(|c| Certificate(c.to_owned())).collect()
        }
    }

    fn signer_infos(&self) -> *mut sys::stack_st_CMS_SignerInfo {
        // SAFETY: the stack is owned by the live structure.
        unsafe { sys::CMS_get0_SignerInfos(self.cms) }
    }

    /// How many SignerInfos the blob carries.
    #[must_use]
    pub fn signer_info_count(&self) -> usize {
        let infos = self.signer_infos();
        if infos.is_null() {
            drain_errors();
            return 0;
        }
        // SAFETY: a live stack owned by the structure.
        usize::try_from(unsafe { sk_num(infos) }).unwrap_or(0)
    }

    fn first_signer_info(&self) -> *mut sys::CMS_SignerInfo {
        let infos = self.signer_infos();
        if infos.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: index 0 of a live stack; null when empty.
        unsafe { sk_value(infos, 0) }
    }

    /// Index into [`SignedData::certificates`] of the certificate the first
    /// SignerInfo names, by issuerAndSerialNumber OR subjectKeyIdentifier
    /// (`CMS_SignerInfo_cert_cmp`).
    #[must_use]
    pub fn signer_index(&self) -> Option<usize> {
        let si = self.first_signer_info();
        if si.is_null() {
            return None;
        }
        let certificates = self.certificates();
        let found = certificates.iter().position(|cert| {
            // SAFETY: both pointers are live for the call; the comparison
            // only reads them.
            unsafe { sys::CMS_SignerInfo_cert_cmp(si, cert.0.as_ptr()) == 0 }
        });
        drain_errors();
        found
    }

    fn algors(&self) -> (*mut ffi::X509_ALGOR, *mut ffi::X509_ALGOR) {
        let si = self.first_signer_info();
        let mut digest: *mut ffi::X509_ALGOR = ptr::null_mut();
        let mut signature: *mut ffi::X509_ALGOR = ptr::null_mut();
        if !si.is_null() {
            // SAFETY: `si` is live; the out-pointers receive borrowed
            // pointers owned by it.
            unsafe { sys::CMS_SignerInfo_get0_algs(si, ptr::null_mut(), ptr::null_mut(), &mut digest, &mut signature) };
        }
        (digest, signature)
    }

    /// The first SignerInfo's digest and signature algorithm OIDs.
    #[must_use]
    pub fn signer_algorithms(&self) -> (String, String) {
        let (digest, signature) = self.algors();
        (algor_oid(digest), algor_oid(signature))
    }

    fn signer_md(&self) -> *const ffi::EVP_MD {
        let (digest, _) = self.algors();
        if digest.is_null() {
            return ptr::null();
        }
        let mut object: *const ffi::ASN1_OBJECT = ptr::null();
        // SAFETY: `digest` is borrowed from the live SignerInfo.
        unsafe {
            ffi::X509_ALGOR_get0(&mut object, ptr::null_mut(), ptr::null_mut(), digest);
            let nid = ffi::OBJ_obj2nid(object);
            if nid == ffi::NID_undef {
                return ptr::null();
            }
            ffi::EVP_get_digestbynid(nid)
        }
    }

    /// Whether the first SignerInfo's digestAlgorithm names a digest the
    /// library implements (same rule as the PKCS7 path).
    #[must_use]
    pub fn signer_digest_known(&self) -> bool {
        !self.signer_md().is_null()
    }

    /// Facts about the first SignerInfo's signed attributes.
    #[must_use]
    pub fn signed_attributes(&self) -> SignedAttributes {
        let si = self.first_signer_info();
        let mut facts = SignedAttributes::default();
        if si.is_null() {
            return facts;
        }
        // SAFETY: every pointer read here is owned by the structure and
        // only read. CMS_signed_get_attr_count answers -1 when the [0]
        // field is absent.
        unsafe {
            let count = sys::CMS_signed_get_attr_count(si);
            if count < 0 {
                drain_errors();
                return facts;
            }
            facts.present = true;
            facts.count = usize::try_from(count).unwrap_or(0);
            let econtent_type = sys::CMS_get0_eContentType(self.cms);
            for index in 0..count {
                let attr = sys::CMS_signed_get_attr(si, index);
                if attr.is_null() {
                    continue;
                }
                let nid = ffi::OBJ_obj2nid(ffi::X509_ATTRIBUTE_get0_object(attr));
                let values = usize::try_from(ffi::X509_ATTRIBUTE_count(attr)).unwrap_or(0);
                if nid == ffi::NID_pkcs9_contentType {
                    facts.content_type.0 += 1;
                    if facts.content_type.0 == 1 {
                        facts.content_type.1 = values;
                        let value = ffi::X509_ATTRIBUTE_get0_type(attr, 0);
                        facts.content_type_matches = !value.is_null()
                            && (*value).type_ == ffi::V_ASN1_OBJECT
                            && !econtent_type.is_null()
                            && ffi::OBJ_cmp((*value).value.object, econtent_type) == 0;
                    }
                } else if nid == ffi::NID_pkcs9_messageDigest {
                    facts.message_digest.0 += 1;
                    if facts.message_digest.0 == 1 {
                        facts.message_digest.1 = values;
                    }
                }
            }
        }
        facts
    }

    /// Verifies the first SignerInfo under `signer`'s key: the signature
    /// over the signed attributes (`CMS_SignerInfo_verify`, which knows
    /// RSA PKCS#1 v1.5, RSA-PSS, ECDSA and Ed25519), then the content
    /// (`CMS_SignerInfo_verify_content`: the messageDigest attribute when
    /// signed attributes are present, else the signature over the content
    /// digest). The digest BIO is built for the SignerInfo's own
    /// digestAlgorithm. No chain, no store.
    #[must_use]
    pub fn verify_first_signer(&mut self, signer: &Certificate) -> bool {
        let si = self.first_signer_info();
        if si.is_null() {
            return false;
        }
        let md = self.signer_md();
        if md.is_null() {
            drain_errors();
            return false;
        }
        let content = self.content();
        let Ok(content_len) = c_int::try_from(content.len()) else {
            return false;
        };
        // SAFETY: `si` is owned by self.cms and mutated only here (the
        // signer certificate slot takes its own reference).
        let signed_attrs = unsafe {
            sys::CMS_SignerInfo_set1_signer_cert(si, signer.0.as_ptr());
            sys::CMS_signed_get_attr_count(si) >= 0
        };
        // SAFETY: as above.
        if signed_attrs && unsafe { sys::CMS_SignerInfo_verify(si) } != 1 {
            drain_errors();
            return false;
        }
        // SAFETY: a read-only memory BIO over `content`, which outlives it,
        // behind a digest BIO; freed once with BIO_free_all below.
        let chain = unsafe {
            let source = ffi::BIO_new_mem_buf(content.as_ptr().cast(), content_len);
            let digest = ffi::BIO_new(sys::BIO_f_md());
            if source.is_null() || digest.is_null() {
                if !source.is_null() {
                    ffi::BIO_free_all(source);
                }
                if !digest.is_null() {
                    ffi::BIO_free_all(digest);
                }
                drain_errors();
                return false;
            }
            ffi::BIO_ctrl(digest, sys::BIO_C_SET_MD, 0, md as *mut libc::c_void);
            sys::BIO_push(digest, source)
        };
        let mut buffer = [0u8; 4096];
        loop {
            // SAFETY: reads into a local buffer of the stated size.
            let read = unsafe { ffi::BIO_read(chain, buffer.as_mut_ptr().cast(), 4096) };
            if read <= 0 {
                break;
            }
        }
        // SAFETY: both pointers are live; the call finds the digest BIO in
        // `chain` by the SignerInfo's digestAlgorithm and only reads it.
        let ok = unsafe { sys::CMS_SignerInfo_verify_content(si, chain) } == 1;
        // SAFETY: frees the chain built above, once.
        unsafe { ffi::BIO_free_all(chain) };
        if !ok {
            drain_errors();
        }
        ok
    }
}
