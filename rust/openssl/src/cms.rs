//! A CMS `SignedData` (RFC 5652), parsed and checked by OpenSSL's CMS API.
//!
//! This module never builds a store and never calls `CMS_verify`: the core
//! picks the signer certificate and validates its path to the pinned
//! anchors itself ([`crate::verify_path`]). Each `SignerInfo` is checked on
//! its own with `CMS_SignerInfo_verify` (the signature over the signed
//! attributes) and `CMS_SignerInfo_verify_content` (the content digest, or
//! the signature over it when there are no signed attributes), digesting
//! the content with that `SignerInfo`'s own `digestAlgorithm` rather than
//! the unsigned `digestAlgorithms` set of the `SignedData`.

use crate::certificate::Certificate;
use crate::item::{nesting_depth, nesting_depth_of};
use crate::sys::{self, CMS_SignerInfo};
use crate::{d2i_whole, drain_errors, init, keys};
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::c_int;
use openssl::asn1::Asn1ObjectRef;
use openssl::cms::CmsContentInfo;
use openssl::stack::Stack;
use openssl::x509::X509;
use openssl_sys as ffi;
use std::ptr;

/// Why a blob is not a `SignedData` the core can look at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmsError {
    /// OpenSSL does not decode it as a `ContentInfo`, which includes an
    /// embedded certificate or a signed attribute set it cannot parse.
    Malformed,
    /// Bytes follow the outer value.
    Trailing,
    /// A `ContentInfo` of another type than `signedData`.
    NotSignedData,
    /// No encapsulated content (a detached signature).
    NoContent,
    /// No `SignerInfo`.
    NoSignerInfo,
}

impl core::fmt::Display for CmsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            CmsError::Malformed => "not a CMS ContentInfo",
            CmsError::Trailing => "bytes follow the CMS ContentInfo",
            CmsError::NotSignedData => "not a CMS SignedData",
            CmsError::NoContent => "no encapsulated payload",
            CmsError::NoSignerInfo => "no signer info",
        })
    }
}

impl std::error::Error for CmsError {}

/// What a `SignerInfo`'s signed attributes hold, for the RFC 5652 section
/// 5.3 and 11 rules the core applies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignedAttributes {
    /// Whether the `signedAttrs [0]` field is present at all.
    pub present: bool,
    /// How many `contentType` attributes there are.
    pub content_type_count: usize,
    /// How many values the first `contentType` attribute holds.
    pub content_type_values: usize,
    /// Whether the first `contentType` value is the `eContentType`.
    pub content_type_matches: bool,
    /// How many `messageDigest` attributes there are.
    pub message_digest_count: usize,
    /// How many values the first `messageDigest` attribute holds.
    pub message_digest_values: usize,
}

/// How deep SEQUENCEs and SETs nest in the values of one `SignerInfo` that
/// OpenSSL keeps whole without looking inside, each 0 when none is one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SignerNesting {
    /// The deepest signed or unsigned attribute value.
    pub attribute_values: usize,
    /// The deeper of the digest and signature algorithm parameters.
    pub algorithm_parameters: usize,
}

/// A parsed CMS `SignedData` with attached content and at least one
/// `SignerInfo`.
pub struct SignedData {
    cms: CmsContentInfo,
    content: Vec<u8>,
}

impl core::fmt::Debug for SignedData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedData")
            .field("content", &self.content.len())
            .finish_non_exhaustive()
    }
}

impl SignedData {
    /// Parses a DER or BER `ContentInfo` (`d2i_CMS_ContentInfo`) and checks
    /// its outer shape.
    ///
    /// # Errors
    /// [`CmsError`] for anything but one `signedData` with attached content
    /// and at least one `SignerInfo`.
    pub fn parse(der: &[u8]) -> Result<SignedData, CmsError> {
        init();
        let (raw, whole) = d2i_whole(der, |cursor, len| {
            // SAFETY: `cursor` points at `len` readable bytes of `der`;
            // d2i_CMS_ContentInfo reads at most `len` of them, advances the
            // cursor within them and returns a new structure the caller
            // owns, or null.
            unsafe { ffi::d2i_CMS_ContentInfo(ptr::null_mut(), cursor, len) }
        })
        .ok_or(CmsError::Malformed)?;
        // SAFETY: `raw` is a freshly allocated CMS_ContentInfo nothing else
        // owns; `CmsContentInfo` takes that ownership and frees it once.
        let cms = unsafe { CmsContentInfo::from_ptr(raw) };
        if !whole {
            return Err(CmsError::Trailing);
        }
        if content_type_nid(&cms) != ffi::NID_pkcs7_signed {
            return Err(CmsError::NotSignedData);
        }
        let content = encapsulated_content(&cms).ok_or(CmsError::NoContent)?;
        let parsed = SignedData { cms, content };
        if parsed.signer_count() == 0 {
            return Err(CmsError::NoSignerInfo);
        }
        Ok(parsed)
    }

    /// The encapsulated content octets, constructed chunks joined.
    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// The embedded certificates (the `certificate` choices of the
    /// `certificates` field), in order.
    #[must_use]
    pub fn certificates(&self) -> Vec<Certificate> {
        // SAFETY: CMS_get1_certs returns a new stack holding a new
        // reference to each certificate, or null when there is none;
        // `Stack` takes ownership of both and frees them when dropped.
        let stack: Option<Stack<X509>> = unsafe {
            let raw = sys::CMS_get1_certs(self.cms.as_ptr());
            (!raw.is_null()).then(|| Stack::from_ptr(raw))
        };
        drain_errors();
        stack.map_or_else(Vec::new, |stack| {
            stack
                .iter()
                .map(|x509| Certificate::from_x509(x509.to_owned()))
                .collect()
        })
    }

    /// How many `SignerInfo`s the blob carries.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        let infos = self.signer_infos();
        if infos.is_null() {
            drain_errors();
            return 0;
        }
        // SAFETY: a live stack owned by the structure.
        usize::try_from(unsafe { ffi::OPENSSL_sk_num(infos.cast()) }).unwrap_or(0)
    }

    /// Whether `SignerInfo` `index` names `certificate` as its signer, by
    /// `issuerAndSerialNumber` or `subjectKeyIdentifier`
    /// (`CMS_SignerInfo_cert_cmp`).
    #[must_use]
    pub fn names_signer(&self, index: usize, certificate: &Certificate) -> bool {
        let Some(si) = self.signer_info(index) else {
            return false;
        };
        // SAFETY: both pointers are live for the call; the comparison only
        // reads them.
        let names = unsafe { sys::CMS_SignerInfo_cert_cmp(si, certificate.x509().as_ptr()) } == 0;
        drain_errors();
        names
    }

    /// Whether `SignerInfo` `index`'s `digestAlgorithm` names a digest
    /// OpenSSL implements.
    #[must_use]
    pub fn signer_digest_known(&self, index: usize) -> bool {
        self.signer_info(index)
            .is_some_and(|si| !signer_md(si).is_null())
    }

    /// The facts about `SignerInfo` `index`'s signed attributes.
    #[must_use]
    pub fn signed_attributes(&self, index: usize) -> SignedAttributes {
        let mut facts = SignedAttributes::default();
        let Some(si) = self.signer_info(index) else {
            return facts;
        };
        // SAFETY: reads the signed attribute count of a live SignerInfo;
        // -1 means the field is absent.
        let count = unsafe { sys::CMS_signed_get_attr_count(si) };
        if count < 0 {
            drain_errors();
            return facts;
        }
        facts.present = true;
        let econtent_type = self.econtent_type();
        for position in 0..count {
            let Some(attribute) = signed_attribute(si, position) else {
                continue;
            };
            let nid = attribute_nid(attribute);
            if nid == ffi::NID_pkcs9_contentType {
                facts.content_type_count = facts.content_type_count.saturating_add(1);
                if facts.content_type_count == 1 {
                    facts.content_type_values = attribute_value_count(attribute);
                    facts.content_type_matches = econtent_type
                        .is_some_and(|wanted| first_value_is_object(attribute, wanted));
                }
            } else if nid == ffi::NID_pkcs9_messageDigest {
                facts.message_digest_count = facts.message_digest_count.saturating_add(1);
                if facts.message_digest_count == 1 {
                    facts.message_digest_values = attribute_value_count(attribute);
                }
            }
        }
        facts
    }

    /// Verifies `SignerInfo` `index` under `signer`'s key: with signed
    /// attributes, the signature over them and then their `messageDigest`
    /// against the content; without, the signature over the content. The
    /// content is digested with the `SignerInfo`'s own `digestAlgorithm`.
    /// No chain, no store: the core has already judged the certificate.
    #[must_use]
    pub fn verify_signer(&mut self, index: usize, signer: &Certificate) -> bool {
        init();
        let Some(si) = self.signer_info(index) else {
            return false;
        };
        let md = signer_md(si);
        if md.is_null() {
            drain_errors();
            return false;
        }
        let Ok(key) = signer.x509().public_key() else {
            drain_errors();
            return false;
        };
        keys::record(&key);
        // SAFETY: `si` is owned by `self.cms`, which `&mut self` borrows
        // exclusively; the call takes its own reference to the certificate
        // and its key.
        unsafe { sys::CMS_SignerInfo_set1_signer_cert(si, signer.x509().as_ptr()) };
        // SAFETY: reads the signed attribute count of a live SignerInfo.
        let has_signed_attributes = unsafe { sys::CMS_signed_get_attr_count(si) } >= 0;
        // SAFETY: `si` carries its signer's key now (set above).
        if has_signed_attributes && unsafe { sys::CMS_SignerInfo_verify(si) } != 1 {
            drain_errors();
            return false;
        }
        let verified = DigestBio::over(&self.content, md).is_some_and(|chain| {
            // SAFETY: both pointers are live for the call; it finds the
            // digest BIO in `chain` by the SignerInfo's digestAlgorithm
            // and only reads it.
            unsafe { sys::CMS_SignerInfo_verify_content(si, chain.as_ptr()) == 1 }
        });
        drain_errors();
        verified
    }

    /// How deep SEQUENCEs and SETs nest in the values of `SignerInfo`
    /// `index` that OpenSSL keeps whole: its signed and unsigned attribute
    /// values and its two algorithm parameters, each measured up to `cap`
    /// (see [`SignerNesting`]). `None` when one does not decode as the
    /// SEQUENCE or SET it claims to be.
    #[must_use]
    pub fn signer_nesting(&self, index: usize, cap: usize) -> Option<SignerNesting> {
        let si = self.signer_info(index)?;
        let mut nesting = SignerNesting::default();
        for (count, get) in [
            (
                sys::CMS_signed_get_attr_count
                    as unsafe extern "C" fn(*const CMS_SignerInfo) -> c_int,
                sys::CMS_signed_get_attr
                    as unsafe extern "C" fn(
                        *const CMS_SignerInfo,
                        c_int,
                    ) -> *mut ffi::X509_ATTRIBUTE,
            ),
            (sys::CMS_unsigned_get_attr_count, sys::CMS_unsigned_get_attr),
        ] {
            // SAFETY: reads the attribute count of a live SignerInfo (-1
            // when the field is absent).
            let attributes = unsafe { count(si) };
            for position in 0..attributes.max(0) {
                // SAFETY: `position` is below that count; the attribute is
                // owned by `si`.
                let attribute = unsafe { get(si, position) };
                if attribute.is_null() {
                    continue;
                }
                for value in 0..attribute_value_count(attribute) {
                    let value = c_int::try_from(value).ok()?;
                    // SAFETY: `value` is below the attribute's value count;
                    // the result is owned by the attribute, or null.
                    let typed = unsafe { ffi::X509_ATTRIBUTE_get0_type(attribute, value) };
                    if typed.is_null() {
                        continue;
                    }
                    nesting.attribute_values =
                        nesting.attribute_values.max(nesting_depth(typed, cap)?);
                }
            }
        }
        let (digest, signature) = algorithms(si);
        for algorithm in [digest, signature] {
            nesting.algorithm_parameters = nesting
                .algorithm_parameters
                .max(parameter_nesting(algorithm, cap)?);
        }
        drain_errors();
        Some(nesting)
    }

    fn signer_infos(&self) -> *mut sys::stack_st_CMS_SignerInfo {
        // SAFETY: the stack is owned by the live structure (null for a type
        // without SignerInfos, which `parse` has refused).
        unsafe { sys::CMS_get0_SignerInfos(self.cms.as_ptr()) }
    }

    fn signer_info(&self, index: usize) -> Option<*mut CMS_SignerInfo> {
        let index = c_int::try_from(index).ok()?;
        if index >= c_int::try_from(self.signer_count()).ok()? {
            return None;
        }
        // SAFETY: `index` is below the live stack's length (checked above).
        let si: *mut CMS_SignerInfo =
            unsafe { ffi::OPENSSL_sk_value(self.signer_infos().cast(), index) }.cast();
        (!si.is_null()).then_some(si)
    }

    fn econtent_type(&self) -> Option<&Asn1ObjectRef> {
        // SAFETY: returns a pointer owned by the live structure, or null.
        let object = unsafe { sys::CMS_get0_eContentType(self.cms.as_ptr()) };
        // SAFETY: a non-null object stays valid while `self` is borrowed.
        (!object.is_null()).then(|| unsafe { Asn1ObjectRef::from_ptr(object.cast_mut()) })
    }
}

fn content_type_nid(cms: &CmsContentInfo) -> c_int {
    // SAFETY: reads the content type of a live structure; OBJ_obj2nid
    // accepts null and answers NID_undef.
    unsafe { ffi::OBJ_obj2nid(sys::CMS_get0_type(cms.as_ptr())) }
}

/// The eContent octets of a `signedData`, or `None` when there are none.
fn encapsulated_content(cms: &CmsContentInfo) -> Option<Vec<u8>> {
    // SAFETY: CMS_get0_content returns a pointer to the eContent slot of the
    // live structure, or null; the octets are copied before `cms` can be
    // dropped.
    let octets = unsafe {
        let slot = sys::CMS_get0_content(cms.as_ptr());
        if slot.is_null() || (*slot).is_null() {
            drain_errors();
            return None;
        }
        *slot
    };
    Some(string_octets(octets.cast()))
}

/// The octets of a live `ASN1_STRING`, copied.
pub(crate) fn string_octets(string: *const ffi::ASN1_STRING) -> Vec<u8> {
    if string.is_null() {
        return Vec::new();
    }
    // SAFETY: `string` is a live ASN1_STRING the caller's owner holds;
    // OpenSSL keeps `length` bytes at `data`.
    let (data, length) = unsafe {
        (
            ffi::ASN1_STRING_get0_data(string),
            ffi::ASN1_STRING_length(string),
        )
    };
    match usize::try_from(length) {
        // SAFETY: as above; the bytes are copied before the owner is freed.
        Ok(length) if length > 0 && !data.is_null() => {
            unsafe { std::slice::from_raw_parts(data, length) }.to_vec()
        }
        _ => Vec::new(),
    }
}

/// `si`'s `digestAlgorithm` and `signatureAlgorithm`, borrowed from it.
fn algorithms(si: *mut CMS_SignerInfo) -> (*mut ffi::X509_ALGOR, *mut ffi::X509_ALGOR) {
    let mut digest: *mut ffi::X509_ALGOR = ptr::null_mut();
    let mut signature: *mut ffi::X509_ALGOR = ptr::null_mut();
    // SAFETY: `si` is live; the out-pointers receive pointers the
    // SignerInfo owns.
    unsafe {
        sys::CMS_SignerInfo_get0_algs(
            si,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut digest,
            &raw mut signature,
        );
    }
    (digest, signature)
}

/// [`nesting_depth`] of an `AlgorithmIdentifier`'s parameters.
fn parameter_nesting(algorithm: *mut ffi::X509_ALGOR, cap: usize) -> Option<usize> {
    if algorithm.is_null() {
        return Some(0);
    }
    let mut kind: c_int = 0;
    let mut value: *const libc::c_void = ptr::null();
    // SAFETY: `algorithm` is live; the out-values receive the parameter's
    // type and a pointer the algorithm owns (for a SEQUENCE or SET, the
    // ASN1_STRING holding its encoding).
    unsafe { ffi::X509_ALGOR_get0(ptr::null_mut(), &raw mut kind, &raw mut value, algorithm) };
    nesting_depth_of(kind, value.cast(), cap)
}

/// The digest `si`'s `digestAlgorithm` names, or null when OpenSSL
/// implements none by that OID.
fn signer_md(si: *mut CMS_SignerInfo) -> *const ffi::EVP_MD {
    let (digest, _) = algorithms(si);
    if digest.is_null() {
        return ptr::null();
    }
    let mut object: *const ffi::ASN1_OBJECT = ptr::null();
    // SAFETY: `digest` is borrowed from the live SignerInfo; the call
    // stores a borrowed pointer to its OID.
    unsafe { ffi::X509_ALGOR_get0(&raw mut object, ptr::null_mut(), ptr::null_mut(), digest) };
    // SAFETY: OBJ_obj2nid accepts null.
    let nid = unsafe { ffi::OBJ_obj2nid(object) };
    if nid == ffi::NID_undef {
        return ptr::null();
    }
    // SAFETY: returns a static method table or null.
    unsafe { ffi::EVP_get_digestbynid(nid) }
}

/// Signed attribute `position` of `si`, borrowed from it.
fn signed_attribute(si: *mut CMS_SignerInfo, position: c_int) -> Option<*mut ffi::X509_ATTRIBUTE> {
    // SAFETY: `position` is below the SignerInfo's signed attribute count
    // (the only caller iterates that range); the result is owned by `si`.
    let attribute = unsafe { sys::CMS_signed_get_attr(si, position) };
    (!attribute.is_null()).then_some(attribute)
}

fn attribute_nid(attribute: *mut ffi::X509_ATTRIBUTE) -> c_int {
    // SAFETY: `attribute` is live and owned by its SignerInfo; both calls
    // only read (OBJ_obj2nid accepts null).
    unsafe { ffi::OBJ_obj2nid(ffi::X509_ATTRIBUTE_get0_object(attribute)) }
}

fn attribute_value_count(attribute: *mut ffi::X509_ATTRIBUTE) -> usize {
    // SAFETY: reads the value count of a live attribute.
    usize::try_from(unsafe { ffi::X509_ATTRIBUTE_count(attribute) }).unwrap_or(0)
}

/// Whether the attribute's first value is an OBJECT IDENTIFIER equal to
/// `wanted`.
fn first_value_is_object(attribute: *mut ffi::X509_ATTRIBUTE, wanted: &Asn1ObjectRef) -> bool {
    // SAFETY: `attribute` is live; X509_ATTRIBUTE_get0_type returns a value
    // it owns, or null. The union member is read only when the type says
    // OBJECT, and OBJ_cmp only reads both objects.
    unsafe {
        let value = ffi::X509_ATTRIBUTE_get0_type(attribute, 0);
        !value.is_null()
            && (*value).type_ == ffi::V_ASN1_OBJECT
            && ffi::OBJ_cmp((*value).value.object, wanted.as_ptr()) == 0
    }
}

/// A memory BIO over some bytes behind a digest BIO, freed once when
/// dropped, fully read (so digested) when built.
struct DigestBio<'a> {
    chain: *mut ffi::BIO,
    _source: core::marker::PhantomData<&'a [u8]>,
}

impl<'a> DigestBio<'a> {
    fn over(data: &'a [u8], md: *const ffi::EVP_MD) -> Option<DigestBio<'a>> {
        let length = c_int::try_from(data.len()).ok()?;
        // SAFETY: a read-only memory BIO over `data`, which outlives it (the
        // lifetime ties it to the borrow), and a digest BIO; either is freed
        // here if the other could not be made, or the pair is owned by the
        // returned value.
        let chain = unsafe {
            let source = ffi::BIO_new_mem_buf(data.as_ptr().cast(), length);
            let digest = ffi::BIO_new(sys::BIO_f_md());
            if source.is_null() || digest.is_null() {
                if !source.is_null() {
                    ffi::BIO_free_all(source);
                }
                if !digest.is_null() {
                    ffi::BIO_free_all(digest);
                }
                drain_errors();
                return None;
            }
            ffi::BIO_ctrl(digest, sys::BIO_C_SET_MD, 0, md.cast_mut().cast());
            sys::BIO_push(digest, source)
        };
        let bio = DigestBio {
            chain,
            _source: core::marker::PhantomData,
        };
        let mut buffer = [0u8; 4096];
        loop {
            // SAFETY: reads at most the buffer's length into it.
            let read = unsafe { ffi::BIO_read(bio.chain, buffer.as_mut_ptr().cast(), 4096) };
            if read <= 0 {
                break;
            }
        }
        Some(bio)
    }

    fn as_ptr(&self) -> *mut ffi::BIO {
        self.chain
    }
}

impl Drop for DigestBio<'_> {
    fn drop(&mut self) {
        // SAFETY: the chain built in `over`, owned by this value alone and
        // freed once, here.
        unsafe { ffi::BIO_free_all(self.chain) };
    }
}
