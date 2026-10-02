//! One X.509 certificate, parsed by OpenSSL.

use crate::{d2i_whole, drain_errors, init, keys};
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::c_int;
use openssl::asn1::{Asn1Object, Asn1ObjectRef, Asn1Time};
use openssl::x509::{X509Ref, X509VerifyResult, X509};
use openssl_sys as ffi;
use std::ptr;

/// An owned certificate as OpenSSL parsed it.
///
/// Cloning takes another reference to the same parsed certificate.
#[derive(Clone)]
pub struct Certificate(X509);

impl core::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Certificate").finish_non_exhaustive()
    }
}

impl Certificate {
    /// Parses exactly one certificate (`d2i_X509`); bytes left over after
    /// it are refused.
    #[must_use]
    pub fn from_der(der: &[u8]) -> Option<Certificate> {
        init();
        let (raw, whole) = d2i_whole(der, |cursor, len| {
            // SAFETY: `cursor` points at `len` readable bytes of `der`;
            // d2i_X509 reads at most `len` of them, advances the cursor
            // within them and returns a new X509 the caller owns, or null.
            unsafe { ffi::d2i_X509(ptr::null_mut(), cursor, len) }
        })?;
        // SAFETY: `raw` is a freshly allocated X509 that nothing else owns;
        // `X509` takes that ownership and frees it once.
        let certificate = Certificate(unsafe { X509::from_ptr(raw) });
        whole.then_some(certificate)
    }

    /// Reads every certificate in PEM text, in order, with OpenSSL's PEM
    /// reader: `PEM_read_bio_X509` until the input ends, the loop
    /// rust-openssl's `X509::stack_from_pem` runs, but with a password
    /// callback that refuses. OpenSSL's default callback prompts on the
    /// terminal, or reads stdin, for an encrypted block (`Proc-Type:
    /// 4,ENCRYPTED`), which would block the caller and could open the
    /// block with a typed passphrase; this one makes such a block a
    /// refusal. Text outside the blocks, and blocks of other types, are
    /// skipped as OpenSSL skips them. An empty list when the text holds no
    /// certificate block; `None` when OpenSSL refuses a block.
    #[must_use]
    pub fn all_from_pem(pem: &[u8]) -> Option<Vec<Certificate>> {
        init();
        let length = c_int::try_from(pem.len()).ok()?;
        // SAFETY: a read-only memory BIO over `pem`, which outlives it: it
        // is freed below, before this function returns.
        let bio = unsafe { ffi::BIO_new_mem_buf(pem.as_ptr().cast(), length) };
        if bio.is_null() {
            drain_errors();
            return None;
        }
        let mut certificates = Vec::new();
        let read = loop {
            // SAFETY: `bio` is the live BIO made above; the callback never
            // writes to `buf`; the result is a new X509 the caller owns, or
            // null.
            let raw = unsafe {
                ffi::PEM_read_bio_X509(bio, ptr::null_mut(), Some(no_password), ptr::null_mut())
            };
            if raw.is_null() {
                // The input ended when the last error is "no start line".
                let ended = openssl::error::ErrorStack::get()
                    .errors()
                    .last()
                    .is_some_and(|error| {
                        error.library_code() == ffi::ERR_LIB_PEM
                            && error.reason_code() == ffi::PEM_R_NO_START_LINE
                    });
                break ended.then_some(certificates);
            }
            // SAFETY: `raw` is a freshly allocated X509 that nothing else
            // owns; `X509` takes that ownership and frees it once.
            certificates.push(Certificate(unsafe { X509::from_ptr(raw) }));
        };
        // SAFETY: `bio` was made above and nothing else holds it.
        unsafe { ffi::BIO_free_all(bio) };
        drain_errors();
        read
    }

    pub(crate) fn from_x509(x509: X509) -> Certificate {
        Certificate(x509)
    }

    pub(crate) fn x509(&self) -> &X509Ref {
        &self.0
    }

    /// The certificate's DER as OpenSSL encodes it (`i2d_X509`).
    #[must_use]
    pub fn to_der(&self) -> Vec<u8> {
        let der = self.0.to_der().unwrap_or_default();
        drain_errors();
        der
    }

    /// Whether two certificates are the same one (`X509_cmp`, which
    /// compares the certificates' digests and encodings).
    #[must_use]
    pub fn same_as(&self, other: &Certificate) -> bool {
        same_x509(&self.0, &other.0)
    }

    /// Whether the certificate is one a strict X.509 reader decodes: version
    /// 1 to 3, a `signatureValue` of whole octets (every signature
    /// algorithm produces whole octets), no extension carried twice, and a
    /// `basicConstraints` and a `keyUsage` that decode when present.
    /// OpenSSL parses all of these without complaint and judges them only
    /// later, if at all.
    ///
    /// The key is not judged here: see [`Certificate::has_usable_key`].
    #[must_use]
    pub fn is_readable(&self) -> bool {
        if !(0..=2).contains(&self.0.version()) || !signature_is_octet_aligned(&self.0) {
            return false;
        }
        let Some(mut oids) = extension_oids(&self.0) else {
            return false;
        };
        oids.sort_unstable();
        if oids.windows(2).any(|pair| pair.first() == pair.get(1)) {
            return false;
        }
        decodes_if_present(&self.0, ffi::NID_basic_constraints)
            && decodes_if_present(&self.0, ffi::NID_key_usage)
    }

    /// Whether OpenSSL can build a public key from the certificate's
    /// `SubjectPublicKeyInfo`: a key it does not implement (an EC key on a
    /// curve it does not know) or one that does not decode is not usable.
    #[must_use]
    pub fn has_usable_key(&self) -> bool {
        init();
        let usable = self.0.public_key().is_ok();
        drain_errors();
        usable
    }

    /// Whether the certificate carries an extension with this OID.
    /// `OBJ_txt2obj` reads the text, so a name OpenSSL knows
    /// (`basicConstraints`) matches as its dotted OID would; the core
    /// passes dotted constants only.
    #[must_use]
    pub fn has_extension(&self, dotted_oid: &str) -> bool {
        init();
        if dotted_oid.contains('\0') {
            return false;
        }
        let Ok(object) = Asn1Object::from_str(dotted_oid) else {
            drain_errors();
            return false;
        };
        extension_position(&self.0, &object).is_some()
    }

    /// Whether `issuer` issued this certificate: `X509_check_issued`
    /// (names by OpenSSL's canonical comparison, the authority key
    /// identifier, the issuer's `keyUsage`) and then the signature under
    /// the issuer's key (`X509_verify`, which also requires the two
    /// signature `AlgorithmIdentifier`s to agree). The issuer's key is
    /// built only once the names match.
    #[must_use]
    pub fn issued_by(&self, issuer: &Certificate) -> bool {
        init();
        if issuer.0.issued(&self.0) != X509VerifyResult::OK {
            drain_errors();
            return false;
        }
        let Ok(key) = issuer.0.public_key() else {
            drain_errors();
            return false;
        };
        keys::record(&key);
        let verified = self.0.verify(&key).unwrap_or(false);
        drain_errors();
        verified
    }

    /// Whether this certificate names `issuer`'s subject as its issuer
    /// (`X509_NAME_cmp`, as OpenSSL's issuer lookup compares them) and
    /// `issuer`'s key verifies its signature (`X509_verify`): the link a
    /// path follows, whether or not the path is valid. Unlike
    /// [`Certificate::issued_by`], the issuer's `keyUsage` and the key
    /// identifiers are not judged here; OpenSSL judges them on the path it
    /// builds and reports what fails. The issuer's key is built only once
    /// the names match.
    #[must_use]
    pub(crate) fn signed_by(&self, issuer: &Certificate) -> bool {
        init();
        let named = issuer
            .0
            .subject_name()
            .try_cmp(self.0.issuer_name())
            .is_ok_and(|order| order == core::cmp::Ordering::Equal);
        if !named {
            drain_errors();
            return false;
        }
        let Ok(key) = issuer.0.public_key() else {
            drain_errors();
            return false;
        };
        keys::record(&key);
        let verified = self.0.verify(&key).unwrap_or(false);
        drain_errors();
        verified
    }

    /// Whether `notBefore` is at or before `secs` (Unix seconds).
    #[must_use]
    pub fn not_before_at_most(&self, secs: i64) -> bool {
        let at_most = libc::time_t::try_from(secs)
            .ok()
            .and_then(|secs| Asn1Time::from_unix(secs).ok())
            .is_some_and(|at| self.0.not_before() <= at);
        drain_errors();
        at_most
    }

    /// Whether the certificate marks critical an extension OpenSSL does not
    /// process: the flag `X509_verify_cert` reports as
    /// `X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION`.
    #[must_use]
    pub fn has_unhandled_critical_extension(&self) -> bool {
        init();
        // SAFETY: X509_get_extension_flags reads the live certificate,
        // caching its decoded extensions inside it under OpenSSL's own lock.
        let flags = unsafe { ffi::X509_get_extension_flags(self.0.as_ptr()) };
        drain_errors();
        flags & ffi::EXFLAG_CRITICAL != 0
    }

    /// Whether the certificate may issue certificates, as `X509_verify_cert`
    /// judges a certificate above the target (`X509_check_ca` non-zero).
    #[must_use]
    pub fn may_issue_certificates(&self) -> bool {
        init();
        // SAFETY: X509_check_ca reads the live certificate, caching its
        // decoded extensions inside it under OpenSSL's own lock.
        let ca = unsafe { crate::sys::X509_check_ca(self.0.as_ptr()) };
        drain_errors();
        ca != 0
    }

    /// Whether `notAfter` is at or after `secs` (Unix seconds).
    #[must_use]
    pub fn not_after_at_least(&self, secs: i64) -> bool {
        let at_least = libc::time_t::try_from(secs)
            .ok()
            .and_then(|secs| Asn1Time::from_unix(secs).ok())
            .is_some_and(|at| self.0.not_after() >= at);
        drain_errors();
        at_least
    }
}

/// Whether the certificate's `signatureValue` BIT STRING has no unused
/// bits.
fn signature_is_octet_aligned(x509: &X509Ref) -> bool {
    let mut signature: *const ffi::ASN1_BIT_STRING = ptr::null();
    let mut length: libc::size_t = 0;
    let mut unused_bits: c_int = -1;
    // SAFETY: X509_get0_signature stores a pointer owned by the live
    // certificate (the algorithm out-pointer may be null);
    // ASN1_BIT_STRING_get_length only reads that string and writes the two
    // out-values.
    let read = unsafe {
        ffi::X509_get0_signature(&raw mut signature, ptr::null_mut(), x509.as_ptr());
        !signature.is_null()
            && crate::sys::ASN1_BIT_STRING_get_length(
                signature,
                &raw mut length,
                &raw mut unused_bits,
            ) == 1
    };
    drain_errors();
    read && unused_bits == 0
}

pub(crate) fn same_x509(a: &X509Ref, b: &X509Ref) -> bool {
    // SAFETY: both pointers are live certificates borrowed for the call;
    // X509_cmp only reads them.
    unsafe { ffi::X509_cmp(a.as_ptr(), b.as_ptr()) == 0 }
}

/// The DER content octets of every extension's OID, in order, or `None`
/// when an extension has no readable OID.
fn extension_oids(x509: &X509Ref) -> Option<Vec<Vec<u8>>> {
    // SAFETY: reads the extension count of a live certificate.
    let count = unsafe { ffi::X509_get_ext_count(x509.as_ptr()) };
    (0..count)
        .map(|index| extension_object(x509, index).map(object_octets))
        .collect()
}

/// The content octets of an OID's encoding, copied.
fn object_octets(object: &Asn1ObjectRef) -> Vec<u8> {
    // SAFETY: both calls only read the live object: OBJ_length is the
    // length of the encoding OBJ_get0_data points at, both owned by it.
    unsafe {
        let length = ffi::OBJ_length(object.as_ptr());
        let data = ffi::OBJ_get0_data(object.as_ptr());
        if data.is_null() || length == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(data, length).to_vec()
        }
    }
}

/// The OID of extension `index`, borrowed from the certificate.
fn extension_object(x509: &X509Ref, index: c_int) -> Option<&Asn1ObjectRef> {
    // SAFETY: `index` is below the certificate's extension count (the only
    // caller iterates that range); X509_get_ext returns a pointer owned by
    // the certificate, and X509_EXTENSION_get_object one owned by the
    // extension, both valid while `x509` is borrowed.
    unsafe {
        let extension = ffi::X509_get_ext(x509.as_ptr(), index);
        if extension.is_null() {
            return None;
        }
        let object = ffi::X509_EXTENSION_get_object(extension);
        if object.is_null() {
            None
        } else {
            Some(Asn1ObjectRef::from_ptr(object))
        }
    }
}

/// The index of the first extension with this OID.
fn extension_position(x509: &X509Ref, object: &Asn1ObjectRef) -> Option<c_int> {
    // SAFETY: both pointers are live for the call; the lookup only reads.
    let position = unsafe { ffi::X509_get_ext_by_OBJ(x509.as_ptr(), object.as_ptr(), -1) };
    (position >= 0).then_some(position)
}

/// Whether the extension `nid`, if the certificate carries it, decodes as
/// its type. A duplicate reads as not decoding.
fn decodes_if_present(x509: &X509Ref, nid: c_int) -> bool {
    let mut critical: c_int = 0;
    // SAFETY: X509_get_ext_d2i decodes the extension into a new object the
    // caller owns (freed below with that type's own free function), or
    // returns null and sets `critical` to -1 when the extension is absent
    // and to -2 when it occurs more than once.
    let decoded =
        unsafe { ffi::X509_get_ext_d2i(x509.as_ptr(), nid, &raw mut critical, ptr::null_mut()) };
    if decoded.is_null() {
        drain_errors();
        return critical == -1;
    }
    free_extension_value(nid, decoded);
    true
}

fn free_extension_value(nid: c_int, value: *mut libc::c_void) {
    // SAFETY: `value` is the object X509_get_ext_d2i allocated for `nid`,
    // owned by the caller and freed exactly once, with that NID's type.
    unsafe {
        if nid == ffi::NID_basic_constraints {
            crate::sys::BASIC_CONSTRAINTS_free(value);
        } else {
            ffi::ASN1_BIT_STRING_free(value.cast());
        }
    }
}

/// The password callback for [`Certificate::all_from_pem`]: no password,
/// so OpenSSL refuses an encrypted block instead of prompting for one.
unsafe extern "C" fn no_password(
    _buf: *mut libc::c_char,
    _size: c_int,
    _rwflag: c_int,
    _user_data: *mut libc::c_void,
) -> c_int {
    -1
}
