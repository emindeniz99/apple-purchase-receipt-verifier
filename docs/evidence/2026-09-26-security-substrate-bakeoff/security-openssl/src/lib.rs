//! Spike only. The one crate in the substrate experiment that contains
//! `unsafe`. It wraps rust-openssl and openssl-sys, and compiles against
//! OpenSSL, LibreSSL or AWS-LC (see Cargo.toml).
//!
//! Rules this file keeps:
//! - no raw pointer leaves this crate: callers get owned values
//!   (`Certificate`, `SignedData`) or plain Rust data;
//! - no trust store is ever built from anything but the caller's anchors:
//!   `X509_STORE_set_default_paths` and lookup methods are never called;
//! - OpenSSL is initialised with `OPENSSL_INIT_NO_LOAD_CONFIG` before any
//!   other call, so `OPENSSL_CONF` and the build's `openssl.cnf` are never
//!   read;
//! - every failure drains the thread's OpenSSL error queue.
//!
//! Every `unsafe` block carries a SAFETY comment.

#![deny(unsafe_op_in_unsafe_fn)]

use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_int, c_long};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
use openssl::x509::{X509StoreContext, X509};
use openssl_sys as ffi;
use std::ffi::CString;
use std::ptr;
use std::sync::Once;

mod sys {
    //! Declarations openssl-sys does not carry, one signature for every
    //! library. OpenSSL and LibreSSL export these names; AWS-LC's symbols
    //! are prefixed by aws-lc-sys, so there they come from its bindings
    //! (which carry the link names) through thin wrappers.
    #![allow(non_camel_case_types, non_snake_case, clippy::missing_safety_doc)]
    use super::ffi;
    use libc::c_int;
    #[cfg(not(aprv_awslc))]
    use libc::c_void;

    #[cfg(all(aprv_openssl, not(feature = "negative-control")))]
    pub const OPENSSL_INIT_NO_LOAD_CONFIG: u64 = 0x0000_0080;
    /// `BIO_set_md` is a macro over `BIO_ctrl` with this command.
    #[cfg(not(any(feature = "a1", aprv_awslc)))]
    pub const BIO_C_SET_MD: c_int = 111;
    #[cfg(any(feature = "a1", aprv_awslc))]
    pub const PKCS7_NOCHAIN: c_int = 0x8;
    #[cfg(any(feature = "a1", aprv_awslc))]
    pub const PKCS7_NOINTERN: c_int = 0x10;
    #[cfg(any(feature = "a1", aprv_awslc))]
    pub const PKCS7_NOVERIFY: c_int = 0x20;

    pub type VerifyCb = Option<unsafe extern "C" fn(c_int, *mut ffi::X509_STORE_CTX) -> c_int>;

    #[cfg(not(aprv_awslc))]
    extern "C" {
        #[cfg(aprv_openssl)]
        pub fn OPENSSL_init_crypto(opts: u64, settings: *const c_void) -> c_int;
        #[cfg(not(feature = "a1"))]
        pub fn PKCS7_signatureVerify(
            bio: *mut ffi::BIO,
            p7: *mut ffi::PKCS7,
            si: *mut ffi::PKCS7_SIGNER_INFO,
            x509: *mut ffi::X509,
        ) -> c_int;
        #[cfg(feature = "a1")]
        pub fn PKCS7_verify(
            p7: *mut ffi::PKCS7,
            certs: *mut ffi::stack_st_X509,
            store: *mut ffi::X509_STORE,
            indata: *mut ffi::BIO,
            out: *mut ffi::BIO,
            flags: c_int,
        ) -> c_int;
        pub fn X509_STORE_CTX_set_verify_cb(ctx: *mut ffi::X509_STORE_CTX, cb: VerifyCb);
        pub fn BASIC_CONSTRAINTS_free(bc: *mut c_void);
        #[cfg(not(feature = "a1"))]
        pub fn BIO_f_md() -> *const ffi::BIO_METHOD;
        pub fn X509_get_version(x: *const ffi::X509) -> libc::c_long;
        #[cfg(not(feature = "a1"))]
        pub fn BIO_push(b: *mut ffi::BIO, append: *mut ffi::BIO) -> *mut ffi::BIO;
        pub fn X509_get_X509_PUBKEY(x: *const ffi::X509) -> *mut c_void;
        pub fn X509_PUBKEY_get0_param(
            ppkalg: *mut *mut ffi::ASN1_OBJECT,
            pk: *mut *const u8,
            ppklen: *mut c_int,
            pa: *mut *mut ffi::X509_ALGOR,
            public: *mut c_void,
        ) -> c_int;
    }

    #[cfg(aprv_awslc)]
    pub use aws::*;
    #[cfg(aprv_awslc)]
    mod aws {
        use super::{ffi, VerifyCb};
        use libc::{c_int, c_void};
        pub unsafe fn PKCS7_verify(
            p7: *mut ffi::PKCS7,
            certs: *mut ffi::stack_st_X509,
            store: *mut ffi::X509_STORE,
            indata: *mut ffi::BIO,
            out: *mut ffi::BIO,
            flags: c_int,
        ) -> c_int {
            // SAFETY: forwarded unchanged.
            unsafe { ffi::PKCS7_verify(p7, certs, store, indata, out, flags) }
        }
        pub unsafe fn X509_STORE_CTX_set_verify_cb(ctx: *mut ffi::X509_STORE_CTX, cb: VerifyCb) {
            // SAFETY: forwarded unchanged.
            unsafe { ffi::X509_STORE_CTX_set_verify_cb(ctx, cb) }
        }
        pub unsafe fn BASIC_CONSTRAINTS_free(bc: *mut c_void) {
            // SAFETY: forwarded; the pointer came from X509_get_ext_d2i for
            // NID_basic_constraints.
            unsafe { ffi::BASIC_CONSTRAINTS_free(bc.cast()) }
        }
        pub unsafe fn X509_get_version(x: *const ffi::X509) -> libc::c_long {
            // SAFETY: forwarded unchanged.
            unsafe { ffi::X509_get_version(x) }
        }
        pub unsafe fn X509_get_X509_PUBKEY(x: *const ffi::X509) -> *mut c_void {
            // SAFETY: forwarded unchanged.
            unsafe { ffi::X509_get_X509_PUBKEY(x).cast() }
        }
        pub unsafe fn X509_PUBKEY_get0_param(
            ppkalg: *mut *mut ffi::ASN1_OBJECT,
            pk: *mut *const u8,
            ppklen: *mut c_int,
            pa: *mut *mut ffi::X509_ALGOR,
            public: *mut c_void,
        ) -> c_int {
            // SAFETY: forwarded unchanged.
            unsafe { ffi::X509_PUBKEY_get0_param(ppkalg, pk, ppklen, pa, public.cast()) }
        }
    }
}

/// Stack access under the names and types each library's bindings use.
///
/// # Safety
/// `stack` is a live OpenSSL stack.
unsafe fn sk_num<T>(stack: *const T) -> c_int {
    // SAFETY (all three arms): the caller's contract.
    #[cfg(aprv_openssl)]
    let n = unsafe { ffi::OPENSSL_sk_num(stack.cast()) };
    #[cfg(aprv_libressl)]
    let n = unsafe { ffi::sk_num(stack.cast()) };
    #[cfg(aprv_awslc)]
    let n = c_int::try_from(unsafe { ffi::OPENSSL_sk_num(stack.cast()) }).unwrap_or(c_int::MAX);
    n
}

/// # Safety
/// As [`sk_num`]; an out-of-range index returns null.
unsafe fn sk_value<T, U>(stack: *const T, index: c_int) -> *mut U {
    // SAFETY (all three arms): the caller's contract.
    #[cfg(aprv_openssl)]
    let v = unsafe { ffi::OPENSSL_sk_value(stack.cast(), index) };
    #[cfg(aprv_libressl)]
    let v = unsafe { ffi::sk_value(stack.cast(), index) };
    #[cfg(aprv_awslc)]
    let v = match usize::try_from(index) {
        Ok(i) => unsafe { ffi::OPENSSL_sk_value(stack.cast(), i) },
        Err(_) => ptr::null_mut(),
    };
    v.cast()
}

static INIT: Once = Once::new();

thread_local! {
    /// The anchors of the verification running on this thread, for the
    /// verify callback (a plain C function pointer with no user data).
    static ANCHORS: std::cell::RefCell<Vec<X509>> = const { std::cell::RefCell::new(Vec::new()) };
    /// The instant that verification judges validity at (Unix seconds).
    static CHECK_TIME: std::cell::Cell<i64> = const { std::cell::Cell::new(0) };
}

/// Library initialisation. Idempotent; every entry point calls it first.
pub fn init() {
    INIT.call_once(|| {
        #[cfg(all(aprv_openssl, not(feature = "negative-control")))]
        // SAFETY: documented init call; a null settings pointer is allowed.
        // Passing NO_LOAD_CONFIG first claims the config RUN_ONCE, so later
        // implicit initialisations cannot load openssl.cnf or OPENSSL_CONF.
        unsafe {
            sys::OPENSSL_init_crypto(sys::OPENSSL_INIT_NO_LOAD_CONFIG, ptr::null());
        }
        #[cfg(all(aprv_openssl, feature = "negative-control"))]
        // SAFETY: as above, with LOAD_CONFIG (0x40) instead.
        unsafe {
            sys::OPENSSL_init_crypto(0x40, ptr::null());
        }
        ffi::init();
    });
}

fn drain_errors() {
    let _ = openssl::error::ErrorStack::get();
}

/// The linked library, as it reports itself.
#[must_use]
pub fn library_version() -> &'static str {
    init();
    openssl::version::version()
}

/// An owned, parsed X.509 certificate.
#[derive(Clone)]
pub struct Certificate(X509);

/// How a certificate's public key decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// The library cannot build a key from the SubjectPublicKeyInfo.
    Undecodable,
    /// RSA
    Rsa,
    /// EC on P-256
    EcP256,
    /// EC on another named curve the library knows
    EcOther,
    /// Anything else the library decodes (Ed25519, DSA, ...)
    Other,
}

impl Certificate {
    /// Parses exactly one DER certificate; trailing bytes are refused.
    #[must_use]
    pub fn from_der(der: &[u8]) -> Option<Certificate> {
        init();
        let len = c_long::try_from(der.len()).ok()?;
        let start = der.as_ptr();
        let mut cursor = start;
        // SAFETY: `cursor` points at `len` readable bytes owned by `der`;
        // d2i_X509 reads at most `len` bytes and advances `cursor` within
        // them. The returned pointer is owned by us (or null).
        let raw = unsafe { ffi::d2i_X509(ptr::null_mut(), &mut cursor, len) };
        if raw.is_null() {
            drain_errors();
            return None;
        }
        // SAFETY: `raw` is a freshly allocated X509 that nothing else owns.
        let cert = Certificate(unsafe { X509::from_ptr(raw) });
        let consumed = cursor as usize - start as usize;
        if consumed != der.len() {
            return None;
        }
        Some(cert)
    }

    /// The DER the certificate was parsed from.
    #[must_use]
    pub fn to_der(&self) -> Vec<u8> {
        self.0.to_der().unwrap_or_default()
    }

    /// Whether the certificate carries an extension with this dotted OID.
    #[must_use]
    pub fn has_extension(&self, dotted_oid: &str) -> bool {
        init();
        let Ok(text) = CString::new(dotted_oid) else {
            return false;
        };
        // SAFETY: `text` is a NUL-terminated string; `no_name = 1` makes
        // OBJ_txt2obj read it as a numeric OID only. The object is freed
        // below and never escapes.
        let object = unsafe { ffi::OBJ_txt2obj(text.as_ptr(), 1) };
        if object.is_null() {
            drain_errors();
            return false;
        }
        // SAFETY: both pointers are valid for the duration of the call.
        let position = unsafe { ffi::X509_get_ext_by_OBJ(self.0.as_ptr(), object, -1) };
        // SAFETY: `object` came from OBJ_txt2obj above and is freed once.
        unsafe { ffi::ASN1_OBJECT_free(object) };
        position >= 0
    }

    /// The kind of public key, or `Undecodable`.
    #[must_use]
    pub fn key_kind(&self) -> KeyKind {
        let Ok(key) = self.0.public_key() else {
            drain_errors();
            return KeyKind::Undecodable;
        };
        if key.rsa().is_ok() {
            return KeyKind::Rsa;
        }
        drain_errors();
        if let Ok(ec) = key.ec_key() {
            return if ec.group().curve_name() == Some(Nid::X9_62_PRIME256V1) {
                KeyKind::EcP256
            } else {
                KeyKind::EcOther
            };
        }
        drain_errors();
        KeyKind::Other
    }

    /// Whether the certificate is one Bouncy Castle would build eagerly
    /// (`X509CertificateHolder` plus `JcaX509CertificateConverter`): X.509
    /// version 1 to 3, no extension carried twice, a basicConstraints and a
    /// keyUsage that decode when present, and, for an EC key, a curve the
    /// library implements. An RSA or other key is not decoded here: Java
    /// decodes those lazily (see `key_kind`).
    ///
    /// OpenSSL's own `EXFLAG_INVALID` is broader (it also covers CRL
    /// distribution points, name constraints and more), so it is not used.
    #[must_use]
    pub fn is_readable(&self) -> bool {
        // SAFETY: reads a field of the live certificate.
        let version = unsafe { sys::X509_get_version(self.0.as_ptr()) };
        if !(0..=2).contains(&version) {
            return false;
        }
        let raw = self.0.as_ptr();
        // SAFETY: read-only walks of the live certificate's extension list;
        // every object pointer is borrowed from it.
        let count = unsafe { ffi::X509_get_ext_count(raw) };
        for i in 0..count {
            for j in 0..i {
                // SAFETY: both indices are below the extension count.
                let same = unsafe {
                    let a = ffi::X509_EXTENSION_get_object(ffi::X509_get_ext(raw, i));
                    let b = ffi::X509_EXTENSION_get_object(ffi::X509_get_ext(raw, j));
                    !a.is_null() && !b.is_null() && ffi::OBJ_cmp(a, b) == 0
                };
                if same {
                    return false;
                }
            }
        }
        for nid in [ffi::NID_basic_constraints, ffi::NID_key_usage] {
            let mut critical: c_int = 0;
            // SAFETY: decodes one extension into a new object that is freed
            // with its own type's free function below.
            let decoded = unsafe { ffi::X509_get_ext_d2i(raw, nid, &mut critical, ptr::null_mut()) };
            if decoded.is_null() {
                if critical >= 0 {
                    drain_errors();
                    return false;
                }
                continue;
            }
            // SAFETY: `decoded` is the object X509_get_ext_d2i allocated for
            // this NID, freed once.
            unsafe {
                if nid == ffi::NID_basic_constraints {
                    sys::BASIC_CONSTRAINTS_free(decoded);
                } else {
                    ffi::ASN1_BIT_STRING_free(decoded.cast());
                }
            }
        }
        let (algorithm, curve) = self.key_algorithm();
        if algorithm == ffi::NID_X9_62_id_ecPublicKey {
            return curve_is_implemented(curve);
        }
        true
    }

    /// The SubjectPublicKeyInfo algorithm NID and, when its parameter is an
    /// OID (an EC named curve), that OID's NID.
    fn key_algorithm(&self) -> (c_int, c_int) {
        // SAFETY: X509_get_X509_PUBKEY borrows from the live certificate;
        // X509_PUBKEY_get0_param and X509_ALGOR_get0 store borrowed pointers.
        unsafe {
            let spki = sys::X509_get_X509_PUBKEY(self.0.as_ptr());
            if spki.is_null() {
                return (ffi::NID_undef, ffi::NID_undef);
            }
            let mut object: *mut ffi::ASN1_OBJECT = ptr::null_mut();
            let mut algor: *mut ffi::X509_ALGOR = ptr::null_mut();
            if sys::X509_PUBKEY_get0_param(&mut object, ptr::null_mut(), ptr::null_mut(), &mut algor, spki) != 1
                || object.is_null()
            {
                drain_errors();
                return (ffi::NID_undef, ffi::NID_undef);
            }
            let mut curve = ffi::NID_undef;
            if !algor.is_null() {
                let mut ptype: c_int = 0;
                let mut pval: *const libc::c_void = ptr::null();
                ffi::X509_ALGOR_get0(ptr::null_mut(), &mut ptype, &mut pval, algor);
                if ptype == ffi::V_ASN1_OBJECT && !pval.is_null() {
                    curve = ffi::OBJ_obj2nid(pval.cast());
                }
            }
            (ffi::OBJ_obj2nid(object), curve)
        }
    }

    /// Whether `notAfter` is at or after `secs` (Unix seconds).
    #[must_use]
    pub fn not_after_at_least(&self, secs: i64) -> bool {
        match openssl::asn1::Asn1Time::from_unix(secs as libc::time_t) {
            Ok(at) => self.0.not_after() >= at,
            Err(_) => {
                drain_errors();
                false
            }
        }
    }

    /// Whether `issuer` issued `self`: `self`'s issuer name equals
    /// `issuer`'s subject name (`X509_NAME_cmp`, which compares the
    /// canonical form, as Java's `X500Principal.equals` does) and `self`'s
    /// signature verifies under `issuer`'s key.
    #[must_use]
    pub fn issued_by(&self, issuer: &Certificate) -> Issued {
        // SAFETY: both names are borrowed from live certificates.
        let names_match =
            unsafe { ffi::X509_NAME_cmp(ffi::X509_get_issuer_name(self.0.as_ptr()), ffi::X509_get_subject_name(issuer.0.as_ptr())) } == 0;
        if !names_match {
            return Issued::No;
        }
        let Ok(key) = issuer.0.public_key() else {
            drain_errors();
            return Issued::IssuerKeyUndecodable;
        };
        let verdict = self.0.verify(&key).unwrap_or(false);
        drain_errors();
        if verdict { Issued::Yes } else { Issued::No }
    }

    /// Whether `self` and `other` are the same DER.
    #[must_use]
    pub fn same_as(&self, other: &Certificate) -> bool {
        self.to_der() == other.to_der()
    }
}

/// Whether the library implements this named curve. Bouncy Castle refuses
/// an unknown curve when it builds the certificate; it checks the point
/// itself only when the key is used.
fn curve_is_implemented(nid: c_int) -> bool {
    if nid == ffi::NID_undef {
        return false;
    }
    let known = openssl::ec::EcGroup::from_curve_name(Nid::from_raw(nid)).is_ok();
    drain_errors();
    known
}

/// Answer of [`Certificate::issued_by`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Issued {
    /// Names match and the signature verifies.
    Yes,
    /// Names differ or the signature does not verify.
    No,
    /// Names match but the issuer's key does not decode.
    IssuerKeyUndecodable,
}

/// Why a PKCS#7 blob was refused before any policy ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmsError {
    /// d2i_PKCS7 refused the bytes (this includes any embedded certificate
    /// the library cannot parse).
    Malformed,
    /// Bytes follow the outer value.
    Trailing,
    /// A PKCS#7 other than signedData.
    NotSignedData,
    /// No attached content, or content that is not an OCTET STRING.
    NoContent,
    /// No SignerInfo.
    NoSignerInfo,
}

/// Facts about the first SignerInfo's signed attributes, for a policy that
/// wants Bouncy Castle's RFC 5652 checks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignedAttributes {
    /// Whether the `[0]` field is present at all.
    pub present: bool,
    /// Number of attributes.
    pub count: usize,
    /// Number of contentType attributes, and values in the first one.
    pub content_type: (usize, usize),
    /// Whether the first contentType value equals eContentType.
    pub content_type_matches: bool,
    /// Number of messageDigest attributes, and values in the first one.
    pub message_digest: (usize, usize),
}

/// A parsed PKCS#7 signedData. Owns its `PKCS7` (rust-openssl's `Pkcs7`
/// wrapper is compiled out for AWS-LC, so this crate owns the pointer).
pub struct SignedData {
    p7: *mut ffi::PKCS7,
}

impl Drop for SignedData {
    fn drop(&mut self) {
        // SAFETY: `p7` came from d2i_PKCS7, is owned by this value and is
        // freed exactly once.
        unsafe { ffi::PKCS7_free(self.p7) };
    }
}

// SAFETY: a PKCS7 is only read after parsing, except by the verify
// functions, which this crate calls with `&mut self` only. It holds no
// thread-affine state.
unsafe impl Send for SignedData {}

const NID_PKCS7_SIGNED: c_int = 22;
const NID_PKCS7_ENCRYPTED: c_int = 26;

impl SignedData {
    /// Parses a DER/BER PKCS#7 blob and checks its outer shape.
    ///
    /// # Errors
    /// [`CmsError`] for anything that is not one signedData with attached
    /// OCTET STRING content and at least one SignerInfo.
    pub fn parse(der: &[u8]) -> Result<SignedData, CmsError> {
        init();
        let len = c_long::try_from(der.len()).map_err(|_| CmsError::Malformed)?;
        let start = der.as_ptr();
        let mut cursor = start;
        // SAFETY: as in Certificate::from_der.
        let raw = unsafe { ffi::d2i_PKCS7(ptr::null_mut(), &mut cursor, len) };
        if raw.is_null() {
            drain_errors();
            return Err(CmsError::Malformed);
        }
        let parsed = SignedData { p7: raw };
        if cursor as usize - start as usize != der.len() {
            return Err(CmsError::Trailing);
        }
        if parsed.signed_ptr().is_null() {
            return Err(CmsError::NotSignedData);
        }
        parsed.content_octets().ok_or(CmsError::NoContent)?;
        if parsed.signer_info_count() == 0 {
            return Err(CmsError::NoSignerInfo);
        }
        Ok(parsed)
    }

    fn signed_ptr(&self) -> *mut ffi::PKCS7_SIGNED {
        // SAFETY: `type_` is set by the parser; the `sign` member is read
        // only when the type says signedData.
        unsafe {
            if ffi::OBJ_obj2nid((*self.p7).type_) != NID_PKCS7_SIGNED {
                return ptr::null_mut();
            }
            (*self.p7).d.sign
        }
    }

    fn certificate_stack(&self) -> *mut ffi::stack_st_X509 {
        let signed = self.signed_ptr();
        if signed.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: a field of the live PKCS7_SIGNED.
        unsafe { (*signed).cert }
    }

    fn inner(&self) -> *mut ffi::PKCS7 {
        let signed = self.signed_ptr();
        if signed.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `signed` is the live PKCS7_SIGNED owned by self.p7.
        unsafe { (*signed).contents }
    }

    fn content_octets(&self) -> Option<&[u8]> {
        let inner = self.inner();
        if inner.is_null() {
            return None;
        }
        // SAFETY: `inner` is owned by self.p7 and outlives the returned
        // slice (tied to &self). The union member read is the one the
        // parser filled for this content type: `data` for id-data, `other`
        // for a type OpenSSL does not model. The other PKCS#7 types are
        // refused before any union member is read.
        unsafe {
            let nid = ffi::OBJ_obj2nid((*inner).type_);
            let octets: *mut ffi::ASN1_OCTET_STRING = if nid == ffi::NID_pkcs7_data {
                (*inner).d.data
            } else if (NID_PKCS7_SIGNED..=NID_PKCS7_ENCRYPTED).contains(&nid) {
                return None;
            } else {
                let other = (*inner).d.other;
                if other.is_null() || (*other).type_ != ffi::V_ASN1_OCTET_STRING {
                    return None;
                }
                (*other).value.octet_string
            };
            if octets.is_null() {
                return None;
            }
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

    /// The embedded certificates, in order.
    #[must_use]
    pub fn certificates(&self) -> Vec<Certificate> {
        let stack = self.certificate_stack();
        if stack.is_null() {
            return Vec::new();
        }
        // SAFETY: every entry of the live stack is a live X509; `to_owned`
        // takes a new reference.
        unsafe {
            (0..sk_num(stack))
                .map(|i| sk_value::<_, ffi::X509>(stack, i))
                .filter(|c| !c.is_null())
                .map(|c| Certificate(openssl::x509::X509Ref::from_ptr(c).to_owned()))
                .collect()
        }
    }

    fn signer_infos(&self) -> *mut ffi::stack_st_PKCS7_SIGNER_INFO {
        // SAFETY: self.p7 is a signedData (checked in parse); the returned
        // stack is owned by it.
        unsafe { ffi::PKCS7_get_signer_info(self.p7) }
    }

    /// How many SignerInfos the blob carries.
    #[must_use]
    pub fn signer_info_count(&self) -> usize {
        let infos = self.signer_infos();
        if infos.is_null() {
            return 0;
        }
        // SAFETY: a live stack owned by self.p7.
        usize::try_from(unsafe { sk_num(infos) }).unwrap_or(0)
    }

    fn first_signer_info(&self) -> *mut ffi::PKCS7_SIGNER_INFO {
        let infos = self.signer_infos();
        if infos.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: index 0 of a live stack; null when empty.
        unsafe { sk_value(infos, 0) }
    }

    /// Index into [`SignedData::certificates`] of the certificate the first
    /// SignerInfo names by issuer and serial number, compared the way
    /// OpenSSL compares them (`X509_NAME_cmp`, `ASN1_INTEGER_cmp`).
    #[must_use]
    pub fn signer_index(&self) -> Option<usize> {
        let si = self.first_signer_info();
        if si.is_null() {
            return None;
        }
        let stack = self.certificate_stack();
        if stack.is_null() {
            return None;
        }
        // SAFETY: `si` and its issuer_and_serial are owned by self.p7 and
        // read only; every certificate pointer comes from the live stack.
        unsafe {
            let ias = (*si).issuer_and_serial;
            if ias.is_null() || (*ias).issuer.is_null() || (*ias).serial.is_null() {
                return None;
            }
            for index in 0..sk_num(stack) {
                let raw: *mut ffi::X509 = sk_value(stack, index);
                if raw.is_null() {
                    continue;
                }
                if ffi::X509_NAME_cmp(ffi::X509_get_issuer_name(raw), (*ias).issuer) == 0
                    && ffi::ASN1_INTEGER_cmp(ffi::X509_get_serialNumber(raw), (*ias).serial) == 0
                {
                    return usize::try_from(index).ok();
                }
            }
        }
        None
    }

    /// The first SignerInfo's digest and signature algorithm OIDs.
    #[must_use]
    pub fn signer_algorithms(&self) -> (String, String) {
        let si = self.first_signer_info();
        if si.is_null() {
            return (String::new(), String::new());
        }
        let mut digest: *mut ffi::X509_ALGOR = ptr::null_mut();
        let mut signature: *mut ffi::X509_ALGOR = ptr::null_mut();
        // SAFETY: `si` is live; the out-pointers receive borrowed pointers
        // owned by it.
        unsafe { ffi::PKCS7_SIGNER_INFO_get0_algs(si, ptr::null_mut(), &mut digest, &mut signature) };
        (algor_oid(digest), algor_oid(signature))
    }

    /// Whether the first SignerInfo's digestAlgorithm names a digest the
    /// library implements. PKCS7_signatureVerify does not check this: an
    /// unknown OID maps to NID_undef, which equals the pkey type of every
    /// provider-fetched digest, so it silently uses whatever digest the
    /// SignedData-level digestAlgorithms set put in the BIO chain.
    #[must_use]
    pub fn signer_digest_known(&self) -> bool {
        let si = self.first_signer_info();
        if si.is_null() {
            return false;
        }
        // SAFETY: `si` and its digest_alg are owned by self.p7, read only.
        unsafe {
            let algor = (*si).digest_alg;
            if algor.is_null() {
                return false;
            }
            let mut object: *const ffi::ASN1_OBJECT = ptr::null();
            ffi::X509_ALGOR_get0(&mut object, ptr::null_mut(), ptr::null_mut(), algor);
            let nid = ffi::OBJ_obj2nid(object);
            nid != ffi::NID_undef && !ffi::EVP_get_digestbynid(nid).is_null()
        }
    }

    /// Facts about the first SignerInfo's signed attributes.
    #[must_use]
    pub fn signed_attributes(&self) -> SignedAttributes {
        let si = self.first_signer_info();
        let mut facts = SignedAttributes::default();
        if si.is_null() {
            return facts;
        }
        // SAFETY: every pointer read here is owned by self.p7 and only read.
        unsafe {
            let attrs = (*si).auth_attr;
            if attrs.is_null() {
                return facts;
            }
            facts.present = true;
            let count = sk_num(attrs);
            facts.count = usize::try_from(count).unwrap_or(0);
            let econtent_type = {
                let inner = self.inner();
                if inner.is_null() { ptr::null_mut() } else { (*inner).type_ }
            };
            for index in 0..count {
                let attr: *mut ffi::X509_ATTRIBUTE = sk_value(attrs, index);
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

    /// Verifies the first SignerInfo's signature under `signer`'s key:
    /// the messageDigest attribute against the content when signed
    /// attributes are present, then the signature. No chain, no store.
    ///
    /// The digest BIO is built here for the SignerInfo's own
    /// digestAlgorithm. `PKCS7_dataInit` would build one per entry of the
    /// SignedData-level digestAlgorithms set instead, so a set that does not
    /// name the signer's digest (it is unsigned) would fail a receipt Java
    /// accepts, and an unknown OID in that set would fail it too.
    #[cfg(not(any(feature = "a1", aprv_awslc)))]
    #[must_use]
    pub fn verify_first_signer(&mut self, signer: &Certificate) -> bool {
        let si = self.first_signer_info();
        if si.is_null() {
            return false;
        }
        let content = self.content();
        let Ok(content_len) = c_int::try_from(content.len()) else {
            return false;
        };
        // SAFETY: `si` is owned by self.p7; the digest lookup returns a
        // static method table or null.
        let md = unsafe {
            let algor = (*si).digest_alg;
            if algor.is_null() {
                return false;
            }
            let mut object: *const ffi::ASN1_OBJECT = ptr::null();
            ffi::X509_ALGOR_get0(&mut object, ptr::null_mut(), ptr::null_mut(), algor);
            ffi::EVP_get_digestbynid(ffi::OBJ_obj2nid(object))
        };
        if md.is_null() {
            drain_errors();
            return false;
        }
        // SAFETY: a read-only memory BIO over `content`, which outlives it;
        // a digest BIO pushed in front of it. The chain is freed once below
        // with BIO_free_all, whatever happens in between.
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
        // SAFETY: all four pointers are live; PKCS7_signatureVerify finds
        // the digest BIO in `chain` by the SignerInfo's digest type and only
        // reads the certificate.
        let ok = unsafe { sys::PKCS7_signatureVerify(chain, self.p7, si, signer.0.as_ptr()) } == 1;
        // SAFETY: frees the chain built above, once.
        unsafe { ffi::BIO_free_all(chain) };
        if !ok {
            drain_errors();
        }
        ok
    }

    /// Experiment A1: the same step through PKCS7_verify with NOVERIFY
    /// (no chain, no S/MIME purpose), NOINTERN and NOCHAIN, the signer
    /// passed explicitly and an empty store. PKCS7_verify checks every
    /// SignerInfo, and digests the content only with the algorithms the
    /// SignedData-level digestAlgorithms set names.
    #[cfg(feature = "a1")]
    #[must_use]
    pub fn verify_first_signer(&mut self, signer: &Certificate) -> bool {
        self.pkcs7_verify_signature_only(signer)
    }

    /// AWS-LC has no public `PKCS7_signatureVerify`, only `PKCS7_verify`.
    /// To keep Java's semantics (the first SignerInfo only, digested with
    /// its own algorithm), the parsed structure is normalised first: every
    /// SignerInfo after the first is dropped and the digestAlgorithms set is
    /// replaced by the first SignerInfo's digestAlgorithm. Neither is
    /// covered by the signature.
    #[cfg(all(aprv_awslc, not(feature = "a1")))]
    #[must_use]
    pub fn verify_first_signer(&mut self, signer: &Certificate) -> bool {
        let signed = self.signed_ptr();
        if signed.is_null() || self.first_signer_info().is_null() {
            return false;
        }
        // SAFETY: `signed` and its stacks are owned by self.p7 and mutated
        // only here, under `&mut self`. Popped entries are freed once; the
        // pushed X509_ALGOR is a fresh copy that the stack then owns.
        unsafe {
            let infos = (*signed).signer_info;
            while sk_num(infos) > 1 {
                let extra = ffi::OPENSSL_sk_pop(infos.cast());
                ffi::PKCS7_SIGNER_INFO_free(extra.cast());
            }
            let si = self.first_signer_info();
            let md_algs = (*signed).md_algs;
            if md_algs.is_null() || (*si).digest_alg.is_null() {
                return false;
            }
            while sk_num(md_algs) > 0 {
                let old = ffi::OPENSSL_sk_pop(md_algs.cast());
                ffi::X509_ALGOR_free(old.cast());
            }
            let copy = ffi::X509_ALGOR_dup((*si).digest_alg);
            if copy.is_null() || ffi::OPENSSL_sk_push(md_algs.cast(), copy.cast()) == 0 {
                ffi::X509_ALGOR_free(copy);
                drain_errors();
                return false;
            }
        }
        self.pkcs7_verify_signature_only(signer)
    }

    #[cfg(any(feature = "a1", aprv_awslc))]
    fn pkcs7_verify_signature_only(&mut self, signer: &Certificate) -> bool {
        let Ok(mut certs) = Stack::new() else { return false };
        if certs.push(signer.0.clone()).is_err() {
            return false;
        }
        let Ok(store) = X509StoreBuilder::new().map(X509StoreBuilder::build) else {
            return false;
        };
        let flags = sys::PKCS7_NOVERIFY | sys::PKCS7_NOINTERN | sys::PKCS7_NOCHAIN;
        // SAFETY: every pointer is live for the call; PKCS7_verify reads
        // the certificate stack and the (empty) store, builds and frees its
        // own BIO chain, and writes no output (null out BIO).
        let ok = unsafe {
            sys::PKCS7_verify(self.p7, certs.as_ptr(), store.as_ptr(), ptr::null_mut(), ptr::null_mut(), flags)
        } == 1;
        if !ok {
            drain_errors();
        }
        ok
    }
}

fn algor_oid(algor: *mut ffi::X509_ALGOR) -> String {
    if algor.is_null() {
        return String::new();
    }
    let mut object: *const ffi::ASN1_OBJECT = ptr::null();
    // SAFETY: `algor` is live; X509_ALGOR_get0 stores a borrowed pointer.
    unsafe { ffi::X509_ALGOR_get0(&mut object, ptr::null_mut(), ptr::null_mut(), algor) };
    oid_text(object)
}

fn oid_text(object: *const ffi::ASN1_OBJECT) -> String {
    if object.is_null() {
        return String::new();
    }
    let mut buffer = [0u8; 128];
    // SAFETY: writes at most 128 bytes, NUL-terminated, into `buffer`.
    let written = unsafe { ffi::OBJ_obj2txt(buffer.as_mut_ptr().cast(), 128, object, 1) };
    let length = usize::try_from(written).unwrap_or(0).min(127);
    String::from_utf8_lossy(&buffer[..length]).into_owned()
}

/// Path validation failure: the library's `X509_V_ERR_*` code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathError(pub i32);

/// Builds and validates a path from `target` through `untrusted` to one of
/// `anchors`, at `at_secs` (Unix seconds), with at most `max_intermediates`
/// certificates between the target and the anchor. The store holds the
/// anchors and nothing else. Returns the built chain, anchor last.
///
/// Flags: `PARTIAL_CHAIN`, so an anchor that is not self-signed is still a
/// trust anchor (Java's TrustAnchor semantics). No purpose, no policy, no
/// CRL, no host check.
///
/// # Errors
/// [`PathError`] with the verification error code.
pub fn verify_path(
    target: &Certificate,
    untrusted: &[Certificate],
    anchors: &[Certificate],
    at_secs: i64,
    max_intermediates: u32,
) -> Result<Vec<Certificate>, PathError> {
    init();
    let internal = PathError(-1);
    let mut builder = X509StoreBuilder::new().map_err(|_| internal)?;
    for anchor in anchors {
        builder.add_cert(anchor.0.clone()).map_err(|_| internal)?;
    }
    #[cfg(feature = "negative-control")]
    builder.set_default_paths().map_err(|_| internal)?;
    let mut param = X509VerifyParam::new().map_err(|_| internal)?;
    param.set_time(at_secs as libc::time_t);
    // OpenSSL's depth counts the intermediates. LibreSSL's verifier counts
    // one more (it stops when the chain without its anchor reaches the
    // depth), so the same number rejects a valid leaf -> CA -> root path
    // there with X509_V_ERR_CERT_CHAIN_TOO_LONG. Callers still check the
    // length of the chain that comes back.
    #[cfg(not(aprv_libressl))]
    let depth = max_intermediates;
    #[cfg(aprv_libressl)]
    let depth = max_intermediates.saturating_add(1);
    param.set_depth(c_int::try_from(depth).unwrap_or(0));
    param
        .set_flags(X509VerifyFlags::PARTIAL_CHAIN)
        .map_err(|_| internal)?;
    builder.set_param(&param).map_err(|_| internal)?;
    let store = builder.build();
    let mut chain = Stack::new().map_err(|_| internal)?;
    for cert in untrusted {
        chain.push(cert.0.clone()).map_err(|_| internal)?;
    }
    ANCHORS.with(|slot| *slot.borrow_mut() = anchors.iter().map(|a| a.0.clone()).collect());
    CHECK_TIME.with(|slot| slot.set(at_secs));
    let mut context = X509StoreContext::new().map_err(|_| internal)?;
    let result = context
        .init(&store, &target.0, &chain, |ctx| {
            // SAFETY: installs a plain function pointer on the live context
            // for the duration of this verification only.
            unsafe { sys::X509_STORE_CTX_set_verify_cb(ctx.as_ptr(), Some(anchor_is_trusted_by_fiat)) };
            let ok = ctx.verify_cert()?;
            if ok {
                let built = ctx
                    .chain()
                    .map(|stack| stack.iter().map(|c| Certificate(c.to_owned())).collect())
                    .unwrap_or_default();
                Ok(Ok(built))
            } else {
                Ok(Err(PathError(ctx.error().as_raw())))
            }
        })
        .map_err(|_| internal);
    ANCHORS.with(|slot| slot.borrow_mut().clear());
    drain_errors();
    result?
}

/// Verify callback: a trust anchor is trusted by fiat, as in Java's
/// `TrustAnchor` (and the Rust core): its own validity window, its CA flag
/// and its path length constraint are not judged. The libraries judge all
/// three for a certificate in the store. The certificate an error is about
/// is compared with the caller's anchors (byte for byte, `X509_cmp`), which
/// works for both OpenSSL's and LibreSSL's verifiers; a depth test does
/// not, because LibreSSL has no chain in the context while it builds one.
/// The one other waiver is an expiry reported at exactly the notAfter
/// second (see below). Every other failure stands.
unsafe extern "C" fn anchor_is_trusted_by_fiat(ok: c_int, ctx: *mut ffi::X509_STORE_CTX) -> c_int {
    if ok == 1 {
        return 1;
    }
    // SAFETY: OpenSSL calls this with the live context it is verifying;
    // the current certificate is borrowed from it for this call only.
    unsafe {
        let error = ffi::X509_STORE_CTX_get_error(ctx);
        let anchor_errors = [
            ffi::X509_V_ERR_CERT_NOT_YET_VALID,
            ffi::X509_V_ERR_CERT_HAS_EXPIRED,
            ffi::X509_V_ERR_INVALID_CA,
            ffi::X509_V_ERR_PATH_LENGTH_EXCEEDED,
        ];
        if !anchor_errors.contains(&error) {
            return 0;
        }
        let current = ffi::X509_STORE_CTX_get_current_cert(ctx);
        if current.is_null() {
            return 0;
        }
        let exempt = ANCHORS.with(|slot| slot.borrow().iter().any(|a| ffi::X509_cmp(a.as_ptr(), current) == 0));
        // OpenSSL 1.1.1 to 3.6 and AWS-LC treat notAfter as exclusive: a
        // certificate is expired at the very second its notAfter names.
        // RFC 5280 section 4.1.2.5, Java, LibreSSL and OpenSSL 4.0 include
        // that second, so an expiry exactly at the checked second is waived
        // for every certificate.
        let exempt = exempt
            || (error == ffi::X509_V_ERR_CERT_HAS_EXPIRED && {
                let at = CHECK_TIME.with(std::cell::Cell::get);
                let cert = openssl::x509::X509Ref::from_ptr(current);
                openssl::asn1::Asn1Time::from_unix(at as libc::time_t).is_ok_and(|t| cert.not_after() == t)
            });
        if exempt {
            ffi::X509_STORE_CTX_set_error(ctx, ffi::X509_V_OK);
            return 1;
        }
    }
    0
}

/// ES256 (RFC 7515): SHA-256 and ECDSA over P-256 with a raw 64-byte
/// `r || s` signature. A key on any other curve fails.
#[must_use]
pub fn verify_es256(leaf: &Certificate, raw_signature: &[u8], message: &[u8]) -> bool {
    init();
    if raw_signature.len() != 64 {
        return false;
    }
    let verdict = (|| {
        let key = leaf.0.public_key().ok()?;
        let ec = key.ec_key().ok()?;
        if ec.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
            return Some(false);
        }
        let r = BigNum::from_slice(raw_signature.get(..32)?).ok()?;
        let s = BigNum::from_slice(raw_signature.get(32..)?).ok()?;
        let signature = EcdsaSig::from_private_components(r, s).ok()?;
        let digest = openssl::sha::sha256(message);
        signature.verify(&digest, &ec).ok()
    })();
    drain_errors();
    verdict == Some(true)
}

/// SHA-1, for the device-binding hash.
#[must_use]
pub fn sha1(data: &[u8]) -> [u8; 20] {
    init();
    openssl::sha::sha1(data)
}

/// Constant-time equality; lengths are public and compared first.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && openssl::memcmp::eq(a, b)
}
