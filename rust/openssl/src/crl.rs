//! One certificate revocation list (RFC 5280 section 5), parsed by OpenSSL.
//!
//! This module reads a list and checks its signature under a key it is
//! given; it decides nothing. Which lists are used, which extensions are
//! supported, what a reason code means and how serials are written are the
//! core's (`rust/src/revocation.rs`, docs/design/revocation.md). The list
//! is decoded by OpenSSL's templates (`crl.c`, OpenSSL's own CRL grammar
//! without the checks `d2i_X509_CRL` runs after decoding, so a genuine list
//! those checks refuse can still be read and set aside), and every value
//! is read through OpenSSL's own accessors and decoders
//! (`X509V3_get_d2i`, `X509_REVOKED_get_ext_d2i`, `ASN1_item_verify`);
//! nothing here walks the list's bytes. Those two extension decoders read
//! the leading value of an extension and pass over octets left after it
//! (`X509V3_EXT_d2i`, `v3_lib.c`), so every decoded value is also checked to
//! fill its `extnValue` exactly ([`value_is_exact`]).

use crate::certificate::Certificate;
use crate::item::{decode_exact, Decoded};
use crate::{drain_errors, init, sys};
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::c_int;
use openssl::asn1::Asn1Time;
use openssl_sys as ffi;
use std::ptr;

/// An INTEGER as OpenSSL holds it: a sign and the magnitude, big-endian,
/// as stored (OpenSSL drops the DER sign octet, so `00 80` reads as the
/// magnitude `80`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integer {
    /// Whether the value is negative.
    pub negative: bool,
    /// The magnitude's octets, most significant first.
    pub magnitude: Vec<u8>,
}

/// A field that may be absent, present, or present in a form OpenSSL does
/// not decode (or present more than once, for an extension).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListField<T> {
    /// Not in the list.
    Absent,
    /// Present, with its value.
    Present(T),
    /// Present, but not readable as its type, or repeated.
    Unreadable,
}

/// The list's `AuthorityKeyIdentifier` extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyIdentifier {
    /// No `AuthorityKeyIdentifier`.
    Absent,
    /// An `AuthorityKeyIdentifier` with this keyIdentifier.
    Present(Vec<u8>),
    /// An `AuthorityKeyIdentifier` with no keyIdentifier.
    WithoutKeyIdentifier,
    /// An `AuthorityKeyIdentifier` OpenSSL does not decode, or more than one.
    Unreadable,
}

/// One extension of a list or of a list entry: its OID in dotted form and
/// whether it is marked critical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListExtension {
    /// The OID, dotted (`2.5.29.20`).
    pub oid: String,
    /// The `critical` flag.
    pub critical: bool,
}

/// One entry of `revokedCertificates`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    /// `userCertificate`, the revoked certificate's serial.
    pub serial: Integer,
    /// The `reasonCode` entry extension's value (RFC 5280 section 5.3.1).
    pub reason: ListField<i64>,
    /// Every entry extension, in order.
    pub extensions: Vec<ListExtension>,
}

/// An owned revocation list as OpenSSL decoded it.
pub struct RevocationList(Decoded);

impl core::fmt::Debug for RevocationList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RevocationList").finish_non_exhaustive()
    }
}

impl RevocationList {
    /// Decodes exactly one `CertificateList` with the templates of `crl.c`
    /// (OpenSSL's own grammar for one, without `d2i_X509_CRL`'s post-decode
    /// checks of the extensions); bytes left over after it are refused.
    #[must_use]
    pub fn from_der(der: &[u8]) -> Option<RevocationList> {
        init();
        // SAFETY: the item getter returns a pointer to a static ASN1_ITEM.
        let item = unsafe { sys::APRV_CERT_LIST_it() };
        let decoded = decode_exact(der, item)?;
        let list = RevocationList(decoded);
        // A decode always fills the mandatory members; checked once here so
        // that every accessor below may rely on it.
        let whole = !list.tbs().is_null()
            // SAFETY: `tbs` is non-null and owned by the decoded value.
            && unsafe {
                let tbs = &*list.tbs();
                !tbs.signature.is_null() && !tbs.issuer.is_null() && !tbs.this_update.is_null()
            }
            // SAFETY: reads two pointers of the live decoded value.
            && unsafe { !(*list.raw()).algorithm.is_null() && !(*list.raw()).signature.is_null() };
        drain_errors();
        whole.then_some(list)
    }

    fn raw(&self) -> *mut sys::APRV_CERT_LIST {
        self.0.value().cast()
    }

    fn tbs(&self) -> *mut sys::APRV_TBS_CERT_LIST {
        // SAFETY: reads one pointer of the live decoded value.
        unsafe { (*self.raw()).tbs }
    }

    /// A member of the live `TBSCertList`, which `from_der` has checked.
    fn member<T>(&self, read: impl FnOnce(&sys::APRV_TBS_CERT_LIST) -> T) -> T {
        // SAFETY: `tbs` is non-null (checked in `from_der`) and owned by the
        // decoded value, which `self` keeps alive.
        read(unsafe { &*self.tbs() })
    }

    /// The list's `issuer` Name as it was encoded in the list:
    /// `i2d_X509_NAME` writes the encoding OpenSSL kept when it decoded
    /// the Name, not a re-encoding.
    #[must_use]
    pub fn issuer_name_der(&self) -> Option<Vec<u8>> {
        let name = self.member(|tbs| tbs.issuer);
        // SAFETY: `name` is non-null and live while `self` is borrowed.
        let der = unsafe { openssl::x509::X509NameRef::from_ptr(name) }
            .to_der()
            .ok();
        drain_errors();
        der
    }

    /// The `version` field: 0 when absent (v1), 1 for v2, -1 when it does
    /// not read as a small integer.
    #[must_use]
    pub fn version(&self) -> i64 {
        let version = self.member(|tbs| tbs.version);
        if version.is_null() {
            return 0;
        }
        let mut value: i64 = 0;
        // SAFETY: reads the live INTEGER.
        let read = unsafe { sys::ASN1_INTEGER_get_int64(&raw mut value, version) } == 1;
        drain_errors();
        if read {
            value
        } else {
            -1
        }
    }

    /// `thisUpdate` as Unix seconds, or `None` when it does not read as a
    /// time.
    #[must_use]
    pub fn this_update(&self) -> Option<i64> {
        unix_seconds(self.member(|tbs| tbs.this_update))
    }

    /// `nextUpdate` as Unix seconds.
    #[must_use]
    pub fn next_update(&self) -> ListField<i64> {
        let time = self.member(|tbs| tbs.next_update);
        if time.is_null() {
            return ListField::Absent;
        }
        unix_seconds(time).map_or(ListField::Unreadable, ListField::Present)
    }

    fn extension_stack(&self) -> *mut ffi::stack_st_X509_EXTENSION {
        self.member(|tbs| tbs.extensions)
    }

    /// One list extension decoded by OpenSSL (`X509V3_get_d2i`) as `item`:
    /// a new value the caller owns, or `Err` with -1 when the extension is
    /// absent, -2 when it is repeated, and 0 or 1 when it does not decode
    /// or leaves octets of its `extnValue` over.
    fn decoded_extension(
        &self,
        nid: c_int,
        item: *const sys::ASN1_ITEM,
    ) -> Result<*mut libc::c_void, c_int> {
        let mut critical: c_int = -1;
        let stack = self.extension_stack();
        if stack.is_null() {
            return Err(-1);
        }
        // SAFETY: decodes the extension into a new value the caller owns,
        // or returns null and sets `critical` as documented above.
        let decoded =
            unsafe { ffi::X509V3_get_d2i(stack, nid, &raw mut critical, ptr::null_mut()) };
        if decoded.is_null() {
            drain_errors();
            return Err(critical);
        }
        // SAFETY: the extension decoded above is in the live stack, once.
        let extension =
            unsafe { ffi::X509v3_get_ext(stack, ffi::X509v3_get_ext_by_NID(stack, nid, -1)) };
        if value_is_exact(extension, item) {
            Ok(decoded)
        } else {
            // SAFETY: `decoded` is a value of `item` (X509V3_EXT_d2i decodes
            // these extensions with their method's item), owned here alone.
            unsafe { sys::ASN1_item_free(decoded.cast(), item) };
            Err(0)
        }
    }

    /// The CRL Number extension (RFC 5280 section 5.2.3).
    #[must_use]
    pub fn number(&self) -> ListField<Integer> {
        // SAFETY: the item getter returns a pointer to a static ASN1_ITEM.
        match self.decoded_extension(ffi::NID_crl_number, unsafe { sys::ASN1_INTEGER_it() }) {
            Err(-1) => ListField::Absent,
            Err(_) => ListField::Unreadable,
            Ok(decoded) => {
                let integer = decoded.cast::<ffi::ASN1_INTEGER>();
                let value = integer_of(integer);
                // SAFETY: `integer` is the value decoded above, owned here
                // alone.
                unsafe { ffi::ASN1_INTEGER_free(integer) };
                value.map_or(ListField::Unreadable, ListField::Present)
            }
        }
    }

    /// The `AuthorityKeyIdentifier` extension's keyIdentifier.
    #[must_use]
    pub fn authority_key_identifier(&self) -> KeyIdentifier {
        // SAFETY: the item getter returns a pointer to a static ASN1_ITEM.
        let item = unsafe { sys::AUTHORITY_KEYID_it() };
        match self.decoded_extension(ffi::NID_authority_key_identifier, item) {
            Err(-1) => KeyIdentifier::Absent,
            Err(_) => KeyIdentifier::Unreadable,
            Ok(decoded) => {
                let akid = decoded.cast::<ffi::AUTHORITY_KEYID>();
                // SAFETY: `akid` is the live AUTHORITY_KEYID decoded above;
                // its `keyid` member is an ASN1_OCTET_STRING it owns, or
                // null.
                let keyid = unsafe { (*akid).keyid };
                let identifier = if keyid.is_null() {
                    KeyIdentifier::WithoutKeyIdentifier
                } else {
                    KeyIdentifier::Present(string_octets(keyid.cast()))
                };
                // SAFETY: `akid` is owned here alone and freed once.
                unsafe { ffi::AUTHORITY_KEYID_free(akid) };
                identifier
            }
        }
    }

    /// Every list extension, in order, or `None` when one has no readable
    /// OID.
    #[must_use]
    pub fn extensions(&self) -> Option<Vec<ListExtension>> {
        let stack = self.extension_stack();
        if stack.is_null() {
            return Some(Vec::new());
        }
        // SAFETY: reads the count of a live stack.
        let count = unsafe { ffi::X509v3_get_ext_count(stack) };
        (0..count)
            .map(|index| {
                // SAFETY: `index` is below the count; the extension is
                // owned by the stack.
                extension_of(unsafe { ffi::X509v3_get_ext(stack, index) })
            })
            .collect()
    }

    fn revoked(&self) -> *mut ffi::stack_st_X509_REVOKED {
        self.member(|tbs| tbs.revoked)
    }

    /// How many entries `revokedCertificates` holds.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        let stack = self.revoked();
        if stack.is_null() {
            return 0;
        }
        // SAFETY: a live stack owned by the list.
        usize::try_from(unsafe { ffi::OPENSSL_sk_num(stack.cast()) }).unwrap_or(0)
    }

    /// Every entry, in order, or `None` when one cannot be read (a serial
    /// that does not read, an extension with no readable OID).
    #[must_use]
    pub fn entries(&self) -> Option<Vec<ListEntry>> {
        let stack = self.revoked();
        if stack.is_null() {
            return Some(Vec::new());
        }
        let entries = crate::item::elements::<ffi::X509_REVOKED>(stack.cast())
            .into_iter()
            .map(entry_of)
            .collect();
        drain_errors();
        entries
    }

    /// Whether `issuer`'s public key verifies the list's signature, as
    /// `X509_CRL_verify` checks one: the outer `signatureAlgorithm` equal
    /// to the `TBSCertList`'s `signature`, then `ASN1_item_verify` over the
    /// `TBSCertList` as it was encoded. No name, key identifier or time is
    /// judged.
    #[must_use]
    pub fn verified_by(&self, issuer: &Certificate) -> bool {
        init();
        let Ok(key) = issuer.x509().public_key() else {
            drain_errors();
            return false;
        };
        #[cfg(feature = "test-seams")]
        crate::keys::record(&key);
        // SAFETY: every pointer is a live member of the decoded value or
        // the key, borrowed for the calls, which only read them. The
        // TBSCertList is re-encoded from its cached original encoding.
        let verified = unsafe {
            let list = &*self.raw();
            let tbs = list.tbs;
            sys::X509_ALGOR_cmp(list.algorithm, (*tbs).signature) == 0
                && sys::ASN1_item_verify(
                    sys::APRV_TBS_CERT_LIST_it(),
                    list.algorithm,
                    list.signature,
                    tbs.cast_const().cast(),
                    key.as_ptr(),
                ) == 1
        };
        drain_errors();
        verified
    }
}

/// One entry, read from a live `X509_REVOKED` its list owns.
fn entry_of(entry: *mut ffi::X509_REVOKED) -> Option<ListEntry> {
    // SAFETY: the serial is owned by the live entry.
    let serial = integer_of(unsafe { ffi::X509_REVOKED_get0_serialNumber(entry) }.cast_mut())?;
    // SAFETY: reads the extension count of the live entry.
    let count = unsafe { ffi::X509_REVOKED_get_ext_count(entry) };
    let extensions = (0..count)
        .map(|index| {
            // SAFETY: `index` is below the count; the extension is owned by
            // the entry.
            extension_of(unsafe { ffi::X509_REVOKED_get_ext(entry, index) })
        })
        .collect::<Option<Vec<_>>>()?;
    let mut critical: c_int = 0;
    // SAFETY: decodes the reasonCode into a new ASN1_ENUMERATED the caller
    // owns, or returns null and sets `critical` to -1 when absent and -2
    // when repeated.
    let decoded = unsafe {
        ffi::X509_REVOKED_get_ext_d2i(
            entry,
            ffi::NID_crl_reason,
            &raw mut critical,
            ptr::null_mut(),
        )
    };
    let reason = if decoded.is_null() {
        drain_errors();
        if critical == -1 {
            ListField::Absent
        } else {
            ListField::Unreadable
        }
    } else {
        let enumerated = decoded.cast::<ffi::ASN1_ENUMERATED>();
        // SAFETY: the reasonCode decoded above is among the live entry's
        // extensions, once; the item getter returns a static ASN1_ITEM.
        let exact = unsafe {
            value_is_exact(
                ffi::X509_REVOKED_get_ext(
                    entry,
                    ffi::X509_REVOKED_get_ext_by_NID(entry, ffi::NID_crl_reason, -1),
                ),
                sys::ASN1_ENUMERATED_it(),
            )
        };
        let mut value: i64 = 0;
        // SAFETY: reads the live value decoded above.
        let read =
            exact && unsafe { ffi::ASN1_ENUMERATED_get_int64(&raw mut value, enumerated) } == 1;
        // SAFETY: owned here alone and freed once.
        unsafe { ffi::ASN1_ENUMERATED_free(enumerated) };
        drain_errors();
        if read {
            ListField::Present(value)
        } else {
            ListField::Unreadable
        }
    };
    Some(ListEntry {
        serial,
        reason,
        extensions,
    })
}

/// Whether a live extension's `extnValue` is exactly one value of `item`,
/// as OpenSSL's template decoder reads it, with no octet left over: the
/// value OpenSSL's extension decoders take from it, not merely its leading
/// part (docs/design/revocation.md §4, "does not read"). False for a null
/// extension.
pub(crate) fn value_is_exact(
    extension: *mut ffi::X509_EXTENSION,
    item: *const sys::ASN1_ITEM,
) -> bool {
    exact_value(extension, item).is_some()
}

/// A live extension's `extnValue` decoded as exactly one value of `item`
/// ([`value_is_exact`]), or `None`.
pub(crate) fn exact_value(
    extension: *mut ffi::X509_EXTENSION,
    item: *const sys::ASN1_ITEM,
) -> Option<Decoded> {
    if extension.is_null() {
        return None;
    }
    // SAFETY: the value is owned by the live extension.
    let data = unsafe { ffi::X509_EXTENSION_get_data(extension) };
    if data.is_null() {
        return None;
    }
    let decoded = decode_exact(&string_octets(data.cast()), item);
    drain_errors();
    decoded
}

/// The OID and the critical flag of a live extension.
fn extension_of(extension: *mut ffi::X509_EXTENSION) -> Option<ListExtension> {
    if extension.is_null() {
        return None;
    }
    // SAFETY: the object is owned by the live extension.
    let object = unsafe { ffi::X509_EXTENSION_get_object(extension) };
    if object.is_null() {
        return None;
    }
    // SAFETY: reads a field of the live extension.
    let critical = unsafe { ffi::X509_EXTENSION_get_critical(extension) } > 0;
    Some(ListExtension {
        oid: dotted(object)?,
        critical,
    })
}

/// An OID in dotted form (`OBJ_obj2txt` with `no_name`), whatever its
/// length.
fn dotted(object: *const ffi::ASN1_OBJECT) -> Option<String> {
    let mut buffer = vec![0u8; 128];
    loop {
        let size = c_int::try_from(buffer.len()).ok()?;
        // SAFETY: writes at most `size` bytes, NUL included, into `buffer`,
        // and reads the live object.
        let needed = unsafe { ffi::OBJ_obj2txt(buffer.as_mut_ptr().cast(), size, object, 1) };
        let needed = usize::try_from(needed).ok().filter(|n| *n > 0)?;
        if needed < buffer.len() {
            buffer.truncate(needed);
            return String::from_utf8(buffer).ok();
        }
        buffer = vec![0u8; needed.checked_add(1)?];
    }
}

/// The sign and magnitude of a live INTEGER.
pub(crate) fn integer_of(integer: *mut ffi::ASN1_INTEGER) -> Option<Integer> {
    if integer.is_null() {
        return None;
    }
    let string = integer.cast::<ffi::ASN1_STRING>();
    // SAFETY: an ASN1_INTEGER is an ASN1_STRING; the type is read from the
    // live value.
    let kind = unsafe { ffi::ASN1_STRING_type(string) };
    let negative = match kind {
        ffi::V_ASN1_INTEGER => false,
        sys::V_ASN1_NEG_INTEGER => true,
        _ => return None,
    };
    Some(Integer {
        negative,
        magnitude: string_octets(string),
    })
}

/// A copy of a live string's octets.
pub(crate) fn string_octets(string: *const ffi::ASN1_STRING) -> Vec<u8> {
    // SAFETY: both calls only read the live string; the data pointer is
    // valid for the length it reports.
    unsafe {
        let length = usize::try_from(ffi::ASN1_STRING_length(string)).unwrap_or(0);
        let data = ffi::ASN1_STRING_get0_data(string);
        if data.is_null() || length == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(data, length).to_vec()
        }
    }
}

/// A live time as Unix seconds: the difference OpenSSL computes from the
/// epoch (`ASN1_TIME_diff`), or `None` when the time does not read.
fn unix_seconds(time: *const ffi::ASN1_TIME) -> Option<i64> {
    if time.is_null() {
        return None;
    }
    let epoch = Asn1Time::from_unix(0).ok()?;
    let (mut days, mut seconds): (c_int, c_int) = (0, 0);
    // SAFETY: both times are live for the call; it writes the two
    // out-values.
    let read =
        unsafe { ffi::ASN1_TIME_diff(&raw mut days, &raw mut seconds, epoch.as_ptr(), time) } == 1;
    drain_errors();
    read.then(|| i64::from(days) * 86_400 + i64::from(seconds))
}
