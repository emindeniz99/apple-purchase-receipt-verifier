//! A shallow decode of a CMS `ContentInfo` and its `SignedData`
//! (`envelope.c`), for what OpenSSL's full decode cannot tell the core in
//! time: the content type, and how many certificates and `SignerInfo`s
//! there are, before `d2i_CMS_ContentInfo` builds every embedded
//! certificate's public key.

use crate::item::{decode_exact, typed, Decoded};
use crate::{drain_errors, sys};
use openssl_sys as ffi;

/// How many members an envelope's `certificates` and `signerInfos` sets
/// hold, counted without decoding a single member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeMembers {
    /// Entries of the `certificates` set, of every `CertificateChoices`
    /// alternative; 0 when the set is absent.
    pub certificates: usize,
    /// Entries of the `signerInfos` set.
    pub signer_infos: usize,
}

/// Why the shallow decode refused an envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShallowError {
    /// Not a `ContentInfo`, or a `signedData` whose `SignedData` does not
    /// have the shape.
    Malformed,
    /// A `ContentInfo` of another type.
    NotSignedData,
}

/// A decoded `APRV_SIGNED_DATA`, from a `ContentInfo` whose content type is
/// `signedData`.
pub(crate) struct Envelope {
    signed: Decoded,
}

impl Envelope {
    /// The shallow decode of `der`, which must be one whole `ContentInfo`.
    /// It costs two copies of the input, where the full decode builds every
    /// certificate's public key.
    pub(crate) fn decode(der: &[u8]) -> Result<Envelope, ShallowError> {
        // SAFETY: an item getter envelope.c defines; it returns a static.
        let Some(info) = decode_exact(der, unsafe { sys::APRV_CONTENT_INFO_it() }) else {
            drain_errors();
            return Err(ShallowError::Malformed);
        };
        let info_value: *const sys::APRV_CONTENT_INFO = info.value().cast_const().cast();
        // SAFETY: `info_value` is the live APRV_CONTENT_INFO `info` owns,
        // laid out as sys::APRV_CONTENT_INFO mirrors it. OBJ_obj2nid reads a
        // live object, or answers NID_undef for null.
        let (content_type, content) = unsafe {
            (
                ffi::OBJ_obj2nid((*info_value).content_type),
                (*info_value).content.cast_const(),
            )
        };
        if content_type != ffi::NID_pkcs7_signed {
            return Err(ShallowError::NotSignedData);
        }
        // `content` is the template's last field and not OPTIONAL, so a
        // decoded value always has one (tasn_dec.c:440-441, 480-492).
        debug_assert!(!content.is_null());
        // A SEQUENCE inside ANY is kept as its whole encoding.
        let (kind, encoding) = typed(content);
        if kind != ffi::V_ASN1_SEQUENCE {
            return Err(ShallowError::Malformed);
        }
        let encoding = crate::cms::string_octets(encoding);
        // SAFETY: an item getter envelope.c defines; it returns a static.
        let Some(signed) = decode_exact(&encoding, unsafe { sys::APRV_SIGNED_DATA_it() }) else {
            drain_errors();
            return Err(ShallowError::Malformed);
        };
        Ok(Envelope { signed })
    }

    /// The `SignedData`, owned by `self`.
    fn signed(&self) -> *const sys::APRV_SIGNED_DATA {
        self.signed.value().cast_const().cast()
    }

    /// The member counts.
    pub(crate) fn members(&self) -> EnvelopeMembers {
        let signed = self.signed();
        // SAFETY: `signed` is the live APRV_SIGNED_DATA `self` owns, laid
        // out as sys::APRV_SIGNED_DATA mirrors it.
        let (certificates, signer_infos) =
            unsafe { ((*signed).certificates, (*signed).signer_infos) };
        EnvelopeMembers {
            certificates: count(certificates),
            signer_infos: count(signer_infos),
        }
    }
}

/// The number of elements of a stack a live `Envelope` owns; 0 for an
/// absent one.
fn count(stack: *const ffi::OPENSSL_STACK) -> usize {
    if stack.is_null() {
        return 0;
    }
    // SAFETY: a live stack the caller's `Envelope` owns.
    usize::try_from(unsafe { ffi::OPENSSL_sk_num(stack) }).unwrap_or(0)
}
