//! A shallow decode of a CMS `SignedData` envelope (`envelope.c`), for the
//! two things OpenSSL's full decode cannot tell the core: how many
//! certificates and `SignerInfo`s there are before each certificate's
//! public key is built, and whether the encapsulated content's chunks are
//! all `OCTET STRING`s.

use crate::item::{decode_exact, Decoded};
use crate::{drain_errors, sys};
use libc::{c_int, c_long};
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

/// The member counts of a `ContentInfo` carrying a `SignedData`, from a
/// shallow decode that keeps each certificate and `SignerInfo` as its raw
/// encoding: it costs a copy of the input, where
/// [`SignedData::parse`](crate::SignedData::parse) builds every
/// certificate's public key. `None` when the input does not have that
/// shape, bytes follow it, or its content type is not `signedData`;
/// [`SignedData::parse`](crate::SignedData::parse) then says why.
#[must_use]
pub fn envelope_members(der: &[u8]) -> Option<EnvelopeMembers> {
    let envelope = Envelope::decode(der)?;
    let signed = envelope.signed();
    // SAFETY: `signed` is the live APRV_SIGNED_DATA `envelope` owns.
    let (certificates, signer_infos) = unsafe { ((*signed).certificates, (*signed).signer_infos) };
    Some(EnvelopeMembers {
        certificates: count(certificates),
        signer_infos: count(signer_infos),
    })
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

/// A decoded `APRV_ENVELOPE` whose content type is `signedData`.
pub(crate) struct Envelope {
    decoded: Decoded,
}

impl Envelope {
    /// The shallow decode of `der`, which must be one whole value.
    pub(crate) fn decode(der: &[u8]) -> Option<Envelope> {
        // SAFETY: an item getter envelope.c defines; it returns a static.
        let Some(decoded) = decode_exact(der, unsafe { sys::APRV_ENVELOPE_it() }) else {
            drain_errors();
            return None;
        };
        let envelope: *const sys::APRV_ENVELOPE = decoded.value().cast_const().cast();
        // SAFETY: `envelope` is the live APRV_ENVELOPE `decoded` owns, laid
        // out as sys::APRV_ENVELOPE mirrors it. OBJ_obj2nid reads a live
        // object, or answers NID_undef for null.
        let (content_type, signed) = unsafe {
            (
                ffi::OBJ_obj2nid((*envelope).content_type),
                (*envelope).content,
            )
        };
        // `content` is not optional in the template, so a decoded value
        // always has one; the check costs nothing.
        (content_type == ffi::NID_pkcs7_signed && !signed.is_null()).then_some(Envelope { decoded })
    }

    /// The `SignedData`, owned by `self`.
    fn signed(&self) -> *const sys::APRV_SIGNED_DATA {
        let envelope: *const sys::APRV_ENVELOPE = self.decoded.value().cast_const().cast();
        // SAFETY: as in `decode`, which refused a null `content`.
        unsafe { (*envelope).content.cast_const() }
    }

    /// Whether the encapsulated content, when it is a constructed
    /// `OCTET STRING`, holds only `OCTET STRING`s at every depth. OpenSSL
    /// joins the chunks of a constructed string whatever their universal
    /// tag, so the content OpenSSL hands over cannot tell; this walks the
    /// raw `EncapsulatedContentInfo` the shallow decode kept, with OpenSSL's
    /// own TLV header decoder. Absent content counts as passing: the full
    /// decode refuses that on its own.
    pub(crate) fn content_chunks_are_octet_strings(&self) -> bool {
        // SAFETY: `signed()` is live while `self` is; the ASN1_TYPE it
        // holds is a SEQUENCE (the template's ANY found one, or OpenSSL's
        // full decode would have refused the envelope first), whose string
        // is the value's whole original encoding.
        let encapsulated = unsafe { (*self.signed()).encapsulated_content };
        let (kind, string) = crate::item::typed(encapsulated);
        if kind != ffi::V_ASN1_SEQUENCE {
            return false;
        }
        econtent_is_octet_string(&crate::cms::string_octets(string)).unwrap_or(false)
    }
}

/// OpenSSL's own nesting bound for constructed strings
/// (`ASN1_MAX_STRING_NEST`, `asn1_dec.c`): deeper, its full decode fails.
const MAX_STRING_NEST: usize = 5;

/// One TLV header, as `ASN1_get_object` reads it.
struct Header {
    tag: c_int,
    class: c_int,
    constructed: bool,
    indefinite: bool,
    /// Octets of the tag and length.
    head: usize,
    /// Octets of the content; 0 for an indefinite length.
    content: usize,
}

/// The header of the TLV at the start of `input`, whose definite content
/// must lie within `input`.
fn header(input: &[u8]) -> Option<Header> {
    let max = c_long::try_from(input.len()).ok()?;
    let start = input.as_ptr();
    let mut cursor = start;
    let (mut length, mut tag, mut class): (c_long, c_int, c_int) = (0, 0, 0);
    // SAFETY: `cursor` points at `max` readable bytes of `input`;
    // ASN1_get_object reads at most that many, advances the cursor past the
    // header, and writes through the three valid out-pointers.
    let answer = unsafe {
        sys::ASN1_get_object(
            &raw mut cursor,
            &raw mut length,
            &raw mut tag,
            &raw mut class,
            max,
        )
    };
    if answer & sys::ASN1_GET_OBJECT_ERROR != 0 {
        drain_errors();
        return None;
    }
    // Both pointers are into `input`, and the header decoder only moves the
    // cursor forward within it.
    let head = (cursor as usize).wrapping_sub(start as usize);
    let content = usize::try_from(length).ok()?;
    (head.checked_add(content)? <= input.len()).then_some(Header {
        tag,
        class,
        constructed: answer & sys::V_ASN1_CONSTRUCTED != 0,
        indefinite: answer & sys::ASN1_GET_OBJECT_INDEFINITE != 0,
        head,
        content,
    })
}

/// Whether the `eContent` of the `EncapsulatedContentInfo` encoded in
/// `encapsulated` is an `OCTET STRING` whose chunks at every depth are
/// `OCTET STRING`s. `Some(true)` when there is no `eContent`.
fn econtent_is_octet_string(encapsulated: &[u8]) -> Option<bool> {
    let outer = header(encapsulated)?;
    let body = encapsulated.get(outer.head..)?;
    let content_type = header(body)?;
    let rest = body.get(content_type.head + content_type.content..)?;
    if rest.is_empty() || rest.starts_with(&[0, 0]) {
        return Some(true);
    }
    let explicit = header(rest)?;
    if explicit.class != sys::V_ASN1_CONTEXT_SPECIFIC || explicit.tag != 0 || !explicit.constructed
    {
        return Some(false);
    }
    Some(octet_string(rest.get(explicit.head..)?, 0).is_some())
}

/// The encoded size of the `OCTET STRING` at the start of `input`, when its
/// chunks at every depth are `OCTET STRING`s. Every chunk consumes at least
/// two octets, so the walk is bounded by the input's length, and its depth
/// by [`MAX_STRING_NEST`].
fn octet_string(input: &[u8], depth: usize) -> Option<usize> {
    let string = header(input)?;
    if string.tag != ffi::V_ASN1_OCTET_STRING || string.class != sys::V_ASN1_UNIVERSAL {
        return None;
    }
    if !string.constructed {
        return Some(string.head + string.content);
    }
    if depth == MAX_STRING_NEST {
        return None;
    }
    let mut at = string.head;
    if string.indefinite {
        loop {
            let rest = input.get(at..)?;
            if rest.starts_with(&[0, 0]) {
                return Some(at + 2);
            }
            at += octet_string(rest, depth + 1)?;
        }
    }
    let end = string.head + string.content;
    while at < end {
        at += octet_string(input.get(at..end)?, depth + 1)?;
    }
    Some(end)
}
