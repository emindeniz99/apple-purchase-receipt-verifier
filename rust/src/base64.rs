//! Base64, in the shapes this crate needs, on the `base64` crate's engines.
//!
//! There are two decoders, and which one a caller gets is a security
//! decision rather than a convenience.
//!
//! [`decode_receipt_base64`] is what `receipt-data`, the base64 string a
//! client actually sends, and every `x5c` entry are decoded with: canonical
//! standard base64 and nothing else, the rule Apple's verifyReceipt applies
//! (measured 2026-09-23) and the one RFC 7515 §4.1.6 gives an `x5c` entry.
//! See its own docs.
//!
//! [`decode_base64url_strict`] refuses anything that is not a canonical
//! RFC 4648 §5 encoding. The three segments of a compact JWS are decoded
//! with it, because there leniency is not convenience but malleability: a
//! lenient decoder lets an attacker who holds one Apple-signed
//! `jwsRepresentation` mint unboundedly many byte-distinct strings that all
//! verify to the same transaction. The signature segment is the exposed
//! one — the header and payload segments are covered by the signing input —
//! and it is not covered by the signature at all.
//!
//! Strict decoding bounds that to two spellings, not one. An ES256
//! signature (r, s) also verifies as (r, n − s), so anyone holding a JWS
//! can rewrite its signature segment without a key. Apple does not
//! normalise to low-S, so refusing high-S would refuse genuine JWS; the
//! core and the Java implementation accept both forms. A JWS string or its hash is therefore never a dedupe key;
//! callers dedupe on `transactionId` or `notificationUUID` inside the
//! verified payload (INTEGRATION.md).
//!
//! Strictness here goes one step past common platform decoders, which
//! accept a final character whose
//! unused low bits are not zero: an ES256 signature is 86 base64 characters
//! carrying 516 bits for 512 bits of signature, so those four bits are four
//! more bits of malleability, and 16 spellings of one signature all verified
//! before this decoder existed. No encoder produces them; they are only ever
//! hand-made.

/// The `base64` crate's standard engine, configured for the rule
/// [`decode_receipt_base64`] documents: canonical padding required, and the
/// unused low bits of the last data character ignored rather than refused.
const RECEIPT_ENGINE: ::base64::engine::GeneralPurpose = ::base64::engine::GeneralPurpose::new(
    &::base64::alphabet::STANDARD,
    ::base64::engine::GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(::base64::engine::DecodePaddingMode::RequireCanonical),
);

/// Decodes `receipt-data`, the base64 string a client sends, by the rule
/// Apple's verifyReceipt applies (measured 2026-09-23, see
/// `docs/evidence/2026-09-23-verifyreceipt-base64.md`): non-empty standard
/// base64 (`A-Z a-z 0-9 + /`) carrying exactly the canonical `=` padding for
/// its length, and nothing else. An `x5c` entry is held to the same rule.
///
/// Refused as [`None`]: whitespace anywhere, the base64url alphabet,
/// omitted, partial or extra padding, anything after the padding, a length
/// no encoding has, and the empty string. Unused low bits in the last data
/// character are accepted, as Apple accepts them; that malleability matters
/// for a JWS signature segment (see [`decode_base64url_strict`]), not for a
/// receipt blob that is itself verified by a signature over its decoded
/// bytes.
///
/// The crate's default `STANDARD` engine refuses those trailing bits, so
/// this uses its own configuration of the same engine; the empty string,
/// which every engine decodes to nothing, is refused first.
#[must_use]
pub fn decode_receipt_base64(text: &[u8]) -> Option<Vec<u8>> {
    use ::base64::Engine as _;
    if text.is_empty() {
        return None;
    }
    RECEIPT_ENGINE.decode(text).ok()
}

/// Standard base64 with padding.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    use ::base64::Engine as _;
    ::base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The `base64` crate's URL-safe engine as RFC 7515 section 2 reads a JWS
/// segment: no padding at all, and a final character's unused low bits
/// must be zero (the crate's default, restated here).
const JWS_SEGMENT_ENGINE: ::base64::engine::GeneralPurpose = ::base64::engine::GeneralPurpose::new(
    &::base64::alphabet::URL_SAFE,
    ::base64::engine::GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(false)
        .with_decode_padding_mode(::base64::engine::DecodePaddingMode::RequireNone),
);

/// Decodes unpadded base64url — RFC 4648 §5 as RFC 7515 §2 requires it —
/// or `None`.
///
/// One byte sequence has exactly one encoding under this function. That
/// makes each segment's text unique for its bytes; it does not make a JWS
/// unique, since the signature's bytes have two valid values (high and
/// low S, see the module docs). Refused, where a lenient decoder would
/// accept:
///
/// - any byte outside `A-Z a-z 0-9 - _`, the standard alphabet's `+` and `/`
///   included: this is base64url, not base64;
/// - `=` anywhere at all. RFC 7515 §2 defines a JWS segment as base64url
///   "with all trailing '=' characters omitted", so a padded segment is
///   another spelling rather than another encoding, though common platform
///   decoders accept the padded form;
/// - a length that leaves one dangling character, which encodes nothing;
/// - a final character whose unused low bits are not zero.
#[must_use]
pub fn decode_base64url_strict(text: &[u8]) -> Option<Vec<u8>> {
    use ::base64::Engine as _;
    JWS_SEGMENT_ENGINE.decode(text).ok()
}

#[cfg(test)]
mod tests {
    use super::{decode_base64url_strict, decode_receipt_base64, encode};

    /// RFC 4648 §10's vectors, padded.
    #[test]
    fn encode_is_padded_standard_base64() {
        for (bytes, text) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"\xfb\xff", "+/8="),
        ] {
            assert_eq!(encode(bytes), text);
        }
    }

    /// One encoding per byte sequence: every other spelling the doc
    /// comment lists is refused.
    #[test]
    fn a_jws_segment_has_one_spelling() {
        assert_eq!(decode_base64url_strict(b"Zm9vYg"), Some(b"foob".to_vec()));
        assert_eq!(decode_base64url_strict(b"-_8"), Some(b"\xfb\xff".to_vec()));
        assert_eq!(decode_base64url_strict(b""), Some(Vec::new()));
        for refused in [
            &b"Zm9vYg=="[..], // padding
            b"Zm9vYg=",       // partial padding
            b"+/8",           // the standard alphabet
            b"Zm9vY",         // a dangling character
            b"Zm9vYh",        // unused low bits that are not zero
            b"-_9",           // the same, two bits wide
            b"Zm9v Yg",       // whitespace
            b"Zm9v\nYg",      // a newline
        ] {
            assert_eq!(decode_base64url_strict(refused), None, "{refused:?}");
        }
    }

    /// Canonical padded standard base64, trailing bits accepted, nothing
    /// else.
    #[test]
    fn receipt_data_is_canonical_standard_base64() {
        assert_eq!(decode_receipt_base64(b"Zm9vYg=="), Some(b"foob".to_vec()));
        assert_eq!(decode_receipt_base64(b"Zm9vYh=="), Some(b"foob".to_vec()));
        for refused in [
            &b""[..],
            b"Zm9vYg",       // padding omitted
            b"Zm9vYg=",      // partial padding
            b"Zm9vYg===",    // extra padding
            b"Zm9vY===",     // a length no encoding has
            b"-_8=",         // the base64url alphabet
            b"Zm9v\nYg==",   // whitespace
            b"Zm9vYg==Zg==", // anything after the padding
        ] {
            assert_eq!(decode_receipt_base64(refused), None, "{refused:?}");
        }
    }
}
