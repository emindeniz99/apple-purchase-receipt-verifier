//! Base64, in the three shapes this crate needs.
//!
//! There are three decoders, and which one a caller gets is a security
//! decision rather than a convenience.
//!
//! [`decode_lenient`] skips everything outside both alphabets. That is what
//! a PEM body carrying line breaks needs.
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
//! verify to the same transaction, which defeats any integrator who dedupes
//! notifications or one-shot redemptions on the JWS string or its hash. The
//! signature segment is the exposed one — the header and payload segments
//! are covered by the signing input — and it is not covered by the
//! signature at all.
//!
//! Strictness here goes one step past Java's `Base64.getUrlDecoder()` and
//! Swift's `Data(base64Encoded:)`, which both accept a final character whose
//! unused low bits are not zero: an ES256 signature is 86 base64 characters
//! carrying 516 bits for 512 bits of signature, so those four bits are four
//! more bits of malleability, and 16 spellings of one signature all verified
//! before this decoder existed. No encoder produces them; they are only ever
//! hand-made.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn value_of(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Decodes base64 or base64url, skipping every character outside both
/// alphabets (whitespace, padding, PEM line breaks).
#[must_use]
pub fn decode_lenient(text: &str) -> Vec<u8> {
    decode_lenient_bytes(text.as_bytes())
}

/// [`decode_lenient`] over raw bytes.
#[must_use]
pub fn decode_lenient_bytes(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 3);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for byte in text {
        let Some(value) = value_of(*byte) else {
            continue;
        };
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((accumulator >> bits) & 0xff).unwrap_or(0));
        }
    }
    out
}

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
pub fn decode_receipt_base64(text: &str) -> Option<Vec<u8>> {
    use ::base64::Engine as _;
    if text.is_empty() {
        return None;
    }
    RECEIPT_ENGINE.decode(text).ok()
}

/// Standard base64 with padding.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut chunks = bytes.chunks_exact(3);
    for chunk in &mut chunks {
        let (a, b, c) = (
            u32::from(*chunk.first().unwrap_or(&0)),
            u32::from(*chunk.get(1).unwrap_or(&0)),
            u32::from(*chunk.get(2).unwrap_or(&0)),
        );
        let n = (a << 16) | (b << 8) | c;
        for shift in [18, 12, 6, 0] {
            let index = usize::try_from((n >> shift) & 0x3f).unwrap_or(0);
            out.push(char::from(*ALPHABET.get(index).unwrap_or(&b'A')));
        }
    }
    let rest = chunks.remainder();
    let push = |out: &mut String, value: u32| {
        let index = usize::try_from(value & 0x3f).unwrap_or(0);
        out.push(char::from(*ALPHABET.get(index).unwrap_or(&b'A')));
    };
    match rest.len() {
        1 => {
            let a = u32::from(*rest.first().unwrap_or(&0));
            push(&mut out, a >> 2);
            push(&mut out, a << 4);
            out.push_str("==");
        }
        2 => {
            let a = u32::from(*rest.first().unwrap_or(&0));
            let b = u32::from(*rest.get(1).unwrap_or(&0));
            push(&mut out, a >> 2);
            push(&mut out, (a << 4) | (b >> 4));
            push(&mut out, b << 2);
            out.push('=');
        }
        _ => {}
    }
    out
}

/// Decodes unpadded base64url — RFC 4648 §5 as RFC 7515 §2 requires it —
/// or `None`.
///
/// One byte sequence has exactly one encoding under this function, which is
/// the property the JWS path needs. Refused, where [`decode_lenient`] would
/// accept:
///
/// - any byte outside `A-Z a-z 0-9 - _`, the standard alphabet's `+` and `/`
///   included: this is base64url, not base64;
/// - `=` anywhere at all. RFC 7515 §2 defines a JWS segment as base64url
///   "with all trailing '=' characters omitted", so a padded segment is
///   another spelling rather than another encoding. Java's
///   `Base64.getUrlDecoder()` and Swift's `Data(base64Encoded:)` both accept
///   the padded form;
/// - a length that leaves one dangling character, which encodes nothing;
/// - a final character whose unused low bits are not zero.
#[must_use]
pub fn decode_base64url_strict(text: &str) -> Option<Vec<u8>> {
    let body = text.as_bytes();
    if body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() / 4 * 3 + 2);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for byte in body {
        let value = match byte {
            b'A'..=b'Z' => u32::from(*byte - b'A'),
            b'a'..=b'z' => u32::from(*byte - b'a') + 26,
            b'0'..=b'9' => u32::from(*byte - b'0') + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((accumulator >> bits) & 0xff).ok()?);
        }
    }
    // The leftover bits are padding, and canonical padding is zero.
    if bits > 0 && accumulator & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod receipt_base64_tests {
    use super::decode_receipt_base64;

    /// Every spelling Apple decoded on 2026-09-23 decodes here to the same
    /// bytes, including a last data character with its unused bits set.
    #[test]
    fn canonical_spellings_and_trailing_bits_decode() {
        for (text, expected) in [
            ("QUJD", b"ABC".to_vec()),
            ("QUI=", b"AB".to_vec()),
            ("QQ==", b"A".to_vec()),
            ("+/8=", vec![0xfb, 0xff]),
            ("QR==", b"A".to_vec()),
            ("Qf==", b"A".to_vec()),
            ("QUJ=", b"AB".to_vec()),
        ] {
            assert_eq!(decode_receipt_base64(text), Some(expected), "{text:?}");
        }
    }

    /// Every spelling Apple answered 21002 is refused here, or a receipt
    /// would verify in Rust that Apple itself refuses.
    #[test]
    fn every_other_spelling_is_refused() {
        for text in [
            "",
            "QQ",
            "QUI",
            "QQ=",
            "QQ===",
            "QQ====",
            "QUJD=",
            "QUJD==",
            "QUJD====",
            "====",
            "Q===",
            "QUJDR",
            "QQ==QUJD",
            "QQ==!!!!",
            "QQ=A",
            "QU!D",
            "QUJD\n",
            "QUJD\r\n",
            "QUJD\nQUJD",
            " QUJD",
            "QU JD",
            "QU\tJD",
            "  QUJD  ",
            "-_8=",
            "-_8",
            "+_8=",
            "QUJ\u{e9}",
        ] {
            assert_eq!(decode_receipt_base64(text), None, "{text:?}");
        }
    }
}
