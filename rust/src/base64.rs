//! Base64, in the three shapes this crate needs.
//!
//! There are two decoders, and which one a caller gets is a security
//! decision rather than a convenience.
//!
//! [`decode_lenient`] skips everything outside both alphabets. That is what
//! the *container* formats need — a PEM body carrying line breaks, an `x5c`
//! entry, the whitespace a real `receipt-data` blob arrives with — and it
//! matches Java's MIME decoder and Swift's `.ignoreUnknownCharacters`, which
//! is what those ports use for exactly the same inputs.
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
