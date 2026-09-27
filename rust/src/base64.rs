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
//! Strictness here goes one step past common platform decoders, which
//! accept a final character whose
//! unused low bits are not zero: an ES256 signature is 86 base64 characters
//! carrying 516 bits for 512 bits of signature, so those four bits are four
//! more bits of malleability, and 16 spellings of one signature all verified
//! before this decoder existed. No encoder produces them; they are only ever
//! hand-made.

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
/// alphabets (whitespace, padding, PEM line breaks). No engine of the
/// `base64` crate skips characters, so this one stays hand-written.
#[must_use]
pub fn decode_lenient(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 3);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for byte in text.as_bytes() {
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
/// One byte sequence has exactly one encoding under this function, which is
/// the property the JWS path needs. Refused, where [`decode_lenient`] would
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
pub fn decode_base64url_strict(text: &str) -> Option<Vec<u8>> {
    use ::base64::Engine as _;
    JWS_SEGMENT_ENGINE.decode(text).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    //! The engines replaced two hand-written routines; these are those
    //! routines, kept as the oracle the engines must match byte for byte.
    use super::{decode_base64url_strict, encode};

    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn old_encode(bytes: &[u8]) -> String {
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
            for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
                if i <= chunk.len() {
                    out.push(char::from(ALPHABET[((n >> shift) & 0x3f) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn old_strict(text: &str) -> Option<Vec<u8>> {
        let body = text.as_bytes();
        if body.len() % 4 == 1 {
            return None;
        }
        let mut out = Vec::new();
        let (mut accumulator, mut bits) = (0u32, 0u32);
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
                out.push(((accumulator >> bits) & 0xff) as u8);
            }
        }
        if bits > 0 && accumulator & ((1 << bits) - 1) != 0 {
            return None;
        }
        Some(out)
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn the_engines_match_the_hand_written_routines() {
        let symbols = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+/= \n";
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..200_000 {
            let length = (rng.next() % 24) as usize;
            let text: String = (0..length)
                .map(|_| {
                    // Mostly the URL alphabet, sometimes anything else.
                    let pick = rng.next();
                    let index = if pick % 8 == 0 {
                        pick % symbols.len() as u64
                    } else {
                        pick % 64
                    };
                    char::from(symbols[index as usize])
                })
                .collect();
            assert_eq!(
                decode_base64url_strict(&text),
                old_strict(&text),
                "{text:?}"
            );
            let bytes: Vec<u8> = (0..length).map(|_| rng.next() as u8).collect();
            assert_eq!(encode(&bytes), old_encode(&bytes), "{bytes:?}");
        }
    }
}
