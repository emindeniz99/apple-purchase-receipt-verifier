//! Base64, in the three shapes this crate needs.
//!
//! There are three decoders, and which one a caller gets is a security
//! decision rather than a convenience.
//!
//! [`decode_lenient`] skips everything outside both alphabets. That is what
//! the *container* formats need — a PEM body carrying line breaks, an `x5c`
//! entry — and it matches Java's MIME decoder and Swift's
//! `.ignoreUnknownCharacters`, which is what those ports use for exactly the
//! same inputs.
//!
//! [`decode_receipt_base64`] is what `receipt-data` — the base64 string a
//! client actually sends — is decoded with. It is not lenient in
//! [`decode_lenient`]'s sense: a character neither alphabet defines, both
//! alphabets in one string, or anything but whitespace once padding starts
//! is a hard `None`, not a silently skipped byte. See its own docs for the
//! accepted shape.
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

/// Decodes `receipt-data` — the base64 string a client sends — exactly as
/// Apple defines it: RFC 4648, as Foundation's
/// `base64EncodedString(options:)` can emit it. Accepted: the standard
/// alphabet (`+`/`/`) or base64url (`-`/`_`), not both in the same string;
/// padding present or omitted; `CR`, `LF`, space or tab anywhere, stripped
/// before anything else is checked.
///
/// Refused as [`None`]: a character neither alphabet defines; anything but
/// whitespace once padding has started; a data length (padding excluded) of
/// `4n + 1`, which no encoding has and which padding cannot rescue; an empty
/// or whitespace-only string; a `=` count other than `0`
/// or the exact count RFC 4648 requires for the data length (no over- or
/// under-padding). There is no canonical-trailing-bits check — that
/// malleability matters for a JWS signature segment (see
/// [`decode_base64url_strict`]), not for a receipt blob that is itself
/// verified by a signature over its decoded bytes.
///
/// Unlike [`decode_lenient`], an unrecognised character is a hard failure
/// here rather than something to skip: `receipt-data` is client-controlled,
/// and the caller turns `None` into `Reason::InvalidReceiptFormat`.
#[must_use]
pub fn decode_receipt_base64(text: &str) -> Option<Vec<u8>> {
    // Fast path for the common case, a canonical standard-alphabet string.
    // Every string `decode_canonical_standard` accepts is non-empty, has
    // only `A-Z a-z 0-9 + /` before the exact `=` run RFC 4648 requires for
    // its length, and a data length not `4n + 1`. Each such string passes
    // every rule of the tolerant path (nothing to strip, one alphabet,
    // nothing after the padding, same length and padding checks), which
    // then decodes the same data to the same bytes. Anything the fast path
    // refuses falls through, so the answer for every other input is
    // unchanged. The differential test below holds this.
    decode_canonical_standard(text).or_else(|| decode_receipt_base64_tolerant(text))
}

/// Canonical standard-alphabet base64 only, or `None`, decoded by the
/// `base64` crate's `STANDARD` engine: canonical padding required, non-zero
/// trailing bits refused, no whitespace, no base64url characters. That
/// engine decodes `""` to an empty vector, which `receipt-data` must never
/// be, so the empty string is refused here first.
fn decode_canonical_standard(text: &str) -> Option<Vec<u8>> {
    use ::base64::engine::general_purpose::STANDARD;
    use ::base64::Engine as _;
    if text.is_empty() {
        return None;
    }
    STANDARD.decode(text).ok()
}

/// The full `receipt-data` decoder described on [`decode_receipt_base64`],
/// without the fast path.
fn decode_receipt_base64_tolerant(text: &str) -> Option<Vec<u8>> {
    let mut seen_std = false;
    let mut seen_url = false;
    let mut padding_started = false;
    let mut core_len: usize = 0;
    let mut body: Vec<u8> = Vec::with_capacity(text.len());
    for byte in text.bytes() {
        if matches!(byte, b'\r' | b'\n' | b' ' | b'\t') {
            continue;
        }
        core_len += 1;
        if byte == b'=' {
            padding_started = true;
            continue;
        }
        if padding_started {
            return None;
        }
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => {}
            b'+' | b'/' => seen_std = true,
            b'-' | b'_' => seen_url = true,
            _ => return None,
        }
        if seen_std && seen_url {
            return None;
        }
        body.push(byte);
    }
    // The impossible-length test is on the DATA, not the padded string:
    // "A===" is a multiple of four in total and still encodes no whole byte.
    let data = body.len();
    if data == 0 || data % 4 == 1 {
        return None;
    }
    let pad = core_len - data;
    let expected_pad = (4 - data % 4) % 4;
    if pad != 0 && pad != expected_pad {
        return None;
    }
    Some(decode_lenient_bytes(&body))
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

    /// The impossible-length test has to look at the data, not at the padded
    /// string: "A===" is a multiple of four characters in total and encodes
    /// no whole byte. A check on the padded length lets it through and then
    /// treats three '=' as a canonical run.
    #[test]
    fn an_impossible_data_length_is_not_rescued_by_padding() {
        assert_eq!(decode_receipt_base64("A==="), None);
        assert_eq!(decode_receipt_base64("QUJDQ==="), None);
        assert_eq!(decode_receipt_base64("===="), None);
        assert_eq!(decode_receipt_base64("QUJDQQ=="), Some(b"ABCA".to_vec()));
        assert_eq!(decode_receipt_base64("QUJDQQ"), Some(b"ABCA".to_vec()));
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]
mod receipt_base64_fast_path_tests {
    use super::{decode_canonical_standard, decode_receipt_base64, decode_receipt_base64_tolerant};
    use super::{encode, ALPHABET};

    /// Which way one input went, so the test can prove every branch ran.
    #[derive(Default)]
    struct Branches {
        fast: usize,
        fell_through_accepted: usize,
        rejected: usize,
    }

    /// The fast path is only allowed to answer early, never differently:
    /// for every input the public decoder must return exactly what the
    /// tolerant path alone returns, bytes on success and `None` on refusal.
    /// A fast path that accepted one string the tolerant path refuses
    /// (whitespace, mixed alphabets, under- or over-padding) or decoded it
    /// to other bytes would let the same `receipt-data` verify differently
    /// depending on which path saw it. The two sides are independent
    /// implementations — the `base64` crate against this module's own
    /// decoder — so agreement is evidence about both.
    ///
    /// The fast path is also held to its own contract, canonical input
    /// only: whatever it accepts must be exactly what [`encode`] produces
    /// for the decoded bytes. That is what keeps a looser engine (padding
    /// optional, non-zero trailing bits allowed) from quietly taking over
    /// inputs that Apple's tolerant rule is meant to judge.
    fn check(text: &str, branches: &mut Branches) {
        let tolerant = decode_receipt_base64_tolerant(text);
        let public = decode_receipt_base64(text);
        assert_eq!(public, tolerant, "input {text:?}");
        match (decode_canonical_standard(text), tolerant) {
            (Some(fast), Some(slow)) => {
                assert_eq!(fast, slow, "input {text:?}");
                assert_eq!(
                    encode(&fast),
                    text,
                    "the fast path accepted a non-canonical spelling"
                );
                branches.fast += 1;
            }
            (Some(_), None) => {
                panic!("the fast path accepted what the tolerant path refuses: {text:?}")
            }
            (None, Some(_)) => branches.fell_through_accepted += 1,
            (None, None) => branches.rejected += 1,
        }
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            // xorshift64*: deterministic, so a failure names a reproducible input.
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, bound: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(bound).unwrap()).unwrap()
        }
    }

    /// A string near the canonical shape: a real encoding, then zero to
    /// three edits that each break one rule the fast path relies on.
    fn near_canonical(rng: &mut Rng) -> String {
        let length = rng.below(40);
        let bytes: Vec<u8> = (0..length).map(|_| rng.next().to_le_bytes()[0]).collect();
        let mut text: Vec<u8> = encode(&bytes).into_bytes();
        for _ in 0..rng.below(4) {
            let edit = rng.below(9);
            let at = if text.is_empty() {
                0
            } else {
                rng.below(text.len() + 1)
            };
            match edit {
                0 => text.retain(|b| *b != b'='),
                1 => text.push(b'='),
                2 => text.insert(at, b" \r\n\t"[rng.below(4)]),
                3 => text.insert(at, b"-_"[rng.below(2)]),
                4 => text.insert(at, b"!.*\0"[rng.below(4)]),
                5 => {
                    text.pop();
                }
                6 => text.push(ALPHABET[rng.below(64)]),
                7 if !text.is_empty() => {
                    let index = rng.below(text.len());
                    text[index] = ALPHABET[rng.below(64)];
                }
                _ => text.insert(at, b'='),
            }
        }
        String::from_utf8(text).unwrap()
    }

    /// A string drawn from every character either path treats specially.
    fn noise(rng: &mut Rng) -> String {
        const CHARS: &[u8] = b"AQgw+/-_= \r\n\t!Zz09";
        (0..rng.below(12))
            .map(|_| char::from(CHARS[rng.below(CHARS.len())]))
            .collect()
    }

    #[test]
    fn the_fast_path_answers_exactly_what_the_tolerant_path_answers() {
        let mut branches = Branches::default();
        for edge in [
            "",
            " ",
            "\r\n",
            "=",
            "==",
            "===",
            "A",
            "A=",
            "A==",
            "A===",
            "AA",
            "AA=",
            "AA==",
            "AA===",
            "AAA",
            "AAA=",
            "AAA==",
            "AAAA",
            "AAAA=",
            "AAAA====",
            "QUJD",
            "QUJDQQ",
            "QUJDQQ==",
            "QUJDQQ=",
            "QUJDQQ===",
            "QUJ=DQQ=",
            "QUJDQQ==A",
            "QUJDQQ== ",
            " QUJDQQ==",
            "QUJ\nDQQ==",
            "QU-DQQ==",
            "QU+/QQ==",
            "QU+_QQ==",
            "////",
            "____",
            "++++",
            "AB/=",
            "AB==",
            "ABC=",
            "AB+/",
            "ABc\u{e9}",
            "\u{e9}\u{e9}\u{e9}\u{e9}",
        ] {
            check(edge, &mut branches);
        }
        let mut rng = Rng(0x5EED_0FBA_5E64);
        for index in 0..24_000 {
            let text = if index % 4 == 3 {
                noise(&mut rng)
            } else {
                near_canonical(&mut rng)
            };
            check(&text, &mut branches);
        }
        // A differential test that never reached one side proves nothing
        // about it.
        assert!(
            branches.fast > 1_000,
            "fast path hit {} times",
            branches.fast
        );
        assert!(
            branches.fell_through_accepted > 1_000,
            "tolerant-only acceptances: {}",
            branches.fell_through_accepted
        );
        assert!(
            branches.rejected > 1_000,
            "rejections: {}",
            branches.rejected
        );
    }
}
