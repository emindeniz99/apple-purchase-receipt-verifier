//! A bounded BER/DER reader — just enough ASN.1 to walk X.509 certificates,
//! CMS `SignedData` and Apple receipt payloads.
//!
//! Hand-rolled on purpose. Every byte this module sees is attacker-supplied,
//! so the bounds are part of the design rather than a configuration:
//!
//! - nesting depth is capped at [`MAX_DEPTH`], so no input can recurse the
//!   parser off the stack;
//! - the total number of decoded nodes is capped at [`MAX_NODES`];
//! - multi-byte tags are refused, and a length is at most four octets;
//! - indefinite (BER) lengths are accepted only on constructed values,
//!   because genuine Apple and Xcode receipts use them;
//! - [`parse_exact`] refuses trailing bytes after the outer value.
//!
//! Every value keeps a slice of the *input*: `full` is the exact TLV that
//! was consumed and `contents` the value octets inside it. Nothing is
//! re-encoded, so a signature is always checked over the bytes that were
//! parsed rather than over a normalised view of them.

use std::borrow::Cow;

/// Maximum ASN.1 nesting depth.
pub const MAX_DEPTH: usize = 32;

/// Maximum number of decoded nodes in one parse.
pub const MAX_NODES: usize = 100_000;

/// Universal tags this crate names.
pub mod tag {
    /// `BOOLEAN`
    pub const BOOLEAN: u8 = 0x01;
    /// `INTEGER`
    pub const INTEGER: u8 = 0x02;
    /// `BIT STRING`
    pub const BIT_STRING: u8 = 0x03;
    /// `OCTET STRING`, primitive form
    pub const OCTET_STRING: u8 = 0x04;
    /// `OCTET STRING`, constructed (BER) form
    pub const OCTET_STRING_CONSTRUCTED: u8 = 0x24;
    /// `OBJECT IDENTIFIER`
    pub const OID: u8 = 0x06;
    /// `UTF8String`
    pub const UTF8_STRING: u8 = 0x0c;
    /// `SEQUENCE`
    pub const SEQUENCE: u8 = 0x30;
    /// `SET`
    pub const SET: u8 = 0x31;
    /// `IA5String`
    pub const IA5_STRING: u8 = 0x16;
    /// `UTCTime`
    pub const UTC_TIME: u8 = 0x17;
    /// `GeneralizedTime`
    pub const GENERALIZED_TIME: u8 = 0x18;
    /// `[0]` constructed
    pub const CONTEXT_0: u8 = 0xa0;
    /// `[1]` constructed
    pub const CONTEXT_1: u8 = 0xa1;
    /// `[2]` constructed
    pub const CONTEXT_2: u8 = 0xa2;
    /// `[3]` constructed
    pub const CONTEXT_3: u8 = 0xa3;
}

/// Why a parse failed. Detail only; every caller maps this onto a
/// [`Reason`](crate::Reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asn1Error(pub(crate) &'static str);

impl core::fmt::Display for Asn1Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Asn1Error {}

/// One decoded ASN.1 value.
#[derive(Debug, Clone)]
pub struct Tlv<'a> {
    /// The full identifier octet (e.g. `0x30` for `SEQUENCE`).
    pub tag: u8,
    /// Whether the constructed bit is set.
    pub constructed: bool,
    /// The complete TLV as it appears in the input.
    pub full: &'a [u8],
    /// The value octets.
    pub contents: &'a [u8],
    /// Decoded children, for a constructed value.
    pub children: Option<Vec<Tlv<'a>>>,
}

impl<'a> Tlv<'a> {
    /// The decoded children, or an empty slice for a primitive value.
    #[must_use]
    pub fn children(&self) -> &[Tlv<'a>] {
        match &self.children {
            Some(children) => children.as_slice(),
            None => &[],
        }
    }

    /// The `n`th child, if there is one.
    #[must_use]
    pub fn child(&self, n: usize) -> Option<&Tlv<'a>> {
        self.children().get(n)
    }

    /// Whether this is an `OCTET STRING` in either encoding.
    #[must_use]
    pub fn is_octet_string(&self) -> bool {
        self.tag == tag::OCTET_STRING || self.tag == tag::OCTET_STRING_CONSTRUCTED
    }

    /// The value bytes of an `OCTET STRING`, joining BER constructed chunks,
    /// or `None` when this value is not one.
    ///
    /// A constructed `OCTET STRING` may contain only `OCTET STRING`s
    /// (X.690 §8.21), and a child of any other tag makes this `None` rather
    /// than being read for its content octets. The looser reading — join
    /// whatever children are there — let the CMS `eContent` of a genuine,
    /// correctly signed receipt be re-encoded as, say,
    /// `24 L { 0C L1 <first half>, 02 L2 <second half> }` without changing
    /// the bytes the RSA signature covers, so one receipt had many accepted
    /// spellings. Node's `der.ts` still joins unconditionally.
    ///
    /// Re-chunking into *legal* `OCTET STRING` children remains possible and
    /// is inherent to BER, which genuine Xcode and `BouncyCastle` receipts
    /// use; see the malleability note in the crate README. This is why a
    /// verified receipt blob is not an identifier.
    #[must_use]
    pub fn octet_string_value(&self) -> Option<Cow<'a, [u8]>> {
        if !self.is_octet_string() {
            return None;
        }
        if !self.constructed {
            return Some(Cow::Borrowed(self.contents));
        }
        let mut out = Vec::new();
        for child in self.children() {
            out.extend_from_slice(&child.octet_string_value()?);
        }
        Some(Cow::Owned(out))
    }
}

struct Budget {
    nodes: usize,
}

/// Parses exactly one value, refusing any trailing bytes.
///
/// Trailing garbage after a CMS blob is a documented rejection
/// (`PLAN.md` §2.3): accepting it would let an attacker append bytes to a
/// genuine receipt and have it still verify.
///
/// # Errors
/// [`Asn1Error`] when the input is not one well-formed value within this
/// module's bounds, or when anything follows it.
pub fn parse_exact(input: &[u8]) -> Result<Tlv<'_>, Asn1Error> {
    let mut budget = Budget { nodes: MAX_NODES };
    let (node, end) = read_node(input, 0, 0, &mut budget)?;
    if end != input.len() {
        return Err(Asn1Error("trailing bytes after ASN.1 value"));
    }
    Ok(node)
}

#[allow(clippy::too_many_lines)]
fn read_node<'a>(
    input: &'a [u8],
    offset: usize,
    depth: usize,
    budget: &mut Budget,
) -> Result<(Tlv<'a>, usize), Asn1Error> {
    if depth > MAX_DEPTH {
        return Err(Asn1Error("maximum ASN.1 nesting depth exceeded"));
    }
    if budget.nodes == 0 {
        return Err(Asn1Error("ASN.1 node budget exceeded"));
    }
    budget.nodes -= 1;

    let tag = *input
        .get(offset)
        .ok_or(Asn1Error("truncated ASN.1 value"))?;
    if tag & 0x1f == 0x1f {
        return Err(Asn1Error("multi-byte ASN.1 tags are not supported"));
    }
    let constructed = tag & 0x20 != 0;
    let mut position = offset + 1;
    let length_byte = *input
        .get(position)
        .ok_or(Asn1Error("truncated ASN.1 value"))?;
    position += 1;

    #[allow(clippy::comparison_chain)]
    let length: Option<usize> = if length_byte < 0x80 {
        Some(usize::from(length_byte))
    } else if length_byte == 0x80 {
        if !constructed {
            return Err(Asn1Error("indefinite length on a primitive value"));
        }
        None
    } else {
        let count = usize::from(length_byte & 0x7f);
        if count > 4 {
            return Err(Asn1Error("unsupported ASN.1 length"));
        }
        let octets = input
            .get(position..position + count)
            .ok_or(Asn1Error("unsupported ASN.1 length"))?;
        let mut value: usize = 0;
        for octet in octets {
            value = value * 256 + usize::from(*octet);
        }
        position += count;
        Some(value)
    };

    if let Some(length) = length {
        let end = position
            .checked_add(length)
            .ok_or(Asn1Error("ASN.1 length exceeds input"))?;
        if end > input.len() {
            return Err(Asn1Error("ASN.1 length exceeds input"));
        }
        let full = input
            .get(offset..end)
            .ok_or(Asn1Error("ASN.1 length exceeds input"))?;
        let contents = input
            .get(position..end)
            .ok_or(Asn1Error("ASN.1 length exceeds input"))?;
        let children = if constructed {
            Some(read_children(contents, depth + 1, budget)?)
        } else {
            None
        };
        return Ok((
            Tlv {
                tag,
                constructed,
                full,
                contents,
                children,
            },
            end,
        ));
    }

    // Indefinite length: children until an end-of-contents (00 00) marker.
    let contents_start = position;
    let mut children = Vec::new();
    loop {
        if position + 2 > input.len() {
            return Err(Asn1Error("unterminated indefinite-length value"));
        }
        if input.get(position) == Some(&0x00) && input.get(position + 1) == Some(&0x00) {
            break;
        }
        let (child, next) = read_node(input, position, depth + 1, budget)?;
        children.push(child);
        position = next;
    }
    // The children are contiguous, so the region between the length octet
    // and the end-of-contents marker is exactly their concatenation — no
    // re-encoding, no allocation.
    let contents = input
        .get(contents_start..position)
        .ok_or(Asn1Error("unterminated indefinite-length value"))?;
    let end = position + 2;
    let full = input
        .get(offset..end)
        .ok_or(Asn1Error("unterminated indefinite-length value"))?;
    Ok((
        Tlv {
            tag,
            constructed: true,
            full,
            contents,
            children: Some(children),
        },
        end,
    ))
}

fn read_children<'a>(
    contents: &'a [u8],
    depth: usize,
    budget: &mut Budget,
) -> Result<Vec<Tlv<'a>>, Asn1Error> {
    let mut children = Vec::new();
    let mut position = 0;
    while position < contents.len() {
        let (child, next) = read_node(contents, position, depth, budget)?;
        children.push(child);
        position = next;
    }
    Ok(children)
}

/// The DER content octets of a dotted `OBJECT IDENTIFIER`.
///
/// `None` for anything that is not a well-formed OID. This crate only calls
/// it on its own constants, but it is total for the same reason everything
/// else here is: a value it cannot represent is refused, never approximated.
#[must_use]
pub fn encode_oid(oid: &str) -> Option<Vec<u8>> {
    let mut arcs = oid.split('.').map(|part| part.parse::<u64>().ok());
    let first = arcs.next()??;
    let second = arcs.next()??;
    if first > 2 || (first < 2 && second >= 40) {
        return None;
    }
    let mut out = Vec::new();
    push_base128(&mut out, first.checked_mul(40)?.checked_add(second)?);
    for arc in arcs {
        push_base128(&mut out, arc?);
    }
    Some(out)
}

fn push_base128(out: &mut Vec<u8>, value: u64) {
    let mut chunk = Vec::new();
    let mut remaining = value;
    loop {
        chunk.insert(0, u8::try_from(remaining & 0x7f).unwrap_or(0));
        remaining >>= 7;
        if remaining == 0 {
            break;
        }
    }
    let last = chunk.len().saturating_sub(1);
    for (index, byte) in chunk.iter().enumerate() {
        out.push(if index == last { *byte } else { *byte | 0x80 });
    }
}

/// The dotted form of `OBJECT IDENTIFIER` content octets.
///
/// `None` for content octets this crate cannot represent — an empty value, a
/// truncated subidentifier, or one wider than 64 bits.
#[must_use]
pub fn decode_oid(contents: &[u8]) -> Option<String> {
    let mut arcs: Vec<u64> = Vec::new();
    let mut value: u64 = 0;
    let mut started = false;
    for byte in contents {
        value = value
            .checked_mul(128)?
            .checked_add(u64::from(byte & 0x7f))?;
        started = true;
        if byte & 0x80 == 0 {
            arcs.push(value);
            value = 0;
            started = false;
        }
    }
    if started || arcs.is_empty() {
        return None;
    }
    let first = *arcs.first()?;
    let (a, b) = if first < 40 {
        (0, first)
    } else if first < 80 {
        (1, first - 40)
    } else {
        (2, first - 80)
    };
    let mut parts = vec![a.to_string(), b.to_string()];
    for arc in arcs.get(1..)? {
        parts.push(arc.to_string());
    }
    Some(parts.join("."))
}
