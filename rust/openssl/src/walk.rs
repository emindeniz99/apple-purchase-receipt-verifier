//! The header walk: OpenSSL's TLV header decoder, `ASN1_get_object`, run
//! over raw BER before any value is decoded. It reads tags and lengths and
//! nothing else: no value is decoded, allocated or copied. This file is the
//! only one in the adapter that calls `ASN1_get_object`, and the core calls
//! it nowhere (`tools/check-layering.mjs`, rule 6).
//!
//! It answers what OpenSSL's decoders do not: how deep constructed values
//! nest and how many values there are before `d2i_CMS_ContentInfo` or a
//! template decode builds any of them (0.7's bounds), whether the chunks of
//! a constructed `OCTET STRING` are all `OCTET STRING`s (X.690 section
//! 8.7.3; OpenSSL joins chunks of any tag), and, for the receipt payload,
//! which header forms 0.7's reader refused.

use crate::{drain_errors, sys};
use libc::{c_int, c_long};
use openssl_sys as ffi;

/// How far one walk may go: constructed values nested inside one another,
/// the outermost one counted as 1, and values in all, primitive ones
/// included. The values inside a primitive value's content are not values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// The deepest nesting of constructed values allowed.
    pub depth: usize,
    /// The most values allowed.
    pub nodes: usize,
}

/// Which header forms a walk accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Headers {
    /// Everything `ASN1_get_object` reads: BER.
    Ber,
    /// BER without a tag in high-tag-number form or a length of more than
    /// four octets, the forms 0.7's reader refused. A tag below 31 written
    /// in high-tag form and a length with leading zero octets are not DER,
    /// and OpenSSL reads both.
    Short,
}

/// Why a walk stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalkError {
    /// A header OpenSSL does not read, a length past the end of its
    /// container, a form [`Headers`] refuses, or a missing end-of-contents.
    Malformed,
    /// Bytes follow the value.
    Trailing,
    /// Constructed values nest deeper than [`Budget::depth`].
    TooDeep,
    /// More values than [`Budget::nodes`].
    TooManyNodes,
}

/// One TLV header, as `ASN1_get_object` reads it.
pub(crate) struct Header {
    pub(crate) tag: c_int,
    pub(crate) class: c_int,
    pub(crate) constructed: bool,
    pub(crate) indefinite: bool,
    /// Octets of the identifier and the length.
    pub(crate) head: usize,
    /// Octets of the content; 0 for an indefinite length.
    pub(crate) content: usize,
    /// The identifier uses the high-tag-number form (its low five bits are
    /// all set).
    pub(crate) high_tag_form: bool,
}

impl Header {
    /// Whether the header is one [`Headers::Short`] refuses.
    pub(crate) fn is_long_form(&self) -> bool {
        // With a one-octet identifier, the head is the identifier, the
        // initial length octet and the long-form length octets after it.
        self.high_tag_form || self.head > 2 + 4
    }

    /// The octets of the whole value, for a definite length.
    fn definite_size(&self) -> usize {
        self.head + self.content
    }
}

/// The header of the TLV at the start of `input`, whose definite content
/// must lie within `input`.
pub(crate) fn header(input: &[u8]) -> Option<Header> {
    crate::init();
    let first = *input.first()?;
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
        high_tag_form: first & 0x1f == 0x1f,
    })
}

/// Walks the one value `input` must be, within `budget`, with nothing after
/// it.
pub(crate) fn walk_exact(input: &[u8], budget: Budget, headers: Headers) -> Result<(), WalkError> {
    let mut walker = Walker {
        nodes_left: budget.nodes,
        max_depth: budget.depth,
        headers,
    };
    let size = walker.value(input, 0)?;
    if size == input.len() {
        Ok(())
    } else {
        Err(WalkError::Trailing)
    }
}

struct Walker {
    nodes_left: usize,
    max_depth: usize,
    headers: Headers,
}

impl Walker {
    /// The encoded size of the value at the start of `input`, which sits
    /// inside `depth` constructed values. Recursion is bounded by the depth
    /// budget, and every value consumes at least two octets.
    fn value(&mut self, input: &[u8], depth: usize) -> Result<usize, WalkError> {
        if self.nodes_left == 0 {
            return Err(WalkError::TooManyNodes);
        }
        self.nodes_left -= 1;
        let header = header(input).ok_or(WalkError::Malformed)?;
        if self.headers == Headers::Short && header.is_long_form() {
            return Err(WalkError::Malformed);
        }
        if !header.constructed {
            return Ok(header.definite_size());
        }
        // A constructed value here is number `depth + 1`.
        if depth >= self.max_depth {
            return Err(WalkError::TooDeep);
        }
        let mut at = header.head;
        if header.indefinite {
            loop {
                let rest = input.get(at..).ok_or(WalkError::Malformed)?;
                if rest.starts_with(&[0, 0]) {
                    return Ok(at + 2);
                }
                at += self.value(rest, depth + 1)?;
            }
        }
        let end = header.definite_size();
        while at < end {
            at += self.value(input.get(at..end).ok_or(WalkError::Malformed)?, depth + 1)?;
        }
        Ok(end)
    }
}

/// The encoded size of the value at the start of `input`, which a walk has
/// already accepted; `None` when it is not one value.
fn size_of_value(input: &[u8]) -> Option<usize> {
    let mut walker = Walker {
        nodes_left: usize::MAX,
        // Deeper than any bound a caller walks with, so a value a walk
        // accepted is measured; the recursion stays bounded.
        max_depth: 256,
        headers: Headers::Ber,
    };
    walker.value(input, 0).ok()
}

/// The values inside the constructed value at the start of `input`, each as
/// its whole encoding, in order. `None` when `input` does not start with a
/// constructed value, or one of them is not a value. Meant for input a walk
/// has accepted: an indefinite-length child is measured by walking it.
pub(crate) fn children(input: &[u8]) -> Option<Vec<&[u8]>> {
    let outer = header(input)?;
    if !outer.constructed {
        return None;
    }
    let body = if outer.indefinite {
        input.get(outer.head..)?
    } else {
        input.get(outer.head..outer.definite_size())?
    };
    let mut at = 0;
    let mut found = Vec::new();
    while at < body.len() {
        let rest = body.get(at..)?;
        if outer.indefinite && rest.starts_with(&[0, 0]) {
            return Some(found);
        }
        let size = size_of_value(rest)?;
        found.push(rest.get(..size)?);
        at += size;
    }
    (!outer.indefinite).then_some(found)
}

/// OpenSSL's nesting bound for the chunks of a constructed string
/// (`ASN1_MAX_STRING_NEST`, `tasn_dec.c`): its `asn1_collect` reads the
/// outer string at level 0 and refuses a constructed chunk found at level
/// 5, so six constructed levels decode and a seventh does not.
pub(crate) const MAX_STRING_NEST: usize = 5;

/// Why the chunks of a constructed `OCTET STRING` are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChunkError {
    /// A chunk, at some depth, is not a universal `OCTET STRING`, or the
    /// value is not one.
    Foreign,
    /// Constructed chunks nest past what OpenSSL decodes.
    TooDeep,
    /// Not one well-formed value.
    Malformed,
}

/// Whether the value that is all of `input` is an `OCTET STRING` whose
/// chunks, at every depth, are `OCTET STRING`s, within OpenSSL's own
/// nesting bound.
pub(crate) fn octet_string_exact(input: &[u8]) -> Result<(), ChunkError> {
    let size = octet_string(input, 0)?;
    if size == input.len() {
        Ok(())
    } else {
        Err(ChunkError::Malformed)
    }
}

/// The encoded size of the `OCTET STRING` at the start of `input`, when its
/// chunks at every depth are `OCTET STRING`s. `level` counts the constructed
/// strings around this one. Every chunk consumes at least two octets, so
/// the walk is bounded by the input's length, and its depth by
/// [`MAX_STRING_NEST`].
pub(crate) fn octet_string(input: &[u8], level: usize) -> Result<usize, ChunkError> {
    let string = header(input).ok_or(ChunkError::Malformed)?;
    if string.tag != ffi::V_ASN1_OCTET_STRING || string.class != sys::V_ASN1_UNIVERSAL {
        return Err(ChunkError::Foreign);
    }
    if !string.constructed {
        return Ok(string.definite_size());
    }
    if level > MAX_STRING_NEST {
        return Err(ChunkError::TooDeep);
    }
    let mut at = string.head;
    if string.indefinite {
        loop {
            let rest = input.get(at..).ok_or(ChunkError::Malformed)?;
            if rest.starts_with(&[0, 0]) {
                return Ok(at + 2);
            }
            at += octet_string(rest, level + 1)?;
        }
    }
    let end = string.definite_size();
    while at < end {
        at += octet_string(input.get(at..end).ok_or(ChunkError::Malformed)?, level + 1)?;
    }
    Ok(end)
}
