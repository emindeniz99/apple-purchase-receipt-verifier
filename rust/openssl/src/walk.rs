//! The header walk: OpenSSL's TLV header decoder, `ASN1_get_object`, run
//! over raw BER before any value is decoded. It reads tags and lengths and
//! nothing else: no value is decoded, allocated or copied. This file is the
//! only one in the adapter that calls `ASN1_get_object`, and the core calls
//! it nowhere (`tools/check-layering.mjs`, rule 6).
//!
//! It answers what OpenSSL's decoders do not: how deep constructed values
//! nest and how many values there are before `d2i_CMS_ContentInfo` or a
//! template decode builds any of them (0.7's bounds). The grammar is
//! OpenSSL's: the walk refuses only a header `ASN1_get_object` does not
//! read, a length past the end of its container, a missing end-of-contents
//! and bytes after the value. It also hands each constructed string, at its
//! outermost level, to OpenSSL's `ANY` decoder ([`decodes_as_any`]), so
//! OpenSSL's own bound on the levels of a string (`ASN1_MAX_STRING_NEST`)
//! applies at any depth, also inside a SEQUENCE OpenSSL keeps whole.

use crate::item::decodes_as_any;
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

/// Why a walk stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalkError {
    /// A header OpenSSL does not read, a length past the end of its
    /// container, a missing end-of-contents, or a constructed string
    /// OpenSSL's `ANY` decoder refuses.
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
}

/// The header of the TLV at the start of `input`, whose definite content
/// must lie within `input`.
pub(crate) fn header(input: &[u8]) -> Option<Header> {
    crate::init();
    if input.is_empty() {
        return None;
    }
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

/// A constructed value the walk is inside.
struct Open {
    /// Where its encoding starts.
    start: usize,
    /// Where its content ends; `None` for an indefinite length.
    end: Option<usize>,
    /// How far its children may reach: its own end, or for an indefinite
    /// length the reach of the value around it.
    reach: usize,
    /// It is the outermost level of a string OpenSSL joins, checked whole
    /// once its end is known.
    string: bool,
    /// It is, or is inside, such a string.
    in_string: bool,
}

/// Walks the one value `input` must be, within `budget`, with nothing after
/// it. Iterative: the values it is inside sit on a stack no deeper than
/// `budget.depth`, and every value consumes at least two octets.
pub(crate) fn walk_exact(input: &[u8], budget: Budget) -> Result<(), WalkError> {
    let mut open: Vec<Open> = Vec::new();
    let (mut at, mut nodes) = (0, 0);
    loop {
        if nodes == budget.nodes {
            return Err(WalkError::TooManyNodes);
        }
        nodes += 1;
        let reach = open.last().map_or(input.len(), |outer| outer.reach);
        let rest = input.get(at..reach).ok_or(WalkError::Malformed)?;
        let header = header(rest).ok_or(WalkError::Malformed)?;
        if header.constructed {
            if open.len() >= budget.depth {
                return Err(WalkError::TooDeep);
            }
            // OpenSSL's `ANY` decoder joins the chunks of a universal
            // constructed value other than a SEQUENCE or a SET.
            let in_string = open.last().is_some_and(|outer| outer.in_string);
            let string = !in_string
                && header.class == sys::V_ASN1_UNIVERSAL
                && header.tag != ffi::V_ASN1_SEQUENCE
                && header.tag != ffi::V_ASN1_SET;
            let end = (!header.indefinite).then_some(at + header.head + header.content);
            open.push(Open {
                start: at,
                end,
                reach: end.unwrap_or(reach),
                string,
                in_string: in_string || string,
            });
            at += header.head;
        } else {
            at += header.head + header.content;
        }
        // Close every value that ends here: a definite length at its end,
        // an indefinite one at its end-of-contents.
        while let Some(top) = open.last() {
            let ends = match top.end {
                Some(end) => at == end,
                None => input
                    .get(at..top.reach)
                    .is_some_and(|rest| rest.starts_with(&[0, 0])),
            };
            if !ends {
                break;
            }
            if top.end.is_none() {
                at += 2;
            }
            let whole = input.get(top.start..at).ok_or(WalkError::Malformed)?;
            if top.string && !decodes_as_any(whole) {
                return Err(WalkError::Malformed);
            }
            open.pop();
        }
        if open.is_empty() {
            break;
        }
    }
    if at == input.len() {
        Ok(())
    } else {
        Err(WalkError::Trailing)
    }
}
