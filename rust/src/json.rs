//! The three documents this crate reads as JSON (a JWS header, a JWS
//! payload and the endpoint's request body), read by `serde_json`.
//!
//! None of them is behind a signature when it is read. Each is read into a
//! map from member name to the member's raw text, so a value nobody asks
//! for is checked against the grammar and skipped without being built:
//! `serde_json` skips it iteratively, on a heap stack of one byte per level,
//! with no nesting limit. The values the callers need are then read from
//! their raw text. A repeated name keeps its last value, as a map does. The
//! grammar is strict RFC 8259: no comments, no trailing commas, no leading
//! zeros or `+`, no `NaN`, no byte order mark, no unescaped control
//! characters, and only the escapes RFC 8259 defines, in skipped values
//! too. A lone surrogate escape is refused in a name or in a value that is
//! read, and not examined in a value that is skipped.
//!
//! [`whole_object_members`] allows only whitespace after the object, the
//! rule for a JWS header and payload; [`top_level_members`] stops at the
//! object's closing brace and does not read the rest, the endpoint's rule
//! for a request body, as Apple's endpoint does not read it either.

use serde_json::value::RawValue;
use serde_json::Deserializer;
use std::collections::BTreeMap;

/// Why a document did not parse. Detail only.
pub(crate) type JsonError = serde_json::Error;

/// A document's top-level members: each name, unescaped, and the raw text
/// of its last value.
pub(crate) type Members<'a> = BTreeMap<String, &'a RawValue>;

/// The members of the object `text` starts with. What follows the object is
/// not read.
///
/// # Errors
/// [`JsonError`] when the text does not start with an object, or the object
/// breaks the grammar.
pub(crate) fn top_level_members(text: &str) -> Result<Members<'_>, JsonError> {
    match Deserializer::from_str(text).into_iter().next() {
        Some(members) => members,
        // Empty or only whitespace: serde_json's own end-of-input error.
        None => serde_json::from_str(text),
    }
}

/// As [`top_level_members`], but the object must be the whole document:
/// only whitespace (space, tab, line feed, carriage return) may follow it.
///
/// # Errors
/// [`JsonError`] as [`top_level_members`], and for anything but whitespace
/// after the object.
pub(crate) fn whole_object_members(text: &str) -> Result<Members<'_>, JsonError> {
    serde_json::from_str(text)
}

/// The member's value when it is a string, unescaped.
pub(crate) fn string(members: &Members<'_>, name: &str) -> Option<String> {
    serde_json::from_str(members.get(name)?.get()).ok()
}

/// The member's value when it is an array whose elements are all strings.
pub(crate) fn strings(members: &Members<'_>, name: &str) -> Option<Vec<String>> {
    serde_json::from_str(members.get(name)?.get()).ok()
}

/// The member's value as epoch milliseconds, by the reference conversion:
/// an integer must fit an `i64`; a number with a fraction or an exponent
/// is read as a double and truncated when it lies within the `i64` range.
/// Anything else, a string, an integer past `i64` or `1e300` say, is no
/// instant and is `None`, and the clock stands in for it.
pub(crate) fn instant(members: &Members<'_>, name: &str) -> Option<i64> {
    // The raw text of a JSON number, which serde_json has checked against
    // the grammar: digits with an optional leading minus is an integer,
    // and only a fraction or an exponent can add anything else.
    let text = members.get(name)?.get().trim();
    if !text.starts_with(|c: char| c == '-' || c.is_ascii_digit()) {
        return None;
    }
    if text.bytes().all(|b| b == b'-' || b.is_ascii_digit()) {
        return text.parse::<i64>().ok();
    }
    let value: f64 = text.parse().ok()?;
    // i64::MIN is exactly -2^63 as a double; i64::MAX rounds up to 2^63,
    // which the range check admits and the cast then clamps.
    #[allow(clippy::cast_precision_loss)]
    let (low, high) = (i64::MIN as f64, i64::MAX as f64);
    if value.is_finite() && value >= low && value <= high {
        #[allow(clippy::cast_possible_truncation)]
        Some(value as i64)
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{instant, string, strings, top_level_members, whole_object_members};

    fn nested(depth: usize) -> String {
        format!(
            "{{\"a\":{}{}}}",
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        )
    }

    #[test]
    fn a_skipped_value_has_no_nesting_limit() {
        assert!(top_level_members(&nested(100_000)).is_ok());
        assert!(whole_object_members(&nested(100_000)).is_ok());
        // Unbalanced is still refused.
        assert!(whole_object_members(&nested(100_000)[1..]).is_err());
    }

    #[test]
    fn brackets_inside_strings_are_data() {
        let text = format!(r#"{{"k":"{}\"{}"}}"#, "[".repeat(200), "{".repeat(200));
        assert!(top_level_members(&text).is_ok());
    }

    #[test]
    fn anything_after_the_object_is_not_read() {
        // The endpoint rule: the object is read, what follows is not.
        assert!(top_level_members("{} trailing").unwrap().is_empty());
        assert!(top_level_members("{}x").unwrap().is_empty());
        assert!(top_level_members("{}\u{0}").unwrap().is_empty());
    }

    #[test]
    fn a_whole_object_allows_only_whitespace_after_it() {
        // The JWS rule: a header or payload with text after the object is
        // not the object that was signed for.
        assert!(whole_object_members("{} \t\r\n").unwrap().is_empty());
        assert_eq!(whole_object_members(" {\"a\":1}").unwrap().len(), 1);
        for text in [
            "{} x",
            "{}{}",
            "{},",
            "{\"a\":1}\u{0}",
            "{}\u{a0}",
            "\u{feff}{}",
        ] {
            assert!(whole_object_members(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn grammar_errors_anywhere_are_refused() {
        for text in [
            "",
            " ",
            "[]",
            "{,}",
            "{\"a\":1,}",
            "{\"a\":[1,]}",
            "{\"a\":01}",
            "{\"a\":[+1]}",
            "{\"a\":1.}",
            "{\"a\":NaN}",
            "{\"a\":truex}",
            "{\"a\":[\"\u{1}\"]}",
            "{\"a\":{\"b\":\"\\x\"}}",
            "{'a':1}",
            "{\"a\":1 /* c */}",
            "\u{feff}{}",
        ] {
            assert!(top_level_members(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn no_name_or_number_length_bound_and_lone_surrogates() {
        let long_name = format!("{{\"{}\":1}}", "n".repeat(100_000));
        assert!(whole_object_members(&long_name).is_ok());
        let long_number = format!("{{\"a\":1{}}}", "0".repeat(100_000));
        assert!(whole_object_members(&long_number).is_ok());
        // A lone surrogate escape in a name is refused; in a skipped value
        // it is not looked at; in a value that is read it is no string.
        assert!(whole_object_members(r#"{"\ud800":1}"#).is_err());
        let members = whole_object_members(r#"{"a":"\ud800"}"#).unwrap();
        assert_eq!(string(&members, "a"), None);
    }

    #[test]
    fn values_are_read_from_the_last_member() {
        let members = top_level_members(r#"{"a":"x","b":[1],"a":["y","z"],"n":-1.5e3}"#).unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(strings(&members, "a"), Some(vec!["y".into(), "z".into()]));
        assert_eq!(string(&members, "a"), None);
        assert_eq!(strings(&members, "b"), None);
        assert_eq!(instant(&members, "n"), Some(-1500));
        assert_eq!(instant(&members, "missing"), None);
    }

    #[test]
    fn escapes_decode_and_names_compare_decoded() {
        let members = top_level_members(r#"{"signedDat\u0065":"\ud83d\ude00\n"}"#).unwrap();
        assert_eq!(string(&members, "signedDate").unwrap(), "\u{1f600}\n");
    }

    #[test]
    fn instants_follow_the_reference_conversion() {
        // Java's JsonFields.instant: an integer must fit a long, a double
        // is truncated within the long range, anything else is no instant.
        let at = |number: &str| {
            instant(
                &top_level_members(&format!("{{\"t\":{number}}}")).unwrap(),
                "t",
            )
        };
        assert_eq!(at("1722945600000"), Some(1_722_945_600_000));
        assert_eq!(at("-1"), Some(-1));
        assert_eq!(at("9223372036854775807"), Some(i64::MAX));
        assert_eq!(at("1.7229456e12"), Some(1_722_945_600_000));
        assert_eq!(at("1722945600000.9"), Some(1_722_945_600_000));
        assert_eq!(at("1e3"), Some(1000));
        assert_eq!(at("1.5"), Some(1));
        // An integer past i64, either way, is no instant, not a clamped
        // one: the clock stands in for it, as in Java and the old reader.
        assert_eq!(at("9223372036854775808"), None);
        assert_eq!(at("-9223372036854775809"), None);
        assert_eq!(at("1e300"), None);
        assert_eq!(at("-1e300"), None);
        assert_eq!(at("1e400"), None);
        assert_eq!(at("\"1\""), None);
        assert_eq!(at("true"), None);
        assert_eq!(at("[1]"), None);
    }
}
