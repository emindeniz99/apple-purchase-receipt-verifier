//! The three documents this crate reads as JSON (a JWS header, a JWS
//! payload and the endpoint's request body), read by `serde_json`.
//!
//! None of them is behind a signature when it is read. Each is read into a
//! map from member name to the member's raw text, so a value nobody asks
//! for is checked against the grammar and skipped without being built
//! (`serde_json` skips it without a nesting limit, on a heap stack of one
//! byte per level). The values the callers need are then read from their
//! raw text. A repeated name keeps its last value, as a map does. The
//! grammar is strict RFC 8259.

use serde_json::value::RawValue;
use serde_json::{Deserializer, Number};
use std::collections::BTreeMap;

/// Why a document did not parse.
pub(crate) type JsonError = serde_json::Error;

/// A document's top-level members: each name, unescaped, and the raw text
/// of its last value.
pub(crate) type Members<'a> = BTreeMap<String, &'a RawValue>;

/// The members of the object `text` starts with. What follows the object is
/// not read (the endpoint's rule for a request body).
///
/// # Errors
/// When the text does not start with an object or the object does not parse.
pub(crate) fn top_level_members(text: &str) -> Result<Members<'_>, JsonError> {
    match Deserializer::from_str(text).into_iter().next() {
        Some(members) => members,
        // Empty or only whitespace: serde_json's own end-of-input error.
        None => serde_json::from_str(text),
    }
}

/// The members of the object that is the whole of `text` (the JWS rule).
///
/// # Errors
/// When the text is not one object, with only whitespace after it.
pub(crate) fn whole_object_members(text: &str) -> Result<Members<'_>, JsonError> {
    serde_json::from_str(text)
}

/// The member's value when it is a string.
pub(crate) fn string(members: &Members<'_>, name: &str) -> Option<String> {
    serde_json::from_str(members.get(name)?.get()).ok()
}

/// The member's value when it is an array of strings.
pub(crate) fn strings(members: &Members<'_>, name: &str) -> Option<Vec<String>> {
    serde_json::from_str(members.get(name)?.get()).ok()
}

/// The member's value as epoch milliseconds: an integer must fit an `i64`;
/// a number with a fraction or exponent is read as a double and truncated
/// when it lies within the `i64` range. Anything else is `None`.
pub(crate) fn instant(members: &Members<'_>, name: &str) -> Option<i64> {
    let number: Number = serde_json::from_str(members.get(name)?.get()).ok()?;
    if number.is_i64() || number.is_u64() {
        return number.as_i64();
    }
    let value = number.as_f64()?;
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
        assert!(whole_object_members(&nested(100_000)[1..]).is_err());
    }

    #[test]
    fn brackets_inside_strings_are_data() {
        let text = format!(r#"{{"k":"{}\"{}"}}"#, "[".repeat(200), "{".repeat(200));
        assert!(top_level_members(&text).is_ok());
    }

    #[test]
    fn anything_after_the_object_is_not_read() {
        assert!(top_level_members("{} trailing").unwrap().is_empty());
        assert!(top_level_members("{}x").unwrap().is_empty());
        assert!(top_level_members("{}\u{0}").unwrap().is_empty());
    }

    #[test]
    fn a_whole_object_allows_only_whitespace_after_it() {
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
    fn where_serde_json_differs_from_the_old_reader() {
        // No name or number length bound.
        let long_name = format!("{{\"{}\":1}}", "n".repeat(100_000));
        assert!(whole_object_members(&long_name).is_ok());
        let long_number = format!("{{\"a\":1{}}}", "0".repeat(100_000));
        assert!(whole_object_members(&long_number).is_ok());
        // A lone surrogate escape in a name is refused (the old reader read
        // U+FFFD); in a skipped value it is not looked at.
        assert!(whole_object_members(r#"{"\ud800":1}"#).is_err());
        assert!(whole_object_members(r#"{"a":"\ud800"}"#).is_ok());
    }

    #[test]
    fn values_are_read_from_the_last_member() {
        let members =
            top_level_members(r#"{"a":"x","b":[1],"a":["y","z"],"s":"\ud800","n":-1.5e3}"#)
                .unwrap();
        assert_eq!(members.len(), 4);
        assert_eq!(strings(&members, "a"), Some(vec!["y".into(), "z".into()]));
        assert_eq!(string(&members, "a"), None);
        assert_eq!(strings(&members, "b"), None);
        assert_eq!(string(&members, "s"), None);
        assert_eq!(instant(&members, "n"), Some(-1500));
    }

    #[test]
    fn escapes_decode_and_names_compare_decoded() {
        let members = top_level_members(r#"{"signedDat\u0065":"\ud83d\ude00\n"}"#).unwrap();
        assert_eq!(string(&members, "signedDate").unwrap(), "\u{1f600}\n");
    }

    #[test]
    fn instants_follow_the_reference_conversion() {
        let at = |number: &str| {
            instant(
                &top_level_members(&format!("{{\"t\":{number}}}")).unwrap(),
                "t",
            )
        };
        assert_eq!(at("1722945600000"), Some(1_722_945_600_000));
        assert_eq!(at("9223372036854775808"), None);
        assert_eq!(at("1.7229456e12"), Some(1_722_945_600_000));
        assert_eq!(at("1722945600000.9"), Some(1_722_945_600_000));
        assert_eq!(at("1e300"), None);
        assert_eq!(at("-1e300"), None);
        assert_eq!(at("1e400"), None);
        assert_eq!(at("\"1\""), None);
        // An integer past u64 is a double to serde_json, so the double rule
        // applies; the old reader said None for every integer past i64.
        assert_eq!(at("-9223372036854775809"), Some(i64::MIN));
    }
}
