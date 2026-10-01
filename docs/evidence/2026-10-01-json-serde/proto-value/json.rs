//! The three documents this crate reads as JSON (a JWS header, a JWS
//! payload and the endpoint's request body), read by `serde_json`.
//!
//! None of them is behind a signature when it is read. The bounds are the
//! callers' input caps and `serde_json`'s own: strict RFC 8259 and a nesting
//! limit of 128. A repeated member name keeps its last value, as a map does.

use serde_json::{Deserializer, Map, Number, Value};

/// Why a document did not parse.
pub(crate) type JsonError = serde_json::Error;

/// The members of the object `text` starts with. What follows the object is
/// not read (the endpoint's rule for a request body).
///
/// # Errors
/// When the text does not start with an object or the object does not parse.
pub(crate) fn top_level_members(text: &str) -> Result<Map<String, Value>, JsonError> {
    match Deserializer::from_str(text).into_iter().next() {
        Some(members) => members,
        // Empty or only whitespace: ask serde_json for its own EOF error.
        None => serde_json::from_str(text),
    }
}

/// The members of the object that is the whole of `text` (the JWS rule).
///
/// # Errors
/// When the text is not one object, with only whitespace after it.
pub(crate) fn whole_object_members(text: &str) -> Result<Map<String, Value>, JsonError> {
    serde_json::from_str(text)
}

/// A JSON number as epoch milliseconds: an integer must fit an `i64`; a
/// number with a fraction or exponent is read as a double and truncated
/// when it lies within the `i64` range. Anything else is `None`.
pub(crate) fn instant(number: &Number) -> Option<i64> {
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
    use super::{instant, top_level_members, whole_object_members};
    use serde_json::Number;
    use std::str::FromStr;

    fn nested(depth: usize) -> String {
        format!(
            "{{\"a\":{}{}}}",
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        )
    }

    #[test]
    fn serde_json_nests_to_127_and_refuses_128() {
        assert!(top_level_members(&nested(127)).is_ok());
        assert!(top_level_members(&nested(128)).is_err());
        assert!(whole_object_members(&nested(127)).is_ok());
        assert!(whole_object_members(&nested(128)).is_err());
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
    fn grammar_errors_inside_the_object_are_refused() {
        for text in [
            "",
            " ",
            "[]",
            "{,}",
            "{\"a\":1,}",
            "{\"a\":01}",
            "{\"a\":+1}",
            "{\"a\":1.}",
            "{\"a\":NaN}",
            "{\"a\":truex}",
            "{\"a\":\"\u{1}\"}",
            "{\"a\":\"\\x\"}",
            "{'a':1}",
            "{\"a\":1 /* c */}",
            "\u{feff}{}",
        ] {
            assert!(top_level_members(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn where_serde_json_differs_from_the_old_reader() {
        // A lone surrogate escape: the old reader read U+FFFD.
        assert!(whole_object_members(r#"{"a":"\ud800"}"#).is_err());
        // A number no f64 holds: the old reader kept the text.
        assert!(whole_object_members(&format!("{{\"a\":1{}}}", "0".repeat(400))).is_err());
        assert!(whole_object_members(r#"{"a":1e400}"#).is_err());
        // No name or number length bound.
        let long_name = format!("{{\"{}\":1}}", "n".repeat(100_000));
        assert!(whole_object_members(&long_name).is_ok());
        let long_fraction = format!("{{\"a\":0.{}}}", "1".repeat(100_000));
        assert!(whole_object_members(&long_fraction).is_ok());
    }

    #[test]
    fn duplicates_keep_the_last_value() {
        let members = top_level_members(r#"{"a":"x","b":[1],"a":["y","z"]}"#).unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members["a"], serde_json::json!(["y", "z"]));
    }

    #[test]
    fn escapes_decode_and_names_compare_decoded() {
        let members = top_level_members(r#"{"signedDat\u0065":"\ud83d\ude00\n"}"#).unwrap();
        assert_eq!(members["signedDate"], "\u{1f600}\n");
    }

    #[test]
    fn instants_follow_the_reference_conversion() {
        let n = |text: &str| Number::from_str(text).unwrap();
        assert_eq!(instant(&n("1722945600000")), Some(1_722_945_600_000));
        assert_eq!(instant(&n("9223372036854775808")), None);
        assert_eq!(instant(&n("1.7229456e12")), Some(1_722_945_600_000));
        assert_eq!(instant(&n("1722945600000.9")), Some(1_722_945_600_000));
        assert_eq!(instant(&n("1e300")), None);
        assert_eq!(instant(&n("-1e300")), None);
        // An integer past u64 is an f64 to serde_json, so the double rule
        // applies; the old reader said None for every integer past i64.
        assert_eq!(instant(&n("-9223372036854775809")), Some(i64::MIN));
    }
}
