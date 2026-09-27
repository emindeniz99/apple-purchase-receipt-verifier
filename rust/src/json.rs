//! The JSON reader for the three documents this crate parses: a JWS header,
//! a JWS payload and the endpoint's request body.
//!
//! None of them is behind a signature when it is read, so the reader is
//! bounded ([`MAX_NESTING_DEPTH`], [`MAX_NUMBER_LENGTH`], [`MAX_NAME_LENGTH`])
//! and allocates only what it keeps. It reads the first value, which must be
//! an object. [`whole_object_members`] then allows only whitespace after it,
//! the rule for a JWS header and payload; [`top_level_members`] stops at the
//! object's closing brace and does not read the rest, the endpoint's rule for
//! a request body, as Apple's endpoint does not read it either. The grammar
//! is strict RFC 8259 inside the object: no comments,
//! no trailing commas, no leading zeros or `+`, no `NaN`, no unescaped
//! control characters, and only the escapes RFC 8259 defines.
//!
//! Only the top-level members are handed back; nested values are validated
//! and skipped.

use core::fmt;

/// How deep a document may nest: arrays and objects open at once, the
/// outermost one included.
pub(crate) const MAX_NESTING_DEPTH: usize = 64;

/// The longest number, in characters. Longer is no number any payload
/// carries, and a bound keeps an unverified document cheap to read.
pub(crate) const MAX_NUMBER_LENGTH: usize = 1000;

/// The longest member name, in UTF-16 units, for the same reason.
pub(crate) const MAX_NAME_LENGTH: usize = 50_000;

/// Why a document did not parse. Detail only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JsonError(&'static str);

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for JsonError {}

/// A top-level member's value, reduced to what the callers read.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value<'a> {
    /// A string, unescaped. A lone surrogate escape becomes U+FFFD.
    String(String),
    /// A number, as written, and whether it has no fraction or exponent.
    Number { text: &'a str, integer: bool },
    /// An array whose elements are all strings.
    Strings(Vec<String>),
    /// Anything else: an object, a mixed array, `true`, `false`, `null`.
    Other,
}

/// The top-level members of the object `text` starts with, in document
/// order, duplicates included.
///
/// # Errors
/// [`JsonError`] when the text does not start with an object, or the object
/// breaks the grammar or a bound.
pub(crate) fn top_level_members(text: &str) -> Result<Vec<(String, Value<'_>)>, JsonError> {
    let mut reader = Reader {
        text,
        bytes: text.as_bytes(),
        at: 0,
        depth: 0,
    };
    reader.object_members()
}

/// As [`top_level_members`], but the object must be the whole document:
/// only whitespace may follow it.
///
/// # Errors
/// [`JsonError`] as [`top_level_members`], and for anything but whitespace
/// after the object.
pub(crate) fn whole_object_members(text: &str) -> Result<Vec<(String, Value<'_>)>, JsonError> {
    let mut reader = Reader {
        text,
        bytes: text.as_bytes(),
        at: 0,
        depth: 0,
    };
    let members = reader.object_members()?;
    reader.skip_whitespace()?;
    if reader.peek().is_some() {
        return Err(JsonError("content after the object"));
    }
    Ok(members)
}

impl<'a> Reader<'a> {
    fn object_members(&mut self) -> Result<Vec<(String, Value<'a>)>, JsonError> {
        let reader = self;
        reader.skip_whitespace()?;
        if reader.peek() != Some(b'{') {
            return Err(JsonError("not a JSON object"));
        }
        reader.at += 1;
        reader.enter()?;
        let mut members = Vec::new();
        reader.skip_whitespace()?;
        if reader.peek() == Some(b'}') {
            reader.at += 1;
            return Ok(members);
        }
        loop {
            reader.skip_whitespace()?;
            let name = reader.name()?;
            reader.skip_whitespace()?;
            reader.expect(b':')?;
            reader.skip_whitespace()?;
            let value = reader.top_value()?;
            members.push((name, value));
            reader.skip_whitespace()?;
            match reader.next_byte()? {
                b',' => {}
                b'}' => return Ok(members),
                _ => return Err(JsonError("expected ',' or '}'")),
            }
        }
    }
}

struct Reader<'a> {
    text: &'a str,
    bytes: &'a [u8],
    at: usize,
    depth: usize,
}

impl<'a> Reader<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn next_byte(&mut self) -> Result<u8, JsonError> {
        let byte = self.peek().ok_or(JsonError("unexpected end of input"))?;
        self.at += 1;
        Ok(byte)
    }

    fn expect(&mut self, wanted: u8) -> Result<(), JsonError> {
        if self.next_byte()? == wanted {
            Ok(())
        } else {
            Err(JsonError("unexpected character"))
        }
    }

    fn enter(&mut self) -> Result<(), JsonError> {
        self.depth += 1;
        if self.depth > MAX_NESTING_DEPTH {
            return Err(JsonError("nesting deeper than 64"));
        }
        Ok(())
    }

    /// Space, tab, line feed and carriage return; any other control
    /// character outside a string is an error.
    fn skip_whitespace(&mut self) -> Result<(), JsonError> {
        while let Some(byte) = self.peek() {
            match byte {
                b' ' | b'\t' | b'\n' | b'\r' => self.at += 1,
                0..=0x1f => return Err(JsonError("illegal control character")),
                _ => break,
            }
        }
        Ok(())
    }

    fn name(&mut self) -> Result<String, JsonError> {
        if self.peek() != Some(b'"') {
            return Err(JsonError("expected a member name"));
        }
        let name = self.string()?;
        if name.encode_utf16().count() > MAX_NAME_LENGTH {
            return Err(JsonError("member name too long"));
        }
        Ok(name)
    }

    /// A top-level member value, reduced to [`Value`].
    fn top_value(&mut self) -> Result<Value<'a>, JsonError> {
        match self.peek() {
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'[') => {
                self.at += 1;
                self.enter()?;
                let mut strings = Some(Vec::new());
                self.skip_whitespace()?;
                if self.peek() == Some(b']') {
                    self.at += 1;
                } else {
                    loop {
                        self.skip_whitespace()?;
                        if self.peek() == Some(b'"') {
                            let text = self.string()?;
                            if let Some(strings) = strings.as_mut() {
                                strings.push(text);
                            }
                        } else {
                            self.skip_value()?;
                            strings = None;
                        }
                        self.skip_whitespace()?;
                        match self.next_byte()? {
                            b',' => {}
                            b']' => break,
                            _ => return Err(JsonError("expected ',' or ']'")),
                        }
                    }
                }
                self.depth -= 1;
                Ok(strings.map_or(Value::Other, Value::Strings))
            }
            Some(b'-' | b'0'..=b'9') => {
                let start = self.at;
                let integer = self.number()?;
                let text = self.text.get(start..self.at).unwrap_or("");
                Ok(Value::Number { text, integer })
            }
            _ => {
                self.skip_value()?;
                Ok(Value::Other)
            }
        }
    }

    /// Validates and skips one value of any kind.
    fn skip_value(&mut self) -> Result<(), JsonError> {
        match self.peek() {
            Some(b'"') => self.string().map(drop),
            Some(b'-' | b'0'..=b'9') => self.number().map(drop),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'{') => {
                self.at += 1;
                self.enter()?;
                self.skip_whitespace()?;
                if self.peek() == Some(b'}') {
                    self.at += 1;
                } else {
                    loop {
                        self.skip_whitespace()?;
                        self.name()?;
                        self.skip_whitespace()?;
                        self.expect(b':')?;
                        self.skip_whitespace()?;
                        self.skip_value()?;
                        self.skip_whitespace()?;
                        match self.next_byte()? {
                            b',' => {}
                            b'}' => break,
                            _ => return Err(JsonError("expected ',' or '}'")),
                        }
                    }
                }
                self.depth -= 1;
                Ok(())
            }
            Some(b'[') => {
                self.at += 1;
                self.enter()?;
                self.skip_whitespace()?;
                if self.peek() == Some(b']') {
                    self.at += 1;
                } else {
                    loop {
                        self.skip_whitespace()?;
                        self.skip_value()?;
                        self.skip_whitespace()?;
                        match self.next_byte()? {
                            b',' => {}
                            b']' => break,
                            _ => return Err(JsonError("expected ',' or ']'")),
                        }
                    }
                }
                self.depth -= 1;
                Ok(())
            }
            Some(_) => Err(JsonError("unexpected character")),
            None => Err(JsonError("unexpected end of input")),
        }
    }

    /// `true`, `false` or `null`, not followed by another letter or digit
    /// (`truex` is one bad token, not `true` and junk).
    fn literal(&mut self, word: &[u8]) -> Result<(), JsonError> {
        let end = self.at + word.len();
        if self.bytes.get(self.at..end) != Some(word) {
            return Err(JsonError("unrecognized token"));
        }
        self.at = end;
        if self
            .peek()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80)
        {
            return Err(JsonError("unrecognized token"));
        }
        Ok(())
    }

    /// Returns whether the number is an integer (no fraction or exponent).
    fn number(&mut self) -> Result<bool, JsonError> {
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        let int_digits = self.digits();
        match int_digits {
            0 => return Err(JsonError("expected a digit")),
            1 => {}
            _ => {
                if self.bytes.get(self.at - int_digits) == Some(&b'0') {
                    return Err(JsonError("leading zeroes are not allowed"));
                }
            }
        }
        let mut total = int_digits;
        let mut integer = true;
        if self.peek() == Some(b'.') {
            self.at += 1;
            let fraction = self.digits();
            if fraction == 0 {
                return Err(JsonError("expected a digit after the decimal point"));
            }
            total += fraction;
            integer = false;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            let exponent = self.digits();
            if exponent == 0 {
                return Err(JsonError("expected a digit in the exponent"));
            }
            total += exponent;
            integer = false;
        }
        let length = if integer { int_digits } else { total };
        if length > MAX_NUMBER_LENGTH {
            return Err(JsonError("number too long"));
        }
        Ok(integer)
    }

    fn digits(&mut self) -> usize {
        let start = self.at;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.at += 1;
        }
        self.at - start
    }

    /// A string, unescaped; the reader stands on its opening quote.
    fn string(&mut self) -> Result<String, JsonError> {
        self.at += 1;
        let mut out = String::new();
        let mut run_start = self.at;
        loop {
            let byte = self.peek().ok_or(JsonError("unterminated string"))?;
            match byte {
                b'"' => {
                    out.push_str(self.text.get(run_start..self.at).unwrap_or(""));
                    self.at += 1;
                    return Ok(out);
                }
                b'\\' => {
                    out.push_str(self.text.get(run_start..self.at).unwrap_or(""));
                    self.at += 1;
                    self.escape(&mut out)?;
                    run_start = self.at;
                }
                0..=0x1f => return Err(JsonError("unescaped control character in string")),
                _ => self.at += 1,
            }
        }
    }

    fn escape(&mut self, out: &mut String) -> Result<(), JsonError> {
        let byte = self.next_byte()?;
        let decoded = match byte {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let unit = self.hex4()?;
                if (0xd800..0xdc00).contains(&unit)
                    && self.bytes.get(self.at..self.at + 2) == Some(b"\\u")
                {
                    let saved = self.at;
                    self.at += 2;
                    let low = self.hex4()?;
                    if (0xdc00..0xe000).contains(&low) {
                        let code = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                        out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                        return Ok(());
                    }
                    self.at = saved;
                }
                char::from_u32(unit).unwrap_or('\u{fffd}')
            }
            _ => return Err(JsonError("unrecognized escape")),
        };
        out.push(decoded);
        Ok(())
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let digit = char::from(self.next_byte()?)
                .to_digit(16)
                .ok_or(JsonError("bad unicode escape"))?;
            value = value * 16 + digit;
        }
        Ok(value)
    }
}

/// A JSON number as epoch milliseconds: an integer must fit an `i64`; a number with a fraction or
/// an exponent is read as a double and truncated when it lies within the
/// `i64` range. Anything else, `1e300` say, is no instant and is `None`.
pub(crate) fn instant(text: &str, integer: bool) -> Option<i64> {
    if integer {
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
    use super::{instant, top_level_members, whole_object_members, Value, MAX_NESTING_DEPTH};

    fn nested(depth: usize) -> String {
        format!(
            "{{\"a\":{}{}}}",
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        )
    }

    #[test]
    fn the_depth_limit_itself_is_allowed_and_one_more_is_not() {
        assert!(top_level_members(&nested(MAX_NESTING_DEPTH)).is_ok());
        assert!(top_level_members(&nested(MAX_NESTING_DEPTH + 1)).is_err());
    }

    #[test]
    fn brackets_inside_strings_are_data() {
        let text = format!(r#"{{"k":"{}\"{}"}}"#, "[".repeat(200), "{".repeat(200));
        assert!(top_level_members(&text).is_ok());
    }

    #[test]
    fn anything_after_the_object_is_not_read() {
        // The endpoint rule: the object is read, what follows is not.
        assert_eq!(top_level_members("{} trailing").unwrap(), vec![]);
    }

    #[test]
    fn a_whole_object_allows_only_whitespace_after_it() {
        // The JWS rule: a header or payload with text after the object is
        // not the object that was signed for.
        assert_eq!(whole_object_members("{} \t\r\n").unwrap(), vec![]);
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
    fn members_keep_document_order_and_duplicates() {
        let members = top_level_members(r#"{"a":"x","b":[1],"a":["y","z"],"n":-1.5e3}"#).unwrap();
        assert_eq!(
            members,
            vec![
                ("a".to_owned(), Value::String("x".to_owned())),
                ("b".to_owned(), Value::Other),
                (
                    "a".to_owned(),
                    Value::Strings(vec!["y".to_owned(), "z".to_owned()])
                ),
                (
                    "n".to_owned(),
                    Value::Number {
                        text: "-1.5e3",
                        integer: false
                    }
                ),
            ]
        );
    }

    #[test]
    fn escapes_decode_and_names_compare_decoded() {
        let members = top_level_members(r#"{"signedDat\u0065":"\ud83d\ude00\n"}"#).unwrap();
        assert_eq!(
            members,
            vec![(
                "signedDate".to_owned(),
                Value::String("\u{1f600}\n".to_owned())
            )]
        );
    }

    #[test]
    fn instants_follow_the_reference_conversion() {
        assert_eq!(instant("1722945600000", true), Some(1_722_945_600_000));
        assert_eq!(instant("9223372036854775808", true), None);
        assert_eq!(instant("1.7229456e12", false), Some(1_722_945_600_000));
        assert_eq!(instant("1722945600000.9", false), Some(1_722_945_600_000));
        assert_eq!(instant("1e300", false), None);
        assert_eq!(instant("-1e300", false), None);
    }
}
