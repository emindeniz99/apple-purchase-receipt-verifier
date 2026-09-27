//! The JSON writer for the canonical payload form and the endpoint's
//! response: objects written key by key, strings escaped exactly as
//! ECMAScript `JSON.stringify` escapes them.

use crate::receipt_payload::UnknownAttributes;

/// A JSON object being written, with the canonical form's rules.
pub(crate) struct Object<'a> {
    out: &'a mut String,
    first: bool,
}

impl<'a> Object<'a> {
    pub(crate) fn open(out: &'a mut String) -> Self {
        out.push('{');
        Object { out, first: true }
    }

    pub(crate) fn close(self) {
        self.out.push('}');
    }

    /// The string being written, for a value the caller appends itself
    /// after [`key`](Object::key).
    pub(crate) fn out(&mut self) -> &mut String {
        self.out
    }

    pub(crate) fn key(&mut self, key: &str) {
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        quote(self.out, key);
        self.out.push(':');
    }

    pub(crate) fn string(&mut self, key: &str, value: Option<&str>) {
        self.key(key);
        match value {
            Some(value) => quote(self.out, value),
            None => self.out.push_str("null"),
        }
    }

    pub(crate) fn number(&mut self, key: &str, value: Option<i64>) {
        self.key(key);
        match value {
            Some(value) => self.out.push_str(&value.to_string()),
            None => self.out.push_str("null"),
        }
    }

    /// A 64-bit id, as a JSON string so JavaScript readers do not round it.
    pub(crate) fn id(&mut self, key: &str, value: Option<i64>) {
        self.string(key, value.map(|value| value.to_string()).as_deref());
    }

    pub(crate) fn boolean(&mut self, key: &str, value: Option<bool>) {
        self.key(key);
        self.out.push_str(match value {
            Some(true) => "true",
            Some(false) => "false",
            None => "null",
        });
    }

    pub(crate) fn bytes(&mut self, key: &str, value: Option<&[u8]>) {
        self.string(key, value.map(crate::base64::encode).as_deref());
    }

    pub(crate) fn attributes(&mut self, key: &str, attributes: &UnknownAttributes) {
        self.key(key);
        // A BTreeMap iterates in ascending key order, which is the order the
        // canonical form requires.
        let mut object = Object::open(self.out);
        for (attribute_type, values) in attributes {
            object.key(&attribute_type.to_string());
            object.out.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    object.out.push(',');
                }
                quote(object.out, &crate::base64::encode(value));
            }
            object.out.push(']');
        }
        object.close();
    }
}

/// A JSON string as ECMAScript `JSON.stringify` writes it: `\"`, `\\` and
/// the short escapes `\b \f \n \r \t`, every other character below U+0020 as
/// a lowercase `\u00xx`, and nothing else (`/` and non-ASCII, U+2028 and
/// U+2029 included, written raw).
pub(crate) fn quote(out: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0}'..='\u{1f}' => {
                let code = c as usize;
                out.push_str("\\u00");
                out.push(char::from(*HEX.get(code >> 4).unwrap_or(&b'0')));
                out.push(char::from(*HEX.get(code & 0xf).unwrap_or(&b'0')));
            }
            _ => out.push(c),
        }
    }
    out.push('"');
}
