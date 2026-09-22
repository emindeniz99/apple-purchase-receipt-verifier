//! The nesting-depth bound on every JSON document this crate parses: the
//! endpoint's request body and a JWS header and payload.
//!
//! `serde_json` has a recursion limit of its own, but it is fixed at 128 and
//! cannot be lowered, so the depth is counted here, in one linear pass that
//! allocates nothing, before the parser runs.

/// How deep any JSON document this crate parses may nest: arrays and objects
/// open at once, the outermost one included.
///
/// 64, the same number as the Java, PHP and Python ports. A `verifyReceipt`
/// body is a flat object of strings and a JWS header or payload nests two or
/// three levels, so nothing genuine comes near it.
pub const MAX_JSON_NESTING_DEPTH: usize = 64;

/// Whether `text` opens more than [`MAX_JSON_NESTING_DEPTH`] arrays and
/// objects at once, outside string literals.
///
/// Brackets inside a string are data, not nesting, so strings are skipped
/// with their escapes. Nothing else about the text is judged: a document
/// that is not JSON is the parser's to refuse, and an unterminated string can
/// only make this undercount something the parser then refuses anyway.
pub(crate) fn nesting_exceeds_limit(text: &[u8]) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in text {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > MAX_JSON_NESTING_DEPTH {
                    return true;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{nesting_exceeds_limit, MAX_JSON_NESTING_DEPTH};

    fn nested(depth: usize) -> String {
        format!("{}{}", "[".repeat(depth), "]".repeat(depth))
    }

    #[test]
    fn the_limit_itself_is_allowed_and_one_more_is_not() {
        assert!(!nesting_exceeds_limit(
            nested(MAX_JSON_NESTING_DEPTH).as_bytes()
        ));
        assert!(nesting_exceeds_limit(
            nested(MAX_JSON_NESTING_DEPTH + 1).as_bytes()
        ));
    }

    #[test]
    fn brackets_inside_strings_are_data() {
        // Without string awareness a legitimate string value full of
        // brackets would be refused as nesting.
        let text = format!(r#"{{"k":"{}\"{}"}}"#, "[".repeat(200), "{".repeat(200));
        assert!(!nesting_exceeds_limit(text.as_bytes()));
    }

    #[test]
    fn siblings_do_not_add_up() {
        // Depth is how many are open at once, not how many there are.
        let text = format!("[{}]", vec![nested(10); 100].join(","));
        assert!(!nesting_exceeds_limit(text.as_bytes()));
    }
}
