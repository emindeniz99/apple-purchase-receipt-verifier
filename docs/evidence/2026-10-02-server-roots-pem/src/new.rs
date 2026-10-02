//! `Roots::from_file_text` with the `pem` crate reading each block,
//! returning the DER list instead of `Roots::Configured`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

/// A `--roots` file: one base64 root per line, or PEM `CERTIFICATE`
/// blocks, which the `pem` crate decodes to DER. Blank lines and lines
/// starting with `#` are ignored. An empty file is refused: an empty
/// root set is a caller's mistake, never a request for the defaults
/// (omit `--roots` for those).
///
/// The lines from a `-----BEGIN` line to the next line starting with
/// `-----` are one block, handed to `pem::parse` whole: it matches the
/// END label to the BEGIN label and decodes the base64 between them.
pub fn from_file_text(text: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut ders = Vec::new();
    let mut block: Option<String> = None;
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        // A delimiter line is five dashes, a label with no dash in it,
        // and five dashes: `pem::parse` would skip text after the first
        // closing dashes, which the old reader refused.
        if line.starts_with("-----") && !is_delimiter(line) {
            return Err(format!("line {}: malformed PEM line {line}", n + 1));
        }
        if let Some(b) = block.as_mut() {
            // Blank lines would read as the end of RFC 1421 headers.
            if line.is_empty() {
                continue;
            }
            // `pem` drops whitespace inside the base64; this file never
            // allowed it there.
            if !line.starts_with("-----") && line.contains(char::is_whitespace) {
                return Err(format!("line {}: whitespace inside PEM base64", n + 1));
            }
            b.push_str(line);
            b.push('\n');
            if line.starts_with("-----") {
                ders.push(certificate(b).map_err(|e| format!("line {}: PEM block: {e}", n + 1))?);
                block = None;
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("-----BEGIN ") {
            block = Some(format!("{line}\n"));
        } else if line.starts_with("-----") {
            return Err(format!("line {}: {line} outside a PEM block", n + 1));
        } else {
            ders.push(decode(line).map_err(|e| format!("line {}: {e}", n + 1))?);
        }
    }
    if block.is_some() {
        return Err("a PEM block has no END line".into());
    }
    if ders.is_empty() {
        return Err(
            "the roots file holds no root; omit --roots for the built-in Apple roots".into(),
        );
    }
    Ok(ders)
}

/// One PEM block's DER, if the block is a `CERTIFICATE`.
fn certificate(block: &str) -> Result<Vec<u8>, String> {
    let p = pem::parse(block).map_err(|e| e.to_string())?;
    if p.tag() != "CERTIFICATE" {
        return Err(format!(
            "only CERTIFICATE PEM blocks are read, not {}",
            p.tag()
        ));
    }
    if p.contents().is_empty() {
        return Err("empty".into());
    }
    Ok(p.into_contents())
}

/// `-----BEGIN CERTIFICATE-----` or `-----END CERTIFICATE-----` and the
/// like: five dashes, a non-empty label with no dash in it (RFC 7468's
/// labels have none), five dashes.
fn is_delimiter(line: &str) -> bool {
    line.strip_prefix("-----")
        .and_then(|rest| rest.strip_suffix("-----"))
        .is_some_and(|label| !label.is_empty() && !label.contains('-'))
}

fn decode(s: &str) -> Result<Vec<u8>, String> {
    let d = STANDARD
        .decode(s)
        .map_err(|e| format!("not standard base64: {e}"))?;
    if d.is_empty() {
        return Err("empty".into());
    }
    Ok(d)
}
