//! `Roots::from_file_text` at the base commit, the hand-written PEM
//! reader, returning the DER list instead of `Roots::Configured`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

/// A `--roots` file: one base64 DER per line, or PEM `CERTIFICATE`
/// blocks. Blank lines and lines starting with `#` are ignored. An
/// empty file is refused: an empty root set is a caller's mistake, never
/// a request for the defaults (omit `--roots` for those).
pub fn from_file_text(text: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut ders = Vec::new();
    let mut pem: Option<String> = None;
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if let Some(body) = pem.as_mut() {
            if line == "-----END CERTIFICATE-----" {
                ders.push(decode(body).map_err(|e| format!("line {}: PEM block: {e}", n + 1))?);
                pem = None;
            } else if line.starts_with("-----") {
                return Err(format!(
                    "line {}: unexpected {line} inside a PEM block",
                    n + 1
                ));
            } else {
                body.push_str(line);
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "-----BEGIN CERTIFICATE-----" {
            pem = Some(String::new());
        } else if line.starts_with("-----") {
            return Err(format!(
                "line {}: only CERTIFICATE PEM blocks are read, not {line}",
                n + 1
            ));
        } else {
            ders.push(decode(line).map_err(|e| format!("line {}: {e}", n + 1))?);
        }
    }
    if pem.is_some() {
        return Err("a PEM block has no END line".into());
    }
    if ders.is_empty() {
        return Err(
            "the roots file holds no root; omit --roots for the built-in Apple roots".into(),
        );
    }
    Ok(ders)
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
