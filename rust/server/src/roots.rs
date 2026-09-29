//! The roots configuration: read once at start, handed to every instance's
//! `init` as `{"roots":["<base64 DER>", ...]}` (or `{}` for the three Apple
//! roots built into the module), and reported as SHA-256 fingerprints by
//! `GET /v1/info` so a client can refuse a server configured otherwise.
//!
//! The server does not parse a certificate: whether a root is one is
//! `init`'s answer. Base64 is decoded here only to fingerprint the DER.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};

/// SHA-256 of the DER of the three Apple roots the module has built in
/// (`certs/`). A test pins them to the files.
pub const DEFAULT_ROOT_SHA256: [&str; 3] = [
    // AppleIncRootCertificate.cer
    "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
    // AppleRootCA-G2.cer
    "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
    // AppleRootCA-G3.cer
    "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
];

/// The roots every instance is initialised with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Roots {
    /// The three Apple roots built into the module.
    Defaults,
    /// The caller's own roots, as DER.
    Configured(Vec<Vec<u8>>),
}

impl Roots {
    /// `init`'s argument.
    pub fn config_json(&self) -> Vec<u8> {
        match self {
            Roots::Defaults => b"{}".to_vec(),
            Roots::Configured(ders) => {
                let roots: Vec<String> = ders.iter().map(|d| STANDARD.encode(d)).collect();
                json!({ "roots": roots }).to_string().into_bytes()
            }
        }
    }

    pub fn fingerprints(&self) -> Vec<String> {
        match self {
            Roots::Defaults => DEFAULT_ROOT_SHA256.iter().map(|s| s.to_string()).collect(),
            Roots::Configured(ders) => ders
                .iter()
                .map(|d| crate::manifest::sha256_hex(d))
                .collect(),
        }
    }

    pub fn info(&self) -> Value {
        json!({
            "source": match self { Roots::Defaults => "defaults", Roots::Configured(_) => "configured" },
            "sha256": self.fingerprints(),
        })
    }

    /// A `--roots` file: one base64 DER per line, or PEM `CERTIFICATE`
    /// blocks. Blank lines and lines starting with `#` are ignored. An
    /// empty file is refused: an empty root set is a caller's mistake, never
    /// a request for the defaults (omit `--roots` for those).
    pub fn from_file_text(text: &str) -> Result<Roots, String> {
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
        Ok(Roots::Configured(ders))
    }

    /// The managed child's second stdin line: `init`'s own shape,
    /// `{"roots":["<base64 DER>", ...]}`, or `{}` for the defaults.
    pub fn from_config_json(text: &str) -> Result<Roots, String> {
        let v: Value =
            serde_json::from_str(text).map_err(|e| format!("roots line is not JSON: {e}"))?;
        let obj = v.as_object().ok_or("roots line is not a JSON object")?;
        if let Some(k) = obj.keys().find(|k| *k != "roots") {
            return Err(format!("roots line has an unknown member {k:?}"));
        }
        let Some(list) = obj.get("roots") else {
            return Ok(Roots::Defaults);
        };
        let list = list.as_array().ok_or("roots is not an array")?;
        if list.is_empty() {
            return Err("roots is an empty list; send {} for the built-in Apple roots".into());
        }
        let ders = list
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let s = r
                    .as_str()
                    .ok_or_else(|| format!("roots[{i}] is not a string"))?;
                decode(s).map_err(|e| format!("roots[{i}]: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Roots::Configured(ders))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_fingerprints_are_the_pinned_apple_roots_in_certs() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/");
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        let got: Vec<String> = names
            .iter()
            .map(|n| {
                crate::manifest::sha256_hex(
                    &std::fs::read(format!("{dir}{}", n.to_string_lossy())).unwrap(),
                )
            })
            .collect();
        assert_eq!(got, DEFAULT_ROOT_SHA256);
    }

    #[test]
    fn reads_base64_lines_and_pem() {
        let pem =
            "# test\n\nAQID\n-----BEGIN CERTIFICATE-----\nBAUG\nBwg=\n-----END CERTIFICATE-----\n";
        let r = Roots::from_file_text(pem).unwrap();
        assert_eq!(
            r,
            Roots::Configured(vec![vec![1, 2, 3], vec![4, 5, 6, 7, 8]])
        );
        assert_eq!(r.config_json(), br#"{"roots":["AQID","BAUGBwg="]}"#);
        assert_eq!(r.fingerprints()[0], crate::manifest::sha256_hex(&[1, 2, 3]));
    }

    #[test]
    fn refuses_empty_and_broken_files() {
        assert!(Roots::from_file_text("# nothing\n").is_err());
        assert!(Roots::from_file_text("not base64!\n").is_err());
        assert!(Roots::from_file_text("-----BEGIN CERTIFICATE-----\nAQID\n").is_err());
        assert!(Roots::from_file_text("-----BEGIN PRIVATE KEY-----\n").is_err());
    }

    #[test]
    fn reads_the_managed_roots_line() {
        assert_eq!(Roots::from_config_json("{}").unwrap(), Roots::Defaults);
        assert_eq!(
            Roots::from_config_json(r#"{"roots":["AQID"]}"#).unwrap(),
            Roots::Configured(vec![vec![1, 2, 3]])
        );
        assert!(Roots::from_config_json(r#"{"roots":[]}"#).is_err());
        assert!(Roots::from_config_json(r#"{"roots":["AQID"],"x":1}"#).is_err());
        assert!(Roots::from_config_json("[]").is_err());
        assert_eq!(Roots::Defaults.config_json(), b"{}");
    }
}
