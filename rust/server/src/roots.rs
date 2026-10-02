//! The roots configuration: read once at start, handed to every instance's
//! `init` as `{"roots":["<base64 DER>", ...]}` (or `{}` for the three Apple
//! roots built into the module), and reported as SHA-256 fingerprints by
//! `GET /v1/info` so a client can refuse a server configured otherwise.
//!
//! The server does not parse a certificate: whether a root is one is
//! `init`'s answer. Base64 lines and PEM blocks (the `pem` crate) are
//! decoded here only to fingerprint the DER.

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

    /// A `--roots` file: one base64 root per line, or PEM `CERTIFICATE`
    /// blocks, which the `pem` crate decodes to DER. Blank lines and lines
    /// starting with `#` are ignored. An empty file is refused: an empty
    /// root set is a caller's mistake, never a request for the defaults
    /// (omit `--roots` for those).
    ///
    /// The lines from a `-----BEGIN` line to the next line starting with
    /// `-----` are one block, handed to `pem::parse` whole: it matches the
    /// END label to the BEGIN label and decodes the base64 between them.
    pub fn from_file_text(text: &str) -> Result<Roots, String> {
        let mut ders = Vec::new();
        let mut block: Option<String> = None;
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            // A delimiter line opens and closes with its own five dashes
            // (so it is at least ten characters long), and no text follows
            // the closing ones, which `pem::parse` would otherwise skip.
            if line.starts_with("-----") && (line.len() < 10 || !line.ends_with("-----")) {
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
                    ders.push(
                        certificate(b).map_err(|e| format!("line {}: PEM block: {e}", n + 1))?,
                    );
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

    /// `certs/`'s three Apple roots as one PEM bundle, wrapped at 64
    /// columns with CRLF line ends, read back to the very DER of the files:
    /// `/v1/info` reports the same fingerprints for them as for the
    /// defaults, which is what the Java and PHP clients compare.
    #[test]
    fn a_pem_bundle_of_the_apple_roots_reads_back_to_their_der() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/");
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        let ders: Vec<Vec<u8>> = names
            .iter()
            .map(|n| std::fs::read(format!("{dir}{}", n.to_string_lossy())).unwrap())
            .collect();
        let mut bundle = String::from("# the Apple roots\r\n");
        for der in &ders {
            bundle += "-----BEGIN CERTIFICATE-----\r\n";
            for chunk in STANDARD.encode(der).as_bytes().chunks(64) {
                bundle += std::str::from_utf8(chunk).unwrap();
                bundle += "\r\n";
            }
            bundle += "-----END CERTIFICATE-----\r\n\r\n";
        }
        let r = Roots::from_file_text(&bundle).unwrap();
        assert_eq!(r, Roots::Configured(ders));
        assert_eq!(r.fingerprints(), DEFAULT_ROOT_SHA256);
    }

    /// A PEM file as a tool wrote it (Apple's test CA in `fixtures/`), its
    /// DER SHA-256 taken with `openssl x509 -outform DER | sha256sum`, and
    /// the same certificate as a base64 DER line reads to the same root.
    #[test]
    fn a_pem_file_and_its_base64_line_have_one_fingerprint() {
        const TEST_CA_SHA256: &str =
            "48aa70550eab2cd71d51dced44e88f9143b6bc0e1a6f430c19ba9a7cf36654e6";
        let pem = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/apple-official/certs/testCA.pem"
        ))
        .unwrap();
        let r = Roots::from_file_text(&pem).unwrap();
        assert_eq!(r.fingerprints(), [TEST_CA_SHA256]);
        let Roots::Configured(ders) = &r else {
            unreachable!()
        };
        let line = STANDARD.encode(&ders[0]);
        let both = Roots::from_file_text(&format!("{line}\n{pem}")).unwrap();
        assert_eq!(both.fingerprints(), [TEST_CA_SHA256, TEST_CA_SHA256]);
    }

    #[test]
    fn refuses_empty_and_broken_files() {
        let refused = |text: &str| Roots::from_file_text(text).unwrap_err();
        assert!(refused("# nothing\n").contains("holds no root"));
        assert!(refused("not base64!\n").starts_with("line 1: not standard base64"));
        // A block that never ends, a nested BEGIN, END for another label.
        assert_eq!(
            refused("-----BEGIN CERTIFICATE-----\nAQID\n"),
            "a PEM block has no END line"
        );
        assert!(refused(
            "-----BEGIN CERTIFICATE-----\nAQID\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"
        )
        .starts_with("line 3: PEM block:"));
        assert!(
            refused("-----BEGIN CERTIFICATE-----\nAQID\n-----END X509 CRL-----\n")
                .starts_with("line 3: PEM block: mismatching")
        );
        // Only CERTIFICATE blocks, whatever else a PEM file holds.
        assert_eq!(
            refused("-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n"),
            "line 3: PEM block: only CERTIFICATE PEM blocks are read, not PRIVATE KEY"
        );
        assert!(refused("-----BEGIN PRIVATE KEY-----\n").contains("no END line"));
        // A body that is not base64, an empty body, and an RFC 1421 header.
        assert!(
            refused("-----BEGIN CERTIFICATE-----\nAQ!D\n-----END CERTIFICATE-----\n")
                .starts_with("line 3: PEM block: invalid data")
        );
        assert_eq!(
            refused("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"),
            "line 2: PEM block: empty"
        );
        assert!(refused(
            "-----BEGIN CERTIFICATE-----\nProc-Type:4,ENCRYPTED\n\nAQID\n-----END CERTIFICATE-----\n"
        )
        .starts_with("line 5: PEM block: invalid data"));
        assert_eq!(
            refused("-----BEGIN CERTIFICATE-----\nAQ ID\n-----END CERTIFICATE-----\n"),
            "line 2: whitespace inside PEM base64"
        );
        // Text after a delimiter's dashes, and a stray delimiter.
        assert_eq!(
            refused("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----AQID\n"),
            "line 3: malformed PEM line -----END CERTIFICATE-----AQID"
        );
        assert_eq!(
            refused("-----END CERTIFICATE-----\n"),
            "line 1: -----END CERTIFICATE----- outside a PEM block"
        );
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
