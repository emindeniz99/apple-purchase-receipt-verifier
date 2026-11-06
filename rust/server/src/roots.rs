//! The configuration: read once at start, handed to every instance's
//! `init` as `{"roots":["<base64>", ...]}` (or `{}` for the three Apple
//! roots built into the module) plus the revocation members
//! (docs/design/revocation.md §8), and reported by `GET /v1/info` (the
//! roots' and issuers' SHA-256 fingerprints, the lists' SHA-256s, the
//! distrust entries) so a client can refuse a server configured otherwise.
//!
//! The server does not parse a revocation list or judge a distrust entry
//! either: it passes them to `init`, which refuses what the core refuses.
//!
//! The server does not parse a certificate: whether a root is one is
//! `init`'s answer. A `--roots` file is one raw DER certificate (Apple's
//! `.cer` files) when its first byte is 0x30, the rule the core uses to
//! tell DER from PEM; otherwise base64 lines and PEM blocks (the `pem`
//! crate). A root that is PEM, whether a block in the file or PEM bytes
//! a base64 line or the managed roots line carries, is unwrapped here to
//! the DER of each certificate in it, and only that DER reaches `init`:
//! what `init` anchors is then exactly what `/v1/info` fingerprints.

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
    /// The caller's own roots, each the bytes `init` receives: a base64
    /// line's DER, or the DER of one certificate of a PEM block or of PEM
    /// bytes a base64 line carried. Never PEM.
    Configured(Vec<Vec<u8>>),
}

impl Roots {
    /// `init`'s argument for these roots and no revocation setting (the
    /// tests' shorthand for [`Settings::config_json`]).
    #[cfg(test)]
    pub fn config_json(&self) -> Vec<u8> {
        Settings {
            roots: self.clone(),
            revocation: Revocation::default(),
        }
        .config_json()
    }

    /// SHA-256 of each root `init` anchors, over its DER. `init` anchors a
    /// DER root as the bytes it was given, and it is never given PEM.
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

    /// The `--roots` files, in order, each `(name, bytes)`: a file whose
    /// first byte is 0x30 (an ASN.1 SEQUENCE, as the core tells DER from
    /// PEM) is one DER certificate, passed on whole for `init` to judge;
    /// any other file is the text format of [`Roots::from_file_text`]. No
    /// files means the defaults.
    pub fn from_files(files: &[(&str, &[u8])]) -> Result<Roots, String> {
        let mut ders = Vec::new();
        for (name, bytes) in files {
            let one = match bytes.first() {
                None => Err("the file is empty; omit --roots for the built-in Apple roots".into()),
                Some(0x30) => Ok(Roots::Configured(vec![bytes.to_vec()])),
                Some(_) => std::str::from_utf8(bytes)
                    .map_err(|_| {
                        "neither a DER certificate (first byte 0x30) nor UTF-8 text".to_owned()
                    })
                    .and_then(Roots::from_file_text),
            };
            match one.map_err(|e| format!("--roots {name}: {e}"))? {
                Roots::Configured(d) => ders.extend(d),
                Roots::Defaults => unreachable!("a file always configures roots"),
            }
        }
        Ok(if ders.is_empty() {
            Roots::Defaults
        } else {
            Roots::Configured(ders)
        })
    }

    /// A text `--roots` file: one base64 root per line, or PEM `CERTIFICATE`
    /// blocks, which the `pem` crate decodes to DER. A base64 line may carry
    /// PEM bytes, read the same way. Blank lines and lines starting with
    /// `#` are ignored. An empty file is refused: an empty root set is a
    /// caller's mistake, never a request for the defaults (omit `--roots`
    /// for those).
    pub fn from_file_text(text: &str) -> Result<Roots, String> {
        let ders = read_text(text, true)?;
        if ders.is_empty() {
            return Err(
                "the roots file holds no root; omit --roots for the built-in Apple roots".into(),
            );
        }
        Ok(Roots::Configured(ders))
    }

    /// The `roots` member of the managed configuration line: `None` (no
    /// member) is the defaults; an empty list is refused.
    fn from_config_member(list: Option<&Value>) -> Result<Roots, String> {
        let Some(list) = list else {
            return Ok(Roots::Defaults);
        };
        let list = list.as_array().ok_or("roots is not an array")?;
        if list.is_empty() {
            return Err("roots is an empty list; send {} for the built-in Apple roots".into());
        }
        Ok(Roots::Configured(certificates_member("roots", list)?))
    }
}

/// The revocation settings every instance's `init` receives
/// (docs/design/revocation.md §4). Empty means none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Revocation {
    /// Each list's bytes as given (a DER CRL as downloaded), in order.
    pub lists: Vec<Vec<u8>>,
    /// Each added issuer's DER, PEM unwrapped as for a root, in order.
    pub issuers: Vec<Vec<u8>>,
    /// Each `(issuer, serial)` exactly as given; `init` judges them.
    pub distrust: Vec<(String, String)>,
}

impl Revocation {
    /// The `--revocation-list`, `--revocation-issuer` and `--distrust`
    /// values. A list file is passed whole (an empty one is refused); an
    /// issuer file has the `--roots` format; a distrust value is
    /// `ISSUER:SERIAL`, split at its first colon.
    pub fn from_flags(
        lists: &[(&str, &[u8])],
        issuers: &[(&str, &[u8])],
        distrust: &[String],
    ) -> Result<Revocation, String> {
        let lists = lists
            .iter()
            .map(|(name, bytes)| {
                if bytes.is_empty() {
                    Err(format!("--revocation-list {name}: the file is empty"))
                } else {
                    Ok(bytes.to_vec())
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut issuer_ders = Vec::new();
        for (name, bytes) in issuers {
            issuer_ders.extend(
                certificates_in_file(bytes)
                    .map_err(|e| format!("--revocation-issuer {name}: {e}"))?,
            );
        }
        let distrust = distrust
            .iter()
            .map(|d| {
                d.split_once(':')
                    .map(|(i, s)| (i.to_owned(), s.to_owned()))
                    .ok_or_else(|| format!("--distrust {d}: expected ISSUER:SERIAL"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Revocation {
            lists,
            issuers: issuer_ders,
            distrust,
        })
    }

    /// What `GET /v1/info` states besides the module's answer: the SHA-256
    /// of each list given, sorted (their order does not matter to the
    /// core); of each issuer's DER, in order (the first issuer whose key
    /// verifies a list owns it); and the distrust entries as given.
    pub fn info(&self) -> (Value, Value, Value) {
        let mut lists: Vec<String> = self
            .lists
            .iter()
            .map(|l| crate::manifest::sha256_hex(l))
            .collect();
        lists.sort();
        let issuers: Vec<String> = self
            .issuers
            .iter()
            .map(|d| crate::manifest::sha256_hex(d))
            .collect();
        (json!(lists), json!(issuers), self.distrust_json())
    }

    /// The distrust entries as given, each `{"issuer":...,"serial":...}`:
    /// the one shape `init` receives and `GET /v1/info` states, which a
    /// client compares with what it sent.
    fn distrust_json(&self) -> Value {
        self.distrust
            .iter()
            .map(|(i, s)| json!({ "issuer": i, "serial": s }))
            .collect()
    }
}

/// The whole configuration `init` receives: the roots and the
/// revocation settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub roots: Roots,
    pub revocation: Revocation,
}

impl Settings {
    /// `init`'s argument: `{}` for the defaults and no revocation setting;
    /// an empty revocation setting is left out, as `init` reads it.
    pub fn config_json(&self) -> Vec<u8> {
        let b64 = |v: &[Vec<u8>]| -> Vec<String> { v.iter().map(|d| STANDARD.encode(d)).collect() };
        let mut m = serde_json::Map::new();
        if let Roots::Configured(ders) = &self.roots {
            m.insert("roots".into(), json!(b64(ders)));
        }
        let r = &self.revocation;
        if !r.lists.is_empty() {
            m.insert("revocation_lists".into(), json!(b64(&r.lists)));
        }
        if !r.issuers.is_empty() {
            m.insert("revocation_issuers".into(), json!(b64(&r.issuers)));
        }
        if !r.distrust.is_empty() {
            m.insert("distrust".into(), r.distrust_json());
        }
        Value::Object(m).to_string().into_bytes()
    }

    /// The managed child's second stdin line: `init`'s own shape
    /// (`rust/bindings/wire/schema/init-config.schema.json`), `{}` for the
    /// defaults. Roots and issuers are base64 of DER or PEM, PEM unwrapped
    /// to DER here; lists are base64 of the list's bytes; a distrust entry
    /// is an object of exactly two strings, `issuer` and `serial`. An empty
    /// revocation array is no setting; an empty list entry is passed on,
    /// for `init` to refuse.
    pub fn from_config_json(text: &str) -> Result<Settings, String> {
        let v: Value = serde_json::from_str(text)
            .map_err(|e| format!("configuration line is not JSON: {e}"))?;
        let obj = v
            .as_object()
            .ok_or("configuration line is not a JSON object")?;
        if let Some(k) = obj.keys().find(|k| {
            !matches!(
                k.as_str(),
                "roots" | "revocation_lists" | "revocation_issuers" | "distrust"
            )
        }) {
            return Err(format!("configuration line has an unknown member {k:?}"));
        }
        let roots = Roots::from_config_member(obj.get("roots"))?;
        let array = |name: &str| -> Result<&[Value], String> {
            match obj.get(name) {
                None => Ok(&[]),
                Some(v) => v
                    .as_array()
                    .map(Vec::as_slice)
                    .ok_or_else(|| format!("{name} is not an array")),
            }
        };
        let lists = array("revocation_lists")?
            .iter()
            .enumerate()
            .map(|(i, l)| {
                let s = l
                    .as_str()
                    .ok_or_else(|| format!("revocation_lists[{i}] is not a string"))?;
                // An empty entry goes on to `init`, which refuses it as the
                // component refuses any list it cannot read, so a client
                // reads it as the configuration refused, as on every other
                // engine, not as a server that failed to start.
                if s.is_empty() {
                    return Ok(Vec::new());
                }
                decode(s).map_err(|e| format!("revocation_lists[{i}]: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let issuers = certificates_member("revocation_issuers", array("revocation_issuers")?)?;
        let distrust = array("distrust")?
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let entry = d.as_object().filter(|o| o.len() == 2);
                let field = |k: &str| entry.and_then(|o| o.get(k)).and_then(Value::as_str);
                match (field("issuer"), field("serial")) {
                    (Some(issuer), Some(serial)) => Ok((issuer.to_owned(), serial.to_owned())),
                    _ => Err(format!(
                        "distrust[{i}] is not an object of two strings, issuer and serial"
                    )),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Settings {
            roots,
            revocation: Revocation {
                lists,
                issuers,
                distrust,
            },
        })
    }
}

/// The certificates of a `roots` or `revocation_issuers` array: each a
/// base64 string of DER or PEM, read as [`root`] reads it.
fn certificates_member(name: &str, list: &[Value]) -> Result<Vec<Vec<u8>>, String> {
    let ders = list
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let s = r
                .as_str()
                .ok_or_else(|| format!("{name}[{i}] is not a string"))?;
            decode(s)
                .and_then(root)
                .map_err(|e| format!("{name}[{i}]: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ders.concat())
}

/// The certificates of one `--roots` or `--revocation-issuer` file, by
/// the rule of [`Roots::from_files`].
fn certificates_in_file(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    match bytes.first() {
        None => Err("the file is empty".into()),
        Some(0x30) => Ok(vec![bytes.to_vec()]),
        Some(_) => {
            let text = std::str::from_utf8(bytes).map_err(|_| {
                "neither a DER certificate (first byte 0x30) nor UTF-8 text".to_owned()
            })?;
            let ders = read_text(text, true)?;
            if ders.is_empty() {
                return Err("the file holds no certificate".into());
            }
            Ok(ders)
        }
    }
}

/// The roots in a text: PEM blocks, blank lines, and, when `lines` is set
/// (a `--roots` file), `#` comments and base64 lines, each one [`root`].
/// PEM bytes a base64 line carries are read with `lines` unset: blocks and
/// blank lines only, so any other text in them is refused rather than
/// passed over as OpenSSL's reader would.
///
/// The lines from a `-----BEGIN` line to the next line starting with
/// `-----` are one block, handed to `pem::parse` whole: it matches the END
/// label to the BEGIN label and decodes the base64 between them.
fn read_text(text: &str, lines: bool) -> Result<Vec<Vec<u8>>, String> {
    let mut ders = Vec::new();
    let mut block: Option<String> = None;
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        // A delimiter line is five dashes, a label with no dash in it, and
        // five dashes: `pem::parse` would skip text after the first closing
        // dashes, which the old reader refused.
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
        if line.is_empty() || (lines && line.starts_with('#')) {
            continue;
        }
        if line.starts_with("-----BEGIN ") {
            block = Some(format!("{line}\n"));
        } else if line.starts_with("-----") {
            return Err(format!("line {}: {line} outside a PEM block", n + 1));
        } else if lines {
            ders.extend(
                decode(line)
                    .and_then(root)
                    .map_err(|e| format!("line {}: {e}", n + 1))?,
            );
        } else {
            return Err(format!("line {}: text outside a PEM block", n + 1));
        }
    }
    if block.is_some() {
        return Err("a PEM block has no END line".into());
    }
    Ok(ders)
}

/// One root as `init` takes it, as the DER `init` will anchor: bytes the
/// core reads as PEM (`-----BEGIN` after any ASCII whitespace, its
/// `TrustAnchor::from_der_or_pem` rule) become the DER of each
/// certificate in them; any other bytes, DER or not, pass as they are, for
/// `init` to anchor whole or refuse.
fn root(bytes: Vec<u8>) -> Result<Vec<Vec<u8>>, String> {
    if !bytes.trim_ascii_start().starts_with(b"-----BEGIN") {
        return Ok(vec![bytes]);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "PEM root: not UTF-8".to_owned())?;
    // Its first line that is not blank is a BEGIN line, so it holds a
    // block or is refused for one without an END line.
    read_text(text, false).map_err(|e| format!("PEM root: {e}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The roots of a managed configuration line.
    fn managed_line(text: &str) -> Result<Roots, String> {
        Settings::from_config_json(text).map(|s| s.roots)
    }

    /// The names of the root certificates in `certs/`: its top-level
    /// `.cer` files, sorted. `certs/` also holds `revocations.json` and the
    /// `revocation-issuers/` intermediates, which are not roots.
    fn root_names() -> Vec<String> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/");
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| e.file_type().unwrap().is_file())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".cer"))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn default_fingerprints_are_the_pinned_apple_roots_in_certs() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/");
        let got: Vec<String> = root_names()
            .iter()
            .map(|n| crate::manifest::sha256_hex(&std::fs::read(format!("{dir}{n}")).unwrap()))
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
        let ders: Vec<Vec<u8>> = root_names()
            .iter()
            .map(|n| std::fs::read(format!("{dir}{n}")).unwrap())
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

    fn pem_of(ders: &[Vec<u8>]) -> String {
        let mut pem = String::new();
        for der in ders {
            pem += "-----BEGIN CERTIFICATE-----\n";
            for chunk in STANDARD.encode(der).as_bytes().chunks(64) {
                pem += std::str::from_utf8(chunk).unwrap();
                pem += "\n";
            }
            pem += "-----END CERTIFICATE-----\n";
        }
        pem
    }

    /// A base64 line, or a managed roots entry, that carries PEM bytes was
    /// passed to `init` as PEM and fingerprinted as the PEM text, a hash no
    /// client compares. Now the PEM is unwrapped here, `init` receives the
    /// DER, and `/v1/info` reports the DER's SHA-256, the same as for the
    /// DER root itself.
    #[test]
    fn a_pem_root_in_a_base64_line_is_fingerprinted_as_its_der() {
        let ders: Vec<Vec<u8>> = certs().into_iter().map(|(_, b)| b).collect();
        let der_line = STANDARD.encode(&ders[2]);
        let pem_line = STANDARD.encode(pem_of(&ders[2..]));
        let der_json = format!(r#"{{"roots":["{der_line}"]}}"#);
        for r in [
            Roots::from_file_text(&format!("{der_line}\n")).unwrap(),
            Roots::from_file_text(&format!("{pem_line}\n")).unwrap(),
            managed_line(&der_json).unwrap(),
            managed_line(&format!(r#"{{"roots":["{pem_line}"]}}"#)).unwrap(),
        ] {
            assert_eq!(r, Roots::Configured(vec![ders[2].clone()]));
            assert_eq!(r.fingerprints(), [DEFAULT_ROOT_SHA256[2]]);
            // `init` is given the DER, never the PEM.
            assert_eq!(r.config_json(), der_json.as_bytes());
        }
    }

    /// A PEM bundle in one base64 line is one root to `init`, which
    /// anchors every certificate in it, so it reports one fingerprint per
    /// certificate, in order; leading whitespace and blank lines are kept
    /// to the core's rule for telling PEM from DER.
    #[test]
    fn a_pem_bundle_in_a_base64_line_has_one_fingerprint_per_certificate() {
        let ders: Vec<Vec<u8>> = certs().into_iter().map(|(_, b)| b).collect();
        let bundle = format!("\r\n  {}\n\n", pem_of(&ders).replace('\n', "\r\n"));
        let line = STANDARD.encode(&bundle);
        for r in [
            Roots::from_file_text(&format!("# bundle\n{line}\n")).unwrap(),
            managed_line(&format!(r#"{{"roots":["{line}"]}}"#)).unwrap(),
        ] {
            assert_eq!(r, Roots::Configured(ders.clone()));
            assert_eq!(r.fingerprints(), DEFAULT_ROOT_SHA256);
        }
        // Next to a DER line, in configuration order.
        let der_line = STANDARD.encode(&ders[1]);
        let r = managed_line(&format!(r#"{{"roots":["{der_line}","{line}"]}}"#)).unwrap();
        assert_eq!(
            r.fingerprints(),
            [
                DEFAULT_ROOT_SHA256[1],
                DEFAULT_ROOT_SHA256[0],
                DEFAULT_ROOT_SHA256[1],
                DEFAULT_ROOT_SHA256[2]
            ]
        );
    }

    /// PEM bytes in a base64 line are blocks and blank lines only: other
    /// text, which OpenSSL's reader would pass over, is refused, so no
    /// certificate reaches `init` that `/v1/info` does not report.
    #[test]
    fn refuses_a_pem_root_with_anything_but_blocks() {
        let der = certs().remove(0).1;
        let pem = pem_of(&[der]);
        let line = |text: &str| STANDARD.encode(text);
        let refused = |text: &str| Roots::from_file_text(&format!("{}\n", line(text))).unwrap_err();
        assert_eq!(
            refused(&format!("{pem}trailing text\n")),
            "line 1: PEM root: line 29: text outside a PEM block"
        );
        assert_eq!(
            refused(&format!("{pem}# a comment\n")),
            "line 1: PEM root: line 29: text outside a PEM block"
        );
        assert_eq!(
            refused("-----BEGIN CERTIFICATE-----\nAQID\n"),
            "line 1: PEM root: a PEM block has no END line"
        );
        assert_eq!(
            refused("-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n"),
            "line 1: PEM root: line 3: PEM block: only CERTIFICATE PEM blocks are read, not PRIVATE KEY"
        );
        assert_eq!(
            managed_line(&format!(
                r#"{{"roots":["{}"]}}"#,
                STANDARD.encode(b"-----BEGIN \xff")
            ))
            .unwrap_err(),
            "roots[0]: PEM root: not UTF-8"
        );
        // Bytes that are neither DER nor PEM still pass whole, for `init`
        // to refuse, as before.
        assert_eq!(
            Roots::from_file_text("AQID\n").unwrap(),
            Roots::Configured(vec![vec![1, 2, 3]])
        );
    }

    /// The built-in roots are reported as the pinned fingerprints, which
    /// this change leaves as they were.
    #[test]
    fn the_built_in_roots_report_the_pinned_fingerprints() {
        assert_eq!(
            Roots::Defaults.info(),
            json!({
                "source": "defaults",
                "sha256": [
                    "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
                    "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
                    "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
                ],
            })
        );
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
        for end in [
            "-----END CERTIFICATE-----x-----",
            "-----END CERTIFICATE----------",
        ] {
            assert_eq!(
                refused(&format!("-----BEGIN CERTIFICATE-----\nAQID\n{end}\n")),
                format!("line 3: malformed PEM line {end}")
            );
        }
        assert_eq!(
            refused("-----END CERTIFICATE-----\n"),
            "line 1: -----END CERTIFICATE----- outside a PEM block"
        );
    }

    fn certs() -> Vec<(String, Vec<u8>)> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/");
        root_names()
            .into_iter()
            .map(|n| {
                let bytes = std::fs::read(format!("{dir}{n}")).unwrap();
                (n, bytes)
            })
            .collect()
    }

    /// Apple's `.cer` files are DER and go in as they are, one file a root;
    /// several files add up, in order, and a DER file mixes with a PEM one.
    #[test]
    fn reads_der_cer_files_and_several_files() {
        let certs = certs();
        let files: Vec<(&str, &[u8])> = certs
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let one = Roots::from_files(&files[2..]).unwrap();
        assert_eq!(one, Roots::Configured(vec![certs[2].1.clone()]));
        assert_eq!(one.fingerprints(), [DEFAULT_ROOT_SHA256[2]]);
        let all = Roots::from_files(&files).unwrap();
        assert_eq!(all.fingerprints(), DEFAULT_ROOT_SHA256);
        // A DER file and a PEM file: the PEM block reads back to its DER.
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(&certs[0].1)
        );
        let mixed = Roots::from_files(&[files[1], ("g.pem", pem.as_bytes())]).unwrap();
        assert_eq!(
            mixed.fingerprints(),
            [DEFAULT_ROOT_SHA256[1], DEFAULT_ROOT_SHA256[0]]
        );
        assert_eq!(Roots::from_files(&[]).unwrap(), Roots::Defaults);
    }

    #[test]
    fn refuses_an_empty_file_and_one_that_is_neither_der_nor_text() {
        assert_eq!(
            Roots::from_files(&[("a.cer", b"")]).unwrap_err(),
            "--roots a.cer: the file is empty; omit --roots for the built-in Apple roots"
        );
        assert_eq!(
            Roots::from_files(&[("b.cer", b"\xff\xfe")]).unwrap_err(),
            "--roots b.cer: neither a DER certificate (first byte 0x30) nor UTF-8 text"
        );
        // The second file names itself in the error.
        let certs = certs();
        assert!(
            Roots::from_files(&[("ok.cer", &certs[0].1), ("c.txt", b"# none\n")])
                .unwrap_err()
                .starts_with("--roots c.txt: the roots file holds no root")
        );
    }

    /// The configuration line carries `init`'s revocation members: lists
    /// as base64 of their bytes, issuers as roots are (PEM unwrapped to
    /// DER), distrust entries of exactly two strings, passed on as given
    /// for `init` to judge. An empty array is no setting, and `init`
    /// receives the same line back with no empty member.
    #[test]
    fn reads_the_revocation_members_of_the_configuration_line() {
        let der = certs().remove(0).1;
        let pem = STANDARD.encode(pem_of(std::slice::from_ref(&der)));
        let text = format!(
            r#"{{"revocation_lists":["AQID","BAU="],"revocation_issuers":["{pem}"],"distrust":[{{"issuer":"AB","serial":"x"}}]}}"#
        );
        let s = Settings::from_config_json(&text).unwrap();
        assert_eq!(s.roots, Roots::Defaults);
        assert_eq!(
            s.revocation,
            Revocation {
                lists: vec![vec![1, 2, 3], vec![4, 5]],
                issuers: vec![der.clone()],
                distrust: vec![("AB".into(), "x".into())],
            }
        );
        let back: Value = serde_json::from_slice(&s.config_json()).unwrap();
        assert_eq!(
            back,
            json!({
                "revocation_lists": ["AQID", "BAU="],
                "revocation_issuers": [STANDARD.encode(&der)],
                "distrust": [{ "issuer": "AB", "serial": "x" }],
            })
        );
        assert_eq!(
            Settings::from_config_json(&String::from_utf8(s.config_json()).unwrap()).unwrap(),
            s
        );
        let empty = Settings::from_config_json(
            r#"{"roots":["AQID"],"revocation_lists":[],"revocation_issuers":[],"distrust":[]}"#,
        )
        .unwrap();
        assert_eq!(empty.revocation, Revocation::default());
        assert_eq!(empty.config_json(), br#"{"roots":["AQID"]}"#);
        let refused = |t: &str| Settings::from_config_json(t).unwrap_err();
        assert_eq!(
            refused(r#"{"revocation_lists":"AQID"}"#),
            "revocation_lists is not an array"
        );
        assert_eq!(
            refused(r#"{"revocation_lists":[1]}"#),
            "revocation_lists[0] is not a string"
        );
        // An empty list is passed on for `init` to refuse, so a client
        // reads the component's refusal, as on its other engines.
        let empty_list = Settings::from_config_json(r#"{"revocation_lists":[""]}"#).unwrap();
        assert_eq!(empty_list.revocation.lists, vec![Vec::<u8>::new()]);
        assert_eq!(empty_list.config_json(), br#"{"revocation_lists":[""]}"#);
        assert!(refused(r#"{"revocation_lists":["AQ!D"]}"#)
            .starts_with("revocation_lists[0]: not standard base64"));
        assert_eq!(
            refused(r#"{"revocation_issuers":[1]}"#),
            "revocation_issuers[0] is not a string"
        );
        for d in [
            r#"[1]"#,
            r#"[{"issuer":"a"}]"#,
            r#"[{"issuer":"a","serial":1}]"#,
            r#"[{"issuer":"a","serial":"1","x":"2"}]"#,
        ] {
            assert_eq!(
                refused(&format!(r#"{{"distrust":{d}}}"#)),
                "distrust[0] is not an object of two strings, issuer and serial",
                "{d}"
            );
        }
        assert_eq!(
            refused(r#"{"crls":[]}"#),
            r#"configuration line has an unknown member "crls""#
        );
    }

    /// `--revocation-list` files pass whole, `--revocation-issuer` files
    /// read as `--roots` files do, `--distrust` splits at its first colon;
    /// `/v1/info` reports the lists' SHA-256s sorted, the issuers' in
    /// order and the distrust entries as given.
    #[test]
    fn reads_the_revocation_flags_and_reports_them() {
        let certs = certs();
        let (g3, root) = (&certs[2].1, &certs[0].1);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(root)
        );
        let r = Revocation::from_flags(
            &[("b.crl", b"\x30\x02"), ("a.crl", b"\x30\x01")],
            &[("g3.cer", g3), ("root.pem", pem.as_bytes())],
            &["ab:0:1".into(), ":".into()],
        )
        .unwrap();
        assert_eq!(r.lists, [vec![0x30, 2], vec![0x30, 1]]);
        assert_eq!(r.issuers, [g3.clone(), root.clone()]);
        assert_eq!(
            r.distrust,
            [("ab".into(), "0:1".into()), (String::new(), String::new())]
        );
        let (lists, issuers, distrust) = r.info();
        let mut sorted = vec![
            crate::manifest::sha256_hex(&[0x30, 2]),
            crate::manifest::sha256_hex(&[0x30, 1]),
        ];
        sorted.sort();
        assert_eq!(lists, json!(sorted));
        assert_eq!(
            issuers,
            json!([DEFAULT_ROOT_SHA256[2], DEFAULT_ROOT_SHA256[0]])
        );
        assert_eq!(
            distrust,
            json!([{"issuer": "ab", "serial": "0:1"}, {"issuer": "", "serial": ""}])
        );
        assert_eq!(
            Revocation::from_flags(&[("l.crl", b"")], &[], &[]).unwrap_err(),
            "--revocation-list l.crl: the file is empty"
        );
        assert_eq!(
            Revocation::from_flags(&[], &[("i.txt", b"# none\n")], &[]).unwrap_err(),
            "--revocation-issuer i.txt: the file holds no certificate"
        );
        assert_eq!(
            Revocation::from_flags(&[], &[], &["ab01".into()]).unwrap_err(),
            "--distrust ab01: expected ISSUER:SERIAL"
        );
        assert_eq!(
            Revocation::default().info(),
            (json!([]), json!([]), json!([]))
        );
    }

    #[test]
    fn reads_the_managed_roots_line() {
        assert_eq!(managed_line("{}").unwrap(), Roots::Defaults);
        assert_eq!(
            managed_line(r#"{"roots":["AQID"]}"#).unwrap(),
            Roots::Configured(vec![vec![1, 2, 3]])
        );
        assert!(managed_line(r#"{"roots":[]}"#).is_err());
        assert!(managed_line(r#"{"roots":["AQID"],"x":1}"#).is_err());
        assert!(managed_line("[]").is_err());
        assert_eq!(Roots::Defaults.config_json(), b"{}");
    }
}
