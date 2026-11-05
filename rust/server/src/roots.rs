//! The roots configuration: read once at start, handed to every instance's
//! `init` as `{"roots":["<base64>", ...]}` (or `{}` for the three Apple
//! roots built into the module), and reported as SHA-256 fingerprints by
//! `GET /v1/info` so a client can refuse a server configured otherwise.
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
                decode(s)
                    .and_then(root)
                    .map_err(|e| format!("roots[{i}]: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Roots::Configured(ders.concat()))
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
            Roots::from_config_json(&der_json).unwrap(),
            Roots::from_config_json(&format!(r#"{{"roots":["{pem_line}"]}}"#)).unwrap(),
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
            Roots::from_config_json(&format!(r#"{{"roots":["{line}"]}}"#)).unwrap(),
        ] {
            assert_eq!(r, Roots::Configured(ders.clone()));
            assert_eq!(r.fingerprints(), DEFAULT_ROOT_SHA256);
        }
        // Next to a DER line, in configuration order.
        let der_line = STANDARD.encode(&ders[1]);
        let r =
            Roots::from_config_json(&format!(r#"{{"roots":["{der_line}","{line}"]}}"#)).unwrap();
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
            Roots::from_config_json(&format!(
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
