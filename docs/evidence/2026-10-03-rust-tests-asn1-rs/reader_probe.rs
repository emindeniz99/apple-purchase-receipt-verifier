//! Differential probe: the test reader and the DER writer in
//! `rust/tests/common/`, before and after the move onto asn1-rs.
//!
//! Copy into `rust/tests/` and run it against each tree (README.md). It
//! prints one line per input with a SHA-256 over everything the tests read
//! from the tree (each node's tag, constructed bit, full TLV, contents and
//! child count, preorder; the joined value of every OCTET STRING), or the
//! parse error, and one line per writer output. Two trees that print the
//! same lines read and write the same bytes.

#[allow(dead_code)]
mod common;

// The reader module: `common::der` before the change; after it, edit
// this line to `use common::ber as reader;`.
use common::der as reader;

use openssl::sha::Sha256;
use std::fmt::Write as _;
use std::path::Path;

fn walk(node: &reader::Tlv<'_>, hash: &mut Sha256, nodes: &mut usize) {
    *nodes += 1;
    hash.update(&[node.tag, u8::from(node.constructed)]);
    for part in [node.full, node.contents] {
        hash.update(&(part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.update(&(node.children().len() as u64).to_be_bytes());
    if node.is_octet_string() {
        match node.octet_string_value() {
            Some(value) => {
                hash.update(b"V");
                hash.update(&value);
            }
            None => hash.update(b"N"),
        }
    }
    for child in node.children() {
        walk(child, hash, nodes);
    }
}

fn line(name: &str, bytes: &[u8]) -> String {
    match reader::parse_exact(bytes) {
        Ok(tree) => {
            let mut hash = Sha256::new();
            let mut nodes = 0;
            walk(&tree, &mut hash, &mut nodes);
            let cms = match common::cms::parse_cms(bytes) {
                Ok(parsed) => {
                    let mut h = Sha256::new();
                    h.update(&parsed.content);
                    for c in &parsed.certificates {
                        h.update(c);
                    }
                    for s in &parsed.signer_infos {
                        h.update(&s.issuer_raw);
                        h.update(&s.serial_contents);
                        h.update(s.signed_attrs.as_deref().unwrap_or(b"-"));
                        h.update(&s.signature);
                    }
                    hex::encode(&h.finish()[..8])
                }
                Err(_) => "not-cms".to_owned(),
            };
            format!(
                "{name} ok nodes={nodes} tree={} cms={cms}",
                hex::encode(&hash.finish()[..8])
            )
        }
        Err(_) => format!("{name} err"),
    }
}

fn inputs(dir: &Path, base: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            inputs(&path, base, out);
            continue;
        }
        let name = path.strip_prefix(base).unwrap().to_string_lossy().into_owned();
        let bytes = std::fs::read(&path).unwrap();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let base64ish = ext == "b64"
            || name.contains("xcode-app-receipt")
            || name.contains("receipt-b64");
        if ext == "der" {
            out.push((name, bytes));
        } else if base64ish {
            let text: String = String::from_utf8_lossy(&bytes).split_whitespace().collect();
            use base64::Engine as _;
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(text) {
                out.push((name, decoded));
            }
        }
    }
}

#[test]
fn probe() {
    let fixtures = common::fixtures_dir();
    let mut all = Vec::new();
    inputs(&fixtures, &fixtures, &mut all);
    let mut report = String::new();
    for (name, bytes) in &all {
        writeln!(report, "{}", line(name, bytes)).unwrap();
    }
    // How many inputs open with an indefinite-length SEQUENCE: BER the
    // `der` crate refuses.
    let indefinite = all.iter().filter(|(_, bytes)| bytes.starts_with(&[0x30, 0x80])).count();
    writeln!(report, "inputs={} starting-30-80={indefinite}", all.len()).unwrap();
    // The builder's own output and the shared receipt's parts.
    let built = common::CmsBuilder::from_shared().build();
    writeln!(report, "{}", line("<CmsBuilder::from_shared().build()>", &built)).unwrap();
    writeln!(report, "built-equals-fixture={}", built == common::receipt_der()).unwrap();
    // The writer: every length form, integers, OIDs.
    let mut writer = Sha256::new();
    for length in (0..=70_000usize).step_by(7).chain([127, 128, 255, 256, 65_535, 65_536]) {
        writer.update(&common::der(0x04, &vec![0xa5; length]));
    }
    for tag in 0..=255u8 {
        if tag & 0x1f != 0x1f {
            writer.update(&common::der(tag, b"x"));
        }
    }
    for value in [0u64, 1, 2, 127, 128, 255, 256, 0x7fff, 0x8000, u64::MAX, 0x0102_0304_0506] {
        writer.update(&common::der_int(value));
    }
    writeln!(report, "writer={}", hex::encode(writer.finish())).unwrap();
    // One line per OID: the tests' OIDs, and two edge cases of the first
    // two arcs.
    for oid in ["1.2.840.113549.1.7.2", "2.5.29.19", "1.2.840.113635.100.6.2.1", "1.2.3.4", "2.999.1", "0.39"] {
        match std::panic::catch_unwind(|| common::der_oid(oid)) {
            Ok(bytes) => writeln!(report, "der_oid({oid})={}", hex::encode(bytes)).unwrap(),
            Err(_) => writeln!(report, "der_oid({oid}) panicked").unwrap(),
        }
    }
    let out = std::env::var("PROBE_OUT").expect("PROBE_OUT names the report file");
    std::fs::write(out, report).unwrap();
}
