#![no_main]
#![allow(dead_code, unused_imports, clippy::all)]

//! Spike only (round 4): a DIFFERENTIAL fuzz target. Every input is a
//! receipt payload, read by two readers:
//!
//! - old: the repository's own `receipt_payload.rs` over `asn1.rs`, compiled
//!   in unchanged from `$REPO/rust/src` (scripts/fuzz.sh copies the five
//!   files below into fuzz/old/);
//! - new: the no-asn1 tree's reader over OpenSSL (the crate under test,
//!   through its hidden `spike_probe`).
//!
//! It compares what `parse_receipt_payload` returns (the whole `AppReceipt`
//! Debug text, or the Reason) and what `read_creation_date` returns. It
//! never panics on a difference: a difference is FILED, under a signature,
//! in $APRV_DIFF_DIR/<signature>/ (at most 50 inputs each), so a campaign
//! enumerates every class instead of stopping at the first.
//!
//! The signature localises the cause. When the old reader cannot even walk
//! the input, the whole input is the culprit. Otherwise each attribute is
//! re-wrapped alone in a SET and given to both readers twice: once alone
//! (the full parse) and once beside a readable creation date (the
//! pre-trust walk: the date comes back only if the walk accepts the
//! attribute). The first attribute on which either disagrees is the
//! culprit (for an in-app purchase, the first nested attribute they
//! disagree on). Only when no single attribute shows it is the whole set
//! the culprit. The signature names where the
//! culprit is, the old reader's error on it, and OpenSSL's reason codes on
//! it (the adapter's spike-only `payload-diagnostics` feature, on in this
//! build only). Next to each filed input, `<n>.txt` holds the culprit's
//! hex, both details and the old tree's features. py/diff_classes.py
//! summarises the directory.

#[path = "../old/asn1.rs"]
mod asn1;
#[path = "../old/clock.rs"]
mod clock;
#[path = "../old/datetime.rs"]
mod datetime;
#[path = "../old/error.rs"]
mod error;
#[path = "../old/receipt_payload.rs"]
mod receipt_payload;

use apple_purchase_receipt_verifier::spike_probe;
use asn1::{parse_exact, tag, Tlv};
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

fn old_payload(data: &[u8]) -> (String, String) {
    match receipt_payload::parse_receipt_payload(data) {
        Ok(receipt) => (format!("OK {receipt:?}"), "OK".to_owned()),
        Err(err) => (format!("ERR {:?}", err.reason()), err.detail().to_owned()),
    }
}

/// What the old tree shows that the two readers are known to treat
/// differently. Walks the payload, every attribute, and (recursively) every
/// attribute value that is itself ASN.1.
fn features(data: &[u8], out: &mut BTreeSet<String>, depth: usize) {
    if depth > 4 {
        return;
    }
    let Ok(outer) = parse_exact(data) else { return };
    if outer.is_octet_string() {
        if let Some(inner) = outer.octet_string_value() {
            let inner = inner.into_owned();
            features_set(&inner, out, depth);
        }
        return;
    }
    features_node(&outer, out, depth);
}

fn features_set(bytes: &[u8], out: &mut BTreeSet<String>, depth: usize) {
    if let Ok(node) = parse_exact(bytes) {
        features_node(&node, out, depth);
    }
}

fn integer_shape(node: &Tlv<'_>) -> Option<&'static str> {
    let c = node.contents;
    if c.is_empty() {
        return Some("empty-integer");
    }
    if c.len() >= 2 && ((c[0] == 0 && c[1] < 0x80) || (c[0] == 0xff && c[1] >= 0x80)) {
        return Some("non-minimal-integer");
    }
    None
}

fn octet_nesting(node: &Tlv<'_>) -> usize {
    if !node.constructed {
        return 0;
    }
    1 + node.children().iter().map(octet_nesting).max().unwrap_or(0)
}

fn features_node(node: &Tlv<'_>, out: &mut BTreeSet<String>, depth: usize) {
    if node.tag != tag::SET {
        return;
    }
    for attribute in node.children() {
        let fields = attribute.children();
        if fields.len() > 3 {
            out.insert("attribute-with-more-than-3-fields".into());
        }
        if let Some(t) = fields.first() {
            if let Some(shape) = integer_shape(t) {
                out.insert(format!("type-{shape}"));
            }
        }
        if let Some(v) = fields.get(1) {
            match v.tag {
                tag::INTEGER => {
                    if let Some(shape) = integer_shape(v) {
                        out.insert(format!("version-{shape}"));
                    }
                }
                other => {
                    out.insert(format!("version-tag-{other:02x}"));
                }
            }
        }
        if let Some(value) = fields.get(2) {
            let nest = octet_nesting(value);
            if nest > 1 {
                out.insert(format!("value-octet-string-nesting-{}", nest.min(9)));
            }
            if let Some(bytes) = value.octet_string_value() {
                if let Ok(inner) = parse_exact(&bytes) {
                    match inner.tag {
                        tag::INTEGER => {
                            if let Some(shape) = integer_shape(&inner) {
                                out.insert(format!("value-{shape}"));
                            }
                        }
                        tag::SET | tag::OCTET_STRING | tag::OCTET_STRING_CONSTRUCTED => {
                            features(&bytes, out, depth + 1)
                        }
                        0x2c | 0x36 => {
                            out.insert("value-constructed-string".into());
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

/// Lower-cases digits away so one error text is one signature.
fn norm(detail: &str) -> String {
    detail
        .chars()
        .map(|c| if c.is_ascii_digit() { '#' } else if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

static FILED: Mutex<Option<HashMap<String, usize>>> = Mutex::new(None);

fn file(signature: &str, data: &[u8], note: &str) {
    let Ok(dir) = std::env::var("APRV_DIFF_DIR") else { return };
    let mut guard = FILED.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    let count = map.entry(signature.to_owned()).or_insert(0);
    if *count >= 50 {
        return;
    }
    *count += 1;
    let d = std::path::Path::new(&dir).join(signature);
    let _ = std::fs::create_dir_all(&d);
    let _ = std::fs::write(d.join(format!("{count:02}")), data);
    let _ = std::fs::write(d.join(format!("{count:02}.txt")), note);
}

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let bytes: Vec<u8> = n.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

fn single_set(attribute: &[u8]) -> Vec<u8> {
    let mut out = vec![tag::SET];
    out.extend(der_len(attribute.len()));
    out.extend_from_slice(attribute);
    out
}

/// `SET { attribute, creation date 2024-08-06T12:00:00Z }`.
fn with_date(attribute: &[u8]) -> Vec<u8> {
    const DATE: &[u8] = b"\x30\x1e\x02\x01\x0c\x02\x01\x01\x04\x16\x16\x142024-08-06T12:00:00Z";
    let mut body = attribute.to_vec();
    body.extend_from_slice(DATE);
    single_set(&body)
}

fn verdicts(data: &[u8]) -> (String, String, String, String) {
    (
        old_payload(data).0,
        spike_probe::payload(data),
        format!("{:?}", receipt_payload::read_creation_date(data)),
        spike_probe::creation_date(data),
    )
}

/// The set the old reader walks for `data` (unwrapping one OCTET STRING).
fn old_set(data: &[u8]) -> Result<Vec<u8>, String> {
    let outer = parse_exact(data).map_err(|e| e.to_string())?;
    if outer.is_octet_string() {
        let inner = outer.octet_string_value().ok_or("double wrap is not an OCTET STRING")?.into_owned();
        parse_exact(&inner).map_err(|e| format!("double wrap: {e}"))?;
        return Ok(inner);
    }
    Ok(data.to_vec())
}

/// Where the two readers first disagree inside `data`: a label and the
/// smallest input that still shows the disagreement.
fn locate(data: &[u8], depth: usize) -> (String, Vec<u8>) {
    let Ok(set) = old_set(data) else { return ("whole".into(), data.to_vec()) };
    let Ok(node) = parse_exact(&set) else { return ("whole".into(), data.to_vec()) };
    if node.tag != tag::SET {
        return ("whole".into(), data.to_vec());
    }
    for attribute in node.children() {
        let single = single_set(attribute.full);
        let (op, np, od, nd) = verdicts(&single);
        let dated = with_date(attribute.full);
        let (_, _, odd, ndd) = verdicts(&dated);
        if op == np && od == nd && odd == ndd {
            continue;
        }
        if op == np && od == nd {
            // Only the walk differs: file the dated form, which shows it.
            return ("attr-walk".into(), dated);
        }
        let fields = attribute.children();
        let is_in_app = fields.first().is_some_and(|t| t.contents == [17]);
        if is_in_app && depth < 2 {
            if let Some(value) = fields.get(2).and_then(Tlv::octet_string_value) {
                let (op2, np2, _, _) = verdicts(&value);
                if op2 != np2 {
                    let (inner, culprit) = locate(&value, depth + 1);
                    return (format!("in-app-{inner}"), culprit);
                }
            }
        }
        return ("attr".into(), single);
    }
    ("set".into(), data.to_vec())
}

/// The new reader's refusal on `data`: OpenSSL's reason codes when it was
/// OpenSSL that refused, else the core's detail; `ok` when it accepts.
fn new_refusal(data: &[u8]) -> String {
    let _ = aprv_security_openssl::payload::last_refusal();
    let detail = spike_probe::payload_detail(data);
    let openssl = aprv_security_openssl::payload::last_refusal();
    if detail == "OK" {
        "ok".into()
    } else if openssl.is_empty() {
        norm(&detail)
    } else {
        norm(&openssl)
    }
}

fuzz_target!(|data: &[u8]| {
    let (old_p, _old_detail) = old_payload(data);
    let new_p = spike_probe::payload(data);
    let old_d = format!("{:?}", receipt_payload::read_creation_date(data));
    let new_d = spike_probe::creation_date(data);
    if old_p == new_p && old_d == new_d {
        return;
    }
    let old_kind = if old_p.starts_with("OK") { "OK" } else { "ERR" };
    let new_kind = if new_p.starts_with("OK") { "OK" } else { "ERR" };
    let (place, culprit) = locate(data, 0);
    let old_on = match receipt_payload::parse_receipt_payload(&culprit) {
        Ok(_) => "ok".to_owned(),
        Err(err) => norm(err.detail()),
    };
    let new_on = new_refusal(&culprit);
    // Which reader's pre-trust walk found a creation date the other did not.
    let date = match (old_d == new_d, old_d.starts_with("Some"), new_d.starts_with("Some")) {
        (true, _, _) => "",
        (false, true, false) => "+date-old-only",
        (false, false, true) => "+date-new-only",
        _ => "+date-differs",
    };
    let signature: String = format!("old-{old_kind}-new-{new_kind}{date}--{place}--old-{old_on}--new-{new_on}")
        .chars()
        .take(200)
        .collect();
    let mut f = BTreeSet::new();
    features(&culprit, &mut f, 0);
    let note = format!(
        "culprit ({} bytes): {}\nold on culprit: {}\nnew on culprit: {} / {}\nold tree features: {:?}\n",
        culprit.len(),
        culprit.iter().take(400).map(|b| format!("{b:02x}")).collect::<String>(),
        old_payload(&culprit).1,
        spike_probe::payload_detail(&culprit),
        new_on,
        f
    );
    file(&signature, data, &note);
});
