//! Spike only (round 4). Copied into both scratch trees as
//! `rust/examples/spike_payload.rs`. For every receipt file named on the
//! command line (DER `*.der`, anything else read as base64 text), takes the
//! CMS eContent the way the verifier does (the adapter's
//! `SignedData::parse(..).content()`, OpenSSL 4.0.2 CMS) and prints, tab
//! separated: file name, content length, what `read_creation_date` returns,
//! and what `parse_receipt_payload` returns. `--raw` treats each file as the
//! payload itself (the fuzz corpora); `--der` reads every file as DER
//! whatever its name. `--dump=DIR` also writes each eContent to
//! DIR/<file stem>. Run it in both trees and diff.
//!
//!   cargo run --release --example spike_payload --features substrate-cms -- [--raw|--der] [--dump=DIR] FILE...

use apple_purchase_receipt_verifier::{base64, spike_probe};
use aprv_security_openssl::SignedData;
use std::path::Path;

fn main() {
    let mut raw = false;
    let mut all_der = false;
    let mut dump: Option<String> = None;
    for arg in std::env::args().skip(1) {
        if arg == "--raw" {
            raw = true;
            continue;
        }
        if arg == "--der" {
            all_der = true;
            continue;
        }
        if let Some(dir) = arg.strip_prefix("--dump=") {
            dump = Some(dir.to_owned());
            continue;
        }
        let bytes = std::fs::read(&arg).expect("readable file");
        let name = Path::new(&arg).file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let content = if raw {
            Some(bytes)
        } else {
            let der = if all_der || arg.ends_with(".der") {
                bytes
            } else {
                let text: String = String::from_utf8_lossy(&bytes).split_whitespace().collect();
                base64::decode_receipt_base64(&text).unwrap_or_default()
            };
            SignedData::parse(&der).ok().map(|cms| cms.content())
        };
        match content {
            None => println!("{name}\t-\tnot a signedData\t-"),
            Some(content) => {
                if let Some(dir) = &dump {
                    let stem = name.split('.').next().unwrap_or(&name);
                    std::fs::write(Path::new(dir).join(stem), &content).expect("writable dump dir");
                }
                println!(
                "{name}\t{}\t{}\t{}",
                content.len(),
                spike_probe::creation_date(&content),
                spike_probe::payload(&content)
            );
            }
        }
    }
}
