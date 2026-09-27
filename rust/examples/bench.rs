//! The cross-port benchmark: the same six operations on the same two genuine
//! sandbox receipts in every port, named after the Java JMH benchmarks in
//! `java-bench/` (`BENCHMARKS.md` at the repository root has the table).
//!
//! ```text
//! cargo run --release --locked --example bench > rust-bench.json
//! ```
//!
//! A plain example with `std::time` rather than criterion: criterion would
//! add a few dozen crates to the lockfile this crate publishes, each subject
//! to `deny.toml` and the 1.85.0 MSRV leg, for a benchmark run by hand.
//! Each benchmark warms up for one second, then takes ten samples of at
//! least 100 ms each; the JSON on stdout carries the median, minimum and
//! maximum microseconds per operation over those samples.

use apple_purchase_receipt_verifier::__internal::{base64_encode, decode_receipt_data};
use apple_purchase_receipt_verifier::{Config, Environment, Reason, Verifier};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const WARMUP: Duration = Duration::from_secs(1);
const SAMPLES: usize = 10;
const MIN_SAMPLE: Duration = Duration::from_millis(100);

/// Any fixed instant (2026-01-01T00:00:00Z): it only feeds `request_date`,
/// since both fixtures carry a creation date.
const NOW_MILLIS: i64 = 1_767_225_600_000;

/// File under `fixtures/public-receipts`, and the bundle id, in-app count
/// and digest `fixtures/cases-0.7.json` pins for it.
const FIXTURES: [(&str, &str, usize, &str); 2] = [
    (
        "receipt-sandbox-g5",
        "dev.bonzer.weeka.app",
        2,
        "bebb16e2a17104d973eeef08177003f2c3303a19ddced83b42df349b4ac25ee0",
    ),
    (
        "receipt-sandbox-legacy",
        "com.nutcall.alert",
        187,
        "ec62c6bd4a34bd8e56b11e675bf5a28319ce69b71d050e73344bab22f46799a8",
    ),
];

fn main() {
    // The roots are parsed once, here, and never per call.
    let verifier = Verifier::new(
        Config::builder()
            .clock(|| NOW_MILLIS)
            .build()
            .expect("config"),
    );
    let mut results = Vec::new();
    for (name, bundle_id, in_app_count, sha256) in FIXTURES {
        let der = read_fixture(name);
        let digest: String = Sha256::digest(&der)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(digest, sha256, "{name} does not match cases-0.7.json");
        let text = base64_encode(&der);
        let body = format!("{{\"receipt-data\":\"{text}\"}}");
        let tampered = base64_encode(&tamper(&der));

        // Every call once, with the answer the conformance suite expects,
        // so no benchmark can time a fast failure by accident.
        assert_eq!(decode_receipt_data(&text).ok().as_deref(), Some(&der[..]));
        let receipt = verifier.verify_receipt(&text).expect("verifyReceipt");
        assert_eq!(receipt.bundle_id.as_deref(), Some(bundle_id));
        assert_eq!(receipt.in_app.len(), in_app_count);
        let ok = parse(&verifier.verify_receipt_endpoint(Environment::Sandbox, &body));
        assert_eq!(ok["status"], 0, "endpointJson");
        assert_eq!(
            ok["receipt"]["in_app"].as_array().map(Vec::len),
            Some(in_app_count)
        );
        let first = parse(&verifier.verify_receipt_endpoint(Environment::Production, &body));
        assert_eq!(first["status"], 21007, "retryViaResult first call");
        let rejected = verifier.verify_receipt(&tampered).expect_err("tampered");
        assert_eq!(rejected.reason(), Reason::InvalidSignature);

        let mut run = |benchmark: &str, op: &mut dyn FnMut()| {
            results.push(measure(benchmark, name, op));
        };
        run("decodeBase64", &mut || {
            let _ = black_box(decode_receipt_data(black_box(&text)));
        });
        // 0.7 has no DER entry point: "core" and "verifierBase64" are both
        // verify_receipt over the base64, so both include the decode that
        // 0.6's "core" did not.
        run("core", &mut || {
            let _ = black_box(verifier.verify_receipt(black_box(&text)));
        });
        run("verifierBase64", &mut || {
            let _ = black_box(verifier.verify_receipt(black_box(&text)));
        });
        run("endpointJson", &mut || {
            black_box(verifier.verify_receipt_endpoint(Environment::Sandbox, black_box(&body)));
        });
        // 21007 on PRODUCTION, then the caller's second, offline call on
        // SANDBOX, as the design routes it.
        run("retryViaResult", &mut || {
            black_box(verifier.verify_receipt_endpoint(Environment::Production, black_box(&body)));
            black_box(verifier.verify_receipt_endpoint(Environment::Sandbox, black_box(&body)));
        });
        run("rejectTamperedSignature", &mut || {
            let _ = black_box(verifier.verify_receipt(black_box(&tampered)));
        });
    }
    let report = json!({
        "port": "rust",
        "tool": "examples/bench.rs (std::time)",
        "settings": {
            "warmup_s": WARMUP.as_secs_f64(),
            "samples": SAMPLES,
            "min_sample_s": MIN_SAMPLE.as_secs_f64(),
        },
        "results": results,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize")
    );
}

/// Warm up, size a sample to at least `MIN_SAMPLE`, then time `SAMPLES`
/// samples and report microseconds per operation.
fn measure(benchmark: &str, fixture: &str, op: &mut dyn FnMut()) -> Value {
    let start = Instant::now();
    let mut warmup_ops: u32 = 0;
    while start.elapsed() < WARMUP {
        op();
        warmup_ops += 1;
    }
    let per_op = start.elapsed() / warmup_ops;
    let ops = u32::try_from(MIN_SAMPLE.as_nanos() / per_op.as_nanos().max(1) + 1).unwrap_or(1);
    let mut samples: Vec<f64> = (0..SAMPLES)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..ops {
                op();
            }
            t.elapsed().as_secs_f64() * 1e6 / f64::from(ops)
        })
        .collect();
    samples.sort_by(f64::total_cmp);
    let median = (samples[SAMPLES / 2 - 1] + samples[SAMPLES / 2]) / 2.0;
    eprintln!("{benchmark:>24} {fixture:<24} {median:>12.1} us/op");
    json!({
        "benchmark": benchmark,
        "fixture": fixture,
        "us_per_op_median": median,
        "us_per_op_min": samples[0],
        "us_per_op_max": samples[SAMPLES - 1],
        "ops_per_sample": ops,
    })
}

/// Flips one bit in the middle of the SignerInfo signature, the byte
/// `java-bench`'s `flipSignatureByte` flips. In both fixtures the signature
/// is a 256-byte OCTET STRING that ends the DER (`openssl asn1parse` shows
/// it), so its middle byte is 128 from the end; setup proves the flip landed
/// there by requiring `INVALID_SIGNATURE`.
fn tamper(der: &[u8]) -> Vec<u8> {
    let mut tampered = der.to_vec();
    let at = tampered.len() - 128;
    tampered[at] ^= 0x01;
    tampered
}

fn parse(body: &str) -> Value {
    serde_json::from_str(body).expect("JSON body")
}

fn read_fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/public-receipts")
        .join(format!("{name}.b64"));
    let text = std::fs::read_to_string(&path).expect("fixture");
    decode_receipt_data(text.trim()).expect("fixture base64")
}
