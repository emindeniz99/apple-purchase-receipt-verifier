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
//!
//! ```text
//! cargo run --release --locked --example bench -- --worst-case
//! ```
//!
//! times, the same way, every shared case in `fixtures/cases.json` that
//! carries a `maxMillis` budget: the hostile inputs (oversized untrusted
//! keys, certificate meshes, encoding oddities inside certificates) the
//! shared suite bounds in time. Each call is run once first and must give
//! the answer the case expects. The README's worst-case CPU figure comes
//! from this mode.

use apple_purchase_receipt_verifier::__internal::{base64_encode, decode_receipt_data};
use apple_purchase_receipt_verifier::{Config, Environment, Reason, TrustAnchor, Verifier};
use serde_json::{json, Value};
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
/// and digest `fixtures/cases.json` pins for it.
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
    let worst = std::env::args().skip(1).any(|arg| arg == "--worst-case");
    let results = if worst { worst_case() } else { cross_port() };
    let report = json!({
        "port": "rust",
        "tool": format!("examples/bench.rs {} (std::time)", if worst { "worst-case" } else { "cross-port" }),
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

fn cross_port() -> Vec<Value> {
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
        let digest: String = openssl::sha::sha256(&der)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(digest, sha256, "{name} does not match cases.json");
        let text = base64_encode(&der);
        let body = format!("{{\"receipt-data\":\"{text}\"}}");
        let tampered = base64_encode(&tamper(&der));

        // Every call once, with the answer the conformance suite expects,
        // so no benchmark can time a fast failure by accident.
        assert_eq!(
            decode_receipt_data(text.as_bytes()).ok().as_deref(),
            Some(&der[..])
        );
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
            let _ = black_box(decode_receipt_data(black_box(text.as_bytes())));
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
    results
}

/// Every shared case with a `maxMillis` budget, each checked against the
/// answer it expects and then timed.
fn worst_case() -> Vec<Value> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures");
    let file = parse(&std::fs::read_to_string(dir.join("cases.json")).expect("cases.json"));
    let registry = &file["fixtures"];
    let bytes = |id: &str| -> Vec<u8> {
        let entry = &registry[id];
        let raw = std::fs::read(dir.join(entry["path"].as_str().expect("path"))).expect("fixture");
        match entry["codec"].as_str() {
            Some("raw" | "text") => raw,
            Some("utf8") => String::from_utf8_lossy(&raw).trim().as_bytes().to_vec(),
            Some("base64") => {
                let text: String = String::from_utf8_lossy(&raw).split_whitespace().collect();
                decode_receipt_data(text.as_bytes()).expect("fixture base64")
            }
            other => panic!("fixture {id} has codec {other:?}"),
        }
    };
    let mut results = Vec::new();
    for case in file["cases"].as_array().expect("cases") {
        if case.get("maxMillis").is_none() {
            continue;
        }
        let id = case["id"].as_str().expect("id");
        let trusted = &case["config"]["trustedRoots"];
        let mut builder = Config::builder().clock(|| NOW_MILLIS);
        if trusted["source"] == "fixtures" {
            let roots = trusted["fixtures"]
                .as_array()
                .expect("root ids")
                .iter()
                .map(|root| {
                    TrustAnchor::from_der(&bytes(root.as_str().expect("root id"))).expect("root")
                });
            builder = builder.roots(roots.collect::<Vec<_>>());
        }
        let verifier = Verifier::new(builder.build().expect("config"));
        let fixture = case["input"]["fixture"].as_str().expect("fixture");
        let input = bytes(fixture);
        let operation = case["operation"].as_str().expect("operation");
        let mut op: Box<dyn FnMut() -> Option<Reason>> = match operation {
            "verifyReceipt" => {
                let text = if registry[fixture]["codec"] == "text"
                    || registry[fixture]["codec"] == "utf8"
                {
                    String::from_utf8(input).expect("UTF-8")
                } else {
                    base64_encode(&input)
                };
                Box::new(move || {
                    verifier
                        .verify_receipt(black_box(&text))
                        .err()
                        .map(|f| f.reason())
                })
            }
            "verifySignedData" => {
                let jws = String::from_utf8(input).expect("UTF-8");
                Box::new(move || {
                    verifier
                        .verify_signed_data(black_box(&jws))
                        .err()
                        .map(|f| f.reason())
                })
            }
            other => panic!("{id}: no adapter for operation {other}"),
        };

        // The answer the case expects, before anything is timed.
        let outcome = op().map_or("ok", Reason::as_str);
        let expected = &case["expected"];
        if let Some(one_of) = expected["oneOf"].as_array() {
            assert!(
                one_of.iter().any(|o| o == outcome),
                "{id} answered {outcome}"
            );
        } else if expected["status"] == "ok" {
            assert_eq!(outcome, "ok", "{id}");
        } else {
            assert_eq!(Some(outcome), expected["reason"].as_str(), "{id}");
        }
        results.push(measure(operation, id, &mut || {
            black_box(op());
        }));
    }
    results
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
    decode_receipt_data(text.trim().as_bytes()).expect("fixture base64")
}
