//! Evidence only (2026-10-05). The native twin of aprv.wasm over a corpus
//! call file, as a test of `rust/ffi` so it builds in the workspace's own
//! target directory: copy it to `rust/ffi/tests/corpus_replay.rs`, set
//! `APRV_CALLS` (a pinned call file of the corpus archive
//! `fixtures/corpus.json` names) and `APRV_ROWS` (where the rows go), and
//! run `cargo test -p apple-purchase-receipt-verifier-ffi --test
//! corpus_replay`. Without `APRV_CALLS` it does nothing.
//!
//! The body is `docs/evidence/2026-09-29-aprv-wasm-parity/runner/src/main.rs`
//! over files instead of stdin and stdout: the same four calls of
//! aprv-surface, answered as aprv-wire documents, one `{"id", "out"}` row
//! per call, as `tools/wasm-trap-host.mjs calls` prints them for the module.

use aprv_surface::{now_ms_from_u64, Environment, Verifier};
use base64::Engine as _;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, BufWriter, Write};

#[test]
fn corpus_replay() {
    let (Ok(calls), Ok(rows)) = (std::env::var("APRV_CALLS"), std::env::var("APRV_ROWS")) else {
        return;
    };
    let input = BufReader::new(std::fs::File::open(&calls).expect("APRV_CALLS"));
    let mut out = BufWriter::new(std::fs::File::create(&rows).expect("APRV_ROWS"));
    let mut verifiers: HashMap<String, Result<Verifier, String>> = HashMap::new();
    for line in input.lines() {
        let line = line.expect("a line");
        if line.trim().is_empty() {
            continue;
        }
        let row: Value = serde_json::from_str(&line).expect("a call row");
        let id = row["id"].clone();
        if let Some(map) = row.get("map") {
            writeln!(out, "{}", json!({"id": id, "map": map})).expect("rows");
            continue;
        }
        let config = row["config"].as_str().expect("config").to_owned();
        let verifier = verifiers.entry(config.clone()).or_insert_with(|| {
            aprv_wire::read_init_config(config.as_bytes())
                .and_then(|roots| Verifier::new(&roots).map_err(|error| error.message))
        });
        let answer = match verifier {
            Err(message) => aprv_wire::init_result(&Err(message.clone())),
            Ok(verifier) => {
                let input = base64::engine::general_purpose::STANDARD
                    .decode(row["b64"].as_str().expect("b64"))
                    .expect("base64");
                let now = row["now"].as_u64().expect("now must be pinned");
                match row["fn"].as_str().expect("fn") {
                    "verify-receipt" => aprv_wire::verify_receipt_result(
                        &now_ms_from_u64(now).and_then(|n| verifier.verify_receipt(&input, n)),
                    ),
                    "verify-signed-data" => aprv_wire::verify_signed_data_result(
                        &now_ms_from_u64(now).and_then(|n| verifier.verify_signed_data(&input, n)),
                    ),
                    "verify-receipt-endpoint" => {
                        let env = match row["env"].as_u64() {
                            Some(0) => Environment::Production,
                            Some(1) => Environment::Sandbox,
                            other => panic!("env {other:?}"),
                        };
                        match now_ms_from_u64(now) {
                            Ok(n) => verifier.verify_receipt_endpoint(env, &input, n),
                            Err(_) => aprv_surface::endpoint_internal_error(),
                        }
                    }
                    other => panic!("fn {other}"),
                }
            }
        };
        writeln!(out, "{}", json!({"id": id, "out": answer})).expect("rows");
    }
}
