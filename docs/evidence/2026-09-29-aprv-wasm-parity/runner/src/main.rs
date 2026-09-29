//! Evidence only (2026-09-29). Reads round 13's call rows (one JSON object
//! per line: `id`, `fn`, `config`, `now`, `env`, `b64`, or `id` and `map`)
//! on stdin and prints `{"id", "out"}` rows on stdout, as
//! tools/wasm-trap-host.mjs `calls` prints them for aprv.wasm, from the
//! same code the module runs, natively:
//!
//! - `init`: `aprv_wire::read_init_config`, then `aprv_surface::Verifier::new`;
//!   a refused configuration is the row's answer, as the trap host does;
//! - the three calls: the surface with `now_ms_from_u64`, then the wire.
//!
//! `now` must be pinned on every row (scripts/pin-now.py), so both sides
//! judge dateless inputs at the same instant.

use aprv_surface::{now_ms_from_u64, Environment, Verifier};
use base64::Engine as _;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let mut verifiers: HashMap<String, Result<Verifier, String>> = HashMap::new();
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        if line.trim().is_empty() {
            continue;
        }
        let row: Value = serde_json::from_str(&line).expect("a call row");
        let id = row["id"].clone();
        if let Some(map) = row.get("map") {
            writeln!(out, "{}", json!({"id": id, "map": map})).expect("stdout");
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
                let now = row["now"].as_u64().expect("now must be pinned (pin-now.py)");
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
        writeln!(out, "{}", json!({"id": id, "out": answer})).expect("stdout");
    }
}
