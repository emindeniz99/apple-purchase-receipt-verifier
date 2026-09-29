//! Evidence only. Reads an ABI v1 call file (one JSON object per line:
//! `id`, `op`, `input` as base64, `map`) and prints one row per call,
//! `{"id", "out"}`, computed with the 0.7 public API only:
//!
//! - op 1 (receipt): `Verifier::verify_receipt` on the receipt-data string;
//! - op 2 (JWS): `Verifier::verify_signed_data`;
//! - ops 3 and 4: `Verifier::verify_receipt_endpoint`, Production and
//!   Sandbox.
//!
//! An op above 256 carries the spike test envelope ("APRVT1" | u32le
//! count | (u32le len | DER)* | i64le now, i64::MIN for none | body):
//! the roots replace Apple's, and a pinned now becomes the clock. `out`
//! is canonical JSON: `verified` with `payload` (a receipt's `to_json`)
//! or `payloadJson` (a JWS payload's text), or `reason` and `message`; an
//! endpoint's answer under `endpoint`, its request_date* fields masked
//! when no clock is pinned; `error` for a call the API cannot take.

use aprv::{Config, Environment, TrustAnchor, Verifier};
use base64::Engine;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

fn take_u32(b: &[u8]) -> Option<(usize, &[u8])> {
    let (n, r) = b.split_at_checked(4)?;
    Some((u32::from_le_bytes(n.try_into().ok()?) as usize, r))
}

fn envelope(bytes: &[u8]) -> Option<(Vec<Vec<u8>>, Option<i64>, &[u8])> {
    let mut rest = bytes.strip_prefix(b"APRVT1")?;
    let (count, r) = take_u32(rest)?;
    rest = r;
    let mut roots = Vec::new();
    for _ in 0..count {
        let (len, r) = take_u32(rest)?;
        let (der, r) = r.split_at_checked(len)?;
        roots.push(der.to_vec());
        rest = r;
    }
    let (now, body) = rest.split_at_checked(8)?;
    let now = i64::from_le_bytes(now.try_into().ok()?);
    Some((roots, (now != i64::MIN).then_some(now), body))
}

fn mask(response: &str) -> Value {
    let mut doc: Value =
        serde_json::from_str(response).unwrap_or(Value::String(response.to_owned()));
    if let Some(receipt) = doc.get_mut("receipt").and_then(Value::as_object_mut) {
        for key in ["request_date", "request_date_ms", "request_date_pst"] {
            receipt.remove(key);
        }
    }
    doc
}

fn out(op: i64, input: &[u8]) -> Value {
    let (base, roots, now, body) = if op > 256 {
        match envelope(input) {
            Some((roots, now, body)) => (op - 256, roots, now, body),
            None => return json!({"error": "INVALID_TEST_ENVELOPE"}),
        }
    } else {
        (op, Vec::new(), None, input)
    };
    let mut builder = Config::builder();
    if !roots.is_empty() {
        let mut anchors = Vec::new();
        for der in &roots {
            match TrustAnchor::from_der(der) {
                Ok(anchor) => anchors.push(anchor),
                Err(err) => return json!({"error": "CONFIGURATION", "message": err.to_string()}),
            }
        }
        builder = builder.roots(anchors);
    }
    if let Some(now) = now {
        builder = builder.clock(move || now);
    }
    let verifier = match builder.build() {
        Ok(config) => Verifier::new(config),
        Err(err) => return json!({"error": "CONFIGURATION", "message": err.to_string()}),
    };
    let Ok(text) = std::str::from_utf8(body) else {
        if base >= 3 {
            let lossy = String::from_utf8_lossy(body);
            let env = if base == 3 {
                Environment::Production
            } else {
                Environment::Sandbox
            };
            return json!({"endpoint": mask(&verifier.verify_receipt_endpoint(env, &lossy))});
        }
        return json!({"error": "NOT_UTF8"});
    };
    match base {
        1 => match verifier.verify_receipt(text) {
            Ok(receipt) => {
                json!({"verified": true, "payload": serde_json::from_str::<Value>(&receipt.to_json()).unwrap()})
            }
            Err(f) => {
                json!({"verified": false, "reason": f.reason().as_str(), "message": f.message()})
            }
        },
        2 => match verifier.verify_signed_data(text) {
            Ok(payload) => json!({"verified": true, "payloadJson": payload.json()}),
            Err(f) => {
                json!({"verified": false, "reason": f.reason().as_str(), "message": f.message()})
            }
        },
        3 | 4 => {
            let env = if base == 3 {
                Environment::Production
            } else {
                Environment::Sandbox
            };
            let answer = verifier.verify_receipt_endpoint(env, text);
            json!({"endpoint": if now.is_some() { serde_json::from_str(&answer).unwrap_or(Value::String(answer)) } else { mask(&answer) }})
        }
        _ => json!({"error": "UNKNOWN_OP"}),
    }
}

fn main() {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let call: Value = serde_json::from_str(&line).unwrap();
        let id = call["id"].clone();
        let row = match call.get("op").and_then(Value::as_i64) {
            None => json!({"id": id, "out": {"skip": call["map"]}}),
            Some(op) => {
                let input = base64::engine::general_purpose::STANDARD
                    .decode(call["input"].as_str().unwrap_or_default())
                    .unwrap();
                json!({"id": id, "out": out(op, &input)})
            }
        };
        writeln!(stdout, "{row}").unwrap();
    }
}
