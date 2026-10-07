//! The wire schemas (`schema/`, JSON Schema 2020-12) against what this
//! crate writes and against the shared contract, `fixtures/cases.json`.
//!
//! A schema that accepts everything would pass the first two tests alone,
//! so the third plants one wrong type per rule and requires a refusal.

use aprv_surface::{Failure, Reason, Verifier};
use base64::Engine as _;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMAS: [&str; 4] = [
    "verify-receipt-result.schema.json",
    "verify-signed-data-result.schema.json",
    "init-config.schema.json",
    "init-result.schema.json",
];

fn schema_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("schema")
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fixtures")
}

fn read_json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn validator(name: &str) -> jsonschema::Validator {
    let schema = read_json(&schema_dir().join(name));
    jsonschema::draft202012::new(&schema).unwrap_or_else(|e| panic!("{name} does not compile: {e}"))
}

/// Validates `answer` (JSON text) against `schema`, naming what failed.
fn check(schema: &jsonschema::Validator, name: &str, what: &str, answer: &str) {
    let value: Value =
        serde_json::from_str(answer).unwrap_or_else(|e| panic!("{what}: not JSON ({e}): {answer}"));
    let errors: Vec<String> = schema.iter_errors(&value).map(|e| e.to_string()).collect();
    assert!(
        errors.is_empty(),
        "{what}: does not validate against {name}: {errors:?}\n{answer}"
    );
}

fn standard(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The shared cases and their fixtures, read the way every port's runner
/// reads them.
struct Cases {
    doc: Value,
}

impl Cases {
    fn load() -> Cases {
        Cases {
            doc: read_json(&fixtures_dir().join("cases.json")),
        }
    }

    fn cases(&self) -> &[Value] {
        self.doc["cases"].as_array().expect("cases")
    }

    fn fixture(&self, id: &str) -> Vec<u8> {
        let entry = &self.doc["fixtures"][id];
        let path = fixtures_dir().join(entry["path"].as_str().expect("path"));
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        match entry["codec"].as_str().expect("codec") {
            "raw" | "text" => raw,
            "utf8" => String::from_utf8(raw)
                .expect("utf8")
                .trim()
                .as_bytes()
                .to_vec(),
            "base64" => {
                let text: String = String::from_utf8(raw)
                    .expect("ascii")
                    .split_whitespace()
                    .collect();
                base64::engine::general_purpose::STANDARD
                    .decode(text)
                    .expect("base64 fixture")
            }
            other => panic!("unknown codec {other}"),
        }
    }

    /// A receipt fixture as the `receipt-data` text a client sends.
    fn receipt_text(&self, id: &str) -> Vec<u8> {
        match self.doc["fixtures"][id]["codec"].as_str() {
            Some("raw" | "base64") => standard(&self.fixture(id)).into_bytes(),
            _ => self.fixture(id),
        }
    }

    /// The case's roots, as DER: empty for the defaults.
    fn roots(&self, case: &Value) -> Vec<Vec<u8>> {
        let spec = &case["config"]["trustedRoots"];
        if spec.is_null() || spec["source"] == "defaults" {
            return Vec::new();
        }
        spec["fixtures"]
            .as_array()
            .expect("fixtures")
            .iter()
            .map(|id| self.fixture(id.as_str().expect("id")))
            .collect()
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` as epoch milliseconds (the form cases.json pins).
fn instant(text: &str) -> i64 {
    let n = |range: std::ops::Range<usize>| -> i64 { text[range].parse().expect("digits") };
    let (y, m, d) = (n(0..4), n(5..7), n(8..10));
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    ((days * 24 + n(11..13)) * 60 + n(14..16)) * 60_000 + n(17..19) * 1000
}

fn now(case: &Value) -> i64 {
    match case["clock"]["now"].as_str() {
        Some(text) => instant(text),
        None => i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("after 1970")
                .as_millis(),
        )
        .expect("fits"),
    }
}

#[test]
fn the_four_schemas_are_json_schema_2020_12_with_their_ids() {
    for name in SCHEMAS {
        let schema = read_json(&schema_dir().join(name));
        assert_eq!(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema",
            "{name}"
        );
        let id = schema["$id"].as_str().expect("$id");
        assert!(
            id.ends_with(&format!("/rust/bindings/wire/schema/{name}")),
            "{name}: {id}"
        );
        validator(name);
    }
    let files: Vec<String> = std::fs::read_dir(schema_dir())
        .expect("schema/")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("name")
        })
        .collect();
    assert_eq!(
        files.len(),
        SCHEMAS.len(),
        "schema/ holds exactly the four: {files:?}"
    );
}

#[test]
fn every_answer_to_every_shared_case_validates() {
    let receipt_schema = validator(SCHEMAS[0]);
    let jws_schema = validator(SCHEMAS[1]);
    let config_schema = validator(SCHEMAS[2]);
    let init_schema = validator(SCHEMAS[3]);
    let cases = Cases::load();
    let mut counts = [0_usize; 4];
    for case in cases.cases() {
        let id = case["id"].as_str().expect("id");
        let roots = cases.roots(case);
        // `{}` is the one spelling of the Apple roots; an empty list is refused.
        let config = if roots.is_empty() {
            json!({})
        } else {
            json!({"roots": roots.iter().map(|der| standard(der)).collect::<Vec<_>>()})
        };
        let config = config.to_string();
        check(&config_schema, SCHEMAS[2], id, &config);
        let made = aprv_wire::read_init_config(config.as_bytes())
            .and_then(|roots| Verifier::new(&roots).map_err(|error| error.message));
        let init = aprv_wire::init_result(&made.as_ref().map(|_| ()).map_err(Clone::clone));
        check(&init_schema, SCHEMAS[3], id, &init);
        counts[2] += 1;
        let verifier = made.unwrap_or_else(|message| panic!("{id}: init refused: {message}"));
        let at = now(case);
        match case["operation"].as_str().expect("operation") {
            "verifyReceipt" => {
                let input = cases.receipt_text(case["input"]["fixture"].as_str().expect("fixture"));
                let answer = aprv_wire::verify_receipt_result(&verifier.verify_receipt(&input, at));
                check(&receipt_schema, SCHEMAS[0], id, &answer);
                counts[0] += 1;
            }
            "verifySignedData" => {
                let input = cases.fixture(case["input"]["fixture"].as_str().expect("fixture"));
                let answer =
                    aprv_wire::verify_signed_data_result(&verifier.verify_signed_data(&input, at));
                check(&jws_schema, SCHEMAS[1], id, &answer);
                counts[1] += 1;
            }
            // Through the ABI a receipt-data text runs through verify-receipt,
            // an x5c text through a JWS header: both answers are wire results.
            "decodeBase64" => {
                for text in case["input"]["texts"].as_array().expect("texts") {
                    let text = text.as_str().expect("text").as_bytes();
                    let answer =
                        aprv_wire::verify_receipt_result(&verifier.verify_receipt(text, at));
                    check(&receipt_schema, SCHEMAS[0], id, &answer);
                    counts[0] += 1;
                }
            }
            // Apple's response format, not ours: no schema (DECISIONS.md R34).
            "verifyReceiptEndpoint" => counts[3] += 1,
            other => panic!("{id}: unknown operation {other}"),
        }
    }
    assert_eq!(counts[2], cases.cases().len());
    assert!(counts[0] > 200 && counts[1] > 90, "{counts:?}");
}

#[test]
fn every_expected_value_in_the_shared_cases_fits_the_schemas() {
    let receipt_schema = validator(SCHEMAS[0]);
    let jws_schema = validator(SCHEMAS[1]);
    let cases = Cases::load();
    let mut payloads = 0;
    for case in cases.cases() {
        let id = case["id"].as_str().expect("id");
        let expected = &case["expected"];
        // A receipt's pinned toJson value and environment, as a verified
        // answer.
        if let Some(to_json) = expected["toJson"].as_str() {
            let environment = &expected["environment"];
            let answer = format!(
                "{{\"verified\":true,\"payload\":{to_json},\"environment\":{environment}}}"
            );
            check(&receipt_schema, SCHEMAS[0], id, &answer);
            payloads += 1;
        }
        // Every reason a case names, as a failure answer of both kinds.
        let mut reasons: Vec<&str> = expected["reason"].as_str().into_iter().collect();
        if let Some(one_of) = expected["oneOf"].as_array() {
            reasons.extend(
                one_of
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|r| *r != "ok"),
            );
        }
        for token in reasons {
            let reason = Reason::from_token(token)
                .unwrap_or_else(|| panic!("{id}: {token} is not one of the eight"));
            let failure = Failure {
                reason,
                message: String::new(),
            };
            check(
                &receipt_schema,
                SCHEMAS[0],
                id,
                &aprv_wire::verify_receipt_result(&Err(failure.clone())),
            );
            check(
                &jws_schema,
                SCHEMAS[1],
                id,
                &aprv_wire::verify_signed_data_result(&Err(failure)),
            );
        }
    }
    assert_eq!(payloads, 11, "the eleven toJson vectors");
}

#[test]
fn a_planted_wrong_type_fails_every_rule() {
    let receipt = r#"{"receipt_type":"ProductionSandbox","app_item_id":"0","bundle_id":"a","bundle_id_bytes":"DAFh","application_version":"1","opaque_value":"AQ==","sha1_hash":"AQI=","receipt_creation_date_ms":1722945600000,"download_id":"-5","version_external_identifier":null,"in_app":[{"quantity":1,"product_id":"p","transaction_id":"1","purchase_date_ms":1000,"original_transaction_id":"1","original_purchase_date_ms":null,"expires_date_ms":null,"web_order_line_item_id":"0","cancellation_date_ms":null,"is_trial_period":false,"is_in_intro_offer_period":null,"unknown_attributes":{}}],"original_purchase_date_ms":null,"preorder_date_ms":null,"original_application_version":null,"expiration_date_ms":null,"unknown_attributes":{"13":["AA=="]}}"#;
    let good = format!("{{\"verified\":true,\"payload\":{receipt},\"environment\":\"Sandbox\"}}");
    let receipt_schema = validator(SCHEMAS[0]);
    check(&receipt_schema, SCHEMAS[0], "the control", &good);
    let plants = [
        ("\"verified\":true", "\"verified\":\"true\""),
        ("\"app_item_id\":\"0\"", "\"app_item_id\":0"),
        ("\"download_id\":\"-5\"", "\"download_id\":\"-05\""),
        (
            "\"receipt_creation_date_ms\":1722945600000",
            "\"receipt_creation_date_ms\":\"1722945600000\"",
        ),
        (
            "\"receipt_creation_date_ms\":1722945600000",
            "\"receipt_creation_date_ms\":1.5",
        ),
        ("\"sha1_hash\":\"AQI=\"", "\"sha1_hash\":\"AQI\""),
        ("\"opaque_value\":\"AQ==\"", "\"opaque_value\":\"AQ-_\""),
        ("\"is_trial_period\":false", "\"is_trial_period\":0"),
        ("\"quantity\":1", "\"quantity\":\"1\""),
        (
            "\"unknown_attributes\":{\"13\":",
            "\"unknown_attributes\":{\"x13\":",
        ),
        (
            "\"unknown_attributes\":{\"13\":[\"AA==\"]",
            "\"unknown_attributes\":{\"13\":\"AA==\"",
        ),
        ("\"purchase_date_ms\":1000", "\"purchase_date_ms\":1000.5"),
        (
            "\"unknown_attributes\":{\"13\":",
            "\"unknown_attributes\":{\"4294967296\":",
        ),
        (
            "\"unknown_attributes\":{\"13\":",
            "\"unknown_attributes\":{\"42949672950\":",
        ),
        ("\"version_external_identifier\":null,", ""),
        (",\"environment\":\"Sandbox\"", ""),
        ("\"environment\":\"Sandbox\"", "\"environment\":\"sandbox\""),
        ("\"environment\":\"Sandbox\"", "\"environment\":\"Xcode\""),
        ("\"bundle_id\":\"a\"", "\"bundle_id\":\"a\",\"adam_id\":0"),
    ];
    for (from, to) in plants {
        assert!(good.contains(from), "{from}");
        let planted: Value = serde_json::from_str(&good.replacen(from, to, 1)).expect("json");
        assert!(!receipt_schema.is_valid(&planted), "accepted {to}");
    }
    // The edges of the tightened rules still validate: the largest
    // attribute type, and a whole second before the epoch.
    for (from, to) in [
        (
            "\"unknown_attributes\":{\"13\":",
            "\"unknown_attributes\":{\"4294967295\":",
        ),
        ("\"purchase_date_ms\":1000", "\"purchase_date_ms\":-1000"),
    ] {
        let edge: Value = serde_json::from_str(&good.replacen(from, to, 1)).expect("json");
        assert!(receipt_schema.is_valid(&edge), "refused {to}");
    }
    let failure_plants = [
        r#"{"verified":false,"reason":"INVALID_CHAIN","message":"m"}"#,
        r#"{"verified":false,"reason":"MALFORMED"}"#,
        r#"{"verified":false,"reason":"MALFORMED","message":"m","payload":null}"#,
        r#"{"verified":true,"reason":"MALFORMED","message":"m"}"#,
    ];
    let jws_schema = validator(SCHEMAS[1]);
    for planted in failure_plants {
        let planted: Value = serde_json::from_str(planted).expect("json");
        assert!(!receipt_schema.is_valid(&planted), "{planted}");
        assert!(!jws_schema.is_valid(&planted), "{planted}");
    }
    for environment in [json!("Production"), json!("Sandbox"), Value::Null] {
        assert!(jws_schema
            .is_valid(&json!({"verified": true, "payload": "{}", "environment": environment})));
    }
    for planted in [
        json!({"verified": true, "payload": {}, "environment": null}),
        json!({"verified": true, "payload": "{}"}),
        json!({"verified": true, "payload": "{}", "environment": "LocalTesting"}),
    ] {
        assert!(!jws_schema.is_valid(&planted), "{planted}");
    }
    let config = validator(SCHEMAS[2]);
    assert!(config.is_valid(&json!({})) && config.is_valid(&json!({"roots": ["AQID"]})));
    for planted in [
        json!({"roots": [1]}),
        json!({"roots": "AQID"}),
        json!({"root": []}),
        json!({"roots": ["AQ"]}),
        json!({"roots": []}),
    ] {
        assert!(!config.is_valid(&planted), "{planted}");
    }
    let init = validator(SCHEMAS[3]);
    assert!(
        init.is_valid(&json!({"ok": true, "max_input_bytes": 3_145_729}))
            && init.is_valid(&json!({"ok": false, "message": "m"}))
    );
    for planted in [
        json!({"ok": false}),
        json!({"ok": true}),
        json!({"ok": true, "max_input_bytes": "3145729"}),
        json!({"ok": true, "max_input_bytes": 0}),
        json!({"ok": true, "max_input_bytes": 3_145_729, "message": "m"}),
        json!({"ok": false, "max_input_bytes": 3_145_729, "message": "m"}),
        json!({"ok": "true", "max_input_bytes": 3_145_729}),
    ] {
        assert!(!init.is_valid(&planted), "{planted}");
    }
}
