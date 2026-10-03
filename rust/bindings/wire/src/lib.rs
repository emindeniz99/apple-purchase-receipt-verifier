//! The 0.7 canonical JSON bytes of [`aprv_surface`]'s values, and the
//! reader of `aprv.wasm`'s `init` configuration.
//!
//! The C ABI and `aprv.wasm` both write through this crate, so the two
//! boundaries hand out the same bytes. The shapes, each described by a JSON
//! Schema 2020-12 file in `schema/`:
//!
//! | Shape | Schema |
//! |---|---|
//! | the answer of `verify-receipt` | `verify-receipt-result.schema.json` |
//! | the answer of `verify-signed-data` | `verify-signed-data-result.schema.json` |
//! | the argument of `init` | `init-config.schema.json` |
//! | the answer of `init` | `init-result.schema.json` |
//!
//! `verify-receipt-endpoint` answers Apple's response JSON, byte for byte
//! as the core writes it, and has no schema of ours (DECISIONS.md R34).
//!
//! The rules of 0.7's "Our JSON" (docs/design/0.7-api.md), as written here:
//!
//! - a verified result is exactly
//!   `{"verified":true,"payload":...,"environment":...}`, the environment
//!   `"Production"`, `"Sandbox"` or `null` as the core states it, a
//!   failure exactly `{"verified":false,"reason":"<TOKEN>","message":"..."}`,
//!   with no other member;
//! - 64-bit ids are JSON strings holding a decimal `i64`; dates are
//!   epoch-millisecond numbers; bytes are padded standard base64; a missing
//!   field is `null`, never omitted; booleans are JSON booleans;
//! - `unknown_attributes` is an object keyed by the decimal attribute type,
//!   in ascending order, each value a list of base64 strings in receipt
//!   order;
//! - a verified JWS's `payload` is a JSON string holding the signed
//!   payload's text, so no host re-serialises Apple's claims;
//! - keys come in the order the 0.7 table lists them, strings escape only
//!   `"`, `\` and the C0 controls, and non-ASCII is written raw. One fixed
//!   byte form, although consumers compare by value.
//!
//! A failure's `message` is the core's, unchanged. Two of them are a stable
//! hook the hosts' runners rely on (see [`aprv_surface::Failure`]): a
//! refused `receipt-data` text carries `receipt is not valid base64`, a
//! refused `x5c` entry `x5c entry is not valid base64`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use aprv_surface::{
    Environment, Failure, InAppPurchase, JsonPayload, ReceiptPayload, UnknownAttributes,
};
use serde::ser::{SerializeStruct as _, Serializer};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------- writer

/// `value` as JSON text. `serde_json` escapes `"`, `\` and U+0000 to U+001F
/// and writes everything else raw, and a struct's members come in the
/// order they are serialised.
fn to_json(value: &impl Serialize) -> String {
    // Nothing here can fail to serialise: every map key is an integer,
    // which serde_json writes as a string, and no impl below returns an
    // error. Were it to, the empty answer is unreadable JSON, which every
    // host reports as INTERNAL_ERROR rather than as a verdict.
    serde_json::to_string(value).unwrap_or_default()
}

/// A 64-bit id: a string holding the decimal value, so no JavaScript
/// reader rounds it.
struct Id(i64);

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

/// Bytes as padded standard base64.
struct Base64<'a>(&'a [u8]);

impl Serialize for Base64<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use base64::Engine as _;
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(self.0))
    }
}

/// `unknown_attributes`: an object keyed by the decimal attribute type, in
/// the surface's (ascending) order, each value a list of base64 strings.
struct Attributes<'a>(&'a UnknownAttributes);

impl Serialize for Attributes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.0.iter().map(|(attribute_type, values)| {
            let values: Vec<Base64<'_>> = values.iter().map(|value| Base64(value)).collect();
            (attribute_type, values)
        }))
    }
}

struct Purchase<'a>(&'a InAppPurchase);

impl Serialize for Purchase<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let purchase = self.0;
        let mut object = serializer.serialize_struct("InAppPurchase", 12)?;
        object.serialize_field("quantity", &purchase.quantity)?;
        object.serialize_field("product_id", &purchase.product_id)?;
        object.serialize_field("transaction_id", &purchase.transaction_id)?;
        object.serialize_field("purchase_date_ms", &purchase.purchase_date_ms)?;
        object.serialize_field("original_transaction_id", &purchase.original_transaction_id)?;
        object.serialize_field(
            "original_purchase_date_ms",
            &purchase.original_purchase_date_ms,
        )?;
        object.serialize_field("expires_date_ms", &purchase.expires_date_ms)?;
        object.serialize_field(
            "web_order_line_item_id",
            &purchase.web_order_line_item_id.map(Id),
        )?;
        object.serialize_field("cancellation_date_ms", &purchase.cancellation_date_ms)?;
        object.serialize_field("is_trial_period", &purchase.is_trial_period)?;
        object.serialize_field(
            "is_in_intro_offer_period",
            &purchase.is_in_intro_offer_period,
        )?;
        object.serialize_field(
            "unknown_attributes",
            &Attributes(&purchase.unknown_attributes),
        )?;
        object.end()
    }
}

struct Receipt<'a>(&'a ReceiptPayload);

impl Serialize for Receipt<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let receipt = self.0;
        let in_app: Vec<Purchase<'_>> = receipt.in_app.iter().map(Purchase).collect();
        let mut object = serializer.serialize_struct("ReceiptPayload", 15)?;
        object.serialize_field("receipt_type", &receipt.receipt_type)?;
        object.serialize_field("app_item_id", &receipt.app_item_id.map(Id))?;
        object.serialize_field("bundle_id", &receipt.bundle_id)?;
        object.serialize_field(
            "bundle_id_bytes",
            &receipt.bundle_id_bytes.as_deref().map(Base64),
        )?;
        object.serialize_field("application_version", &receipt.application_version)?;
        object.serialize_field("opaque_value", &receipt.opaque_value.as_deref().map(Base64))?;
        object.serialize_field("sha1_hash", &receipt.sha1_hash.as_deref().map(Base64))?;
        object.serialize_field(
            "receipt_creation_date_ms",
            &receipt.receipt_creation_date_ms,
        )?;
        object.serialize_field("download_id", &receipt.download_id.map(Id))?;
        object.serialize_field(
            "version_external_identifier",
            &receipt.version_external_identifier.map(Id),
        )?;
        object.serialize_field("in_app", &in_app)?;
        object.serialize_field(
            "original_purchase_date_ms",
            &receipt.original_purchase_date_ms,
        )?;
        object.serialize_field(
            "original_application_version",
            &receipt.original_application_version,
        )?;
        object.serialize_field("expiration_date_ms", &receipt.expiration_date_ms)?;
        object.serialize_field(
            "unknown_attributes",
            &Attributes(&receipt.unknown_attributes),
        )?;
        object.end()
    }
}

// --------------------------------------------------------------- results

/// A verified answer: `{"verified":true,"payload":...,"environment":...}`.
/// The field names are the wire's member names.
#[derive(Serialize)]
#[allow(clippy::struct_field_names)]
struct Verified<P> {
    verified: bool,
    payload: P,
    environment: Option<&'static str>,
}

/// Apple's spelling of an environment, `null` for none.
fn spelling(environment: Option<Environment>) -> Option<&'static str> {
    environment.map(|environment| match environment {
        Environment::Production => "Production",
        Environment::Sandbox => "Sandbox",
    })
}

/// A refusal: `{"verified":false,"reason":"<TOKEN>","message":"..."}`.
#[derive(Serialize)]
struct Refused<'a> {
    verified: bool,
    reason: &'a str,
    message: &'a str,
}

impl<'a> Refused<'a> {
    fn new(failure: &'a Failure) -> Self {
        Refused {
            verified: false,
            reason: failure.reason.token(),
            message: &failure.message,
        }
    }
}

/// A receipt payload as 0.7's `ReceiptPayload.toJson()`: the value inside a
/// verified `verify-receipt` answer, and what the C ABI hands out for a
/// verified receipt.
#[must_use]
pub fn receipt_payload(receipt: &ReceiptPayload) -> String {
    to_json(&Receipt(receipt))
}

/// The answer of `verify-receipt`:
/// `{"verified":true,"payload":<receipt>,"environment":<"Production",
/// "Sandbox" or null>}` or a failure (`verify-receipt-result.schema.json`).
#[must_use]
pub fn verify_receipt_result(result: &Result<ReceiptPayload, Failure>) -> String {
    match result {
        Ok(receipt) => to_json(&Verified {
            verified: true,
            payload: Receipt(receipt),
            environment: spelling(receipt.environment),
        }),
        Err(refusal) => to_json(&Refused::new(refusal)),
    }
}

/// The answer of `verify-signed-data`: `{"verified":true,"payload":"<the
/// signed payload JSON, as a string>","environment":<"Production",
/// "Sandbox" or null>}` or a failure
/// (`verify-signed-data-result.schema.json`).
#[must_use]
pub fn verify_signed_data_result(result: &Result<JsonPayload, Failure>) -> String {
    match result {
        Ok(payload) => to_json(&Verified {
            verified: true,
            payload: &payload.json,
            environment: spelling(payload.environment),
        }),
        Err(refusal) => to_json(&Refused::new(refusal)),
    }
}

// ------------------------------------------------------------------ init

/// The answer of `init`: `{"ok":true,"max_input_bytes":N}` or
/// `{"ok":false,"message":"..."}`.
#[derive(Serialize)]
struct InitAnswer<'a> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_input_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
}

/// The answer of `init` (`init-result.schema.json`):
/// `{"ok":true,"max_input_bytes":N}`, or `{"ok":false,"message":"..."}`
/// naming why the configuration was refused.
///
/// `max_input_bytes` is [`aprv_surface::MAX_INPUT_BYTES`]: the most bytes
/// of one input a host needs to hand the module. A longer input may be cut
/// to this length, and the module answers `TOO_LARGE` for it. A host reads
/// it here rather than keeping a copy (DECISIONS.md R42).
#[must_use]
pub fn init_result(result: &Result<(), String>) -> String {
    to_json(&InitAnswer {
        ok: result.is_ok(),
        max_input_bytes: result.as_ref().ok().map(|()| aprv_surface::MAX_INPUT_BYTES),
        message: result.as_ref().err().map(String::as_str),
    })
}

/// `init`'s configuration as serde reads a struct: a derived `Deserialize`
/// refuses a member named twice, where `serde_json`'s own map keeps only
/// the last. Read for that refusal alone; the value is taken from the map.
#[derive(Deserialize)]
struct Once {
    #[serde(rename = "roots")]
    _roots: Option<serde::de::IgnoredAny>,
}

/// Reads `init`'s configuration (`init-config.schema.json`) into the
/// decoded bytes of the roots it names, in order: DER or PEM, which the
/// core tells apart. An empty list means the three Apple roots
/// compiled into the library.
///
/// Accepted: no bytes at all (or only JSON whitespace), `{}`, and
/// `{"roots":["<base64>", ...]}`, each root in padded standard base64
/// by the core's `receipt-data` rule ([`aprv_surface::decode_base64`]).
/// Anything else is refused with a message, so a wrapper that misspells a
/// member finds out at `create` instead of getting the Apple roots it did
/// not ask for; so is `roots` named twice, which a JSON reader that keeps
/// the last member would read as whichever came last. Whether a root is a
/// certificate is the surface's question, asked when the verifier is made.
///
/// # Errors
/// A message naming what is wrong: not UTF-8, not JSON, not an object,
/// `roots` more than once, a member other than `roots`, `roots` not a
/// list, or a root that is not a string or not base64 (by its index), the
/// first of these that applies.
pub fn read_init_config(config: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let text =
        core::str::from_utf8(config).map_err(|_| "the configuration is not UTF-8".to_owned())?;
    if text.trim_matches([' ', '\t', '\n', '\r']).is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| "the configuration is not JSON".to_owned())?;
    let serde_json::Value::Object(mut members) = value else {
        return Err("the configuration is not a JSON object".to_owned());
    };
    // The text is a JSON object, so the one thing `Once` can refuse is a
    // repeated `roots`.
    serde_json::from_str::<Once>(text)
        .map_err(|_| "the configuration names \"roots\" more than once".to_owned())?;
    let roots = members.remove("roots");
    if !members.is_empty() {
        return Err("the configuration has a member other than \"roots\"".to_owned());
    }
    let entries = match roots {
        None => Vec::new(),
        Some(serde_json::Value::Array(entries)) => entries,
        Some(_) => return Err("roots is not a list".to_owned()),
    };
    entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            let serde_json::Value::String(entry) = entry else {
                return Err(format!("roots[{index}] is not a string"));
            };
            aprv_surface::decode_base64(entry.as_bytes())
                .ok_or_else(|| format!("roots[{index}] is not padded standard base64"))
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::{
        init_result, read_init_config, receipt_payload, verify_receipt_result,
        verify_signed_data_result,
    };
    use aprv_surface::{Environment, Failure, InAppPurchase, JsonPayload, Reason, ReceiptPayload};

    #[test]
    fn a_failure_carries_exactly_three_members_in_a_fixed_order() {
        let refusal = Failure {
            reason: Reason::UntrustedChain,
            message: "a \"quoted\" \\ line\nbreak \u{1}".to_owned(),
        };
        let expected = r#"{"verified":false,"reason":"UNTRUSTED_CHAIN","message":"a \"quoted\" \\ line\nbreak \u0001"}"#;
        assert_eq!(verify_receipt_result(&Err(refusal.clone())), expected);
        assert_eq!(verify_signed_data_result(&Err(refusal)), expected);
    }

    #[test]
    fn a_verified_jws_carries_its_payload_as_a_string_holding_the_signed_text() {
        let json = "{\"b\":1, \"a\":\"\u{e9}\"}";
        let answer = verify_signed_data_result(&Ok(JsonPayload {
            json: json.to_owned(),
            environment: None,
        }));
        assert_eq!(
            answer,
            "{\"verified\":true,\"payload\":\"{\\\"b\\\":1, \\\"a\\\":\\\"\u{e9}\\\"}\",\"environment\":null}"
        );
        let back: serde_json::Value = serde_json::from_str(&answer).unwrap();
        assert_eq!(back["payload"].as_str(), Some(json));
    }

    #[test]
    fn an_empty_receipt_writes_every_key_as_null_or_empty() {
        assert_eq!(
            receipt_payload(&ReceiptPayload::default()),
            concat!(
                r#"{"receipt_type":null,"app_item_id":null,"bundle_id":null,"bundle_id_bytes":null,"#,
                r#""application_version":null,"opaque_value":null,"sha1_hash":null,"#,
                r#""receipt_creation_date_ms":null,"download_id":null,"version_external_identifier":null,"#,
                r#""in_app":[],"original_purchase_date_ms":null,"original_application_version":null,"#,
                r#""expiration_date_ms":null,"unknown_attributes":{}}"#
            )
        );
    }

    /// Every field `Some`, two purchases, and the strings, keys and numbers
    /// a writer can get wrong.
    fn full_receipt() -> ReceiptPayload {
        ReceiptPayload {
            receipt_type: Some("Production\u{0}\u{1}\u{1f}\u{7f}".to_owned()),
            app_item_id: Some(i64::MIN),
            bundle_id: Some("com.example.\u{e9}\u{2028}\u{2029}\u{1f600}/\"\\".to_owned()),
            bundle_id_bytes: Some(vec![]),
            application_version: Some("1.0\t\r\n\u{8}\u{c}\u{b}".to_owned()),
            opaque_value: Some(vec![0xfb, 0xff, 0xbf]),
            sha1_hash: Some(vec![0, 1, 2, 3, 4]),
            receipt_creation_date_ms: Some(i64::MIN),
            download_id: Some(i64::MAX),
            version_external_identifier: Some(0),
            in_app: vec![
                InAppPurchase {
                    quantity: Some(i64::MAX),
                    product_id: Some("p\u{0}\u{a0}\u{feff}".to_owned()),
                    transaction_id: Some("-1".to_owned()),
                    purchase_date_ms: Some(-1),
                    original_transaction_id: Some(String::new()),
                    original_purchase_date_ms: Some(0),
                    expires_date_ms: Some(i64::MAX),
                    web_order_line_item_id: Some(i64::MIN),
                    cancellation_date_ms: Some(i64::MIN),
                    is_trial_period: Some(true),
                    is_in_intro_offer_period: Some(false),
                    unknown_attributes: vec![
                        (-1, vec![vec![]]),
                        (1714, vec![vec![1, 2, 3], vec![]]),
                        (1714, vec![vec![0xff]]),
                    ],
                },
                InAppPurchase {
                    quantity: Some(1),
                    product_id: Some("\u{80}\u{9f}\u{fffd}\u{10ffff}".to_owned()),
                    transaction_id: Some("1000000000000000".to_owned()),
                    purchase_date_ms: Some(1_375_340_400_000),
                    original_transaction_id: Some("1000000000000000".to_owned()),
                    original_purchase_date_ms: Some(1_375_340_400_000),
                    expires_date_ms: Some(1_375_344_000_000),
                    web_order_line_item_id: Some(0),
                    cancellation_date_ms: Some(1_375_341_000_000),
                    is_trial_period: Some(false),
                    is_in_intro_offer_period: Some(true),
                    unknown_attributes: vec![],
                },
            ],
            original_purchase_date_ms: Some(1_375_340_400_000),
            original_application_version: Some("\u{1e}\u{1b}\u{e000}".to_owned()),
            expiration_date_ms: Some(-62_135_596_800_000),
            unknown_attributes: vec![
                (i64::MIN, vec![vec![]]),
                (-5, vec![vec![0]]),
                (13, vec![vec![0xfb, 0xff], vec![]]),
                (13, vec![vec![1]]),
                (i64::MAX, vec![]),
            ],
            // Written as the surface carries it: the wire derives nothing
            // from receipt_type.
            environment: Some(Environment::Sandbox),
        }
    }

    /// The whole verified `verify-receipt` answer for [`full_receipt`], byte
    /// for byte: C0 controls and U+007F, raw non-ASCII (U+2028, U+FEFF,
    /// private use, outside the BMP), negative and repeated attribute keys,
    /// `i64` extremes and empty byte strings. The expected text was produced
    /// by the hand-written writer that the `serde_json` one replaced, run on
    /// this same receipt, so a failure here is a change of 0.7's bytes. The
    /// one deliberate change since is the `environment` member after the
    /// payload (DECISIONS.md R42); the payload's own bytes are 0.7's.
    #[test]
    fn a_full_receipt_answer_keeps_the_bytes_of_the_hand_written_writer() {
        assert_eq!(
            verify_receipt_result(&Ok(full_receipt())),
            concat!(
                r#"{"verified":true,"payload":{"receipt_type":"Production\u0000\u0001\u001f"#,
                "\u{7f}",
                r#"","app_item_id":"-9223372036854775808","bundle_id":"com.example."#,
                "\u{e9}\u{2028}\u{2029}\u{1f600}",
                r#"/\"\\","bundle_id_bytes":"","application_version":"1.0\t\r\n\b\f\u000b""#,
                r#","opaque_value":"+/+/","sha1_hash":"AAECAwQ=""#,
                r#","receipt_creation_date_ms":-9223372036854775808"#,
                r#","download_id":"9223372036854775807","version_external_identifier":"0""#,
                r#","in_app":[{"quantity":9223372036854775807,"product_id":"p\u0000"#,
                "\u{a0}\u{feff}",
                r#"","transaction_id":"-1","purchase_date_ms":-1,"original_transaction_id":"""#,
                r#","original_purchase_date_ms":0,"expires_date_ms":9223372036854775807"#,
                r#","web_order_line_item_id":"-9223372036854775808""#,
                r#","cancellation_date_ms":-9223372036854775808"#,
                r#","is_trial_period":true,"is_in_intro_offer_period":false"#,
                r#","unknown_attributes":{"-1":[""],"1714":["AQID",""],"1714":["/w=="]}}"#,
                r#",{"quantity":1,"product_id":""#,
                "\u{80}\u{9f}\u{fffd}\u{10ffff}",
                r#"","transaction_id":"1000000000000000","purchase_date_ms":1375340400000"#,
                r#","original_transaction_id":"1000000000000000""#,
                r#","original_purchase_date_ms":1375340400000,"expires_date_ms":1375344000000"#,
                r#","web_order_line_item_id":"0","cancellation_date_ms":1375341000000"#,
                r#","is_trial_period":false,"is_in_intro_offer_period":true"#,
                r#","unknown_attributes":{}}]"#,
                r#","original_purchase_date_ms":1375340400000"#,
                r#","original_application_version":"\u001e\u001b"#,
                "\u{e000}",
                r#"","expiration_date_ms":-62135596800000"#,
                r#","unknown_attributes":{"-9223372036854775808":[""],"-5":["AA=="]"#,
                r#","13":["+/8=",""],"13":["AQ=="],"9223372036854775807":[]}}"#,
                r#","environment":"Sandbox"}"#
            )
        );
    }

    #[test]
    fn ids_are_decimal_strings_dates_numbers_bytes_padded_base64() {
        let receipt = ReceiptPayload {
            app_item_id: Some(-5),
            download_id: Some(i64::MAX),
            receipt_creation_date_ms: Some(1_600_000_000_000),
            sha1_hash: Some(vec![0xfb, 0xff]),
            in_app: vec![InAppPurchase {
                quantity: Some(1),
                web_order_line_item_id: Some(0),
                is_trial_period: Some(false),
                unknown_attributes: vec![(1714, vec![vec![], vec![1, 2, 3]])],
                ..InAppPurchase::default()
            }],
            unknown_attributes: vec![(13, vec![vec![0]]), (20_000, vec![vec![0xff]])],
            ..ReceiptPayload::default()
        };
        let json = receipt_payload(&receipt);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["app_item_id"], "-5");
        assert_eq!(value["download_id"], "9223372036854775807");
        assert_eq!(value["receipt_creation_date_ms"], 1_600_000_000_000_i64);
        assert_eq!(value["sha1_hash"], "+/8=");
        assert_eq!(value["in_app"][0]["web_order_line_item_id"], "0");
        assert_eq!(value["in_app"][0]["is_trial_period"], false);
        assert_eq!(value["in_app"][0]["unknown_attributes"]["1714"][0], "");
        assert_eq!(value["in_app"][0]["unknown_attributes"]["1714"][1], "AQID");
        assert!(json.ends_with(r#""unknown_attributes":{"13":["AA=="],"20000":["/w=="]}}"#));
    }

    #[test]
    fn a_verified_answer_states_the_environment_after_the_payload() {
        let receipt = |environment| ReceiptPayload {
            environment,
            ..ReceiptPayload::default()
        };
        let empty = receipt_payload(&ReceiptPayload::default());
        for (environment, written) in [
            (Some(Environment::Production), "\"Production\""),
            (Some(Environment::Sandbox), "\"Sandbox\""),
            (None, "null"),
        ] {
            assert_eq!(
                verify_receipt_result(&Ok(receipt(environment))),
                format!("{{\"verified\":true,\"payload\":{empty},\"environment\":{written}}}")
            );
            assert_eq!(
                verify_signed_data_result(&Ok(JsonPayload {
                    json: "{}".to_owned(),
                    environment,
                })),
                format!("{{\"verified\":true,\"payload\":\"{{}}\",\"environment\":{written}}}")
            );
        }
        // The payload's own JSON, which the C ABI's 0.7 calls hand out, has
        // no environment member.
        assert!(!receipt_payload(&receipt(Some(Environment::Sandbox))).contains("environment"));
    }

    #[test]
    fn init_answers_ok_with_the_input_length_or_a_message() {
        // One over the core's largest cap, 3 MiB: pinned here so a change
        // of it is seen, not carried silently to every host.
        assert_eq!(aprv_surface::MAX_INPUT_BYTES, 3_145_729);
        assert_eq!(
            init_result(&Ok(())),
            r#"{"ok":true,"max_input_bytes":3145729}"#
        );
        assert_eq!(
            init_result(&Err("roots[0]: \"x\"".to_owned())),
            r#"{"ok":false,"message":"roots[0]: \"x\""}"#
        );
    }

    #[test]
    fn the_configuration_names_roots_or_nothing() {
        for built_in in ["", " \n", "{}", "{\"roots\":[]}", " { \"roots\" : [ ] } "] {
            assert_eq!(
                read_init_config(built_in.as_bytes()),
                Ok(Vec::new()),
                "{built_in:?}"
            );
        }
        assert_eq!(
            read_init_config(b"{\"roots\":[\"AQID\",\"BA==\"]}"),
            Ok(vec![vec![1, 2, 3], vec![4]])
        );
        let refused: [(&[u8], &str); 11] = [
            // Named twice, a reader keeping the last member would take the
            // Apple roots here, and the first root in the other order.
            (
                b"{\"roots\":[\"AQ==\"],\"roots\":[]}",
                "the configuration names \"roots\" more than once",
            ),
            (
                b"{\"roots\":[],\"roots\":[\"AQ==\"]}",
                "the configuration names \"roots\" more than once",
            ),
            (b"\xff", "the configuration is not UTF-8"),
            (b"{", "the configuration is not JSON"),
            (b"[]", "the configuration is not a JSON object"),
            (b"null", "the configuration is not a JSON object"),
            (
                b"{\"root\":[]}",
                "the configuration has a member other than \"roots\"",
            ),
            (b"{\"roots\":\"AQID\"}", "roots is not a list"),
            (b"{\"roots\":[1]}", "roots[0] is not a string"),
            (
                b"{\"roots\":[\"AQID\",\"AQ\"]}",
                "roots[1] is not padded standard base64",
            ),
            (
                b"{\"roots\":[\"\"]}",
                "roots[0] is not padded standard base64",
            ),
        ];
        for (config, message) in refused {
            assert_eq!(read_init_config(config), Err(message.to_owned()));
        }
    }
}
