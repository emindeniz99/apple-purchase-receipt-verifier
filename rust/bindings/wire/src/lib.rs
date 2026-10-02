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
//! - a verified result is exactly `{"verified":true,"payload":...}`, a
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

use aprv_surface::{Failure, InAppPurchase, JsonPayload, ReceiptPayload, UnknownAttributes};
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

/// A verified answer: `{"verified":true,"payload":...}`.
#[derive(Serialize)]
struct Verified<P> {
    verified: bool,
    payload: P,
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

/// The answer of `verify-receipt`: `{"verified":true,"payload":<receipt>}`
/// or a failure (`verify-receipt-result.schema.json`).
#[must_use]
pub fn verify_receipt_result(result: &Result<ReceiptPayload, Failure>) -> String {
    match result {
        Ok(receipt) => to_json(&Verified {
            verified: true,
            payload: Receipt(receipt),
        }),
        Err(refusal) => to_json(&Refused::new(refusal)),
    }
}

/// The answer of `verify-signed-data`: `{"verified":true,"payload":"<the
/// signed payload JSON, as a string>"}` or a failure
/// (`verify-signed-data-result.schema.json`).
#[must_use]
pub fn verify_signed_data_result(result: &Result<JsonPayload, Failure>) -> String {
    match result {
        Ok(payload) => to_json(&Verified {
            verified: true,
            payload: &payload.json,
        }),
        Err(refusal) => to_json(&Refused::new(refusal)),
    }
}

// ------------------------------------------------------------------ init

/// The answer of `init`: `{"ok":true}` or `{"ok":false,"message":"..."}`.
#[derive(Serialize)]
struct InitAnswer<'a> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
}

/// The answer of `init` (`init-result.schema.json`): `{"ok":true}`, or
/// `{"ok":false,"message":"..."}` naming why the configuration was refused.
#[must_use]
pub fn init_result(result: &Result<(), String>) -> String {
    to_json(&InitAnswer {
        ok: result.is_ok(),
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
    use aprv_surface::{Failure, InAppPurchase, JsonPayload, Reason, ReceiptPayload};

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
        }));
        assert_eq!(
            answer,
            "{\"verified\":true,\"payload\":\"{\\\"b\\\":1, \\\"a\\\":\\\"\u{e9}\\\"}\"}"
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
    fn init_answers_ok_or_a_message() {
        assert_eq!(init_result(&Ok(())), r#"{"ok":true}"#);
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
