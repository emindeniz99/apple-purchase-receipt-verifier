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
use core::fmt::Write as _;

// ---------------------------------------------------------------- writer

/// `text` as a JSON string literal: `"`, `\` and U+0000 to U+001F escaped,
/// everything else raw.
fn string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Writes one object, member by member, in the order they are added.
struct Object<'a> {
    out: &'a mut String,
    first: bool,
}

impl<'a> Object<'a> {
    fn new(out: &'a mut String) -> Self {
        out.push('{');
        Object { out, first: true }
    }

    fn key(&mut self, key: &str) -> &mut String {
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        string(self.out, key);
        self.out.push(':');
        self.out
    }

    fn raw(&mut self, key: &str, json: &str) {
        self.key(key).push_str(json);
    }

    fn text(&mut self, key: &str, value: Option<&str>) {
        let out = self.key(key);
        match value {
            Some(value) => string(out, value),
            None => out.push_str("null"),
        }
    }

    /// A 64-bit id: a string, so no JavaScript reader rounds it.
    fn id(&mut self, key: &str, value: Option<i64>) {
        let out = self.key(key);
        match value {
            Some(value) => {
                let _ = write!(out, "\"{value}\"");
            }
            None => out.push_str("null"),
        }
    }

    fn number(&mut self, key: &str, value: Option<i64>) {
        let out = self.key(key);
        match value {
            Some(value) => {
                let _ = write!(out, "{value}");
            }
            None => out.push_str("null"),
        }
    }

    fn boolean(&mut self, key: &str, value: Option<bool>) {
        self.raw(
            key,
            match value {
                Some(true) => "true",
                Some(false) => "false",
                None => "null",
            },
        );
    }

    fn bytes(&mut self, key: &str, value: Option<&[u8]>) {
        let out = self.key(key);
        match value {
            Some(value) => string(out, &base64(value)),
            None => out.push_str("null"),
        }
    }

    fn unknown_attributes(&mut self, attributes: &UnknownAttributes) {
        let out = self.key("unknown_attributes");
        let mut object = Object::new(out);
        for (attribute_type, values) in attributes {
            let out = object.key(&attribute_type.to_string());
            out.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                string(out, &base64(value));
            }
            out.push(']');
        }
        object.end();
    }

    fn end(self) {
        self.out.push('}');
    }
}

// --------------------------------------------------------------- results

fn in_app_purchase(out: &mut String, purchase: &InAppPurchase) {
    let mut object = Object::new(out);
    object.number("quantity", purchase.quantity);
    object.text("product_id", purchase.product_id.as_deref());
    object.text("transaction_id", purchase.transaction_id.as_deref());
    object.number("purchase_date_ms", purchase.purchase_date_ms);
    object.text(
        "original_transaction_id",
        purchase.original_transaction_id.as_deref(),
    );
    object.number(
        "original_purchase_date_ms",
        purchase.original_purchase_date_ms,
    );
    object.number("expires_date_ms", purchase.expires_date_ms);
    object.id("web_order_line_item_id", purchase.web_order_line_item_id);
    object.number("cancellation_date_ms", purchase.cancellation_date_ms);
    object.boolean("is_trial_period", purchase.is_trial_period);
    object.boolean(
        "is_in_intro_offer_period",
        purchase.is_in_intro_offer_period,
    );
    object.unknown_attributes(&purchase.unknown_attributes);
    object.end();
}

/// A receipt payload as 0.7's `ReceiptPayload.toJson()`: the value inside a
/// verified `verify-receipt` answer, and what the C ABI hands out for a
/// verified receipt.
#[must_use]
pub fn receipt_payload(receipt: &ReceiptPayload) -> String {
    let mut out = String::with_capacity(1024);
    let mut object = Object::new(&mut out);
    object.text("receipt_type", receipt.receipt_type.as_deref());
    object.id("app_item_id", receipt.app_item_id);
    object.text("bundle_id", receipt.bundle_id.as_deref());
    object.bytes("bundle_id_bytes", receipt.bundle_id_bytes.as_deref());
    object.text(
        "application_version",
        receipt.application_version.as_deref(),
    );
    object.bytes("opaque_value", receipt.opaque_value.as_deref());
    object.bytes("sha1_hash", receipt.sha1_hash.as_deref());
    object.number("receipt_creation_date_ms", receipt.receipt_creation_date_ms);
    object.id("download_id", receipt.download_id);
    object.id(
        "version_external_identifier",
        receipt.version_external_identifier,
    );
    {
        let out = object.key("in_app");
        out.push('[');
        for (index, purchase) in receipt.in_app.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            in_app_purchase(out, purchase);
        }
        out.push(']');
    }
    object.number(
        "original_purchase_date_ms",
        receipt.original_purchase_date_ms,
    );
    object.text(
        "original_application_version",
        receipt.original_application_version.as_deref(),
    );
    object.number("expiration_date_ms", receipt.expiration_date_ms);
    object.unknown_attributes(&receipt.unknown_attributes);
    object.end();
    out
}

fn failure(out: &mut String, failure: &Failure) {
    let mut object = Object::new(out);
    object.raw("verified", "false");
    object.text("reason", Some(failure.reason.token()));
    object.text("message", Some(&failure.message));
    object.end();
}

/// The answer of `verify-receipt`: `{"verified":true,"payload":<receipt>}`
/// or a failure (`verify-receipt-result.schema.json`).
#[must_use]
pub fn verify_receipt_result(result: &Result<ReceiptPayload, Failure>) -> String {
    let mut out = String::new();
    match result {
        Ok(receipt) => {
            let mut object = Object::new(&mut out);
            object.raw("verified", "true");
            object.raw("payload", &receipt_payload(receipt));
            object.end();
        }
        Err(refusal) => failure(&mut out, refusal),
    }
    out
}

/// The answer of `verify-signed-data`: `{"verified":true,"payload":"<the
/// signed payload JSON, as a string>"}` or a failure
/// (`verify-signed-data-result.schema.json`).
#[must_use]
pub fn verify_signed_data_result(result: &Result<JsonPayload, Failure>) -> String {
    let mut out = String::new();
    match result {
        Ok(payload) => {
            let mut object = Object::new(&mut out);
            object.raw("verified", "true");
            object.text("payload", Some(&payload.json));
            object.end();
        }
        Err(refusal) => failure(&mut out, refusal),
    }
    out
}

// ------------------------------------------------------------------ init

/// The answer of `init` (`init-result.schema.json`): `{"ok":true}`, or
/// `{"ok":false,"message":"..."}` naming why the configuration was refused.
#[must_use]
pub fn init_result(result: &Result<(), String>) -> String {
    let mut out = String::new();
    let mut object = Object::new(&mut out);
    match result {
        Ok(()) => object.raw("ok", "true"),
        Err(message) => {
            object.raw("ok", "false");
            object.text("message", Some(message));
        }
    }
    object.end();
    out
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
/// the last member would read as whichever came last. Whether a root is a certificate is the surface's question,
/// asked when the verifier is made.
///
/// # Errors
/// A message naming what is wrong: not UTF-8, not JSON, not an object, a
/// member other than `roots`, `roots` more than once, `roots` not a list,
/// or a root that is not a string or not base64 (by its index).
pub fn read_init_config(config: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let text =
        core::str::from_utf8(config).map_err(|_| "the configuration is not UTF-8".to_owned())?;
    if text.trim_matches([' ', '\t', '\n', '\r']).is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| "the configuration is not JSON".to_owned())?;
    if !value.is_object() {
        return Err("the configuration is not a JSON object".to_owned());
    }
    let Members(members) =
        serde_json::from_str(text).map_err(|_| "the configuration is not JSON".to_owned())?;
    if members.iter().filter(|(name, _)| name == "roots").count() > 1 {
        return Err("the configuration names \"roots\" more than once".to_owned());
    }
    let mut roots = Vec::new();
    for (name, value) in members {
        if name != "roots" {
            return Err("the configuration has a member other than \"roots\"".to_owned());
        }
        let serde_json::Value::Array(entries) = value else {
            return Err("roots is not a list".to_owned());
        };
        for (index, entry) in entries.into_iter().enumerate() {
            let serde_json::Value::String(entry) = entry else {
                return Err(format!("roots[{index}] is not a string"));
            };
            let der = aprv_surface::decode_base64(entry.as_bytes())
                .ok_or_else(|| format!("roots[{index}] is not padded standard base64"))?;
            roots.push(der);
        }
    }
    Ok(roots)
}

/// Every member of a JSON object, repeated names included, in order.
struct Members(Vec<(String, serde_json::Value)>);

impl<'de> serde::Deserialize<'de> for Members {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Members, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Members;
            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Members, A::Error> {
                let mut members = Vec::new();
                while let Some(name) = map.next_key::<String>()? {
                    members.push((name, map.next_value()?));
                }
                Ok(Members(members))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
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
