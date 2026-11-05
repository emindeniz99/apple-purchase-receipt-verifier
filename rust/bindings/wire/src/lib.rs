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
//! - a verified receipt's `payload` is the core's
//!   [`ReceiptPayload::to_json`], byte for byte: the one writer of a
//!   receipt's JSON, whose doc states its rules (64-bit ids as decimal
//!   strings, dates as epoch-millisecond numbers, bytes as padded standard
//!   base64, `null` for a missing field, `unknown_attributes` keyed by the
//!   decimal attribute type in ascending order, keys in the order the 0.7
//!   table lists them);
//! - a verified JWS's `payload` is a JSON string holding the signed
//!   payload's text, so no host re-serialises Apple's claims;
//! - everything is written by `serde_json`: strings escape only `"`, `\`
//!   and the C0 controls, and non-ASCII is written raw. One fixed byte form,
//!   although consumers compare by value.
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

use aprv_surface::{Environment, Failure, JsonPayload, ReceiptPayload, Revocation, Verifier};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------- writer

/// `value` as JSON text. `serde_json` escapes `"`, `\` and U+0000 to U+001F
/// and writes everything else raw, and a struct's members come in the
/// order they are serialised.
fn to_json(value: &impl Serialize) -> String {
    // Nothing here can fail to serialise: every value is a string, a
    // number, a boolean or a struct of them. Were it to, the empty answer
    // is unreadable JSON, which every host reports as INTERNAL_ERROR rather
    // than as a verdict.
    serde_json::to_string(value).unwrap_or_default()
}

// --------------------------------------------------------------- results

/// A verified answer: `{"verified":true,"payload":<payload>,"environment":
/// <"Production", "Sandbox" or null>}`, `payload` already JSON text.
fn verified(payload: &str, environment: Option<Environment>) -> String {
    let environment = to_json(&environment.map(Environment::as_str));
    format!("{{\"verified\":true,\"payload\":{payload},\"environment\":{environment}}}")
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
            reason: failure.reason().as_str(),
            message: failure.message(),
        }
    }
}

/// A receipt payload as 0.7's `ReceiptPayload.toJson()`: the value inside a
/// verified `verify-receipt` answer, and what the C ABI hands out for a
/// verified receipt. The bytes are the core's
/// [`ReceiptPayload::to_json`], the one writer of a receipt's JSON.
#[must_use]
pub fn receipt_payload(receipt: &ReceiptPayload) -> String {
    receipt.to_json()
}

/// The answer of `verify-receipt`:
/// `{"verified":true,"payload":<receipt>,"environment":<"Production",
/// "Sandbox" or null>}` or a failure (`verify-receipt-result.schema.json`).
#[must_use]
pub fn verify_receipt_result(result: &Result<ReceiptPayload, Failure>) -> String {
    match result {
        Ok(receipt) => verified(&receipt.to_json(), receipt.environment()),
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
        Ok(payload) => verified(&to_json(&payload.json()), payload.environment()),
        Err(refusal) => to_json(&Refused::new(refusal)),
    }
}

// ------------------------------------------------------------------ init

/// The answer of `init` to a configuration it accepted.
#[derive(Serialize)]
struct InitAccepted<'a> {
    ok: bool,
    max_input_bytes: usize,
    revocation_urls: &'a [String],
    /// `null` when the verifier reports none.
    revocation_valid_until_ms: Option<i64>,
}

/// The answer of `init` to a configuration it refused.
#[derive(Serialize)]
struct InitRefused<'a> {
    ok: bool,
    message: &'a str,
}

/// The answer of `init` (`init-result.schema.json`):
/// `{"ok":true,"max_input_bytes":N,"revocation_urls":[...],
/// "revocation_valid_until_ms":N|null}` for the verifier `init` made, or
/// `{"ok":false,"message":"..."}` naming why the configuration was
/// refused.
///
/// `max_input_bytes` is [`aprv_surface::MAX_INPUT_BYTES`]: the most bytes
/// of one input a host needs to hand the module. A longer input may be cut
/// to this length, and the module answers `TOO_LARGE` for it. A host reads
/// it here rather than keeping a copy (DECISIONS.md R42).
///
/// `revocation_urls` and `revocation_valid_until_ms` are the verifier's
/// [`revocation_urls`](aprv_surface::Verifier::revocation_urls) and
/// [`revocation_valid_until_ms`](aprv_surface::Verifier::revocation_valid_until_ms)
/// (docs/design/revocation.md §7, §8): every wrapper reads both from here,
/// and none reads a certificate or a list.
#[must_use]
pub fn init_result(result: &Result<&Verifier, String>) -> String {
    match result {
        Ok(verifier) => to_json(&InitAccepted {
            ok: true,
            max_input_bytes: aprv_surface::MAX_INPUT_BYTES,
            revocation_urls: verifier.revocation_urls(),
            revocation_valid_until_ms: verifier.revocation_valid_until_ms(),
        }),
        Err(message) => to_json(&InitRefused { ok: false, message }),
    }
}

/// `init`'s configuration as serde reads a struct: a derived `Deserialize`
/// refuses a member named twice, where `serde_json`'s own map keeps only
/// the last. Read for that refusal alone; the values are taken from the
/// map.
#[derive(Deserialize)]
struct Once {
    #[serde(rename = "roots")]
    _roots: Option<serde::de::IgnoredAny>,
    #[serde(rename = "revocation_lists")]
    _revocation_lists: Option<serde::de::IgnoredAny>,
    #[serde(rename = "revocation_issuers")]
    _revocation_issuers: Option<serde::de::IgnoredAny>,
    #[serde(rename = "distrust")]
    _distrust: Option<serde::de::IgnoredAny>,
}

/// The members `init`'s configuration may hold, in the order a refusal
/// names them.
const MEMBERS: [&str; 4] = [
    "roots",
    "revocation_lists",
    "revocation_issuers",
    "distrust",
];

/// What `init`'s configuration asks for: the decoded roots (empty for the
/// three Apple roots compiled into the library) and the revocation
/// settings, which the core judges when the verifier is made.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InitConfig {
    /// The roots, each the decoded bytes of one DER certificate or of PEM
    /// text; empty means the Apple roots.
    pub roots: Vec<Vec<u8>>,
    /// The revocation lists, issuers and `distrust` entries.
    pub revocation: Revocation,
}

impl InitConfig {
    /// The verifier this configuration asks for.
    ///
    /// # Errors
    /// The surface's message for a root or issuer that is not a
    /// certificate, or for a revocation setting the core refuses.
    pub fn verifier(&self) -> Result<Verifier, String> {
        Verifier::with_revocation(&self.roots, &self.revocation).map_err(|error| error.message)
    }
}

/// Reads `init`'s configuration (`init-config.schema.json`).
///
/// Accepted: no bytes at all (or only JSON whitespace) and `{}`, both the
/// Apple roots with no revocation setting; and an object with any of
/// `roots` (at least one root), `revocation_lists` and
/// `revocation_issuers` (lists of padded standard base64 by the core's
/// `receipt-data` rule, [`aprv_surface::decode_base64`]), and `distrust`
/// (a list of `{"issuer":"...","serial":"..."}` objects with exactly
/// those two string members). A root or an issuer is DER or PEM, which the
/// core tells apart. Anything else is refused with a message, so a wrapper
/// that misspells a member finds out at `create` instead of getting
/// settings it did not ask for; so is a member named twice, which a JSON
/// reader that keeps the last member would read as whichever came last.
/// An empty `roots` list is refused with the message the core's `Config`
/// gives an empty root set, so no verifier with no roots is made and a
/// configuration that came up empty fails at `create` rather than reading
/// as the Apple roots (DECISIONS.md R23, owner decision Q30). Whether a
/// root or an issuer is a certificate, and whether a list or a `distrust`
/// entry is accepted, is the core's question, asked when the verifier is
/// made ([`InitConfig::verifier`]).
///
/// # Errors
/// A message naming what is wrong: not UTF-8, not JSON, not an object, a
/// member more than once, a member other than the four, a member that is
/// not a list, `roots` an empty list, an entry that is not a string or not
/// base64, or a `distrust` entry that is not such an object (by its
/// index), the first of these that applies.
pub fn read_init_config(config: &[u8]) -> Result<InitConfig, String> {
    let text =
        core::str::from_utf8(config).map_err(|_| "the configuration is not UTF-8".to_owned())?;
    if text.trim_matches([' ', '\t', '\n', '\r']).is_empty() {
        return Ok(InitConfig::default());
    }
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| "the configuration is not JSON".to_owned())?;
    let serde_json::Value::Object(mut members) = value else {
        return Err("the configuration is not a JSON object".to_owned());
    };
    // The text is a JSON object, so the one thing `Once` can refuse is a
    // repeated member.
    if let Err(error) = serde_json::from_str::<Once>(text) {
        let named = MEMBERS
            .iter()
            .find(|member| error.to_string().contains(&format!("`{member}`")))
            .copied()
            .unwrap_or("a member");
        return Err(format!(
            "the configuration names \"{named}\" more than once"
        ));
    }
    let mut taken: Vec<Option<serde_json::Value>> = MEMBERS
        .iter()
        .map(|member| members.remove(*member))
        .collect();
    if !members.is_empty() {
        return Err(
            "the configuration has a member other than \"roots\", \"revocation_lists\", \
             \"revocation_issuers\" and \"distrust\""
                .to_owned(),
        );
    }
    let mut take = |index: usize| taken.get_mut(index).and_then(Option::take);
    let roots = match take(0) {
        None => Vec::new(),
        Some(serde_json::Value::Array(entries)) if entries.is_empty() => {
            return Err("roots must not be empty".to_owned())
        }
        Some(value) => base64_list("roots", value)?,
    };
    let lists = take(1)
        .map(|value| base64_list("revocation_lists", value))
        .transpose()?
        .unwrap_or_default();
    let issuers = take(2)
        .map(|value| base64_list("revocation_issuers", value))
        .transpose()?
        .unwrap_or_default();
    let distrust = take(3).map(distrust_list).transpose()?.unwrap_or_default();
    Ok(InitConfig {
        roots,
        revocation: Revocation {
            lists,
            issuers,
            distrust,
        },
    })
}

/// A member that must be a list of padded standard base64 strings,
/// decoded.
fn base64_list(member: &str, value: serde_json::Value) -> Result<Vec<Vec<u8>>, String> {
    let serde_json::Value::Array(entries) = value else {
        return Err(format!("{member} is not a list"));
    };
    entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            let serde_json::Value::String(entry) = entry else {
                return Err(format!("{member}[{index}] is not a string"));
            };
            aprv_surface::decode_base64(entry.as_bytes())
                .ok_or_else(|| format!("{member}[{index}] is not padded standard base64"))
        })
        .collect()
}

/// `distrust`: a list of `{"issuer":"...","serial":"..."}`, both strings,
/// nothing else. Whether the strings are an issuer id and a hex serial is
/// the core's question.
fn distrust_list(value: serde_json::Value) -> Result<Vec<(String, String)>, String> {
    let serde_json::Value::Array(entries) = value else {
        return Err("distrust is not a list".to_owned());
    };
    entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            let refused =
                || format!("distrust[{index}] is not {{\"issuer\":\"...\",\"serial\":\"...\"}}");
            let serde_json::Value::Object(mut members) = entry else {
                return Err(refused());
            };
            let (Some(serde_json::Value::String(issuer)), Some(serde_json::Value::String(serial))) =
                (members.remove("issuer"), members.remove("serial"))
            else {
                return Err(refused());
            };
            if !members.is_empty() {
                return Err(refused());
            }
            Ok((issuer, serial))
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::{
        init_result, read_init_config, receipt_payload, verify_receipt_result,
        verify_signed_data_result, InitConfig, Revocation,
    };
    use apple_purchase_receipt_verifier::__internal as seams;
    use aprv_surface::{Reason, ReceiptPayload, UnknownAttributes};

    #[test]
    fn a_failure_carries_exactly_three_members_in_a_fixed_order() {
        let refusal = seams::failure(Reason::UntrustedChain, "a \"quoted\" \\ line\nbreak \u{1}");
        let expected = r#"{"verified":false,"reason":"UNTRUSTED_CHAIN","message":"a \"quoted\" \\ line\nbreak \u0001"}"#;
        assert_eq!(verify_receipt_result(&Err(refusal.clone())), expected);
        assert_eq!(verify_signed_data_result(&Err(refusal)), expected);
    }

    #[test]
    fn a_verified_jws_carries_its_payload_as_a_string_holding_the_signed_text() {
        let json = "{\"b\":1, \"a\":\"\u{e9}\"}";
        let answer = verify_signed_data_result(&Ok(seams::json_payload(json)));
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
            receipt_payload(&seams::receipt_payload()),
            concat!(
                r#"{"receipt_type":null,"app_item_id":null,"bundle_id":null,"bundle_id_bytes":null,"#,
                r#""application_version":null,"opaque_value":null,"sha1_hash":null,"#,
                r#""receipt_creation_date_ms":null,"download_id":null,"version_external_identifier":null,"#,
                r#""in_app":[],"original_purchase_date_ms":null,"preorder_date_ms":null,"#,
                r#""original_application_version":null,"#,
                r#""expiration_date_ms":null,"unknown_attributes":{}}"#
            )
        );
    }

    /// Every field `Some`, two purchases, and the strings, keys and numbers
    /// a writer can get wrong.
    fn full_receipt() -> ReceiptPayload {
        let mut first = seams::in_app_purchase();
        first.quantity = Some(i64::MAX);
        first.product_id = Some("p\u{0}\u{a0}\u{feff}".to_owned());
        first.transaction_id = Some("-1".to_owned());
        first.purchase_date_ms = Some(-1);
        first.original_transaction_id = Some(String::new());
        first.original_purchase_date_ms = Some(0);
        first.expires_date_ms = Some(i64::MAX);
        first.web_order_line_item_id = Some(i64::MIN);
        first.cancellation_date_ms = Some(i64::MIN);
        first.is_trial_period = Some(true);
        first.is_in_intro_offer_period = Some(false);
        first.unknown_attributes = UnknownAttributes::from([
            (0, vec![vec![]]),
            (1714, vec![vec![1, 2, 3], vec![], vec![0xff]]),
        ]);
        let mut second = seams::in_app_purchase();
        second.quantity = Some(1);
        second.product_id = Some("\u{80}\u{9f}\u{fffd}\u{10ffff}".to_owned());
        second.transaction_id = Some("1000000000000000".to_owned());
        second.purchase_date_ms = Some(1_375_340_400_000);
        second.original_transaction_id = Some("1000000000000000".to_owned());
        second.original_purchase_date_ms = Some(1_375_340_400_000);
        second.expires_date_ms = Some(1_375_344_000_000);
        second.web_order_line_item_id = Some(0);
        second.cancellation_date_ms = Some(1_375_341_000_000);
        second.is_trial_period = Some(false);
        second.is_in_intro_offer_period = Some(true);
        let mut receipt = seams::receipt_payload();
        receipt.receipt_type = Some("Production\u{0}\u{1}\u{1f}\u{7f}".to_owned());
        receipt.app_item_id = Some(i64::MIN);
        receipt.bundle_id = Some("com.example.\u{e9}\u{2028}\u{2029}\u{1f600}/\"\\".to_owned());
        receipt.bundle_id_bytes = Some(vec![]);
        receipt.application_version = Some("1.0\t\r\n\u{8}\u{c}\u{b}".to_owned());
        receipt.opaque_value = Some(vec![0xfb, 0xff, 0xbf]);
        receipt.sha1_hash = Some(vec![0, 1, 2, 3, 4]);
        receipt.receipt_creation_date_ms = Some(i64::MIN);
        receipt.download_id = Some(i64::MAX);
        receipt.version_external_identifier = Some(0);
        receipt.in_app = vec![first, second];
        receipt.original_purchase_date_ms = Some(1_375_340_400_000);
        receipt.preorder_date_ms = Some(1_719_913_520_000);
        receipt.original_application_version = Some("\u{1e}\u{1b}\u{e000}".to_owned());
        receipt.expiration_date_ms = Some(-62_135_596_800_000);
        // The extremes of the attribute type, and 9 before 13: ascending
        // by value, not by the decimal text.
        receipt.unknown_attributes = UnknownAttributes::from([
            (0, vec![vec![]]),
            (9, vec![vec![0]]),
            (13, vec![vec![0xfb, 0xff], vec![], vec![1]]),
            (u32::MAX, vec![]),
        ]);
        receipt
    }

    /// The whole verified `verify-receipt` answer for [`full_receipt`], byte
    /// for byte: C0 controls and U+007F, raw non-ASCII (U+2028, U+FEFF,
    /// private use, outside the BMP), attribute keys in numeric order
    /// (`9` before `13`, `u32::MAX`), `i64` extremes and empty byte strings. The expected text was produced
    /// by the hand-written writer that the `serde_json` one replaced, run on
    /// this same receipt, when the receipt type was the surface's own copy;
    /// the core's type holds no negative or repeated attribute type, so
    /// those keys left the test with it. The payload's bytes now come from
    /// the core's `ReceiptPayload::to_json`, which took over this crate's
    /// writer unchanged. It includes the environment member
    /// after the payload (DECISIONS.md R42), `null` here because the core
    /// reads no environment from this `receipt_type`, pre-order date and
    /// nullable cancellation reason; changes to its byte form must be
    /// deliberate.
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
                r#","cancellation_reason":null,"is_trial_period":true,"is_in_intro_offer_period":false"#,
                r#","unknown_attributes":{"0":[""],"1714":["AQID","","/w=="]}}"#,
                r#",{"quantity":1,"product_id":""#,
                "\u{80}\u{9f}\u{fffd}\u{10ffff}",
                r#"","transaction_id":"1000000000000000","purchase_date_ms":1375340400000"#,
                r#","original_transaction_id":"1000000000000000""#,
                r#","original_purchase_date_ms":1375340400000,"expires_date_ms":1375344000000"#,
                r#","web_order_line_item_id":"0","cancellation_date_ms":1375341000000"#,
                r#","cancellation_reason":null,"is_trial_period":false,"is_in_intro_offer_period":true"#,
                r#","unknown_attributes":{}}]"#,
                r#","original_purchase_date_ms":1375340400000"#,
                r#","preorder_date_ms":1719913520000"#,
                r#","original_application_version":"\u001e\u001b"#,
                "\u{e000}",
                r#"","expiration_date_ms":-62135596800000"#,
                r#","unknown_attributes":{"0":[""],"9":["AA=="]"#,
                r#","13":["+/8=","","AQ=="],"4294967295":[]}}"#,
                r#","environment":null}"#
            )
        );
    }

    #[test]
    fn ids_are_decimal_strings_dates_numbers_bytes_padded_base64() {
        let mut purchase = seams::in_app_purchase();
        purchase.quantity = Some(1);
        purchase.web_order_line_item_id = Some(0);
        purchase.is_trial_period = Some(false);
        purchase.unknown_attributes =
            UnknownAttributes::from([(1714, vec![vec![], vec![1, 2, 3]])]);
        let mut receipt = seams::receipt_payload();
        receipt.app_item_id = Some(-5);
        receipt.download_id = Some(i64::MAX);
        receipt.receipt_creation_date_ms = Some(1_600_000_000_000);
        receipt.sha1_hash = Some(vec![0xfb, 0xff]);
        receipt.in_app = vec![purchase];
        receipt.unknown_attributes =
            UnknownAttributes::from([(13, vec![vec![0]]), (20_000, vec![vec![0xff]])]);
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

    /// The environment is the core's reading of `receipt_type`, written
    /// after the payload.
    #[test]
    fn a_verified_answer_states_the_environment_after_the_payload() {
        for (receipt_type, written) in [
            (Some("Production"), "\"Production\""),
            (Some("ProductionVPP"), "\"Production\""),
            (Some("ProductionSandbox"), "\"Sandbox\""),
            (Some("ProductionVPPSandbox"), "\"Sandbox\""),
            (Some("Xcode"), "null"),
            (None, "null"),
        ] {
            let mut receipt = seams::receipt_payload();
            receipt.receipt_type = receipt_type.map(str::to_owned);
            let payload = receipt_payload(&receipt);
            // The payload's own JSON, which the C ABI's 0.7 calls hand out,
            // has no environment member.
            assert!(!payload.contains("environment"), "{payload}");
            assert_eq!(
                verify_receipt_result(&Ok(receipt)),
                format!("{{\"verified\":true,\"payload\":{payload},\"environment\":{written}}}")
            );
        }
        // A JWS payload's environment is the core's reading of its claims;
        // the payload is written as signed.
        for (json, written) in [
            (r#"{"environment":"Production"}"#, "\"Production\""),
            (r#"{"data":{"environment":"Sandbox"}}"#, "\"Sandbox\""),
            (r#"{"environment":"Xcode"}"#, "null"),
            ("{}", "null"),
        ] {
            let payload = serde_json::to_string(json).unwrap();
            assert_eq!(
                verify_signed_data_result(&Ok(seams::json_payload(json))),
                format!("{{\"verified\":true,\"payload\":{payload},\"environment\":{written}}}")
            );
        }
    }

    #[test]
    fn init_answers_ok_with_the_input_length_and_revocation_state_or_a_message() {
        // One over the core's largest cap, 3 MiB: pinned here so a change
        // of it is seen, not carried silently to every host.
        assert_eq!(aprv_surface::MAX_INPUT_BYTES, 3_145_729);
        let verifier = aprv_surface::Verifier::new(&[]).unwrap();
        assert_eq!(
            init_result(&Ok(&verifier)),
            concat!(
                r#"{"ok":true,"max_input_bytes":3145729,"revocation_urls":["#,
                r#""http://crl.apple.com/root.crl","http://crl.apple.com/applerootcag3.crl","#,
                r#""http://crl.apple.com/wwdrg5.crl","http://crl.apple.com/wwdrg6.crl"],"#,
                r#""revocation_valid_until_ms":null}"#
            )
        );
        assert_eq!(
            init_result(&Err("roots[0]: \"x\"".to_owned())),
            r#"{"ok":false,"message":"roots[0]: \"x\""}"#
        );
    }

    fn roots_only(roots: Vec<Vec<u8>>) -> InitConfig {
        InitConfig {
            roots,
            ..InitConfig::default()
        }
    }

    #[test]
    fn the_configuration_names_roots_and_revocation_settings_or_nothing() {
        for built_in in ["", " \n", "{}", " { } "] {
            assert_eq!(
                read_init_config(built_in.as_bytes()),
                Ok(InitConfig::default()),
                "{built_in:?}"
            );
        }
        assert_eq!(
            read_init_config(b"{\"roots\":[\"AQID\",\"BA==\"]}"),
            Ok(roots_only(vec![vec![1, 2, 3], vec![4]]))
        );
        assert_eq!(
            read_init_config(
                br#"{"revocation_lists":["AQID"],"revocation_issuers":["BA=="],"distrust":[{"issuer":"ab","serial":"01"}]}"#
            ),
            Ok(InitConfig {
                roots: Vec::new(),
                revocation: Revocation {
                    lists: vec![vec![1, 2, 3]],
                    issuers: vec![vec![4]],
                    distrust: vec![("ab".to_owned(), "01".to_owned())],
                },
            })
        );
        // Empty revocation members are no setting.
        assert_eq!(
            read_init_config(br#"{"revocation_lists":[],"revocation_issuers":[],"distrust":[]}"#),
            Ok(InitConfig::default())
        );
        let other = "the configuration has a member other than \"roots\", \"revocation_lists\", \
                     \"revocation_issuers\" and \"distrust\"";
        let refused: [(&[u8], &str); 24] = [
            // One spelling for the Apple roots, `{}`: an empty list is a
            // root set that came up empty, the core's `Config` refusal.
            (b"{\"roots\":[]}", "roots must not be empty"),
            (b" { \"roots\" : [ ] } ", "roots must not be empty"),
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
            (
                br#"{"distrust":[],"distrust":[{"issuer":"a","serial":"1"}]}"#,
                "the configuration names \"distrust\" more than once",
            ),
            (
                br#"{"revocation_lists":["AQ=="],"revocation_lists":[]}"#,
                "the configuration names \"revocation_lists\" more than once",
            ),
            (b"\xff", "the configuration is not UTF-8"),
            (b"{", "the configuration is not JSON"),
            (b"[]", "the configuration is not a JSON object"),
            (b"null", "the configuration is not a JSON object"),
            (b"{\"root\":[]}", other),
            (b"{\"revocationLists\":[]}", other),
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
            (
                br#"{"revocation_lists":"AQID"}"#,
                "revocation_lists is not a list",
            ),
            (
                br#"{"revocation_lists":["AQID","A"]}"#,
                "revocation_lists[1] is not padded standard base64",
            ),
            (
                br#"{"revocation_issuers":[null]}"#,
                "revocation_issuers[0] is not a string",
            ),
            (br#"{"distrust":{}}"#, "distrust is not a list"),
            (
                br#"{"distrust":["ab:01"]}"#,
                "distrust[0] is not {\"issuer\":\"...\",\"serial\":\"...\"}",
            ),
            (
                br#"{"distrust":[{"issuer":"ab"}]}"#,
                "distrust[0] is not {\"issuer\":\"...\",\"serial\":\"...\"}",
            ),
            (
                br#"{"distrust":[{"issuer":"ab","serial":1}]}"#,
                "distrust[0] is not {\"issuer\":\"...\",\"serial\":\"...\"}",
            ),
            (
                br#"{"distrust":[{"issuer":"ab","serial":"01","note":""}]}"#,
                "distrust[0] is not {\"issuer\":\"...\",\"serial\":\"...\"}",
            ),
        ];
        for (config, message) in refused {
            assert_eq!(read_init_config(config), Err(message.to_owned()));
        }
    }
}
