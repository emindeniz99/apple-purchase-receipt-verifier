//! The legacy receipt payload: the attribute SET inside the CMS envelope,
//! decoded into [`ReceiptPayload`].
//!
//! ```text
//! SET OF ReceiptAttribute
//! ReceiptAttribute ::= SEQUENCE { type INTEGER, version INTEGER, value OCTET STRING }
//! ```
//!
//! Attribute types from Apple's archived "Receipt Fields" chapter, plus two
//! community-established ones (0 receipt type, 18 original purchase date).
//! Types 1, 15, 16 and 1713 are on none of Apple's pages either. They were
//! established by decoding a genuine production receipt and lining its
//! attributes up against the answer Apple's `verifyReceipt` endpoint gives
//! for the same receipt (measured 2026-09-21):
//!
//! ```text
//! 1     app item id               -> adam_id AND app_item_id
//! 15    download id               -> download_id
//! 16    version external id       -> version_external_identifier
//! 1713  is trial period (in-app)  -> is_trial_period
//! ```
//!
//! Type 32, the pre-order date, was established the same way, by comparing
//! production receipts with Apple's `verifyReceipt` answers on 2026-10-07
//! (the receipts are not committed). It is an `IA5String` holding an RFC 3339
//! date, like types 12 and 18, and the answer carries it as `preorder_date`.
//!
//! Decode rules: a missing attribute is `None`; the first copy of a known attribute fills its
//! field; every attribute that does not end up in a field (an unmodelled
//! type, a later copy, a value that does not parse) is kept raw in
//! `unknown_attributes`, except an empty date string, which means "not set".
//! Only an attribute SET, or an attribute, that does not parse makes the
//! whole payload unreadable.
//!
//! OpenSSL reads the ASN.1 (`aprv_openssl::payload`, the grammar declared
//! as OpenSSL templates): the SET, each attribute's three fields, each
//! value's INTEGER or string. What the types mean, which values are dates,
//! and what does or does not decode as text is decided here.

use crate::datetime::parse_receipt_date;
use crate::environment::Environment;
use aprv_openssl::payload::{attribute_integer, attribute_string, receipt_attributes, StringKind};
use aprv_openssl::Budget;
use serde_json::{json, Value};
use std::collections::BTreeMap;

// App-level attribute types.
const ATTR_RECEIPT_TYPE: u32 = 0;
const ATTR_APP_ITEM_ID: u32 = 1;
const ATTR_BUNDLE_ID: u32 = 2;
const ATTR_APP_VERSION: u32 = 3;
const ATTR_OPAQUE_VALUE: u32 = 4;
const ATTR_SHA1_HASH: u32 = 5;
const ATTR_CREATION_DATE: u32 = 12;
const ATTR_DOWNLOAD_ID: u32 = 15;
const ATTR_VERSION_EXTERNAL_IDENTIFIER: u32 = 16;
const ATTR_IN_APP: u32 = 17;
const ATTR_ORIGINAL_PURCHASE_DATE: u32 = 18;
const ATTR_ORIGINAL_APP_VERSION: u32 = 19;
const ATTR_EXPIRATION_DATE: u32 = 21;
const ATTR_PREORDER_DATE: u32 = 32;

// In-app purchase attribute types.
const IAP_QUANTITY: u32 = 1701;
const IAP_PRODUCT_ID: u32 = 1702;
const IAP_TRANSACTION_ID: u32 = 1703;
const IAP_PURCHASE_DATE: u32 = 1704;
const IAP_ORIGINAL_TRANSACTION_ID: u32 = 1705;
const IAP_ORIGINAL_PURCHASE_DATE: u32 = 1706;
const IAP_EXPIRES_DATE: u32 = 1708;
const IAP_WEB_ORDER_LINE_ITEM_ID: u32 = 1711;
const IAP_CANCELLATION_DATE: u32 = 1712;
const IAP_IS_TRIAL_PERIOD: u32 = 1713;
const IAP_IS_IN_INTRO_OFFER_PERIOD: u32 = 1719;

/// The raw attributes that did not end up in a typed field, by attribute
/// type, each type's values in receipt order.
pub type UnknownAttributes = BTreeMap<u32, Vec<Vec<u8>>>;

/// A verified legacy app receipt.
///
/// Only a value returned by
/// [`Verifier::verify_receipt`](crate::Verifier::verify_receipt) came from a
/// receipt whose chain and signature passed. The fields are public, and the type implements
/// [`Default`], so callers can build one by hand in their own tests.
///
/// Dates are epoch milliseconds, UTC. The 64-bit ids are `i64`: an ASN.1
/// INTEGER can be negative, and the decoder reports what is there.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReceiptPayload {
    /// Attribute 0, e.g. `Production` or `ProductionSandbox`.
    pub receipt_type: Option<String>,
    /// Attribute 1, the app's App Store item id. Zero in sandbox receipts.
    pub app_item_id: Option<i64>,
    /// Attribute 2, decoded.
    pub bundle_id: Option<String>,
    /// Attribute 2, the value octets as they sit in the receipt: the input
    /// to Apple's device-hash formula.
    pub bundle_id_bytes: Option<Vec<u8>>,
    /// Attribute 3.
    pub application_version: Option<String>,
    /// Attribute 4.
    pub opaque_value: Option<Vec<u8>>,
    /// Attribute 5, the SHA-1 device hash.
    pub sha1_hash: Option<Vec<u8>>,
    /// Attribute 12.
    pub receipt_creation_date_ms: Option<i64>,
    /// Attribute 15. Genuine values run to eighteen digits.
    pub download_id: Option<i64>,
    /// Attribute 16.
    pub version_external_identifier: Option<i64>,
    /// Attribute 17, one entry per copy.
    pub in_app: Vec<InAppPurchase>,
    /// Attribute 18.
    pub original_purchase_date_ms: Option<i64>,
    /// Attribute 32, the pre-order date.
    pub preorder_date_ms: Option<i64>,
    /// Attribute 19.
    pub original_application_version: Option<String>,
    /// Attribute 21.
    pub expiration_date_ms: Option<i64>,
    /// Every attribute that did not end up in a field above.
    pub unknown_attributes: UnknownAttributes,
}

/// One in-app purchase (attribute 17) of a [`ReceiptPayload`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InAppPurchase {
    /// 1701
    pub quantity: Option<i64>,
    /// 1702
    pub product_id: Option<String>,
    /// 1703
    pub transaction_id: Option<String>,
    /// 1704
    pub purchase_date_ms: Option<i64>,
    /// 1705
    pub original_transaction_id: Option<String>,
    /// 1706
    pub original_purchase_date_ms: Option<i64>,
    /// 1708
    pub expires_date_ms: Option<i64>,
    /// 1711
    pub web_order_line_item_id: Option<i64>,
    /// 1712
    pub cancellation_date_ms: Option<i64>,
    /// 1713: 0 is `false`, any other value `true`.
    pub is_trial_period: Option<bool>,
    /// 1719: 0 is `false`, any other value `true`.
    pub is_in_intro_offer_period: Option<bool>,
    /// Every attribute of this purchase that did not end up in a field.
    pub unknown_attributes: UnknownAttributes,
}

/// Why a payload could not be read at all. Carried as the
/// [`source`](std::error::Error::source) of an `UNREADABLE_PAYLOAD` failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PayloadError(String);

impl core::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PayloadError {}

fn unreadable(what: &str, err: impl core::fmt::Display) -> PayloadError {
    PayloadError(format!("{what}: {err}"))
}

/// A value that does not decode as its attribute's type. The attribute is
/// then kept raw.
struct Undecodable;

/// One entry of an attribute SET: its type, and its value still raw.
pub(crate) struct Attribute {
    attribute_type: u32,
    value: Vec<u8>,
}

/// Decodes the attributes of a receipt payload that a trusted signer has
/// signed, as [`parse_payload_attributes`] parsed them. A value that does
/// not decode is not an error: it is kept raw.
pub(crate) fn parse_receipt_payload(attributes: Vec<Attribute>) -> ReceiptPayload {
    let mut receipt = ReceiptPayload::default();
    let mut seen: Vec<u32> = Vec::new();
    for attribute in attributes {
        let value = attribute.value.as_slice();
        let known = matches!(
            attribute.attribute_type,
            ATTR_RECEIPT_TYPE
                | ATTR_APP_ITEM_ID
                | ATTR_BUNDLE_ID
                | ATTR_APP_VERSION
                | ATTR_OPAQUE_VALUE
                | ATTR_SHA1_HASH
                | ATTR_CREATION_DATE
                | ATTR_DOWNLOAD_ID
                | ATTR_VERSION_EXTERNAL_IDENTIFIER
                | ATTR_ORIGINAL_PURCHASE_DATE
                | ATTR_ORIGINAL_APP_VERSION
                | ATTR_EXPIRATION_DATE
                | ATTR_PREORDER_DATE
        );
        if known && is_later_copy(&mut seen, attribute.attribute_type) {
            keep_raw(&mut receipt.unknown_attributes, attribute);
            continue;
        }
        let decoded = match attribute.attribute_type {
            ATTR_RECEIPT_TYPE => decode_string(value).map(|v| receipt.receipt_type = Some(v)),
            ATTR_APP_ITEM_ID => decode_integer(value).map(|v| receipt.app_item_id = Some(v)),
            ATTR_BUNDLE_ID => {
                // The octets are a field of their own, kept even when the
                // string does not decode, so they are never kept raw.
                receipt.bundle_id_bytes = Some(value.to_vec());
                receipt.bundle_id = decode_string(value).ok();
                Ok(())
            }
            ATTR_APP_VERSION => decode_string(value).map(|v| receipt.application_version = Some(v)),
            ATTR_OPAQUE_VALUE => {
                receipt.opaque_value = Some(value.to_vec());
                Ok(())
            }
            ATTR_SHA1_HASH => {
                receipt.sha1_hash = Some(value.to_vec());
                Ok(())
            }
            ATTR_CREATION_DATE => date(value).map(|v| receipt.receipt_creation_date_ms = v),
            ATTR_DOWNLOAD_ID => decode_integer(value).map(|v| receipt.download_id = Some(v)),
            ATTR_VERSION_EXTERNAL_IDENTIFIER => {
                decode_integer(value).map(|v| receipt.version_external_identifier = Some(v))
            }
            ATTR_IN_APP => parse_in_app(value).map(|v| receipt.in_app.push(v)),
            ATTR_ORIGINAL_PURCHASE_DATE => {
                date(value).map(|v| receipt.original_purchase_date_ms = v)
            }
            ATTR_ORIGINAL_APP_VERSION => {
                decode_string(value).map(|v| receipt.original_application_version = Some(v))
            }
            ATTR_EXPIRATION_DATE => date(value).map(|v| receipt.expiration_date_ms = v),
            ATTR_PREORDER_DATE => date(value).map(|v| receipt.preorder_date_ms = v),
            _ => Err(Undecodable),
        };
        if decoded.is_err() {
            keep_raw(&mut receipt.unknown_attributes, attribute);
        }
    }
    receipt
}

/// An in-app purchase. Anything that stops it from parsing, its attribute
/// SET or one of its attributes, makes the whole attribute 17 raw.
fn parse_in_app(value: &[u8]) -> Result<InAppPurchase, Undecodable> {
    let attributes =
        parse_attribute_set(value, "in-app purchase attribute").map_err(|_| Undecodable)?;
    let mut purchase = InAppPurchase::default();
    let mut seen: Vec<u32> = Vec::new();
    for attribute in attributes {
        let value = attribute.value.as_slice();
        let known = matches!(
            attribute.attribute_type,
            IAP_QUANTITY
                | IAP_PRODUCT_ID
                | IAP_TRANSACTION_ID
                | IAP_PURCHASE_DATE
                | IAP_ORIGINAL_TRANSACTION_ID
                | IAP_ORIGINAL_PURCHASE_DATE
                | IAP_EXPIRES_DATE
                | IAP_WEB_ORDER_LINE_ITEM_ID
                | IAP_CANCELLATION_DATE
                | IAP_IS_TRIAL_PERIOD
                | IAP_IS_IN_INTRO_OFFER_PERIOD
        );
        if known && is_later_copy(&mut seen, attribute.attribute_type) {
            keep_raw(&mut purchase.unknown_attributes, attribute);
            continue;
        }
        let decoded = match attribute.attribute_type {
            IAP_QUANTITY => decode_integer(value).map(|v| purchase.quantity = Some(v)),
            IAP_PRODUCT_ID => decode_string(value).map(|v| purchase.product_id = Some(v)),
            IAP_TRANSACTION_ID => decode_string(value).map(|v| purchase.transaction_id = Some(v)),
            IAP_PURCHASE_DATE => date(value).map(|v| purchase.purchase_date_ms = v),
            IAP_ORIGINAL_TRANSACTION_ID => {
                decode_string(value).map(|v| purchase.original_transaction_id = Some(v))
            }
            IAP_ORIGINAL_PURCHASE_DATE => {
                date(value).map(|v| purchase.original_purchase_date_ms = v)
            }
            IAP_EXPIRES_DATE => date(value).map(|v| purchase.expires_date_ms = v),
            IAP_WEB_ORDER_LINE_ITEM_ID => {
                decode_integer(value).map(|v| purchase.web_order_line_item_id = Some(v))
            }
            IAP_CANCELLATION_DATE => date(value).map(|v| purchase.cancellation_date_ms = v),
            IAP_IS_TRIAL_PERIOD => {
                decode_integer(value).map(|v| purchase.is_trial_period = Some(v != 0))
            }
            IAP_IS_IN_INTRO_OFFER_PERIOD => {
                decode_integer(value).map(|v| purchase.is_in_intro_offer_period = Some(v != 0))
            }
            _ => Err(Undecodable),
        };
        if decoded.is_err() {
            keep_raw(&mut purchase.unknown_attributes, attribute);
        }
    }
    Ok(purchase)
}

/// Whether `attribute_type` was already seen in this SET; records it if not.
/// The first copy of a known attribute decides its field, and a later one is
/// kept raw.
fn is_later_copy(seen: &mut Vec<u32>, attribute_type: u32) -> bool {
    if seen.contains(&attribute_type) {
        return true;
    }
    seen.push(attribute_type);
    false
}

fn keep_raw(unknown: &mut UnknownAttributes, attribute: Attribute) {
    unknown
        .entry(attribute.attribute_type)
        .or_default()
        .push(attribute.value);
}

/// A payload's top-level attribute SET, parsed the only way anything in a
/// payload is parsed before its signer is trusted: walked under the depth
/// and node bounds, which cap the work at 100,000 values whatever the
/// input, into each entry's type and raw value. An entry the walk cannot
/// read fails the parse as a whole rather than being skipped, since it
/// might have been the first attribute 12.
pub(crate) fn parse_payload_attributes(content: &[u8]) -> Result<Vec<Attribute>, PayloadError> {
    parse_attribute_set(content, "receipt payload")
}

/// The receipt creation date, the one value read before the signer is
/// trusted. `None` means "judge the chain at the clock": no attribute 12,
/// or a first one that is empty or does not decode. Never an error:
/// nothing is trusted yet, so nothing here can blame anyone.
pub(crate) fn creation_date(attributes: &[Attribute]) -> Option<i64> {
    let first = attributes
        .iter()
        .find(|attribute| attribute.attribute_type == ATTR_CREATION_DATE)?;
    date(&first.value).ok().flatten()
}

/// How deep constructed values may nest in a value parsed on its own: the
/// CMS envelope from its `ContentInfo`, the signed content from its
/// attribute SET (0.7 bounds table). 32 is accepted and 33 refused.
pub(crate) const MAX_ASN1_DEPTH: usize = 32;

/// How many values, primitive ones included, a value parsed on its own may
/// hold: 0.7's reader's node budget, kept so that no input makes a decode
/// build more than this many values before it is refused.
pub(crate) const MAX_ASN1_NODES: usize = 100_000;

/// The walk budget of each attribute SET: the payload's, and each in-app
/// purchase's, which is parsed on its own.
const PAYLOAD_BUDGET: Budget = Budget {
    depth: MAX_ASN1_DEPTH,
    nodes: MAX_ASN1_NODES,
};

fn parse_attribute_set(der: &[u8], what: &str) -> Result<Vec<Attribute>, PayloadError> {
    // The Xcode double wrap (one more OCTET STRING around the SET) is
    // unwrapped by the adapter.
    let attributes =
        receipt_attributes(der, PAYLOAD_BUDGET).map_err(|err| unreadable(what, err))?;
    attributes
        .into_iter()
        .map(|attribute| {
            // Refused rather than narrowed: narrowing would invent an
            // attribute the receipt never carried.
            let attribute_type = u32::try_from(attribute.attribute_type)
                .ok()
                .filter(|value| i32::try_from(*value).is_ok())
                .ok_or_else(|| unreadable(what, "receipt attribute type out of range"))?;
            Ok(Attribute {
                attribute_type,
                value: attribute.value,
            })
        })
        .collect()
}

/// A `UTF8String` or an `IA5String`, the two string types Apple's receipts
/// use. A `UTF8String` must be valid UTF-8; an `IA5String` must be ASCII,
/// as IA5 is: a byte from 0x80 up does not decode, rather than being read as
/// Latin-1.
fn decode_string(der: &[u8]) -> Result<String, Undecodable> {
    match attribute_string(der) {
        Ok((StringKind::Utf8, octets)) => String::from_utf8(octets).map_err(|_| Undecodable),
        Ok((StringKind::Ia5, octets)) if octets.is_ascii() => {
            Ok(octets.iter().map(|byte| char::from(*byte)).collect())
        }
        _ => Err(Undecodable),
    }
}

/// An INTEGER that fits a signed 64-bit value, negative ones included. One
/// that is empty or has a redundant leading octet is not DER, and OpenSSL
/// refuses it.
fn decode_integer(der: &[u8]) -> Result<i64, Undecodable> {
    attribute_integer(der).map_err(|_| Undecodable)
}

/// A date in an `IA5String` or `UTF8String`, as epoch milliseconds. An
/// empty string is `Ok(None)`: Apple writes an unset date that way, so it is
/// not kept raw. Anything else must be an RFC 3339 `date-time`; see
/// [`parse_receipt_date`].
fn date(der: &[u8]) -> Result<Option<i64>, Undecodable> {
    let text = decode_string(der)?;
    if text.is_empty() {
        return Ok(None);
    }
    parse_receipt_date(&text).map(Some).ok_or(Undecodable)
}

// ------------------------------------------------------------------ JSON

/// A 64-bit id as a JSON string, so JavaScript readers do not round it.
fn id_json(value: Option<i64>) -> Value {
    value.map_or(Value::Null, |value| Value::String(value.to_string()))
}

/// Bytes as padded standard base64.
fn bytes_json(value: Option<&[u8]>) -> Value {
    value.map_or(Value::Null, |value| {
        Value::String(crate::base64::encode(value))
    })
}

/// `{"13": ["<base64>", ...]}`, each type's values in receipt order.
fn attributes_json(attributes: &UnknownAttributes) -> Value {
    Value::Object(
        attributes
            .iter()
            .map(|(attribute_type, values)| {
                let values = values
                    .iter()
                    .map(|value| Value::String(crate::base64::encode(value)))
                    .collect();
                (attribute_type.to_string(), Value::Array(values))
            })
            .collect(),
    )
}

impl ReceiptPayload {
    /// The environment the receipt names, read from
    /// [`receipt_type`](ReceiptPayload::receipt_type): `Production` and
    /// `ProductionVPP` are [`Environment::Production`], `ProductionSandbox`
    /// and `ProductionVPPSandbox` are [`Environment::Sandbox`], anything
    /// else (`Xcode`, a missing value) is `None`. It states what Apple's
    /// value means and decides nothing; whether to accept it is the
    /// caller's decision. The endpoint routes 21007 and 21008 on the same
    /// rule.
    #[must_use]
    pub fn environment(&self) -> Option<Environment> {
        Environment::from_receipt_type(self.receipt_type.as_deref())
    }

    /// This payload as JSON (docs/design/0.7-api.md "Our JSON"). It holds the
    /// full purchase data; the caller decides what to write where. Every port
    /// writes the same value; the bytes may differ.
    /// `null` for a missing field, 64-bit ids as strings, bytes as padded
    /// standard base64, dates as epoch-millisecond numbers.
    ///
    /// `receipt_type`, `app_item_id`, `bundle_id`, `bundle_id_bytes`,
    /// `application_version`, `opaque_value`, `sha1_hash`,
    /// `receipt_creation_date_ms`, `download_id`,
    /// `version_external_identifier`, `in_app`, `original_purchase_date_ms`,
    /// `preorder_date_ms`, `original_application_version`,
    /// `expiration_date_ms`, `unknown_attributes`.
    #[must_use]
    pub fn to_json(&self) -> String {
        json!({
            "receipt_type": self.receipt_type,
            "app_item_id": id_json(self.app_item_id),
            "bundle_id": self.bundle_id,
            "bundle_id_bytes": bytes_json(self.bundle_id_bytes.as_deref()),
            "application_version": self.application_version,
            "opaque_value": bytes_json(self.opaque_value.as_deref()),
            "sha1_hash": bytes_json(self.sha1_hash.as_deref()),
            "receipt_creation_date_ms": self.receipt_creation_date_ms,
            "download_id": id_json(self.download_id),
            "version_external_identifier": id_json(self.version_external_identifier),
            "in_app": self.in_app.iter().map(InAppPurchase::json_value).collect::<Vec<_>>(),
            "original_purchase_date_ms": self.original_purchase_date_ms,
            "preorder_date_ms": self.preorder_date_ms,
            "original_application_version": self.original_application_version,
            "expiration_date_ms": self.expiration_date_ms,
            "unknown_attributes": attributes_json(&self.unknown_attributes),
        })
        .to_string()
    }
}

impl InAppPurchase {
    fn json_value(&self) -> Value {
        json!({
            "quantity": self.quantity,
            "product_id": self.product_id,
            "transaction_id": self.transaction_id,
            "purchase_date_ms": self.purchase_date_ms,
            "original_transaction_id": self.original_transaction_id,
            "original_purchase_date_ms": self.original_purchase_date_ms,
            "expires_date_ms": self.expires_date_ms,
            "web_order_line_item_id": id_json(self.web_order_line_item_id),
            "cancellation_date_ms": self.cancellation_date_ms,
            "is_trial_period": self.is_trial_period,
            "is_in_intro_offer_period": self.is_in_intro_offer_period,
            "unknown_attributes": attributes_json(&self.unknown_attributes),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    //! The payload grammar, tested against the decoder itself. Through the
    //! verifier these payloads would need a trusted signer, because nothing
    //! but the creation date is decoded until the chain and the signature
    //! have passed.

    use super::{
        creation_date, parse_payload_attributes, InAppPurchase, PayloadError, ReceiptPayload,
    };

    /// The verifier's two readings of one payload's single parse: all of
    /// it once the signature has passed, and the creation date before.
    fn parse_receipt_payload(content: &[u8]) -> Result<ReceiptPayload, PayloadError> {
        parse_payload_attributes(content).map(super::parse_receipt_payload)
    }

    fn read_creation_date(content: &[u8]) -> Option<i64> {
        parse_payload_attributes(content)
            .ok()
            .as_deref()
            .and_then(creation_date)
    }

    /// The universal tags these tests write.
    mod tag {
        pub const INTEGER: u8 = 0x02;
        pub const OCTET_STRING: u8 = 0x04;
        pub const IA5_STRING: u8 = 0x16;
        pub const SEQUENCE: u8 = 0x30;
        pub const SET: u8 = 0x31;
    }

    /// The ASN.1 nesting bound of 0.7's bounds table.
    const MAX_DEPTH: usize = 32;

    fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
        assert!(contents.len() < 0x80, "short-form lengths only");
        let mut out = vec![tag, u8::try_from(contents.len()).unwrap()];
        out.extend_from_slice(contents);
        out
    }

    fn int(bytes: &[u8]) -> Vec<u8> {
        der(tag::INTEGER, bytes)
    }

    fn attribute(type_bytes: &[u8], value: &[u8]) -> Vec<u8> {
        der(
            tag::SEQUENCE,
            &[int(type_bytes), int(&[1]), der(tag::OCTET_STRING, value)].concat(),
        )
    }

    fn set(entries: &[Vec<u8>]) -> Vec<u8> {
        der(tag::SET, &entries.concat())
    }

    fn ia5(text: &str) -> Vec<u8> {
        der(tag::IA5_STRING, text.as_bytes())
    }

    fn date(text: &str) -> Vec<u8> {
        attribute(&[12], &ia5(text))
    }

    #[test]
    fn a_payload_whose_set_or_attribute_does_not_parse_is_unreadable() {
        for payload in [
            der(tag::SEQUENCE, &int(&[1])),
            set(&[der(tag::SEQUENCE, &[int(&[2]), int(&[1])].concat())]),
            set(&[attribute(&[0xff], &ia5("x"))]),
            set(&[attribute(&[0x00, 0x80, 0, 0, 0], &[1, 2, 3])]),
            set(&[attribute(&[0x00, 0x01], &[1])]),
            set(&[attribute(&[], &[1])]),
        ] {
            assert!(parse_receipt_payload(&payload).is_err(), "{payload:02x?}");
        }
    }

    #[test]
    fn the_first_copy_of_a_known_attribute_wins_and_later_ones_are_kept_raw() {
        let first = ia5("com.example.first");
        let second = ia5("com.example.second");
        let receipt =
            parse_receipt_payload(&set(&[attribute(&[3], &first), attribute(&[3], &second)]))
                .unwrap();
        assert_eq!(
            receipt.application_version.as_deref(),
            Some("com.example.first")
        );
        assert_eq!(receipt.unknown_attributes.get(&3), Some(&vec![second]));
    }

    #[test]
    fn a_value_that_does_not_decode_is_null_and_kept_raw() {
        let not_a_date = ia5("not-a-date");
        let not_an_integer = ia5("7");
        let receipt = parse_receipt_payload(&set(&[
            attribute(&[12], &not_a_date),
            attribute(&[15], &not_an_integer),
        ]))
        .unwrap();
        assert_eq!(receipt.receipt_creation_date_ms, None);
        assert_eq!(receipt.download_id, None);
        assert_eq!(receipt.unknown_attributes.get(&12), Some(&vec![not_a_date]));
        assert_eq!(
            receipt.unknown_attributes.get(&15),
            Some(&vec![not_an_integer])
        );
    }

    #[test]
    fn an_ia5_string_with_a_byte_from_0x80_up_is_kept_raw() {
        // IA5 is seven-bit: 0xE9 is no IA5 character, so it is not read as
        // Latin-1. Top level and in-app alike.
        let not_ia5 = der(tag::IA5_STRING, b"caf\xe9");
        let in_app = set(&[attribute(&[0x06, 0xa6], &not_ia5)]);
        let receipt = parse_receipt_payload(&set(&[
            attribute(&[3], &not_ia5),
            attribute(&[17], &in_app),
        ]))
        .unwrap();
        assert_eq!(receipt.application_version, None);
        assert_eq!(
            receipt.unknown_attributes.get(&3),
            Some(&vec![not_ia5.clone()])
        );
        let purchase = receipt.in_app.first().unwrap();
        assert_eq!(purchase.product_id, None);
        assert_eq!(purchase.unknown_attributes.get(&1702), Some(&vec![not_ia5]));
        // Seven-bit text still decodes.
        let receipt = parse_receipt_payload(&set(&[attribute(&[3], &ia5("1.0\u{7f}"))])).unwrap();
        assert_eq!(receipt.application_version.as_deref(), Some("1.0\u{7f}"));
    }

    #[test]
    fn an_integer_or_flag_that_is_not_minimally_encoded_is_kept_raw() {
        let padded = der(tag::INTEGER, &[0x00, 0x01]);
        let in_app = set(&[attribute(&[0x06, 0xb1], &padded)]);
        let receipt =
            parse_receipt_payload(&set(&[attribute(&[1], &padded), attribute(&[17], &in_app)]))
                .unwrap();
        assert_eq!(receipt.app_item_id, None);
        assert_eq!(
            receipt.unknown_attributes.get(&1),
            Some(&vec![padded.clone()])
        );
        let purchase = receipt.in_app.first().unwrap();
        assert_eq!(purchase.is_trial_period, None);
        assert_eq!(purchase.unknown_attributes.get(&1713), Some(&vec![padded]));
    }

    #[test]
    fn a_date_in_any_other_form_is_kept_raw_and_does_not_set_the_chain_instant() {
        // Any RFC 3339 date-time (owner, Q68, 2026-10-06).
        for (text, millis) in [
            ("2024-08-06T12:00:00Z", 1_722_945_600_000),
            ("2024-08-06t15:00:00.123+03:00", 1_722_945_600_123),
        ] {
            let receipt = parse_receipt_payload(&set(&[date(text)])).unwrap();
            assert_eq!(receipt.receipt_creation_date_ms, Some(millis), "{text}");
            assert!(receipt.unknown_attributes.is_empty(), "{text}");
            assert_eq!(read_creation_date(&set(&[date(text)])), Some(millis));
        }
        for text in [
            "2024-08-06 12:00:00Z",
            "2024-08-06T12:00:00+0300",
            "2024-08-06T12:00Z",
        ] {
            let receipt = parse_receipt_payload(&set(&[date(text)])).unwrap();
            assert_eq!(receipt.receipt_creation_date_ms, None, "{text}");
            assert_eq!(receipt.unknown_attributes.get(&12), Some(&vec![ia5(text)]));
            assert_eq!(read_creation_date(&set(&[date(text)])), None, "{text}");
        }
    }

    #[test]
    fn attribute_32_is_the_preorder_date_and_reads_like_attributes_12_and_18() {
        // Same grammar and same failure behaviour as the other receipt-level
        // dates: an RFC 3339 date-time fills the field, an empty string means
        // "not set", anything else (and a later copy) is kept raw.
        let attribute_32 = |text: &str| attribute(&[32], &ia5(text));
        let receipt = parse_receipt_payload(&set(&[attribute_32("2024-07-02T09:45:20Z")])).unwrap();
        assert_eq!(receipt.preorder_date_ms, Some(1_719_913_520_000));
        assert!(receipt.unknown_attributes.is_empty());
        let written: serde_json::Value = serde_json::from_str(&receipt.to_json()).unwrap();
        assert_eq!(
            written.get("preorder_date_ms"),
            Some(&serde_json::json!(1_719_913_520_000_i64))
        );

        let receipt = parse_receipt_payload(&set(&[attribute_32("")])).unwrap();
        assert_eq!(receipt.preorder_date_ms, None);
        assert!(receipt.unknown_attributes.is_empty());

        let receipt = parse_receipt_payload(&set(&[attribute_32("2024-07-02 09:45:20Z")])).unwrap();
        assert_eq!(receipt.preorder_date_ms, None);
        assert_eq!(
            receipt.unknown_attributes.get(&32),
            Some(&vec![ia5("2024-07-02 09:45:20Z")])
        );

        let receipt = parse_receipt_payload(&set(&[
            attribute_32("2024-07-02T09:45:20Z"),
            attribute_32("2024-07-03T09:45:20Z"),
        ]))
        .unwrap();
        assert_eq!(receipt.preorder_date_ms, Some(1_719_913_520_000));
        assert_eq!(
            receipt.unknown_attributes.get(&32),
            Some(&vec![ia5("2024-07-03T09:45:20Z")])
        );
    }

    #[test]
    fn signed_content_nested_past_the_asn1_bound_is_unreadable() {
        // Signed content nested past the bound (32 constructed values)
        // cannot be read, which the verifier reports as UNREADABLE_PAYLOAD,
        // never MALFORMED. OpenSSL's template decoder refuses it well before
        // any depth counting: a SET inside the SET is not an attribute.
        let mut nested: Vec<u8> = Vec::new();
        for _ in 0..=MAX_DEPTH {
            let length = u8::try_from(nested.len()).unwrap();
            nested = if length < 0x80 {
                [&[tag::SET, length][..], &nested].concat()
            } else {
                [&[tag::SET, 0x81, length][..], &nested].concat()
            };
        }
        assert!(parse_receipt_payload(&nested).is_err());
    }

    /// One TLV with a definite length of any size.
    fn der_long(tag: u8, contents: &[u8]) -> Vec<u8> {
        if contents.len() < 0x80 {
            return der(tag, contents);
        }
        let length = contents.len().to_be_bytes();
        let significant: Vec<u8> = length
            .iter()
            .copied()
            .skip_while(|byte| *byte == 0)
            .collect();
        let mut out = vec![tag, 0x80 | u8::try_from(significant.len()).unwrap()];
        out.extend_from_slice(&significant);
        out.extend_from_slice(contents);
        out
    }

    /// An attribute 9000 whose fourth field is `fourth`.
    fn with_fourth_field(fourth: &[u8]) -> Vec<u8> {
        der_long(
            tag::SEQUENCE,
            &[
                int(&[0x23, 0x28]),
                int(&[1]),
                der(tag::OCTET_STRING, &int(&[1])),
                fourth.to_vec(),
            ]
            .concat(),
        )
    }

    fn nested_in(identifier: u8, levels: usize) -> Vec<u8> {
        let mut value = int(&[1]);
        for _ in 0..levels {
            value = der_long(identifier, &value);
        }
        value
    }

    #[test]
    fn signed_content_nested_33_deep_is_unreadable_whatever_the_tags() {
        // C-F2, Rust-F3: the depth used to be measured through universal
        // SEQUENCEs and SETs only, so 40 levels of context or application
        // tags read. The SET is 1 and the attribute 2, so a fourth field of
        // 30 levels is 32 deep and of 31 levels 33.
        for identifier in [tag::SEQUENCE, 0xa0, 0x61] {
            let at_bound = set(&[
                date("2024-08-06T12:00:00Z"),
                with_fourth_field(&nested_in(identifier, 30)),
            ]);
            assert!(parse_receipt_payload(&at_bound).is_ok(), "{identifier:02x}");
            let over = set(&[
                date("2024-08-06T12:00:00Z"),
                with_fourth_field(&nested_in(identifier, 31)),
            ]);
            assert!(parse_receipt_payload(&over).is_err(), "{identifier:02x}");
            assert_eq!(read_creation_date(&over), None, "{identifier:02x}");
        }
        let under_a_sequence = der(tag::SEQUENCE, &nested_in(0xa0, 30));
        assert!(parse_receipt_payload(&set(&[with_fourth_field(&under_a_sequence)])).is_err());
    }

    #[test]
    fn the_payload_holds_at_most_100000_values() {
        // Rust-F4, Policy-F6: 0.7's reader capped a parse at 100,000 values;
        // without it a 3 MiB payload of tiny values cost 300 to 700 ms
        // before any signature. The SET, the attribute, its three fields
        // and the fourth field's SEQUENCE are 6 values.
        let flood = |count: usize| {
            let fourth = der_long(tag::SEQUENCE, &[0x05, 0x00].repeat(count));
            der_long(
                tag::SET,
                &[date("2024-08-06T12:00:00Z"), with_fourth_field(&fourth)].concat(),
            )
        };
        // The date attribute is 4 more values and its string is inside a
        // primitive OCTET STRING, so it adds none.
        let at_budget = flood(100_000 - 6 - 4);
        assert!(parse_receipt_payload(&at_budget).is_ok());
        assert_eq!(read_creation_date(&at_budget), Some(1_722_945_600_000));
        let over = flood(100_000 - 6 - 4 + 1);
        assert!(parse_receipt_payload(&over).is_err());
        assert_eq!(read_creation_date(&over), None);
    }

    /// An OCTET STRING of `levels` constructed levels around `inner`, the
    /// innermost chunk tagged `leaf`.
    fn chunked(levels: usize, leaf: u8, inner: &[u8]) -> Vec<u8> {
        let mut value = der_long(leaf, inner);
        for _ in 0..levels {
            value = der_long(0x24, &value);
        }
        value
    }

    fn raw_attribute(type_tlv: &[u8], value_tlv: &[u8]) -> Vec<u8> {
        der(tag::SEQUENCE, &[type_tlv, &int(&[1]), value_tlv].concat())
    }

    #[test]
    fn a_value_or_a_wrap_with_a_chunk_that_is_not_an_octet_string_is_unreadable() {
        // C-F3, Rust-F6, Policy-F5: OpenSSL joins the chunks of a
        // constructed OCTET STRING whatever their tag; X.690 section 8.7.3
        // allows only OCTET STRINGs, and 0.7 and Java refuse the others.
        let bundle = der(0x0c, b"com.example.app");
        let legal = set(&[raw_attribute(
            &int(&[2]),
            &chunked(2, tag::OCTET_STRING, &bundle),
        )]);
        let receipt = parse_receipt_payload(&legal).unwrap();
        assert_eq!(receipt.bundle_id.as_deref(), Some("com.example.app"));
        let foreign = set(&[raw_attribute(&int(&[2]), &chunked(1, 0x0c, &bundle))]);
        assert!(parse_receipt_payload(&foreign).is_err());
        // Six constructed levels decode, as OpenSSL decodes them; a
        // seventh does not (DECISIONS.md R20).
        let six = set(&[raw_attribute(
            &int(&[2]),
            &chunked(6, tag::OCTET_STRING, &bundle),
        )]);
        assert!(parse_receipt_payload(&six).is_ok());
        let seven = set(&[raw_attribute(
            &int(&[2]),
            &chunked(7, tag::OCTET_STRING, &bundle),
        )]);
        assert!(parse_receipt_payload(&seven).is_err());

        let payload = set(&[date("2024-08-06T12:00:00Z")]);
        let wrapped = parse_receipt_payload(&chunked(1, tag::OCTET_STRING, &payload)).unwrap();
        assert_eq!(wrapped.receipt_creation_date_ms, Some(1_722_945_600_000));
        for leaf in [0x0c, tag::INTEGER] {
            let foreign_wrap = chunked(1, leaf, &payload);
            assert!(parse_receipt_payload(&foreign_wrap).is_err(), "{leaf:02x}");
            assert_eq!(read_creation_date(&foreign_wrap), None, "{leaf:02x}");
        }
    }

    #[test]
    fn a_constructed_string_value_is_kept_raw() {
        // C-F3: OpenSSL joins a constructed UTF8String's chunks; 0.7 did not
        // read one as a string, and DER has none.
        let mut constructed = vec![0x2c, 0x80];
        constructed.extend(der(tag::OCTET_STRING, b"com.example.app"));
        constructed.extend([0, 0]);
        let receipt = parse_receipt_payload(&set(&[
            raw_attribute(&int(&[2]), &der(tag::OCTET_STRING, &constructed)),
            raw_attribute(&int(&[3]), &der(tag::OCTET_STRING, &constructed)),
        ]))
        .unwrap();
        assert_eq!(receipt.bundle_id, None);
        assert_eq!(receipt.bundle_id_bytes, Some(constructed.clone()));
        assert_eq!(receipt.application_version, None);
        assert_eq!(receipt.unknown_attributes.get(&3), Some(&vec![constructed]));
    }

    #[test]
    fn a_tag_in_high_tag_form_or_a_five_octet_length_is_not_read() {
        // C-F3: 0.7's reader refused both anywhere; OpenSSL reads them. In
        // the SET they make the payload unreadable, in a value they keep the
        // attribute raw.
        let high_tag_type = raw_attribute(
            &[0x1f, 0x02, 0x01, 0x02],
            &der(tag::OCTET_STRING, &ia5("x")),
        );
        assert!(parse_receipt_payload(&set(&[high_tag_type])).is_err());
        let high_tag_value = [0x1f, 0x02, 0x01, 0x05];
        let receipt = parse_receipt_payload(&set(&[attribute(&[1], &high_tag_value)])).unwrap();
        assert_eq!(receipt.app_item_id, None);
        assert_eq!(
            receipt.unknown_attributes.get(&1),
            Some(&vec![high_tag_value.to_vec()])
        );

        let mut five_octets = vec![0x0c, 0x85, 0, 0, 0, 0, 15];
        five_octets.extend(b"com.example.app");
        let receipt = parse_receipt_payload(&set(&[attribute(&[2], &five_octets)])).unwrap();
        assert_eq!(receipt.bundle_id, None);
        assert_eq!(receipt.bundle_id_bytes, Some(five_octets));
        let long_set = [&[tag::SET, 0x85, 0, 0, 0, 0, 0][..]].concat();
        assert!(parse_receipt_payload(&long_set).is_err());
        // Four length octets, not minimal, are read, as 0.7 read them.
        let four_octets = [&[tag::SET, 0x84, 0, 0, 0, 0][..]].concat();
        assert!(parse_receipt_payload(&four_octets).is_ok());
    }

    #[test]
    fn fields_after_the_value_are_valid_asn1_at_every_depth() {
        // C-F3: a BOOLEAN of two octets, a NULL with content or a padded
        // INTEGER is not valid ASN.1 (X.690 sections 8.2, 8.8 and 8.3.2, BER
        // and DER alike), so the payload is unreadable, whether the value is
        // the fourth field itself, which OpenSSL's ANY decodes, or sits
        // inside it, which the header walk hands to the same decoder. 0.7
        // kept the fourth field opaque; Java refuses both.
        let padded = [0x02, 0x02, 0x00, 0x01];
        for fourth in [
            vec![0x01, 0x02, 0x00, 0x00],
            vec![0x05, 0x01, 0x00],
            padded.to_vec(),
            der(tag::SEQUENCE, &padded),
            der(0xa0, &der(tag::SEQUENCE, &padded)),
        ] {
            let payload = set(&[with_fourth_field(&fourth)]);
            assert!(parse_receipt_payload(&payload).is_err(), "{fourth:02x?}");
        }
        let valid = der(
            0xa0,
            &der(tag::SEQUENCE, &[int(&[1]), der(0x05, &[])].concat()),
        );
        assert!(parse_receipt_payload(&set(&[with_fourth_field(&valid)])).is_ok());
    }

    #[test]
    fn what_openssl_refuses_on_its_own_is_refused_one_sequence_deeper_too() {
        // Round-2 review F3: OpenSSL's ANY decoder refuses these as the
        // fourth field, but the walk passed them one SEQUENCE deeper, where
        // OpenSSL keeps the SEQUENCE whole, so the verdict depended on the
        // depth. A short UTCTime or GeneralizedTime, a constructed BOOLEAN,
        // INTEGER, NULL, OID or ENUMERATED, a primitive SEQUENCE, an
        // end-of-contents inside a definite length, a constructed time
        // whose joined octets are too short, and a string of seven
        // constructed levels (ASN1_MAX_STRING_NEST).
        let refused: [Vec<u8>; 12] = [
            vec![0x17, 0x01, 0x30],
            vec![0x18, 0x02, 0x32, 0x30],
            vec![0x21, 0x03, 0x01, 0x01, 0xff],
            vec![0x22, 0x03, 0x02, 0x01, 0x05],
            vec![0x25, 0x02, 0x05, 0x00],
            vec![0x26, 0x03, 0x06, 0x01, 0x2a],
            vec![0x2a, 0x03, 0x0a, 0x01, 0x01],
            vec![0x30, 0x02, 0x10, 0x00],
            vec![0x24, 0x05, 0x04, 0x01, 0x41, 0x00, 0x00],
            [&[0x37, 0x10][..], &der(4, b"240101"), &der(4, b"00000Z")].concat(),
            chunked(7, tag::OCTET_STRING, b"x"),
            chunked(7, 0x0c, b"x"),
        ];
        for value in &refused {
            for fourth in [value.clone(), der_long(tag::SEQUENCE, value)] {
                let payload = set(&[with_fourth_field(&fourth)]);
                assert!(parse_receipt_payload(&payload).is_err(), "{fourth:02x?}");
            }
        }
        // What OpenSSL decodes stays readable at both depths: a
        // constructed time of 13 joined octets, a constructed BIT STRING,
        // six constructed levels, a SEQUENCE-tagged chunk inside a string.
        let accepted: [Vec<u8>; 4] = [
            [&[0x37, 0x11][..], &der(4, b"240101"), &der(4, b"000000Z")].concat(),
            vec![0x23, 0x04, 0x03, 0x02, 0x00, 0x01],
            chunked(6, tag::OCTET_STRING, b"x"),
            vec![0x24, 0x05, 0x30, 0x03, 0x04, 0x01, 0x41],
        ];
        for value in &accepted {
            for fourth in [value.clone(), der_long(tag::SEQUENCE, value)] {
                let payload = set(&[with_fourth_field(&fourth)]);
                assert!(parse_receipt_payload(&payload).is_ok(), "{fourth:02x?}");
            }
        }
    }

    #[test]
    fn seven_constructed_levels_are_refused_wherever_openssl_decodes_a_string() {
        // N1, N2: OpenSSL joins six constructed levels of a string and no
        // more, wherever it decodes one: the value, the version field, the
        // Xcode wrap. Six read; seven are unreadable, refused by OpenSSL's
        // own decoder when the walk hands it the whole string, so the
        // detail does not blame a chunk's type.
        let bundle = der(0x0c, b"com.example.app");
        let version = |levels| {
            set(&[der(
                tag::SEQUENCE,
                &[
                    int(&[2]),
                    chunked(levels, tag::OCTET_STRING, &[1]),
                    der(tag::OCTET_STRING, &bundle),
                ]
                .concat(),
            )])
        };
        let value = |levels| {
            set(&[raw_attribute(
                &int(&[2]),
                &chunked(levels, tag::OCTET_STRING, &bundle),
            )])
        };
        let payload = set(&[date("2024-08-06T12:00:00Z")]);
        let wrap = |levels| chunked(levels, tag::OCTET_STRING, &payload);
        for build in [&version as &dyn Fn(usize) -> Vec<u8>, &value, &wrap] {
            assert!(parse_receipt_payload(&build(6)).is_ok());
            let refused = parse_receipt_payload(&build(7)).unwrap_err().to_string();
            assert!(
                refused.contains("payload is not one well-formed value"),
                "{refused}"
            );
        }
    }

    #[test]
    fn an_empty_date_means_not_set_and_is_not_kept() {
        let receipt = parse_receipt_payload(&set(&[date(""), attribute(&[21], &ia5(""))])).unwrap();
        assert_eq!(receipt.receipt_creation_date_ms, None);
        assert_eq!(receipt.expiration_date_ms, None);
        assert!(receipt.unknown_attributes.is_empty());
    }

    #[test]
    fn integers_are_reported_as_they_are_negative_ones_included() {
        let receipt = parse_receipt_payload(&set(&[attribute(&[1], &int(&[0xff]))])).unwrap();
        assert_eq!(receipt.app_item_id, Some(-1));
        let wide = der(tag::INTEGER, &[0x01, 0, 0, 0, 0, 0, 0, 0, 0]);
        let receipt = parse_receipt_payload(&set(&[attribute(&[1], &wide)])).unwrap();
        assert_eq!(receipt.app_item_id, None);
        assert_eq!(receipt.unknown_attributes.get(&1), Some(&vec![wide]));
    }

    #[test]
    fn an_in_app_purchase_that_does_not_parse_is_kept_raw_under_17() {
        let broken = set(&[der(tag::SEQUENCE, &int(&[7]))]);
        let receipt = parse_receipt_payload(&set(&[attribute(&[17], &broken)])).unwrap();
        assert!(receipt.in_app.is_empty());
        assert_eq!(receipt.unknown_attributes.get(&17), Some(&vec![broken]));
    }

    #[test]
    fn the_bundle_id_octets_are_kept_even_when_the_string_does_not_decode() {
        let octets = der(tag::INTEGER, &[1]);
        let receipt = parse_receipt_payload(&set(&[attribute(&[2], &octets)])).unwrap();
        assert_eq!(receipt.bundle_id, None);
        assert_eq!(receipt.bundle_id_bytes, Some(octets));
        assert!(receipt.unknown_attributes.is_empty());
    }

    #[test]
    fn the_first_creation_date_is_the_chain_instant() {
        let good = date("2024-08-06T12:00:00Z");
        assert_eq!(
            read_creation_date(&set(&[good.clone(), date("2030-01-01T00:00:00Z")])),
            Some(1_722_945_600_000)
        );
        for (what, payload) in [
            ("missing", set(&[attribute(&[2], &[])])),
            ("empty", set(&[date("")])),
            ("unreadable first", set(&[date("not-a-date"), good.clone()])),
            (
                "an entry the walk cannot read",
                set(&[good.clone(), der(tag::SEQUENCE, &int(&[7]))]),
            ),
            ("no attribute SET at all", Vec::new()),
            ("not a SET", der(tag::SEQUENCE, &good)),
        ] {
            assert_eq!(read_creation_date(&payload), None, "{what}");
        }
    }

    #[test]
    fn an_empty_purchase_writes_every_key_as_null() {
        // A missing field is null, never omitted.
        let json = InAppPurchase::default().json_value();
        assert_eq!(
            json,
            serde_json::json!({
                "quantity": null, "product_id": null, "transaction_id": null,
                "purchase_date_ms": null, "original_transaction_id": null,
                "original_purchase_date_ms": null, "expires_date_ms": null,
                "web_order_line_item_id": null, "cancellation_date_ms": null,
                "is_trial_period": null, "is_in_intro_offer_period": null,
                "unknown_attributes": {}
            })
        );
    }
}
