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
//! Decode rules: a missing attribute is `None`; the first copy of a known attribute fills its
//! field; every attribute that does not end up in a field (an unmodelled
//! type, a later copy, a value that does not parse) is kept raw in
//! `unknown_attributes`, except an empty date string, which means "not set".
//! Only an attribute SET, or an attribute, that does not parse makes the
//! whole payload unreadable.

use crate::asn1::{parse_exact, tag, Asn1Error, Tlv};
use crate::datetime::parse_receipt_date;
use crate::json_writer::Object;
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

struct Attribute {
    attribute_type: u32,
    value: Vec<u8>,
}

/// Decodes a receipt payload that a trusted signer has signed.
///
/// # Errors
/// [`PayloadError`] when the attribute SET, or one of its attributes, does
/// not parse. A value that does not decode is not an error: it is kept raw.
pub(crate) fn parse_receipt_payload(content: &[u8]) -> Result<ReceiptPayload, PayloadError> {
    let attributes = parse_attribute_set(content, "receipt payload")?;
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
            _ => Err(Undecodable),
        };
        if decoded.is_err() {
            keep_raw(&mut receipt.unknown_attributes, attribute);
        }
    }
    Ok(receipt)
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

/// The receipt creation date (attribute 12), read the only way anything in
/// a payload is read before its signer is trusted: the top-level attribute
/// SET is walked shallowly, each entry's type is read, and only the value of
/// the first type 12 is decoded.
///
/// `None` means "judge the chain at the clock": no attribute 12, a first one
/// that is empty or does not decode, or a walk that fails anywhere. An entry
/// the walk cannot read fails it as a whole rather than being skipped, since
/// that entry might have been the first attribute 12. Never an error:
/// nothing is trusted yet, so nothing here can blame anyone.
pub(crate) fn read_creation_date(content: &[u8]) -> Option<i64> {
    let attributes = parse_attribute_set(content, "receipt payload").ok()?;
    let first = attributes
        .iter()
        .find(|attribute| attribute.attribute_type == ATTR_CREATION_DATE)?;
    date(&first.value).ok().flatten()
}

fn parse_attribute_set(der: &[u8], what: &str) -> Result<Vec<Attribute>, PayloadError> {
    let outer = parse_exact(der).map_err(|err| unreadable(what, err))?;
    // Xcode receipts double-wrap the payload in an extra OCTET STRING.
    let unwrapped;
    let node = if outer.is_octet_string() {
        unwrapped = outer
            .octet_string_value()
            .ok_or_else(|| unreadable(what, "double-wrap is not an OCTET STRING"))?
            .into_owned();
        parse_exact(&unwrapped).map_err(|err| unreadable(what, err))?
    } else {
        outer
    };
    if node.tag != tag::SET {
        return Err(unreadable(what, "not an ASN.1 SET"));
    }
    let mut attributes = Vec::with_capacity(node.children().len());
    for child in node.children() {
        attributes.push(attribute(child).map_err(|err| unreadable(what, err))?);
    }
    Ok(attributes)
}

/// One attribute. Fields after the third are tolerated, so a field Apple
/// appends later does not break parsing; the version is not read.
fn attribute(node: &Tlv<'_>) -> Result<Attribute, &'static str> {
    let fields = node.children();
    let (Some(type_node), Some(version_node), Some(value_node)) =
        (fields.first(), fields.get(1), fields.get(2))
    else {
        return Err("malformed receipt attribute");
    };
    if node.tag != tag::SEQUENCE || type_node.tag != tag::INTEGER || !value_node.is_octet_string() {
        return Err("malformed receipt attribute");
    }
    // The version is not read, but an INTEGER there must still be one.
    if version_node.tag == tag::INTEGER && integer_value(version_node).is_none() {
        return Err("malformed receipt attribute");
    }
    // Refused rather than narrowed: narrowing would invent an attribute the
    // receipt never carried.
    let attribute_type = integer_value(type_node)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| i32::try_from(*value).is_ok())
        .ok_or("receipt attribute type out of range")?;
    let value = value_node
        .octet_string_value()
        .ok_or("malformed receipt attribute")?
        .into_owned();
    Ok(Attribute {
        attribute_type,
        value,
    })
}

/// A DER INTEGER's value, or `None` for one that is empty, not minimally
/// encoded, or wider than 64 bits.
fn integer_value(node: &Tlv<'_>) -> Option<i64> {
    let contents = node.contents;
    let first = *contents.first()?;
    if node.constructed || contents.len() > 8 {
        return None;
    }
    if let Some(second) = contents.get(1) {
        // X.690 8.3.2: the first nine bits are never all zero or all one.
        if (first == 0x00 && second & 0x80 == 0) || (first == 0xff && second & 0x80 != 0) {
            return None;
        }
    }
    let mut value: i64 = if first & 0x80 == 0 { 0 } else { -1 };
    for byte in contents {
        value = (value << 8) | i64::from(*byte);
    }
    Some(value)
}

fn decode_nested(der: &[u8]) -> Result<Tlv<'_>, Undecodable> {
    parse_exact(der).map_err(|_: Asn1Error| Undecodable)
}

/// A `UTF8String` or an `IA5String`, the two string types Apple's receipts
/// use. A `UTF8String` must be valid UTF-8; an `IA5String` must be ASCII,
/// as IA5 is: a byte from 0x80 up does not decode, rather than being read as
/// Latin-1.
fn decode_string(der: &[u8]) -> Result<String, Undecodable> {
    let node = decode_nested(der)?;
    match node.tag {
        tag::UTF8_STRING => String::from_utf8(node.contents.to_vec()).map_err(|_| Undecodable),
        tag::IA5_STRING if node.contents.is_ascii() => {
            Ok(node.contents.iter().map(|byte| char::from(*byte)).collect())
        }
        _ => Err(Undecodable),
    }
}

/// An INTEGER that fits a signed 64-bit value, negative ones included.
fn decode_integer(der: &[u8]) -> Result<i64, Undecodable> {
    let node = decode_nested(der)?;
    if node.tag != tag::INTEGER {
        return Err(Undecodable);
    }
    integer_value(&node).ok_or(Undecodable)
}

/// A date in an `IA5String` or `UTF8String`, as epoch milliseconds. An
/// empty string is `Ok(None)`: Apple writes an unset date that way, so it is
/// not kept raw. Anything else must be exactly `YYYY-MM-DDTHH:MM:SSZ`; see
/// [`parse_receipt_date`].
fn date(der: &[u8]) -> Result<Option<i64>, Undecodable> {
    let text = decode_string(der)?;
    if text.is_empty() {
        return Ok(None);
    }
    parse_receipt_date(&text).map(Some).ok_or(Undecodable)
}

// ------------------------------------------------------------------ JSON

impl ReceiptPayload {
    /// The canonical JSON, fixed byte for byte: the keys below
    /// in this order, no whitespace, `null` for a missing field, 64-bit ids
    /// as strings, bytes as padded standard base64, `unknown_attributes`
    /// keys in ascending numeric order, and strings escaped exactly as
    /// ECMAScript `JSON.stringify` escapes them.
    ///
    /// `receipt_type`, `app_item_id`, `bundle_id`, `bundle_id_bytes`,
    /// `application_version`, `opaque_value`, `sha1_hash`,
    /// `receipt_creation_date_ms`, `download_id`,
    /// `version_external_identifier`, `in_app`, `original_purchase_date_ms`,
    /// `original_application_version`, `expiration_date_ms`,
    /// `unknown_attributes`.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(512 + 512 * self.in_app.len());
        let mut json = Object::open(&mut out);
        json.string("receipt_type", self.receipt_type.as_deref());
        json.id("app_item_id", self.app_item_id);
        json.string("bundle_id", self.bundle_id.as_deref());
        json.bytes("bundle_id_bytes", self.bundle_id_bytes.as_deref());
        json.string("application_version", self.application_version.as_deref());
        json.bytes("opaque_value", self.opaque_value.as_deref());
        json.bytes("sha1_hash", self.sha1_hash.as_deref());
        json.number("receipt_creation_date_ms", self.receipt_creation_date_ms);
        json.id("download_id", self.download_id);
        json.id(
            "version_external_identifier",
            self.version_external_identifier,
        );
        json.key("in_app");
        json.out().push('[');
        for (index, purchase) in self.in_app.iter().enumerate() {
            if index > 0 {
                json.out().push(',');
            }
            purchase.write_json(json.out());
        }
        json.out().push(']');
        json.number("original_purchase_date_ms", self.original_purchase_date_ms);
        json.string(
            "original_application_version",
            self.original_application_version.as_deref(),
        );
        json.number("expiration_date_ms", self.expiration_date_ms);
        json.attributes("unknown_attributes", &self.unknown_attributes);
        json.close();
        out
    }
}

impl InAppPurchase {
    fn write_json(&self, out: &mut String) {
        let mut json = Object::open(out);
        json.number("quantity", self.quantity);
        json.string("product_id", self.product_id.as_deref());
        json.string("transaction_id", self.transaction_id.as_deref());
        json.number("purchase_date_ms", self.purchase_date_ms);
        json.string(
            "original_transaction_id",
            self.original_transaction_id.as_deref(),
        );
        json.number("original_purchase_date_ms", self.original_purchase_date_ms);
        json.number("expires_date_ms", self.expires_date_ms);
        json.id("web_order_line_item_id", self.web_order_line_item_id);
        json.number("cancellation_date_ms", self.cancellation_date_ms);
        json.boolean("is_trial_period", self.is_trial_period);
        json.boolean("is_in_intro_offer_period", self.is_in_intro_offer_period);
        json.attributes("unknown_attributes", &self.unknown_attributes);
        json.close();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    //! The payload grammar, tested against the decoder itself. Through the
    //! verifier these payloads would need a trusted signer, because the full
    //! parse runs only after the chain and the signature have passed.

    use super::{parse_receipt_payload, read_creation_date, InAppPurchase};
    use crate::asn1::tag;
    use crate::json_writer::quote;

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
        // Exactly YYYY-MM-DDTHH:MM:SSZ.
        let exact = parse_receipt_payload(&set(&[date("2024-08-06T12:00:00Z")])).unwrap();
        assert_eq!(exact.receipt_creation_date_ms, Some(1_722_945_600_000));
        for text in [
            "2024-08-06T12:00:00.000Z",
            "2024-08-06T12:00:00+00:00",
            "2024-08-06t12:00:00Z",
        ] {
            let receipt = parse_receipt_payload(&set(&[date(text)])).unwrap();
            assert_eq!(receipt.receipt_creation_date_ms, None, "{text}");
            assert_eq!(receipt.unknown_attributes.get(&12), Some(&vec![ia5(text)]));
            assert_eq!(read_creation_date(&set(&[date(text)])), None, "{text}");
        }
    }

    #[test]
    fn signed_content_nested_past_the_asn1_bound_is_unreadable() {
        // The bound is the reader's (64 constructed values); signed content
        // that exceeds it cannot be read, which the verifier reports as
        // UNREADABLE_PAYLOAD, never MALFORMED.
        let mut nested: Vec<u8> = Vec::new();
        for _ in 0..=crate::asn1::MAX_DEPTH {
            let length = u8::try_from(nested.len()).unwrap();
            nested = if length < 0x80 {
                [&[tag::SET, length][..], &nested].concat()
            } else {
                [&[tag::SET, 0x81, length][..], &nested].concat()
            };
        }
        assert!(parse_receipt_payload(&nested).is_err());
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
    fn strings_escape_as_json_stringify_does() {
        let mut out = String::new();
        quote(
            &mut out,
            "\"\\/\u{8}\u{c}\n\r\t\u{0}\u{1f}\u{7f}\u{e9}\u{2028}\u{2029}",
        );
        assert_eq!(
            out,
            "\"\\\"\\\\/\\b\\f\\n\\r\\t\\u0000\\u001f\u{7f}\u{e9}\u{2028}\u{2029}\""
        );
    }

    #[test]
    fn an_empty_purchase_writes_every_key_as_null() {
        let mut out = String::new();
        InAppPurchase::default().write_json(&mut out);
        assert_eq!(
            out,
            "{\"quantity\":null,\"product_id\":null,\"transaction_id\":null,\
             \"purchase_date_ms\":null,\"original_transaction_id\":null,\
             \"original_purchase_date_ms\":null,\"expires_date_ms\":null,\
             \"web_order_line_item_id\":null,\"cancellation_date_ms\":null,\
             \"is_trial_period\":null,\"is_in_intro_offer_period\":null,\
             \"unknown_attributes\":{}}"
        );
    }
}
