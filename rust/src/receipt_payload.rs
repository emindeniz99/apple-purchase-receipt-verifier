//! The legacy receipt payload attribute grammar.
//!
//! ```text
//! SET OF ReceiptAttribute
//! ReceiptAttribute ::= SEQUENCE { type INTEGER, version INTEGER, value OCTET STRING }
//! ```
//!
//! Apple, "Validating receipts on the device", plus two community-
//! established attribute types (0 receipt type, 18 original purchase date)
//! that the `verifyReceipt` response compatibility needs.

use crate::asn1::{parse_exact, tag, Tlv};
use crate::datetime::{parse_rfc3339, system_time_from_millis};
use crate::error::{Reason, Result, VerificationError};
use std::collections::BTreeMap;
use std::time::SystemTime;

// App-level attribute types.
const ATTR_RECEIPT_TYPE: u32 = 0;
const ATTR_BUNDLE_ID: u32 = 2;
const ATTR_APP_VERSION: u32 = 3;
const ATTR_OPAQUE_VALUE: u32 = 4;
const ATTR_SHA1_HASH: u32 = 5;
const ATTR_CREATION_DATE: u32 = 12;
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
const IAP_IS_IN_INTRO_OFFER_PERIOD: u32 = 1719;

/// Attribute *types* live in a 32-bit signed space.
///
/// Every type Apple has ever issued is a small number, and a value above
/// `2^31 − 1` cannot be represented by ports whose attribute-type field is
/// an `int`. Mapping such a type onto a sentinel and filing it under
/// `unknownAttributes` would let two ports disagree about what the same
/// receipt says, so an unrepresentable type is a malformed receipt in every
/// port — fail closed, never rename or clamp.
const MAX_ATTRIBUTE_TYPE: i64 = 2_147_483_647;

/// Attribute *values* keep the wider range: `web_order_line_item_id` is
/// genuinely a 7-byte integer. The ceiling is the one every port shares.
const MAX_ATTRIBUTE_VALUE: i64 = 9_007_199_254_740_991;

/// One in-app purchase from a legacy app receipt (attribute 17).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct InAppPurchase {
    /// Raw values of attribute types this library does not model, keyed by
    /// type — forward compatibility for fields Apple may add
    /// (`PLAN.md` D10). Values are verified but undecoded.
    pub unknown_attributes: BTreeMap<u32, Vec<Vec<u8>>>,
    /// 1701
    pub quantity: Option<i64>,
    /// 1702
    pub product_id: Option<String>,
    /// 1703
    pub transaction_id: Option<String>,
    /// 1705
    pub original_transaction_id: Option<String>,
    /// 1704
    pub purchase_date: Option<SystemTime>,
    /// 1706
    pub original_purchase_date: Option<SystemTime>,
    /// 1708
    pub expires_date: Option<SystemTime>,
    /// 1712
    pub cancellation_date: Option<SystemTime>,
    /// 1711
    pub web_order_line_item_id: Option<i64>,
    /// 1719
    pub is_in_intro_offer_period: Option<i64>,
}

/// A verified legacy app receipt.
///
/// Only a value returned by [`ReceiptVerifier`](crate::ReceiptVerifier) or
/// [`verify_receipt_core`](crate::verify_receipt_core) should be trusted:
/// nothing partial is ever returned, so every byte here came from a receipt
/// whose chain and signature passed.
///
/// Dates here are [`SystemTime`], the language's own instant type — unlike
/// the JWS payloads, whose date claims stay epoch-millisecond integers
/// because that is how Apple ships them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct AppReceipt {
    /// Raw values of unmodelled attribute types, keyed by type
    /// (`PLAN.md` D10).
    pub unknown_attributes: BTreeMap<u32, Vec<Vec<u8>>>,
    /// Attribute 0, e.g. `Production` / `ProductionSandbox` (undocumented).
    pub receipt_type: Option<String>,
    /// Attribute 2.
    pub bundle_id: Option<String>,
    /// The raw DER of attribute 2 — the input to the device-hash check.
    pub bundle_id_bytes: Option<Vec<u8>>,
    /// Attribute 3.
    pub app_version: Option<String>,
    /// Attribute 4.
    pub opaque_value: Option<Vec<u8>>,
    /// Attribute 5.
    pub sha1_hash: Option<Vec<u8>>,
    /// Attribute 12.
    pub creation_date: Option<SystemTime>,
    /// Attribute 18 (undocumented; community-established).
    pub original_purchase_date: Option<SystemTime>,
    /// Attribute 19.
    pub original_app_version: Option<String>,
    /// Attribute 21.
    pub expiration_date: Option<SystemTime>,
    /// Attribute 17, repeated.
    pub in_app_purchases: Vec<InAppPurchase>,
}

fn malformed(detail: impl Into<String>) -> VerificationError {
    VerificationError::new(Reason::InvalidReceiptFormat, detail)
}

struct Attribute {
    attribute_type: u32,
    value: Vec<u8>,
}

/// Decodes a receipt payload.
///
/// # Errors
/// [`Reason::InvalidReceiptFormat`] for any shape this grammar cannot
/// represent.
pub fn parse_receipt_payload(content: &[u8]) -> Result<AppReceipt> {
    let attributes = parse_attribute_set(content, "receipt payload")?;
    let mut receipt = AppReceipt::default();
    for attribute in attributes {
        let value = attribute.value.as_slice();
        match attribute.attribute_type {
            ATTR_RECEIPT_TYPE => receipt.receipt_type = Some(decode_string(value)?),
            ATTR_BUNDLE_ID => {
                receipt.bundle_id = Some(decode_string(value)?);
                receipt.bundle_id_bytes = Some(value.to_vec());
            }
            ATTR_APP_VERSION => receipt.app_version = Some(decode_string(value)?),
            ATTR_OPAQUE_VALUE => receipt.opaque_value = Some(value.to_vec()),
            ATTR_SHA1_HASH => receipt.sha1_hash = Some(value.to_vec()),
            ATTR_CREATION_DATE => receipt.creation_date = decode_date(value)?,
            ATTR_IN_APP => receipt.in_app_purchases.push(parse_in_app(value)?),
            ATTR_ORIGINAL_PURCHASE_DATE => receipt.original_purchase_date = decode_date(value)?,
            ATTR_ORIGINAL_APP_VERSION => {
                receipt.original_app_version = Some(decode_string(value)?);
            }
            ATTR_EXPIRATION_DATE => receipt.expiration_date = decode_date(value)?,
            other => record_unknown(&mut receipt.unknown_attributes, other, value),
        }
    }
    Ok(receipt)
}

fn parse_in_app(value: &[u8]) -> Result<InAppPurchase> {
    let attributes = parse_attribute_set(value, "in-app purchase attribute")?;
    let mut purchase = InAppPurchase::default();
    for attribute in attributes {
        let value = attribute.value.as_slice();
        match attribute.attribute_type {
            IAP_QUANTITY => purchase.quantity = Some(decode_integer(value)?),
            IAP_PRODUCT_ID => purchase.product_id = Some(decode_string(value)?),
            IAP_TRANSACTION_ID => purchase.transaction_id = Some(decode_string(value)?),
            IAP_PURCHASE_DATE => purchase.purchase_date = decode_date(value)?,
            IAP_ORIGINAL_TRANSACTION_ID => {
                purchase.original_transaction_id = Some(decode_string(value)?);
            }
            IAP_ORIGINAL_PURCHASE_DATE => purchase.original_purchase_date = decode_date(value)?,
            IAP_EXPIRES_DATE => purchase.expires_date = decode_date(value)?,
            IAP_WEB_ORDER_LINE_ITEM_ID => {
                purchase.web_order_line_item_id = Some(decode_integer(value)?);
            }
            IAP_CANCELLATION_DATE => purchase.cancellation_date = decode_date(value)?,
            IAP_IS_IN_INTRO_OFFER_PERIOD => {
                purchase.is_in_intro_offer_period = Some(decode_integer(value)?);
            }
            other => record_unknown(&mut purchase.unknown_attributes, other, value),
        }
    }
    Ok(purchase)
}

fn record_unknown(unknown: &mut BTreeMap<u32, Vec<Vec<u8>>>, attribute_type: u32, value: &[u8]) {
    unknown
        .entry(attribute_type)
        .or_default()
        .push(value.to_vec());
}

fn parse_attribute_set(der: &[u8], what: &str) -> Result<Vec<Attribute>> {
    let outer =
        parse_exact(der).map_err(|err| malformed(format!("{what} is not valid ASN.1: {err}")))?;
    // Xcode receipts double-wrap the payload in an extra OCTET STRING.
    let unwrapped;
    let node = if outer.is_octet_string() {
        unwrapped = outer
            .octet_string_value()
            .ok_or_else(|| malformed(format!("{what} double-wrap is not an OCTET STRING")))?
            .into_owned();
        parse_exact(&unwrapped)
            .map_err(|err| malformed(format!("{what} double-wrap is not valid ASN.1: {err}")))?
    } else {
        outer
    };
    if node.tag != tag::SET {
        return Err(malformed(format!("{what} is not an ASN.1 SET")));
    }
    let mut attributes = Vec::with_capacity(node.children().len());
    for child in node.children() {
        let fields = child.children();
        let (Some(type_node), Some(value_node)) = (fields.first(), fields.get(2)) else {
            return Err(malformed("malformed receipt attribute"));
        };
        if child.tag != tag::SEQUENCE
            || fields.len() < 3
            || type_node.tag != tag::INTEGER
            || !value_node.is_octet_string()
        {
            return Err(malformed("malformed receipt attribute"));
        }
        attributes.push(Attribute {
            attribute_type: attribute_type(type_node)?,
            value: value_node
                .octet_string_value()
                .ok_or_else(|| malformed("malformed receipt attribute"))?
                .into_owned(),
        });
    }
    Ok(attributes)
}

fn attribute_type(node: &Tlv<'_>) -> Result<u32> {
    let value = integer_value(node)?;
    if value > MAX_ATTRIBUTE_TYPE {
        return Err(malformed(
            "receipt attribute type exceeds the 32-bit signed range",
        ));
    }
    u32::try_from(value).map_err(|_| malformed("receipt attribute type out of range"))
}

fn integer_value(node: &Tlv<'_>) -> Result<i64> {
    // 8-byte cap: real receipts carry 7-byte integers
    // (web_order_line_item_id).
    if node.contents.len() > 8 {
        return Err(malformed("attribute integer out of range"));
    }
    // Negative attribute types and values never occur in receipts.
    if node.contents.first().is_some_and(|byte| *byte >= 0x80) {
        return Err(malformed("negative receipt integer"));
    }
    let mut value: i128 = 0;
    for byte in node.contents {
        value = value * 256 + i128::from(*byte);
    }
    if value > i128::from(MAX_ATTRIBUTE_VALUE) {
        return Err(malformed(
            "receipt integer exceeds the shared safe-integer range",
        ));
    }
    i64::try_from(value).map_err(|_| malformed("receipt integer out of range"))
}

fn decode_nested(der: &[u8]) -> Result<Tlv<'_>> {
    parse_exact(der).map_err(|err| malformed(format!("attribute value is not valid ASN.1: {err}")))
}

fn decode_string(der: &[u8]) -> Result<String> {
    let node = decode_nested(der)?;
    if node.tag != tag::UTF8_STRING && node.tag != tag::IA5_STRING {
        return Err(malformed("attribute value is not an ASN.1 string"));
    }
    Ok(String::from_utf8_lossy(node.contents).into_owned())
}

fn decode_integer(der: &[u8]) -> Result<i64> {
    let node = decode_nested(der)?;
    if node.tag != tag::INTEGER {
        return Err(malformed("attribute value is not an ASN.1 integer"));
    }
    integer_value(&node)
}

/// An RFC 3339 date in an `IA5String`; an empty string means absent, which
/// real receipts do use.
///
/// The timezone designator is mandatory — see
/// [`parse_rfc3339`](crate::datetime::parse_rfc3339) for why that is a
/// security property and not pedantry.
fn decode_date(der: &[u8]) -> Result<Option<SystemTime>> {
    let text = decode_string(der)?;
    if text.is_empty() {
        return Ok(None);
    }
    match parse_rfc3339(&text) {
        Some(millis) => Ok(Some(system_time_from_millis(millis))),
        None => Err(malformed("unparseable receipt date")),
    }
}
