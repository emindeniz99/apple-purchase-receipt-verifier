//! Spike only (round 4). Copied into BOTH scratch trees (the round-3 CMS
//! baseline, whose payload reader is `asn1.rs`, and the no-asn1 tree, whose
//! reader is OpenSSL) so the two readers can be compared on the same bytes:
//! `examples/spike_payload.rs` prints these strings for every genuine and
//! generated receipt, and `fuzz/payload-diff.rs` compares them per input.
//! Not part of any proposed API.

use crate::receipt_payload::{parse_receipt_payload, read_creation_date};

/// Everything the payload reader returns for `content`, as one string:
/// `OK <AppReceipt Debug>` or `ERR <Reason>` (the detail text is not
/// compared: it names the reader).
#[must_use]
pub fn payload(content: &[u8]) -> String {
    match parse_receipt_payload(content) {
        Ok(receipt) => format!("OK {receipt:?}"),
        Err(err) => format!("ERR {:?}", err.reason()),
    }
}

/// What the pre-trust creation-date read returns for `content`.
#[must_use]
pub fn creation_date(content: &[u8]) -> String {
    format!("{:?}", read_creation_date(content))
}

/// The failure detail of the payload reader, or `OK` (fuzz/payload-diff.rs
/// files differences under it).
#[must_use]
pub fn payload_detail(content: &[u8]) -> String {
    match parse_receipt_payload(content) {
        Ok(_) => "OK".to_owned(),
        Err(err) => err.detail().to_owned(),
    }
}
