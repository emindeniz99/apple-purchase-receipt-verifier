//! The decoder behind a valid signature, driven with seeded random
//! payloads.
//!
//! The payload decoder (`receipt_payload.rs`: the attribute SET, each
//! in-app purchase, the strings, integers and dates) runs only once a
//! trusted signer has signed the content. Mutating a signed receipt breaks
//! its signature, so the mutation loops in `hostile.rs` and the fuzz
//! targets stop before it. Here every mutated payload is signed afresh by
//! a test PKI the verifier pins, so each one reaches the decoder through
//! the public API, as a payload Apple signed would.
//!
//! What must hold for every payload: nothing panics (the library would
//! contain a panic here and answer `UNREADABLE_PAYLOAD`, so the count is
//! what catches it); a payload either decodes to JSON that parses or is
//! refused as `UNREADABLE_PAYLOAD`, never blamed on the client
//! (`MALFORMED`), the signature or the library (`INTERNAL_ERROR`), the
//! one exception being a creation date that moves the chain instant out
//! of the chain's validity (`INVALID_CERTIFICATE`); and the same bytes
//! give the same answer twice.
//! The keys are fresh each run, but the payloads come from a fixed seed
//! and the clock is pinned, so a failure names a payload that reproduces.

mod common;

use apple_purchase_receipt_verifier::{Reason, Verifier};
use common::pki::{ia5, integer, parse_rfc3339, receipt_attribute, utf8, Pki, DAY_MS};
use common::{der, der_set, tag, Rng};

const SEED: u64 = 0x0DEC_0DE5_16AE_D000;
const PAYLOADS: usize = 2000;

/// The chain is valid for this year; the payload is created, and the
/// clock reads, in the middle of it.
const NOT_BEFORE: &str = "2025-01-01T00:00:00Z";
const CREATED: &str = "2025-06-01T12:00:00Z";

/// One in-app purchase carrying every attribute the decoder reads.
fn in_app(product: &str, transaction: u64) -> Vec<u8> {
    der_set(&[
        receipt_attribute(1701, &integer(1)),
        receipt_attribute(1702, &utf8(product)),
        receipt_attribute(1703, &utf8(&transaction.to_string())),
        receipt_attribute(1704, &ia5(CREATED)),
        receipt_attribute(1705, &utf8(&transaction.to_string())),
        receipt_attribute(1706, &ia5(CREATED)),
        receipt_attribute(1708, &ia5("2025-07-01T12:00:00Z")),
        receipt_attribute(1711, &integer(transaction + 1)),
        receipt_attribute(1712, &ia5("")),
        receipt_attribute(1713, &integer(0)),
        receipt_attribute(1719, &integer(1)),
        receipt_attribute(1720, &integer(0)),
        receipt_attribute(1799, &[0x05, 0x00]),
    ])
}

/// The attributes of a payload carrying every top-level attribute the
/// decoder reads, an unknown one, and two in-app purchases.
fn attributes() -> Vec<Vec<u8>> {
    vec![
        receipt_attribute(0, &utf8("ProductionSandbox")),
        receipt_attribute(1, &integer(1_234_567)),
        receipt_attribute(2, &utf8("com.example.app")),
        receipt_attribute(3, &utf8("1.0")),
        receipt_attribute(4, &[1, 2, 3, 4]),
        receipt_attribute(5, &[5, 6, 7, 8]),
        receipt_attribute(12, &ia5(CREATED)),
        receipt_attribute(15, &integer(99)),
        receipt_attribute(16, &integer(0)),
        receipt_attribute(17, &in_app("gems.small", 2001)),
        receipt_attribute(17, &in_app("gems.large", 2002)),
        receipt_attribute(18, &ia5(CREATED)),
        receipt_attribute(19, &utf8("1.0")),
        receipt_attribute(21, &ia5("")),
        receipt_attribute(32, &ia5("")),
        receipt_attribute(9999, &[1, 2, 3]),
    ]
}

/// A value of a random shape: the string, integer and date encodings the
/// decoder reads, their near misses, nested attribute SETs and junk.
fn random_value(rng: &mut Rng, depth: usize) -> Vec<u8> {
    let text = |rng: &mut Rng| -> Vec<u8> {
        let pool: &[&[u8]] = &[
            b"",
            b"1.0",
            CREATED.as_bytes(),
            b"2025-06-01T12:00:00.123Z",
            b"2025-06-01T12:00:00+09:00",
            b"2025-06-01 12:00:00 Etc/GMT",
            b"2025-02-30T12:00:00Z",
            b"9999-12-31T23:59:59Z",
            b"0000-01-01T00:00:00Z",
            b"\xc3\x28",
            b"\x80\xff",
            b"\x00",
        ];
        pool[rng.below(pool.len())].to_vec()
    };
    match rng.below(10) {
        0 => der(tag::UTF8_STRING, &text(rng)),
        1 => der(tag::IA5_STRING, &text(rng)),
        2 => integer(rng.next_u64() >> rng.below(64)),
        // An INTEGER whose content is random: negative, empty, padded or
        // past 64 bits.
        3 => {
            let length = rng.below(11);
            let bytes: Vec<u8> = (0..length).map(|_| rng.next_u64() as u8).collect();
            der(tag::INTEGER, &bytes)
        }
        4 => der(tag::OCTET_STRING, &text(rng)),
        5 if depth < 3 => {
            let count = rng.below(4);
            let members: Vec<Vec<u8>> = (0..count)
                .map(|_| {
                    let attribute_type = random_type(rng);
                    receipt_attribute(attribute_type, &random_value(rng, depth + 1))
                })
                .collect();
            der_set(&members)
        }
        6 => vec![],
        7 => vec![0x05, 0x00],
        _ => {
            let length = rng.below(24);
            (0..length).map(|_| rng.next_u64() as u8).collect()
        }
    }
}

/// An attribute type the decoder reads, or one it does not.
fn random_type(rng: &mut Rng) -> u64 {
    const KNOWN: &[u64] = &[
        0, 1, 2, 3, 4, 5, 12, 15, 16, 17, 18, 19, 21, 32, 1701, 1702, 1703, 1704, 1705, 1706, 1708,
        1711, 1712, 1713, 1719, 1720,
    ];
    match rng.below(4) {
        0 => rng.next_u64() >> rng.below(64),
        _ => KNOWN[rng.below(KNOWN.len())],
    }
}

/// One payload: the full one, reshaped one of four ways.
fn random_payload(rng: &mut Rng) -> Vec<u8> {
    let mut attributes = attributes();
    match rng.below(4) {
        // Bit flips anywhere in the encoded payload.
        0 => {
            let mut payload = der_set(&attributes);
            for _ in 0..=rng.below(4) {
                let index = rng.below(payload.len());
                payload[index] ^= 1 << rng.below(8);
            }
            payload
        }
        // Values of the wrong shape under known and unknown types.
        1 => {
            for _ in 0..=rng.below(3) {
                let index = rng.below(attributes.len());
                let attribute_type = random_type(rng);
                attributes[index] = receipt_attribute(attribute_type, &random_value(rng, 0));
            }
            der_set(&attributes)
        }
        // Repeated, dropped and added attributes.
        2 => {
            for _ in 0..=rng.below(4) {
                match rng.below(3) {
                    0 => {
                        let copy = attributes[rng.below(attributes.len())].clone();
                        attributes.push(copy);
                    }
                    1 if attributes.len() > 1 => {
                        attributes.remove(rng.below(attributes.len()));
                    }
                    _ => {
                        let attribute_type = random_type(rng);
                        attributes.push(receipt_attribute(attribute_type, &random_value(rng, 0)));
                    }
                }
            }
            der_set(&attributes)
        }
        // Cut short.
        _ => {
            let payload = der_set(&attributes);
            payload[..rng.below(payload.len())].to_vec()
        }
    }
}

/// The verdict a test can compare: the payload's JSON, or the reason and
/// message.
fn verdict(verifier: &Verifier, receipt: &str) -> Result<String, (Reason, String)> {
    verifier
        .verify_receipt(receipt)
        .map(|payload| payload.to_json())
        .map_err(|failure| (failure.reason(), failure.message().to_owned()))
}

#[test]
fn seeded_random_payloads_under_a_valid_signature_decode_or_refuse_cleanly() {
    let not_before = parse_rfc3339(NOT_BEFORE);
    let pki = Pki::receipt_with(not_before, not_before + 365 * DAY_MS, true, true);
    let created = parse_rfc3339(CREATED);
    let verifier = common::verifier_at([pki.anchor()], created);
    let encode = apple_purchase_receipt_verifier::__internal::base64_encode;

    // The unmutated payload must verify, or every refusal below would be
    // about something other than the decoder.
    let control = encode(&pki.sign_receipt_at(&der_set(&attributes()), created));
    assert!(verdict(&verifier, &control).is_ok(), "the control payload");

    let mut rng = Rng::new(SEED);
    let (mut decoded, mut unreadable, mut other) = (0usize, 0usize, 0usize);
    for index in 0..PAYLOADS {
        let payload = random_payload(&mut rng);
        let receipt = encode(&pki.sign_receipt_at(&payload, created));
        let ((first, second), panics) = common::panics::panics_during(|| {
            (verdict(&verifier, &receipt), verdict(&verifier, &receipt))
        });
        let at = format!(
            "payload {index} (seed {SEED:#x}): {}",
            hex::encode(&payload)
        );
        assert_eq!(panics, 0, "{at} panicked");
        assert_eq!(first, second, "{at} answered differently twice");
        match first {
            Ok(json) => {
                serde_json::from_str::<serde_json::Value>(&json).unwrap_or_else(|err| {
                    panic!("{at} decoded to JSON that does not parse: {err}")
                });
                decoded += 1;
            }
            Err((Reason::UnreadablePayload, _)) => unreadable += 1,
            // A creation date moved outside the chain's validity judges
            // the chain at that date, which is the chain's verdict, not
            // the decoder's.
            Err((Reason::InvalidCertificate, _)) => other += 1,
            Err((reason, message)) => panic!("{at} was refused as {reason}: {message}"),
        }
    }
    eprintln!(
        "{PAYLOADS} signed payloads: {decoded} decoded, {unreadable} unreadable, {other} \
         refused on the chain"
    );
    // Both outcomes of the decoder must be well represented, or the loop
    // has stopped reaching it.
    assert!(decoded > PAYLOADS / 5, "only {decoded} payloads decoded");
    assert!(
        unreadable > PAYLOADS / 10,
        "only {unreadable} payloads were unreadable"
    );
}
