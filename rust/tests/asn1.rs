//! The BER/DER reader, on its own.
//!
//! This is the first thing any attacker-supplied byte meets, so its bounds
//! are tested directly rather than only through a verifier.

use apple_purchase_receipt_verifier::asn1::{
    decode_oid, encode_oid, parse_exact, tag, MAX_DEPTH, MAX_NODES,
};

#[test]
fn a_definite_length_value_exposes_its_exact_tlv() {
    let input = [0x04u8, 0x03, 0x01, 0x02, 0x03];
    let node = parse_exact(&input).unwrap();
    assert_eq!(node.tag, tag::OCTET_STRING);
    assert!(!node.constructed);
    assert_eq!(node.full, &input[..]);
    assert_eq!(node.contents, &[0x01, 0x02, 0x03]);
    assert!(node.children.is_none());
}

#[test]
fn a_constructed_value_exposes_its_children() {
    // SEQUENCE { INTEGER 1, OCTET STRING "ab" }
    let input = [0x30u8, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, b'a', b'b'];
    let node = parse_exact(&input).unwrap();
    assert_eq!(node.children().len(), 2);
    assert_eq!(node.child(0).unwrap().contents, &[0x01]);
    assert_eq!(node.child(1).unwrap().contents, b"ab");
    assert!(node.child(2).is_none());
}

#[test]
fn an_indefinite_length_value_reads_to_its_end_of_contents_marker() {
    // SEQUENCE (indefinite) { INTEGER 1 } — what BouncyCastle emits and
    // what every generated receipt in this repo is encoded with.
    let input = [0x30u8, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00];
    let node = parse_exact(&input).unwrap();
    assert_eq!(node.tag, tag::SEQUENCE);
    assert!(node.constructed);
    assert_eq!(node.full, &input[..]);
    // The contents are the children's bytes, borrowed from the input — not
    // a re-encoding of them.
    assert_eq!(node.contents, &[0x02, 0x01, 0x01]);
    assert_eq!(node.children().len(), 1);
}

#[test]
fn trailing_bytes_are_refused() {
    assert!(parse_exact(&[0x04, 0x01, 0x00]).is_ok());
    assert!(parse_exact(&[0x04, 0x01, 0x00, 0x00]).is_err());
    assert!(parse_exact(&[0x30, 0x80, 0x00, 0x00, 0x05, 0x00]).is_err());
}

#[test]
fn an_empty_input_is_refused() {
    assert!(parse_exact(&[]).is_err());
    assert!(parse_exact(&[0x30]).is_err());
}

#[test]
fn a_length_that_exceeds_the_input_is_refused() {
    assert!(parse_exact(&[0x04, 0x05, 0x00]).is_err());
    assert!(parse_exact(&[0x30, 0x82, 0xff, 0xff, 0x00]).is_err());
}

#[test]
fn a_length_of_more_than_four_octets_is_refused() {
    assert!(parse_exact(&[0x30, 0x84, 0x00, 0x00, 0x00, 0x00]).is_ok());
    assert!(parse_exact(&[0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00]).is_err());
}

#[test]
fn a_multi_byte_tag_is_refused() {
    assert!(parse_exact(&[0x1f, 0x01, 0x00]).is_err());
}

#[test]
fn an_indefinite_length_on_a_primitive_value_is_refused() {
    assert!(parse_exact(&[0x04, 0x80, 0x00, 0x00]).is_err());
    assert!(parse_exact(&[0x02, 0x80, 0x00, 0x00]).is_err());
}

#[test]
fn the_depth_bound_is_exactly_where_it_says_it_is() {
    let build = |levels: usize| {
        let mut nested = vec![0x05u8, 0x00];
        for _ in 0..levels {
            let mut wrapped = vec![0x30, u8::try_from(nested.len()).unwrap()];
            wrapped.extend_from_slice(&nested);
            nested = wrapped;
        }
        nested
    };
    assert!(parse_exact(&build(MAX_DEPTH - 1)).is_ok());
    assert!(parse_exact(&build(MAX_DEPTH + 4)).is_err());
}

#[test]
fn the_node_budget_bounds_a_wide_structure() {
    let children = [0x05u8, 0x00].repeat(MAX_NODES + 10);
    let mut input = vec![0x30, 0x84];
    input.extend_from_slice(&u32::try_from(children.len()).unwrap().to_be_bytes());
    input.extend_from_slice(&children);
    assert!(parse_exact(&input).is_err());
}

#[test]
fn a_constructed_octet_string_joins_its_chunks() {
    // OCTET STRING (constructed) { OCTET STRING "ab", OCTET STRING "cd" }
    let input = [0x24u8, 0x08, 0x04, 0x02, b'a', b'b', 0x04, 0x02, b'c', b'd'];
    let node = parse_exact(&input).unwrap();
    assert!(node.is_octet_string());
    assert_eq!(node.octet_string_value().unwrap().as_ref(), b"abcd");
}

#[test]
fn object_identifiers_round_trip() {
    for oid in [
        "1.2.840.113635.100.6.11.1",
        "1.2.840.113635.100.6.2.1",
        "1.2.840.113549.1.7.2",
        "1.3.14.3.2.26",
        "2.16.840.1.101.3.4.2.1",
        "1.2.840.10045.4.3.3",
        "0.0",
        "2.999",
    ] {
        let encoded = encode_oid(oid).unwrap_or_else(|| panic!("{oid}"));
        assert_eq!(decode_oid(&encoded).as_deref(), Some(oid), "{oid}");
    }
}

#[test]
fn a_truncated_object_identifier_is_refused() {
    // A final octet with the continuation bit set has no terminating byte.
    assert!(decode_oid(&[0x2a, 0x86]).is_none());
    assert!(decode_oid(&[]).is_none());
}

#[test]
fn the_reader_never_panics_on_random_bytes() {
    let mut state: u64 = 0x1234_5678_9ABC_DEF1;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..20_000 {
        let length = (next() % 64) as usize;
        let bytes: Vec<u8> = (0..length).map(|_| (next() & 0xff) as u8).collect();
        let outcome = std::panic::catch_unwind(|| parse_exact(&bytes).is_ok());
        assert!(outcome.is_ok(), "the reader panicked on {bytes:02x?}");
    }
}
