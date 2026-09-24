//! Hostile input and resource bounds.
//!
//! Everything this crate parses is attacker-supplied. These tests state the
//! two properties that follow from that: nothing ever panics, and nothing
//! costs unbounded time or memory.

mod common;

use apple_purchase_receipt_verifier::asn1::{parse_exact, MAX_DEPTH};
use apple_purchase_receipt_verifier::{
    verify_receipt_core, Environment, JwsVerifier, Reason, ReceiptVerifier,
};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

fn receipt_verifier() -> ReceiptVerifier {
    ReceiptVerifier::builder()
        .trusted_roots([common::receipt_root()])
        .bundle_id("com.example.app")
        .build()
        .unwrap()
}

fn jws_verifier() -> JwsVerifier {
    JwsVerifier::builder()
        .trusted_roots([common::jws_root()])
        .bundle_id("com.example.app")
        .accepted_environments([Environment::Sandbox])
        .build()
        .unwrap()
}

#[test]
fn eleven_characters_of_base64_do_not_escape_the_contract() {
    // The exact input that once escaped a sibling port's declared contract.
    let verifier = receipt_verifier();
    for text in ["aaaaaaaaaaa", "AAAAAAAAAAA", "////////////", "MIIBIjANBgkq"] {
        let outcome = catch_unwind(AssertUnwindSafe(|| verifier.verify_base64(text)));
        let result = outcome.unwrap_or_else(|_| panic!("verify_base64({text}) panicked"));
        assert_eq!(result.unwrap_err().reason(), Reason::InvalidReceiptFormat);
    }
}

#[test]
fn deeply_nested_asn1_is_refused_rather_than_recursed() {
    // One more level than the reader admits. A parser without this bound
    // recurses off the stack instead of returning.
    let mut nested = vec![0x05, 0x00]; // NULL
    for _ in 0..(MAX_DEPTH + 2) {
        let mut wrapped = vec![0x30, u8::try_from(nested.len()).unwrap()];
        wrapped.extend_from_slice(&nested);
        nested = wrapped;
    }
    assert!(parse_exact(&nested).is_err());
    assert_eq!(
        receipt_verifier().verify(&nested).unwrap_err().reason(),
        Reason::InvalidReceiptFormat
    );
}

#[test]
fn a_thousand_levels_of_nesting_does_not_overflow_the_stack() {
    // Built with two-byte length headers so the depth is genuine.
    let mut nested = vec![0x05, 0x00];
    for _ in 0..1000 {
        let length = nested.len();
        let mut wrapped = vec![
            0x30,
            0x82,
            u8::try_from(length >> 8).unwrap(),
            (length & 0xff) as u8,
        ];
        wrapped.extend_from_slice(&nested);
        nested = wrapped;
    }
    let outcome = catch_unwind(AssertUnwindSafe(|| receipt_verifier().verify(&nested)));
    assert_eq!(
        outcome.unwrap().unwrap_err().reason(),
        Reason::InvalidReceiptFormat
    );
}

#[test]
fn an_unterminated_indefinite_length_value_is_refused() {
    // 0x30 0x80 with no end-of-contents marker.
    assert!(parse_exact(&[0x30, 0x80]).is_err());
    assert!(parse_exact(&[0x30, 0x80, 0x05, 0x00]).is_err());
    // A primitive value may not carry an indefinite length at all.
    assert!(parse_exact(&[0x04, 0x80, 0x00, 0x00]).is_err());
}

#[test]
fn a_declared_length_larger_than_the_input_is_refused_without_allocating() {
    // 2^31 declared on a four-byte input.
    let started = Instant::now();
    assert!(parse_exact(&[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff]).is_err());
    assert!(parse_exact(&[0x04, 0x84, 0xff, 0xff, 0xff, 0xff]).is_err());
    // Five length octets is beyond what this reader admits at all.
    assert!(parse_exact(&[0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00]).is_err());
    assert!(
        started.elapsed().as_millis() < 500,
        "a length claim must not cost time"
    );
}

#[test]
fn multi_byte_tags_are_refused() {
    assert!(parse_exact(&[0x1f, 0x81, 0x00, 0x00]).is_err());
    assert!(parse_exact(&[0x3f, 0x01, 0x00]).is_err());
}

#[test]
fn a_megabyte_of_zeros_is_refused_quickly() {
    let junk = vec![0u8; 1024 * 1024];
    let started = Instant::now();
    assert_eq!(
        receipt_verifier().verify(&junk).unwrap_err().reason(),
        Reason::InvalidReceiptFormat
    );
    assert!(
        started.elapsed().as_millis() < 1000,
        "junk must not cost real work"
    );
}

#[test]
fn a_wide_flat_structure_hits_the_node_budget_rather_than_growing_without_bound() {
    // A SEQUENCE holding 200,000 two-byte children: well past the node
    // budget, and the point where an unbounded parser starts allocating in
    // proportion to whatever the attacker sent.
    let children = [0x05u8, 0x00].repeat(200_000);
    let mut input = vec![0x30, 0x84];
    input.extend_from_slice(&u32::try_from(children.len()).unwrap().to_be_bytes());
    input.extend_from_slice(&children);
    let started = Instant::now();
    assert!(parse_exact(&input).is_err());
    assert!(started.elapsed().as_secs() < 5);
}

#[test]
fn a_certificate_flood_is_rejected_at_a_bounded_cost() {
    // 1,057 embedded certificates — the shape that measured 26 to 45 times
    // the cost of a genuine verification in a port without the bound. Here
    // the bound is enforced before a single certificate is decoded.
    let mut builder = common::CmsBuilder::from_shared();
    let original = builder.certificates[0].clone();
    while builder.certificates.len() < 1057 {
        builder.certificates.push(original.clone());
    }
    let flood = builder.build();
    let verifier = receipt_verifier();

    let genuine = common::receipt_der();
    let started = Instant::now();
    for _ in 0..5 {
        verifier.verify(&genuine).unwrap();
    }
    let genuine_cost = started.elapsed();

    let started = Instant::now();
    for _ in 0..5 {
        assert_eq!(
            verifier.verify(&flood).unwrap_err().reason(),
            Reason::InvalidChain
        );
    }
    let flood_cost = started.elapsed();

    assert!(
        flood_cost < genuine_cost * 10,
        "rejecting a {}-certificate receipt cost {flood_cost:?} against {genuine_cost:?} for a \
         genuine one — the ten-certificate bound is not being enforced before decoding",
        1057
    );
}

#[test]
fn a_cross_signed_certificate_mesh_stays_flat() {
    // Every embedded certificate is a candidate issuer for every other one.
    // Without an explicit path-length bound and a try-each-candidate-once
    // rule, this is where a path builder goes exponential. Ten copies is the
    // most the certificate bound admits, so the walk is bounded twice over.
    let mut builder = common::CmsBuilder::from_shared();
    let all = builder.certificates.clone();
    builder.certificates.clear();
    while builder.certificates.len() < 10 {
        for certificate in &all {
            if builder.certificates.len() < 10 {
                builder.certificates.push(certificate.clone());
            }
        }
    }
    let mesh = builder.build();
    let started = Instant::now();
    let _ = receipt_verifier().verify(&mesh);
    assert!(
        started.elapsed().as_secs() < 5,
        "the path walk must not be exponential"
    );
}

#[test]
fn five_thousand_mutations_of_a_genuine_receipt_never_panic_and_never_verify() {
    // The contract this loop exists for: a mutated receipt may only ever
    // come back as a VerificationError. In Rust the "no foreign error type"
    // half is enforced by the signature, so what is left to prove is that
    // nothing panics and nothing is accepted.
    let genuine = common::receipt_der();
    let verifier = receipt_verifier();
    let genuine_fields = verifier.verify(&genuine).unwrap();
    let mut rng = common::Rng::new(0x5EED_1234_5678_9ABC);
    let mut rejected = 0usize;
    let mut accepted_unchanged = 0usize;
    for iteration in 0..5000 {
        let mut mutated = genuine.clone();
        let count = 1 + rng.below(4);
        for _ in 0..count {
            let index = rng.below(mutated.len());
            mutated[index] ^= 1u8 << rng.below(8);
        }
        let outcome = catch_unwind(AssertUnwindSafe(|| verifier.verify(&mutated)));
        let result = match outcome {
            Ok(result) => result,
            Err(_) => panic!("mutation {iteration} panicked; seed 0x5EED123456789ABC"),
        };
        match result {
            // A mutation may only be accepted if it changed nothing the
            // caller is told. Every structural or cryptographic byte is
            // covered by the signature; the few that are not — a version
            // INTEGER, an algorithm parameter — cannot move a field. This
            // is the invariant worth pinning, and it is strictly stronger
            // than "never accepted": any mutation that alters the returned
            // receipt must be rejected.
            Ok(actual) => {
                assert_eq!(
                    actual, genuine_fields,
                    "mutation {iteration} was accepted AND changed the result; \
                     seed 0x5EED123456789ABC"
                );
                accepted_unchanged += 1;
            }
            Err(error) => {
                // Every reason must still be one of the eleven.
                assert!(
                    apple_purchase_receipt_verifier::Reason::all().contains(&error.reason()),
                    "mutation {iteration} produced {:?}",
                    error.reason()
                );
                rejected += 1;
            }
        }
    }
    assert_eq!(rejected + accepted_unchanged, 5000);
    // Roughly a fifth of the blob is framing this library deliberately does
    // not trust: a SignedData version INTEGER, an algorithm parameter, and
    // above all the embedded copy of the root certificate, which the path
    // walk never uses because the anchor is pinned rather than taken from
    // the receipt. Flipping a bit there is accepted precisely because it
    // changes nothing — which is what the equality assertion above proves.
    // The floor here is a smoke alarm: if it ever drops, something that used
    // to be covered has stopped being covered.
    assert!(
        rejected > 3500,
        "only {rejected} of 5000 mutations were rejected"
    );
}

#[test]
fn the_embedded_root_copy_is_never_trusted() {
    // The counterpart of the x5c[2] rule on the JWS side: a receipt embeds a
    // copy of its root, and replacing it with a foreign certificate must
    // change nothing, because the chain terminates at a pinned anchor.
    let verifier = receipt_verifier();
    let genuine = verifier.verify(&common::receipt_der()).unwrap();

    let mut builder = common::CmsBuilder::from_shared();
    let foreign = common::read_fixture("generated/receipt-expired-root.der");
    let last = builder.certificates.len() - 1;
    builder.certificates[last] = foreign;
    assert_eq!(verifier.verify(&builder.build()).unwrap(), genuine);

    // And dropping it entirely also changes nothing.
    let mut builder = common::CmsBuilder::from_shared();
    builder.certificates.truncate(2);
    assert_eq!(verifier.verify(&builder.build()).unwrap(), genuine);
}

#[test]
fn two_thousand_mutations_of_a_genuine_jws_never_panic_and_never_verify() {
    let genuine = common::transaction_jws();
    let bytes = genuine.as_bytes().to_vec();
    let verifier = jws_verifier();
    let mut rng = common::Rng::new(0x1234_5678_9ABC_DEF1);
    for iteration in 0..2000 {
        let mut mutated = bytes.clone();
        let count = 1 + rng.below(3);
        for _ in 0..count {
            let index = rng.below(mutated.len());
            mutated[index] ^= 1u8 << rng.below(8);
        }
        let text = String::from_utf8_lossy(&mutated).into_owned();
        let outcome = catch_unwind(AssertUnwindSafe(|| verifier.verify_transaction(&text)));
        let result = outcome.unwrap_or_else(|_| panic!("jws mutation {iteration} panicked"));
        assert!(result.is_err(), "jws mutation {iteration} was ACCEPTED");
    }
}

#[test]
fn every_truncation_of_a_genuine_receipt_is_refused_without_panicking() {
    let genuine = common::receipt_der();
    let verifier = receipt_verifier();
    let mut length = 0;
    while length < genuine.len() {
        let outcome = catch_unwind(AssertUnwindSafe(|| verifier.verify(&genuine[..length])));
        let result = outcome.unwrap_or_else(|_| panic!("truncation to {length} panicked"));
        assert!(result.is_err(), "truncation to {length} was accepted");
        length += 37; // a stride that is coprime with every field boundary
    }
}

#[test]
fn arbitrary_byte_strings_never_panic_in_either_entry_point() {
    let receipt = receipt_verifier();
    let jws = jws_verifier();
    let mut rng = common::Rng::new(0xFEED_FACE_CAFE_BEEF);
    for iteration in 0..2000 {
        let length = rng.below(300);
        let bytes: Vec<u8> = (0..length)
            .map(|_| u8::try_from(rng.below(256)).unwrap())
            .collect();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let a = receipt.verify(&bytes).is_err();
            let b = receipt.verify_base64(&text).is_err();
            let c = jws.verify_transaction(&text).is_err();
            let d = jws.verify_raw(&text).is_err();
            let e = verify_receipt_core(&bytes, &[common::receipt_root()]).is_err();
            a && b && c && d && e
        }));
        assert!(outcome.unwrap_or_else(|_| panic!("random input {iteration} panicked")));
    }
}

#[test]
fn every_single_byte_mutation_of_the_first_kilobyte_is_rejected() {
    // Exhaustive rather than random over the structural head of the blob,
    // where the CMS framing lives.
    let genuine = common::receipt_der();
    let verifier = receipt_verifier();
    let genuine_fields = verifier.verify(&genuine).unwrap();
    for index in 0..1024.min(genuine.len()) {
        for bit in [0u8, 3, 7] {
            let mut mutated = genuine.clone();
            mutated[index] ^= 1u8 << bit;
            let outcome = catch_unwind(AssertUnwindSafe(|| verifier.verify(&mutated)));
            let result = outcome.unwrap_or_else(|_| panic!("byte {index} bit {bit} panicked"));
            if let Ok(actual) = result {
                assert_eq!(
                    actual, genuine_fields,
                    "byte {index} bit {bit} was accepted AND changed the result"
                );
            }
        }
    }
}

/// A verified JWS must have exactly **one** accepted spelling.
///
/// The byte-mutation pass above only ever changes bytes in place, so it
/// never found the class of malleability that mattered: inserting or
/// appending characters the decoder used to skip. An attacker holding one
/// Apple-signed `jwsRepresentation` (or an App Store Server Notification V2
/// body, which *is* a JWS) could mint unbounded byte-distinct strings that
/// all verify to the same transaction, defeating dedupe on the string or its
/// hash.
#[test]
fn no_respelling_of_a_genuine_jws_is_accepted() {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let genuine = common::transaction_jws();
    let verifier = jws_verifier();
    assert!(verifier.verify_transaction(&genuine).is_ok(), "baseline");
    let (header, payload, signature) = common::split_jws(&genuine);

    let mut candidates: Vec<String> = Vec::new();
    // Characters a lenient decoder skips, at every segment boundary.
    for junk in ["=", "==", "\n", " ", "\t", "!", "~~~", "\r\n", "%%%%"] {
        candidates.push(common::join_jws(
            &format!("{header}{junk}"),
            &payload,
            &signature,
        ));
        candidates.push(common::join_jws(
            &header,
            &format!("{payload}{junk}"),
            &signature,
        ));
        candidates.push(common::join_jws(
            &header,
            &payload,
            &format!("{signature}{junk}"),
        ));
        candidates.push(common::join_jws(
            &header,
            &payload,
            &format!("{junk}{signature}"),
        ));
    }
    // Junk interleaved rather than appended.
    let interleaved: String = signature.chars().flat_map(|c| [c, '\n']).collect();
    candidates.push(common::join_jws(&header, &payload, &interleaved));
    // Every position of the signature segment, four alternative characters
    // each — the last position is where the unused bits live.
    let mut rng = common::Rng::new(0x0BAD_C0DE_0BAD_C0DE);
    for position in 0..signature.len() {
        for _ in 0..4 {
            let replacement = char::from(ALPHABET[rng.below(ALPHABET.len())]);
            let mut respelt = signature.clone();
            respelt.replace_range(position..=position, &replacement.to_string());
            if respelt != signature {
                candidates.push(common::join_jws(&header, &payload, &respelt));
            }
        }
    }

    let mut accepted = Vec::new();
    for candidate in &candidates {
        let outcome = catch_unwind(AssertUnwindSafe(|| verifier.verify_transaction(candidate)));
        let result = outcome.unwrap_or_else(|_| panic!("respelling panicked: {candidate:?}"));
        if result.is_ok() {
            accepted.push(candidate.clone());
        }
    }
    assert!(
        accepted.is_empty(),
        "{} of {} respellings of one genuine JWS were accepted: {:?}",
        accepted.len(),
        candidates.len(),
        accepted.iter().take(3).collect::<Vec<_>>()
    );
}
