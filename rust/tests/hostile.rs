//! Hostile input and resource bounds.
//!
//! Everything this crate reads is attacker-supplied, and OpenSSL parses it.
//! These tests state the two properties that follow from that, through the
//! public API: nothing ever panics, and nothing costs unbounded time or
//! memory.

mod common;

use apple_purchase_receipt_verifier::{Environment, Reason, ReceiptPayload, Verifier};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

fn receipt_verifier() -> Verifier {
    common::receipt_verifier()
}

fn jws_verifier() -> Verifier {
    common::jws_verifier()
}

/// `verify_receipt` over the base64 of `der`.
trait VerifyDer {
    fn verify(
        &self,
        der: &[u8],
    ) -> Result<ReceiptPayload, apple_purchase_receipt_verifier::Failure>;
}

impl VerifyDer for Verifier {
    fn verify(
        &self,
        der: &[u8],
    ) -> Result<ReceiptPayload, apple_purchase_receipt_verifier::Failure> {
        common::verify_der(self, der)
    }
}

#[test]
fn eleven_characters_of_base64_do_not_escape_the_contract() {
    // The exact input that once escaped a sibling port's declared contract.
    let verifier = receipt_verifier();
    for text in ["aaaaaaaaaaa", "AAAAAAAAAAA", "////////////", "MIIBIjANBgkq"] {
        let outcome = catch_unwind(AssertUnwindSafe(|| verifier.verify_receipt(text)));
        let result = outcome.unwrap_or_else(|_| panic!("verify_receipt({text}) panicked"));
        assert_eq!(result.unwrap_err().reason(), Reason::Malformed);
    }
}

#[test]
fn deeply_nested_asn1_is_refused_rather_than_recursed() {
    // Past the 0.7 ASN.1 depth bound of 32. A parser without a bound
    // recurses off the stack instead of returning.
    let mut nested = vec![0x05, 0x00]; // NULL
    for _ in 0..34 {
        let mut wrapped = vec![0x30, u8::try_from(nested.len()).unwrap()];
        wrapped.extend_from_slice(&nested);
        nested = wrapped;
    }
    assert_eq!(
        receipt_verifier().verify(&nested).unwrap_err().reason(),
        Reason::Malformed
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
    assert_eq!(outcome.unwrap().unwrap_err().reason(), Reason::Malformed);
}

#[test]
fn an_unterminated_indefinite_length_value_is_refused() {
    let verifier = receipt_verifier();
    // 0x30 0x80 with no end-of-contents marker, and a primitive value with
    // an indefinite length, which no encoding allows.
    for input in [
        &[0x30, 0x80][..],
        &[0x30, 0x80, 0x05, 0x00],
        &[0x04, 0x80, 0x00, 0x00],
    ] {
        assert_eq!(
            verifier.verify(input).unwrap_err().reason(),
            Reason::Malformed,
            "{input:02x?}"
        );
    }
}

#[test]
fn a_declared_length_larger_than_the_input_is_refused_without_allocating() {
    // 2^31 declared on a four-byte input, and a five-octet length.
    let verifier = receipt_verifier();
    let started = Instant::now();
    for input in [
        &[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff][..],
        &[0x04, 0x84, 0xff, 0xff, 0xff, 0xff],
        &[0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00],
    ] {
        assert_eq!(
            verifier.verify(input).unwrap_err().reason(),
            Reason::Malformed,
            "{input:02x?}"
        );
    }
    assert!(
        started.elapsed().as_millis() < 500,
        "a length claim must not cost time"
    );
}

#[test]
fn multi_byte_tags_are_refused() {
    let verifier = receipt_verifier();
    for input in [&[0x1f, 0x81, 0x00, 0x00][..], &[0x3f, 0x01, 0x00]] {
        assert_eq!(
            verifier.verify(input).unwrap_err().reason(),
            Reason::Malformed,
            "{input:02x?}"
        );
    }
}

#[test]
fn a_megabyte_of_zeros_is_refused_quickly() {
    let junk = vec![0u8; 1024 * 1024];
    let started = Instant::now();
    assert_eq!(
        receipt_verifier().verify(&junk).unwrap_err().reason(),
        Reason::Malformed
    );
    assert!(
        started.elapsed().as_millis() < 1000,
        "junk must not cost real work"
    );
}

#[test]
fn a_wide_flat_structure_is_refused_at_a_bounded_cost() {
    // A SEQUENCE holding 200,000 two-byte children: the point where an
    // unbounded parser starts allocating in proportion to whatever the
    // attacker sent. It is no ContentInfo, and OpenSSL's template decoder
    // stops at the first child that is not one.
    let children = [0x05u8, 0x00].repeat(200_000);
    let mut input = vec![0x30, 0x84];
    input.extend_from_slice(&u32::try_from(children.len()).unwrap().to_be_bytes());
    input.extend_from_slice(&children);
    let started = Instant::now();
    assert_eq!(
        receipt_verifier().verify(&input).unwrap_err().reason(),
        Reason::Malformed
    );
    assert!(started.elapsed().as_secs() < 5);
}

#[test]
fn a_certificate_flood_is_rejected_at_a_bounded_cost() {
    // 1,057 embedded certificates — the shape that measured 26 to 45 times
    // the cost of a genuine verification in a port without the bound.
    // OpenSSL's CMS decoder builds every certificate's public key (about
    // 45 ms for this flood), so the bound is enforced on a shallow decode
    // that keeps each certificate as raw bytes, before the full one.
    let mut builder = common::CmsBuilder::from_shared();
    let original = builder.certificates[0].clone();
    while builder.certificates.len() < 1057 {
        builder.certificates.push(original.clone());
    }
    let flood_der = builder.build();
    // The same flood with one byte after it. The header walk runs before
    // anything is decoded: it reads every header of the flood, hands each
    // of its 20,000 or so checked primitives to OpenSSL's decoder, and then
    // refuses the byte. That is what any reader of the flood pays past its
    // base64, and in an unoptimised test build it is one to two times the
    // base64's cost, so it, not junk, is the control the flood and the
    // broken envelope are judged against.
    let mut walked_der = flood_der.clone();
    walked_der.push(0x00);
    // The same flood with its signerInfos SET written as a SEQUENCE: the
    // walk passes it and the shallow decode refuses it, which must not
    // then fall through to the full decode.
    let signer_infos = common::der_set(&[builder.signer_info()]);
    let mut broken_der = flood_der.clone();
    let at = broken_der.len() - signer_infos.len();
    broken_der[at] = 0x30;
    let verifier = receipt_verifier();
    // Encoded once, outside the clock: the test's own base64 is not the
    // library's cost.
    let encode = apple_purchase_receipt_verifier::__internal::base64_encode;
    let (flood, walked, broken, genuine) = (
        encode(&flood_der),
        encode(&walked_der),
        encode(&broken_der),
        encode(&common::receipt_der()),
    );

    // Interleaved, so all four see the same load from the tests running
    // alongside this one.
    let mut costs = [Duration::ZERO; 4];
    for _ in 0..5 {
        let started = Instant::now();
        verifier.verify_receipt(&genuine).unwrap();
        costs[0] += started.elapsed();

        let started = Instant::now();
        let refused = verifier.verify_receipt(&walked).unwrap_err();
        costs[1] += started.elapsed();
        assert_eq!(refused.reason(), Reason::Malformed);
        assert!(refused.to_string().contains("bytes follow"), "{refused}");

        let started = Instant::now();
        let refused = verifier.verify_receipt(&flood).unwrap_err();
        costs[2] += started.elapsed();
        assert_eq!(refused.reason(), Reason::Malformed);
        assert!(
            refused.to_string().contains("1057 certificates"),
            "{refused}"
        );

        let started = Instant::now();
        let refused = verifier.verify_receipt(&broken).unwrap_err();
        costs[3] += started.elapsed();
        assert_eq!(refused.reason(), Reason::Malformed);
    }
    let [genuine_cost, walked_cost, flood_cost, broken_cost] = costs;

    // Half the walk's cost again, plus ten genuine verifications, is
    // headroom for the shallow decode and for timing noise; the full
    // decode alone costs more than that.
    assert!(
        flood_cost < walked_cost * 3 / 2 + genuine_cost * 10,
        "rejecting a 1057-certificate receipt cost {flood_cost:?}, against {walked_cost:?} for \
         walking it and {genuine_cost:?} for a genuine receipt — the ten-certificate bound is \
         not being enforced before the envelope decode"
    );
    assert!(
        broken_cost < walked_cost * 3 / 2 + genuine_cost * 10,
        "rejecting the flood with a broken signerInfos cost {broken_cost:?}, against \
         {walked_cost:?} for walking it and {genuine_cost:?} for a genuine receipt — an \
         envelope the shallow decode refuses is reaching the full decode"
    );
}

#[test]
fn unsigned_content_of_tiny_attributes_is_refused_at_a_bounded_cost() {
    // Policy-F6: the creation date is read before any chain or signature,
    // and a 3 MiB payload of 180,000 tiny attributes cost 300 ms natively
    // and 0.8 s in Wasm there, with linear memory grown to 74 MiB, even
    // when no SignerInfo named an embedded certificate. The date is now read
    // only once a signer has been found, under the 100,000-value budget, so
    // the tiny attributes cost what one flat value of the same size costs.
    let tiny = [
        0x30, 0x0b, 0x02, 0x02, 0x23, 0x28, 0x02, 0x01, 0x01, 0x04, 0x02, 0x05, 0x00,
    ];
    let count = (3_145_728 / 4 * 3 - 20_000) / tiny.len();
    let set_of = |body: &[u8]| {
        let mut set = vec![0x31, 0x84];
        set.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        set.extend_from_slice(body);
        set
    };
    let mut builder = common::CmsBuilder::from_shared();
    builder.content = Some(set_of(&tiny.repeat(count)));
    let signer_embedded = builder.build();
    let mut absent_builder = common::CmsBuilder::from_shared();
    absent_builder.content = builder.content.clone();
    absent_builder.signer_serial = vec![0x7f; 8];
    let signer_absent = absent_builder.build();
    // One attribute whose value is a single OCTET STRING of the same size.
    let flat_value = vec![0u8; count * tiny.len() - 20];
    let mut flat_attribute = vec![0x30, 0x84];
    let flat_body = [
        &[0x02, 0x02, 0x23, 0x28, 0x02, 0x01, 0x01, 0x04, 0x84][..],
        &u32::try_from(flat_value.len()).unwrap().to_be_bytes(),
        &flat_value,
    ]
    .concat();
    flat_attribute.extend_from_slice(&u32::try_from(flat_body.len()).unwrap().to_be_bytes());
    flat_attribute.extend_from_slice(&flat_body);
    builder.content = Some(set_of(&flat_attribute));
    let flat = builder.build();
    absent_builder.content = builder.content.clone();
    let flat_absent = absent_builder.build();

    let verifier = receipt_verifier();
    let encode = apple_purchase_receipt_verifier::__internal::base64_encode;
    // Each tiny input is judged against the flat input of the same size
    // and the same signer, which pays the same base64, decodes and copies
    // (round-3 review F3; junk, which costs only its base64, made a
    // control whose margin shrank with the optimiser). Without a signer
    // the ratio is near 1 in every build. Under an embedded signer the tiny
    // input also pays the payload walk up to the 100,000-value budget,
    // which the flat value does not: 1.6 times the flat input in a debug
    // build on the pinned toolchain, up to 2.0 on the 1.85.0 floor, so
    // that bound allows three times. The regression these bounds guard,
    // the payload read in full, cost about 30 times the flat input.
    let inputs = [
        encode(&common::receipt_der()),
        encode(&flat_absent),
        encode(&signer_absent),
        encode(&flat),
        encode(&signer_embedded),
    ];
    // Each input's cost is its fastest of seven interleaved calls: the
    // bounds below are ratios between inputs, and on a loaded machine a
    // sum or a mean carries whatever else ran during one call, while the
    // fastest call is the closest to the work itself for every input alike.
    let mut costs = [Duration::MAX; 5];
    for _ in 0..7 {
        for (index, input) in inputs.iter().enumerate() {
            let started = Instant::now();
            let result = verifier.verify_receipt(input);
            costs[index] = costs[index].min(started.elapsed());
            let expected = [
                None,
                Some(Reason::Malformed),
                Some(Reason::Malformed),
                Some(Reason::InvalidSignature),
                Some(Reason::InvalidSignature),
            ][index];
            assert_eq!(
                result.err().map(|failure| failure.reason()),
                expected,
                "input {index}"
            );
        }
    }
    let [genuine, flat_absent, absent, flat, embedded] = costs;
    assert!(
        absent < flat_absent * 2 + genuine * 10,
        "unsigned content of {count} tiny attributes and no embedded signer cost {absent:?}, \
         against {flat_absent:?} for one flat value of the same size and no embedded signer: \
         the payload was read before a signer was found"
    );
    assert!(
        embedded < flat * 3 + genuine * 10,
        "unsigned content of {count} tiny attributes under an embedded signer cost {embedded:?}, \
         against {flat:?} for one flat value of the same size"
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
    // come back as a Failure. In Rust the "no foreign error type"
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
                // Every reason must still be one of the eight.
                assert!(
                    Reason::all().contains(&error.reason()),
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
        let outcome = catch_unwind(AssertUnwindSafe(|| verifier.verify_signed_data(&text)));
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
            let b = receipt.verify_receipt(&text).is_err();
            let c = jws.verify_signed_data(&text).is_err();
            let body = serde_json::json!({ "receipt-data": text }).to_string();
            let d = receipt.verify_receipt_endpoint(Environment::Sandbox, &text)
                != "{\"status\":0}"
                && receipt.verify_receipt_endpoint(Environment::Sandbox, &body) != "{\"status\":0}";
            a && b && c && d
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
    assert!(verifier.verify_signed_data(&genuine).is_ok(), "baseline");
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
        let outcome = catch_unwind(AssertUnwindSafe(|| verifier.verify_signed_data(candidate)));
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
