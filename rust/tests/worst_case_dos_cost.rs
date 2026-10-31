//! The measured cost envelope of the denial-of-service surface, case by
//! case from Java's `WorstCaseDosCostTest`: the longest request the core
//! serves (a genuine receipt at Apple's cap), the worst shape (the cap
//! spent on nested SETs), the historic huge-key receipt, Apple's genuine
//! SignerInfo copied to the SignerInfo cap, and a sustained burst of
//! distinct tampered receipts whose per-item cost must hold flat.
//!
//! Each case prints its cost. Java pins each near its measured number;
//! an unoptimised Cargo build on a shared machine cannot, so the
//! absolute bounds here are `common::pki::BUDGET` and the burst keeps
//! Java's relative bound. Release numbers come from a `--release` run.

mod common;

use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{Config, Environment, Reason, Verifier};
use common::pki::{
    self, best_of, cert_fields, g5_der, in_app_purchase, index_of, modulus_without_small_factors,
    nested_sets, now_ms, receipt_payload, rsa_spki, sign_receipt_as, single_attribute_payload,
    small_primes_product, test_pki_cert_named, timed, with_bag, CertSpec, Hash, Key, Pki,
    SignedDataParts, Synthetic, BUDGET, CAP_DER, E65537, MAX_RECEIPT_BYTES, SIGNING_LEAF_OID,
};
use std::time::Duration;

const BUNDLE: &str = "com.example.app";
const MAX_REQUEST_BYTES: usize = 3_145_728;

// --- the envelope ------------------------------------------------------------

/// Mirrors `genuineTrafficVerifiesInMilliseconds`: the best of three.
#[test]
fn genuine_traffic_verifies_in_milliseconds() {
    let synthetic = Synthetic::new();
    let verifier = synthetic.pki.verifier();
    let receipt = synthetic.base64();
    let verified = verifier.verify_receipt(&receipt).unwrap();
    assert_eq!(verified.bundle_id.as_deref(), Some(BUNDLE));
    let (_, best) = best_of(3, || verifier.verify_receipt(&receipt).unwrap());
    eprintln!("genuine receipt verify: {} ms", best.as_millis());
    assert!(best < BUDGET, "took {best:?}");
}

/// Mirrors `theLongestRequestWeServeIsAGenuineReceiptAtTheCapAndItVerifiesQuickly`:
/// a genuine receipt of exactly 2,359,296 bytes of DER, 2,300 purchases,
/// built here at run time (`LargeReceiptFixture.exactSize`).
#[test]
fn the_longest_request_we_serve_is_a_genuine_receipt_at_the_cap_and_it_verifies_quickly() {
    let synthetic = Synthetic::new();
    let der = synthetic.exact_size(CAP_DER);
    let receipt = base64_encode(&der);
    assert_eq!(receipt.len(), MAX_RECEIPT_BYTES);
    let verifier = synthetic.pki.verifier();
    let (verified, best) = best_of(2, || verifier.verify_receipt(&receipt).unwrap());
    eprintln!(
        "genuine receipt at Apple's cap (2,359,296 B of DER): {} ms",
        best.as_millis()
    );
    assert_eq!(verified.bundle_id.as_deref(), Some(BUNDLE));
    assert_eq!(verified.in_app.len(), 2300);
    assert!(best < BUDGET, "took {best:?}");
}

/// A verifying request body, optionally carrying a padding member.
fn request_json(receipt: &str, padding: Option<&str>) -> String {
    match padding {
        Some(padding) if !padding.is_empty() => {
            format!(r#"{{"receipt-data":"{receipt}","padding":"{padding}"}}"#)
        }
        _ => format!(r#"{{"receipt-data":"{receipt}"}}"#),
    }
}

/// Mirrors `anEndpointBodyAtTheCapAnswersNearTheCostOfTheReceiptItCarries`:
/// a body of exactly 3,145,728 UTF-8 bytes, a genuine receipt and a
/// padding member of U+00E9.
#[test]
fn an_endpoint_body_at_the_cap_answers_near_the_cost_of_the_receipt_it_carries() {
    let synthetic = Synthetic::new();
    let verifier = synthetic.pki.verifier();
    let receipt = synthetic.base64();
    let fixed = request_json(&receipt, None).len() + r#","padding":"""#.len();
    let missing = MAX_REQUEST_BYTES - fixed;
    let padding = format!(
        "{}{}",
        "\u{e9}".repeat(missing / 2),
        if missing % 2 == 1 { "a" } else { "" }
    );
    let body = request_json(&receipt, Some(&padding));
    assert_eq!(body.len(), MAX_REQUEST_BYTES);

    let expected =
        verifier.verify_receipt_endpoint(Environment::Sandbox, &request_json(&receipt, None));
    assert!(expected.starts_with(r#"{"status":0,"#), "{expected:.200}");

    let (answer, cost) = timed(|| verifier.verify_receipt_endpoint(Environment::Sandbox, &body));
    eprintln!(
        "endpoint body at the 3,145,728-byte cap: {} ms",
        cost.as_millis()
    );
    assert!(answer.starts_with(r#"{"status":0,"#), "{answer:.200}");
    assert!(cost < BUDGET, "took {cost:?}");
}

/// Mirrors `theHistoricFourteenSecondHugeKeyAttackNowVerifiesInMilliseconds`:
/// eight strangers named as the intermediate and issued under the root's
/// name, each a CA on a fresh 16,384-bit modulus with no factor below
/// 10,000, signed by an attacker key, beside the genuine chain. None is
/// vouched for, so none is decoded, and the receipt verifies.
#[test]
fn the_historic_fourteen_second_huge_key_attack_now_verifies_in_milliseconds() {
    let pki = Pki::receipt();
    let (attacker, signer_key) = (Key::rsa(), Key::rsa());
    let intermediate = cert_fields(&pki.intermediate);
    let root = cert_fields(&pki.root);
    let signer = test_pki_cert_named(
        pki::name("Fake Receipt Signing"),
        &signer_key,
        intermediate.subject.clone(),
        &pki.intermediate_key,
        false,
        Some(SIGNING_LEAF_OID),
        pki.not_before,
        pki.not_after,
    );
    let small_primes = small_primes_product();
    let mut embedded = vec![signer.clone(), pki.intermediate.clone()];
    for _ in 0..8 {
        let modulus = modulus_without_small_factors(16_384, &small_primes);
        let mut spec = CertSpec::new(
            intermediate.subject.clone(),
            root.subject.clone(),
            rsa_spki(&modulus, E65537),
        );
        spec.not_before = pki.not_before;
        spec.not_after = pki.not_after;
        spec.extensions.push(pki::basic_constraints(true, None));
        embedded.push(spec.sign(&attacker));
    }
    let creation = now_ms() / 1000 * 1000;
    let payload = receipt_payload(
        BUNDLE,
        "1.0",
        &[1, 2, 3, 4],
        &[0; 20],
        &pki::rfc3339(creation),
        &[],
    );
    let receipt = sign_receipt_as(
        &payload,
        creation,
        &signer_key,
        Hash::Sha256,
        &[&signer],
        &embedded,
    );

    let verifier = pki.verifier();
    let encoded = base64_encode(&receipt);
    let (verified, cost) = timed(|| verifier.verify_receipt(&encoded));
    eprintln!(
        "genuine receipt beside eight 16,384-bit strangers: {} ms",
        cost.as_millis()
    );
    assert_eq!(verified.unwrap().bundle_id.as_deref(), Some(BUNDLE));
    assert!(cost < BUDGET, "took {cost:?}");
}

/// Mirrors `theWorstShapedReceiptRefusesAtTheCostOfItsParse`: a genuine
/// receipt's chain beside the cap spent on SETs nested 59 deep.
///
/// Java walks every node before refusing the entry as no certificate
/// ("an embedded certificate is not a valid certificate"). The core
/// refuses it at its envelope walk, the depth bound of 32, before OpenSSL
/// decodes anything (DECISIONS.md R20, "An envelope nested 33 deep"); the
/// reason is the same.
#[test]
fn the_worst_shaped_receipt_refuses_at_the_cost_of_its_parse() {
    let pki = Pki::receipt();
    let genuine =
        SignedDataParts::parse(&pki.sign_receipt(&single_attribute_payload(9999, &[0; 16])));
    let mut bag = genuine.certificates.clone();
    bag.push(nested_sets(59, CAP_DER - 16_384));
    let receipt = base64_encode(&with_bag(&genuine, bag));
    let verifier = pki.verifier();
    let (refused, best) = best_of(2, || verifier.verify_receipt(&receipt).unwrap_err());
    eprintln!(
        "worst shape, the cap in nested SETs (parse floor): {} ms ({})",
        best.as_millis(),
        refused.message()
    );
    assert_eq!(refused.reason(), Reason::Malformed, "{refused}");
    assert!(best < BUDGET, "took {best:?}");
}

// --- the real pins -------------------------------------------------------------

/// Mirrors `theWorstShapeUnderApplesOwnPinsIsStillTheParseFloor`: the
/// genuine G5 chain beside the same tree, under the bundled roots. As
/// above, the core refuses it at its depth bound.
#[test]
fn the_worst_shape_under_apples_own_pins_is_still_the_parse_floor() {
    let verifier = Verifier::new(Config::default());
    let genuine = SignedDataParts::parse(&g5_der());
    let mut bag = genuine.certificates.clone();
    bag.push(nested_sets(59, CAP_DER - 16_384));
    let receipt = base64_encode(&with_bag(&genuine, bag));
    let (refused, best) = best_of(2, || verifier.verify_receipt(&receipt).unwrap_err());
    eprintln!(
        "worst shape under Apple's own pins: {} ms ({})",
        best.as_millis(),
        refused.message()
    );
    assert_eq!(refused.reason(), Reason::Malformed, "{refused}");
    assert!(best < BUDGET, "took {best:?}");
}

/// Mirrors `fourCopiesOfApplesGenuineSignerAtTheCapCostMillisecondsUnderApplesOwnPins`:
/// Apple's genuine SignerInfo four times (the SignerInfo cap) over
/// cap-sized content it never signed, created inside the real leaf's
/// window. Each copy runs the full pipeline against the real pins and
/// fails at the signature.
#[test]
fn four_copies_of_apples_genuine_signer_at_the_cap_cost_milliseconds_under_apples_own_pins() {
    let verifier = Verifier::new(Config::default());
    let genuine = SignedDataParts::parse(&g5_der());
    let product_id = BUNDLE.to_owned() + &"x".repeat(CAP_DER - 16_384 - BUNDLE.len());
    let content = receipt_payload(
        BUNDLE,
        "1.0",
        &[1, 2, 3, 4],
        &[0; 20],
        "2025-06-01T00:00:00Z",
        &[in_app_purchase(
            1,
            &product_id,
            "70000000000001",
            "70000000000001",
            "2024-01-15T12:00:00Z",
            None,
        )],
    );
    let receipt = SignedDataParts {
        digest_algorithms: genuine.digest_algorithms.clone(),
        encap: SignedDataParts::encap_of(&content),
        certificates: genuine.certificates.clone(),
        signer_infos: vec![genuine.signer_infos[0].clone(); 4],
    }
    .build();
    assert!(
        receipt.len() <= CAP_DER,
        "the receipt is over the cap: {}",
        receipt.len()
    );
    let encoded = base64_encode(&receipt);
    let (refused, best) = best_of(2, || verifier.verify_receipt(&encoded).unwrap_err());
    eprintln!(
        "four genuine Apple signers over cap-sized content: {} ms ({})",
        best.as_millis(),
        refused.message()
    );
    assert_eq!(refused.reason(), Reason::InvalidSignature, "{refused}");
    assert!(best < BUDGET, "took {best:?}");
}

// --- the burst -------------------------------------------------------------------

/// The genuine receipt with one product-id byte changed, a different one
/// per `seed`.
fn tampered(der: &[u8], product: &[u8], seed: usize) -> Vec<u8> {
    let mut hostile = der.to_vec();
    let at = index_of(&hostile, product).unwrap() + seed % product.len();
    hostile[at] ^= u8::try_from((seed + 1) % 256).unwrap();
    hostile
}

/// Mirrors `aSustainedBurstOfDistinctTamperedReceiptsStaysFlat`: 200
/// distinct tampered receipts, each refused only after its content is
/// digested and its signature compared; the average over the burst must
/// not rise past three times the first fifty's (Java's relative bound).
#[test]
fn a_sustained_burst_of_distinct_tampered_receipts_stays_flat() {
    let synthetic = Synthetic::new();
    let verifier = synthetic.pki.verifier();
    let product = format!("{BUNDLE}.vip").into_bytes();
    for seed in 0..5 {
        assert!(common::verify_der(&verifier, &tampered(&synthetic.der, &product, seed)).is_err());
    }
    let (mut first, mut total, mut worst) = (Duration::ZERO, Duration::ZERO, Duration::ZERO);
    for i in 0..200 {
        let receipt = base64_encode(&tampered(&synthetic.der, &product, i));
        let (result, cost) = timed(|| verifier.verify_receipt(&receipt));
        let failure = result.unwrap_err();
        assert_eq!(
            failure.reason(),
            Reason::InvalidSignature,
            "item {i}: {failure}"
        );
        if i < 50 {
            first += cost;
        }
        total += cost;
        worst = worst.max(cost);
    }
    let (first_avg, all_avg) = (first / 50, total / 200);
    eprintln!(
        "200 distinct tampered receipts: first 50 avg {:.3} ms, all avg {:.3} ms, worst {} ms",
        first_avg.as_secs_f64() * 1000.0,
        all_avg.as_secs_f64() * 1000.0,
        worst.as_millis()
    );
    assert!(worst < BUDGET, "an item took {worst:?}");
    assert!(
        all_avg < first_avg * 3 + Duration::from_millis(100),
        "the burst degraded: first 50 avg {first_avg:?}, all avg {all_avg:?}"
    );
}
