//! The red-team smoke over the attack shapes a hostile receipt reaches,
//! case by case from Java's `WorstCaseAttackSurfaceTest`. Every case is a
//! real attack: each must be refused, refused within the budget, and
//! never panic, and the no-panic rule is re-checked on random and mutated
//! input. Each case prints its cost; `common::pki::BUDGET` explains the
//! bound.

mod common;

use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{Environment, Reason, ReceiptPayload, Verifier};
use common::pki::{
    self, basic_constraints, latin1, marker, payload_now, random_below, random_bytes, refused,
    refused_der, test_pki_cert, timed, CertSpec, Key, Pki, BUDGET, NULL, SIGNING_LEAF_OID,
};
use common::{der_int, der_seq, Rng};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::OnceLock;
use std::time::Duration;

const PREFIX: &str = "worstCase";

struct Material {
    pki: Pki,
    other_pki: Pki,
    deep_pki: Pki,
    verifier: Verifier,
    deep_verifier: Verifier,
    genuine: String,
}

/// Java's `@BeforeAll`: three PKIs and a genuine receipt, minted once.
fn material() -> &'static Material {
    static MATERIAL: OnceLock<Material> = OnceLock::new();
    MATERIAL.get_or_init(|| {
        let pki = Pki::receipt();
        let other_pki = Pki::receipt();
        // 7 intermediates and 1 self-issued tail: 10 embedded certificates
        // (the cap), a path of 9 below the anchor.
        let deep_pki = Pki::deep(7, 1);
        let verifier = pki.verifier();
        let deep_verifier = deep_pki.verifier();
        let genuine = base64_encode(&pki.sign_receipt(&payload_now()));
        Material {
            pki,
            other_pki,
            deep_pki,
            verifier,
            deep_verifier,
            genuine,
        }
    })
}

fn b64(der: &[u8]) -> String {
    base64_encode(der)
}

/// `TestPki.cert("CN=Padding i", ...)`: self-signed strangers on one key.
fn padding(count: usize, from: usize) -> Vec<Vec<u8>> {
    let key = Key::rsa();
    let pki = &material().pki;
    (from..from + count)
        .map(|i| {
            let cn = format!("Padding {i}");
            test_pki_cert(
                &cn,
                &key,
                &cn,
                &key,
                false,
                None,
                pki.not_before,
                pki.not_after,
            )
        })
        .collect()
}

/// A certificate with the leaf's issuer, serial, validity and subject on
/// `key`, signed by `key`: `TestPki.twinOfLeaf`.
fn twin_of_leaf(pki: &Pki, key: &Key) -> Vec<u8> {
    let leaf = pki::cert_fields(&pki.leaf);
    let mut spec = CertSpec::new(leaf.subject, leaf.issuer, key.spki());
    spec.serial = leaf.serial;
    spec.not_before = pki.not_before;
    spec.not_after = pki.not_after;
    spec.extensions.push(basic_constraints(false, None));
    spec.extensions.push(marker(SIGNING_LEAF_OID, NULL));
    spec.sign(key)
}

/// Mirrors `controlGenuineReceiptVerifiesUnderThePinnedRoot`.
#[test]
fn control_genuine_receipt_verifies_under_the_pinned_root() {
    let m = material();
    let payload = pki::verifies(PREFIX, "genuine control", &m.verifier, &m.genuine);
    assert_eq!(payload.bundle_id.as_deref(), Some("com.example.app"));
}

/// Mirrors `asn1NestedFiveHundredDeepIsRefusedAsMalformedFast`: 500
/// SEQUENCEs around an INTEGER, refused at the core's depth bound (32).
#[test]
fn asn1_nested_five_hundred_deep_is_refused_as_malformed_fast() {
    let mut nested = der_int(0);
    for _ in 0..500 {
        nested = der_seq(&[nested]);
    }
    refused_der(
        PREFIX,
        "nesting-500-deep",
        &material().verifier,
        &nested,
        &[Reason::Malformed],
    );
}

/// Mirrors `receiptOverTheSizeCapIsRefusedBeforeAnythingIsDecoded`.
#[test]
fn receipt_over_the_size_cap_is_refused_before_anything_is_decoded() {
    let oversized = "A".repeat(4 * 1024 * 1024);
    refused(
        PREFIX,
        "oversized-4mib",
        &material().verifier,
        &oversized,
        &[Reason::TooLarge],
    );
}

/// Mirrors `nonCanonicalBase64IsRefusedAsMalformed`, both of its cases.
#[test]
fn non_canonical_base64_is_refused_as_malformed() {
    let m = material();
    let broken = format!("{}!!", &m.genuine[..m.genuine.len() - 2]);
    refused(
        PREFIX,
        "non-canonical-base64",
        &m.verifier,
        &broken,
        &[Reason::Malformed],
    );
    refused(
        PREFIX,
        "empty-receipt",
        &m.verifier,
        "",
        &[Reason::Malformed],
    );
}

/// Mirrors `certificateBagPaddingIsRefusedOnTheCount`, both of its cases:
/// 203 certificates and 102 (a hundred leaf copies), over the cap of ten.
#[test]
fn certificate_bag_padding_is_refused_on_the_count() {
    let m = material();
    let mut bag = m.pki.chain.clone();
    bag.extend(padding(200, 0));
    refused_der(
        PREFIX,
        "bag-padded-203-certs",
        &m.verifier,
        &m.pki.sign_receipt_with_bag(&payload_now(), &bag),
        &[Reason::Malformed],
    );
    let mut copies = vec![m.pki.leaf.clone(); 100];
    copies.push(m.pki.intermediate.clone());
    copies.push(m.pki.root.clone());
    refused_der(
        PREFIX,
        "bag-hundred-leaf-copies",
        &m.verifier,
        &m.pki.sign_receipt_with_bag(&payload_now(), &copies),
        &[Reason::Malformed],
    );
}

/// Mirrors `receiptOmittingTheSignerCertificateIsRefusedAsMalformed`: the
/// leaf signs, twenty strangers are embedded and the signer is not.
#[test]
fn receipt_omitting_the_signer_certificate_is_refused_as_malformed() {
    let m = material();
    refused_der(
        PREFIX,
        "signer-omitted",
        &m.verifier,
        &m.pki.sign_receipt_with_bag(&payload_now(), &padding(20, 0)),
        &[Reason::Malformed],
    );
}

/// Mirrors `crossSignedMeshWithNoPathToTheAnchorIsRefusedFast`: three
/// layers of three equally valid issuers, the top one naming an issuer
/// that is not embedded (`TestPki.signReceiptWithCrossSignedMesh(3, 3)`).
#[test]
fn cross_signed_mesh_with_no_path_to_the_anchor_is_refused_fast() {
    let m = material();
    let (layers, branching) = (3, 3);
    let keys: Vec<Key> = (0..=layers).map(|_| Key::rsa()).collect();
    let mut bag = Vec::new();
    for layer in 1..=layers {
        let issuer = if layer == 1 {
            "Mesh Trust".to_owned()
        } else {
            format!("Mesh Layer {}", layer - 1)
        };
        for _ in 0..branching {
            bag.push(test_pki_cert(
                &format!("Mesh Layer {layer}"),
                &keys[layer],
                &issuer,
                &keys[layer - 1],
                true,
                None,
                m.pki.not_before,
                m.pki.not_after,
            ));
        }
    }
    let leaf_key = Key::rsa();
    let leaf = test_pki_cert(
        "Mesh Receipt Signing",
        &leaf_key,
        &format!("Mesh Layer {layers}"),
        &keys[layers],
        false,
        Some(SIGNING_LEAF_OID),
        m.pki.not_before,
        m.pki.not_after,
    );
    bag.insert(0, leaf.clone());
    let receipt = pki::sign_receipt_as(
        &payload_now(),
        pki::now_ms(),
        &leaf_key,
        pki::Hash::Sha256,
        &[&leaf],
        &bag,
    );
    refused_der(
        PREFIX,
        "cross-signed-mesh-27-combos",
        &m.verifier,
        &receipt,
        &[Reason::UntrustedChain],
    );
}

/// Mirrors `chainDeeperThanTheBuildersBoundIsRefusedFast`: a path of nine
/// below the anchor whose last CA is self-issued, no key identifiers.
///
/// The verdict agrees and the reason differs. Java refuses it at its
/// builder's bound; the core has no length bound (DECISIONS.md R20, the
/// "eight to ten certificates below a pinned root" row) and refuses it
/// because OpenSSL's issuer lookup cannot tell the self-issued CA from
/// its same-named issuer (R20, the "self-issued" row).
#[test]
fn chain_deeper_than_the_builders_bound_is_refused_fast() {
    let m = material();
    assert_eq!(m.deep_pki.chain.len(), 10);
    refused_der(
        PREFIX,
        "chain-9-deep",
        &m.deep_verifier,
        &m.deep_pki.sign_receipt(&payload_now()),
        &[Reason::UntrustedChain],
    );
}

/// Mirrors `signerInfoCountOverTheCapIsRefusedAsMalformed`: five
/// SignerInfos, each from its own PKI (fifteen embedded certificates).
#[test]
fn signer_info_count_over_the_cap_is_refused_as_malformed() {
    let five: Vec<Pki> = (0..5).map(|_| Pki::receipt()).collect();
    let refs: Vec<&Pki> = five.iter().collect();
    refused_der(
        PREFIX,
        "five-signer-infos",
        &material().verifier,
        &pki::sign_receipt_by_each(&payload_now(), &refs),
        &[Reason::Malformed],
    );
}

/// Mirrors `twinCertCloningTheSignersIdentityIsRejected`: an attacker key
/// whose certificate clones the leaf's issuer, serial and subject,
/// embedded first, signs the receipt.
#[test]
fn twin_cert_cloning_the_signers_identity_is_rejected() {
    let m = material();
    let rogue = Key::rsa();
    let twin = twin_of_leaf(&m.pki, &rogue);
    let bag = vec![
        twin.clone(),
        m.pki.leaf.clone(),
        m.pki.intermediate.clone(),
        m.pki.root.clone(),
    ];
    let receipt = pki::sign_receipt_as(
        &payload_now(),
        pki::now_ms(),
        &rogue,
        pki::Hash::Sha256,
        &[&twin],
        &bag,
    );
    refused_der(
        PREFIX,
        "twin-cert-identity-clone",
        &m.verifier,
        &receipt,
        &[Reason::UntrustedChain],
    );
}

/// Mirrors `twinIntheBagDoesNotBreakAGenuineSignature`: the genuine leaf
/// signs, an attacker's twin of it sits ahead of it in the bag.
#[test]
fn twin_in_the_bag_does_not_break_a_genuine_signature() {
    let m = material();
    let twin = twin_of_leaf(&m.pki, &Key::rsa());
    let mut bag = vec![twin];
    bag.extend(m.pki.chain.iter().cloned());
    let receipt = m.pki.sign_receipt_with_bag(&payload_now(), &bag);
    pki::verifies_der(PREFIX, "twin-ahead control", &m.verifier, &receipt);
}

/// Mirrors `validlySignedReceiptFromAnotherRootIsRefusedAsUntrusted`.
#[test]
fn validly_signed_receipt_from_another_root_is_refused_as_untrusted() {
    let m = material();
    refused_der(
        PREFIX,
        "wrong-root-pki",
        &m.verifier,
        &m.other_pki.sign_receipt(&payload_now()),
        &[Reason::UntrustedChain],
    );
}

/// Mirrors `randomInputNeverThrowsNeverVerifiesAndIsNeverInternalError`:
/// 300 random inputs up to 100,000 bytes, every tenth as Latin-1 text and
/// the rest base64.
#[test]
fn random_input_never_panics_never_verifies_and_is_never_internal_error() {
    let verifier = &material().verifier;
    let mut worst = Duration::ZERO;
    for i in 0..300 {
        let bytes = random_bytes(random_below(100_000));
        let receipt = if i % 10 == 0 {
            latin1(&bytes)
        } else {
            b64(&bytes)
        };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            timed(|| verifier.verify_receipt(&receipt))
        }));
        let (result, cost) = outcome.unwrap_or_else(|_| panic!("random input {i} panicked"));
        worst = worst.max(cost);
        let failure = result
            .err()
            .unwrap_or_else(|| panic!("random input {i} verified"));
        assert_ne!(failure.reason(), Reason::InternalError, "random input {i}");
    }
    eprintln!("{PREFIX} 300 random inputs: worst {} ms", worst.as_millis());
    assert!(worst < BUDGET, "a random input took {worst:?}");
}

/// Mirrors `bitFlippedGenuineReceiptsNeverVerifyADifferentPayload`: 300
/// single-bit flips (seed 20261015). A flip that verifies landed in bytes
/// no signature covers and must return the genuine payload unchanged.
#[test]
fn bit_flipped_genuine_receipts_never_verify_a_different_payload() {
    let m = material();
    let der = common::decode_base64(&m.genuine);
    let genuine: ReceiptPayload = m.verifier.verify_receipt(&m.genuine).unwrap();
    let mut rng = Rng::new(20_261_015);
    let (mut worst, mut tolerated) = (Duration::ZERO, 0);
    for i in 0..300 {
        let mut mutated = der.clone();
        let index = rng.below(mutated.len());
        mutated[index] ^= 1 << rng.below(8);
        let encoded = b64(&mutated);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            timed(|| m.verifier.verify_receipt(&encoded))
        }));
        let (result, cost) =
            outcome.unwrap_or_else(|_| panic!("flip {i} at byte {index} panicked"));
        worst = worst.max(cost);
        match result {
            Ok(payload) => {
                tolerated += 1;
                assert_eq!(
                    payload, genuine,
                    "a flip at byte {index} verified a different payload ({i})"
                );
            }
            Err(failure) => assert_ne!(failure.reason(), Reason::InternalError, "flip {i}"),
        }
    }
    eprintln!(
        "{PREFIX} 300 bit flips: {tolerated} tolerated (all with the genuine payload) of {} bytes, worst {} ms",
        der.len(),
        worst.as_millis()
    );
    assert!(worst < BUDGET, "a bit-flipped receipt took {worst:?}");
}

/// Mirrors `endpointNeverAnswersTheAlertStatusOnHostileRequests`: 200
/// random `receipt-data` values, none answered 21009.
#[test]
fn endpoint_never_answers_the_alert_status_on_hostile_requests() {
    let verifier = &material().verifier;
    let mut worst = Duration::ZERO;
    for i in 0..200 {
        let bytes = random_bytes(random_below(50_000));
        let receipt = if i % 10 == 0 {
            latin1(&bytes)
        } else {
            b64(&bytes)
        };
        // Concatenated as Java does, so a Latin-1 value may break the JSON.
        let body = format!("{{\"receipt-data\":\"{receipt}\"}}");
        let (answer, cost) =
            timed(|| verifier.verify_receipt_endpoint(Environment::Production, &body));
        let status = pki::status_of(&answer);
        worst = worst.max(cost);
        assert_ne!(
            status, 21009,
            "the endpoint answered the alert status 21009 on hostile input {i}"
        );
    }
    eprintln!(
        "{PREFIX} 200 hostile endpoint calls: worst {} ms",
        worst.as_millis()
    );
    assert!(worst < BUDGET, "a hostile endpoint call took {worst:?}");
}
