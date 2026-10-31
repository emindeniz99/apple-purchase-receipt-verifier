//! The same attacks, aimed at Apple's own: case by case from Java's
//! `WorstCaseRealAppleRootsTest`. The classes that target the roots and
//! the walk run against the bundled Apple roots (`Config::default()`),
//! with the genuine Apple-signed sandbox receipts under
//! `fixtures/public-receipts/` as the substrate, and the verdicts are
//! read off the `verifyReceipt`-compatible endpoint as well.
//!
//! What the core cannot refuse, and does not try to: a genuine
//! Apple-signed receipt of another app. It is app-agnostic by design;
//! the bundle id is the caller's to compare.

mod common;

use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{AppleStatus, Config, Environment, Reason, Verifier};
use common::pki::{
    self, bc_signed, cert_fields, g5_der, index_of, payload_at, payload_now, rsa_label, Attrs,
    CertSpec, Hash, Key, SignedDataParts, SHA256_WITH_RSA, SIGNING_LEAF_OID, TRUE, WWDR_OID,
};
use openssl::x509::X509;
use std::sync::OnceLock;

const PREFIX: &str = "real";

struct Material {
    verifier: Verifier,
    genuine: SignedDataParts,
    genuine_signer: Vec<u8>,
    genuine_wwdr: Vec<u8>,
    roots: Vec<Vec<u8>>,
    attacker_key: Key,
    stranger_root: Vec<u8>,
    lookalike_wwdr: Vec<u8>,
    stranger_leaf: Vec<u8>,
    stranger_leaf_key: Key,
}

/// Java's `@BeforeAll`: the pins prod uses, the genuine G5 receipt with
/// its signer and WWDR, the real roots, and an attacker's PKI: a stranger
/// root, a WWDR lookalike carrying Apple's exact WWDR name vouched by it,
/// a leaf under the lookalike, and one attacker key.
fn material() -> &'static Material {
    static MATERIAL: OnceLock<Material> = OnceLock::new();
    MATERIAL.get_or_init(|| {
        let verifier = Verifier::new(Config::default());
        let genuine = SignedDataParts::parse(&g5_der());
        let signer_identity = common::cms::parse_cms(&g5_der()).unwrap().signer_infos[0].clone();
        let genuine_signer = genuine
            .certificates
            .iter()
            .find(|c| {
                let f = cert_fields(c);
                f.issuer == signer_identity.issuer_raw
                    && f.serial == signer_identity.serial_contents
            })
            .expect("the genuine signer is embedded")
            .clone();
        let roots: Vec<Vec<u8>> = Config::default()
            .roots()
            .iter()
            .map(|r| r.der().to_vec())
            .collect();
        let genuine_wwdr = genuine
            .certificates
            .iter()
            .find(|c| {
                let f = cert_fields(c);
                roots.iter().any(|r| {
                    let root = cert_fields(r);
                    f.issuer == root.subject && f.subject != root.subject
                })
            })
            .expect("the genuine chain reaches no pinned root")
            .clone();

        let (root_key, wwdr_key, leaf_key, attacker_key) =
            (Key::rsa(), Key::rsa(), Key::rsa(), Key::rsa());
        let stranger_name = pki::name("Stranger Root that is not Apple");
        let wwdr_name = cert_fields(&genuine_wwdr).subject;
        let stranger_root = CertSpec::suite(
            stranger_name.clone(),
            root_key.spki(),
            stranger_name.clone(),
            true,
            None,
        )
        .sign(&root_key);
        let lookalike_wwdr = CertSpec::suite(
            wwdr_name.clone(),
            wwdr_key.spki(),
            stranger_name,
            true,
            Some(WWDR_OID),
        )
        .sign(&root_key);
        let stranger_leaf = CertSpec::suite(
            pki::name("Stranger Receipt Signer"),
            leaf_key.spki(),
            wwdr_name,
            false,
            Some(SIGNING_LEAF_OID),
        )
        .sign(&wwdr_key);
        Material {
            verifier,
            genuine,
            genuine_signer,
            genuine_wwdr,
            roots,
            attacker_key,
            stranger_root,
            lookalike_wwdr,
            stranger_leaf,
            stranger_leaf_key: leaf_key,
        }
    })
}

fn public_receipt(name: &str) -> Vec<u8> {
    common::read_base64_fixture(&format!("public-receipts/{name}.b64"))
}

fn refused(what: &str, der: &[u8], expected: &[Reason]) {
    pki::refused_der(PREFIX, what, &material().verifier, der, expected);
}

fn verifies(what: &str, der: &[u8]) -> apple_purchase_receipt_verifier::ReceiptPayload {
    pki::verifies_der(PREFIX, what, &material().verifier, der)
}

fn status(environment: Environment, der: &[u8]) -> i64 {
    pki::endpoint_status(&material().verifier, environment, &base64_encode(der))
}

/// The suite's `sign`: a direct signature, the form Apple's receipts
/// carry, by `key` under any signer certificate, with any bag.
fn sign(content: &[u8], key: &Key, signer_cert: &[u8], chain: &[Vec<u8>]) -> Vec<u8> {
    bc_signed(
        content,
        true,
        Hash::Sha256,
        &key.label(Hash::Sha256),
        &|data| key.sign(Hash::Sha256, data),
        signer_cert,
        chain,
        Attrs::Direct,
        &[],
    )
}

/// The suite's `garbageSigned`: Apple's issuer name, the marker, and
/// garbage where the issuer's signature would be.
fn garbage_signed(subject: &str, spki: Vec<u8>, issuer: Vec<u8>, marker: &str) -> Vec<u8> {
    let mut spec = CertSpec::new(pki::name(subject), issuer, spki);
    spec.extensions.push(pki::marker(marker, TRUE));
    spec.garbage(&rsa_label(SHA256_WITH_RSA))
}

/// The genuine G5 receipt with `bag` as its certificates
/// (`CMSSignedData.replaceCertificatesAndCRLs`).
fn with_bag(bag: Vec<Vec<u8>>) -> Vec<u8> {
    let genuine = &material().genuine;
    SignedDataParts {
        digest_algorithms: genuine.digest_algorithms.clone(),
        encap: genuine.encap.clone(),
        certificates: bag,
        signer_infos: genuine.signer_infos.clone(),
    }
    .build()
}

// --- the baseline -----------------------------------------------------------------

/// Mirrors `genuineAppStoreReceiptsVerifyAgainstThePinsProdUsesAndMapToApplesEndpointStatuses`.
#[test]
fn genuine_app_store_receipts_verify_against_the_pins_prod_uses_and_map_to_apples_endpoint_statuses(
) {
    for name in ["receipt-sandbox-g5", "receipt-sandbox-legacy"] {
        let der = public_receipt(name);
        verifies(name, &der);
        assert_eq!(
            status(Environment::Sandbox, &der),
            i64::from(AppleStatus::OK),
            "{name} on sandbox"
        );
        assert_eq!(
            status(Environment::Production, &der),
            i64::from(AppleStatus::SANDBOX_RECEIPT_ON_PRODUCTION),
            "{name} on production"
        );
    }
}

/// Mirrors `applesOwnXcodeSigningChainDoesNotReachThePinsAndIsRefused`.
#[test]
fn apples_own_xcode_signing_chain_does_not_reach_the_pins_and_is_refused() {
    let der = public_receipt("receipt-xcode-with-purchases");
    refused(
        "Apple's own Xcode signing chain",
        &der,
        &[Reason::UntrustedChain],
    );
    assert_eq!(
        status(Environment::Sandbox, &der),
        i64::from(AppleStatus::RECEIPT_NOT_AUTHENTICATED)
    );
    assert_eq!(
        status(Environment::Production, &der),
        i64::from(AppleStatus::RECEIPT_NOT_AUTHENTICATED)
    );
}

/// Mirrors `theBleichenbacherCubeRootForgeryHasNoTargetAmongApplesRealPins`:
/// every RSA root uses the exponent 65537 and one pin is EC.
#[test]
fn the_bleichenbacher_cube_root_forgery_has_no_target_among_apples_real_pins() {
    let (mut saw_rsa, mut saw_ec) = (false, false);
    for root in &material().roots {
        let key = X509::from_der(root).unwrap().public_key().unwrap();
        if let Ok(rsa) = key.rsa() {
            saw_rsa = true;
            assert_eq!(
                rsa.e().to_vec(),
                vec![0x01, 0x00, 0x01],
                "an RSA root with an unexpected exponent"
            );
        } else {
            assert!(key.ec_key().is_ok(), "a root that is neither RSA nor EC");
            saw_ec = true;
        }
    }
    assert!(saw_rsa, "expected at least one RSA root among the pins");
    assert!(saw_ec, "expected the EC root among the pins");
}

// --- Apple's own certificates, an attacker's signature ---------------------------

/// Mirrors `anAttackersSignatureUnderApplesGenuineSignerCertificateIsAnInvalidSignature`:
/// the genuine signer certificate, WWDR and root, an honest payload
/// created inside the real leaf's window, and the attacker's signature.
#[test]
fn an_attackers_signature_under_apples_genuine_signer_certificate_is_an_invalid_signature() {
    let m = material();
    let transplant = sign(
        &payload_at("2025-06-01T00:00:00Z"),
        &m.attacker_key,
        &m.genuine_signer,
        &m.genuine.certificates,
    );
    refused(
        "the genuine signer certificate over an attacker's key",
        &transplant,
        &[Reason::InvalidSignature],
    );
    assert_eq!(
        status(Environment::Sandbox, &transplant),
        i64::from(AppleStatus::RECEIPT_NOT_AUTHENTICATED)
    );
}

/// Mirrors `aLeafForgedUnderApplesRealWwdrIsUntrusted`: a leaf claiming
/// Apple's WWDR issued it, marker and all, garbage for a signature.
#[test]
fn a_leaf_forged_under_apples_real_wwdr_is_untrusted() {
    let m = material();
    let forged = garbage_signed(
        "Leaf Apple never issued",
        m.attacker_key.spki(),
        cert_fields(&m.genuine_wwdr).subject,
        SIGNING_LEAF_OID,
    );
    let mut bag = vec![forged.clone()];
    bag.extend(m.genuine.certificates.iter().cloned());
    let receipt = sign(&payload_now(), &m.attacker_key, &forged, &bag);
    refused(
        "a leaf forged under Apple's real WWDR",
        &receipt,
        &[Reason::UntrustedChain],
    );
    assert_eq!(
        status(Environment::Sandbox, &receipt),
        i64::from(AppleStatus::RECEIPT_NOT_AUTHENTICATED)
    );
}

/// Mirrors `squattersUnderApplesRealRootDnsAreRefusedByEveryRoot`: for
/// each pinned root, a signer certificate claiming it issued it.
#[test]
fn squatters_under_apples_real_root_dns_are_refused_by_every_root() {
    let m = material();
    for root in &m.roots {
        let subject = cert_fields(root).subject;
        let squatter = garbage_signed(
            "Receipt signer Apple never vouched",
            m.attacker_key.spki(),
            subject,
            SIGNING_LEAF_OID,
        );
        let receipt = sign(
            &payload_now(),
            &m.attacker_key,
            &squatter,
            &[squatter.clone(), root.clone()],
        );
        refused(
            "a squatter under a pinned root",
            &receipt,
            &[Reason::UntrustedChain, Reason::InvalidCertificate],
        );
        assert_eq!(
            status(Environment::Sandbox, &receipt),
            i64::from(AppleStatus::RECEIPT_NOT_AUTHENTICATED)
        );
    }
}

// --- a stranger CA trying to become an anchor through Apple's names ----------------

/// Mirrors `aWwdrLookalikeVouchedByAStrangerRootIsNotAnAnchorAndIsInertJunk`.
#[test]
fn a_wwdr_lookalike_vouched_by_a_stranger_root_is_not_an_anchor_and_is_inert_junk() {
    let m = material();
    let receipt = sign(
        &payload_now(),
        &m.stranger_leaf_key,
        &m.stranger_leaf,
        &[
            m.stranger_leaf.clone(),
            m.lookalike_wwdr.clone(),
            m.stranger_root.clone(),
        ],
    );
    refused(
        "a WWDR lookalike vouched by a stranger root",
        &receipt,
        &[Reason::UntrustedChain],
    );
    assert_eq!(
        status(Environment::Sandbox, &receipt),
        i64::from(AppleStatus::RECEIPT_NOT_AUTHENTICATED)
    );

    let mut bag = m.genuine.certificates.clone();
    bag.push(m.lookalike_wwdr.clone());
    bag.push(m.stranger_root.clone());
    let polluted = with_bag(bag);
    verifies("a genuine receipt with the lookalike in the bag", &polluted);
    assert_eq!(
        status(Environment::Sandbox, &polluted),
        i64::from(AppleStatus::OK)
    );
}

/// Mirrors `appleRootsThemselvesAsBagJunkAreInert`.
#[test]
fn apple_roots_themselves_as_bag_junk_are_inert() {
    let m = material();
    let mut bag = m.genuine.certificates.clone();
    bag.extend(m.roots.iter().cloned());
    let polluted = with_bag(bag);
    verifies(
        "a genuine receipt with all three real roots in the bag",
        &polluted,
    );
    assert_eq!(
        status(Environment::Sandbox, &polluted),
        i64::from(AppleStatus::OK)
    );
}

// --- the genuine substrate, re-aimed at the endpoint --------------------------------

/// Mirrors `oneTamperedByteInAGenuineReceiptIs21003AtTheEndpoint`.
#[test]
fn one_tampered_byte_in_a_genuine_receipt_is_21003_at_the_endpoint() {
    let mut der = g5_der();
    let bundle_id = b"dev.bonzer.weeka.app";
    let at = index_of(&der, bundle_id).expect("bundle id not found in the receipt");
    der[at + bundle_id.len() - 1] ^= 0x01;
    refused(
        "one byte of a genuine receipt changed",
        &der,
        &[Reason::InvalidSignature],
    );
    assert_eq!(
        status(Environment::Sandbox, &der),
        i64::from(AppleStatus::RECEIPT_NOT_AUTHENTICATED)
    );
}

/// Mirrors `aCertificateFloodOnAGenuineReceiptIs21002AtTheEndpoint`.
#[test]
fn a_certificate_flood_on_a_genuine_receipt_is_21002_at_the_endpoint() {
    let m = material();
    let mut flood = Vec::new();
    while flood.len() < 64 {
        flood.extend(m.genuine.certificates.iter().cloned());
    }
    let flooded = with_bag(flood);
    refused(
        "64 certificates in a genuine receipt's bag",
        &flooded,
        &[Reason::Malformed],
    );
    assert_eq!(
        status(Environment::Sandbox, &flooded),
        i64::from(AppleStatus::MALFORMED_RECEIPT_DATA)
    );
}

// --- the honest boundary --------------------------------------------------------------

/// Mirrors `aGenuineReceiptOfAnotherAppVerifiesAndTheWrapperOwnsTheRefusal`.
#[test]
fn a_genuine_receipt_of_another_app_verifies_and_the_wrapper_owns_the_refusal() {
    let der = g5_der();
    let payload = verifies("a genuine receipt of another app", &der);
    assert_eq!(payload.bundle_id.as_deref(), Some("dev.bonzer.weeka.app"));
    assert_ne!(payload.bundle_id.as_deref(), Some("com.example.app"));
    assert_eq!(
        status(Environment::Sandbox, &der),
        i64::from(AppleStatus::OK)
    );
}
