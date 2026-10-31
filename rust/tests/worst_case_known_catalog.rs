//! The known-attack catalog, case by case from Java's
//! `WorstCaseKnownCatalogTest`: classic CMS and X.509 attacks, old
//! (exponent forgeries, weak digests, weak keys, RFC 5280 issuance rules)
//! and recent (certificate transplants, key-issuance abuse, nested and
//! detached signatures), ending in a chain forged with nothing but
//! crafted PKCS#1 blocks, no private key anywhere.

mod common;

use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{AppleStatus, Environment, Reason, TrustAnchor, Verifier};
use common::pki::{
    self, basic_constraints, bc_sign, bc_signed, extension, key_usage, marker, name, now_rfc3339,
    payload_now, random_rsa_spki, receipt_payload, rsa_label, rsa_spki_with_parameters, timed,
    Attrs, CertSpec, Hash, Key, Pki, BUDGET, E65537, KEY_USAGE_DIGITAL_SIGNATURE,
    KEY_USAGE_KEY_ENCIPHERMENT, MD5_WITH_RSA, SHA256_WITH_RSA, SIGNING_LEAF_OID, TRUE, WWDR_OID,
};
use common::{der_oid, der_set};
use openssl::bn::BigNum;
use std::sync::OnceLock;

const PREFIX: &str = "catalog";
const ROOT: &str = "Catalog Fake Apple Root CA";
const INTER: &str = "Catalog Fake Apple WWDR CA";
const LEAF: &str = "Catalog Fake Receipt Signer";

struct Material {
    root_key: Key,
    inter_key: Key,
    leaf_key: Key,
    root: Vec<u8>,
    inter: Vec<u8>,
    leaf: Vec<u8>,
    verifier: Verifier,
    test_pki: Pki,
    test_pki_verifier: Verifier,
}

/// Java's `@BeforeAll`: an Apple-shaped RSA PKI pinned alone, and a
/// `TestPki` with its own verifier.
fn material() -> &'static Material {
    static MATERIAL: OnceLock<Material> = OnceLock::new();
    MATERIAL.get_or_init(|| {
        let (root_key, inter_key, leaf_key) = (Key::rsa(), Key::rsa(), Key::rsa());
        let root = cert(ROOT, &root_key, ROOT, &root_key, true, None, None, None);
        let inter = cert(
            INTER,
            &inter_key,
            ROOT,
            &root_key,
            true,
            Some(WWDR_OID),
            None,
            None,
        );
        let leaf = cert(
            LEAF,
            &leaf_key,
            INTER,
            &inter_key,
            false,
            Some(SIGNING_LEAF_OID),
            None,
            None,
        );
        let verifier = common::verifier([TrustAnchor::from_der(&root).unwrap()]);
        let test_pki = Pki::receipt();
        let test_pki_verifier = test_pki.verifier();
        Material {
            root_key,
            inter_key,
            leaf_key,
            root,
            inter,
            leaf,
            verifier,
            test_pki,
            test_pki_verifier,
        }
    })
}

/// The suite's `cert`, with the knobs the plain builder leaves out: a
/// keyUsage and a path length.
#[allow(clippy::too_many_arguments)]
fn cert(
    subject: &str,
    key: &Key,
    issuer: &str,
    issuer_key: &Key,
    ca: bool,
    marker_oid: Option<&str>,
    usage: Option<&[u8]>,
    path_len: Option<u64>,
) -> Vec<u8> {
    let mut spec = CertSpec::new(name(subject), name(issuer), key.spki());
    if ca {
        spec.extensions.push(basic_constraints(true, path_len));
    }
    if let Some(oid) = marker_oid {
        spec.extensions.push(marker(oid, TRUE));
    }
    if let Some(bits) = usage {
        spec.extensions.push(key_usage(bits));
    }
    spec.sign(issuer_key)
}

/// The suite's `craftedSubjectCert`: a hand-made SPKI, signed the normal way.
fn crafted(
    subject: &str,
    spki: Vec<u8>,
    issuer: &str,
    issuer_key: &Key,
    ca: bool,
    marker_oid: Option<&str>,
) -> Vec<u8> {
    CertSpec::suite(name(subject), spki, name(issuer), ca, marker_oid).sign(issuer_key)
}

fn sha256_rsa() -> Vec<u8> {
    rsa_label(SHA256_WITH_RSA)
}

fn refused(what: &str, der: &[u8], expected: &[Reason]) {
    pki::refused_der(PREFIX, what, &material().verifier, der, expected);
}

fn verifies(what: &str, der: &[u8]) {
    pki::verifies_der(PREFIX, what, &material().verifier, der);
}

fn printed(what: &str, der: &[u8]) {
    let _ = pki::printed(PREFIX, what, &material().verifier, der);
}

fn chain(certs: &[&Vec<u8>]) -> Vec<Vec<u8>> {
    certs.iter().map(|c| (*c).clone()).collect()
}

/// The genuine leaf signs `content`, SHA256withRSA, with `bag`.
fn genuine(content: &[u8], signer: &[u8], bag: &[&Vec<u8>]) -> Vec<u8> {
    bc_sign(
        content,
        &material().leaf_key,
        Hash::Sha256,
        signer,
        &chain(bag),
    )
}

// Java's `exponentOneCraftedChainCannotForgeAnything` has no port here.
// Java refuses that chain only when BouncyCastle rejects the random
// modulus for a small factor, so it passes by luck; the core verifies it
// on a random modulus and on a product of two primes alike. Whether an
// RSA exponent below 3 is refused is the owner's decision.

/// Mirrors `weakDigestLabelsAreAcceptedOnlyUnderAPinnedRoot`: the pinned
/// PKI signing with MD5, SHA-1, SHA-384 and SHA-512 verifies; a
/// stranger's certificate claiming the MD5 label does not, and is inert
/// as junk.
#[test]
fn weak_digest_labels_are_accepted_only_under_a_pinned_root() {
    let m = material();
    for hash in [Hash::Md5, Hash::Sha1, Hash::Sha384, Hash::Sha512] {
        let receipt = bc_sign(
            &payload_now(),
            &m.leaf_key,
            hash,
            &m.leaf,
            &chain(&[&m.leaf, &m.inter, &m.root]),
        );
        verifies(&format!("{hash:?}withRSA-signed genuine receipt"), &receipt);
    }
    let md5_leaf = CertSpec::suite(
        name("MD5 Labeled Signer"),
        random_rsa_spki(2048, E65537),
        name(INTER),
        false,
        Some(SIGNING_LEAF_OID),
    )
    .garbage(&rsa_label(MD5_WITH_RSA));
    refused(
        "md5-labeled stranger as signer",
        &genuine(
            &payload_now(),
            &md5_leaf,
            &[&m.leaf, &m.inter, &m.root, &md5_leaf],
        ),
        &[Reason::UntrustedChain],
    );
    verifies(
        "md5-labeled stranger as bag junk",
        &genuine(
            &payload_now(),
            &m.leaf,
            &[&m.leaf, &m.inter, &m.root, &md5_leaf],
        ),
    );
}

/// Mirrors `hugePublicExponentsCostIsBoundedEvenVouched`: a vouched CA
/// with a 20,001-bit exponent, and a garbage-signed certificate naming
/// it as issuer, beside a genuine receipt.
#[test]
fn huge_public_exponents_cost_is_bounded_even_vouched() {
    let m = material();
    let mut huge_e = BigNum::new().unwrap();
    huge_e
        .lshift(&BigNum::from_u32(1).unwrap(), 20_001)
        .unwrap();
    huge_e.add_word(1).unwrap();
    let huge_e_ca = crafted(
        "Huge Exponent CA",
        random_rsa_spki(2048, &huge_e.to_vec()),
        INTER,
        &m.inter_key,
        true,
        Some(WWDR_OID),
    );
    let namee = CertSpec::new(
        name("Huge Exponent Namee"),
        name("Huge Exponent CA"),
        random_rsa_spki(2048, E65537),
    )
    .garbage(&sha256_rsa());
    verifies(
        "20001-bit-exponent vouched CA",
        &genuine(
            &payload_now(),
            &m.leaf,
            &[&m.leaf, &m.inter, &m.root, &huge_e_ca, &namee],
        ),
    );
}

/// Mirrors `weakModulusKeysAreHandledSafely`: a 512-bit stranger as the
/// signer is refused; a vouched 512-bit CA with a certificate naming it
/// prints its verdict, inside the budget.
#[test]
fn weak_modulus_keys_are_handled_safely() {
    let m = material();
    let small_key = random_rsa_spki(512, E65537);
    let small_signer = CertSpec::suite(
        name("512-bit Signer"),
        small_key.clone(),
        name(INTER),
        false,
        Some(SIGNING_LEAF_OID),
    )
    .garbage(&sha256_rsa());
    refused(
        "512-bit stranger as signer",
        &genuine(
            &payload_now(),
            &small_signer,
            &[&m.leaf, &m.inter, &m.root, &small_signer],
        ),
        &[Reason::UntrustedChain],
    );
    let small_ca = crafted(
        "512-bit CA",
        small_key,
        INTER,
        &m.inter_key,
        true,
        Some(WWDR_OID),
    );
    let small_namee = CertSpec::new(
        name("512-bit Namee"),
        name("512-bit CA"),
        random_rsa_spki(2048, E65537),
    )
    .garbage(&sha256_rsa());
    printed(
        "512-bit vouched CA",
        &genuine(
            &payload_now(),
            &m.leaf,
            &[&m.leaf, &m.inter, &m.root, &small_ca, &small_namee],
        ),
    );
}

/// Mirrors `nonRsaSignerKeysCannotVerifyRsaSignatures`: an EC certificate
/// genuinely issued by the pinned intermediate, named as the signer of a
/// receipt the RSA leaf key signed; and the same certificate as junk.
#[test]
fn non_rsa_signer_keys_cannot_verify_rsa_signatures() {
    let m = material();
    let ec_signer = cert(
        "Elliptic Signer",
        &Key::ec(),
        INTER,
        &m.inter_key,
        false,
        Some(SIGNING_LEAF_OID),
        None,
        None,
    );
    refused(
        "elliptic-curve signer",
        &genuine(&payload_now(), &ec_signer, &[&ec_signer, &m.inter, &m.root]),
        &[
            Reason::InvalidCertificate,
            Reason::UntrustedChain,
            Reason::InvalidSignature,
        ],
    );
    verifies(
        "elliptic-curve stranger as bag junk",
        &genuine(
            &payload_now(),
            &m.leaf,
            &[&m.leaf, &m.inter, &m.root, &ec_signer],
        ),
    );
}

// --- RFC 5280 issuance rules ------------------------------------------------------

/// The receipt `key` signs as `signer`, with `bag`.
fn signed_by(key: &Key, signer: &[u8], bag: &[&Vec<u8>]) -> Vec<u8> {
    bc_sign(&payload_now(), key, Hash::Sha256, signer, &chain(bag))
}

/// Mirrors `intermediateWithoutKeyCertSignCannotIssue`.
#[test]
fn intermediate_without_key_cert_sign_cannot_issue() {
    let m = material();
    let (inter_key, child_key) = (Key::rsa(), Key::rsa());
    let inter = cert(
        "WWDR No KeyCertSign",
        &inter_key,
        ROOT,
        &m.root_key,
        true,
        Some(WWDR_OID),
        Some(KEY_USAGE_DIGITAL_SIGNATURE),
        None,
    );
    let child = cert(
        "Signer Under No KeyCertSign",
        &child_key,
        "WWDR No KeyCertSign",
        &inter_key,
        false,
        Some(SIGNING_LEAF_OID),
        None,
        None,
    );
    refused(
        "intermediate lacking keyCertSign",
        &signed_by(&child_key, &child, &[&child, &inter, &m.root]),
        &[Reason::UntrustedChain, Reason::InvalidCertificate],
    );
}

/// Mirrors `pathLenConstraintZeroForbidsAnotherIntermediate`.
#[test]
fn path_len_constraint_zero_forbids_another_intermediate() {
    let m = material();
    let (inter0_key, inter2_key, leaf_key) = (Key::rsa(), Key::rsa(), Key::rsa());
    let inter0 = cert(
        "WWDR PathLen Zero",
        &inter0_key,
        ROOT,
        &m.root_key,
        true,
        Some(WWDR_OID),
        None,
        Some(0),
    );
    let inter2 = cert(
        "WWDR Deeper Intermediate",
        &inter2_key,
        "WWDR PathLen Zero",
        &inter0_key,
        true,
        Some(WWDR_OID),
        None,
        None,
    );
    let deep_leaf = cert(
        "Signer Beyond PathLen",
        &leaf_key,
        "WWDR Deeper Intermediate",
        &inter2_key,
        false,
        Some(SIGNING_LEAF_OID),
        None,
        None,
    );
    refused(
        "chain exceeding pathLen 0",
        &signed_by(
            &leaf_key,
            &deep_leaf,
            &[&deep_leaf, &inter2, &inter0, &m.root],
        ),
        &[Reason::UntrustedChain, Reason::InvalidCertificate],
    );
}

/// Mirrors `markerLeafCannotIssueCertificates`: the marker leaf (no
/// basicConstraints) "issues" a marker certificate with its own key.
#[test]
fn marker_leaf_cannot_issue_certificates() {
    let m = material();
    let child_key = Key::rsa();
    let child = cert(
        "Signer Issued By A Leaf",
        &child_key,
        LEAF,
        &m.leaf_key,
        false,
        Some(SIGNING_LEAF_OID),
        None,
        None,
    );
    refused(
        "certificate issued by a leaf",
        &signed_by(&child_key, &child, &[&child, &m.leaf, &m.inter, &m.root]),
        &[Reason::UntrustedChain],
    );
}

/// Mirrors `leafWithoutDigitalSignatureUsageIsPrintedNotAssumed`: a leaf
/// whose keyUsage is keyEncipherment alone prints its verdict.
#[test]
fn leaf_without_digital_signature_usage_is_printed_not_assumed() {
    let m = material();
    let enc_key = Key::rsa();
    let enc_leaf = cert(
        "KeyEncipherment Only Signer",
        &enc_key,
        INTER,
        &m.inter_key,
        false,
        Some(SIGNING_LEAF_OID),
        Some(KEY_USAGE_KEY_ENCIPHERMENT),
        None,
    );
    printed(
        "keyEncipherment-only leaf",
        &signed_by(&enc_key, &enc_leaf, &[&enc_leaf, &m.inter, &m.root]),
    );
}

/// Mirrors `unknownCriticalExtensionRefusesTheChain`: an intermediate
/// with an unrecognised critical extension; refused on the path, inert as
/// junk.
#[test]
fn unknown_critical_extension_refuses_the_chain() {
    let m = material();
    let (weird_key, child_key) = (Key::rsa(), Key::rsa());
    let weird = CertSpec::suite(
        name("WWDR Weird Critical"),
        weird_key.spki(),
        name(ROOT),
        true,
        Some(WWDR_OID),
    )
    .with(extension("1.2.3.4.99", true, TRUE))
    .sign(&m.root_key);
    let child = cert(
        "Signer Under Weird Critical",
        &child_key,
        "WWDR Weird Critical",
        &weird_key,
        false,
        Some(SIGNING_LEAF_OID),
        None,
        None,
    );
    refused(
        "chain through unknown critical extension",
        &signed_by(&child_key, &child, &[&child, &weird, &m.root]),
        &[Reason::UntrustedChain, Reason::InvalidCertificate],
    );
    verifies(
        "unknown-critical stranger as bag junk",
        &genuine(
            &payload_now(),
            &m.leaf,
            &[&m.leaf, &m.inter, &m.root, &weird],
        ),
    );
}

// --- CMS shape attacks ---------------------------------------------------------------

/// Mirrors `berEncodedCertificateInBagIsHandledSafely` (BERserk): a copy
/// of the intermediate re-encoded with an indefinite outer length rides
/// in the bag; either verdict, inside the budget.
///
/// BouncyCastle re-encodes a parsed DER certificate as definite-length
/// DER, so Java's copy is likely byte-identical to the original; this
/// one is genuinely BER, which is the attack the case names.
#[test]
fn ber_encoded_certificate_in_bag_is_handled_safely() {
    let m = material();
    let contents = common::ber::parse_exact(&m.inter)
        .unwrap()
        .contents
        .to_vec();
    let mut ber_inter = vec![0x30, 0x80];
    ber_inter.extend_from_slice(&contents);
    ber_inter.extend_from_slice(&[0x00, 0x00]);
    printed(
        "ber-reencoded bag certificate",
        &genuine(
            &payload_now(),
            &m.leaf,
            &[&m.leaf, &m.inter, &m.root, &ber_inter],
        ),
    );
}

/// Mirrors `detachedSignatureWithoutContentIsRefused`.
#[test]
fn detached_signature_without_content_is_refused() {
    let m = material();
    let detached = bc_signed(
        &payload_now(),
        false,
        Hash::Sha256,
        &sha256_rsa(),
        &|data| m.leaf_key.sign(Hash::Sha256, data),
        &m.leaf,
        &chain(&[&m.leaf, &m.inter, &m.root]),
        Attrs::Standard,
        &[],
    );
    refused(
        "detached signature with no content",
        &detached,
        &[
            Reason::Malformed,
            Reason::InvalidSignature,
            Reason::UnreadablePayload,
        ],
    );
}

/// Mirrors `nestedSignedDataIsRefused`: a genuine signature over another
/// SignedData instead of a receipt payload; the endpoint answers 21009.
#[test]
fn nested_signed_data_is_refused() {
    let m = material();
    let inner = genuine(&payload_now(), &m.leaf, &[&m.leaf, &m.inter, &m.root]);
    let nested = genuine(&inner, &m.leaf, &[&m.leaf, &m.inter, &m.root]);
    refused("nested signed data", &nested, &[Reason::UnreadablePayload]);
    assert_eq!(
        pki::endpoint_status(&m.verifier, Environment::Sandbox, &base64_encode(&nested)),
        i64::from(AppleStatus::INTERNAL_DATA_ACCESS_ERROR)
    );
}

/// Mirrors `genuineSignerCertTransplantedOntoAnAttackersKey`.
#[test]
fn genuine_signer_cert_transplanted_onto_an_attackers_key() {
    let m = material();
    refused(
        "genuine signer cert on a stranger key",
        &signed_by(&Key::rsa(), &m.leaf, &[&m.leaf, &m.inter, &m.root]),
        &[Reason::InvalidSignature],
    );
}

/// Mirrors `undecodableInAppPurchaseAnswersApples21009`: a genuinely
/// signed receipt whose in-app purchase is `30 03 17 01 FF`. The receipt
/// verifies with the purchase kept raw under attribute 17 and an empty
/// `in_app`, and the endpoint answers 21009 rather than 0.
#[test]
fn undecodable_in_app_purchase_answers_apples_21009() {
    let m = material();
    let now = now_rfc3339();
    let undecodable = receipt_payload(
        "com.example.app",
        "1.0",
        &[1, 2, 3, 4],
        &[5, 6, 7, 8],
        &now,
        &[vec![0x30, 0x03, 0x17, 0x01, 0xFF]],
    );
    let receipt = base64_encode(&m.test_pki.sign_receipt(&undecodable));
    let (result, cost) = timed(|| m.test_pki_verifier.verify_receipt(&receipt));
    pki::print_verdict(PREFIX, "undecodable in-app purchase", cost, &result);
    let payload = result.unwrap_or_else(|f| panic!("a lenient decode refused the receipt: {f}"));
    assert!(
        payload.in_app.is_empty(),
        "the undecodable purchase parsed anyway"
    );
    assert!(
        payload.unknown_attributes.contains_key(&17),
        "the undecodable purchase was not kept raw"
    );
    assert_eq!(
        pki::endpoint_status(&m.test_pki_verifier, Environment::Sandbox, &receipt),
        i64::from(AppleStatus::INTERNAL_DATA_ACCESS_ERROR)
    );
    assert!(cost < BUDGET, "took {cost:?}");
}

/// Mirrors `garbageAndEmptyCreationDatesAreHandledGracefully`: a garbage
/// date string is kept raw and the receipt judged at the clock; an empty
/// one reads as not set and is not kept raw. Both answer 0.
#[test]
fn garbage_and_empty_creation_dates_are_handled_gracefully() {
    let m = material();
    for date in ["not-a-date", ""] {
        let payload = receipt_payload(
            "com.example.app",
            "1.0",
            &[1, 2, 3, 4],
            &[5, 6, 7, 8],
            date,
            &[pki::in_app_purchase(
                1,
                "gems.small",
                "2001",
                "2001",
                date,
                None,
            )],
        );
        let receipt = base64_encode(&m.test_pki.sign_receipt(&payload));
        let (result, cost) = timed(|| m.test_pki_verifier.verify_receipt(&receipt));
        let payload =
            result.unwrap_or_else(|f| panic!("creation date {date:?} refused the receipt: {f}"));
        eprintln!(
            "{PREFIX} creation date {date:?}: {} ms, VERIFIED, unknown attribute types {:?}",
            cost.as_millis(),
            payload.unknown_attributes.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            payload.receipt_creation_date_ms, None,
            "{date:?} was read as a date"
        );
        if date.is_empty() {
            assert!(
                !payload.unknown_attributes.contains_key(&12),
                "an empty creation date was kept raw"
            );
            assert!(
                !payload.unknown_attributes.contains_key(&18),
                "an empty purchase date was kept raw"
            );
        }
        assert_eq!(
            pki::endpoint_status(&m.test_pki_verifier, Environment::Sandbox, &receipt),
            i64::from(AppleStatus::OK)
        );
        assert!(cost < BUDGET, "took {cost:?}");
    }
}

/// Mirrors `weirdSerialsAreHandledSafely`: a negative serial (-1) on a
/// garbage-signed stranger: refused as the signer, inert as junk.
#[test]
fn weird_serials_are_handled_safely() {
    let m = material();
    let mut spec = CertSpec::suite(
        name("Negative Serial Signer"),
        random_rsa_spki(2048, E65537),
        name(INTER),
        false,
        Some(SIGNING_LEAF_OID),
    );
    spec.serial = vec![0xFF];
    let negative = spec.garbage(&sha256_rsa());
    refused(
        "negative-serial stranger as signer",
        &genuine(
            &payload_now(),
            &negative,
            &[&m.leaf, &m.inter, &m.root, &negative],
        ),
        &[Reason::UntrustedChain],
    );
    verifies(
        "negative-serial stranger as bag junk",
        &genuine(
            &payload_now(),
            &m.leaf,
            &[&m.leaf, &m.inter, &m.root, &negative],
        ),
    );
}

/// Mirrors `spkiParametersHoldingSetsArePassedOver`: a stranger whose
/// rsaEncryption parameters are a SET holding an OID; as signer it is
/// refused, as junk it is passed over.
#[test]
fn spki_parameters_holding_sets_are_passed_over() {
    let m = material();
    let set_params = rsa_spki_with_parameters(
        &pki::random_modulus(2048),
        E65537,
        der_set(&[der_oid("1.2.3.4.5")]),
    );
    let signer = CertSpec::suite(
        name("Set Params Signer"),
        set_params,
        name(INTER),
        false,
        Some(SIGNING_LEAF_OID),
    )
    .garbage(&sha256_rsa());
    refused(
        "set-params stranger as signer",
        &genuine(
            &payload_now(),
            &signer,
            &[&m.leaf, &m.inter, &m.root, &signer],
        ),
        &[Reason::Malformed, Reason::UntrustedChain],
    );
    verifies(
        "set-params stranger as bag junk",
        &genuine(
            &payload_now(),
            &m.leaf,
            &[&m.leaf, &m.inter, &m.root, &signer],
        ),
    );
}
