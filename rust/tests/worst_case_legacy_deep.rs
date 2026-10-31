//! The deep red-team suite for the legacy receipt path (`verify_receipt`
//! and `verify_receipt_endpoint`), case by case from Java's
//! `WorstCaseLegacyDeepTest`. Beyond the smoke suite
//! (`worst_case_attack_surface.rs`) it mints attacks with an
//! attacker-grade PKI shaped like Apple's (root, WWDR-marked
//! intermediate, marker leaf), so the holder of every key can craft what
//! a name-only attacker cannot: mislabelled certificates that ARE validly
//! signed, a signer named as the pinned root, historical and future
//! validity windows, and label surgery on genuine receipts.

mod common;

use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{AppleStatus, Environment, Reason, TrustAnchor, Verifier};
use common::pki::{
    self, basic_constraints, count, extension, index_of, last_index_of, latin1, marker, name,
    now_ms, now_rfc3339, parse_rfc3339, payload_now, random_below, random_bytes, random_rsa_spki,
    receipt_payload_full, rsa_label, sign_receipt_as, sign_receipt_by_each, timed, CertSpec, Hash,
    Key, Pki, BUDGET, E65537, GENERIC_COMPOSITE, MD2_WITH_RSA, MGF1, RSASSA_PSS, SHA256,
    SHA256_WITH_RSA, SIGNING_LEAF_OID, TRUE, WWDR_OID,
};
use common::{der, der_int, der_oid, der_seq, tag};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::OnceLock;
use std::time::Duration;

const PREFIX: &str = "deep";
const ROOT: &str = "Deep Fake Apple Root CA";
const INTER: &str = "Deep Fake Apple WWDR CA";

struct Material {
    pki: Pki,
    pki_verifier: Verifier,
    pki_genuine: String,
    my_root: Vec<u8>,
    my_inter: Vec<u8>,
    my_leaf: Vec<u8>,
    my_root_key: Key,
    my_inter_key: Key,
    my_leaf_key: Key,
    my_verifier: Verifier,
    my_genuine: String,
    my_genuine_der: Vec<u8>,
}

/// Java's `@BeforeAll`: a `TestPki` with a genuine receipt, and the
/// attacker-grade PKI with its own.
fn material() -> &'static Material {
    static MATERIAL: OnceLock<Material> = OnceLock::new();
    MATERIAL.get_or_init(|| {
        let pki = Pki::receipt();
        let pki_verifier = pki.verifier();
        let pki_genuine = base64_encode(&pki.sign_receipt(&payload_now()));
        let (my_root_key, my_inter_key, my_leaf_key) = (Key::rsa(), Key::rsa(), Key::rsa());
        let my_root = cert(ROOT, &my_root_key, ROOT, &my_root_key, true, None);
        let my_inter = cert(
            INTER,
            &my_inter_key,
            ROOT,
            &my_root_key,
            true,
            Some(WWDR_OID),
        );
        let my_leaf = cert(
            "Deep Fake Receipt Signer",
            &my_leaf_key,
            INTER,
            &my_inter_key,
            false,
            Some(SIGNING_LEAF_OID),
        );
        let my_verifier = common::verifier([TrustAnchor::from_der(&my_root).unwrap()]);
        let my_genuine_der = sign_receipt_as(
            &payload_now(),
            now_ms(),
            &my_leaf_key,
            Hash::Sha256,
            &[&my_leaf],
            &[my_leaf.clone(), my_inter.clone(), my_root.clone()],
        );
        let my_genuine = base64_encode(&my_genuine_der);
        Material {
            pki,
            pki_verifier,
            pki_genuine,
            my_root,
            my_inter,
            my_leaf,
            my_root_key,
            my_inter_key,
            my_leaf_key,
            my_verifier,
            my_genuine,
            my_genuine_der,
        }
    })
}

/// The suite's `cert`: basicConstraints always (critical), the marker
/// valued BOOLEAN TRUE.
fn cert(
    subject: &str,
    key: &Key,
    issuer: &str,
    issuer_key: &Key,
    ca: bool,
    marker_oid: Option<&str>,
) -> Vec<u8> {
    let mut spec = CertSpec::new(name(subject), name(issuer), key.spki());
    spec.extensions.push(basic_constraints(ca, None));
    if let Some(oid) = marker_oid {
        spec.extensions.push(marker(oid, TRUE));
    }
    spec.sign(issuer_key)
}

/// The suite's `hostileCert`: any label, a garbage signature, an RSA key
/// of `bits` nobody holds, issued under the intermediate's name.
fn hostile_cert(subject: &str, label: &[u8], ca: bool, bits: i32) -> Vec<u8> {
    let mut spec = CertSpec::new(name(subject), name(INTER), random_rsa_spki(bits, E65537));
    if ca {
        spec.extensions.push(basic_constraints(true, None));
    }
    spec.garbage(label)
}

/// The suite's `mislabeledVouchedCert`: a CA validly signed by the WWDR
/// key with SHA256withRSA, carrying `label`.
fn mislabeled_vouched_cert(subject: &str, label: &[u8]) -> Vec<u8> {
    CertSpec::new(name(subject), name(INTER), random_rsa_spki(2048, E65537))
        .with(basic_constraints(true, None))
        .mislabeled(&material().my_inter_key, label)
}

fn sha256_null() -> Vec<u8> {
    der_seq(&[der_oid(SHA256), der(0x05, &[])])
}

/// RSASSA-PSS with a saltLength no RSA key can hold, in BouncyCastle's
/// untagged form.
fn huge_salt_pss() -> Vec<u8> {
    der_seq(&[
        der_oid(RSASSA_PSS),
        der_seq(&[
            sha256_null(),
            der_seq(&[der_oid(MGF1), sha256_null()]),
            der_int(100_000),
            der_int(1),
        ]),
    ])
}

/// The same in the RFC 8017 tagged form.
fn tagged_pss_params() -> Vec<u8> {
    der_seq(&[
        der_oid(RSASSA_PSS),
        der_seq(&[
            der(tag::CONTEXT_0, &sha256_null()),
            der(tag::CONTEXT_1, &der_seq(&[der_oid(MGF1), sha256_null()])),
            der(tag::CONTEXT_2, &der_int(100_000)),
            der(tag::CONTEXT_3, &der_int(1)),
        ]),
    ])
}

fn normal_label() -> Vec<u8> {
    rsa_label(SHA256_WITH_RSA)
}

/// The three label bombs, by name.
fn label_bombs() -> [(&'static str, Vec<u8>); 3] {
    [
        ("pss-huge-salt", tagged_pss_params()),
        ("md2-digest", rsa_label(MD2_WITH_RSA)),
        ("generic-composite", rsa_label(GENERIC_COMPOSITE)),
    ]
}

fn b64(der: &[u8]) -> String {
    base64_encode(der)
}

fn refused(what: &str, verifier: &Verifier, receipt: &str, expected: &[Reason]) {
    pki::refused(PREFIX, what, verifier, receipt, expected);
}

fn verifies(what: &str, verifier: &Verifier, receipt: &str) {
    pki::verifies(PREFIX, what, verifier, receipt);
}

/// The attacker-grade leaf signs a fresh payload, now, named as `signer`,
/// with `bag`.
fn my_signed(signer: &[u8], bag: &[&Vec<u8>]) -> Vec<u8> {
    let m = material();
    let bag: Vec<Vec<u8>> = bag.iter().map(|c| (*c).clone()).collect();
    sign_receipt_as(
        &payload_now(),
        now_ms(),
        &m.my_leaf_key,
        Hash::Sha256,
        &[signer],
        &bag,
    )
}

fn endpoint_body(verifier: &Verifier, body: &str) -> i64 {
    pki::status_of(&verifier.verify_receipt_endpoint(Environment::Sandbox, body))
}

/// Mirrors `controlMyAppleShapedPkiVerifies`, both controls.
#[test]
fn control_my_apple_shaped_pki_verifies() {
    let m = material();
    verifies("attacker-grade-pki control", &m.my_verifier, &m.my_genuine);
    verifies("upstream-pki control", &m.pki_verifier, &m.pki_genuine);
}

/// Mirrors `developerCertWithoutSigningMarkerCannotForge`: a chain
/// without the leaf's marker, without the intermediate's, and without
/// either.
#[test]
fn developer_cert_without_signing_marker_cannot_forge() {
    let (past, future) = (
        parse_rfc3339("2026-01-01T00:00:00Z"),
        parse_rfc3339("2027-01-01T00:00:00Z"),
    );
    for (what, leaf_marker, wwdr_marker) in [
        ("developer-cert-without-signing-marker", false, true),
        ("wwdr-intermediate-without-marker", true, false),
        ("both-markers-missing", false, false),
    ] {
        let pki = Pki::receipt_with(past, future, leaf_marker, wwdr_marker);
        refused(
            what,
            &pki.verifier(),
            &b64(&pki.sign_receipt(&payload_now())),
            &[Reason::InvalidCertificatePurpose],
        );
    }
}

/// Mirrors `signerIssuedByTheRootDirectlyIsRefused`: a marker leaf issued
/// by the root, no intermediate.
#[test]
fn signer_issued_by_the_root_directly_is_refused() {
    let m = material();
    let key = Key::rsa();
    let leaf = cert(
        "Deep Fake Root-Issued Signer",
        &key,
        ROOT,
        &m.my_root_key,
        false,
        Some(SIGNING_LEAF_OID),
    );
    let receipt = sign_receipt_as(
        &payload_now(),
        now_ms(),
        &key,
        Hash::Sha256,
        &[&leaf],
        &[leaf.clone(), m.my_root.clone()],
    );
    refused(
        "signer-issued-by-root-directly",
        &m.my_verifier,
        &b64(&receipt),
        &[Reason::InvalidCertificatePurpose],
    );
}

/// Mirrors `receiptEnvironmentMismatchesAnswerApplesStatuses`.
#[test]
fn receipt_environment_mismatches_answer_apples_statuses() {
    let m = material();
    let now = now_rfc3339();
    let prod_payload = receipt_payload_full(
        Some("Production"),
        "com.example.app",
        "1.0",
        &[1, 2, 3, 4],
        &[5, 6, 7, 8],
        &now,
        &[pki::in_app_purchase(
            1,
            "gems.small",
            "2001",
            "2001",
            &now,
            None,
        )],
        true,
    );
    let prod = b64(&m.pki.sign_receipt(&prod_payload));
    let status =
        |environment, receipt: &str| pki::endpoint_status(&m.pki_verifier, environment, receipt);
    assert_eq!(
        status(Environment::Production, &prod),
        i64::from(AppleStatus::OK)
    );
    assert_eq!(
        status(Environment::Sandbox, &prod),
        i64::from(AppleStatus::PRODUCTION_RECEIPT_ON_SANDBOX)
    );
    assert_eq!(
        status(Environment::Sandbox, &m.pki_genuine),
        i64::from(AppleStatus::OK)
    );
    assert_eq!(
        status(Environment::Production, &m.pki_genuine),
        i64::from(AppleStatus::SANDBOX_RECEIPT_ON_PRODUCTION)
    );
    assert!(
        m.pki_verifier.verify_receipt(&prod).is_ok(),
        "verify_receipt itself must not check the environment"
    );
}

fn historical_payload(creation_attribute: bool) -> Vec<u8> {
    receipt_payload_full(
        Some("ProductionSandbox"),
        "com.example.app",
        "1.0",
        &[1, 2, 3, 4],
        &[5, 6, 7, 8],
        "2020-06-15T12:00:00Z",
        &[pki::in_app_purchase(
            1,
            "gems.small",
            "2001",
            "2001",
            "2020-06-15T12:00:00Z",
            None,
        )],
        creation_attribute,
    )
}

fn expired_pki() -> Pki {
    Pki::receipt_with(
        parse_rfc3339("2020-01-01T00:00:00Z"),
        parse_rfc3339("2020-12-31T00:00:00Z"),
        true,
        true,
    )
}

/// Mirrors `expiredHistoricalReceiptInsideItsValidityStillVerifies`: a
/// chain that expired in 2020, a receipt created and signed inside it.
#[test]
fn expired_historical_receipt_inside_its_validity_still_verifies() {
    let expired = expired_pki();
    let historical = expired.sign_receipt_at(
        &historical_payload(true),
        parse_rfc3339("2020-06-15T12:00:00Z"),
    );
    verifies(
        "expired-chain-historical-date (documented policy)",
        &expired.verifier(),
        &b64(&historical),
    );
}

/// Mirrors `expiredChainWithoutACreationDateIsJudgedAtTheClockAndRefused`.
#[test]
fn expired_chain_without_a_creation_date_is_judged_at_the_clock_and_refused() {
    let expired = expired_pki();
    refused(
        "expired-chain-no-creation-date",
        &expired.verifier(),
        &b64(&expired.sign_receipt(&historical_payload(false))),
        &[Reason::InvalidCertificate, Reason::UntrustedChain],
    );
}

/// Mirrors `notYetValidChainIsRefused`: a chain valid from 2027.
#[test]
fn not_yet_valid_chain_is_refused() {
    let future = Pki::receipt_with(
        parse_rfc3339("2027-01-01T00:00:00Z"),
        parse_rfc3339("2030-01-01T00:00:00Z"),
        true,
        true,
    );
    refused(
        "not-yet-valid-chain",
        &future.verifier(),
        &b64(&future.sign_receipt(&payload_now())),
        &[Reason::InvalidCertificate, Reason::UntrustedChain],
    );
}

/// Mirrors `digestLabelSurgeryToSha384FailsTheSignatureFast`: the second
/// SHA-256 OID (the SignerInfo's digestAlgorithm; the first is the
/// digest set, the third the CMSAlgorithmProtection copy) turned into
/// SHA-384.
#[test]
fn digest_label_surgery_to_sha384_fails_the_signature_fast() {
    let m = material();
    let sha256_oid = der_oid(SHA256);
    let second = m
        .my_genuine_der
        .windows(sha256_oid.len())
        .enumerate()
        .filter(|(_, w)| *w == sha256_oid.as_slice())
        .nth(1)
        .map(|(i, _)| i)
        .expect("the SHA-256 digest OID should appear at least twice");
    let mut patched = m.my_genuine_der.clone();
    patched[second + sha256_oid.len() - 1] = 0x02;
    refused(
        "digest-label-sha384-surgery",
        &m.my_verifier,
        &b64(&patched),
        &[Reason::InvalidSignature],
    );
}

/// Mirrors `signatureLabelSurgeryToPssWithNullParamsIsRefusedFast`: the
/// SignerInfo's sha256WithRSAEncryption (the last in the DER) turned into
/// RSASSA-PSS with NULL parameters is refused; the last rsaEncryption
/// OID, inside an embedded certificate's key, turned the same way leaves
/// the receipt verifying.
#[test]
fn signature_label_surgery_to_pss_with_null_params_is_refused_fast() {
    let m = material();
    let combined = der_oid(SHA256_WITH_RSA);
    let at = last_index_of(&m.my_genuine_der, &combined).expect("no sha256WithRSAEncryption label");
    let mut patched = m.my_genuine_der.clone();
    patched[at + combined.len() - 1] = 0x0A;
    refused(
        "signature-label-pss-null-params-surgery",
        &m.my_verifier,
        &b64(&patched),
        &[Reason::InvalidSignature, Reason::Malformed],
    );

    let rsa = der_oid(pki::RSA_ENCRYPTION);
    let inert = last_index_of(&m.my_genuine_der, &rsa).expect("no rsaEncryption label");
    let mut patched_outer = m.my_genuine_der.clone();
    patched_outer[inert + rsa.len() - 1] = 0x0A;
    verifies(
        "certificate-outer-label-surgery-is-inert",
        &m.my_verifier,
        &b64(&patched_outer),
    );
}

/// Mirrors `hostileCertificateLabelsAreRefusedBeforeAnyWork`: a
/// PSS-huge-salt, an MD2 and a generic-composite label on garbage-signed
/// strangers; refused as the signer, inert as junk.
#[test]
fn hostile_certificate_labels_are_refused_before_any_work() {
    let m = material();
    for (what, label) in label_bombs() {
        let hostile = hostile_cert(&format!("Hostile {what} signer"), &label, false, 2048);
        refused(
            &format!("label-bomb-{what}-as-signer"),
            &m.my_verifier,
            &b64(&my_signed(
                &hostile,
                &[&m.my_leaf, &m.my_inter, &m.my_root, &hostile],
            )),
            &[Reason::UntrustedChain, Reason::Malformed],
        );
        verifies(
            &format!("label-bomb-{what}-as-bag-junk"),
            &m.my_verifier,
            &b64(&my_signed(
                &m.my_leaf,
                &[&m.my_leaf, &m.my_inter, &m.my_root, &hostile],
            )),
        );
    }
}

/// Mirrors `nonstandardPssParameterFormsAreRefusedCleanlyAtTheBagDecode`:
/// a PSS label in BouncyCastle's untagged parameter form, as junk and as
/// the signer.
///
/// As the signer both refuse it: Java at the bag decode (`MALFORMED`),
/// the core because no pinned root vouches for it (`UNTRUSTED_CHAIN`).
/// As junk Java refuses the whole receipt (`MALFORMED`: BouncyCastle's
/// certificate converter crashes on the parameters) and the core passes
/// it over and verifies (measured 2026-10-31).
///
/// STOPPED, the junk half: that difference is not recorded in
/// DECISIONS.md R20. It runs the safe way round (the core accepts a
/// genuinely signed receipt that Java refuses for an unsigned bag entry,
/// and accepts nothing unsigned), but the rule says it must be recorded,
/// so the half only prints its verdict until the owner decides.
#[test]
fn nonstandard_pss_parameter_forms_are_refused_cleanly_at_the_bag_decode() {
    let m = material();
    let untagged = hostile_cert("Untagged PSS pretender", &huge_salt_pss(), false, 2048);
    refused(
        "untagged-pss-params-as-signer",
        &m.my_verifier,
        &b64(&my_signed(
            &untagged,
            &[&m.my_leaf, &m.my_inter, &m.my_root, &untagged],
        )),
        &[Reason::Malformed, Reason::UntrustedChain],
    );
    let as_junk = my_signed(
        &m.my_leaf,
        &[&m.my_leaf, &m.my_inter, &m.my_root, &untagged],
    );
    let _ = pki::printed(
        PREFIX,
        "untagged-pss-params-as-bag-junk",
        &m.my_verifier,
        &as_junk,
    );
}

/// Mirrors `mislabeledCertificatesSignedByTheCaKeyStillRefuseBeforeWork`:
/// the leaked-WWDR-key scenario, a validly signed CA carrying each label
/// bomb and a certificate naming it as issuer, beside a genuine receipt.
#[test]
fn mislabeled_certificates_signed_by_the_ca_key_still_refuse_before_work() {
    let m = material();
    for (what, label) in label_bombs() {
        let subject = format!("Vouched {what}");
        let vouched = mislabeled_vouched_cert(&subject, &label);
        let namee = CertSpec::new(
            name(&format!("Namee of {what}")),
            name(&subject),
            random_rsa_spki(2048, E65537),
        )
        .garbage(&normal_label());
        verifies(
            &format!("leaked-key-mislabeled-{what}-cannot-bomb"),
            &m.my_verifier,
            &b64(&my_signed(
                &m.my_leaf,
                &[&m.my_leaf, &m.my_inter, &m.my_root, &vouched, &namee],
            )),
        );
    }
}

/// Mirrors `hugeModulusPretendersAreNeverDecoded`: a 16,384-bit stranger
/// and a 16,384-bit clone of the intermediate's name, both garbage
/// signed, beside a genuine receipt.
#[test]
fn huge_modulus_pretenders_are_never_decoded() {
    let m = material();
    let pretender = hostile_cert("Huge Modulus Pretender", &normal_label(), false, 16_384);
    verifies(
        "16384-bit-pretender-never-decoded",
        &m.my_verifier,
        &b64(&my_signed(
            &m.my_leaf,
            &[&m.my_leaf, &m.my_inter, &m.my_root, &pretender],
        )),
    );
    let clone = CertSpec::new(name(INTER), name(INTER), random_rsa_spki(16_384, E65537))
        .garbage(&normal_label());
    verifies(
        "16384-bit-intermediate-name-clone-never-decoded",
        &m.my_verifier,
        &b64(&my_signed(
            &m.my_leaf,
            &[&m.my_leaf, &m.my_inter, &m.my_root, &clone],
        )),
    );
}

/// Mirrors `vouchedHugeKeysCostBoundedSecondsOnlyWithALeakedCaKey`: two
/// CAs validly signed by the WWDR key on 16,384-bit keys, each named as
/// the issuer of a garbage-signed certificate. Java bounds it at 30 s.
#[test]
fn vouched_huge_keys_cost_bounded_seconds_only_with_a_leaked_ca_key() {
    let m = material();
    let vouched = |subject: &str| {
        CertSpec::new(name(subject), name(INTER), random_rsa_spki(16_384, E65537))
            .with(basic_constraints(true, None))
            .sign(&m.my_inter_key)
    };
    let namee = |subject: &str, issuer: &str| {
        CertSpec::new(name(subject), name(issuer), random_rsa_spki(2048, E65537))
            .garbage(&normal_label())
    };
    let (vouched1, vouched2) = (vouched("Vouched Huge 1"), vouched("Vouched Huge 2"));
    let (namee1, namee2) = (
        namee("Namee 1", "Vouched Huge 1"),
        namee("Namee 2", "Vouched Huge 2"),
    );
    let receipt = b64(&my_signed(
        &m.my_leaf,
        &[
            &m.my_leaf,
            &m.my_inter,
            &m.my_root,
            &vouched1,
            &namee1,
            &vouched2,
            &namee2,
        ],
    ));
    let (result, cost) = timed(|| m.my_verifier.verify_receipt(&receipt));
    eprintln!(
        "{PREFIX} leaked-ca-key two 16384-bit vouched keys: {} ms, {}",
        cost.as_millis(),
        result.is_ok()
    );
    result.unwrap_or_else(|f| panic!("the genuine receipt should still verify: {f}"));
    assert!(
        cost < Duration::from_secs(30),
        "the leaked-CA-key worst case cost {cost:?}"
    );
}

/// Mirrors `injectedJunkSignersCannotShadowAGenuineOne`: an attacker's
/// SignerInfo ahead of the genuine one, and a SignerInfo naming a junk
/// certificate beside the genuine one.
#[test]
fn injected_junk_signers_cannot_shadow_a_genuine_one() {
    let m = material();
    let other_pki = Pki::receipt();
    let injected = sign_receipt_by_each(&payload_now(), &[&other_pki, &m.pki]);
    verifies(
        "attacker-signer-injected-first",
        &m.pki_verifier,
        &b64(&injected),
    );

    let junk = hostile_cert("Junk Signer", &normal_label(), false, 2048);
    let junk_first = sign_receipt_as(
        &payload_now(),
        now_ms(),
        &m.my_leaf_key,
        Hash::Sha256,
        &[&junk, &m.my_leaf],
        &[
            m.my_leaf.clone(),
            m.my_inter.clone(),
            m.my_root.clone(),
            junk.clone(),
        ],
    );
    verifies(
        "junk-signer-injected-beside-genuine",
        &m.my_verifier,
        &b64(&junk_first),
    );
}

/// Mirrors `signerNamedAsThePinnedRootIsRefused`.
#[test]
fn signer_named_as_the_pinned_root_is_refused() {
    let m = material();
    refused(
        "signer-named-as-the-pinned-root",
        &m.my_verifier,
        &b64(&my_signed(
            &m.my_root,
            &[&m.my_leaf, &m.my_inter, &m.my_root],
        )),
        &[Reason::InvalidCertificatePurpose, Reason::UntrustedChain],
    );
}

/// Mirrors `undecodableBagEntriesAreRefused`: five certificates whose
/// critical basicConstraints holds an INTEGER instead of a SEQUENCE
/// (`TestPki.signReceiptWithUndecodablePadding`).
#[test]
fn undecodable_bag_entries_are_refused() {
    let m = material();
    let padding_key = Key::rsa();
    let mut bag = m.pki.chain.clone();
    for i in 0..5 {
        let cn = format!("Undecodable {i}");
        let mut spec = CertSpec::new(name(&cn), name(&cn), padding_key.spki());
        spec.not_before = m.pki.not_before;
        spec.not_after = m.pki.not_after;
        bag.push(
            spec.with(extension("2.5.29.19", true, &der_int(1)))
                .sign(&padding_key),
        );
    }
    refused(
        "undecodable-bag-entries",
        &m.pki_verifier,
        &b64(&m.pki.sign_receipt_with_bag(&payload_now(), &bag)),
        &[Reason::InvalidCertificate, Reason::Malformed],
    );
}

/// Mirrors `tamperedMessageDigestAttributeFailsTheSignature`.
#[test]
fn tampered_message_digest_attribute_fails_the_signature() {
    let m = material();
    let oid = der_oid(pki::MESSAGE_DIGEST);
    assert_eq!(
        count(&m.my_genuine_der, &oid),
        1,
        "the messageDigest OID should appear exactly once"
    );
    let mut patched = m.my_genuine_der.clone();
    let at = index_of(&patched, &oid).unwrap() + oid.len();
    assert_eq!(patched[at], 0x31, "expected the attribute value SET tag");
    assert_eq!(
        patched[at + 2],
        0x04,
        "expected the digest OCTET STRING tag"
    );
    assert_eq!(patched[at + 3], 0x20, "expected a 32-byte SHA-256 digest");
    patched[at + 4] ^= 0x01;
    refused(
        "tampered-messageDigest-attribute",
        &m.my_verifier,
        &b64(&patched),
        &[Reason::InvalidSignature],
    );
}

/// Mirrors `tamperedPayloadFailsTheSignature`.
#[test]
fn tampered_payload_fails_the_signature() {
    let m = material();
    let bundle_id = b"com.example.app";
    assert_eq!(
        count(&m.my_genuine_der, bundle_id),
        1,
        "the bundle id should appear exactly once"
    );
    let mut patched = m.my_genuine_der.clone();
    let at = index_of(&patched, bundle_id).unwrap();
    patched[at] ^= 0x01;
    refused(
        "tampered-payload",
        &m.my_verifier,
        &b64(&patched),
        &[Reason::InvalidSignature],
    );
}

/// Mirrors `tamperedIntermediateBreaksTheChain`.
#[test]
fn tampered_intermediate_breaks_the_chain() {
    let m = material();
    assert_eq!(
        count(&m.my_genuine_der, &m.my_inter),
        1,
        "the intermediate should appear exactly once"
    );
    let mut patched = m.my_genuine_der.clone();
    let at = index_of(&patched, &m.my_inter).unwrap();
    patched[at + m.my_inter.len() / 2] ^= 0x01;
    refused(
        "tampered-intermediate-certificate",
        &m.my_verifier,
        &b64(&patched),
        &[
            Reason::UntrustedChain,
            Reason::InvalidCertificate,
            Reason::Malformed,
        ],
    );
}

/// Mirrors `malformedDerShapesAreRefusedFast`: content typed as plain
/// data, a SignedData with no signers, a garbage digest algorithm set, a
/// huge length claim, high-tag continuation octets, and truncations at
/// 25, 50, 75 and 99 per cent.
#[test]
fn malformed_der_shapes_are_refused_fast() {
    let m = material();
    let payload = payload_now();
    let inner = der_seq(&[
        der_oid(pki::ID_DATA),
        der(tag::CONTEXT_0, &der(tag::OCTET_STRING, &payload)),
    ]);
    let content_info =
        |signed: Vec<u8>| der_seq(&[der_oid(pki::ID_SIGNED_DATA), der(tag::CONTEXT_0, &signed)]);
    let malformed = |what: &str, der: &[u8]| {
        refused(what, &m.my_verifier, &b64(der), &[Reason::Malformed]);
    };
    malformed("content-typed-as-plain-data", &inner);
    malformed(
        "signed-data-with-no-signers",
        &content_info(der_seq(&[
            der_int(1),
            common::der_set(&[]),
            inner.clone(),
            common::der_set(&[]),
        ])),
    );
    malformed(
        "garbage-digest-algorithm-set",
        &content_info(der_seq(&[
            der_int(1),
            common::der_set(&[der_seq(&[der_oid("1.2.3.4.5"), der(0x05, &[])])]),
            inner.clone(),
            common::der_set(&[]),
        ])),
    );
    malformed(
        "huge-der-length-claim",
        &[0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0x02, 0x01, 0x01],
    );
    malformed(
        "high-tag-continuation-bytes",
        &[0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F],
    );
    for fraction in [25, 50, 75, 99] {
        let truncated = &m.my_genuine_der[..m.my_genuine_der.len() * fraction / 100];
        malformed(&format!("truncated-at-{fraction}-percent"), truncated);
    }
}

/// Mirrors `sizeCapBoundaryIsEnforcedExactly`.
#[test]
fn size_cap_boundary_is_enforced_exactly() {
    let m = material();
    let mut at_cap = "A".repeat(3_145_728);
    refused(
        "receipt-at-exactly-the-cap",
        &m.my_verifier,
        &at_cap,
        &[Reason::Malformed],
    );
    at_cap.push('A');
    refused(
        "receipt-one-char-over-the-cap",
        &m.my_verifier,
        &at_cap,
        &[Reason::TooLarge],
    );
}

/// Mirrors `looseBase64VariantsAreRefusedStrictly`: MIME line breaks,
/// trailing whitespace and a NUL are refused; unpadded and base64url
/// spellings print their verdicts.
#[test]
fn loose_base64_variants_are_refused_strictly() {
    let m = material();
    let mime: String = m
        .my_genuine
        .as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    refused(
        "mime-base64-with-line-breaks",
        &m.my_verifier,
        &mime,
        &[Reason::Malformed],
    );
    refused(
        "trailing-whitespace",
        &m.my_verifier,
        &format!("{} ", m.my_genuine),
        &[Reason::Malformed],
    );
    refused(
        "nul-character-inside",
        &m.my_verifier,
        &format!("{}\0{}", &m.my_genuine[..100], &m.my_genuine[100..]),
        &[Reason::Malformed],
    );
    let unpadded = &m.my_genuine[..m.my_genuine.len() - 2];
    let result = m.my_verifier.verify_receipt(unpadded);
    eprintln!(
        "{PREFIX} unpadded-standard-base64: {:?}",
        result.as_ref().map(|_| ()).map_err(|f| f.reason())
    );
    let url_safe = m.my_genuine.replace('+', "-").replace('/', "_");
    let url_safe = url_safe.trim_end_matches('=');
    let result = m.my_verifier.verify_receipt(url_safe);
    eprintln!(
        "{PREFIX} base64url-of-a-receipt: {:?}",
        result.as_ref().map(|_| ()).map_err(|f| f.reason())
    );
}

/// Mirrors `berIndefiniteLengthReceiptIsHandledWithoutThrowing`: the
/// genuine receipt's outer SEQUENCE rewritten with an indefinite length.
#[test]
fn ber_indefinite_length_receipt_is_handled_without_throwing() {
    let m = material();
    let der = &m.my_genuine_der;
    let body_start = if der[1] & 0x80 == 0 {
        2
    } else {
        2 + usize::from(der[1] & 0x7F)
    };
    let mut wrapped = vec![0x30, 0x80];
    wrapped.extend_from_slice(&der[body_start..]);
    wrapped.extend_from_slice(&[0x00, 0x00]);
    let _ = pki::printed(
        PREFIX,
        "ber-indefinite-length-wrap",
        &m.my_verifier,
        &wrapped,
    );
}

/// Mirrors `endpointAnswersOnlyMappedStatusesUnderStructuredAbuse`.
///
/// Java's `endpointStatus(null)` has no counterpart: the Rust endpoint
/// takes a `&str`, which cannot be null. The empty body stands in for it.
#[test]
fn endpoint_answers_only_mapped_statuses_under_structured_abuse() {
    let m = material();
    let genuine = &m.pki_genuine;
    let started = std::time::Instant::now();
    let malformed = i64::from(AppleStatus::MALFORMED_RECEIPT_DATA);
    let ok = i64::from(AppleStatus::OK);
    assert_eq!(
        endpoint_body(
            &m.pki_verifier,
            &format!(r#"{{"receipt-data":"{genuine}"}}"#)
        ),
        ok
    );
    for body in [
        r#"{"receipt-data":12345}"#,
        r#"{"receipt-data":null}"#,
        r#"{"receipt-data":["x"]}"#,
        r#"{"receipt-data":{"x":1}}"#,
        r#"{"receipt-data":true}"#,
        r#"{"receipt-data":""}"#,
        "{}",
        "[1,2,3]",
        "42",
        r#"{"receipt-data":"AAAA",}"#,
        "{'receipt-data':'AAAA'}",
        r#"{"receipt-data":NaN}"#,
        "\u{FEFF}{\"receipt-data\":\"AAAA\"}",
        "",
    ] {
        assert_eq!(endpoint_body(&m.pki_verifier, body), malformed, "{body}");
    }
    assert_eq!(
        endpoint_body(
            &m.pki_verifier,
            &format!(r#"{{"receipt-data":"AAAA","receipt-data":"{genuine}"}}"#)
        ),
        ok
    );
    // The last duplicate wins, and "@@@" is not base64.
    assert_eq!(
        endpoint_body(
            &m.pki_verifier,
            &format!(r#"{{"receipt-data":"{genuine}","receipt-data":"@@@"}}"#)
        ),
        malformed
    );
    let cost = started.elapsed();
    assert!(
        cost < BUDGET,
        "the structured endpoint battery took {cost:?}"
    );
}

/// Mirrors `endpointDeepAndOversizedBodiesAreBounded`: a body nested
/// 2,000 deep, a genuine receipt buried 900 deep, 3,500,000 spaces of
/// `receipt-data` and 3,140,000 characters of it.
#[test]
fn endpoint_deep_and_oversized_bodies_are_bounded() {
    let m = material();
    let malformed = i64::from(AppleStatus::MALFORMED_RECEIPT_DATA);
    let nested = |depth: usize, inner: &str| {
        format!("{}{inner}{}", r#"{"a":"#.repeat(depth), "}".repeat(depth))
    };

    let deep = nested(2000, r#"{"receipt-data":"AAAA"}"#);
    let (status, cost) = timed(|| endpoint_body(&m.pki_verifier, &deep));
    eprintln!(
        "{PREFIX} 2000-deep-json-body: {} ms, status {status}",
        cost.as_millis()
    );
    assert!(
        status == malformed || status == i64::from(AppleStatus::RECEIPT_NOT_AUTHENTICATED),
        "{status}"
    );
    assert!(cost < BUDGET, "the deep body took {cost:?}");

    // Only top-level members are read, so a receipt-data buried nine
    // hundred levels deep is not read at all.
    let buried = nested(900, &format!(r#"{{"receipt-data":"{}"}}"#, m.pki_genuine));
    let (status, cost) = timed(|| endpoint_body(&m.pki_verifier, &buried));
    eprintln!(
        "{PREFIX} 900-deep-buried-receipt-data: {} ms",
        cost.as_millis()
    );
    assert_eq!(status, malformed);
    assert!(cost < BUDGET, "the buried receipt body took {cost:?}");

    let huge = format!(r#"{{"receipt-data":"{}"}}"#, " ".repeat(3_500_000));
    let (status, cost) = timed(|| endpoint_body(&m.pki_verifier, &huge));
    eprintln!("{PREFIX} oversized-body: {} ms", cost.as_millis());
    assert_eq!(status, malformed);
    assert!(cost < BUDGET, "the oversized body took {cost:?}");

    let near_cap = format!(r#"{{"receipt-data":"{}"}}"#, "A".repeat(3_140_000));
    let (status, cost) = timed(|| endpoint_body(&m.pki_verifier, &near_cap));
    eprintln!(
        "{PREFIX} near-cap-body-full-pipeline: {} ms",
        cost.as_millis()
    );
    assert_eq!(status, malformed);
    assert!(cost < BUDGET, "the near-cap body took {cost:?}");
}

/// Mirrors `endpointAgreesWithVerifyReceiptOnEveryVerdict`.
#[test]
fn endpoint_agrees_with_verify_receipt_on_every_verdict() {
    let m = material();
    let mut receipts = vec![
        m.pki_genuine.clone(),
        m.my_genuine.clone(),
        b64(&pki::corrupt_signatures(&m.my_genuine_der, 1)),
        "AAAA".to_owned(),
        String::new(),
    ];
    for _ in 0..20 {
        receipts.push(b64(&random_bytes(random_below(50_000))));
    }
    receipts.push("A".repeat(3_145_729));
    for receipt in &receipts {
        let result = m.pki_verifier.verify_receipt(receipt);
        let status = pki::endpoint_status(&m.pki_verifier, Environment::Sandbox, receipt);
        match result {
            Ok(_) => assert_eq!(
                status,
                i64::from(AppleStatus::OK),
                "a verified receipt answered {status}"
            ),
            Err(failure) => {
                assert_ne!(
                    status,
                    i64::from(AppleStatus::OK),
                    "a refused receipt answered 0"
                );
                assert_ne!(
                    status,
                    i64::from(AppleStatus::INTERNAL_DATA_ACCESS_ERROR),
                    "a refused receipt answered 21009: {failure}"
                );
                match failure.reason() {
                    Reason::Malformed | Reason::TooLarge => {
                        assert_eq!(status, i64::from(AppleStatus::MALFORMED_RECEIPT_DATA));
                    }
                    Reason::InvalidSignature
                    | Reason::UntrustedChain
                    | Reason::InvalidCertificate
                    | Reason::InvalidCertificatePurpose => {
                        assert_eq!(status, i64::from(AppleStatus::RECEIPT_NOT_AUTHENTICATED));
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Mirrors `sharedVerifierIsThreadSafeUnderMixedLoad`: twelve threads,
/// 25 rounds each over five receipts on two shared verifiers, each
/// verdict and its endpoint answer checked.
#[test]
fn shared_verifier_is_thread_safe_under_mixed_load() {
    let m = material();
    let corrupted = b64(&pki::corrupt_signatures(&m.my_genuine_der, 1));
    let half = m.my_genuine[..m.my_genuine.len() / 2].to_owned();
    let pool: Vec<(&Verifier, &str, Option<Reason>)> = vec![
        (&m.my_verifier, &m.my_genuine, None),
        (&m.pki_verifier, &m.pki_genuine, None),
        (&m.my_verifier, &corrupted, Some(Reason::InvalidSignature)),
        (&m.my_verifier, "AAAA", Some(Reason::Malformed)),
        (&m.my_verifier, &half, Some(Reason::Malformed)),
    ];
    let (all_agreed, cost) = timed(|| {
        std::thread::scope(|scope| {
            let workers: Vec<_> = (0..12)
                .map(|seed| {
                    let pool = &pool;
                    scope.spawn(move || {
                        for _ in 0..25 {
                            for i in 0..pool.len() {
                                let (verifier, receipt, expected) = pool[(i + seed) % pool.len()];
                                let result = verifier.verify_receipt(receipt);
                                if result.as_ref().err().map(|f| f.reason()) != expected {
                                    return false;
                                }
                                let status =
                                    pki::endpoint_status(verifier, Environment::Sandbox, receipt);
                                if result.is_ok() != (status == i64::from(AppleStatus::OK)) {
                                    return false;
                                }
                            }
                        }
                        true
                    })
                })
                .collect();
            workers.into_iter().all(|worker| worker.join().unwrap())
        })
    });
    eprintln!(
        "{PREFIX} concurrency: {} mixed ops on shared verifiers in {} ms",
        12 * 25 * pool.len() * 2,
        cost.as_millis()
    );
    assert!(all_agreed, "a worker saw a cross-contaminated verdict");
}

/// Mirrors `deepRandomFuzzNeverVerifiesNeverThrows`: 300 random inputs,
/// the first 50 of 3.0 to 3.1 MB, the rest up to 1 MB, every tenth as
/// Latin-1 text.
#[test]
fn deep_random_fuzz_never_verifies_never_panics() {
    let verifier = &material().my_verifier;
    let mut worst = Duration::ZERO;
    for i in 0..300 {
        let size = if i < 50 {
            3_000_000 + random_below(100_000)
        } else {
            random_below(1_000_000)
        };
        let bytes = random_bytes(size);
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
    eprintln!(
        "{PREFIX} 300 random inputs (up to 3.1 MB): worst {} ms",
        worst.as_millis()
    );
    assert!(worst < BUDGET, "a random input took {worst:?}");
}
