//! The fifty-year catalog, case by case from Java's
//! `WorstCaseFiftyYearTest`: 1970s RSA (the common-modulus shape and the
//! Bleichenbacher 2006 cube-root forgery under an exponent-3 key, rebuilt
//! as published), 1990s identity tricks (DN squatters, SignerIdentifier
//! collisions, outlaw serials), 2000s mesh abuse (a cross-signing cycle
//! and a root-issued twin of the intermediate's name) and 2010s CMS
//! attribute abuse (unsigned attributes, a signed messageDigest naming
//! another payload, a direct signature).
//!
//! The eras Java lists as not executable (timing and fault side
//! channels, the 1998 padding oracle, MD5/SHA-1 chosen-prefix forgery,
//! replay, quantum, Apple's WWDR key, supply-chain substitution of
//! BouncyCastle) are not executable here either, for the same reasons;
//! the last becomes a pinned OpenSSL 4 and `cargo deny`.

mod common;

use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{Reason, TrustAnchor, Verifier};
use common::pki::{
    self, attribute, bc_garbage_signed, bc_sign, bc_signed, name, payload_now, random_rsa_spki,
    rsa_label, rsa_spki, timed, Attrs, CertSpec, Hash, Key, BUDGET, E65537, MESSAGE_DIGEST, SHA256,
    SHA256_WITH_RSA, SIGNING_LEAF_OID, WWDR_OID,
};
use common::{der, der_oid, der_seq, tag};
use openssl::bn::BigNum;
use std::sync::OnceLock;

const PREFIX: &str = "fifty";
const ROOT: &str = "Fifty Year Fake Apple Root CA";
const INTER: &str = "Fifty Year Fake Apple WWDR CA";

struct Material {
    root_key: Key,
    inter_key: Key,
    leaf_key: Key,
    root: Vec<u8>,
    inter: Vec<u8>,
    leaf: Vec<u8>,
    verifier: Verifier,
}

/// Java's `@BeforeAll`: an Apple-shaped RSA PKI, the marker leaf's
/// extension valued BOOLEAN TRUE, pinned alone.
fn material() -> &'static Material {
    static MATERIAL: OnceLock<Material> = OnceLock::new();
    MATERIAL.get_or_init(|| {
        let (root_key, inter_key, leaf_key) = (Key::rsa(), Key::rsa(), Key::rsa());
        let root = cert(name(ROOT), &root_key, name(ROOT), &root_key, true, None);
        let inter = cert(
            name(INTER),
            &inter_key,
            name(ROOT),
            &root_key,
            true,
            Some(WWDR_OID),
        );
        let leaf = cert(
            name("Fifty Year Fake Receipt Signer"),
            &leaf_key,
            name(INTER),
            &inter_key,
            false,
            Some(SIGNING_LEAF_OID),
        );
        let verifier = common::verifier([TrustAnchor::from_der(&root).unwrap()]);
        Material {
            root_key,
            inter_key,
            leaf_key,
            root,
            inter,
            leaf,
            verifier,
        }
    })
}

/// The suite's `cert`: signed the normal way, with or without the CA role
/// and a marker.
fn cert(
    subject: Vec<u8>,
    key: &Key,
    issuer: Vec<u8>,
    issuer_key: &Key,
    ca: bool,
    marker: Option<&str>,
) -> Vec<u8> {
    CertSpec::suite(subject, key.spki(), issuer, ca, marker).sign(issuer_key)
}

/// The suite's `craftedSubjectCert`: a hand-made SPKI, signed the normal way.
fn crafted(
    subject: Vec<u8>,
    spki: Vec<u8>,
    issuer: Vec<u8>,
    issuer_key: &Key,
    ca: bool,
    marker: Option<&str>,
) -> Vec<u8> {
    CertSpec::suite(subject, spki, issuer, ca, marker).sign(issuer_key)
}

/// A garbage-signed certificate under the SHA256withRSA label.
fn garbage(spec: CertSpec) -> Vec<u8> {
    spec.garbage(&rsa_label(SHA256_WITH_RSA))
}

fn refused(what: &str, der: &[u8], expected: &[Reason]) {
    pki::refused_der(PREFIX, what, &material().verifier, der, expected);
}

fn verifies(what: &str, der: &[u8]) {
    pki::verifies_der(PREFIX, what, &material().verifier, der);
}

fn chain(extra: &[&Vec<u8>]) -> Vec<Vec<u8>> {
    extra.iter().map(|c| (*c).clone()).collect()
}

// --- the 2006 Bleichenbacher forgery ---------------------------------------------

/// The least cube root, as a ceiling, by Newton's method.
fn ceil_cbrt(value: &BigNum) -> BigNum {
    let mut context = pki::bn_context();
    let three = BigNum::from_u32(3).unwrap();
    let one = BigNum::from_u32(1).unwrap();
    let cube = |x: &BigNum, context: &mut openssl::bn::BigNumContext| {
        let mut square = BigNum::new().unwrap();
        square.sqr(x, context).unwrap();
        let mut out = BigNum::new().unwrap();
        out.checked_mul(&square, x, context).unwrap();
        out
    };
    let mut x = BigNum::new().unwrap();
    x.lshift(&one, value.num_bits() / 3 + 2).unwrap();
    loop {
        let mut square = BigNum::new().unwrap();
        square.sqr(&x, &mut context).unwrap();
        let mut quotient = BigNum::new().unwrap();
        quotient.checked_div(value, &square, &mut context).unwrap();
        let mut doubled = BigNum::new().unwrap();
        doubled.lshift1(&x).unwrap();
        let mut sum = BigNum::new().unwrap();
        sum.checked_add(&doubled, &quotient).unwrap();
        let mut next = BigNum::new().unwrap();
        next.checked_div(&sum, &three, &mut context).unwrap();
        if next.ucmp(&x) != std::cmp::Ordering::Less {
            break;
        }
        x = next;
    }
    while cube(&x, &mut context).ucmp(value) == std::cmp::Ordering::Less {
        x.add_word(1).unwrap();
    }
    loop {
        let mut below = x.to_owned().unwrap();
        below.sub_word(1).unwrap();
        if cube(&x, &mut context).ucmp(value) == std::cmp::Ordering::Greater
            && cube(&below, &mut context).ucmp(value) != std::cmp::Ordering::Less
        {
            x = below;
        } else {
            break;
        }
    }
    x
}

/// The suite's `cubeRootCert`: a signature that is the cube root of a
/// PKCS#1 v1.5 block, `00 01 FF*25 00 DigestInfo`, with room after the
/// DigestInfo for the garbage a cube root cannot help producing. The
/// prefix must survive cubing, or the forgery is not the published one.
fn cube_root_cert(spec: &CertSpec) -> Vec<u8> {
    spec.with_signature(&rsa_label(SHA256_WITH_RSA), |tbs| {
        let digest_info = der_seq(&[
            der_seq(&[der_oid(SHA256), der(0x05, &[])]),
            der(tag::OCTET_STRING, &Hash::Sha256.digest(tbs)),
        ]);
        let mut prefix = vec![0x00, 0x01];
        prefix.extend_from_slice(&[0xFF; 25]);
        prefix.push(0x00);
        prefix.extend_from_slice(&digest_info);
        let mut block = prefix.clone();
        block.resize(256, 0);
        let root = ceil_cbrt(&BigNum::from_slice(&block).unwrap());
        let mut context = pki::bn_context();
        let mut square = BigNum::new().unwrap();
        square.sqr(&root, &mut context).unwrap();
        let mut cube = BigNum::new().unwrap();
        cube.checked_mul(&square, &root, &mut context).unwrap();
        let cube = cube.to_vec_padded(256).unwrap();
        assert_eq!(
            cube[..prefix.len()],
            prefix[..],
            "the cube root lost the PKCS#1 prefix"
        );
        root.to_vec_padded(256).unwrap()
    })
}

/// Mirrors `bleichenbacherCubeRootForgedChainIsRefused`: a CA genuinely
/// issued by the pinned intermediate but on an exponent-3 key nobody
/// holds, a marker leaf under it whose signature is a cube root, and a
/// receipt with a garbage signature.
#[test]
fn bleichenbacher_cube_root_forged_chain_is_refused() {
    let m = material();
    let three = [3u8];
    let cube_ca = crafted(
        name("Cube Root CA"),
        random_rsa_spki(2048, &three),
        name(INTER),
        &m.inter_key,
        true,
        Some(WWDR_OID),
    );
    let leaf_spec = CertSpec::suite(
        name("Cube Root Signer"),
        random_rsa_spki(2048, &three),
        name("Cube Root CA"),
        false,
        Some(SIGNING_LEAF_OID),
    );
    let cube_leaf = cube_root_cert(&leaf_spec);
    let receipt = bc_garbage_signed(
        &payload_now(),
        &cube_leaf,
        &chain(&[&cube_leaf, &cube_ca, &m.inter, &m.root]),
    );
    refused(
        "bleichenbacher cube-root forged chain",
        &receipt,
        &[
            Reason::UntrustedChain,
            Reason::InvalidCertificate,
            Reason::InvalidSignature,
        ],
    );
}

/// Mirrors `genuinelyUsedExponentThreeKeysAreNotRefusedForTheirExponent`:
/// a chain whose CA and leaf keys were generated and used with e = 3.
#[test]
fn genuinely_used_exponent_three_keys_are_not_refused_for_their_exponent() {
    let m = material();
    let (ca_key, leaf_key) = (
        Key::rsa_with_exponent(2048, 3),
        Key::rsa_with_exponent(2048, 3),
    );
    let ca = cert(
        name("Exponent Three CA"),
        &ca_key,
        name(INTER),
        &m.inter_key,
        true,
        Some(WWDR_OID),
    );
    let leaf = cert(
        name("Exponent Three Signer"),
        &leaf_key,
        name("Exponent Three CA"),
        &ca_key,
        false,
        Some(SIGNING_LEAF_OID),
    );
    let receipt = bc_sign(
        &payload_now(),
        &leaf_key,
        Hash::Sha256,
        &leaf,
        &chain(&[&leaf, &ca, &m.inter, &m.root]),
    );
    verifies("genuinely used exponent-3 chain", &receipt);
}

/// Mirrors `sharedModulusSiblingsStayDistinct`: two CAs over one modulus,
/// one with the held key's exponent and one with 17. The held key's
/// chain verifies; the sibling's garbage-issued leaf as signer is refused.
#[test]
fn shared_modulus_siblings_stay_distinct() {
    let m = material();
    let shared = Key::rsa();
    let modulus = shared.modulus();
    let ca_one = crafted(
        name("Shared Modulus CA"),
        rsa_spki(&modulus, E65537),
        name(INTER),
        &m.inter_key,
        true,
        Some(WWDR_OID),
    );
    let ca_two = crafted(
        name("Shared Modulus CA"),
        rsa_spki(&modulus, &[17]),
        name(INTER),
        &m.inter_key,
        true,
        Some(WWDR_OID),
    );
    let leaf_key = Key::rsa();
    let leaf_one = cert(
        name("Shared Modulus Signer"),
        &leaf_key,
        name("Shared Modulus CA"),
        &shared,
        false,
        Some(SIGNING_LEAF_OID),
    );
    let genuine = bc_sign(
        &payload_now(),
        &leaf_key,
        Hash::Sha256,
        &leaf_one,
        &chain(&[&leaf_one, &ca_one, &ca_two, &m.inter, &m.root]),
    );
    verifies("shared-modulus chain with the held key", &genuine);

    let sibling_leaf = garbage(CertSpec::suite(
        name("Shared Modulus Sibling Signer"),
        rsa_spki(&modulus, &[17]),
        name("Shared Modulus CA"),
        false,
        Some(SIGNING_LEAF_OID),
    ));
    let forged = bc_sign(
        &payload_now(),
        &m.leaf_key,
        Hash::Sha256,
        &sibling_leaf,
        &chain(&[&sibling_leaf, &ca_one, &ca_two, &m.inter, &m.root]),
    );
    refused(
        "shared-modulus sibling's garbage-issued signer",
        &forged,
        &[Reason::UntrustedChain],
    );
}

// --- 1990s identity tricks --------------------------------------------------------

/// Mirrors `dnSquattersAreInert`: garbage-signed lookalikes of the
/// intermediate and of the pinned root ride beside a genuine receipt;
/// the intermediate's lookalike as the signer is refused.
#[test]
fn dn_squatters_are_inert() {
    let m = material();
    let inter_squatter = garbage(CertSpec::suite(
        name(INTER),
        random_rsa_spki(2048, E65537),
        name(ROOT),
        true,
        Some(WWDR_OID),
    ));
    let root_squatter = garbage(CertSpec::suite(
        name(ROOT),
        random_rsa_spki(2048, E65537),
        name(ROOT),
        true,
        None,
    ));
    let receipt = bc_sign(
        &payload_now(),
        &m.leaf_key,
        Hash::Sha256,
        &m.leaf,
        &chain(&[&m.leaf, &m.inter, &m.root, &inter_squatter, &root_squatter]),
    );
    verifies("receipt beside intermediate and root squatters", &receipt);

    let as_signer = bc_sign(
        &payload_now(),
        &m.leaf_key,
        Hash::Sha256,
        &inter_squatter,
        &chain(&[&m.leaf, &m.inter, &m.root, &inter_squatter]),
    );
    refused(
        "intermediate squatter as signer",
        &as_signer,
        &[Reason::UntrustedChain],
    );
}

/// Mirrors `sidCollisionWithTheGenuineSignerStillVerifies`: a stranger
/// with the genuine signer's issuer and serial, another key and a garbage
/// signature. Beside the genuine signer the receipt verifies; alone it is
/// refused.
#[test]
fn sid_collision_with_the_genuine_signer_still_verifies() {
    let m = material();
    let mut spec = CertSpec::suite(
        name("Sid Colliding Signer"),
        random_rsa_spki(2048, E65537),
        name(INTER),
        false,
        Some(SIGNING_LEAF_OID),
    );
    spec.serial = pki::cert_fields(&m.leaf).serial;
    let stranger = garbage(spec);
    let beside = bc_sign(
        &payload_now(),
        &m.leaf_key,
        Hash::Sha256,
        &m.leaf,
        &chain(&[&m.leaf, &stranger, &m.inter, &m.root]),
    );
    verifies("genuine signer beside a sid-colliding stranger", &beside);

    let alone = bc_sign(
        &payload_now(),
        &m.leaf_key,
        Hash::Sha256,
        &m.leaf,
        &chain(&[&stranger, &m.inter, &m.root]),
    );
    refused(
        "sid-colliding stranger alone",
        &alone,
        &[Reason::UntrustedChain, Reason::Malformed],
    );
}

/// Mirrors `outlawSerialsAreHandledSafely`: a 33-octet serial and a zero
/// serial (RFC 5280 wants a positive serial of at most 20 octets), each
/// on a garbage-signed stranger: refused as the signer, inert as junk.
#[test]
fn outlaw_serials_are_handled_safely() {
    let m = material();
    let mut oversized = pki::random_modulus(263);
    oversized = pki::unsigned_integer(&oversized);
    for (what, serial) in [("33-byte", oversized), ("zero", vec![0x00])] {
        let mut spec = CertSpec::suite(
            name("Outlaw Serial Signer"),
            random_rsa_spki(2048, E65537),
            name(INTER),
            false,
            Some(SIGNING_LEAF_OID),
        );
        spec.serial = serial;
        let outlaw = garbage(spec);
        let as_signer = bc_sign(
            &payload_now(),
            &m.leaf_key,
            Hash::Sha256,
            &outlaw,
            &chain(&[&m.leaf, &m.inter, &m.root, &outlaw]),
        );
        refused(
            &format!("{what}-serial stranger as signer"),
            &as_signer,
            &[Reason::UntrustedChain],
        );
        let as_junk = bc_sign(
            &payload_now(),
            &m.leaf_key,
            Hash::Sha256,
            &m.leaf,
            &chain(&[&m.leaf, &m.inter, &m.root, &outlaw]),
        );
        verifies(&format!("{what}-serial stranger as bag junk"), &as_junk);
    }
}

// --- 2000s mesh abuse --------------------------------------------------------------

/// Mirrors `cycleMeshesAndNamedTwinsStayBounded`: two CAs that sign each
/// other, a leaf genuinely issued by one of them, and a root-issued twin
/// of the intermediate's own name with a leaf under it. A genuine receipt
/// beside all of them verifies, and so does one signed under the twin,
/// which a pinned root vouched for.
#[test]
fn cycle_meshes_and_named_twins_stay_bounded() {
    let m = material();
    let (mesh_a_key, mesh_b_key) = (Key::rsa(), Key::rsa());
    let mesh_a = cert(
        name("Mesh A"),
        &mesh_a_key,
        name("Mesh B"),
        &mesh_b_key,
        true,
        Some(WWDR_OID),
    );
    let mesh_b = cert(
        name("Mesh B"),
        &mesh_b_key,
        name("Mesh A"),
        &mesh_a_key,
        true,
        Some(WWDR_OID),
    );
    let mesh_c = cert(
        name("Mesh C"),
        &Key::rsa(),
        name("Mesh A"),
        &mesh_a_key,
        false,
        Some(SIGNING_LEAF_OID),
    );
    let (twin_key, twin_leaf_key) = (Key::rsa(), Key::rsa());
    let twin = cert(
        name(INTER),
        &twin_key,
        name(ROOT),
        &m.root_key,
        true,
        Some(WWDR_OID),
    );
    let twin_leaf = cert(
        name("Signer Under The Twin"),
        &twin_leaf_key,
        name(INTER),
        &twin_key,
        false,
        Some(SIGNING_LEAF_OID),
    );
    let receipt = bc_sign(
        &payload_now(),
        &m.leaf_key,
        Hash::Sha256,
        &m.leaf,
        &chain(&[
            &m.leaf, &m.inter, &twin, &twin_leaf, &mesh_a, &mesh_b, &mesh_c, &m.root,
        ]),
    );
    verifies("receipt beside cycles and a named twin", &receipt);

    let under_twin = bc_sign(
        &payload_now(),
        &twin_leaf_key,
        Hash::Sha256,
        &twin_leaf,
        &chain(&[&twin_leaf, &twin, &m.root]),
    );
    verifies("genuine leaf under the root-issued twin", &under_twin);
}

// --- 2010s CMS attribute abuse --------------------------------------------------

fn genuine_signed(attrs: Attrs, unsigned: &[Vec<u8>]) -> Vec<u8> {
    let m = material();
    bc_signed(
        &payload_now(),
        true,
        Hash::Sha256,
        &m.leaf_key.label(Hash::Sha256),
        &|data| m.leaf_key.sign(Hash::Sha256, data),
        &m.leaf,
        &chain(&[&m.leaf, &m.inter, &m.root]),
        attrs,
        unsigned,
    )
}

/// Mirrors `unsignedAttributesAreInert`: a garbage unsigned attribute,
/// covered by nothing, on a genuine receipt.
#[test]
fn unsigned_attributes_are_inert() {
    let unsigned = attribute("1.2.3.4.98", &[der(tag::OCTET_STRING, &[9, 9, 9, 9])]);
    verifies(
        "genuine receipt with an injected unsigned attribute",
        &genuine_signed(Attrs::Standard, &[unsigned]),
    );
}

/// Mirrors `messageDigestMismatchIsRefused`: a genuine signature over
/// signed attributes whose messageDigest names another payload's digest.
#[test]
fn message_digest_mismatch_is_refused() {
    let attributes = vec![
        attribute(pki::CONTENT_TYPE, &[der_oid(pki::ID_DATA)]),
        attribute(
            MESSAGE_DIGEST,
            &[der(
                tag::OCTET_STRING,
                &Hash::Sha256.digest(&[1, 1, 2, 3, 5, 8]),
            )],
        ),
    ];
    refused(
        "signed messageDigest naming another payload",
        &genuine_signed(Attrs::Custom(attributes), &[]),
        &[Reason::InvalidSignature, Reason::Malformed],
    );
}

/// Mirrors `directSignatureWithoutAttributesPrintsItsVerdict`: RFC 5652
/// allows a direct signature; whatever the verdict, it is bounded and
/// one of the reasons Java allows.
#[test]
fn direct_signature_without_attributes_prints_its_verdict() {
    let receipt = base64_encode(&genuine_signed(Attrs::Direct, &[]));
    let (result, cost) = timed(|| material().verifier.verify_receipt(&receipt));
    pki::print_verdict(PREFIX, "direct-signature receipt", cost, &result);
    assert!(cost < BUDGET, "the direct-signature receipt took {cost:?}");
    if let Err(failure) = result {
        assert!(
            [
                Reason::Malformed,
                Reason::InvalidSignature,
                Reason::UnreadablePayload
            ]
            .contains(&failure.reason()),
            "direct signature refused as {failure}"
        );
    }
}
