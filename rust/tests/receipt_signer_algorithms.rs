//! No algorithm or key-type allowlist on the receipt signer beyond what
//! OpenSSL implements.
//!
//! Apple signs receipts with RSA and SHA-1 or SHA-256 today, but a signer
//! that chains to a pinned root and carries Apple's marker is trusted
//! whatever it signs with, so a change on Apple's side does not reject
//! genuine receipts. The signature still has to hold as labelled.
//!
//! No test key here could sign as Apple, so each test mints its own small
//! PKI (root, WWDR-marked intermediate, marked signer) on P-256 with fixed
//! scalars, and pins that root. The RSA-PSS signer is an RSA-2048 key built
//! from two fixed primes, for this file only, so no test waits on key
//! generation. Keys and signatures come from OpenSSL.

mod common;

use apple_purchase_receipt_verifier::{Config, Reason, TrustAnchor, Verifier};
use common::mint::SigningKey;
use common::mint::{
    certificate, certificate_for_spki, key, name, RECEIPT_SIGNER_MARKER, WWDR_MARKER,
};
use common::{der, der_int, der_oid, der_seq, CmsBuilder};
use openssl::bn::{BigNum, BigNumContext};
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{PKey, Private};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{RsaPssSaltlen, Signer};

use common::mint::ECDSA_WITH_SHA256;
const ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
const ECDSA_WITH_SHA512: &str = "1.2.840.10045.4.3.4";
const SHA1: &str = "1.3.14.3.2.26";
const SHA224: &str = "2.16.840.1.101.3.4.2.4";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const SHA384: &str = "2.16.840.1.101.3.4.2.2";
const ECDSA_WITH_SHA224: &str = "1.2.840.10045.4.3.1";
const RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
const MGF1: &str = "1.2.840.113549.1.1.8";
const MD5: &str = "1.2.840.113549.2.5";
/// `id-ecPublicKey` as a `signatureAlgorithm`: names no hash, so the
/// `SignerInfo`'s digest is the one checked.
const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const SHA3_256: &str = "2.16.840.1.101.3.4.2.8";
/// An OID under the IANA example arc: no digest anyone implements.
const NO_SUCH_DIGEST: &str = "1.3.6.1.4.1.32473.1";
const SHA512: &str = "2.16.840.1.101.3.4.2.3";
const NOW: i64 = 1_735_689_600_000;

struct Pki {
    verifier: Verifier,
    signer_key: SigningKey,
    certificates: Vec<Vec<u8>>,
}

/// The minted chain, with `signer_spki` as the signer's key, or the P-256
/// `key(3)` when `None`.
fn pki_with(signer_spki: Option<Vec<u8>>) -> Pki {
    let (root_key, intermediate_key, signer_key) = (key(1), key(2), key(3));
    let root = certificate(
        "Test Root",
        &root_key,
        "Test Root",
        &root_key,
        1,
        true,
        None,
    );
    let intermediate = certificate(
        "Test WWDR",
        &intermediate_key,
        "Test Root",
        &root_key,
        2,
        true,
        Some(WWDR_MARKER),
    );
    let signer = certificate_for_spki(
        "Test Signer",
        signer_spki.unwrap_or_else(|| common::mint::spki(&signer_key)),
        "Test WWDR",
        &intermediate_key,
        3,
        false,
        Some(RECEIPT_SIGNER_MARKER),
    );
    let config = Config::builder()
        .roots([TrustAnchor::from_der(&root).unwrap()])
        .clock(|| NOW)
        .build()
        .unwrap();
    Pki {
        verifier: Verifier::new(config),
        signer_key,
        certificates: vec![signer, intermediate],
    }
}

fn pki() -> Pki {
    pki_with(None)
}

/// The shared receipt's content, signed by `pki`'s signer with no
/// signedAttrs, under the given digest and signatureAlgorithm labels.
fn receipt(pki: &Pki, digest_oid: &str, signature_oid: &str, signature: &[u8]) -> Vec<u8> {
    receipt_with_algorithm(
        pki,
        digest_oid,
        der_seq(&[der_oid(signature_oid)]),
        signature,
    )
}

fn receipt_with_algorithm(
    pki: &Pki,
    digest_oid: &str,
    signature_algorithm: Vec<u8>,
    signature: &[u8],
) -> Vec<u8> {
    let mut builder = CmsBuilder::from_shared();
    builder.certificates = pki.certificates.clone();
    builder.signer_issuer = name("Test WWDR");
    builder.signer_serial = vec![3];
    builder.signed_attrs = None;
    builder.digest_oid = digest_oid.to_owned();
    builder.signature_algorithm = signature_algorithm;
    builder.signature = signature.to_vec();
    builder.build()
}

fn content() -> Vec<u8> {
    CmsBuilder::from_shared().content.unwrap()
}

fn digest(md: MessageDigest, data: &[u8]) -> Vec<u8> {
    hash(md, data).unwrap().to_vec()
}

fn sign_prehash(key: &SigningKey, prehash: &[u8]) -> Vec<u8> {
    key.sign_prehash_der(prehash)
}

#[test]
fn the_control_an_ec_signer_under_the_pinned_root_verifies() {
    let pki = pki();
    let signature = pki.signer_key.sign_der(&content());
    let der = receipt(&pki, SHA256, ECDSA_WITH_SHA256, &signature);
    let payload = common::verify_der(&pki.verifier, &der).unwrap();
    assert_eq!(payload.bundle_id.as_deref(), Some("com.example.app"));
}

#[test]
fn a_digest_apple_does_not_use_today_verifies_when_the_signature_holds() {
    let pki = pki();
    for (digest_oid, signature_oid, prehash) in [
        (
            SHA224,
            ECDSA_WITH_SHA224,
            digest(MessageDigest::sha224(), &content()),
        ),
        (
            SHA384,
            ECDSA_WITH_SHA384,
            digest(MessageDigest::sha384(), &content()),
        ),
        (
            SHA512,
            ECDSA_WITH_SHA512,
            digest(MessageDigest::sha512(), &content()),
        ),
        // SHA3-256, which the pure-Rust core of 0.7 did not implement and
        // OpenSSL does: Java accepts it too (DECISIONS.md R20).
        (
            SHA3_256,
            ID_EC_PUBLIC_KEY,
            digest(MessageDigest::sha3_256(), &content()),
        ),
    ] {
        let signature = sign_prehash(&pki.signer_key, &prehash);
        let der = receipt(&pki, digest_oid, signature_oid, &signature);
        assert!(
            common::verify_der(&pki.verifier, &der).is_ok(),
            "{digest_oid} must verify"
        );
    }
}

#[test]
fn a_signature_that_does_not_hold_as_labelled_is_an_invalid_signature() {
    let pki = pki();
    // Signed over SHA-512, digestAlgorithm SHA-1: the digestAlgorithm is
    // what is checked.
    let signature = sign_prehash(
        &pki.signer_key,
        &digest(MessageDigest::sha512(), &content()),
    );
    let der = receipt(&pki, SHA1, ECDSA_WITH_SHA512, &signature);
    let failure = common::verify_der(&pki.verifier, &der).unwrap_err();
    assert_eq!(failure.reason(), Reason::InvalidSignature, "{failure}");
}

#[test]
fn an_md5_digest_under_the_pinned_root_verifies() {
    // Owner, 2026-09-27 (Q15): any digest the signer's pinned chain signed,
    // MD5 included, as Java accepts it. A relabelling attack needs an Apple
    // signature and a collision.
    let pki = pki();
    let signature = sign_prehash(&pki.signer_key, &digest(MessageDigest::md5(), &content()));
    let der = receipt(&pki, MD5, ID_EC_PUBLIC_KEY, &signature);
    assert!(common::verify_der(&pki.verifier, &der).is_ok());
}

#[test]
fn a_digest_openssl_does_not_implement_is_an_invalid_signature() {
    // A digest OID nobody implements: a signer naming it cannot be checked,
    // and fails as a signature.
    let pki = pki();
    let signature = pki.signer_key.sign_der(&content());
    let der = receipt(&pki, NO_SUCH_DIGEST, ID_EC_PUBLIC_KEY, &signature);
    let failure = common::verify_der(&pki.verifier, &der).unwrap_err();
    assert_eq!(failure.reason(), Reason::InvalidSignature, "{failure}");
}

#[test]
fn an_ecdsa_signature_verifies_under_its_digest_whatever_the_label_names() {
    // One genuine signature over SHA-256, the SignerInfo's digestAlgorithm.
    // OpenSSL checks it under that digest and, for an ECDSA key, does not
    // read the signatureAlgorithm, so a label naming another hash verifies
    // too. An ECDSA signature binds no hash, so the label is not a security
    // boundary; the shared case allows both answers (DECISIONS.md R20).
    let pki = pki();
    let signature = pki.signer_key.sign_der(&content());
    for label in [
        ECDSA_WITH_SHA256,
        ID_EC_PUBLIC_KEY,
        ECDSA_WITH_SHA224,
        ECDSA_WITH_SHA384,
        ECDSA_WITH_SHA512,
    ] {
        let der = receipt(&pki, SHA256, label, &signature);
        assert!(common::verify_der(&pki.verifier, &der).is_ok(), "{label}");
    }
}

// --- signed attributes: the rules OpenSSL enforces ---------------------------

const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const ID_DATA: &str = "1.2.840.113549.1.7.1";
const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

/// One `Attribute`, its values written in the order given. Callers give
/// them in DER order, as OpenSSL re-encodes them before it verifies.
fn attribute(oid: &str, values: &[Vec<u8>]) -> Vec<u8> {
    der_seq(&[der_oid(oid), der(0x31, &values.concat())])
}

fn content_type(values: &[&str]) -> Vec<u8> {
    let values: Vec<Vec<u8>> = values.iter().map(|oid| der_oid(oid)).collect();
    attribute(CONTENT_TYPE, &values)
}

fn message_digest(copies: usize) -> Vec<u8> {
    let value = der(0x04, &digest(MessageDigest::sha256(), &content()));
    attribute(MESSAGE_DIGEST, &vec![value; copies])
}

/// The shared content under `pki`'s signer with `attributes` as its
/// signedAttrs, in that order, and a genuine signature over exactly them:
/// OpenSSL verifies over the attributes in the order received. A refusal
/// is then the attribute rules' doing, not a signature that does not hold.
fn receipt_with_signed_attrs(pki: &Pki, attributes: &[Vec<u8>]) -> Vec<u8> {
    let body = attributes.concat();
    let mut builder = CmsBuilder::from_shared();
    builder.certificates = pki.certificates.clone();
    builder.signer_issuer = name("Test WWDR");
    builder.signer_serial = vec![3];
    builder.signed_attrs = Some(der(0xa0, &body));
    builder.digest_oid = SHA256.to_owned();
    builder.signature_algorithm = der_seq(&[der_oid(ECDSA_WITH_SHA256)]);
    builder.signature = pki.signer_key.sign_der(&der(0x31, &body));
    builder.build()
}

fn assert_invalid_signature(pki: &Pki, attributes: &[Vec<u8>]) {
    let der = receipt_with_signed_attrs(pki, attributes);
    let failure = common::verify_der(&pki.verifier, &der).unwrap_err();
    assert_eq!(failure.reason(), Reason::InvalidSignature, "{failure}");
}

#[test]
fn the_control_signed_attributes_built_here_verify() {
    // One contentType naming the eContentType and one messageDigest of the
    // content: the helpers above sign what OpenSSL checks.
    let pki = pki();
    let der = receipt_with_signed_attrs(&pki, &[content_type(&[ID_DATA]), message_digest(1)]);
    assert!(common::verify_der(&pki.verifier, &der).is_ok());
}

/// RFC 5652 section 5.3 allows one `contentType` attribute. The core does
/// not count them: `CMS_SignerInfo_verify` refuses the set in
/// `ossl_cms_si_check_attributes` before it checks the signature.
#[test]
fn a_content_type_attribute_twice_is_an_invalid_signature() {
    let pki = pki();
    let content_type = content_type(&[ID_DATA]);
    assert_invalid_signature(
        &pki,
        &[content_type.clone(), content_type, message_digest(1)],
    );
}

/// A `contentType` attribute holds exactly one value; the first one here
/// names the eContentType, so the core's own comparison passes and the
/// refusal is OpenSSL's (`ossl_cms_si_check_attributes`).
#[test]
fn a_content_type_attribute_with_two_values_is_an_invalid_signature() {
    let pki = pki();
    assert_invalid_signature(
        &pki,
        &[content_type(&[ID_DATA, ID_SIGNED_DATA]), message_digest(1)],
    );
}

/// A `messageDigest` attribute holds exactly one value, even when both are
/// the content's digest (`ossl_cms_si_check_attributes`).
#[test]
fn a_message_digest_attribute_with_two_values_is_an_invalid_signature() {
    let pki = pki();
    assert_invalid_signature(&pki, &[content_type(&[ID_DATA]), message_digest(2)]);
}

/// An empty signedAttrs (`A0 00`), genuinely signed. OpenSSL's attribute
/// rules require `contentType` and `messageDigest` only when the set has
/// at least one attribute (`ossl_cms_si_check_attributes` in
/// `crypto/cms/cms_att.c`), so `CMS_SignerInfo_verify` accepts the
/// signature over the empty set. The refusal comes after it:
/// `CMS_SignerInfo_verify_content` looks for the `messageDigest` whenever
/// the field is present and fails without one (`crypto/cms/cms_sd.c`).
#[test]
fn an_empty_signed_attrs_set_is_an_invalid_signature() {
    let pki = pki();
    assert_invalid_signature(&pki, &[]);
}

// --- RSASSA-PSS ------------------------------------------------------------

/// A fixed RSA-2048 test key: two 1024-bit primes found once with a seeded
/// Miller-Rabin search. It signs nothing outside this file.
fn pss_key() -> PKey<Private> {
    let p = BigNum::from_hex_str(concat!(
        "fc9b3a6af4c921059147d0a57ba46848567e8f477f8bf1fd75a4c97f4fad4a79",
        "df3c75de5d9f6b19c5dd895be1441068ac432254c5a4a27f8f3c0b82c1c3b833",
        "a8f3a554d792006087926cc36c20d7735193809c5c42dd6882f5bce002f06334",
        "181437dcd7eeda787f11964f3a54fea974934fcfce382d0d6b011e6048a1d101",
    ))
    .unwrap();
    let q = BigNum::from_hex_str(concat!(
        "e4ff0b3817ba3d75741cb558108c6a152c21d90154fb4dc1422362501a0d1549",
        "d6ca48f03589ad19b1b3e8f30dcc19d61a99336cc4031d3de042a2719cdf4f46",
        "633c0ba4dfed762cfb028e0267ba0f3169ec4c9e6e6e39e851cdc9e0315e21e1",
        "da67b7601377123d70162811d97e5bb46576579f92a5f6afb757abd656484e8b",
    ))
    .unwrap();
    let mut context = BigNumContext::new().unwrap();
    let one = BigNum::from_u32(1).unwrap();
    let e = BigNum::from_u32(65_537).unwrap();
    let mut n = BigNum::new().unwrap();
    n.checked_mul(&p, &q, &mut context).unwrap();
    let (mut p1, mut q1, mut phi) = (
        BigNum::new().unwrap(),
        BigNum::new().unwrap(),
        BigNum::new().unwrap(),
    );
    p1.checked_sub(&p, &one).unwrap();
    q1.checked_sub(&q, &one).unwrap();
    phi.checked_mul(&p1, &q1, &mut context).unwrap();
    let mut d = BigNum::new().unwrap();
    d.mod_inverse(&e, &phi, &mut context).unwrap();
    let (mut dmp1, mut dmq1, mut iqmp) = (
        BigNum::new().unwrap(),
        BigNum::new().unwrap(),
        BigNum::new().unwrap(),
    );
    dmp1.nnmod(&d, &p1, &mut context).unwrap();
    dmq1.nnmod(&d, &q1, &mut context).unwrap();
    iqmp.mod_inverse(&q, &p, &mut context).unwrap();
    let rsa = Rsa::from_private_components(n, e, d, p, q, dmp1, dmq1, iqmp).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

fn rsa_spki(key: &PKey<Private>) -> Vec<u8> {
    key.public_key_to_der().unwrap()
}

/// A PKCS#1 v1.5 signature of `data` over `md`.
fn pkcs1_sign(key: &PKey<Private>, md: MessageDigest, data: &[u8]) -> Vec<u8> {
    let mut signer = Signer::new(md, key).unwrap();
    signer.sign_oneshot_to_vec(data).unwrap()
}

/// `RSASSA-PSS-params` naming `hash_oid` for the hash and MGF1, and a salt
/// length.
fn pss_algorithm(hash_oid: &str, salt_length: u64) -> Vec<u8> {
    let hash = der_seq(&[der_oid(hash_oid), der(0x05, &[])]);
    der_seq(&[
        der_oid(RSASSA_PSS),
        der_seq(&[
            der(0xA0, &hash),
            der(0xA1, &der_seq(&[der_oid(MGF1), hash.clone()])),
            der(0xA2, &der_int(salt_length)),
        ]),
    ])
}

/// A PSS signature of `content` over `md` and MGF1 with `md`, with a salt of
/// `salt_length` bytes.
fn pss_sign_with(
    key: &PKey<Private>,
    md: MessageDigest,
    salt_length: i32,
    content: &[u8],
) -> Vec<u8> {
    let mut signer = Signer::new(md, key).unwrap();
    signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
    signer
        .set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt_length))
        .unwrap();
    signer.set_rsa_mgf1_md(md).unwrap();
    signer.sign_oneshot_to_vec(content).unwrap()
}

fn pss_sign(key: &PKey<Private>, content: &[u8]) -> Vec<u8> {
    pss_sign_with(key, MessageDigest::sha256(), 32, content)
}

#[test]
fn an_rsa_pss_signer_under_the_pinned_root_verifies() {
    let key = pss_key();
    let pki = pki_with(Some(rsa_spki(&key)));
    let signature = pss_sign(&key, &content());
    let der = receipt_with_algorithm(&pki, SHA256, pss_algorithm(SHA256, 32), &signature);
    let payload = common::verify_der(&pki.verifier, &der).unwrap();
    assert_eq!(payload.bundle_id.as_deref(), Some("com.example.app"));
}

#[test]
fn an_rsa_pss_signature_over_other_content_or_parameters_is_an_invalid_signature() {
    let key = pss_key();
    let pki = pki_with(Some(rsa_spki(&key)));
    let mut tampered = content();
    if let Some(last) = tampered.last_mut() {
        *last ^= 0x01;
    }
    let over_other_content = pss_sign(&key, &tampered);
    let genuine = pss_sign(&key, &content());
    for (algorithm, signature) in [
        (pss_algorithm(SHA256, 32), over_other_content),
        // The parameters are part of what is checked: the right signature
        // under another salt length, or another hash, does not hold.
        (pss_algorithm(SHA256, 20), genuine.clone()),
        (pss_algorithm(SHA384, 32), genuine.clone()),
        // And a PSS signature labelled PKCS#1 v1.5 is not one.
        (
            der_seq(&[der_oid("1.2.840.113549.1.1.11"), der(0x05, &[])]),
            genuine,
        ),
    ] {
        let der = receipt_with_algorithm(&pki, SHA256, algorithm, &signature);
        let failure = common::verify_der(&pki.verifier, &der).unwrap_err();
        assert_eq!(failure.reason(), Reason::InvalidSignature, "{failure}");
    }
}

// --- certificate signature algorithms --------------------------------------

/// Every certificate signature algorithm OpenSSL verifies is accepted
/// under the pinned chain (owner, 2026-09-27: no stricter list than what the
/// library itself refuses). An intermediate signed by the pinned root with
/// each one is authenticated, top-down, by that root.
#[test]
fn every_certificate_signature_algorithm_openssl_verifies_is_accepted() {
    use apple_purchase_receipt_verifier::__internal::path::{self, Certificate};
    use common::mint::{assemble, spki, tbs};

    let intermediate_spki = spki(&key(2));
    let intermediate = |algorithm: Vec<u8>, sign: &dyn Fn(&[u8]) -> Vec<u8>| {
        let tbs = tbs(
            "Test WWDR",
            intermediate_spki.clone(),
            "Test Root",
            2,
            true,
            None,
            &algorithm,
        );
        let signature = sign(&tbs);
        Certificate::from_der(&assemble(tbs, algorithm, &signature)).unwrap()
    };
    let authenticated = |root: &[u8], certificate: &Certificate| {
        let roots = [TrustAnchor::from_der(root).unwrap()];
        path::authenticated_top_down(std::slice::from_ref(certificate), &roots).len() == 1
    };

    // ECDSA, over a P-256 root, with every digest the crate computes.
    let ec_root_key = key(1);
    let ec_root = certificate(
        "Test Root",
        &ec_root_key,
        "Test Root",
        &ec_root_key,
        1,
        true,
        None,
    );
    let ecdsa = |oid: &str, prehash: Vec<u8>| {
        let signature = ec_root_key.sign_prehash_der(&prehash);
        intermediate(der_seq(&[der_oid(oid)]), &|_| signature.clone())
    };
    let tbs_bytes = |algorithm: &str| {
        tbs(
            "Test WWDR",
            intermediate_spki.clone(),
            "Test Root",
            2,
            true,
            None,
            &der_seq(&[der_oid(algorithm)]),
        )
    };
    for (oid, prehash) in [
        (
            "1.2.840.10045.4.1",
            digest(MessageDigest::sha1(), &tbs_bytes("1.2.840.10045.4.1")),
        ),
        (
            "1.2.840.10045.4.3.1",
            digest(MessageDigest::sha224(), &tbs_bytes("1.2.840.10045.4.3.1")),
        ),
        (
            "1.2.840.10045.4.3.2",
            digest(MessageDigest::sha256(), &tbs_bytes("1.2.840.10045.4.3.2")),
        ),
        (
            "1.2.840.10045.4.3.3",
            digest(MessageDigest::sha384(), &tbs_bytes("1.2.840.10045.4.3.3")),
        ),
        (
            "1.2.840.10045.4.3.4",
            digest(MessageDigest::sha512(), &tbs_bytes("1.2.840.10045.4.3.4")),
        ),
    ] {
        assert!(authenticated(&ec_root, &ecdsa(oid, prehash)), "{oid}");
    }

    // RSA PKCS#1 v1.5 and PSS, over an RSA root.
    let rsa_key = pss_key();
    let rsa_root = {
        let algorithm = der_seq(&[der_oid("1.2.840.113549.1.1.11"), der(0x05, &[])]);
        let tbs = tbs(
            "Test Root",
            rsa_spki(&rsa_key),
            "Test Root",
            1,
            true,
            None,
            &algorithm,
        );
        let signature = pkcs1_sign(&rsa_key, MessageDigest::sha256(), &tbs);
        assemble(tbs, algorithm, &signature)
    };
    let pkcs1 = |oid: &str, md: MessageDigest| {
        intermediate(der_seq(&[der_oid(oid), der(0x05, &[])]), &|tbs| {
            pkcs1_sign(&rsa_key, md, tbs)
        })
    };
    for (oid, certificate) in [
        (
            "sha1WithRSAEncryption",
            pkcs1("1.2.840.113549.1.1.5", MessageDigest::sha1()),
        ),
        (
            "sha224WithRSAEncryption",
            pkcs1("1.2.840.113549.1.1.14", MessageDigest::sha224()),
        ),
        (
            "sha512WithRSAEncryption",
            pkcs1("1.2.840.113549.1.1.13", MessageDigest::sha512()),
        ),
        (
            "RSASSA-PSS",
            intermediate(pss_algorithm(SHA384, 48), &|tbs| {
                pss_sign_with(&rsa_key, MessageDigest::sha384(), 48, tbs)
            }),
        ),
    ] {
        assert!(authenticated(&rsa_root, &certificate), "{oid}");
    }

    // MD5 with RSA too (Q14). DSA with SHA-256 over the RSA root's key is
    // not authenticated: the algorithm does not match the issuer's key, so
    // its signature bytes are never read.
    let md5 = pkcs1("1.2.840.113549.1.1.4", MessageDigest::md5());
    assert!(authenticated(&rsa_root, &md5), "md5WithRSAEncryption");
    let dsa = intermediate(der_seq(&[der_oid("2.16.840.1.101.3.4.3.2")]), &|_| {
        vec![0; 64]
    });
    assert!(!authenticated(&rsa_root, &dsa));
}
