//! No algorithm or key-type allowlist on the receipt signer beyond what the
//! crate implements.
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
//! generation.

mod common;

use apple_purchase_receipt_verifier::{Config, Reason, TrustAnchor, Verifier};
use common::mint::{
    certificate, certificate_for_spki, key, name, RECEIPT_SIGNER_MARKER, WWDR_MARKER,
};
use common::{der, der_int, der_oid, der_seq, CmsBuilder};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use rsa::rand_core::{CryptoRng, RngCore};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, Pss, RsaPrivateKey};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

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
const SHA3_256: &str = "2.16.840.1.101.3.4.2.8";
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

fn sign_prehash(key: &SigningKey, prehash: &[u8]) -> Vec<u8> {
    let signature: p256::ecdsa::Signature = key.sign_prehash(prehash).unwrap();
    signature.to_der().as_bytes().to_vec()
}

#[test]
fn the_control_an_ec_signer_under_the_pinned_root_verifies() {
    let pki = pki();
    let signature: DerSignature = pki.signer_key.sign(&content());
    let der = receipt(&pki, SHA256, ECDSA_WITH_SHA256, signature.as_bytes());
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
            Sha224::digest(content()).to_vec(),
        ),
        (
            SHA384,
            ECDSA_WITH_SHA384,
            Sha384::digest(content()).to_vec(),
        ),
        (
            SHA512,
            ECDSA_WITH_SHA512,
            Sha512::digest(content()).to_vec(),
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
    // Signed over SHA-512, labelled SHA-1: the label is what is checked.
    let signature = sign_prehash(&pki.signer_key, &Sha512::digest(content()));
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
    let signature = sign_prehash(&pki.signer_key, &md5::Md5::digest(content()));
    let der = receipt(&pki, MD5, ECDSA_WITH_SHA256, &signature);
    assert!(common::verify_der(&pki.verifier, &der).is_ok());
}

#[test]
fn a_digest_the_crate_does_not_implement_is_an_invalid_signature() {
    // SHA3-256: a real digest no crate here implements, so a signer naming
    // it cannot be checked and fails as a signature.
    let pki = pki();
    let signature: DerSignature = pki.signer_key.sign(&content());
    let der = receipt(&pki, SHA3_256, ECDSA_WITH_SHA256, signature.as_bytes());
    let failure = common::verify_der(&pki.verifier, &der).unwrap_err();
    assert_eq!(failure.reason(), Reason::InvalidSignature, "{failure}");
}

// --- RSASSA-PSS ------------------------------------------------------------

/// A fixed RSA-2048 test key: two 1024-bit primes found once with a seeded
/// Miller-Rabin search. It signs nothing outside this file.
fn pss_key() -> RsaPrivateKey {
    let p = BigUint::parse_bytes(
        b"fc9b3a6af4c921059147d0a57ba46848567e8f477f8bf1fd75a4c97f4fad4a79\
          df3c75de5d9f6b19c5dd895be1441068ac432254c5a4a27f8f3c0b82c1c3b833\
          a8f3a554d792006087926cc36c20d7735193809c5c42dd6882f5bce002f06334\
          181437dcd7eeda787f11964f3a54fea974934fcfce382d0d6b011e6048a1d101",
        16,
    )
    .unwrap();
    let q = BigUint::parse_bytes(
        b"e4ff0b3817ba3d75741cb558108c6a152c21d90154fb4dc1422362501a0d1549\
          d6ca48f03589ad19b1b3e8f30dcc19d61a99336cc4031d3de042a2719cdf4f46\
          633c0ba4dfed762cfb028e0267ba0f3169ec4c9e6e6e39e851cdc9e0315e21e1\
          da67b7601377123d70162811d97e5bb46576579f92a5f6afb757abd656484e8b",
        16,
    )
    .unwrap();
    RsaPrivateKey::from_p_q(p, q, BigUint::from(65_537u32)).unwrap()
}

fn rsa_spki(key: &RsaPrivateKey) -> Vec<u8> {
    let integer = |value: &BigUint| {
        let mut bytes = value.to_bytes_be();
        if bytes.first().is_some_and(|b| *b >= 0x80) {
            bytes.insert(0, 0);
        }
        der(0x02, &bytes)
    };
    let mut bits = vec![0x00];
    bits.extend_from_slice(&der_seq(&[integer(key.n()), integer(key.e())]));
    der_seq(&[
        der_seq(&[der_oid("1.2.840.113549.1.1.1"), der(0x05, &[])]),
        der(0x03, &bits),
    ])
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

/// A fixed byte stream for the PSS salt: the salt is part of what is
/// signed, not a secret, and a fixed one keeps the test replayable.
struct FixedSalt(u8);

impl RngCore for FixedSalt {
    fn next_u32(&mut self) -> u32 {
        u32::from(self.next_u8())
    }
    fn next_u64(&mut self) -> u64 {
        u64::from(self.next_u8())
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.next_u8();
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl FixedSalt {
    fn next_u8(&mut self) -> u8 {
        self.0 = self.0.wrapping_mul(29).wrapping_add(7);
        self.0
    }
}

impl CryptoRng for FixedSalt {}

fn pss_sign(key: &RsaPrivateKey, content: &[u8]) -> Vec<u8> {
    key.sign_with_rng(
        &mut FixedSalt(1),
        Pss::new_with_salt::<Sha256>(32),
        &Sha256::digest(content),
    )
    .unwrap()
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

/// Every certificate signature algorithm the crypto crates verify is
/// accepted under the pinned chain (owner, 2026-09-27: no stricter list than
/// what the library itself refuses). An intermediate signed by the pinned
/// root with each one is authenticated, top-down, by that root.
#[test]
fn every_certificate_signature_algorithm_the_crates_verify_is_accepted() {
    use apple_purchase_receipt_verifier::__internal::{chain, x509::Certificate};
    use common::mint::{assemble, spki, tbs};
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    use rsa::Pkcs1v15Sign;
    use sha1::Sha1;

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
        chain::authenticated_top_down(std::slice::from_ref(certificate), &roots)
            .certificates()
            .len()
            == 1
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
        let signature: p256::ecdsa::Signature = ec_root_key.sign_prehash(&prehash).unwrap();
        intermediate(der_seq(&[der_oid(oid)]), &|_| {
            signature.to_der().as_bytes().to_vec()
        })
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
            Sha1::digest(tbs_bytes("1.2.840.10045.4.1")).to_vec(),
        ),
        (
            "1.2.840.10045.4.3.1",
            Sha224::digest(tbs_bytes("1.2.840.10045.4.3.1")).to_vec(),
        ),
        (
            "1.2.840.10045.4.3.2",
            Sha256::digest(tbs_bytes("1.2.840.10045.4.3.2")).to_vec(),
        ),
        (
            "1.2.840.10045.4.3.3",
            Sha384::digest(tbs_bytes("1.2.840.10045.4.3.3")).to_vec(),
        ),
        (
            "1.2.840.10045.4.3.4",
            Sha512::digest(tbs_bytes("1.2.840.10045.4.3.4")).to_vec(),
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
        let signature = rsa_key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&tbs))
            .unwrap();
        assemble(tbs, algorithm, &signature)
    };
    let pkcs1 = |oid: &str, padding: Pkcs1v15Sign, digest: fn(&[u8]) -> Vec<u8>| {
        intermediate(der_seq(&[der_oid(oid), der(0x05, &[])]), &|tbs| {
            rsa_key.sign(padding.clone(), &digest(tbs)).unwrap()
        })
    };
    for (oid, certificate) in [
        (
            "sha1WithRSAEncryption",
            pkcs1("1.2.840.113549.1.1.5", Pkcs1v15Sign::new::<Sha1>(), |t| {
                Sha1::digest(t).to_vec()
            }),
        ),
        (
            "sha224WithRSAEncryption",
            pkcs1(
                "1.2.840.113549.1.1.14",
                Pkcs1v15Sign::new::<Sha224>(),
                |t| Sha224::digest(t).to_vec(),
            ),
        ),
        (
            "sha512WithRSAEncryption",
            pkcs1(
                "1.2.840.113549.1.1.13",
                Pkcs1v15Sign::new::<Sha512>(),
                |t| Sha512::digest(t).to_vec(),
            ),
        ),
        (
            "RSASSA-PSS",
            intermediate(pss_algorithm(SHA384, 48), &|tbs| {
                rsa_key
                    .sign_with_rng(
                        &mut FixedSalt(3),
                        Pss::new_with_salt::<Sha384>(48),
                        &Sha384::digest(tbs),
                    )
                    .unwrap()
            }),
        ),
    ] {
        assert!(authenticated(&rsa_root, &certificate), "{oid}");
    }

    // MD5 with RSA too (Q14), and DSA with SHA-256, which no crate here
    // implements, is not authenticated. Its signature bytes do not matter;
    // nothing gets far enough to read them.
    let md5 = pkcs1(
        "1.2.840.113549.1.1.4",
        Pkcs1v15Sign::new::<md5::Md5>(),
        |t| md5::Md5::digest(t).to_vec(),
    );
    assert!(authenticated(&rsa_root, &md5), "md5WithRSAEncryption");
    let dsa = intermediate(der_seq(&[der_oid("2.16.840.1.101.3.4.3.2")]), &|_| {
        vec![0; 64]
    });
    assert!(!authenticated(&rsa_root, &dsa));
}
