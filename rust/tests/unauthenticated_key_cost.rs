//! Certificates nobody trusted yet must cost almost nothing to reject.
//!
//! An RSA public-key operation costs what the key's owner chose: the modulus
//! size and the exponent. This crate caps the modulus at 8192 bits and the
//! `rsa` crate caps the exponent at 2^33 - 1, and a signature is only
//! exponentiated when it is as long as the modulus, so the most expensive
//! check an attacker can buy is a certificate of their own with such a key
//! and a signature to match: about 40 ms each in a debug build. A receipt
//! whose signer and nine padding certificates are all the attacker's, named
//! as issuers of one another, with every `SignerInfo` the cap allows naming
//! that signer, made the old bottom-up walk run 36 of them, 1.4 s. The walk
//! now starts from the pinned roots, so a key no root vouched for is never
//! used, and the same receipt is refused in about 1.5 ms.
//!
//! The bounds are set for `cargo test`'s debug profile: for the refusals the
//! regression is about thirty times the bound and the fixed path a thirtieth
//! of it.
//!
//! What made the Java fix urgent does not carry over: BouncyCastle ran a
//! primality test while decoding an RSA key, seconds for a 16384-bit
//! modulus, before any signature. The `rsa` crate does no such test, and a
//! modulus over 8192 bits is refused before any arithmetic. The walk order
//! is the part that does carry over, and it is what these tests pin.

mod common;

use apple_purchase_receipt_verifier::__internal::asn1::tag;
use apple_purchase_receipt_verifier::__internal::x509::Certificate;
use apple_purchase_receipt_verifier::__internal::{base64_encode, chain, keys_used_during};
use apple_purchase_receipt_verifier::Reason;
use common::{der, der_int, der_oid, der_seq, CmsBuilder};
use std::time::{Duration, Instant};

/// For a receipt that verifies: a debug-build verify of the padded
/// receipts takes about 15 ms.
const BOUND: Duration = Duration::from_millis(200);

/// For an input refused before any signature it carries is checked: about
/// 1.5 ms in a debug build, against 1.4 s for the regression.
const REFUSAL_BOUND: Duration = Duration::from_millis(50);

const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const LEAF_MARKER: &str = "1.2.840.113635.100.6.11.1";
const INTERMEDIATE_MARKER: &str = "1.2.840.113635.100.6.2.1";

/// The most expensive RSA key the crate accepts: an 8192-bit odd modulus
/// and the largest exponent the `rsa` crate allows.
fn expensive_spki() -> Vec<u8> {
    let mut modulus = vec![0x00];
    modulus.extend(std::iter::repeat_n(0xFF, 1024));
    let exponent = der_int((1 << 33) - 1);
    let key = der_seq(&[der(tag::INTEGER, &modulus), exponent]);
    let mut bits = vec![0x00];
    bits.extend_from_slice(&key);
    der_seq(&[
        der_seq(&[der_oid(OID_RSA_ENCRYPTION), der(0x05, &[])]),
        der(0x03, &bits),
    ])
}

/// A certificate carrying [`expensive_spki`], with the given Name TLVs, a
/// serial, optionally a marker extension, and a signature as long as an
/// 8192-bit key's, so every check up to the modular exponentiation passes.
/// Nobody signed it.
fn expensive_certificate(
    subject: &[u8],
    issuer: &[u8],
    serial: u64,
    marker: Option<&str>,
) -> Vec<u8> {
    stranger(subject, issuer, serial, marker, expensive_spki())
}

/// An RSA key over the crate's cap: a 16384-bit modulus.
fn oversized_spki() -> Vec<u8> {
    let mut modulus = vec![0x00];
    modulus.extend(std::iter::repeat_n(0xFF, 2048));
    rsa_spki_of(&der_seq(&[der(tag::INTEGER, &modulus), der_int(65_537)]))
}

/// An RSA key whose bits are not an `RSAPublicKey` at all.
fn broken_rsa_spki() -> Vec<u8> {
    rsa_spki_of(b"not an RSAPublicKey")
}

/// A P-256 key whose point is not on the curve.
fn broken_ec_spki() -> Vec<u8> {
    let mut point = vec![0x00, 0x04];
    point.extend(std::iter::repeat_n(0x01, 64));
    der_seq(&[
        der_seq(&[der_oid("1.2.840.10045.2.1"), der_oid("1.2.840.10045.3.1.7")]),
        der(0x03, &point),
    ])
}

fn rsa_spki_of(key: &[u8]) -> Vec<u8> {
    let mut bits = vec![0x00];
    bits.extend_from_slice(key);
    der_seq(&[
        der_seq(&[der_oid(OID_RSA_ENCRYPTION), der(0x05, &[])]),
        der(0x03, &bits),
    ])
}

/// Every kind of stranger key: the costliest the crate accepts, one over its
/// cap, and two that do not decode as keys at all.
fn stranger_spkis() -> [Vec<u8>; 4] {
    [
        expensive_spki(),
        oversized_spki(),
        broken_rsa_spki(),
        broken_ec_spki(),
    ]
}

/// As [`expensive_certificate`], with any SPKI.
fn stranger(
    subject: &[u8],
    issuer: &[u8],
    serial: u64,
    marker: Option<&str>,
    spki: Vec<u8>,
) -> Vec<u8> {
    let algorithm = der_seq(&[der_oid(OID_SHA256_WITH_RSA), der(0x05, &[])]);
    let mut extensions = vec![der_seq(&[
        der_oid(OID_BASIC_CONSTRAINTS),
        der(0x01, &[0xFF]),
        der(tag::OCTET_STRING, &der_seq(&[der(0x01, &[0xFF])])),
    ])];
    if let Some(oid) = marker {
        extensions.push(der_seq(&[
            der_oid(oid),
            der(tag::OCTET_STRING, &[0x05, 0x00]),
        ]));
    }
    let tbs = der_seq(&[
        der(tag::CONTEXT_0, &der_int(2)),
        der_int(serial),
        algorithm.clone(),
        issuer.to_vec(),
        der_seq(&[der(0x17, b"200101000000Z"), der(0x18, b"20991231000000Z")]),
        subject.to_vec(),
        spki,
        der(0xA3, &der_seq(&extensions)),
    ]);
    let mut signature = vec![0x00, 0x7F];
    signature.extend(std::iter::repeat_n(0x5A, 1023));
    let certificate = der_seq(&[tbs, algorithm, der(0x03, &signature)]);
    Certificate::from_der(&certificate).expect("a stranger certificate must still parse");
    certificate
}

fn parsed(der: &[u8]) -> Certificate {
    Certificate::from_der(der).unwrap()
}

fn root() -> Certificate {
    parsed(common::receipt_root().der())
}

/// The shared receipt's signer and WWDR intermediate, in that order.
fn signer_and_intermediate(builder: &CmsBuilder) -> (Vec<u8>, Vec<u8>) {
    let signer = builder
        .certificates
        .iter()
        .find(|raw| parsed(raw).serial_number() == builder.signer_serial.as_slice())
        .unwrap()
        .clone();
    let issuer = parsed(&signer).issuer_der().to_vec();
    let intermediate = builder
        .certificates
        .iter()
        .find(|raw| parsed(raw).subject_der() == issuer.as_slice())
        .unwrap()
        .clone();
    (signer, intermediate)
}

fn assert_fast(start: Instant) {
    let elapsed = start.elapsed();
    assert!(elapsed < BOUND, "took {elapsed:?}");
}

/// The direct statement behind the timing: no signature was checked with
/// any key a stranger certificate carries.
fn assert_no_stranger_key_used(used: &[Vec<u8>]) {
    let strangers = stranger_spkis();
    assert!(
        used.iter().all(|spki| !strangers.contains(spki)),
        "a stranger's key checked a signature ({} checks in all)",
        used.len()
    );
}

fn assert_refused_fast(start: Instant) {
    let elapsed = start.elapsed();
    assert!(elapsed < REFUSAL_BOUND, "took {elapsed:?}");
}

#[test]
fn a_genuine_receipt_padded_with_stranger_keys_verifies_quickly() {
    let mut builder = CmsBuilder::from_shared();
    let (signer, intermediate) = signer_and_intermediate(&builder);
    let intermediate_name = parsed(&intermediate).subject_der().to_vec();
    let root_name = root().subject_der().to_vec();
    // The padding comes first, so a walk that tried embedded keys in order
    // would try every one of them before the genuine intermediate.
    let spkis = stranger_spkis();
    let mut certificates: Vec<Vec<u8>> = (0..8u64)
        .zip(spkis.iter().cycle())
        .map(|(serial, spki)| {
            stranger(
                &intermediate_name,
                &root_name,
                100 + serial,
                None,
                spki.clone(),
            )
        })
        .collect();
    certificates.push(signer);
    certificates.push(intermediate);
    builder.certificates = certificates;
    let receipt = builder.build();

    let verifier = common::receipt_verifier();
    let start = Instant::now();
    let (payload, used) = keys_used_during(|| common::verify_der(&verifier, &receipt));
    assert_fast(start);
    assert_no_stranger_key_used(&used);
    assert_eq!(
        payload.unwrap().bundle_id.as_deref(),
        Some("com.example.app")
    );
}

#[test]
fn a_receipt_whose_only_issuers_have_expensive_keys_is_refused_quickly() {
    let mut builder = CmsBuilder::from_shared();
    let (_, intermediate) = signer_and_intermediate(&builder);
    let intermediate_name = parsed(&intermediate).subject_der().to_vec();
    // The signer is the attacker's too, so its signature is as long as the
    // expensive keys and every one of them gets as far as the modular
    // exponentiation. Each padding certificate names the intermediate as
    // subject and issuer, so each is a candidate issuer of the signer, and
    // every SignerInfo the cap allows names the same signer.
    let signer = expensive_certificate(&der_seq(&[]), &intermediate_name, 99, Some(LEAF_MARKER));
    let mut certificates: Vec<Vec<u8>> = (0..9)
        .map(|serial| {
            expensive_certificate(&intermediate_name, &intermediate_name, 100 + serial, None)
        })
        .collect();
    certificates.push(signer);
    builder.certificates = certificates;
    builder.signer_issuer = intermediate_name;
    builder.signer_serial = vec![99];
    builder.signer_info_copies = 4;
    let receipt = builder.build();

    let verifier = common::receipt_verifier();
    let start = Instant::now();
    let (result, used) = keys_used_during(|| common::verify_der(&verifier, &receipt));
    assert_refused_fast(start);
    assert_no_stranger_key_used(&used);
    let failure = result.unwrap_err();
    assert_eq!(failure.reason(), Reason::UntrustedChain, "{failure}");
}

#[test]
fn a_jws_whose_certificates_have_expensive_keys_is_refused_quickly() {
    let jws_root = parsed(common::jws_root().der());
    let root_name = jws_root.subject_der().to_vec();
    let intermediate_name = der_seq(&[]);
    let leaf = expensive_certificate(&der_seq(&[]), &intermediate_name, 1, Some(LEAF_MARKER));
    let intermediate =
        expensive_certificate(&intermediate_name, &root_name, 2, Some(INTERMEDIATE_MARKER));
    let fake_root = expensive_certificate(&root_name, &root_name, 3, None);
    let header = format!(
        r#"{{"alg":"ES256","x5c":["{}","{}","{}"]}}"#,
        base64_encode(&leaf),
        base64_encode(&intermediate),
        base64_encode(&fake_root)
    );
    let jws = common::join_jws(
        &common::base64url(header.as_bytes()),
        &common::base64url(b"{}"),
        &common::base64url(&[0; 64]),
    );

    let verifier = common::jws_verifier();
    let start = Instant::now();
    let (result, used) = keys_used_during(|| verifier.verify_signed_data(&jws));
    assert_refused_fast(start);
    assert_no_stranger_key_used(&used);
    let failure = result.unwrap_err();
    assert_eq!(failure.reason(), Reason::UntrustedChain, "{failure}");
    // One capped signature check is too cheap to time, so the order is
    // pinned by what refused it: the intermediate, under the root's key,
    // before the leaf is ever checked under the intermediate's.
    assert_eq!(
        failure.message(),
        "intermediate is not issued by a pinned root"
    );
}

#[test]
fn only_certificates_a_root_vouched_for_reach_the_path_builder() {
    let builder = CmsBuilder::from_shared();
    let (signer, intermediate) = signer_and_intermediate(&builder);
    let intermediate_name = parsed(&intermediate).subject_der().to_vec();
    let embedded = vec![
        parsed(&expensive_certificate(
            &intermediate_name,
            &intermediate_name,
            100,
            None,
        )),
        parsed(&signer),
        parsed(&intermediate),
    ];
    let roots = [common::receipt_root()];
    let authenticated = chain::authenticated_top_down(&embedded, &roots);
    let authenticated = authenticated.certificates();
    // The intermediate in the first round, the signer in the second; the
    // stranger never.
    assert_eq!(authenticated.len(), 2);
    assert!(authenticated
        .iter()
        .all(|certificate| !core::ptr::eq(*certificate, &embedded[0])));
}

#[test]
fn a_genuine_apple_receipt_padded_with_stranger_keys_still_verifies() {
    // The owner's rule (2026-09-27), as in the Java port: extra certificates
    // nobody vouched for, with huge or broken keys, are ignored, not a
    // verdict. The genuine G5 receipt, rebuilt with its own content,
    // certificates and signature, padded up to the certificate cap.
    use apple_purchase_receipt_verifier::__internal::cms;
    use apple_purchase_receipt_verifier::{Config, Verifier};

    let genuine = common::read_base64_fixture("public-receipts/receipt-sandbox-g5.b64");
    let parsed_cms = cms::parse_cms(&genuine).unwrap();
    let info = &parsed_cms.signer_infos[0];
    let mut builder = CmsBuilder::from_shared();
    builder.content = Some(parsed_cms.content.clone());
    builder.signer_issuer = info.issuer_raw.clone();
    builder.signer_serial = info.serial_contents.clone();
    builder.signed_attrs = info.signed_attrs.clone();
    builder.signature = info.signature.clone();
    builder.certificates = parsed_cms.certificates.clone();
    let verifier = Verifier::new(Config::defaults());
    let control = common::verify_der(&verifier, &builder.build())
        .expect("the rebuilt genuine receipt verifies unpadded");

    let intermediate_name = parsed_cms
        .certificates
        .iter()
        .map(|raw| parsed(raw))
        .find(|certificate| certificate.serial_number() == info.serial_contents.as_slice())
        .unwrap()
        .issuer_der()
        .to_vec();
    let root_name = parsed(Config::defaults().roots()[0].der())
        .subject_der()
        .to_vec();
    let room = 10 - parsed_cms.certificates.len();
    let spkis = stranger_spkis();
    let mut certificates: Vec<Vec<u8>> = (0..room)
        .zip(spkis.iter().cycle())
        .map(|(serial, spki)| {
            let issuer = if serial % 2 == 0 {
                &root_name
            } else {
                &intermediate_name
            };
            stranger(
                &intermediate_name,
                issuer,
                100 + serial as u64,
                None,
                spki.clone(),
            )
        })
        .collect();
    certificates.extend(parsed_cms.certificates.iter().cloned());
    builder.certificates = certificates;
    let receipt = builder.build();

    let start = Instant::now();
    let (payload, used) = keys_used_during(|| common::verify_der(&verifier, &receipt));
    assert_fast(start);
    assert_no_stranger_key_used(&used);
    assert_eq!(payload.unwrap(), control);
}

/// Every signature check goes through one recorded key use, the ES256 check
/// over the JWS included: a genuine transaction uses the root's key on the
/// intermediate, the intermediate's on the leaf, and last the leaf's own.
#[test]
fn the_es256_check_is_recorded_as_a_key_use() {
    use apple_purchase_receipt_verifier::__internal::x509::Certificate;
    let jws = common::transaction_jws();
    let header = common::jws_header(&jws);
    let leaf_entry = header["x5c"][0].as_str().unwrap();
    let leaf = Certificate::from_der(
        &apple_purchase_receipt_verifier::__internal::base64_decode_lenient(leaf_entry),
    )
    .unwrap();
    let (result, used) = keys_used_during(|| common::jws_verifier().verify_signed_data(&jws));
    assert!(result.is_ok());
    assert_eq!(used.last().map(Vec::as_slice), Some(leaf.spki()));
}
