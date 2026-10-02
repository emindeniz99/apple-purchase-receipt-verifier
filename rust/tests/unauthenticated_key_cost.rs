//! Certificates nobody trusted yet must cost almost nothing to reject.
//!
//! An RSA public-key operation costs what the key's owner chose: the modulus
//! size and the exponent. OpenSSL takes moduli up to 16384 bits, and a
//! signature is only exponentiated when it is as long as the modulus, so a
//! certificate of the attacker's own with such a key and a signature to
//! match is an expensive check to buy. A receipt whose signer and nine
//! padding certificates are all the attacker's, named as issuers of one
//! another, with every `SignerInfo` the cap allows naming that signer, made
//! the old bottom-up walk run 36 of them. The walk starts from the pinned
//! roots, so a key no root vouched for is never used, and the same receipt
//! is refused in about a millisecond.
//!
//! The bounds are set for `cargo test`'s debug profile. The direct
//! statement, that no stranger key checked a signature, comes from the
//! OpenSSL adapter's record of every key it builds for a signature check.

mod common;

use apple_purchase_receipt_verifier::__internal::path::{self, Certificate};
use apple_purchase_receipt_verifier::__internal::{base64_encode, keys_used_during};
use apple_purchase_receipt_verifier::Reason;
use common::der::{parse_exact, tag};
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

/// An expensive RSA key: an 8192-bit odd modulus and a 34-bit exponent.
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

/// An RSA key at OpenSSL's cap: a 16384-bit modulus.
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

/// Every kind of stranger key: two expensive ones, and two that do not
/// decode as keys at all.
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

/// A certificate's TBS fields, read with the test DER reader.
fn tbs_field(certificate: &[u8], after_version: usize) -> Vec<u8> {
    let certificate = parse_exact(certificate).unwrap();
    let fields = certificate.child(0).unwrap().children();
    let index = usize::from(matches!(fields.first(), Some(f) if f.tag == tag::CONTEXT_0));
    let field = &fields[index + after_version];
    if after_version == 0 {
        field.contents.to_vec()
    } else {
        field.full.to_vec()
    }
}

fn serial_number(certificate: &[u8]) -> Vec<u8> {
    tbs_field(certificate, 0)
}

fn issuer_der(certificate: &[u8]) -> Vec<u8> {
    tbs_field(certificate, 2)
}

fn subject_der(certificate: &[u8]) -> Vec<u8> {
    tbs_field(certificate, 4)
}

fn root() -> Vec<u8> {
    common::receipt_root().der().to_vec()
}

/// The shared receipt's signer and WWDR intermediate, in that order.
fn signer_and_intermediate(builder: &CmsBuilder) -> (Vec<u8>, Vec<u8>) {
    let signer = builder
        .certificates
        .iter()
        .find(|raw| serial_number(raw) == builder.signer_serial)
        .unwrap()
        .clone();
    let issuer = issuer_der(&signer);
    let intermediate = builder
        .certificates
        .iter()
        .find(|raw| subject_der(raw) == issuer)
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
    let intermediate_name = subject_der(&intermediate);
    let root_name = subject_der(&root());
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
    let intermediate_name = subject_der(&intermediate);
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
    let root_name = subject_der(common::jws_root().der());
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
    let intermediate_name = subject_der(&intermediate);
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
    let (authenticated, used) =
        keys_used_during(|| path::authenticated_top_down(&embedded, &roots));
    // The intermediate in the first round, the signer in the second; the
    // stranger never.
    assert_eq!(authenticated.len(), 2);
    assert!(authenticated
        .iter()
        .all(|certificate| !certificate.same_as(&embedded[0])));
    assert_no_stranger_key_used(&used);
}

#[test]
fn a_genuine_apple_receipt_padded_with_stranger_keys_still_verifies() {
    // The owner's rule (2026-09-27), as in the Java port: extra certificates
    // nobody vouched for, with huge or broken keys, are ignored, not a
    // verdict. The genuine G5 receipt, rebuilt with its own content,
    // certificates and signature, padded up to the certificate cap.
    use apple_purchase_receipt_verifier::{Config, Verifier};
    use common::cms;

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
    let verifier = Verifier::new(Config::default());
    let control = common::verify_der(&verifier, &builder.build())
        .expect("the rebuilt genuine receipt verifies unpadded");

    let intermediate_name = issuer_der(
        parsed_cms
            .certificates
            .iter()
            .find(|raw| serial_number(raw) == info.serial_contents)
            .unwrap(),
    );
    let root_name = subject_der(Config::default().roots()[0].der());
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
    let jws = common::transaction_jws();
    let header = common::jws_header(&jws);
    let leaf_entry = header["x5c"][0].as_str().unwrap();
    let leaf = openssl::x509::X509::from_der(&common::decode_base64(leaf_entry)).unwrap();
    let leaf_spki = leaf.public_key().unwrap().public_key_to_der().unwrap();
    let (result, used) = keys_used_during(|| common::jws_verifier().verify_signed_data(&jws));
    assert!(result.is_ok());
    assert_eq!(used.last(), Some(&leaf_spki));
}
