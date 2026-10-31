//! An RSA test PKI shaped like Apple's (root, WWDR-marked intermediate,
//! receipt-signing leaf), a hand-written X.509 and CMS writer, and the
//! receipt payload builder: the Rust side of the Java suites' `TestPki`.
//!
//! Everything is written as DER by hand over the helpers in `mod.rs`, so
//! a test can state any certificate or `SignedData` a hostile signer
//! could send: a garbage or crafted signature, a label that does not
//! match the signature, an outlaw serial, a key nobody holds. Keys and
//! signatures come from OpenSSL. The library reads none of this code.

use super::ber::{parse_exact, Tlv};
use super::{der, der_int, der_oid, der_seq, der_set, tag, verifier};
use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{Failure, Reason, ReceiptPayload, TrustAnchor, Verifier};
use openssl::bn::{BigNum, BigNumContext, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use std::cmp::Ordering;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const SIGNING_LEAF_OID: &str = "1.2.840.113635.100.6.11.1";
pub const WWDR_OID: &str = "1.2.840.113635.100.6.2.1";
pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const MD2_WITH_RSA: &str = "1.2.840.113549.1.1.2";
pub const MD5_WITH_RSA: &str = "1.2.840.113549.1.1.4";
pub const SHA1_WITH_RSA: &str = "1.2.840.113549.1.1.5";
pub const RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
pub const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
pub const SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";
pub const SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";
pub const MGF1: &str = "1.2.840.113549.1.1.8";
pub const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
pub const SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub const GENERIC_COMPOSITE: &str = "1.3.6.1.4.1.18227.2.1";
pub const ID_DATA: &str = "1.2.840.113549.1.7.1";
pub const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
pub const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
pub const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
pub const SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
pub const CMS_ALGORITHM_PROTECTION: &str = "1.2.840.113549.1.9.52";

pub const DAY_MS: i64 = 86_400_000;

/// The Java suites' per-case budget, 2,000 ms, and its free-refusal
/// budget, 50 ms, are for a warmed JVM. A Cargo test is an unoptimised
/// build sharing a loaded machine, so the bounds asserted here are ten
/// times Java's: loose enough never to flap, tight enough to fail the
/// classes those budgets guard against, which cost seconds to minutes.
/// The cost is printed for every case; the release numbers are read
/// from a `--release` run.
pub const BUDGET: Duration = Duration::from_millis(20_000);
pub const FREE_BUDGET: Duration = Duration::from_millis(2_000);

pub fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// `now_ms` truncated to the second, as an RFC 3339 string.
pub fn now_rfc3339() -> String {
    rfc3339(now_ms() / 1000 * 1000)
}

// --- keys ------------------------------------------------------------------

/// A private key the test holds: RSA or P-256.
pub struct Key(pub PKey<Private>);

impl Key {
    /// A fresh RSA-2048 key, exponent 65537.
    pub fn rsa() -> Key {
        Key(PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap())
    }

    /// A fresh RSA key with the given size and public exponent.
    pub fn rsa_with_exponent(bits: u32, exponent: u32) -> Key {
        let e = BigNum::from_u32(exponent).unwrap();
        Key(PKey::from_rsa(Rsa::generate_with_e(bits, &e).unwrap()).unwrap())
    }

    /// A fresh P-256 key.
    pub fn ec() -> Key {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        Key(PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap())
    }

    pub fn is_rsa(&self) -> bool {
        self.0.rsa().is_ok()
    }

    /// The `SubjectPublicKeyInfo` DER.
    pub fn spki(&self) -> Vec<u8> {
        self.0.public_key_to_der().unwrap()
    }

    /// The RSA modulus, big-endian.
    pub fn modulus(&self) -> Vec<u8> {
        self.0.rsa().unwrap().n().to_vec()
    }

    /// A PKCS#1 v1.5 (RSA) or DER ECDSA (EC) signature of `data` over `hash`.
    pub fn sign(&self, hash: Hash, data: &[u8]) -> Vec<u8> {
        let mut signer = Signer::new(hash.md(), &self.0).unwrap();
        signer.sign_oneshot_to_vec(data).unwrap()
    }

    /// The signatureAlgorithm label this key signs `hash` under.
    pub fn label(&self, hash: Hash) -> Vec<u8> {
        if self.is_rsa() {
            rsa_label(hash.rsa_oid())
        } else {
            der_seq(&[der_oid(ECDSA_WITH_SHA256)])
        }
    }
}

/// The digests the suites sign with.
#[derive(Clone, Copy, Debug)]
pub enum Hash {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn md(self) -> MessageDigest {
        match self {
            Hash::Md5 => MessageDigest::md5(),
            Hash::Sha1 => MessageDigest::sha1(),
            Hash::Sha256 => MessageDigest::sha256(),
            Hash::Sha384 => MessageDigest::sha384(),
            Hash::Sha512 => MessageDigest::sha512(),
        }
    }

    pub fn oid(self) -> &'static str {
        match self {
            Hash::Md5 => "1.2.840.113549.2.5",
            Hash::Sha1 => "1.3.14.3.2.26",
            Hash::Sha256 => SHA256,
            Hash::Sha384 => "2.16.840.1.101.3.4.2.2",
            Hash::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }

    pub fn rsa_oid(self) -> &'static str {
        match self {
            Hash::Md5 => MD5_WITH_RSA,
            Hash::Sha1 => SHA1_WITH_RSA,
            Hash::Sha256 => SHA256_WITH_RSA,
            Hash::Sha384 => SHA384_WITH_RSA,
            Hash::Sha512 => SHA512_WITH_RSA,
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        openssl::hash::hash(self.md(), data).unwrap().to_vec()
    }
}

/// An `AlgorithmIdentifier` with NULL parameters, as RSA labels carry them.
pub fn rsa_label(oid: &str) -> Vec<u8> {
    der_seq(&[der_oid(oid), der(0x05, &[])])
}

/// The content octets of a DER INTEGER holding the unsigned big-endian
/// `magnitude`.
pub fn unsigned_integer(magnitude: &[u8]) -> Vec<u8> {
    let start = magnitude
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(magnitude.len());
    let mut out = magnitude[start..].to_vec();
    if out.first().is_none_or(|&b| b & 0x80 != 0) {
        out.insert(0, 0);
    }
    out
}

/// An RSA `SubjectPublicKeyInfo` for a key nobody need hold.
pub fn rsa_spki(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    rsa_spki_with_parameters(modulus, exponent, der(0x05, &[]))
}

/// The same, with `parameters` in place of the rsaEncryption NULL.
pub fn rsa_spki_with_parameters(modulus: &[u8], exponent: &[u8], parameters: Vec<u8>) -> Vec<u8> {
    let key = der_seq(&[
        der(tag::INTEGER, &unsigned_integer(modulus)),
        der(tag::INTEGER, &unsigned_integer(exponent)),
    ]);
    let mut bits = vec![0x00];
    bits.extend_from_slice(&key);
    der_seq(&[
        der_seq(&[der_oid(RSA_ENCRYPTION), parameters]),
        der(tag::BIT_STRING, &bits),
    ])
}

/// A random odd modulus of exactly `bits` bits.
pub fn random_modulus(bits: i32) -> Vec<u8> {
    let mut n = BigNum::new().unwrap();
    n.rand(bits, MsbOption::ONE, true).unwrap();
    n.to_vec()
}

/// An RSA SPKI on a random `bits`-bit modulus with exponent `exponent`.
pub fn random_rsa_spki(bits: i32, exponent: &[u8]) -> Vec<u8> {
    rsa_spki(&random_modulus(bits), exponent)
}

pub const E65537: &[u8] = &[0x01, 0x00, 0x01];

// --- names, times, serials ---------------------------------------------------

/// A `Name` holding one commonName, as a UTF8String.
pub fn name(common_name: &str) -> Vec<u8> {
    super::mint::name(common_name)
}

static SERIAL: AtomicU64 = AtomicU64::new(1_000);

/// The content octets of a fresh positive serial, unique in this process.
pub fn next_serial() -> Vec<u8> {
    unsigned_integer(&SERIAL.fetch_add(1, AtomicOrdering::Relaxed).to_be_bytes())
}

/// (year, month, day, hour, minute, second) of a Unix instant in ms.
fn civil(ms: i64) -> (i64, u32, u32, u32, u32, u32) {
    let seconds = ms.div_euclid(1000);
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap(),
        u32::try_from(day).unwrap(),
        u32::try_from(rest / 3600).unwrap(),
        u32::try_from(rest % 3600 / 60).unwrap(),
        u32::try_from(rest % 60).unwrap(),
    )
}

/// An instant as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn rfc3339(ms: i64) -> String {
    let (y, mo, d, h, mi, s) = civil(ms);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// `YYYY-MM-DDTHH:MM:SSZ` as an instant in ms.
pub fn parse_rfc3339(text: &str) -> i64 {
    let field = |range: std::ops::Range<usize>| text[range].parse::<i64>().unwrap();
    let (y, mo, d) = (field(0..4), field(5..7), field(8..10));
    let (h, mi, s) = (field(11..13), field(14..16), field(17..19));
    // Howard Hinnant's days_from_civil.
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if mo > 2 { mo - 3 } else { mo + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    ((days * 86_400) + h * 3600 + mi * 60 + s) * 1000
}

/// An X.509 `Time`: UTCTime through 2049, GeneralizedTime from 2050.
pub fn x509_time(ms: i64) -> Vec<u8> {
    let (y, mo, d, h, mi, s) = civil(ms);
    if (1950..2050).contains(&y) {
        let text = format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z", y % 100);
        der(tag::UTC_TIME, text.as_bytes())
    } else {
        let text = format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z");
        der(tag::GENERALIZED_TIME, text.as_bytes())
    }
}

// --- certificates ------------------------------------------------------------

/// One extension: `extnID`, `critical` when set, and `extnValue`.
pub fn extension(oid: &str, critical: bool, value: &[u8]) -> Vec<u8> {
    let mut fields = vec![der_oid(oid)];
    if critical {
        fields.push(der(tag::BOOLEAN, &[0xFF]));
    }
    fields.push(der(tag::OCTET_STRING, value));
    der_seq(&fields)
}

/// basicConstraints, critical: `cA` when `ca`, and a path length.
pub fn basic_constraints(ca: bool, path_len: Option<u64>) -> Vec<u8> {
    let mut fields = Vec::new();
    if ca {
        fields.push(der(tag::BOOLEAN, &[0xFF]));
    }
    if let Some(n) = path_len {
        fields.push(der_int(n));
    }
    extension("2.5.29.19", true, &der_seq(&fields))
}

/// A marker extension, non-critical, valued `value` (a DER NULL in
/// `TestPki`, a BOOLEAN TRUE in the attack suites).
pub fn marker(oid: &str, value: &[u8]) -> Vec<u8> {
    extension(oid, false, value)
}

pub const NULL: &[u8] = &[0x05, 0x00];
pub const TRUE: &[u8] = &[0x01, 0x01, 0xFF];

/// keyUsage, critical, the BIT STRING `bits` (unused-bit count first).
pub fn key_usage(bits: &[u8]) -> Vec<u8> {
    extension("2.5.29.15", true, &der(tag::BIT_STRING, bits))
}

pub const KEY_USAGE_DIGITAL_SIGNATURE: &[u8] = &[0x07, 0x80];
pub const KEY_USAGE_KEY_ENCIPHERMENT: &[u8] = &[0x05, 0x20];

/// What a certificate states, before it is signed.
#[derive(Clone)]
pub struct CertSpec {
    pub issuer: Vec<u8>,
    pub serial: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    pub subject: Vec<u8>,
    pub spki: Vec<u8>,
    pub extensions: Vec<Vec<u8>>,
}

impl CertSpec {
    /// A v3 certificate valid from a day ago for a year, with a fresh
    /// serial and no extensions.
    pub fn new(subject: Vec<u8>, issuer: Vec<u8>, spki: Vec<u8>) -> CertSpec {
        let now = now_ms() / 1000 * 1000;
        CertSpec {
            issuer,
            serial: next_serial(),
            not_before: now - DAY_MS,
            not_after: now + 365 * DAY_MS,
            subject,
            spki,
            extensions: Vec::new(),
        }
    }

    /// The attack suites' `cert`: the CA role as a critical basicConstraints
    /// when `ca`, and the marker valued BOOLEAN TRUE.
    pub fn suite(
        subject: Vec<u8>,
        spki: Vec<u8>,
        issuer: Vec<u8>,
        ca: bool,
        marker_oid: Option<&str>,
    ) -> CertSpec {
        let mut spec = CertSpec::new(subject, issuer, spki);
        if ca {
            spec.extensions.push(basic_constraints(true, None));
        }
        if let Some(oid) = marker_oid {
            spec.extensions.push(marker(oid, TRUE));
        }
        spec
    }

    pub fn with(mut self, extension: Vec<u8>) -> CertSpec {
        self.extensions.push(extension);
        self
    }

    pub fn tbs(&self, label: &[u8]) -> Vec<u8> {
        let mut fields = vec![
            der(tag::CONTEXT_0, &der_int(2)),
            der(tag::INTEGER, &self.serial),
            label.to_vec(),
            self.issuer.clone(),
            der_seq(&[x509_time(self.not_before), x509_time(self.not_after)]),
            self.subject.clone(),
            self.spki.clone(),
        ];
        if !self.extensions.is_empty() {
            fields.push(der(tag::CONTEXT_3, &der_seq(&self.extensions)));
        }
        der_seq(&fields)
    }

    /// Signed by `key` over `hash`, the label matching.
    pub fn sign_with(&self, key: &Key, hash: Hash) -> Vec<u8> {
        let label = key.label(hash);
        let tbs = self.tbs(&label);
        let signature = key.sign(hash, &tbs);
        assemble(tbs, &label, &signature)
    }

    /// Signed by `key`, SHA256withRSA (or ecdsa-with-SHA256).
    pub fn sign(&self, key: &Key) -> Vec<u8> {
        self.sign_with(key, Hash::Sha256)
    }

    /// `label` in both places, and 256 zero octets as the signature.
    pub fn garbage(&self, label: &[u8]) -> Vec<u8> {
        assemble(self.tbs(label), label, &[0u8; 256])
    }

    /// Genuinely signed by `key` with SHA256withRSA, but labelled `label`.
    pub fn mislabeled(&self, key: &Key, label: &[u8]) -> Vec<u8> {
        let tbs = self.tbs(label);
        let signature = key.sign(Hash::Sha256, &tbs);
        assemble(tbs, label, &signature)
    }

    /// Labelled `label`, with whatever `signature` makes of the TBS.
    pub fn with_signature(
        &self,
        label: &[u8],
        signature: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> Vec<u8> {
        let tbs = self.tbs(label);
        let signature = signature(&tbs);
        assemble(tbs, label, &signature)
    }
}

/// The certificate: `tbs`, `label` and `signature` as a BIT STRING.
pub fn assemble(tbs: Vec<u8>, label: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut bits = vec![0x00];
    bits.extend_from_slice(signature);
    der_seq(&[tbs, label.to_vec(), der(tag::BIT_STRING, &bits)])
}

/// A certificate's fields, read with the test BER reader.
pub struct CertFields {
    pub serial: Vec<u8>,
    pub issuer: Vec<u8>,
    pub not_before: Vec<u8>,
    pub not_after: Vec<u8>,
    pub subject: Vec<u8>,
    pub spki: Vec<u8>,
}

pub fn cert_fields(certificate: &[u8]) -> CertFields {
    let parsed = parse_exact(certificate).expect("not a certificate");
    let fields = parsed.child(0).unwrap().children();
    let at = usize::from(fields[0].tag == tag::CONTEXT_0);
    let validity = fields[at + 3].children();
    CertFields {
        serial: fields[at].contents.to_vec(),
        issuer: fields[at + 2].full.to_vec(),
        not_before: validity[0].full.to_vec(),
        not_after: validity[1].full.to_vec(),
        subject: fields[at + 4].full.to_vec(),
        spki: fields[at + 5].full.to_vec(),
    }
}

// --- the PKI -------------------------------------------------------------------

/// `TestPki`: a root, an intermediate and a receipt-signing leaf, each
/// with its own RSA-2048 key, and the bag a receipt embeds.
pub struct Pki {
    pub root_key: Key,
    pub intermediate_key: Key,
    pub leaf_key: Key,
    pub root: Vec<u8>,
    pub intermediate: Vec<u8>,
    pub leaf: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
    pub not_before: i64,
    pub not_after: i64,
}

/// `TestPki.cert`: basicConstraints always (critical), the marker NULL.
#[allow(clippy::too_many_arguments)]
pub fn test_pki_cert(
    subject: &str,
    subject_key: &Key,
    issuer: &str,
    issuer_key: &Key,
    ca: bool,
    marker_oid: Option<&str>,
    not_before: i64,
    not_after: i64,
) -> Vec<u8> {
    test_pki_cert_named(
        name(subject),
        subject_key,
        name(issuer),
        issuer_key,
        ca,
        marker_oid,
        not_before,
        not_after,
    )
}

/// The same, the names given as `Name` DER.
#[allow(clippy::too_many_arguments)]
pub fn test_pki_cert_named(
    subject: Vec<u8>,
    subject_key: &Key,
    issuer: Vec<u8>,
    issuer_key: &Key,
    ca: bool,
    marker_oid: Option<&str>,
    not_before: i64,
    not_after: i64,
) -> Vec<u8> {
    let mut spec = CertSpec::new(subject, issuer, subject_key.spki());
    spec.not_before = not_before;
    spec.not_after = not_after;
    spec.extensions.push(basic_constraints(ca, None));
    if let Some(oid) = marker_oid {
        spec.extensions.push(marker(oid, NULL));
    }
    spec.sign(issuer_key)
}

// --- the cost suites' shapes -------------------------------------------------------

/// The receipt-string cap, in base64 characters.
pub const MAX_RECEIPT_BYTES: usize = 3_145_728;

/// The largest receipt DER whose base64 fits the cap.
pub const CAP_DER: usize = MAX_RECEIPT_BYTES / 4 * 3;

/// The cost suites' `nestedSets`: a SEQUENCE of copies of one chain of
/// SETs `depth` deep (each SET the deeper chain and an INTEGER, in that
/// order, as a definite-length encoding keeps them), about `bytes` long.
pub fn nested_sets(depth: usize, bytes: usize) -> Vec<u8> {
    let mut chain = der_int(7);
    for _ in 0..depth {
        chain = der_set(&[chain, der_int(1)]);
    }
    let copies = bytes / chain.len();
    der(tag::SEQUENCE, &chain.repeat(copies))
}

/// `genuine`'s digest algorithms, content and signer infos around `bag`:
/// the cost suites' worst shape, encoded definite-length as built.
pub fn with_bag(genuine: &SignedDataParts, bag: Vec<Vec<u8>>) -> Vec<u8> {
    let rebuilt = SignedDataParts {
        digest_algorithms: genuine.digest_algorithms.clone(),
        encap: genuine.encap.clone(),
        certificates: bag,
        signer_infos: genuine.signer_infos.clone(),
    }
    .build();
    assert!(
        rebuilt.len() <= CAP_DER,
        "the receipt is over the cap: {}",
        rebuilt.len()
    );
    rebuilt
}

/// The product of the odd primes below 10,000, for keys that pass a
/// small-factor check.
pub fn small_primes_product() -> BigNum {
    let limit = 10_000usize;
    let mut composite = vec![false; limit];
    let mut product = BigNum::from_u32(1).unwrap();
    for n in 2..limit {
        if composite[n] {
            continue;
        }
        let mut multiple = n * n;
        while multiple < limit {
            composite[multiple] = true;
            multiple += n;
        }
        if n > 2 {
            product.mul_word(u32::try_from(n).unwrap()).unwrap();
        }
    }
    product
}

/// A random odd `bits`-bit modulus with no factor below 10,000, so only
/// an expensive primality test could tell it is no RSA key.
pub fn modulus_without_small_factors(bits: i32, small_primes: &BigNum) -> Vec<u8> {
    let mut context = bn_context();
    loop {
        let mut n = BigNum::new().unwrap();
        n.rand(bits, MsbOption::ONE, true).unwrap();
        let mut gcd = BigNum::new().unwrap();
        gcd.gcd(&n, small_primes, &mut context).unwrap();
        if gcd == BigNum::from_u32(1).unwrap() {
            return n.to_vec();
        }
    }
}

/// The genuine sandbox G5 receipt's DER, whose chain and signer are
/// Apple's own.
pub fn g5_der() -> Vec<u8> {
    super::read_base64_fixture("public-receipts/receipt-sandbox-g5.b64")
}

impl Pki {
    /// `TestPki.receipt()`: valid from a day ago for a year, both markers.
    pub fn receipt() -> Pki {
        let now = now_ms() / 1000 * 1000;
        Pki::receipt_with(now - DAY_MS, now + 365 * DAY_MS, true, true)
    }

    /// `TestPki.receipt(notBefore, notAfter, signerOid, intermediateOid)`.
    pub fn receipt_with(
        not_before: i64,
        not_after: i64,
        leaf_marker: bool,
        wwdr_marker: bool,
    ) -> Pki {
        let (root_key, intermediate_key, leaf_key) = (Key::rsa(), Key::rsa(), Key::rsa());
        let root = test_pki_cert(
            "Fake Apple Inc Root",
            &root_key,
            "Fake Apple Inc Root",
            &root_key,
            true,
            None,
            not_before,
            not_after,
        );
        let intermediate = test_pki_cert(
            "Fake WWDR CA",
            &intermediate_key,
            "Fake Apple Inc Root",
            &root_key,
            true,
            wwdr_marker.then_some(WWDR_OID),
            not_before,
            not_after,
        );
        let leaf = test_pki_cert(
            "Fake Receipt Signing",
            &leaf_key,
            "Fake WWDR CA",
            &intermediate_key,
            false,
            leaf_marker.then_some(SIGNING_LEAF_OID),
            not_before,
            not_after,
        );
        let chain = vec![leaf.clone(), intermediate.clone(), root.clone()];
        Pki {
            root_key,
            intermediate_key,
            leaf_key,
            root,
            intermediate,
            leaf,
            chain,
            not_before,
            not_after,
        }
    }

    /// `TestPki.deepReceipt`: `intermediates` CAs below the root, then
    /// `self_issued_tail` CAs that repeat the deepest one's name, then the
    /// leaf; the bag is the leaf, every CA and the root. `intermediate`
    /// is the deepest CA.
    pub fn deep(intermediates: usize, self_issued_tail: usize) -> Pki {
        let now = now_ms() / 1000 * 1000;
        let (not_before, not_after) = (now - DAY_MS, now + 365 * DAY_MS);
        let root_key = Key::rsa();
        let root = test_pki_cert(
            "Deep Root",
            &root_key,
            "Deep Root",
            &root_key,
            true,
            None,
            not_before,
            not_after,
        );
        let mut cas = Vec::new();
        let mut issuer = "Deep Root".to_owned();
        let mut keys: Vec<Key> = Vec::new();
        for i in 1..=intermediates {
            let subject = format!("Deep CA {i}");
            let key = Key::rsa();
            cas.push(test_pki_cert(
                &subject,
                &key,
                &issuer,
                keys.last().unwrap_or(&root_key),
                true,
                Some(WWDR_OID),
                not_before,
                not_after,
            ));
            issuer = subject;
            keys.push(key);
        }
        for _ in 0..self_issued_tail {
            let key = Key::rsa();
            cas.push(test_pki_cert(
                &issuer,
                &key,
                &issuer,
                keys.last().unwrap_or(&root_key),
                true,
                Some(WWDR_OID),
                not_before,
                not_after,
            ));
            keys.push(key);
        }
        let leaf_key = Key::rsa();
        let leaf = test_pki_cert(
            "Deep Receipt Signing",
            &leaf_key,
            &issuer,
            keys.last().unwrap_or(&root_key),
            false,
            Some(SIGNING_LEAF_OID),
            not_before,
            not_after,
        );
        let deepest = cas.last().cloned().unwrap_or_else(|| root.clone());
        let mut chain = vec![leaf.clone()];
        chain.extend(cas);
        chain.push(root.clone());
        Pki {
            root_key,
            intermediate_key: keys.pop().unwrap_or_else(Key::rsa),
            leaf_key,
            root,
            intermediate: deepest,
            leaf,
            chain,
            not_before,
            not_after,
        }
    }

    pub fn anchor(&self) -> TrustAnchor {
        TrustAnchor::from_der(&self.root).unwrap()
    }

    /// A verifier pinned to this root alone, on the system clock.
    pub fn verifier(&self) -> Verifier {
        verifier([self.anchor()])
    }

    /// `signReceipt`: the leaf signs, now, the whole chain embedded.
    pub fn sign_receipt(&self, payload: &[u8]) -> Vec<u8> {
        self.sign_receipt_at(payload, now_ms())
    }

    /// `signReceipt(payload, signingTime)`.
    pub fn sign_receipt_at(&self, payload: &[u8], signing_time: i64) -> Vec<u8> {
        sign_receipt_as(
            payload,
            signing_time,
            &self.leaf_key,
            Hash::Sha256,
            &[&self.leaf],
            &self.chain,
        )
    }

    /// The leaf signs, now, with `bag` embedded.
    pub fn sign_receipt_with_bag(&self, payload: &[u8], bag: &[Vec<u8>]) -> Vec<u8> {
        sign_receipt_as(
            payload,
            now_ms(),
            &self.leaf_key,
            Hash::Sha256,
            &[&self.leaf],
            bag,
        )
    }
}

// --- CMS -----------------------------------------------------------------------

/// One `Attribute`: the type and a SET of `values`, sorted as DER.
pub fn attribute(oid: &str, values: &[Vec<u8>]) -> Vec<u8> {
    der_seq(&[der_oid(oid), der_set_sorted(values)])
}

/// A DER `SET OF`: the members sorted by their encodings.
pub fn der_set_sorted(members: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted = members.to_vec();
    sorted.sort_by(|a, b| der_order(a, b));
    der_set(&sorted)
}

/// `members` in DER `SET OF` order: what BouncyCastle's
/// `getEncoded("DER")` does to a certificate bag and to the SignerInfos.
pub fn der_sorted(members: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut sorted = members.to_vec();
    sorted.sort_by(|a, b| der_order(a, b));
    sorted
}

/// X.690 11.6: as octet strings, the shorter padded with zeros.
fn der_order(a: &[u8], b: &[u8]) -> Ordering {
    let length = a.len().max(b.len());
    for i in 0..length {
        let (x, y) = (
            a.get(i).copied().unwrap_or(0),
            b.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return x.cmp(&y);
        }
    }
    Ordering::Equal
}

/// The signed attributes BouncyCastle's default table writes: contentType,
/// signingTime, messageDigest of `content` and CMSAlgorithmProtection.
pub fn standard_signed_attrs(
    content: &[u8],
    hash: Hash,
    label: &[u8],
    signing_time: i64,
) -> Vec<Vec<u8>> {
    let digest_algorithm = der_seq(&[der_oid(hash.oid())]);
    // RFC 6211: signatureAlgorithm is [1] IMPLICIT.
    let label_contents = parse_exact(label).unwrap().contents.to_vec();
    let protection = der_seq(&[digest_algorithm, der(0xA1, &label_contents)]);
    vec![
        attribute(CONTENT_TYPE, &[der_oid(ID_DATA)]),
        attribute(SIGNING_TIME, &[x509_time(signing_time)]),
        attribute(
            MESSAGE_DIGEST,
            &[der(tag::OCTET_STRING, &hash.digest(content))],
        ),
        attribute(CMS_ALGORITHM_PROTECTION, &[protection]),
    ]
}

/// One `SignerInfo` naming `signer_cert` by issuer and serial.
///
/// `signed_attrs` `None` is a direct signature over the content;
/// otherwise the attributes are sorted as DER and signed as a SET.
/// `signature` makes the signature of whatever is signed.
pub fn signer_info(
    signer_cert: &[u8],
    hash: Hash,
    label: &[u8],
    content: &[u8],
    signed_attrs: Option<&[Vec<u8>]>,
    unsigned_attrs: &[Vec<u8>],
    signature: &dyn Fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let identity = cert_fields(signer_cert);
    let mut fields = vec![
        der_int(1),
        der_seq(&[identity.issuer, der(tag::INTEGER, &identity.serial)]),
        der_seq(&[der_oid(hash.oid())]),
    ];
    let signed = match signed_attrs {
        Some(attributes) => {
            let set = der_set_sorted(attributes);
            let contents = parse_exact(&set).unwrap().contents.to_vec();
            fields.push(der(tag::CONTEXT_0, &contents));
            set
        }
        None => content.to_vec(),
    };
    fields.push(label.to_vec());
    fields.push(der(tag::OCTET_STRING, &signature(&signed)));
    if !unsigned_attrs.is_empty() {
        fields.push(der(tag::CONTEXT_1, &unsigned_attrs.concat()));
    }
    der_seq(&fields)
}

/// A `ContentInfo` holding a `SignedData`: `content` encapsulated (or
/// left out, detached), the certificates in the order given.
pub fn signed_data(
    content: &[u8],
    encapsulate: bool,
    hashes: &[Hash],
    certificates: &[Vec<u8>],
    signer_infos: &[Vec<u8>],
) -> Vec<u8> {
    let mut encap = vec![der_oid(ID_DATA)];
    if encapsulate {
        encap.push(der(tag::CONTEXT_0, &der(tag::OCTET_STRING, content)));
    }
    let digests: Vec<Vec<u8>> = hashes
        .iter()
        .map(|h| der_seq(&[der_oid(h.oid())]))
        .collect();
    let signed = der_seq(&[
        der_int(1),
        der_set_sorted(&digests),
        der_seq(&encap),
        der(tag::CONTEXT_0, &certificates.concat()),
        der_set(signer_infos),
    ]);
    der_seq(&[der_oid(ID_SIGNED_DATA), der(tag::CONTEXT_0, &signed)])
}

/// `TestPki.signReceiptAs`: one `SignerInfo` per entry of `signer_certs`,
/// each signed by `key` over the standard attributes, `bag` embedded.
pub fn sign_receipt_as(
    content: &[u8],
    signing_time: i64,
    key: &Key,
    hash: Hash,
    signer_certs: &[&[u8]],
    bag: &[Vec<u8>],
) -> Vec<u8> {
    let label = key.label(hash);
    let attributes = standard_signed_attrs(content, hash, &label, signing_time);
    let infos: Vec<Vec<u8>> = signer_certs
        .iter()
        .map(|cert| {
            signer_info(
                cert,
                hash,
                &label,
                content,
                Some(&attributes),
                &[],
                &|data| key.sign(hash, data),
            )
        })
        .collect();
    signed_data(content, true, &[hash], bag, &infos)
}

/// How the attack suites' own generators shape one `SignerInfo`.
pub enum Attrs {
    /// BouncyCastle's default signed attributes, signed now.
    Standard,
    /// A direct signature over the content, no signed attributes.
    Direct,
    /// Exactly these signed attributes.
    Custom(Vec<Vec<u8>>),
}

/// The attack suites' `CMSSignedDataGenerator` output re-encoded as DER
/// (`toASN1Structure().getEncoded("DER")`): one `SignerInfo` naming
/// `signer_cert`, labelled `label`, its signature whatever `signature`
/// makes of what is signed, and the bag sorted as DER sorts a SET.
#[allow(clippy::too_many_arguments)]
pub fn bc_signed(
    content: &[u8],
    encapsulate: bool,
    hash: Hash,
    label: &[u8],
    signature: &dyn Fn(&[u8]) -> Vec<u8>,
    signer_cert: &[u8],
    chain: &[Vec<u8>],
    attrs: Attrs,
    unsigned_attrs: &[Vec<u8>],
) -> Vec<u8> {
    let attributes = match attrs {
        Attrs::Standard => Some(standard_signed_attrs(content, hash, label, now_ms())),
        Attrs::Direct => None,
        Attrs::Custom(attributes) => Some(attributes),
    };
    let info = signer_info(
        signer_cert,
        hash,
        label,
        content,
        attributes.as_deref(),
        unsigned_attrs,
        signature,
    );
    signed_data(content, encapsulate, &[hash], &der_sorted(chain), &[info])
}

/// `bc_signed` by `key` over `hash`, standard attributes, encapsulated.
pub fn bc_sign(
    content: &[u8],
    key: &Key,
    hash: Hash,
    signer_cert: &[u8],
    chain: &[Vec<u8>],
) -> Vec<u8> {
    bc_signed(
        content,
        true,
        hash,
        &key.label(hash),
        &|data| key.sign(hash, data),
        signer_cert,
        chain,
        Attrs::Standard,
        &[],
    )
}

/// `bc_signed` with a `GarbageSigner`: a SHA256withRSA label and 256 zero
/// octets as the signature.
pub fn bc_garbage_signed(content: &[u8], signer_cert: &[u8], chain: &[Vec<u8>]) -> Vec<u8> {
    bc_signed(
        content,
        true,
        Hash::Sha256,
        &rsa_label(SHA256_WITH_RSA),
        &|_| vec![0u8; 256],
        signer_cert,
        chain,
        Attrs::Standard,
        &[],
    )
}

/// `TestPki.signReceiptByEach`: one `SignerInfo` per PKI, each by its
/// leaf, every chain embedded once.
pub fn sign_receipt_by_each(content: &[u8], signers: &[&Pki]) -> Vec<u8> {
    let mut bag: Vec<Vec<u8>> = Vec::new();
    let mut infos = Vec::new();
    for pki in signers {
        let label = pki.leaf_key.label(Hash::Sha256);
        let attributes = standard_signed_attrs(content, Hash::Sha256, &label, now_ms());
        infos.push(signer_info(
            &pki.leaf,
            Hash::Sha256,
            &label,
            content,
            Some(&attributes),
            &[],
            &|data| pki.leaf_key.sign(Hash::Sha256, data),
        ));
        for certificate in &pki.chain {
            if !bag.contains(certificate) {
                bag.push(certificate.clone());
            }
        }
    }
    signed_data(content, true, &[Hash::Sha256], &bag, &infos)
}

/// `TestPki.corruptSignatures(receipt, count)`: one bit flipped in the
/// middle of each of the first `count` SignerInfos' signatures.
pub fn corrupt_signatures(receipt: &[u8], count: usize) -> Vec<u8> {
    let parsed = super::cms::parse_cms(receipt).unwrap();
    let mut corrupted = receipt.to_vec();
    for info in parsed.signer_infos.iter().take(count) {
        let at = index_of(&corrupted, &info.signature).unwrap();
        corrupted[at + info.signature.len() / 2] ^= 0x01;
    }
    corrupted
}

/// Where `needle` first starts in `haystack`.
pub fn index_of(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Where `needle` last starts in `haystack`.
pub fn last_index_of(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

/// How many times `needle` occurs in `haystack`, overlapping.
pub fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

/// A `SignedData` taken apart into the TLVs it is rebuilt from, as the
/// Java suites rebuild one with BouncyCastle's `SignedData` accessors.
pub struct SignedDataParts {
    pub digest_algorithms: Vec<u8>,
    pub encap: Vec<u8>,
    pub certificates: Vec<Vec<u8>>,
    pub signer_infos: Vec<Vec<u8>>,
}

impl SignedDataParts {
    pub fn parse(receipt: &[u8]) -> SignedDataParts {
        let content_info = parse_exact(receipt).unwrap();
        let fields: &[Tlv<'_>] = content_info.child(1).unwrap().child(0).unwrap().children();
        let certificates = fields
            .iter()
            .find(|f| f.tag == tag::CONTEXT_0)
            .map(|bag| bag.children().iter().map(|c| c.full.to_vec()).collect())
            .unwrap_or_default();
        SignedDataParts {
            digest_algorithms: fields[1].full.to_vec(),
            encap: fields[2].full.to_vec(),
            certificates,
            signer_infos: fields
                .last()
                .unwrap()
                .children()
                .iter()
                .map(|s| s.full.to_vec())
                .collect(),
        }
    }

    /// The content the encapsulated `OCTET STRING` holds.
    pub fn content(&self) -> Vec<u8> {
        let encap = parse_exact(&self.encap).unwrap();
        encap
            .child(1)
            .unwrap()
            .child(0)
            .unwrap()
            .octet_string_value()
            .unwrap()
            .into_owned()
    }

    /// An encapContentInfo of id-data holding `content`.
    pub fn encap_of(content: &[u8]) -> Vec<u8> {
        der_seq(&[
            der_oid(ID_DATA),
            der(tag::CONTEXT_0, &der(tag::OCTET_STRING, content)),
        ])
    }

    /// Rebuilt with definite lengths, the members in the order held.
    pub fn build(&self) -> Vec<u8> {
        let signed = der_seq(&[
            der_int(1),
            self.digest_algorithms.clone(),
            self.encap.clone(),
            der(tag::CONTEXT_0, &self.certificates.concat()),
            der_set(&self.signer_infos),
        ]);
        der_seq(&[der_oid(ID_SIGNED_DATA), der(tag::CONTEXT_0, &signed)])
    }
}

// --- the receipt payload --------------------------------------------------------

pub fn utf8(text: &str) -> Vec<u8> {
    der(tag::UTF8_STRING, text.as_bytes())
}

pub fn ia5(text: &str) -> Vec<u8> {
    der(tag::IA5_STRING, text.as_bytes())
}

/// The DER INTEGER of a non-negative `value`.
pub fn integer(value: u64) -> Vec<u8> {
    der_int(value)
}

/// One receipt attribute: type, version 1, and `value` in an OCTET STRING.
pub fn receipt_attribute(attribute_type: u64, value: &[u8]) -> Vec<u8> {
    der_seq(&[
        der_int(attribute_type),
        der_int(1),
        der(tag::OCTET_STRING, value),
    ])
}

/// `TestPki.receiptPayload(bundleId, appVersion, opaque, sha1, creation,
/// inApps)`: a ProductionSandbox receipt.
pub fn receipt_payload(
    bundle_id: &str,
    app_version: &str,
    opaque: &[u8],
    sha1_hash: &[u8],
    creation_date: &str,
    in_apps: &[Vec<u8>],
) -> Vec<u8> {
    receipt_payload_full(
        Some("ProductionSandbox"),
        bundle_id,
        app_version,
        opaque,
        sha1_hash,
        creation_date,
        in_apps,
        true,
    )
}

/// The same with the receipt type (attribute 0, `None` leaves it out) and
/// whether the creation date (attribute 12) is written.
#[allow(clippy::too_many_arguments)]
pub fn receipt_payload_full(
    receipt_type: Option<&str>,
    bundle_id: &str,
    app_version: &str,
    opaque: &[u8],
    sha1_hash: &[u8],
    creation_date: &str,
    in_apps: &[Vec<u8>],
    creation_date_attribute: bool,
) -> Vec<u8> {
    let mut attributes = Vec::new();
    if let Some(receipt_type) = receipt_type {
        attributes.push(receipt_attribute(0, &utf8(receipt_type)));
    }
    attributes.push(receipt_attribute(2, &utf8(bundle_id)));
    attributes.push(receipt_attribute(3, &utf8(app_version)));
    attributes.push(receipt_attribute(18, &ia5(creation_date)));
    attributes.push(receipt_attribute(4, opaque));
    attributes.push(receipt_attribute(5, sha1_hash));
    if creation_date_attribute {
        attributes.push(receipt_attribute(12, &ia5(creation_date)));
    }
    attributes.push(receipt_attribute(19, &utf8("1.0")));
    attributes.push(receipt_attribute(9999, &[1, 2, 3]));
    for in_app in in_apps {
        attributes.push(receipt_attribute(17, in_app));
    }
    der_set_sorted(&attributes)
}

/// `TestPki.inAppPurchase`: one attribute-17 value.
pub fn in_app_purchase(
    quantity: u64,
    product_id: &str,
    transaction_id: &str,
    original_transaction_id: &str,
    purchase_date: &str,
    expires_date: Option<&str>,
) -> Vec<u8> {
    let mut attributes = vec![
        receipt_attribute(1701, &integer(quantity)),
        receipt_attribute(1702, &utf8(product_id)),
        receipt_attribute(1703, &utf8(transaction_id)),
        receipt_attribute(1705, &utf8(original_transaction_id)),
        receipt_attribute(1704, &ia5(purchase_date)),
        receipt_attribute(1706, &ia5(purchase_date)),
    ];
    if let Some(expires) = expires_date {
        attributes.push(receipt_attribute(1708, &ia5(expires)));
    }
    attributes.push(receipt_attribute(1711, &integer(42)));
    der_set_sorted(&attributes)
}

/// `TestPki.singleAttributePayload`.
pub fn single_attribute_payload(attribute_type: u64, value: &[u8]) -> Vec<u8> {
    der_set(&[receipt_attribute(attribute_type, value)])
}

/// SHA-1 over the GUID, the opaque value and the bundle id's UTF8String.
pub fn device_hash(guid: &[u8], opaque: &[u8], bundle_id: &str) -> Vec<u8> {
    Hash::Sha1.digest(&[guid, opaque, &utf8(bundle_id)].concat())
}

/// The suites' `payload()`: one purchase, created now.
pub fn payload_now() -> Vec<u8> {
    payload_at(&now_rfc3339())
}

/// The suites' payload created at `creation_date`.
pub fn payload_at(creation_date: &str) -> Vec<u8> {
    receipt_payload(
        "com.example.app",
        "1.0",
        &[1, 2, 3, 4],
        &[5, 6, 7, 8],
        creation_date,
        &[in_app_purchase(
            1,
            "gems.small",
            "2001",
            "2001",
            creation_date,
            None,
        )],
    )
}

// --- the synthetic receipt ------------------------------------------------------

/// `SyntheticReceipts`: the shared generated receipt's payload and dates,
/// signed under a fresh PKI valid from 2024 to 2050.
pub struct Synthetic {
    pub pki: Pki,
    pub der: Vec<u8>,
}

pub const SYNTHETIC_BUNDLE: &str = "com.example.app";
const SYNTHETIC_CREATION: &str = "2024-08-06T12:00:00Z";
const SYNTHETIC_SIGNED: i64 = 1_722_945_600_000;
const SYNTHETIC_NOT_BEFORE: i64 = 1_704_067_200_000;
const SYNTHETIC_NOT_AFTER: i64 = 2_524_608_000_000;
const GUID: [u8; 16] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];
const OPAQUE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

impl Synthetic {
    pub fn new() -> Synthetic {
        let pki = Pki::receipt_with(SYNTHETIC_NOT_BEFORE, SYNTHETIC_NOT_AFTER, true, true);
        let payload = receipt_payload(
            SYNTHETIC_BUNDLE,
            "1.2.3",
            &OPAQUE,
            &device_hash(&GUID, &OPAQUE, SYNTHETIC_BUNDLE),
            SYNTHETIC_CREATION,
            &[
                in_app_purchase(
                    1,
                    "com.example.app.coins100",
                    "70000000000001",
                    "70000000000001",
                    "2024-01-15T12:00:00Z",
                    None,
                ),
                in_app_purchase(
                    1,
                    "com.example.app.vip",
                    "70000000000002",
                    "70000000000002",
                    "2024-02-01T09:30:00Z",
                    Some("2030-02-01T09:30:00Z"),
                ),
            ],
        );
        let der = pki.sign_receipt_at(&payload, SYNTHETIC_SIGNED);
        Synthetic { pki, der }
    }

    pub fn base64(&self) -> String {
        base64_encode(&self.der)
    }

    /// `LargeReceiptFixture.exactSize`: 2,300 purchases whose padded
    /// product ids grow the receipt to exactly `bytes` of DER.
    pub fn exact_size(&self, bytes: usize) -> Vec<u8> {
        const PURCHASES: usize = 2300;
        const PRODUCT_ID_LENGTH: usize = 262;
        let per_purchase = PURCHASES - 2;
        let sign = |id_length: usize, extra: usize| {
            self.pki.sign_receipt_at(
                &padded_purchases_payload(PURCHASES, id_length, extra),
                SYNTHETIC_SIGNED,
            )
        };
        let floor = sign(PRODUCT_ID_LENGTH, 0).len();
        let mut id_length = PRODUCT_ID_LENGTH + (bytes - floor) / per_purchase;
        let mut remainder = 0usize;
        for _ in 0..10 {
            let receipt = sign(id_length, remainder);
            if receipt.len() == bytes {
                return receipt;
            }
            if receipt.len() < bytes {
                remainder += bytes - receipt.len();
            } else {
                let over = receipt.len() - bytes;
                if over <= remainder {
                    remainder -= over;
                } else {
                    id_length -= over.div_ceil(per_purchase);
                    remainder = 0;
                }
            }
        }
        panic!("the receipt did not settle on {bytes} bytes");
    }
}

impl Default for Synthetic {
    fn default() -> Self {
        Synthetic::new()
    }
}

/// `count` purchases with product ids padded to `id_length` characters,
/// the second by `extra` more, the first and last kept short.
fn padded_purchases_payload(count: usize, id_length: usize, extra: usize) -> Vec<u8> {
    let in_apps: Vec<Vec<u8>> = (0..count)
        .map(|i| {
            let transaction_id = (70_000_000_000_000u64 + i as u64).to_string();
            let short = format!("{SYNTHETIC_BUNDLE}.coins{i}");
            let selectable = i == 0 || i == count - 1;
            let product_id = if selectable {
                short
            } else {
                let length = id_length + if i == 1 { extra } else { 0 };
                format!("{short:x<length$}")
            };
            in_app_purchase(
                1,
                &product_id,
                &transaction_id,
                &transaction_id,
                "2024-01-15T12:00:00Z",
                (i == count - 1).then_some("2030-02-01T09:30:00Z"),
            )
        })
        .collect();
    receipt_payload(
        SYNTHETIC_BUNDLE,
        "1.2.3",
        &OPAQUE,
        &device_hash(&GUID, &OPAQUE, SYNTHETIC_BUNDLE),
        SYNTHETIC_CREATION,
        &in_apps,
    )
}

// --- verdicts and costs ---------------------------------------------------------

/// The cost of one call, and its result.
pub fn timed<T>(body: impl FnOnce() -> T) -> (T, Duration) {
    let started = Instant::now();
    let result = body();
    (result, started.elapsed())
}

/// The fastest of `runs` calls, and the last result.
pub fn best_of<T>(runs: usize, mut body: impl FnMut() -> T) -> (T, Duration) {
    let mut best = Duration::MAX;
    let mut last = None;
    for _ in 0..runs {
        let (result, cost) = timed(&mut body);
        best = best.min(cost);
        last = Some(result);
    }
    (last.unwrap(), best)
}

/// One refusal: printed as `prefix what: N ms, REASON (message)`, refused
/// with one of `expected`, inside `BUDGET`.
pub fn refused(
    prefix: &str,
    what: &str,
    verifier: &Verifier,
    receipt: &str,
    expected: &[Reason],
) -> Failure {
    let (result, cost) = timed(|| verifier.verify_receipt(receipt));
    print_verdict(prefix, what, cost, &result);
    let failure = result.unwrap_err();
    assert!(
        expected.contains(&failure.reason()),
        "{what} refused as {:?}, expected one of {expected:?}: {failure}",
        failure.reason()
    );
    assert!(cost < BUDGET, "{what} took {cost:?}");
    failure
}

/// The same over DER.
pub fn refused_der(
    prefix: &str,
    what: &str,
    verifier: &Verifier,
    der: &[u8],
    expected: &[Reason],
) -> Failure {
    refused(prefix, what, verifier, &base64_encode(der), expected)
}

/// One verification, inside `BUDGET`, printed like a refusal.
pub fn verifies(prefix: &str, what: &str, verifier: &Verifier, receipt: &str) -> ReceiptPayload {
    let (result, cost) = timed(|| verifier.verify_receipt(receipt));
    print_verdict(prefix, what, cost, &result);
    let payload = result.unwrap_or_else(|failure| panic!("{what} was refused: {failure}"));
    assert!(cost < BUDGET, "{what} took {cost:?}");
    payload
}

pub fn verifies_der(prefix: &str, what: &str, verifier: &Verifier, der: &[u8]) -> ReceiptPayload {
    verifies(prefix, what, verifier, &base64_encode(der))
}

/// A verdict that may go either way, printed and bounded.
pub fn printed(
    prefix: &str,
    what: &str,
    verifier: &Verifier,
    der: &[u8],
) -> Result<ReceiptPayload, Failure> {
    let receipt = base64_encode(der);
    let (result, cost) = timed(|| verifier.verify_receipt(&receipt));
    print_verdict(prefix, what, cost, &result);
    assert!(cost < BUDGET, "{what} took {cost:?}");
    result
}

pub fn print_verdict(
    prefix: &str,
    what: &str,
    cost: Duration,
    result: &Result<ReceiptPayload, Failure>,
) {
    match result {
        Ok(_) => eprintln!("{prefix} {what}: {} ms, VERIFIED", cost.as_millis()),
        Err(failure) => eprintln!(
            "{prefix} {what}: {} ms, {:?} ({})",
            cost.as_millis(),
            failure.reason(),
            failure.message()
        ),
    }
}

/// The `status` an endpoint answer carries.
pub fn status_of(answer: &str) -> i64 {
    let value: serde_json::Value =
        serde_json::from_str(answer).unwrap_or_else(|_| panic!("not JSON: {answer:.100}"));
    value["status"]
        .as_i64()
        .unwrap_or_else(|| panic!("no status in: {answer:.100}"))
}

/// The endpoint's status for a body carrying `receipt` as `receipt-data`.
pub fn endpoint_status(
    verifier: &Verifier,
    environment: apple_purchase_receipt_verifier::Environment,
    receipt: &str,
) -> i64 {
    let body = serde_json::json!({ "receipt-data": receipt }).to_string();
    status_of(&verifier.verify_receipt_endpoint(environment, &body))
}

/// `bytes` decoded as ISO 8859-1, as Java's `new String(bytes, ISO_8859_1)`.
pub fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// `n` random bytes.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    if n > 0 {
        openssl::rand::rand_bytes(&mut out).unwrap();
    }
    out
}

/// A random number below `bound`.
pub fn random_below(bound: usize) -> usize {
    let mut bytes = [0u8; 8];
    openssl::rand::rand_bytes(&mut bytes).unwrap();
    (u64::from_le_bytes(bytes) % bound as u64) as usize
}

/// A `BigNumContext`, for the tests' own big-integer work.
pub fn bn_context() -> BigNumContext {
    BigNumContext::new().unwrap()
}
