//! Shared helpers for the native suite: fixture loading, a tiny DER writer,
//! and a CMS rebuilder that lets a test state one structural fault at a time.
#![allow(dead_code)]

use apple_purchase_receipt_verifier::__internal::asn1::tag;
use apple_purchase_receipt_verifier::__internal::{
    asn1, base64_decode_lenient, base64_encode, cms,
};
use apple_purchase_receipt_verifier::{
    Config, Failure, InAppPurchase, JsonPayload, ReceiptPayload, TrustAnchor, Verifier,
};
use std::path::{Path, PathBuf};

pub fn fixtures_dir() -> PathBuf {
    let mut dir: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join("fixtures");
        if candidate.join("cases-0.7.json").is_file() {
            return candidate;
        }
        dir = dir
            .parent()
            .expect("no fixtures/ above the crate directory");
    }
}

pub fn read_fixture(relative: &str) -> Vec<u8> {
    let path = fixtures_dir().join(relative);
    std::fs::read(&path).unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
}

pub fn read_base64_fixture(relative: &str) -> Vec<u8> {
    let text = String::from_utf8(read_fixture(relative)).expect("fixture is not UTF-8");
    base64_decode_lenient(text.trim())
}

pub fn read_text_fixture(relative: &str) -> String {
    String::from_utf8(read_fixture(relative))
        .expect("fixture is not UTF-8")
        .trim()
        .to_owned()
}

pub fn anchor(relative: &str) -> TrustAnchor {
    TrustAnchor::from_der(&read_fixture(relative)).expect("fixture is not a certificate")
}

// --- the shared generated corpus ---------------------------------------

pub fn transaction_jws() -> String {
    read_text_fixture("generated/transaction.jws")
}

pub fn app_transaction_jws() -> String {
    read_text_fixture("generated/app-transaction.jws")
}

pub fn jws_root() -> TrustAnchor {
    anchor("generated/jws-root.der")
}

/// The shared generated receipt, re-minted for 0.7 with the WWDR marker on
/// its intermediate (`fixtures/generated-0.7/`); the one under `generated/`
/// predates the marker check and now fails it.
pub fn receipt_der() -> Vec<u8> {
    read_fixture("generated-0.7/receipt.der")
}

pub fn receipt_root() -> TrustAnchor {
    anchor("generated-0.7/receipt-root.der")
}

// --- the 0.7 API, shortened ----------------------------------------------

/// A verifier pinned to `roots`, on the system clock.
pub fn verifier(roots: impl IntoIterator<Item = TrustAnchor>) -> Verifier {
    Verifier::new(Config::builder().roots(roots).build().expect("roots"))
}

/// A verifier pinned to `roots`, with the clock fixed at `now_millis`.
pub fn verifier_at(roots: impl IntoIterator<Item = TrustAnchor>, now_millis: i64) -> Verifier {
    Verifier::new(
        Config::builder()
            .roots(roots)
            .clock(move || now_millis)
            .build()
            .expect("roots"),
    )
}

pub fn receipt_verifier() -> Verifier {
    verifier([receipt_root()])
}

pub fn jws_verifier() -> Verifier {
    verifier([jws_root()])
}

/// `verify_receipt` over the base64 of `der`.
pub fn verify_der(verifier: &Verifier, der: &[u8]) -> Result<ReceiptPayload, Failure> {
    verifier.verify_receipt(&base64_encode(der))
}

/// The verified payload of a JWS, parsed.
pub fn claims(payload: &JsonPayload) -> serde_json::Map<String, serde_json::Value> {
    match serde_json::from_str(payload.json()).expect("payload is not JSON") {
        serde_json::Value::Object(map) => map,
        other => panic!("payload is not a JSON object: {other}"),
    }
}

/// The purchase with this product id.
pub fn purchase<'r>(receipt: &'r ReceiptPayload, product_id: &str) -> &'r InAppPurchase {
    receipt
        .in_app
        .iter()
        .find(|p| p.product_id.as_deref() == Some(product_id))
        .unwrap_or_else(|| panic!("no purchase {product_id}"))
}

pub fn device_guid() -> Vec<u8> {
    let hex_text = read_text_fixture("generated/device-guid.hex");
    hex::decode(hex_text).expect("device-guid.hex is not hex")
}

// --- base64url for rebuilt JWS segments ---------------------------------

pub fn base64url(bytes: &[u8]) -> String {
    base64_encode(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// Rebuilds a compact JWS from three already-encoded segments.
pub fn join_jws(header: &str, payload: &str, signature: &str) -> String {
    format!("{header}.{payload}.{signature}")
}

pub fn split_jws(jws: &str) -> (String, String, String) {
    let parts: Vec<&str> = jws.split('.').collect();
    (
        parts[0].to_owned(),
        parts[1].to_owned(),
        parts[2].to_owned(),
    )
}

/// The decoded header of a JWS, as a mutable JSON object.
pub fn jws_header(jws: &str) -> serde_json::Map<String, serde_json::Value> {
    let (header, _, _) = split_jws(jws);
    let bytes = base64_decode_lenient(&header);
    match serde_json::from_slice(&bytes).expect("header is not JSON") {
        serde_json::Value::Object(map) => map,
        other => panic!("header is not a JSON object: {other}"),
    }
}

/// A JWS whose header has been replaced. The signature no longer covers the
/// header, which is exactly right for the checks that run before it.
pub fn with_header(jws: &str, header: &serde_json::Map<String, serde_json::Value>) -> String {
    let (_, payload, signature) = split_jws(jws);
    let encoded = base64url(serde_json::to_string(header).unwrap().as_bytes());
    join_jws(&encoded, &payload, &signature)
}

// --- a minimal DER writer ------------------------------------------------

/// Encodes one TLV with a definite length.
pub fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = contents.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let mut bytes = Vec::new();
        let mut value = length;
        while value > 0 {
            bytes.insert(0, (value & 0xff) as u8);
            value >>= 8;
        }
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(contents);
    out
}

pub fn der_seq(parts: &[Vec<u8>]) -> Vec<u8> {
    der(tag::SEQUENCE, &parts.concat())
}

pub fn der_set(parts: &[Vec<u8>]) -> Vec<u8> {
    der(tag::SET, &parts.concat())
}

pub fn der_oid(dotted: &str) -> Vec<u8> {
    der(tag::OID, &asn1::encode_oid(dotted).expect("bad OID"))
}

pub fn der_int(value: u64) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes[0] >= 0x80 {
        bytes.insert(0, 0);
    }
    der(tag::INTEGER, &bytes)
}

/// A P-256 test PKI minted on the spot from fixed scalars, for tests that
/// need a signer no fixture has: a key type or digest Apple does not use, or
/// a payload of the test's own.
pub mod mint {
    use super::{der, der_int, der_oid, der_seq, der_set};
    use apple_purchase_receipt_verifier::__internal::asn1::tag;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{DerSignature, SigningKey};

    pub const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
    pub const RECEIPT_SIGNER_MARKER: &str = "1.2.840.113635.100.6.11.1";
    pub const WWDR_MARKER: &str = "1.2.840.113635.100.6.2.1";

    /// A JWS over `payload`, ES256-signed by a minted leaf whose x5c chain
    /// carries both Apple marker OIDs, and the DER of the root to pin.
    pub fn signed_jws(payload: &[u8]) -> (Vec<u8>, String) {
        let (root_key, intermediate_key, leaf_key) = (key(11), key(12), key(13));
        let root = certificate("JWS Root", &root_key, "JWS Root", &root_key, 1, true, None);
        let intermediate = certificate(
            "JWS WWDR",
            &intermediate_key,
            "JWS Root",
            &root_key,
            2,
            true,
            Some(WWDR_MARKER),
        );
        let leaf = certificate(
            "JWS Leaf",
            &leaf_key,
            "JWS WWDR",
            &intermediate_key,
            3,
            false,
            Some(RECEIPT_SIGNER_MARKER),
        );
        let header = format!(
            r#"{{"alg":"ES256","x5c":["{}","{}","{}"]}}"#,
            super::base64_encode(&leaf),
            super::base64_encode(&intermediate),
            super::base64_encode(&root)
        );
        let signing_input = format!(
            "{}.{}",
            super::base64url(header.as_bytes()),
            super::base64url(payload)
        );
        let signature: p256::ecdsa::Signature = leaf_key.sign(signing_input.as_bytes());
        let jws = format!(
            "{signing_input}.{}",
            super::base64url(&signature.to_bytes())
        );
        (root, jws)
    }

    pub fn key(scalar: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[31] = scalar;
        SigningKey::from_bytes(&bytes.into()).unwrap()
    }

    pub fn name(common_name: &str) -> Vec<u8> {
        der_seq(&[der_set(&[der_seq(&[
            der_oid("2.5.4.3"),
            der(0x0C, common_name.as_bytes()),
        ])])])
    }

    pub fn spki(key: &SigningKey) -> Vec<u8> {
        let point = key.verifying_key().to_encoded_point(false);
        let mut bits = vec![0x00];
        bits.extend_from_slice(point.as_bytes());
        der_seq(&[
            der_seq(&[der_oid("1.2.840.10045.2.1"), der_oid("1.2.840.10045.3.1.7")]),
            der(0x03, &bits),
        ])
    }

    pub fn certificate(
        subject: &str,
        subject_key: &SigningKey,
        issuer: &str,
        issuer_key: &SigningKey,
        serial: u64,
        ca: bool,
        marker: Option<&str>,
    ) -> Vec<u8> {
        certificate_for_spki(
            subject,
            spki(subject_key),
            issuer,
            issuer_key,
            serial,
            ca,
            marker,
        )
    }

    /// As [`certificate`], for a subject key given as its SPKI.
    pub fn certificate_for_spki(
        subject: &str,
        subject_spki: Vec<u8>,
        issuer: &str,
        issuer_key: &SigningKey,
        serial: u64,
        ca: bool,
        marker: Option<&str>,
    ) -> Vec<u8> {
        let algorithm = der_seq(&[der_oid(ECDSA_WITH_SHA256)]);
        let tbs = tbs(
            subject,
            subject_spki,
            issuer,
            serial,
            ca,
            marker,
            &algorithm,
        );
        let signature: DerSignature = issuer_key.sign(&tbs);
        assemble(tbs, algorithm, signature.as_bytes())
    }

    /// A `TBSCertificate` stating `algorithm` as its signature algorithm.
    pub fn tbs(
        subject: &str,
        subject_spki: Vec<u8>,
        issuer: &str,
        serial: u64,
        ca: bool,
        marker: Option<&str>,
        algorithm: &[u8],
    ) -> Vec<u8> {
        let mut extensions = Vec::new();
        if ca {
            extensions.push(der_seq(&[
                der_oid("2.5.29.19"),
                der(0x01, &[0xFF]),
                der(tag::OCTET_STRING, &der_seq(&[der(0x01, &[0xFF])])),
            ]));
        }
        if let Some(oid) = marker {
            extensions.push(der_seq(&[
                der_oid(oid),
                der(tag::OCTET_STRING, &[0x05, 0x00]),
            ]));
        }
        der_seq(&[
            der(tag::CONTEXT_0, &der_int(2)),
            der_int(serial),
            algorithm.to_vec(),
            name(issuer),
            der_seq(&[der(0x17, b"200101000000Z"), der(0x18, b"20991231000000Z")]),
            name(subject),
            subject_spki,
            der(0xA3, &der_seq(&extensions)),
        ])
    }

    /// The certificate: `tbs`, the same `algorithm`, and `signature`.
    pub fn assemble(tbs: Vec<u8>, algorithm: Vec<u8>, signature: &[u8]) -> Vec<u8> {
        let mut bits = vec![0x00];
        bits.extend_from_slice(signature);
        der_seq(&[tbs, algorithm, der(0x03, &bits)])
    }
}

// --- CMS rebuilding ------------------------------------------------------

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_DATA: &str = "1.2.840.113549.1.7.1";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
const OID_RSA: &str = "1.2.840.113549.1.1.1";

/// The pieces of the shared generated receipt, so a test can rebuild it with
/// exactly one thing changed.
pub struct ReceiptParts {
    pub content: Vec<u8>,
    pub certificates: Vec<Vec<u8>>,
    pub signer_issuer: Vec<u8>,
    pub signer_serial: Vec<u8>,
    pub signed_attrs: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}

pub fn receipt_parts() -> ReceiptParts {
    let der = receipt_der();
    let parsed = cms::parse_cms(&der).expect("the shared receipt must parse");
    ReceiptParts {
        content: parsed.content,
        certificates: parsed.certificates,
        signer_issuer: parsed.signer_infos[0].issuer_raw.clone(),
        signer_serial: parsed.signer_infos[0].serial_contents.clone(),
        signed_attrs: parsed.signer_infos[0].signed_attrs.clone(),
        signature: parsed.signer_infos[0].signature.clone(),
    }
}

/// Everything a rebuilt CMS can vary. Defaults reproduce a structurally
/// valid `SignedData`; each test flips one field.
pub struct CmsBuilder {
    pub content: Option<Vec<u8>>,
    pub certificates: Vec<Vec<u8>>,
    pub digest_oid: String,
    pub signer_issuer: Vec<u8>,
    pub signer_serial: Vec<u8>,
    pub signed_attrs: Option<Vec<u8>>,
    pub signature: Vec<u8>,
    pub include_signer_info: bool,
    pub content_as_sequence: bool,
    /// The complete eContent TLV, used verbatim in place of the
    /// `OCTET STRING` the builder would otherwise write. Lets a test state a
    /// BER re-encoding of the payload that leaves `cms.content` — and so the
    /// bytes the signature covers — unchanged.
    pub content_tlv: Option<Vec<u8>>,
    /// How many times the one `SignerInfo` is repeated.
    pub signer_info_copies: usize,
    /// The `SignerInfo`'s `signatureAlgorithm` TLV.
    pub signature_algorithm: Vec<u8>,
    /// Complete `SignerInfo` TLVs written before and after the builder's own.
    pub signer_infos_before: Vec<Vec<u8>>,
    pub signer_infos_after: Vec<Vec<u8>>,
}

impl CmsBuilder {
    pub fn from_shared() -> Self {
        let parts = receipt_parts();
        CmsBuilder {
            content: Some(parts.content),
            certificates: parts.certificates,
            digest_oid: OID_SHA256.to_owned(),
            signer_issuer: parts.signer_issuer,
            signer_serial: parts.signer_serial,
            signed_attrs: parts.signed_attrs,
            signature: parts.signature,
            include_signer_info: true,
            content_as_sequence: false,
            content_tlv: None,
            signer_info_copies: 1,
            signature_algorithm: der_seq(&[der_oid(OID_RSA), der(0x05, &[])]),
            signer_infos_before: Vec::new(),
            signer_infos_after: Vec::new(),
        }
    }

    /// The builder's own `SignerInfo` TLV.
    pub fn signer_info(&self) -> Vec<u8> {
        let mut fields = vec![
            der_int(1),
            der_seq(&[
                self.signer_issuer.clone(),
                der(tag::INTEGER, &self.signer_serial),
            ]),
            der_seq(&[der_oid(&self.digest_oid)]),
        ];
        if let Some(signed_attrs) = &self.signed_attrs {
            fields.push(signed_attrs.clone());
        }
        fields.push(self.signature_algorithm.clone());
        fields.push(der(tag::OCTET_STRING, &self.signature));
        der_seq(&fields)
    }

    pub fn with_sha512_digest(mut self) -> Self {
        self.digest_oid = OID_SHA512.to_owned();
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut encap_parts = vec![der_oid(OID_DATA)];
        if let Some(tlv) = &self.content_tlv {
            encap_parts.push(der(tag::CONTEXT_0, tlv));
        } else if let Some(content) = &self.content {
            let inner = if self.content_as_sequence {
                der(tag::SEQUENCE, content)
            } else {
                der(tag::OCTET_STRING, content)
            };
            encap_parts.push(der(tag::CONTEXT_0, &inner));
        }
        let encap = der_seq(&encap_parts);

        let certificates = der(tag::CONTEXT_0, &self.certificates.concat());

        let mut signer_infos_parts: Vec<Vec<u8>> = self.signer_infos_before.clone();
        if self.include_signer_info {
            let signer_info = self.signer_info();
            for _ in 0..self.signer_info_copies {
                signer_infos_parts.push(signer_info.clone());
            }
        }
        signer_infos_parts.extend(self.signer_infos_after.iter().cloned());
        let signer_infos = der_set(&signer_infos_parts);

        let signed_data = der_seq(&[
            der_int(1),
            der_set(&[der_seq(&[der_oid(&self.digest_oid)])]),
            encap,
            certificates,
            signer_infos,
        ]);
        der_seq(&[der_oid(OID_SIGNED_DATA), der(tag::CONTEXT_0, &signed_data)])
    }
}

/// A deterministic, replayable byte-mutation source. Fixed seed, xorshift —
/// no dependency, and a failure is reproducible from the printed index.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }
}
