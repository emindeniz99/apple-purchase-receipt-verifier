//! Shared helpers for the native suite: fixture loading, a tiny DER writer,
//! and a CMS rebuilder that lets a test state one structural fault at a time.
#![allow(dead_code)]

use apple_purchase_receipt_verifier::asn1::tag;
use apple_purchase_receipt_verifier::{base64, cms, TrustAnchor};
use std::path::{Path, PathBuf};

pub fn fixtures_dir() -> PathBuf {
    let mut dir: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join("fixtures");
        if candidate.join("cases.json").is_file() {
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
    base64::decode_lenient(text.trim())
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

pub fn receipt_der() -> Vec<u8> {
    read_fixture("generated/receipt.der")
}

pub fn receipt_root() -> TrustAnchor {
    anchor("generated/receipt-root.der")
}

pub fn device_guid() -> Vec<u8> {
    let hex_text = read_text_fixture("generated/device-guid.hex");
    hex::decode(hex_text).expect("device-guid.hex is not hex")
}

// --- base64url for rebuilt JWS segments ---------------------------------

pub fn base64url(bytes: &[u8]) -> String {
    base64::encode(bytes)
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
    let bytes = base64::decode_lenient(&header);
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
    der(
        tag::OID,
        &apple_purchase_receipt_verifier::asn1::encode_oid(dotted).expect("bad OID"),
    )
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
        signer_issuer: parsed.signer_info.issuer_raw,
        signer_serial: parsed.signer_info.serial_contents,
        signed_attrs: parsed.signer_info.signed_attrs,
        signature: parsed.signer_info.signature,
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
        }
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

        let mut signer_infos_parts: Vec<Vec<u8>> = Vec::new();
        if self.include_signer_info {
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
            fields.push(der_seq(&[der_oid(OID_RSA), der(0x05, &[])]));
            fields.push(der(tag::OCTET_STRING, &self.signature));
            signer_infos_parts.push(der_seq(&fields));
        }
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
