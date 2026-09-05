//! X.509 field extraction, built on this crate's own ASN.1 reader.
//!
//! Everything the chain walk needs from a certificate: the `tbsCertificate`
//! bytes the signature actually covers, the issuer and subject names it
//! chains on, the validity window, the `SubjectPublicKeyInfo`, the
//! signature algorithm and value, and the extensions the CA and Apple
//! marker checks read.
//!
//! The `tbsCertificate` slice is taken straight out of the input. Nothing is
//! re-encoded before it is verified, so the bytes checked are always the
//! bytes parsed.

use crate::asn1::{decode_oid, encode_oid, parse_exact, tag, Asn1Error, Tlv};
use std::borrow::Cow;
use std::collections::BTreeMap;

const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_KEY_USAGE: &str = "2.5.29.15";
const OID_SUBJECT_KEY_ID: &str = "2.5.29.14";
const OID_AUTHORITY_KEY_ID: &str = "2.5.29.35";

/// `rsaEncryption` — the SPKI algorithm of every receipt-signing key.
pub const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
/// `id-ecPublicKey` — the SPKI algorithm of every App Store JWS signing key.
pub const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

/// `keyUsage` bit 5 (RFC 5280 §4.2.1.3) — `keyCertSign`.
pub const KEY_CERT_SIGN_BIT: usize = 5;

/// A parsed X.509 certificate that owns its DER.
///
/// Every field is an owned copy, so a `Certificate` never aliases the
/// caller's input buffer: a caller reusing that buffer cannot mutate an
/// already-parsed certificate (contract rule S13).
#[derive(Debug, Clone)]
pub struct Certificate {
    der: Vec<u8>,
    tbs_bytes: Vec<u8>,
    serial_number: Vec<u8>,
    issuer_der: Vec<u8>,
    subject_der: Vec<u8>,
    not_before: Option<i64>,
    not_after: Option<i64>,
    spki: Vec<u8>,
    public_key_algorithm_oid: String,
    public_key_curve_oid: Option<String>,
    public_key_bits: Vec<u8>,
    signature_algorithm_oid: String,
    signature_value: Vec<u8>,
    is_ca: bool,
    key_usage: Option<Vec<bool>>,
    subject_key_id: Option<Vec<u8>>,
    authority_key_id: Option<Vec<u8>>,
    authority_cert_serial: Option<Vec<u8>>,
    extension_oids: Vec<Vec<u8>>,
}

impl Certificate {
    /// The certificate's complete DER.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The `tbsCertificate` TLV — exactly the bytes `signatureValue` covers.
    #[must_use]
    pub fn tbs_bytes(&self) -> &[u8] {
        &self.tbs_bytes
    }

    /// `serialNumber` content octets, as encoded.
    #[must_use]
    pub fn serial_number(&self) -> &[u8] {
        &self.serial_number
    }

    /// The issuer `Name` TLV; chains by byte equality with a subject.
    #[must_use]
    pub fn issuer_der(&self) -> &[u8] {
        &self.issuer_der
    }

    /// The subject `Name` TLV.
    #[must_use]
    pub fn subject_der(&self) -> &[u8] {
        &self.subject_der
    }

    /// `notBefore` as epoch milliseconds, or `None` when the encoded time is
    /// not one this parser can represent — in which case the certificate is
    /// valid at no instant at all.
    #[must_use]
    pub const fn not_before(&self) -> Option<i64> {
        self.not_before
    }

    /// `notAfter` as epoch milliseconds; see [`Certificate::not_before`].
    #[must_use]
    pub const fn not_after(&self) -> Option<i64> {
        self.not_after
    }

    /// The `SubjectPublicKeyInfo` TLV.
    #[must_use]
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    /// The SPKI algorithm OID.
    #[must_use]
    pub fn public_key_algorithm_oid(&self) -> &str {
        &self.public_key_algorithm_oid
    }

    /// The named-curve OID for an EC key.
    #[must_use]
    pub fn public_key_curve_oid(&self) -> Option<&str> {
        self.public_key_curve_oid.as_deref()
    }

    /// The `subjectPublicKey` bits, unused-bits octet removed.
    #[must_use]
    pub fn public_key_bits(&self) -> &[u8] {
        &self.public_key_bits
    }

    /// The certificate's outer `signatureAlgorithm` OID.
    #[must_use]
    pub fn signature_algorithm_oid(&self) -> &str {
        &self.signature_algorithm_oid
    }

    /// `signatureValue`, unused-bits octet removed.
    #[must_use]
    pub fn signature_value(&self) -> &[u8] {
        &self.signature_value
    }

    /// Whether the certificate may sign certificates: `basicConstraints`
    /// with `cA` true and, if a `keyUsage` extension is present, the
    /// `keyCertSign` bit set. This is `X509_check_ca(cert) == 1`.
    #[must_use]
    pub const fn is_ca(&self) -> bool {
        self.is_ca
    }

    /// The `keyUsage` bits, when the extension is present.
    #[must_use]
    pub fn key_usage(&self) -> Option<&[bool]> {
        self.key_usage.as_deref()
    }

    /// `subjectKeyIdentifier`, when present.
    #[must_use]
    pub fn subject_key_id(&self) -> Option<&[u8]> {
        self.subject_key_id.as_deref()
    }

    /// `authorityKeyIdentifier`'s `keyIdentifier [0]`, when present.
    #[must_use]
    pub fn authority_key_id(&self) -> Option<&[u8]> {
        self.authority_key_id.as_deref()
    }

    /// `authorityKeyIdentifier`'s `authorityCertSerialNumber [2]`.
    #[must_use]
    pub fn authority_cert_serial(&self) -> Option<&[u8]> {
        self.authority_cert_serial.as_deref()
    }

    /// Whether the certificate carries an extension with this OID.
    #[must_use]
    pub fn has_extension(&self, oid: &str) -> bool {
        match encode_oid(oid) {
            Some(wanted) => self.extension_oids.contains(&wanted),
            None => false,
        }
    }

    /// Whether the certificate is inside its validity window at an
    /// epoch-millisecond instant.
    #[must_use]
    pub fn valid_at(&self, millis: i64) -> bool {
        match (self.not_before, self.not_after) {
            (Some(from), Some(to)) => from <= millis && millis <= to,
            _ => false,
        }
    }

    /// Parses a DER certificate.
    ///
    /// # Errors
    /// Returns [`Asn1Error`] when the bytes are not a certificate this
    /// parser can represent. A certificate it cannot represent is rejected,
    /// never repaired.
    pub fn from_der(der: &[u8]) -> Result<Certificate, Asn1Error> {
        parse_certificate(der)
    }

    /// Parses a PEM certificate.
    ///
    /// # Errors
    /// Returns [`Asn1Error`] when the input holds no `CERTIFICATE` block or
    /// the block does not decode to a certificate.
    pub fn from_pem(pem: &str) -> Result<Certificate, Asn1Error> {
        const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
        const END: &str = "-----END CERTIFICATE-----";
        let start = pem
            .find(BEGIN)
            .ok_or(Asn1Error("no PEM CERTIFICATE block"))?;
        let body_start = start + BEGIN.len();
        let rest = pem
            .get(body_start..)
            .ok_or(Asn1Error("no PEM CERTIFICATE block"))?;
        let end = rest
            .find(END)
            .ok_or(Asn1Error("unterminated PEM CERTIFICATE block"))?;
        let body = rest
            .get(..end)
            .ok_or(Asn1Error("unterminated PEM CERTIFICATE block"))?;
        let der = crate::base64::decode_lenient(body);
        Certificate::from_der(&der)
    }
}

fn time_millis(node: &Tlv<'_>) -> Result<Option<i64>, Asn1Error> {
    if node.tag != tag::UTC_TIME && node.tag != tag::GENERALIZED_TIME {
        return Err(Asn1Error("unexpected Validity time type"));
    }
    let text = String::from_utf8_lossy(node.contents);
    // RFC 5280: UTCTime "YYMMDDHHMMSSZ", GeneralizedTime "YYYYMMDDHHMMSSZ".
    // Contents that are neither yield None rather than an error, which is
    // deliberate parity with OpenSSL: it stores an ASN1_TIME as an unchecked
    // string, so such a certificate parses and only fails later, when the
    // validity comparison can never be true. None here produces exactly
    // that — the certificate is valid at no instant.
    let year_digits = if node.tag == tag::UTC_TIME { 2 } else { 4 };
    let bytes = text.as_bytes();
    if bytes.len() != year_digits + 11 || bytes.last() != Some(&b'Z') {
        return Ok(None);
    }
    let field = |from: usize, len: usize| -> Option<i64> {
        let slice = bytes.get(from..from + len)?;
        let mut value = 0i64;
        for byte in slice {
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value * 10 + i64::from(byte - b'0');
        }
        Some(value)
    };
    let (Some(mut year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        field(0, year_digits),
        field(year_digits, 2),
        field(year_digits + 2, 2),
        field(year_digits + 4, 2),
        field(year_digits + 6, 2),
        field(year_digits + 8, 2),
    ) else {
        return Ok(None);
    };
    if node.tag == tag::UTC_TIME {
        year += if year >= 50 { 1900 } else { 2000 };
    }
    let iso = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z");
    Ok(crate::datetime::parse_rfc3339(&iso))
}

fn bit_string_bits(contents: &[u8]) -> Result<Vec<bool>, Asn1Error> {
    let unused = usize::from(*contents.first().ok_or(Asn1Error("empty BIT STRING"))?);
    if unused > 7 {
        return Err(Asn1Error("invalid BIT STRING unused-bit count"));
    }
    let body = contents.get(1..).unwrap_or(&[]);
    let mut bits = Vec::new();
    for (index, byte) in body.iter().enumerate() {
        let last = index + 1 == body.len();
        let count = if last { 8 - unused } else { 8 };
        for bit in 0..count {
            bits.push(byte & (0x80u8 >> bit) != 0);
        }
    }
    Ok(bits)
}

#[allow(clippy::too_many_lines)]
fn parse_certificate(der: &[u8]) -> Result<Certificate, Asn1Error> {
    let cert = parse_exact(der)?;
    if cert.tag != tag::SEQUENCE || cert.children().len() < 3 {
        return Err(Asn1Error("not an X.509 certificate"));
    }
    let tbs = cert.child(0).ok_or(Asn1Error("not an X.509 certificate"))?;
    let algorithm_node = cert.child(1).ok_or(Asn1Error("not an X.509 certificate"))?;
    let signature_node = cert.child(2).ok_or(Asn1Error("not an X.509 certificate"))?;
    if tbs.tag != tag::SEQUENCE {
        return Err(Asn1Error("unexpected TBSCertificate layout"));
    }
    let fields = tbs.children();
    let mut index = 0;
    if let Some(version) = fields.first().filter(|f| f.tag == tag::CONTEXT_0) {
        // version [0] EXPLICIT INTEGER. RFC 5280 defines 0, 1 and 2 (v1, v2,
        // v3) and nothing else. Nothing downstream reads the field, which is
        // exactly why it is checked here: a certificate claiming version 11
        // would otherwise parse like any other and verify on the strength of
        // its signature and extensions alone.
        let value = version
            .child(0)
            .filter(|node| node.tag == tag::INTEGER)
            .and_then(|node| match node.contents {
                [only] => Some(*only),
                _ => None,
            })
            .ok_or(Asn1Error("unknown X.509 certificate version"))?;
        if value > 2 {
            return Err(Asn1Error("unknown X.509 certificate version"));
        }
        index = 1;
    }
    let bad = Asn1Error("unexpected TBSCertificate layout");
    let serial = fields.get(index).ok_or(bad)?;
    let inner_signature = fields.get(index + 1).ok_or(bad)?;
    let issuer = fields.get(index + 2).ok_or(bad)?;
    let validity = fields.get(index + 3).ok_or(bad)?;
    let subject = fields.get(index + 4).ok_or(bad)?;
    let spki = fields.get(index + 5).ok_or(bad)?;
    if serial.tag != tag::INTEGER
        || issuer.tag != tag::SEQUENCE
        || validity.tag != tag::SEQUENCE
        || subject.tag != tag::SEQUENCE
        || spki.tag != tag::SEQUENCE
    {
        return Err(bad);
    }
    let not_before = time_millis(
        validity
            .child(0)
            .ok_or(Asn1Error("unexpected Validity layout"))?,
    )?;
    let not_after = time_millis(
        validity
            .child(1)
            .ok_or(Asn1Error("unexpected Validity layout"))?,
    )?;

    let spki_algorithm = spki
        .child(0)
        .filter(|node| node.tag == tag::SEQUENCE)
        .ok_or(Asn1Error("unexpected SubjectPublicKeyInfo layout"))?;
    let algorithm_oid_node = spki_algorithm
        .child(0)
        .filter(|node| node.tag == tag::OID)
        .ok_or(Asn1Error("unexpected SubjectPublicKeyInfo layout"))?;
    let public_key_algorithm_oid =
        decode_oid(algorithm_oid_node.contents).ok_or(Asn1Error("malformed algorithm OID"))?;
    let public_key_curve_oid = match spki_algorithm.child(1) {
        Some(node) if node.tag == tag::OID => decode_oid(node.contents),
        _ => None,
    };
    let key_bits_node = spki
        .child(1)
        .filter(|node| node.tag == tag::BIT_STRING && node.contents.len() >= 2)
        .ok_or(Asn1Error("unexpected subjectPublicKey layout"))?;

    if algorithm_node.tag != tag::SEQUENCE {
        return Err(Asn1Error("unexpected signatureAlgorithm layout"));
    }
    let outer_algorithm = algorithm_node
        .child(0)
        .filter(|node| node.tag == tag::OID)
        .ok_or(Asn1Error("unexpected signatureAlgorithm layout"))?;
    // RFC 5280 §4.1.1.2: the two AlgorithmIdentifiers must be the same one.
    // Without this, the algorithm the signature is checked under comes from
    // a field the signature does not cover.
    let inner_algorithm = inner_signature
        .child(0)
        .filter(|node| inner_signature.tag == tag::SEQUENCE && node.tag == tag::OID)
        .ok_or(Asn1Error("unexpected signatureAlgorithm layout"))?;
    if inner_algorithm.contents != outer_algorithm.contents {
        return Err(Asn1Error(
            "signatureAlgorithm disagrees with tbsCertificate.signature",
        ));
    }
    let signature_algorithm_oid =
        decode_oid(outer_algorithm.contents).ok_or(Asn1Error("malformed signature OID"))?;
    if signature_node.tag != tag::BIT_STRING || signature_node.contents.len() < 2 {
        return Err(Asn1Error("unexpected signatureValue layout"));
    }

    let mut extensions: Option<&Tlv<'_>> = None;
    for field in fields {
        if field.tag == tag::CONTEXT_3 {
            extensions = field.child(0);
        }
    }
    let extension_nodes: &[Tlv<'_>] = match extensions {
        Some(node) => node.children(),
        None => &[],
    };
    let mut by_oid: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut extension_oids: Vec<Vec<u8>> = Vec::new();
    for extension in extension_nodes {
        let parts = extension.children();
        let oid_node = parts
            .first()
            .ok_or(Asn1Error("malformed certificate extension"))?;
        let value_node = parts
            .last()
            .ok_or(Asn1Error("malformed certificate extension"))?;
        if oid_node.tag != tag::OID || !value_node.is_octet_string() {
            return Err(Asn1Error("malformed certificate extension"));
        }
        extension_oids.push(oid_node.contents.to_vec());
        let oid = decode_oid(oid_node.contents).ok_or(Asn1Error("malformed extension OID"))?;
        let value: Cow<'_, [u8]> = value_node
            .octet_string_value()
            .ok_or(Asn1Error("malformed certificate extension"))?;
        by_oid.entry(oid).or_insert_with(|| value.into_owned());
    }

    let key_usage = match by_oid.get(OID_KEY_USAGE) {
        Some(raw) => Some(bit_string_bits(parse_exact(raw)?.contents)?),
        None => None,
    };
    let basic_constraints_ca = match by_oid.get(OID_BASIC_CONSTRAINTS) {
        Some(raw) => {
            let value = parse_exact(raw)?;
            match value.child(0) {
                Some(first) => first.tag == tag::BOOLEAN && first.contents.first() != Some(&0x00),
                None => false,
            }
        }
        None => false,
    };
    let cert_sign_allowed = match &key_usage {
        Some(bits) => bits.get(KEY_CERT_SIGN_BIT) == Some(&true),
        None => true,
    };
    let subject_key_id = match by_oid.get(OID_SUBJECT_KEY_ID) {
        Some(raw) => Some(parse_exact(raw)?.contents.to_vec()),
        None => None,
    };
    let mut authority_key_id = None;
    let mut authority_cert_serial = None;
    if let Some(raw) = by_oid.get(OID_AUTHORITY_KEY_ID) {
        for part in parse_exact(raw)?.children() {
            if part.tag == tag::CONTEXT_0 {
                authority_key_id = Some(part.contents.to_vec());
            } else if part.tag == tag::CONTEXT_2 {
                authority_cert_serial = Some(part.contents.to_vec());
            }
        }
    }

    Ok(Certificate {
        der: der.to_vec(),
        tbs_bytes: tbs.full.to_vec(),
        serial_number: serial.contents.to_vec(),
        issuer_der: issuer.full.to_vec(),
        subject_der: subject.full.to_vec(),
        not_before,
        not_after,
        spki: spki.full.to_vec(),
        public_key_algorithm_oid,
        public_key_curve_oid,
        public_key_bits: key_bits_node.contents.get(1..).unwrap_or(&[]).to_vec(),
        signature_algorithm_oid,
        signature_value: signature_node.contents.get(1..).unwrap_or(&[]).to_vec(),
        is_ca: basic_constraints_ca && cert_sign_allowed,
        key_usage,
        subject_key_id,
        authority_key_id,
        authority_cert_serial,
        extension_oids,
    })
}
