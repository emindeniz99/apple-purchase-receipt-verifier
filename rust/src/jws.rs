//! [`Verifier::verify_signed_data`](crate::Verifier::verify_signed_data):
//! any Apple-signed compact JWS (`StoreKit` 2 `jwsRepresentation`, App Store
//! Server `signedTransactionInfo` and `signedRenewalInfo`, app transactions,
//! Server Notifications V2), verified offline.
//!
//! ES256 only, exactly three `x5c` certificates, Apple's marker OIDs on leaf
//! and intermediate, the chain to a pinned root at the payload's
//! `signedDate` (the clock when it states none), then the signature. The
//! order of the checks is observable: an input that fails an early check
//! reports that check's reason, and the shared cases pin it.

use crate::base64::{decode_base64url_strict, decode_receipt_base64};
use crate::chain::validate_pair;
use crate::crypto::{curve_field_size, record_key_use, verify_es256};
use crate::error::{Failure, Reason};
use crate::json::{instant, top_level_members, JsonError, Value};
use crate::roots::TrustAnchor;
use crate::x509::{Certificate, OID_EC_PUBLIC_KEY};
use core::fmt;

/// Apple marker OID: a leaf certificate used for App Store signing.
pub(crate) const LEAF_OID: &str = "1.2.840.113635.100.6.11.1";
/// Apple marker OID: the Worldwide Developer Relations intermediate CA.
pub(crate) const INTERMEDIATE_OID: &str = "1.2.840.113635.100.6.2.1";

/// The longest compact JWS, in UTF-8 bytes, checked before the string is
/// split or any segment decoded, because everything below allocates in
/// proportion to it and none of it is behind a signature check. Every JWS
/// Apple signs is a few kilobytes, so 256 KiB is a hundredfold headroom.
pub(crate) const MAX_JWS_BYTES: usize = 262_144;

/// A verified JWS payload: the JSON object Apple signed, unchanged.
///
/// The library reads only `signedDate` from it. Parse
/// [`json`](JsonPayload::json) with the JSON library of your choice, into a
/// struct declaring the claims you use; Apple's claims are epoch
/// milliseconds already.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JsonPayload {
    json: String,
}

impl JsonPayload {
    /// A payload. Public so callers can build one in their own tests.
    #[must_use]
    pub fn new(json: impl Into<String>) -> Self {
        JsonPayload { json: json.into() }
    }

    /// The verified payload, exactly as signed.
    #[must_use]
    pub fn json(&self) -> &str {
        &self.json
    }

    /// The verified payload, owned.
    #[must_use]
    pub fn into_json(self) -> String {
        self.json
    }
}

impl fmt::Display for JsonPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.json)
    }
}

fn malformed(detail: impl Into<String>) -> Failure {
    Failure::new(Reason::Malformed, detail)
}

fn invalid_certificate(detail: &'static str) -> Failure {
    Failure::new(Reason::InvalidCertificate, detail)
}

/// Why a payload does not read as a JSON object in UTF-8.
#[derive(Debug)]
enum Unreadable {
    NotUtf8(core::str::Utf8Error),
    NotAnObject(JsonError),
}

impl fmt::Display for Unreadable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unreadable::NotUtf8(err) => write!(f, "not UTF-8: {err}"),
            Unreadable::NotAnObject(err) => write!(f, "not a JSON object: {err}"),
        }
    }
}

impl std::error::Error for Unreadable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Unreadable::NotUtf8(err) => Some(err),
            Unreadable::NotAnObject(err) => Some(err),
        }
    }
}

/// Verifies `jws` and returns its payload.
///
/// A broken outer structure fails as `MALFORMED` before any cryptography:
/// not three segments, a segment that is not canonical base64url, a header
/// that is not a JSON object, an `alg` other than ES256, an `x5c` that is not
/// three strings. A payload that does not parse as a JSON object is not
/// reported there: it is carried past the chain and signature checks with
/// `now_millis` standing in for its signing date, and fails as
/// `INVALID_SIGNATURE` if the signature does not verify, `UNREADABLE_PAYLOAD`
/// if it does. Nothing unverified gets to decide which of the two a caller
/// sees.
pub(crate) fn verify(
    jws: &str,
    anchors: &[TrustAnchor],
    now_millis: i64,
) -> Result<JsonPayload, Failure> {
    if jws.is_empty() {
        return Err(malformed("jws is empty"));
    }
    if jws.len() > MAX_JWS_BYTES {
        return Err(Failure::new(
            Reason::TooLarge,
            format!("jws exceeds the maximum accepted size of {MAX_JWS_BYTES} bytes"),
        ));
    }
    let parts: Vec<&str> = jws.split('.').collect();
    let [header_b64, payload_b64, signature_b64] = parts.as_slice() else {
        return Err(malformed(format!(
            "expected 3 dot-separated segments, got {}",
            parts.len()
        )));
    };
    // Strict, not lenient: a lenient reading would give one Apple-signed
    // payload unboundedly many accepted wire forms, and the signature
    // segment is not covered by the signature at all.
    let header_bytes = decode_base64url_strict(header_b64)
        .ok_or_else(|| malformed("header is not canonical base64url"))?;
    let payload_bytes = decode_base64url_strict(payload_b64)
        .ok_or_else(|| malformed("payload is not canonical base64url"))?;
    let signature = decode_base64url_strict(signature_b64)
        .ok_or_else(|| malformed("signature is not canonical base64url"))?;

    let (alg, x5c) = read_header(&header_bytes)?;
    if alg.as_deref() != Some("ES256") {
        return Err(malformed("alg must be ES256"));
    }
    let Some([leaf_entry, intermediate_entry, root_entry]) = x5c.as_deref() else {
        return Err(malformed("x5c must contain exactly 3 certificates"));
    };
    let leaf = parse_x5c_certificate(leaf_entry)?;
    let intermediate = parse_x5c_certificate(intermediate_entry)?;
    // Parsed and then dropped: the third entry is trusted by nobody, and
    // reading it decides only whether it IS a certificate.
    parse_x5c_certificate(root_entry)?;
    // The marker OIDs are checked before the chain on the JWS path.
    if !leaf.has_extension(LEAF_OID) {
        return Err(Failure::new(
            Reason::InvalidCertificatePurpose,
            format!("leaf certificate lacks Apple marker OID {LEAF_OID}"),
        ));
    }
    if !intermediate.has_extension(INTERMEDIATE_OID) {
        return Err(Failure::new(
            Reason::InvalidCertificatePurpose,
            format!("intermediate certificate lacks Apple marker OID {INTERMEDIATE_OID}"),
        ));
    }

    let payload = read_payload(&payload_bytes);
    // Chain validity is judged at the payload's signing date, so a payload
    // signed with a since-rotated certificate keeps verifying.
    let signed_date = payload.as_ref().ok().and_then(|(_, date)| *date);
    validate_pair(
        &leaf,
        &intermediate,
        anchors,
        signed_date.unwrap_or(now_millis),
    )?;
    verify_signature(&leaf, header_b64, payload_b64, &signature)?;
    match payload {
        Ok((json, _)) => Ok(JsonPayload { json }),
        Err(err) => Err(Failure::new(
            Reason::UnreadablePayload,
            "signed payload is not a JSON object",
        )
        .with_source(err)),
    }
}

/// The last `alg` string and the last `x5c` array of strings, as a map
/// would keep them. The header is outer structure, so anything that stops
/// the read is `MALFORMED`.
fn read_header(bytes: &[u8]) -> Result<(Option<String>, Option<Vec<String>>), Failure> {
    // A UTF-8 byte order mark is skipped, as a byte-oriented JSON reader
    // skips one.
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let text = core::str::from_utf8(bytes).map_err(|_| malformed("header is not UTF-8"))?;
    let members = top_level_members(text).map_err(|_| malformed("header is not a JSON object"))?;
    let mut alg = None;
    let mut x5c = None;
    for (name, value) in members {
        match name.as_str() {
            "alg" => {
                alg = match value {
                    Value::String(text) => Some(text),
                    _ => None,
                };
            }
            "x5c" => {
                x5c = match value {
                    Value::Strings(entries) => Some(entries),
                    _ => None,
                };
            }
            _ => {}
        }
    }
    Ok((alg, x5c))
}

/// The payload text and its last top-level `signedDate`, or why it is not a
/// JSON object in UTF-8. Reading it never fails verification by itself.
///
/// A `signedDate` that is not a number, or is a number no instant can hold
/// (`1e300`), counts as not stated: the clock stands in for it (owner,
/// 2026-09-27).
fn read_payload(bytes: &[u8]) -> Result<(String, Option<i64>), Unreadable> {
    let text = core::str::from_utf8(bytes).map_err(Unreadable::NotUtf8)?;
    let members = top_level_members(text).map_err(Unreadable::NotAnObject)?;
    let mut signed_date = None;
    for (name, value) in members {
        if name == "signedDate" {
            signed_date = match value {
                Value::Number { text, integer } => instant(text, integer),
                _ => None,
            };
        }
    }
    Ok((text.to_owned(), signed_date))
}

fn verify_signature(
    leaf: &Certificate,
    header_b64: &str,
    payload_b64: &str,
    signature: &[u8],
) -> Result<(), Failure> {
    if leaf.public_key_algorithm_oid() != OID_EC_PUBLIC_KEY {
        return Err(Failure::new(Reason::InvalidSignature, "leaf key is not EC"));
    }
    if signature.len() != 64 {
        return Err(Failure::new(
            Reason::InvalidSignature,
            format!("ES256 signature must be 64 bytes, got {}", signature.len()),
        ));
    }
    let mut signing_input = Vec::with_capacity(header_b64.len() + 1 + payload_b64.len());
    signing_input.extend_from_slice(header_b64.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(payload_b64.as_bytes());
    record_key_use(leaf.spki());
    if verify_es256(leaf.public_key_bits(), signature, &signing_input) {
        Ok(())
    } else {
        Err(Failure::new(
            Reason::InvalidSignature,
            "ES256 signature does not match the leaf key",
        ))
    }
}

/// Decodes one `x5c` entry: standard base64 with canonical padding
/// (RFC 7515 4.1.6), then a certificate. Package-internal so the shared
/// decodeBase64 cases can reach the decoder directly.
pub(crate) fn decode_x5c_entry(text: &str) -> Result<Vec<u8>, Failure> {
    decode_receipt_base64(text).ok_or_else(|| invalid_certificate("x5c entry is not valid base64"))
}

/// An EC key on a curve this crate does not implement is a defect of the
/// certificate, not of the path it sits on: there is no key to check an
/// issuance against.
fn parse_x5c_certificate(entry: &str) -> Result<Certificate, Failure> {
    let der = decode_x5c_entry(entry)?;
    let certificate = Certificate::from_der(&der)
        .map_err(|_| invalid_certificate("x5c entry is not a valid certificate"))?;
    if certificate.public_key_algorithm_oid() == OID_EC_PUBLIC_KEY
        && certificate
            .public_key_curve_oid()
            .and_then(curve_field_size)
            .is_none()
    {
        return Err(invalid_certificate(
            "x5c entry uses an unimplemented elliptic curve",
        ));
    }
    Ok(certificate)
}
