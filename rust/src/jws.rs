//! [`Verifier::verify_signed_data`](crate::Verifier::verify_signed_data):
//! any Apple-signed compact JWS (`StoreKit` 2 `jwsRepresentation`, App Store
//! Server `signedTransactionInfo` and `signedRenewalInfo`, app transactions,
//! Server Notifications V2), verified offline.
//!
//! ES256 only, exactly three `x5c` certificates, the chain to a pinned root
//! at the payload's `signedDate` (the clock when it states none), Apple's
//! marker OIDs on leaf and intermediate, then the signature. The
//! order of the checks is observable: an input that fails an early check
//! reports that check's reason, and the shared cases pin it.

use crate::base64::{decode_base64url_strict, decode_receipt_base64};
use crate::environment::Environment;
use crate::error::{malformed, Failure, Reason};
use crate::json::{instant, string, strings, whole_object_members, JsonError, Members};
use crate::path::validate_pair;
use crate::roots::{TrustAnchor, SIGNING_LEAF_OID, WWDR_INTERMEDIATE_OID};
use crate::verifier::{self, Clock, Stage};
use aprv_openssl::{verify_es256, Certificate};
use core::fmt;

/// The longest compact JWS, in UTF-8 bytes, checked before the string is
/// split or any segment decoded, because everything below allocates in
/// proportion to it and none of it is behind a signature check. Every JWS
/// Apple signs is a few kilobytes, so 256 KiB is a hundredfold headroom.
pub(crate) const MAX_JWS_BYTES: usize = 262_144;

/// A verified JWS payload: the JSON object Apple signed, unchanged.
///
/// The library reads only `signedDate` and the environment from it. Parse
/// [`json`](JsonPayload::json) with the JSON library of your choice, into a
/// struct declaring the claims you use; Apple's claims are epoch
/// milliseconds already.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JsonPayload {
    json: String,
    environment: Option<Environment>,
}

impl JsonPayload {
    /// A payload. Public so callers can build one in their own tests; its
    /// [`environment`](JsonPayload::environment) is read from `json` as a
    /// verified payload's is.
    #[must_use]
    pub fn new(json: impl Into<String>) -> Self {
        let json = json.into();
        let environment = whole_object_members(&json)
            .ok()
            .and_then(|members| environment(&members));
        JsonPayload { json, environment }
    }

    /// The environment the payload names, from the first of the three
    /// places Apple documents that is present: the top-level `environment`
    /// (a transaction, renewal info), `data.environment` (an App Store
    /// Server Notification V2), `summary.environment` (a summary
    /// notification). `Production` is [`Environment::Production`] and
    /// `Sandbox` [`Environment::Sandbox`]; anything else there (`Xcode`,
    /// `LocalTesting`, a value that is not a string), or none of the three,
    /// is `None`. It states what Apple's value means and decides nothing;
    /// whether to accept it is the caller's decision.
    #[must_use]
    pub fn environment(&self) -> Option<Environment> {
        self.environment
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
/// the clock standing in for its signing date, and fails as
/// `INVALID_SIGNATURE` if the signature does not verify, `UNREADABLE_PAYLOAD`
/// if it does. Nothing unverified gets to decide which of the two a caller
/// sees.
pub(crate) fn verify(
    jws: &[u8],
    anchors: &[TrustAnchor],
    clock: &Clock<'_>,
) -> Result<JsonPayload, Failure> {
    if jws.len() > MAX_JWS_BYTES {
        return Err(Failure::new(
            Reason::TooLarge,
            format!("jws exceeds the maximum accepted size of {MAX_JWS_BYTES} bytes"),
        ));
    }
    // Split as bytes: input that is not UTF-8 is judged by the same rules,
    // and cannot be canonical base64url.
    let parts: Vec<&[u8]> = jws.split(|byte| *byte == b'.').collect();
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
    let payload = read_payload(&payload_bytes);
    // Chain validity is judged at the payload's signing date, so a payload
    // signed with a since-rotated certificate keeps verifying.
    let signed_date = payload.as_ref().ok().and_then(|read| read.signed_date);
    let at_millis = match signed_date {
        Some(millis) => millis,
        None => clock.now()?,
    };
    validate_pair(&leaf, &intermediate, anchors, at_millis)?;
    // The marker OIDs after the chain, as on the receipt path: a foreign
    // chain is UNTRUSTED_CHAIN whatever it carries, and only a pinned chain can be the wrong kind of Apple
    // certificate. Still before the leaf's key checks the JWS signature.
    if !leaf.has_extension(SIGNING_LEAF_OID) {
        return Err(Failure::new(
            Reason::InvalidCertificatePurpose,
            format!("leaf certificate lacks Apple marker OID {SIGNING_LEAF_OID}"),
        ));
    }
    if !intermediate.has_extension(WWDR_INTERMEDIATE_OID) {
        return Err(Failure::new(
            Reason::InvalidCertificatePurpose,
            format!("intermediate certificate lacks Apple marker OID {WWDR_INTERMEDIATE_OID}"),
        ));
    }
    if !leaf.has_usable_key() {
        return Err(invalid_certificate(
            "x5c entry has a public key this library cannot use",
        ));
    }
    verify_signature(&leaf, header_b64, payload_b64, &signature)?;
    verifier::enter(Stage::AfterSignature);
    match payload {
        Ok(read) => Ok(JsonPayload {
            json: read.json,
            environment: read.environment,
        }),
        Err(err) => Err(Failure::new(
            Reason::UnreadablePayload,
            "signed payload is not a JSON object",
        )
        .with_source(err)),
    }
}

/// The last `alg` string and the last `x5c` array of strings, as a map
/// would keep them. The header is outer structure, so anything that stops
/// the read is `MALFORMED`: bytes that are not strict UTF-8, a byte order
/// mark (RFC 8259 section 8.1 forbids one), and anything but whitespace
/// after the object.
fn read_header(bytes: &[u8]) -> Result<(Option<String>, Option<Vec<String>>), Failure> {
    let text = core::str::from_utf8(bytes).map_err(|_| malformed("header is not UTF-8"))?;
    let members =
        whole_object_members(text).map_err(|_| malformed("header is not a JSON object"))?;
    Ok((string(&members, "alg"), strings(&members, "x5c")))
}

/// What one read of a payload yields.
#[derive(Debug)]
struct ReadPayload {
    json: String,
    /// The last top-level `signedDate`.
    signed_date: Option<i64>,
    /// [`JsonPayload::environment`].
    environment: Option<Environment>,
}

/// The payload text, its last top-level `signedDate` and its environment,
/// or why it is not a JSON object in UTF-8. Reading it never fails
/// verification by itself.
///
/// A `signedDate` that is not a number, or is a number no instant can hold
/// (`1e300`), counts as not stated: the clock stands in for it.
fn read_payload(bytes: &[u8]) -> Result<ReadPayload, Unreadable> {
    let text = core::str::from_utf8(bytes).map_err(Unreadable::NotUtf8)?;
    let members = whole_object_members(text).map_err(Unreadable::NotAnObject)?;
    Ok(ReadPayload {
        json: text.to_owned(),
        signed_date: instant(&members, "signedDate"),
        environment: environment(&members),
    })
}

/// [`JsonPayload::environment`] of a payload's top-level members. The
/// first of `environment`, `data.environment` and `summary.environment`
/// that is present decides, whatever its value; a `data` or `summary` that
/// is not an object holds none. A repeated name keeps its last value, as
/// everywhere in a payload. `data` and `summary` were checked against the
/// grammar when the payload was read; reading their members is the one
/// further step, and one that does not read (a lone surrogate escape in a
/// member name) holds no environment.
fn environment(members: &Members<'_>) -> Option<Environment> {
    if members.contains_key("environment") {
        return Environment::from_jws_environment(string(members, "environment").as_deref());
    }
    for container in ["data", "summary"] {
        let Some(raw) = members.get(container) else {
            continue;
        };
        let Ok(inner) = whole_object_members(raw.get()) else {
            continue;
        };
        if inner.contains_key("environment") {
            return Environment::from_jws_environment(string(&inner, "environment").as_deref());
        }
    }
    None
}

fn verify_signature(
    leaf: &Certificate,
    header_b64: &[u8],
    payload_b64: &[u8],
    signature: &[u8],
) -> Result<(), Failure> {
    let mut signing_input = Vec::with_capacity(header_b64.len() + 1 + payload_b64.len());
    signing_input.extend_from_slice(header_b64);
    signing_input.push(b'.');
    signing_input.extend_from_slice(payload_b64);
    // False for a key that is not EC on P-256, and for a signature that is
    // not 64 bytes, as well as for one that does not match.
    if verify_es256(leaf, signature, &signing_input) {
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
    decode_receipt_base64(text.as_bytes())
        .ok_or_else(|| invalid_certificate("x5c entry is not valid base64"))
}

/// Only whether the entry IS a certificate: one that OpenSSL parses whole
/// and a strict reader decodes. Its key is judged when it is about to be
/// used, once a pinned anchor has vouched for it: the intermediate's in
/// [`validate_pair`], the leaf's before ES256, and the third entry's never.
fn parse_x5c_certificate(entry: &str) -> Result<Certificate, Failure> {
    let der = decode_x5c_entry(entry)?;
    Certificate::from_der(&der)
        .filter(Certificate::is_readable)
        .ok_or_else(|| invalid_certificate("x5c entry is not a valid certificate"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{read_header, read_payload, JsonPayload, Unreadable};
    use crate::{Environment, Reason};

    #[test]
    fn a_header_with_a_byte_order_mark_or_trailing_text_is_malformed() {
        let header = br#"{"alg":"ES256"}"#;
        assert_eq!(read_header(header).unwrap().0.as_deref(), Some("ES256"));
        assert!(read_header(b"{\"alg\":\"ES256\"}\n ").is_ok());
        let bom = [b"\xef\xbb\xbf".as_slice(), header].concat();
        let trailing = [header.as_slice(), b" x"].concat();
        let not_utf8 = [header.as_slice(), b" \xff"].concat();
        for bytes in [bom, trailing, not_utf8] {
            let failure = read_header(&bytes).unwrap_err();
            assert_eq!(failure.reason(), Reason::Malformed, "{bytes:?}");
        }
    }

    /// The three places Apple documents, the first present one deciding:
    /// a transaction or renewal info at the top level, a notification in
    /// `data`, a summary notification in `summary`.
    #[test]
    fn the_environment_is_read_from_the_first_of_three_places() {
        let production = Some(Environment::Production);
        let sandbox = Some(Environment::Sandbox);
        for (json, expected) in [
            (r#"{"environment":"Production"}"#, production),
            (r#"{"environment":"Sandbox","signedDate":1}"#, sandbox),
            (r#"{"data":{"environment":"Sandbox"}}"#, sandbox),
            (r#"{"summary":{"environment":"Production"}}"#, production),
            // The first present one decides, whatever it says.
            (
                r#"{"environment":"Xcode","data":{"environment":"Sandbox"}}"#,
                None,
            ),
            (
                r#"{"environment":null,"data":{"environment":"Sandbox"}}"#,
                None,
            ),
            (
                r#"{"data":{"environment":1},"summary":{"environment":"Sandbox"}}"#,
                None,
            ),
            (
                r#"{"summary":{"environment":"Sandbox"},"data":{"environment":"Production"}}"#,
                production,
            ),
            // Absent from a container that is there: the next one decides.
            (
                r#"{"data":{},"summary":{"environment":"Sandbox"}}"#,
                sandbox,
            ),
            (
                r#"{"data":"Sandbox","summary":{"environment":"Sandbox"}}"#,
                sandbox,
            ),
            // Anything but the two spellings is no environment.
            (r#"{"environment":"LocalTesting"}"#, None),
            (r#"{"environment":"sandbox"}"#, None),
            (r#"{"environment":"ProductionSandbox"}"#, None),
            (r#"{"data":{"data":{"environment":"Sandbox"}}}"#, None),
            (r#"{"transaction":{"environment":"Sandbox"}}"#, None),
            ("{}", None),
            // A repeated name keeps its last value, a container included.
            (
                r#"{"environment":"Sandbox","environment":"Production"}"#,
                production,
            ),
            (r#"{"data":{"environment":"Production"},"data":{}}"#, None),
            // Nested values inside a container are skipped whole.
            (
                r#"{"data":{"renewalInfo":{"environment":"Production"},"environment":"Sandbox"}}"#,
                sandbox,
            ),
        ] {
            let read = read_payload(json.as_bytes()).unwrap();
            assert_eq!(read.environment, expected, "{json}");
            assert_eq!(JsonPayload::new(json).environment(), expected, "{json}");
        }
        assert_eq!(JsonPayload::new("not json").environment(), None);
    }

    #[test]
    fn a_payload_with_trailing_text_is_unreadable() {
        assert!(read_payload(b"{\"signedDate\":1} \r\n").is_ok());
        assert!(matches!(
            read_payload(b"{\"signedDate\":1} {}"),
            Err(Unreadable::NotAnObject(_))
        ));
    }
}
