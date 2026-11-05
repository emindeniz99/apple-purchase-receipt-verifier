//! Certificate revocation (docs/design/revocation.md): the built-in list,
//! the configuration's `distrust` and the revocation lists a caller
//! downloads, all evaluated offline.
//!
//! OpenSSL parses each list and checks its signature (the adapter's
//! `RevocationList`); this module keeps the policy: which issuer a list
//! belongs to, which lists are refused and which ignored, which one list
//! per issuer is kept, which certificates sign lists, and what an entry
//! means for a certificate on a verified path. Nothing here reads a clock
//! when the configuration is built; a `certificateHold` entry is judged at
//! the call's `now`, read only when such an entry matches.

use crate::error::{ConfigError, Failure, Reason};
use crate::roots::{
    sha256_hex, TrustAnchor, REVOCATIONS_JSON, REVOCATIONS_JSON_SHA256, REVOCATION_ISSUER_DER,
    REVOCATION_ISSUER_SHA256, WWDR_INTERMEDIATE_OID,
};
use crate::verifier::Clock;
use aprv_openssl::{Certificate, Integer, KeyIdentifier, ListEntry, ListField, RevocationList};
use core::fmt::Write;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

/// The most lists a configuration may hold.
pub(crate) const MAX_LISTS: usize = 16;
/// The largest list, in bytes: 1 MiB. Apple's frozen WWDR G1 list (2.3 MB)
/// is over it.
pub(crate) const MAX_LIST_BYTES: usize = 1_048_576;
/// The most entries all lists together may hold.
pub(crate) const MAX_ENTRIES: usize = 100_000;
/// The most `distrust` entries.
pub(crate) const MAX_DISTRUST: usize = 1_000;

/// The extensions this profile reads (RFC 5280 sections 4.2.1.1, 5.2.3,
/// 5.3.1, 5.3.2) and the ones that make a list one it does not support
/// (sections 5.2.5, 5.2.4, 5.2.6, 5.3.3).
const AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
const CRL_NUMBER: &str = "2.5.29.20";
const REASON_CODE: &str = "2.5.29.21";
const INVALIDITY_DATE: &str = "2.5.29.24";
const ISSUING_DISTRIBUTION_POINT: &str = "2.5.29.28";
const DELTA_CRL_INDICATOR: &str = "2.5.29.27";
const FRESHEST_CRL: &str = "2.5.29.46";
const CERTIFICATE_ISSUER: &str = "2.5.29.29";

/// `CRLReason` values with a meaning of their own here (RFC 5280 section
/// 5.3.1); every other value, and none, revokes.
const CERTIFICATE_HOLD: i64 = 6;
const REMOVE_FROM_CRL: i64 = 8;

// ------------------------------------------------------------ identifiers

/// A certificate's issuer id (§2): lowercase hex of SHA-256 over its
/// `subject` and `subjectPublicKeyInfo`, each as encoded in its
/// `TBSCertificate`.
pub(crate) fn issuer_id(certificate: &Certificate) -> Option<String> {
    let (subject, key) = certificate.subject_and_key_der()?;
    Some(sha256_hex(&[subject, key].concat()))
}

/// A serial (or CRL Number) as §2 writes it: uppercase hex, an even number
/// of digits, no leading `00` pair unless the value is zero. `None` for a
/// negative value, which is never matched.
pub(crate) fn integer_hex(integer: &Integer) -> Option<String> {
    if integer.negative {
        return None;
    }
    let significant: Vec<u8> = integer
        .magnitude
        .iter()
        .copied()
        .skip_while(|byte| *byte == 0)
        .collect();
    if significant.is_empty() {
        return Some("00".to_owned());
    }
    let mut hex = String::with_capacity(significant.len() * 2);
    for byte in significant {
        // Writing to a String cannot fail.
        let _ = write!(hex, "{byte:02X}");
    }
    Some(hex)
}

/// A hex serial as a caller writes it, normalised as [`integer_hex`]
/// writes one: either letter case and any digit count are accepted.
/// `None` when it is empty or holds anything but hex digits.
pub(crate) fn normalise_hex(text: &str) -> Option<String> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let digits = text.trim_start_matches('0').to_ascii_uppercase();
    Some(match digits.len() {
        0 => "00".to_owned(),
        n if n % 2 == 1 => format!("0{digits}"),
        _ => digits,
    })
}

/// Numeric order of two hex values written by [`normalise_hex`]: no
/// leading `00` pair, so a longer one is larger.
fn compare_hex(a: &str, b: &str) -> core::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn is_issuer_id(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

// --------------------------------------------------------- the built-in list

/// The newest list the built-in file records for an issuer (§5).
#[derive(Debug, Clone)]
struct Newest {
    number: Option<String>,
    this_update_ms: i64,
}

/// One of the built-in file's `issuers`.
#[derive(Debug, Clone)]
struct BuiltInIssuer {
    id: String,
    list: String,
    /// The issuer's certificate, or `None` for a root, which is used only
    /// when it is a configured root.
    certificate: Option<Certificate>,
    newest: Newest,
}

/// The built-in revocation list (§5), parsed.
#[derive(Debug)]
pub(crate) struct BuiltIn {
    issuers: Vec<BuiltInIssuer>,
    /// (issuer id, serial) of every entry.
    revoked: BTreeSet<(String, String)>,
}

impl BuiltIn {
    /// The list compiled into this library, parsed once per process, or
    /// `None` when a file does not match its pin or does not read.
    pub(crate) fn compiled() -> Option<Arc<BuiltIn>> {
        static BUILT_IN: OnceLock<Option<Arc<BuiltIn>>> = OnceLock::new();
        BUILT_IN
            .get_or_init(|| {
                if sha256_hex(REVOCATIONS_JSON) != REVOCATIONS_JSON_SHA256
                    || REVOCATION_ISSUER_DER
                        .iter()
                        .zip(REVOCATION_ISSUER_SHA256)
                        .any(|(der, pin)| sha256_hex(der) != pin)
                {
                    return None;
                }
                BuiltIn::parse(REVOCATIONS_JSON, &REVOCATION_ISSUER_DER).map(Arc::new)
            })
            .clone()
    }

    /// Reads a list in the format of `certs/revocations.json`, with the
    /// certificates of its issuers that are not roots. Every `issuers`
    /// entry with a `certificate` must find its certificate, by issuer id,
    /// among `certificates`. Members the format does not name (an entry's
    /// `delisted`) are passed over. `None` when anything does not read.
    pub(crate) fn parse(json: &[u8], certificates: &[&[u8]]) -> Option<BuiltIn> {
        let value: serde_json::Value = serde_json::from_slice(json).ok()?;
        let parsed: Vec<(Certificate, String)> = certificates
            .iter()
            .map(|der| {
                let certificate = Certificate::from_der(der).filter(Certificate::is_readable)?;
                let id = issuer_id(&certificate)?;
                Some((certificate, id))
            })
            .collect::<Option<_>>()?;
        let issuers = value
            .get("issuers")?
            .as_array()?
            .iter()
            .map(|issuer| {
                let id = issuer.get("id")?.as_str()?.to_ascii_lowercase();
                if !is_issuer_id(&id) {
                    return None;
                }
                let certificate = match issuer.get("certificate")? {
                    serde_json::Value::Null => None,
                    serde_json::Value::String(_) => Some(
                        parsed
                            .iter()
                            .find(|(_, parsed_id)| *parsed_id == id)?
                            .0
                            .clone(),
                    ),
                    _ => return None,
                };
                let newest = issuer.get("newest")?;
                let number = match newest.get("crlNumber")? {
                    serde_json::Value::Null => None,
                    serde_json::Value::String(text) => Some(normalise_hex(text)?),
                    _ => return None,
                };
                let this_update_ms =
                    crate::datetime::parse_receipt_date(newest.get("thisUpdate")?.as_str()?)?;
                Some(BuiltInIssuer {
                    id,
                    list: issuer.get("list")?.as_str()?.to_owned(),
                    certificate,
                    newest: Newest {
                        number,
                        this_update_ms,
                    },
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let revoked = value
            .get("revoked")?
            .as_array()?
            .iter()
            .map(|entry| {
                let issuer = entry.get("issuer")?.as_str()?.to_ascii_lowercase();
                if !is_issuer_id(&issuer) {
                    return None;
                }
                Some((issuer, normalise_hex(entry.get("serial")?.as_str()?)?))
            })
            .collect::<Option<BTreeSet<_>>>()?;
        Some(BuiltIn { issuers, revoked })
    }
}

// ------------------------------------------------------------- the lists

/// What a held list says about one serial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Listed {
    /// `certificateHold`: revoked while the list is fresh.
    Hold,
    /// Any other reason but `removeFromCRL`, or none: revoked.
    Revoked,
}

/// The one list kept for an issuer.
#[derive(Debug, Clone)]
struct HeldList {
    next_update_ms: i64,
    entries: BTreeMap<String, Listed>,
}

/// A list that parsed, with what selection and the profile need.
struct Parsed {
    list: RevocationList,
    der: Vec<u8>,
    this_update_ms: i64,
    number: Option<String>,
    /// `Some` when the list is inside the supported profile (§4).
    supported: Option<HeldList>,
}

fn list_error(index: usize, detail: &str) -> ConfigError {
    ConfigError::new(format!("revocation_lists[{index}]: {detail}"))
}

/// Reads one list, or the refusal for it; its times in epoch
/// milliseconds.
fn parse_list(index: usize, der: &[u8]) -> Result<Parsed, ConfigError> {
    if der.len() > MAX_LIST_BYTES {
        return Err(list_error(index, "the list is over 1 MiB"));
    }
    let list = RevocationList::from_der(der)
        .ok_or_else(|| list_error(index, "not a DER certificate revocation list"))?;
    let this_update_ms = list
        .this_update()
        .and_then(|seconds| seconds.checked_mul(1000))
        .ok_or_else(|| list_error(index, "thisUpdate does not read as a time"))?;
    let number = match list.number() {
        ListField::Present(number) => integer_hex(&number),
        ListField::Absent | ListField::Unreadable => None,
    };
    let supported = supported(&list);
    Ok(Parsed {
        der: der.to_vec(),
        this_update_ms,
        number,
        supported,
        list,
    })
}

/// The list as a held list when it is inside the supported profile (§4),
/// `None` when it is ignored: version 1, no `nextUpdate`, an
/// `IssuingDistributionPoint`, a `DeltaCRLIndicator`, a `FreshestCRL`, an
/// indirect entry (certificateIssuer), a critical extension or entry
/// extension this profile does not read, a duplicate serial, or a CRL
/// Number that does not read or is negative.
fn supported(list: &RevocationList) -> Option<HeldList> {
    if list.version() != 1 {
        return None;
    }
    let ListField::Present(next_update) = list.next_update() else {
        return None;
    };
    match list.number() {
        ListField::Absent => {}
        ListField::Present(number) if !number.negative => {}
        _ => return None,
    }
    for extension in list.extensions()? {
        let oid = extension.oid.as_str();
        if [
            ISSUING_DISTRIBUTION_POINT,
            DELTA_CRL_INDICATOR,
            FRESHEST_CRL,
        ]
        .contains(&oid)
            || (extension.critical && ![AUTHORITY_KEY_IDENTIFIER, CRL_NUMBER].contains(&oid))
        {
            return None;
        }
    }
    let mut serials: BTreeSet<(bool, Vec<u8>)> = BTreeSet::new();
    let mut entries = BTreeMap::new();
    for entry in list.entries()? {
        if !entry_supported(&entry) {
            return None;
        }
        let ListEntry { serial, reason, .. } = entry;
        let significant: Vec<u8> = serial
            .magnitude
            .iter()
            .copied()
            .skip_while(|byte| *byte == 0)
            .collect();
        if !serials.insert((serial.negative, significant)) {
            return None;
        }
        // A negative serial is never matched (§2).
        let Some(hex) = integer_hex(&serial) else {
            continue;
        };
        let listed = match reason {
            ListField::Present(REMOVE_FROM_CRL) => continue,
            ListField::Present(CERTIFICATE_HOLD) => Listed::Hold,
            _ => Listed::Revoked,
        };
        entries.insert(hex, listed);
    }
    Some(HeldList {
        next_update_ms: next_update.checked_mul(1000)?,
        entries,
    })
}

fn entry_supported(entry: &ListEntry) -> bool {
    entry.extensions.iter().all(|extension| {
        let oid = extension.oid.as_str();
        oid != CERTIFICATE_ISSUER
            && (!extension.critical || [REASON_CODE, INVALIDITY_DATE].contains(&oid))
    })
}

/// Whether `list` is older than the newest list the built-in file records
/// for its issuer (§4): a lower CRL Number, or, when either lacks one, an
/// earlier `thisUpdate`.
fn older_than(list: &Parsed, newest: &Newest) -> bool {
    match (&list.number, &newest.number) {
        (Some(number), Some(newest)) => compare_hex(number, newest).is_lt(),
        _ => list.this_update_ms < newest.this_update_ms,
    }
}

/// The list kept among several for one issuer (§4): the highest CRL
/// Number; when any lacks one, the latest `thisUpdate`; on a tie, the DER
/// that sorts first.
fn keep<'a>(lists: &[&'a Parsed]) -> Option<&'a Parsed> {
    let numbered = lists.iter().all(|list| list.number.is_some());
    lists.iter().copied().reduce(|kept, list| {
        let order = if numbered {
            compare_hex(
                list.number.as_deref().unwrap_or_default(),
                kept.number.as_deref().unwrap_or_default(),
            )
        } else {
            list.this_update_ms.cmp(&kept.this_update_ms)
        };
        if order.is_gt() || (order.is_eq() && list.der < kept.der) {
            list
        } else {
            kept
        }
    })
}

// ------------------------------------------------------------- issuers

/// A list's `issuer` Name and its `AuthorityKeyIdentifier`'s keyIdentifier,
/// when it has one.
type Named = (Vec<u8>, Option<Vec<u8>>);

/// A certificate that may sign lists: a configured root or an accepted
/// issuer.
#[derive(Clone)]
struct Candidate {
    certificate: Certificate,
    id: String,
    subject: Vec<u8>,
}

impl Candidate {
    fn of(certificate: &Certificate) -> Option<Candidate> {
        let (subject, key) = certificate.subject_and_key_der()?;
        Some(Candidate {
            certificate: certificate.clone(),
            id: sha256_hex(&[subject.clone(), key].concat()),
            subject,
        })
    }

    /// Whether this candidate may have signed `list` (§4): its `subject`
    /// byte-identical to the list's `issuer`, and, when the list has an
    /// `AuthorityKeyIdentifier`, its `SubjectKeyIdentifier` equal to it.
    fn names(&self, issuer_name: &[u8], key_identifier: Option<&[u8]>) -> bool {
        self.subject == issuer_name
            && key_identifier.is_none_or(|wanted| {
                self.certificate
                    .subject_key_identifier()
                    .is_some_and(|own| own == wanted)
            })
    }
}

/// Why a certificate is not accepted as a list issuer (§6), or `Ok` with
/// the root that signed it.
fn authenticate<'a>(
    certificate: &Certificate,
    roots: &'a [Candidate],
    revoked: impl Fn(&str, &str) -> bool,
) -> Result<&'a Candidate, &'static str> {
    let root = roots
        .iter()
        .find(|root| certificate.signed_by(&root.certificate))
        .ok_or("the certificate does not chain to a configured root")?;
    if !certificate.is_ca() {
        return Err("the certificate is not a CA");
    }
    if !certificate.key_usage_permits_crl_sign() {
        return Err("the certificate's keyUsage does not include cRLSign");
    }
    if !certificate.has_extension(WWDR_INTERMEDIATE_OID) {
        return Err("the certificate lacks Apple's WWDR marker OID 1.2.840.113635.100.6.2.1");
    }
    let serial = certificate
        .serial()
        .as_ref()
        .and_then(integer_hex)
        .ok_or("the certificate's serial is negative or does not read")?;
    if revoked(&root.id, &serial) {
        return Err("the certificate is revoked");
    }
    Ok(root)
}

// ------------------------------------------------------- the configuration

/// One `distrust` entry as given: an issuer id and a serial.
pub(crate) type DistrustEntry = (String, String);

/// The revocation state of one configuration: built when the
/// configuration is built, read on every verification.
#[derive(Debug)]
pub(crate) struct Revocation {
    built_in: Arc<BuiltIn>,
    distrust: BTreeSet<(String, String)>,
    /// The kept list of each issuer, by issuer id.
    held: BTreeMap<String, HeldList>,
    urls: Vec<String>,
    valid_until_ms: Option<i64>,
}

/// What a configuration asks for.
pub(crate) struct Settings<'a> {
    pub(crate) roots: &'a [TrustAnchor],
    pub(crate) lists: &'a [Vec<u8>],
    pub(crate) issuers: &'a [TrustAnchor],
    pub(crate) distrust: &'a [DistrustEntry],
}

impl Revocation {
    /// The state for `settings`, or the first problem, named with its
    /// index (§4). The checks run in this order: the count of lists; per
    /// list in input order its size, its DER and the running count of
    /// entries; then per list in input order its issuer, its signature and
    /// its age; then the added issuers in input order; then the `distrust`
    /// entries. A list's issuer can be an added issuer, and whether an
    /// issuer is accepted depends on its root's list, so every list is read
    /// before any list's issuer is judged.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn build(
        settings: &Settings<'_>,
        built_in: Arc<BuiltIn>,
    ) -> Result<Revocation, ConfigError> {
        if settings.lists.len() > MAX_LISTS {
            return Err(ConfigError::new(format!(
                "revocation_lists: more than {MAX_LISTS} lists"
            )));
        }
        let mut parsed = Vec::with_capacity(settings.lists.len());
        let mut entries = 0usize;
        for (index, der) in settings.lists.iter().enumerate() {
            let list = parse_list(index, der)?;
            entries = entries.saturating_add(list.list.entry_count());
            if entries > MAX_ENTRIES {
                return Err(list_error(
                    index,
                    "the lists hold more than 100,000 entries in all",
                ));
            }
            parsed.push(list);
        }

        // Malformed entries are reported last, after the lists and the
        // issuers; the well-formed ones already take part in judging
        // issuers.
        let mut distrust_error = None;
        if settings.distrust.len() > MAX_DISTRUST {
            distrust_error = Some(ConfigError::new(format!(
                "distrust: more than {MAX_DISTRUST} entries"
            )));
        }
        let mut distrust = BTreeSet::new();
        for (index, (issuer, serial)) in settings.distrust.iter().enumerate() {
            match (is_issuer_id(issuer), normalise_hex(serial)) {
                (true, Some(serial)) => {
                    distrust.insert((issuer.to_ascii_lowercase(), serial));
                }
                _ => {
                    distrust_error.get_or_insert_with(|| {
                        ConfigError::new(format!(
                            "distrust[{index}]: not a 64-hex-digit issuer id and a hex serial"
                        ))
                    });
                }
            }
        }

        let roots: Vec<Candidate> = settings
            .roots
            .iter()
            .map(|root| Candidate::of(root.certificate()))
            .collect::<Option<_>>()
            .ok_or_else(|| ConfigError::new("a root's subject or key does not read"))?;

        // Each list's issuer Name and key identifier, or its refusal.
        let mut named: Vec<Result<Named, &'static str>> = Vec::new();
        for list in &parsed {
            let key_identifier = match list.list.authority_key_identifier() {
                KeyIdentifier::Absent => Ok(None),
                KeyIdentifier::Present(identifier) => Ok(Some(identifier)),
                KeyIdentifier::WithoutKeyIdentifier => {
                    Err("the AuthorityKeyIdentifier has no keyIdentifier")
                }
                KeyIdentifier::Unreadable => Err("the AuthorityKeyIdentifier does not read"),
            };
            named.push(key_identifier.and_then(|key_identifier| {
                let name = list
                    .list
                    .issuer_name_der()
                    .ok_or("the issuer Name does not read")?;
                Ok((name, key_identifier))
            }));
        }

        // The lists a configured root signed, and the one kept per root.
        let owner_among = |index: usize, candidates: &[Candidate]| -> Option<Candidate> {
            let (name, key_identifier) = named.get(index)?.as_ref().ok()?;
            let list = parsed.get(index)?;
            candidates
                .iter()
                .filter(|candidate| candidate.names(name, key_identifier.as_deref()))
                .find(|candidate| list.list.verified_by(&candidate.certificate))
                .cloned()
        };
        let mut owners: Vec<Option<Candidate>> = (0..parsed.len())
            .map(|index| owner_among(index, &roots))
            .collect();
        let root_held = held_lists(&parsed, &owners);

        let revoked_under = |root: &str, serial: &str| {
            let key = (root.to_owned(), serial.to_owned());
            built_in.revoked.contains(&key)
                || distrust.contains(&key)
                || root_held
                    .get(root)
                    .is_some_and(|held| held.entries.contains_key(serial))
        };

        // The built-in issuers that chain to the configured roots.
        let mut chaining: Vec<&BuiltInIssuer> = Vec::new();
        let mut accepted: Vec<Candidate> = Vec::new();
        for issuer in &built_in.issuers {
            match &issuer.certificate {
                None => {
                    if roots.iter().any(|root| root.id == issuer.id) {
                        chaining.push(issuer);
                    }
                }
                Some(certificate) => {
                    if authenticate(certificate, &roots, revoked_under).is_ok() {
                        if let Some(candidate) = Candidate::of(certificate) {
                            chaining.push(issuer);
                            accepted.push(candidate);
                        }
                    }
                }
            }
        }
        // The added issuers; a refusal is reported after the lists'.
        let mut issuer_error = None;
        let mut added: Vec<Candidate> = Vec::new();
        for (index, anchor) in settings.issuers.iter().enumerate() {
            let certificate = anchor.certificate();
            let verdict = authenticate(certificate, &roots, revoked_under).and_then(|_| {
                Candidate::of(certificate).ok_or("the certificate's subject or key does not read")
            });
            match verdict {
                Ok(candidate) => added.push(candidate),
                Err(detail) => {
                    issuer_error.get_or_insert_with(|| {
                        ConfigError::new(format!("revocation_issuers[{index}]: {detail}"))
                    });
                }
            }
        }
        let issuers: Vec<Candidate> = accepted.iter().chain(&added).cloned().collect();

        // Every list's owner: a root, else an accepted issuer, in
        // configuration order; then each list's age.
        for (index, owner) in owners.iter_mut().enumerate() {
            if owner.is_none() {
                *owner = owner_among(index, &issuers);
            }
            let (Some(list), Some(name)) = (parsed.get(index), named.get(index)) else {
                continue;
            };
            let (name, key_identifier) =
                name.as_ref().map_err(|detail| list_error(index, detail))?;
            let Some(owner) = owner else {
                let named_any = roots
                    .iter()
                    .chain(&issuers)
                    .any(|candidate| candidate.names(name, key_identifier.as_deref()));
                return Err(list_error(
                    index,
                    if named_any {
                        "no candidate issuer's key verifies the list's signature"
                    } else {
                        "no configured root or issuer has the list's issuer Name and key identifier"
                    },
                ));
            };
            if let Some(known) = built_in.issuers.iter().find(|issuer| issuer.id == owner.id) {
                if older_than(list, &known.newest) {
                    return Err(list_error(
                        index,
                        "the list is older than the newest list the built-in list records for its issuer",
                    ));
                }
            }
        }
        if let Some(error) = issuer_error.or(distrust_error) {
            return Err(error);
        }

        let held = held_lists(&parsed, &owners);
        let mut urls: Vec<String> = Vec::new();
        let mut push = |url: &str| {
            if !urls.iter().any(|seen| seen == url) {
                urls.push(url.to_owned());
            }
        };
        for issuer in &chaining {
            push(&issuer.list);
        }
        for issuer in &added {
            for uri in issuer.certificate.crl_distribution_uris() {
                // http and https only (§7): an ldap or file URI is no URL a
                // host fetches a list from.
                let web = uri.split_once("://").is_some_and(|(scheme, _)| {
                    scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
                });
                if web {
                    push(&uri);
                }
            }
        }
        let expected: BTreeSet<&str> = chaining
            .iter()
            .map(|issuer| issuer.id.as_str())
            .chain(added.iter().map(|issuer| issuer.id.as_str()))
            .collect();
        let valid_until_ms = if expected.is_empty() {
            None
        } else {
            expected
                .iter()
                .map(|id| held.get(*id).map(|list| list.next_update_ms))
                .collect::<Option<Vec<i64>>>()
                .and_then(|until| until.into_iter().min())
        };
        Ok(Revocation {
            built_in,
            distrust,
            held,
            urls,
            valid_until_ms,
        })
    }

    /// The URLs a host downloads lists from (§7).
    pub(crate) fn urls(&self) -> &[String] {
        &self.urls
    }

    /// The earliest `nextUpdate` among the expected issuers' held lists,
    /// epoch milliseconds, or `None` when one has none (§7).
    pub(crate) fn valid_until_ms(&self) -> Option<i64> {
        self.valid_until_ms
    }

    /// The check of §3 over a verified path, target first, the anchor last.
    /// The anchor itself is never checked.
    ///
    /// # Errors
    /// `CERTIFICATE_REVOKED` naming the layer and the serial; or
    /// `INTERNAL_ERROR` when a certificate's issuer id cannot be computed,
    /// or the clock panics for a `certificateHold` entry.
    pub(crate) fn check(&self, path: &[Certificate], clock: &Clock<'_>) -> Result<(), Failure> {
        for pair in path.windows(2) {
            let [certificate, issuer] = pair else {
                continue;
            };
            let Some(id) = issuer_id(issuer) else {
                return Err(Failure::new(
                    Reason::InternalError,
                    "a certificate's subject or key on the verified path does not read",
                ));
            };
            // A negative serial is never matched (§2).
            let Some(serial) = certificate.serial().as_ref().and_then(integer_hex) else {
                continue;
            };
            let key = (id, serial);
            let layer = if self.built_in.revoked.contains(&key) {
                Some("revoked: built-in list")
            } else if self.distrust.contains(&key) {
                Some("revoked: distrust")
            } else {
                match self
                    .held
                    .get(&key.0)
                    .and_then(|list| Some((list, *list.entries.get(&key.1)?)))
                {
                    Some((_, Listed::Revoked)) => Some("revoked: Apple's list"),
                    Some((list, Listed::Hold)) if clock.now()? <= list.next_update_ms => {
                        Some("revoked: Apple's list")
                    }
                    _ => None,
                }
            };
            if let Some(layer) = layer {
                return Err(Failure::new(
                    Reason::CertificateRevoked,
                    format!("{layer}, serial {}", key.1),
                ));
            }
        }
        Ok(())
    }
}

/// The kept list of every owner that has a supported list, by its id.
fn held_lists(parsed: &[Parsed], owners: &[Option<Candidate>]) -> BTreeMap<String, HeldList> {
    let mut by_owner: BTreeMap<&str, Vec<&Parsed>> = BTreeMap::new();
    for (list, owner) in parsed.iter().zip(owners) {
        if let (Some(owner), Some(_)) = (owner, &list.supported) {
            by_owner.entry(owner.id.as_str()).or_default().push(list);
        }
    }
    by_owner
        .into_iter()
        .filter_map(|(id, lists)| Some((id.to_owned(), keep(&lists)?.supported.clone()?)))
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::{compare_hex, integer_hex, normalise_hex, BuiltIn};
    use aprv_openssl::Integer;

    #[test]
    fn serials_are_written_as_section_2_says() {
        let hex = |negative, magnitude: &[u8]| {
            integer_hex(&Integer {
                negative,
                magnitude: magnitude.to_vec(),
            })
        };
        assert_eq!(hex(false, &[2]).as_deref(), Some("02"));
        assert_eq!(hex(false, &[0x80]).as_deref(), Some("80"));
        assert_eq!(hex(false, &[0, 0x80]).as_deref(), Some("80"));
        assert_eq!(hex(false, &[]).as_deref(), Some("00"));
        assert_eq!(hex(false, &[0]).as_deref(), Some("00"));
        assert_eq!(hex(false, &[0x08, 0x57]).as_deref(), Some("0857"));
        assert_eq!(hex(true, &[2]), None);
        for (text, written) in [
            ("2", "02"),
            ("02", "02"),
            ("0080", "80"),
            ("80", "80"),
            ("0", "00"),
            ("00", "00"),
            ("000", "00"),
            ("abc", "0ABC"),
            ("7d3920094ebef3f8", "7D3920094EBEF3F8"),
        ] {
            assert_eq!(normalise_hex(text).as_deref(), Some(written), "{text}");
        }
        for refused in ["", "0x80", "g", " 80", "80 ", "-1", "8_0"] {
            assert_eq!(normalise_hex(refused), None, "{refused:?}");
        }
    }

    #[test]
    fn crl_numbers_compare_by_value() {
        assert!(compare_hex("0857", "FF").is_gt());
        assert!(compare_hex("0857", "1000").is_lt());
        assert!(compare_hex("00", "01").is_lt());
        assert!(compare_hex("38", "38").is_eq());
    }

    #[test]
    fn the_compiled_list_loads_with_its_four_issuers() {
        let built_in = BuiltIn::compiled().unwrap();
        let ids: Vec<&str> = built_in.issuers.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "0274fe858b04726bb2c6fd7ba73fe4c63a1d076f6eff78373bdb81498151c86e",
                "e691a373c3e637bf2d2e0abc6056ea4e5413c90414b47b0b0133ad3cb757be57",
                "c4c7a18465d55f4f7d20ff2a525bceafb55d860fc3b59a1981b04783fd74f96b",
                "ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee",
            ]
        );
        assert!(built_in.issuers[0].certificate.is_none());
        assert!(built_in.issuers[2].certificate.is_some());
        assert_eq!(built_in.revoked.len(), 19);
        assert!(built_in.revoked.contains(&(
            "0274fe858b04726bb2c6fd7ba73fe4c63a1d076f6eff78373bdb81498151c86e".to_owned(),
            "3EDF4E5729AECD39".to_owned()
        )));
    }

    #[test]
    fn a_built_in_list_that_does_not_read_is_none() {
        let certificates = super::REVOCATION_ISSUER_DER;
        for json in [
            &b"{"[..],
            b"{}",
            br#"{"issuers":[],"revoked":[{"issuer":"ab","serial":"01"}]}"#,
            br#"{"issuers":[{"id":"00","certificate":null,"list":"x","newest":{"crlNumber":null,"thisUpdate":"2026-01-01T00:00:00Z"}}],"revoked":[]}"#,
        ] {
            assert!(BuiltIn::parse(json, &certificates).is_none());
        }
        // An issuer whose certificate is not among those given.
        let json = br#"{"issuers":[{"id":"0000000000000000000000000000000000000000000000000000000000000000","certificate":"x.cer","list":"x","newest":{"crlNumber":null,"thisUpdate":"2026-01-01T00:00:00Z"}}],"revoked":[]}"#;
        assert!(BuiltIn::parse(json, &certificates).is_none());
        // `delisted` and other members are passed over.
        let json = br#"{"comment":"","issuers":[],"revoked":[{"issuer":"0000000000000000000000000000000000000000000000000000000000000000","serial":"1","delisted":{"crlNumber":"02","thisUpdate":"2026-01-01T00:00:00Z"}}]}"#;
        assert_eq!(
            BuiltIn::parse(json, &certificates).unwrap().revoked.len(),
            1
        );
    }
}
