//! Runs every vector in `fixtures/cases.json`, the normative
//! cross-language conformance set for the 0.7 API, through the three public
//! [`Verifier`] methods and the two base64 decoders.
//!
//! The adapter below knows nothing about any individual case. It loads the
//! file, resolves fixture ids to bytes and checks their recorded digest,
//! builds a [`Config`] from the case's trusted roots and clock, dispatches on
//! `operation`, and evaluates the expectation on the JSON the library
//! returns: `ReceiptPayload::to_json()`, `JsonPayload::json()` or the
//! endpoint's response body. The file's top-level `comment` defines the
//! semantics implemented here. There is no skip list, no case count in the
//! source, and no per-case fix-up: a vector that disagrees with the library
//! is a bug report against one of the two, never something to special-case
//! here.

use apple_purchase_receipt_verifier::__internal::{
    base64_decode_lenient, base64_encode, decode_receipt_data, decode_x5c_entry, keys_used_during,
};
use apple_purchase_receipt_verifier::{Config, Environment, Reason, TrustAnchor, Verifier};
use libtest_mimic::{Arguments, Failed, Trial};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;

const CASES: &str = "cases.json";

// --- the vector file ----------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CasesFile {
    #[serde(rename = "$schema")]
    _schema: String,
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "comment")]
    _comment: String,
    fixtures: BTreeMap<String, Fixture>,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Fixture {
    path: String,
    #[serde(rename = "role")]
    _role: String,
    codec: String,
    #[serde(rename = "contentSha256")]
    content_sha256: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    #[serde(default, rename = "legacyId")]
    _legacy_id: Option<String>,
    #[serde(rename = "description")]
    _description: String,
    operation: String,
    /// `decodeBase64` only: the decoders the group runs through.
    #[serde(default)]
    decoders: Option<Vec<String>>,
    input: Input,
    /// Absent exactly on `decodeBase64`, which builds no verifier.
    #[serde(default)]
    config: Option<CaseConfig>,
    #[serde(default)]
    clock: Option<ClockSpec>,
    expected: Expected,
    #[serde(default, rename = "fault")]
    _fault: Option<String>,
    /// A wall-clock budget for the verify call, measured after one warm-up
    /// call of the same case.
    #[serde(default, rename = "maxMillis")]
    max_millis: Option<u64>,
    #[serde(rename = "tags")]
    _tags: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Input {
    #[serde(default)]
    fixture: Option<String>,
    /// `verifyReceiptEndpoint` only: a text fixture that is the whole
    /// request body, handed over verbatim.
    #[serde(default)]
    request_body: Option<String>,
    /// `decodeBase64` only: the spellings of the group.
    #[serde(default)]
    texts: Option<Vec<String>>,
}

/// `deny_unknown_fields` is load-bearing: a new config key must fail this
/// adapter loudly rather than be ignored, which would silently turn the case
/// it belongs to into a weaker one.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CaseConfig {
    trusted_roots: TrustedRoots,
    #[serde(default)]
    environment: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct TrustedRoots {
    source: String,
    #[serde(default)]
    fixtures: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct ClockSpec {
    now: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Expected {
    /// Absent on endpoint cases, which pin `/status` among the fields.
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    /// Code points the failure message must not contain, so it can go into
    /// a log line as is.
    #[serde(default)]
    message_must_not_contain: Option<Vec<u32>>,
    /// The outcomes a port may give, `"ok"` or a reason; no panic.
    #[serde(default)]
    one_of: Option<Vec<String>>,
    #[serde(default)]
    fields: Option<Map<String, Value>>,
    #[serde(default)]
    lengths: Option<Map<String, Value>>,
    #[serde(default)]
    to_json: Option<String>,
    /// `decodeBase64` only: what every text of an ok group decodes to.
    #[serde(default)]
    bytes_hex: Option<String>,
}

// --- locating and decoding fixtures -------------------------------------

/// `APRV_FIXTURES_DIR` when set, as Java's `aprv.fixtures.dir`; otherwise
/// walks up from this crate's directory until a `fixtures/` directory holding
/// the vectors appears, never a `../../..` literal, so moving the port does
/// not silently point the suite at nothing.
fn fixtures_dir() -> Result<PathBuf, Failed> {
    if let Some(configured) = std::env::var_os("APRV_FIXTURES_DIR").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(configured));
    }
    let mut dir: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join("fixtures");
        if candidate.join(CASES).is_file() {
            return Ok(candidate);
        }
        dir = dir.parent().ok_or_else(|| {
            Failed::from(format!(
                "harness error: no fixtures/{CASES} above the crate directory"
            ))
        })?;
    }
}

fn load_cases() -> Result<(PathBuf, CasesFile), Failed> {
    let dir = fixtures_dir()?;
    let text = std::fs::read_to_string(dir.join(CASES))
        .map_err(|err| Failed::from(format!("harness error: cannot read {CASES}: {err}")))?;
    let parsed: CasesFile = serde_json::from_str(&text)
        .map_err(|err| Failed::from(format!("harness error: cannot parse {CASES}: {err}")))?;
    if parsed.schema_version != 2 {
        return Err(Failed::from(format!(
            "harness error: {CASES} is schemaVersion {}, this adapter implements 2",
            parsed.schema_version
        )));
    }
    Ok((dir, parsed))
}

/// The decoded logical bytes of a registered fixture, checked against the
/// digest the registry records for them, so fixture bytes and the registry
/// cannot drift apart unnoticed.
fn fixture_bytes(
    dir: &Path,
    fixtures: &BTreeMap<String, Fixture>,
    id: &str,
) -> Result<Vec<u8>, Failed> {
    let entry = fixtures.get(id).ok_or_else(|| {
        Failed::from(format!(
            "harness error: {CASES} registers no fixture \"{id}\""
        ))
    })?;
    let raw = std::fs::read(dir.join(&entry.path)).map_err(|err| {
        Failed::from(format!(
            "harness error: cannot read fixture \"{id}\" ({}): {err}",
            entry.path
        ))
    })?;
    let bytes = match entry.codec.as_str() {
        // text is untrimmed, unlike utf8: a registered fixture may be 0
        // bytes or carry CRLF, and both must survive as stored.
        "raw" | "text" => raw,
        "base64" => {
            let text = String::from_utf8_lossy(&raw);
            let stripped: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            base64_decode_lenient(&stripped)
        }
        "utf8" => String::from_utf8_lossy(&raw).trim().as_bytes().to_vec(),
        other => {
            return Err(Failed::from(format!(
                "harness error: unknown fixture codec \"{other}\" on \"{id}\""
            )))
        }
    };
    let actual = hex::encode(Sha256::digest(&bytes));
    if actual != entry.content_sha256 {
        return Err(Failed::from(format!(
            "fixture \"{id}\" ({}, codec {}) has drifted: {CASES} records contentSha256 {}, \
             the decoded bytes hash to {actual}",
            entry.path, entry.codec, entry.content_sha256
        )));
    }
    Ok(bytes)
}

fn check_whole_registry(dir: &Path, fixtures: &BTreeMap<String, Fixture>) -> Result<(), Failed> {
    if fixtures.is_empty() {
        return Err(Failed::from(format!(
            "harness error: {CASES} registers no fixtures"
        )));
    }
    for id in fixtures.keys() {
        fixture_bytes(dir, fixtures, id)?;
    }
    Ok(())
}

/// Every expected integer survived the parse with all its digits.
///
/// The file pins a `download_id` of 2^63 - 1, an integer an IEEE-754 double
/// rounds to 2^63, precisely because Apple's real ones run to eighteen
/// digits. A runner that read the file through a double would compare
/// against 9223372036854775808 and let a rounding library pass. That is
/// invisible in a green run, so it is checked here: at least one expected
/// integer must come back changed by an `f64` round trip, which no value
/// that passed through a double can.
fn expectations_keep_every_digit(file: &CasesFile) -> Result<(), Failed> {
    let mut beyond_a_double = 0usize;
    for case in &file.cases {
        for value in case.expected.fields.iter().flat_map(Map::values) {
            let Value::Number(number) = value else {
                continue;
            };
            let Some(exact) = number.as_u64() else {
                continue;
            };
            #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
            let through_a_double = exact as f64 as u64;
            if through_a_double != exact {
                beyond_a_double += 1;
            }
        }
    }
    if beyond_a_double == 0 {
        return Err(Failed::from(format!(
            "no expected integer in {CASES} survives an f64 round trip changed, so nothing \
             here proves the expectations were not read through a double"
        )));
    }
    Ok(())
}

// --- config --------------------------------------------------------------

/// The case's config: its trusted roots, and a clock fixed at `clock.now`
/// when it pins one, else the default clock.
fn config(dir: &Path, fixtures: &BTreeMap<String, Fixture>, case: &Case) -> Result<Config, Failed> {
    let spec = case
        .config
        .as_ref()
        .ok_or_else(|| Failed::from(format!("{}: harness error: no config", case.id)))?;
    let mut builder = Config::builder();
    match spec.trusted_roots.source.as_str() {
        "defaults" => {}
        "fixtures" => {
            let mut roots = Vec::new();
            for id in spec.trusted_roots.fixtures.iter().flatten() {
                let der = fixture_bytes(dir, fixtures, id)?;
                roots.push(TrustAnchor::from_der(&der).map_err(|err| {
                    Failed::from(format!("{}: root \"{id}\" does not parse: {err}", case.id))
                })?);
            }
            builder = builder.roots(roots);
        }
        other => {
            return Err(Failed::from(format!(
                "{}: harness error: unknown trustedRoots source \"{other}\"",
                case.id
            )))
        }
    }
    if let Some(clock) = &case.clock {
        let now = parse_instant(&clock.now).ok_or_else(|| {
            Failed::from(format!(
                "{}: harness error: bad clock {}",
                case.id, clock.now
            ))
        })?;
        builder = builder.clock(move || now);
    }
    builder
        .build()
        .map_err(|err| Failed::from(format!("{}: config refused: {err}", case.id)))
}

/// `YYYY-MM-DDTHH:MM:SSZ` to epoch milliseconds, the only form the schema
/// allows for `clock.now`.
fn parse_instant(text: &str) -> Option<i64> {
    let digits = |range: std::ops::Range<usize>| text.get(range)?.parse::<i64>().ok();
    let (year, month, day) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    let (hour, minute, second) = (digits(11..13)?, digits(14..16)?, digits(17..19)?);
    // Howard Hinnant's days_from_civil.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000)
}

/// The string `verifyReceipt` gets, and the endpoint's `receipt-data`: a
/// text fixture verbatim, exactly as a client sent it; any other fixture
/// holds DER, encoded as canonical base64.
fn receipt_string(
    dir: &Path,
    fixtures: &BTreeMap<String, Fixture>,
    id: &str,
) -> Result<String, Failed> {
    let bytes = fixture_bytes(dir, fixtures, id)?;
    let codec = fixtures
        .get(id)
        .map_or("", |fixture| fixture.codec.as_str());
    if codec == "text" {
        String::from_utf8(bytes)
            .map_err(|_| Failed::from(format!("harness error: text fixture \"{id}\" is not UTF-8")))
    } else {
        Ok(base64_encode(&bytes))
    }
}

// --- expectations --------------------------------------------------------

/// An RFC 6901 pointer with one extension: a token `[key=value]` selects the
/// single array element whose member `key` is the JSON string `value`, and
/// the case fails unless exactly one matches. `Ok(None)` when the pointer
/// leads nowhere.
fn resolve<'v>(root: &'v Value, pointer: &str) -> Result<Option<&'v Value>, String> {
    let Some(rest) = pointer.strip_prefix('/') else {
        return Err(format!("harness error: \"{pointer}\" is not a pointer"));
    };
    let mut current = root;
    for raw in rest.split('/') {
        if let Some(selector) = raw.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Some((key, wanted)) = selector.split_once('=') {
                let Value::Array(items) = current else {
                    return Err(format!("{pointer}: {raw} needs an array"));
                };
                let matches: Vec<&Value> = items
                    .iter()
                    .filter(|item| item.get(key).and_then(Value::as_str) == Some(wanted))
                    .collect();
                let [only] = matches.as_slice() else {
                    return Err(format!(
                        "{pointer}: {raw} must select exactly one element, selected {}",
                        matches.len()
                    ));
                };
                current = only;
                continue;
            }
        }
        let token = raw.replace("~1", "/").replace("~0", "~");
        let next = match current {
            Value::Object(map) => map.get(&token),
            Value::Array(items) => token.parse::<usize>().ok().and_then(|i| items.get(i)),
            _ => None,
        };
        match next {
            Some(next) => current = next,
            None => return Ok(None),
        }
    }
    Ok(Some(current))
}

/// `null` means absent or JSON null; numbers compare by value, integers
/// exactly.
fn matches(expected: &Value, actual: Option<&Value>) -> bool {
    match (expected, actual) {
        (Value::Null, None | Some(Value::Null)) => true,
        (Value::Number(want), Some(Value::Number(got))) => match (want.as_i64(), got.as_i64()) {
            (Some(want), Some(got)) => want == got,
            _ => match (want.as_u64(), got.as_u64()) {
                (Some(want), Some(got)) => want == got,
                _ => want.as_f64().is_some() && want.as_f64() == got.as_f64(),
            },
        },
        (want, Some(got)) => want == got,
        _ => false,
    }
}

/// Every `fields` and `lengths` expectation that does not hold on `actual`.
fn check(id: &str, expected: &Expected, actual: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    for (pointer, want) in expected.fields.iter().flatten() {
        match resolve(actual, pointer) {
            Ok(got) if matches(want, got) => {}
            Ok(got) => failures.push(format!(
                "{id} {pointer}: expected {want} but got {}",
                got.map_or_else(|| "absent".to_owned(), ToString::to_string)
            )),
            Err(err) => failures.push(format!("{id} {err}")),
        }
    }
    for (pointer, want) in expected.lengths.iter().flatten() {
        match resolve(actual, pointer) {
            Ok(Some(Value::Array(items))) if Some(items.len() as u64) == want.as_u64() => {}
            Ok(got) => failures.push(format!(
                "{id} {pointer}: expected an array of {want} but got {}",
                got.map_or_else(|| "absent".to_owned(), ToString::to_string)
            )),
            Err(err) => failures.push(format!("{id} {err}")),
        }
    }
    failures
}

fn parse_json(id: &str, text: &str) -> Result<Value, Failed> {
    serde_json::from_str(text).map_err(|err| {
        Failed::from(format!(
            "{id}: the library returned JSON that does not parse ({err}): {text}"
        ))
    })
}

// --- decodeBase64 --------------------------------------------------------

/// Runs every text of the group through every decoder it names and reports
/// every text that got the wrong answer, by case id, decoder, index and
/// escaped text, rather than stopping at the first. `receipt-data` refuses
/// with `MALFORMED` and `x5c` with `INVALID_CERTIFICATE`; an error group
/// states `MALFORMED` and is mapped here for `x5c`.
fn run_decode_base64(case: &Case) -> Result<(), Failed> {
    let texts = case
        .input
        .texts
        .as_ref()
        .filter(|texts| !texts.is_empty())
        .ok_or_else(|| Failed::from("harness error: decodeBase64 needs input.texts"))?;
    let decoders = case
        .decoders
        .as_ref()
        .filter(|decoders| !decoders.is_empty())
        .ok_or_else(|| Failed::from("harness error: decodeBase64 needs decoders"))?;
    let ok = case.expected.status.as_deref() == Some("ok");
    let want = if ok {
        case.expected
            .bytes_hex
            .clone()
            .ok_or_else(|| Failed::from("harness error: an ok group with no bytesHex"))?
    } else if case.expected.reason.as_deref() == Some("MALFORMED") {
        String::new()
    } else {
        return Err(Failed::from(
            "harness error: an error group states MALFORMED",
        ));
    };
    let mut failures = Vec::new();
    for decoder in decoders {
        let (decode, refusal): (fn(&str) -> _, Reason) = match decoder.as_str() {
            "receipt-data" => (decode_receipt_data, Reason::Malformed),
            "x5c" => (decode_x5c_entry, Reason::InvalidCertificate),
            other => {
                return Err(Failed::from(format!(
                    "harness error: no decoder \"{other}\""
                )))
            }
        };
        for (index, text) in texts.iter().enumerate() {
            let at = format!("{}: {decoder} texts[{index}] {text:?}", case.id);
            match decode(text) {
                Ok(bytes) if !ok => failures.push(format!(
                    "{at} was accepted (decoded to {})",
                    hex::encode(bytes)
                )),
                Ok(bytes) if hex::encode(&bytes) != want => failures.push(format!(
                    "{at} decoded to {}, want {want}",
                    hex::encode(&bytes)
                )),
                Err(failure) if ok => failures.push(format!(
                    "{at} was refused ({}), want {want}",
                    failure.reason()
                )),
                Err(failure) if failure.reason() != refusal => {
                    failures.push(format!("{at}: reason {}, want {refusal}", failure.reason()))
                }
                _ => {}
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(Failed::from(failures.join("\n")))
    }
}

// --- one case ------------------------------------------------------------

/// Which case ids actually ran, so the coverage check after the run is a
/// fact rather than a loop-shaped assumption.
static RAN: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn run_case(dir: &Path, fixtures: &BTreeMap<String, Fixture>, case: &Case) -> Result<(), Failed> {
    if let Ok(mut ran) = RAN.lock() {
        ran.push(case.id.clone());
    }
    let id = case.id.as_str();
    if case.operation == "decodeBase64" {
        return run_decode_base64(case);
    }
    let verifier = Verifier::new(config(dir, fixtures, case)?);
    let expected = &case.expected;
    let fixture = case.input.fixture.as_deref();
    let actual = match case.operation.as_str() {
        "verifyReceiptEndpoint" => {
            let environment = match case.config.as_ref().and_then(|c| c.environment.as_deref()) {
                Some("PRODUCTION") => Environment::Production,
                Some("SANDBOX") => Environment::Sandbox,
                other => {
                    return Err(Failed::from(format!(
                        "{id}: harness error: environment {other:?}"
                    )))
                }
            };
            let body = match (&case.input.request_body, fixture) {
                (Some(body), _) => String::from_utf8(fixture_bytes(dir, fixtures, body)?)
                    .map_err(|_| Failed::from(format!("{id}: request body is not UTF-8")))?,
                (None, Some(fixture)) => serde_json::to_string(&serde_json::json!({
                    "receipt-data": receipt_string(dir, fixtures, fixture)?
                }))
                .map_err(|err| Failed::from(format!("{id}: harness error: {err}")))?,
                (None, None) => return Err(Failed::from(format!("{id}: harness error: no input"))),
            };
            if !expected
                .fields
                .as_ref()
                .is_some_and(|f| f.contains_key("/status"))
            {
                return Err(Failed::from(format!(
                    "{id}: harness error: /status not pinned"
                )));
            }
            parse_json(id, &verifier.verify_receipt_endpoint(environment, &body))?
        }
        operation @ ("verifyReceipt" | "verifySignedData") => {
            let fixture =
                fixture.ok_or_else(|| Failed::from(format!("{id}: harness error: no fixture")))?;
            let input = if operation == "verifyReceipt" {
                receipt_string(dir, fixtures, fixture)?
            } else {
                String::from_utf8(fixture_bytes(dir, fixtures, fixture)?)
                    .map_err(|_| Failed::from(format!("{id}: harness error: JWS not UTF-8")))?
            };
            let call = || {
                if operation == "verifyReceipt" {
                    verifier
                        .verify_receipt(&input)
                        .map(|receipt| receipt.to_json())
                } else {
                    verifier
                        .verify_signed_data(&input)
                        .map(apple_purchase_receipt_verifier::JsonPayload::into_json)
                }
            };
            if let Some(allowed) = &expected.one_of {
                let guarded = || {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(&call)).map_err(|_| {
                        Failed::from(format!("{id}: the operation panicked instead of answering"))
                    })
                };
                let result = match case.max_millis {
                    None => guarded()?,
                    Some(budget) => {
                        let _warm_up = guarded()?;
                        let start = std::time::Instant::now();
                        let result = guarded()?;
                        let elapsed = start.elapsed();
                        if elapsed.as_millis() > u128::from(budget) {
                            return Err(Failed::from(format!(
                                "{id}: took {elapsed:?}, over the {budget} ms budget"
                            )));
                        }
                        result
                    }
                };
                let outcome = result
                    .as_ref()
                    .map_or_else(|f| f.reason().as_str(), |_| "ok");
                if !allowed.iter().any(|a| a == outcome) {
                    return Err(Failed::from(format!(
                        "{id}: answered {outcome}, want one of {allowed:?}"
                    )));
                }
                return Ok(());
            }
            let result = match case.max_millis {
                None => call(),
                Some(budget) => {
                    let _warm_up = call();
                    let start = std::time::Instant::now();
                    let (result, used) = keys_used_during(call);
                    let elapsed = start.elapsed();
                    if elapsed.as_millis() > u128::from(budget) {
                        return Err(Failed::from(format!(
                            "{id}: took {elapsed:?}, over the {budget} ms budget"
                        )));
                    }
                    // The direct form of the budget: every stranger in these
                    // cases carries a key far over the 8192-bit cap, so an
                    // SPKI that large among the keys used means a stranger's
                    // key reached a signature check. An 8192-bit RSA SPKI is
                    // about 1,050 bytes.
                    if let Some(spki) = used.iter().find(|spki| spki.len() > 1100) {
                        return Err(Failed::from(format!(
                            "{id}: a {}-byte stranger key checked a signature",
                            spki.len()
                        )));
                    }
                    result
                }
            };
            match (expected.status.as_deref().unwrap_or(""), result) {
                ("error", Ok(_)) => {
                    return Err(Failed::from(format!(
                        "{id}: expected {} but the operation verified",
                        expected.reason.as_deref().unwrap_or("?")
                    )))
                }
                ("error", Err(failure)) => {
                    let want = expected
                        .reason
                        .as_deref()
                        .ok_or_else(|| Failed::from(format!("{id}: harness error: no reason")))?;
                    let want = Reason::from_str(want)
                        .map_err(|err| Failed::from(format!("{id}: harness error: {err}")))?;
                    if failure.reason() != want {
                        return Err(Failed::from(format!(
                            "{id}: expected {want} but got {failure}"
                        )));
                    }
                    if let Some(forbidden) = &expected.message_must_not_contain {
                        let message = failure.message();
                        for &code_point in forbidden {
                            if message.chars().any(|c| u32::from(c) == code_point) {
                                return Err(Failed::from(format!(
                                    "{id}: the failure message contains U+{code_point:04X}: {}",
                                    message.escape_default()
                                )));
                            }
                        }
                    }
                    return Ok(());
                }
                ("ok", Err(failure)) => {
                    return Err(Failed::from(format!("{id}: expected ok but got {failure}")))
                }
                ("ok", Ok(json)) => {
                    let actual = parse_json(id, &json)?;
                    // Same value, not same bytes: whitespace, key order and
                    // escaping are free (docs/design/0.7-api.md "Our JSON").
                    if let Some(want) = &expected.to_json {
                        if parse_json(id, want)? != actual {
                            return Err(Failed::from(format!(
                                "{id}: toJson value\n  expected {want}\n  but got  {json}"
                            )));
                        }
                    }
                    actual
                }
                (other, _) => {
                    return Err(Failed::from(format!(
                        "{id}: harness error: unknown status \"{other}\""
                    )))
                }
            }
        }
        other => {
            return Err(Failed::from(format!(
                "{id}: harness error: unknown operation \"{other}\""
            )))
        }
    };
    let failures = check(id, expected, &actual);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(Failed::from(failures.join("\n")))
    }
}

fn main() -> std::process::ExitCode {
    let arguments = Arguments::from_args();
    let (dir, file) = match load_cases() {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("{err:?}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let mut trials = Vec::new();

    // A fixture no case happens to reference would otherwise drift
    // unnoticed, and the registry is the thing being guarded.
    {
        let dir = dir.clone();
        let fixtures = file.fixtures.clone();
        trials.push(Trial::test(
            format!("{CASES} every registered fixture matches its contentSha256"),
            move || check_whole_registry(&dir, &fixtures),
        ));
    }
    trials.push(Trial::test(
        format!("{CASES} every expected integer keeps its digits"),
        || {
            let (_, fresh) = load_cases()?;
            expectations_keep_every_digit(&fresh)
        },
    ));

    for case in &file.cases {
        let dir = dir.clone();
        let fixtures = file.fixtures.clone();
        let case = case.clone();
        trials.push(Trial::test(format!("{CASES} {}", case.id), move || {
            run_case(&dir, &fixtures, &case)
        }));
    }

    let conclusion = libtest_mimic::run(&arguments, trials);

    // Coverage self-check after the run: every case id in the parsed file
    // actually ran, compared against the file and never against a literal
    // count. A filter, a skip or an ignored-only run is the one thing that
    // may leave cases unrun, so the check stands down for it.
    if arguments.filter.is_some()
        || !arguments.skip.is_empty()
        || arguments.ignored
        || arguments.list
    {
        return conclusion.exit_code();
    }
    let ran = match RAN.lock() {
        Ok(ran) => ran.clone(),
        Err(_) => {
            eprintln!("harness error: the ran-case list is poisoned");
            return std::process::ExitCode::FAILURE;
        }
    };
    let missing: Vec<&str> = file
        .cases
        .iter()
        .map(|case| case.id.as_str())
        .filter(|id| !ran.iter().any(|ran| ran == id))
        .collect();
    if !missing.is_empty() {
        eprintln!(
            "coverage self-check: {} of {} cases did not run: {}",
            missing.len(),
            file.cases.len(),
            missing.join(", ")
        );
        return std::process::ExitCode::FAILURE;
    }
    println!(
        "{CASES}: {} cases ran, {} fixtures registered, 0 skipped",
        file.cases.len(),
        file.fixtures.len()
    );
    conclusion.exit_code()
}
