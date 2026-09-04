//! Runs `fixtures/cases.json` — the normative cross-language conformance
//! vectors — against this implementation.
//!
//! The adapter below knows nothing about any individual case. It loads the
//! file, resolves fixture ids to bytes and checks their recorded digest,
//! builds a verifier from the generic config, dispatches on `operation`,
//! normalises the result into the language-neutral view the field paths are
//! written against, and reads the reason off a failure. There is no skip
//! list, no case count in the source, and no per-case fix-up: a vector that
//! disagrees with the library is a bug report against one of the two, and it
//! is never something to special-case here.

use apple_purchase_receipt_verifier::{
    apple_jws_roots, apple_receipt_roots, datetime, status, AppReceipt, Environment, FixedClock,
    InAppPurchase, JwsVerifier, Reason, ReceiptVerifier, TrustAnchor, VerificationError,
    VerifyReceiptEndpoint, VerifyReceiptRequest,
};
use libtest_mimic::{Arguments, Failed, Trial};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

// --- the vector file ----------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CasesFile {
    #[serde(rename = "$schema")]
    _schema: String,
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    _comment: Option<String>,
    #[serde(rename = "comment")]
    _comment_text: String,
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
    #[serde(rename = "description")]
    _description: String,
    operation: String,
    input: Input,
    config: Config,
    #[serde(default)]
    clock: Option<ClockSpec>,
    expected: Expected,
    #[serde(default, rename = "fault")]
    _fault: Option<String>,
    #[serde(rename = "tags")]
    _tags: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Input {
    fixture: String,
}

/// `deny_unknown_fields` here is load-bearing: a new config key added to
/// `cases.json` must fail this adapter loudly rather than be ignored, which
/// would silently turn the case it belongs to into a weaker one.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Config {
    trusted_roots: TrustedRoots,
    #[serde(default)]
    bundle_id: Option<String>,
    #[serde(default)]
    accepted_environments: Option<Vec<String>>,
    #[serde(default)]
    app_apple_id: Option<u64>,
    #[serde(default)]
    max_signed_age_seconds: Option<u64>,
    #[serde(default)]
    device_guid_hex: Option<String>,
    #[serde(default)]
    environment: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TrustedRoots {
    source: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    fixtures: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct ClockSpec {
    now: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Expected {
    status: String,
    #[serde(default)]
    fields: Option<Map<String, Value>>,
    #[serde(default)]
    reason: Option<String>,
}

// --- locating and decoding fixtures -------------------------------------

/// Walks up from this test's own source directory until a `fixtures/`
/// directory holding `cases.json` appears — never a `../../..` literal, so
/// moving the port does not silently point the suite at nothing.
fn fixtures_dir() -> Result<PathBuf, Failed> {
    let mut dir: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join("fixtures");
        if candidate.join("cases.json").is_file() {
            return Ok(candidate);
        }
        dir = match dir.parent() {
            Some(parent) => parent,
            None => {
                return Err(Failed::from(
                    "harness error: no fixtures/cases.json above the crate directory",
                ))
            }
        };
    }
}

fn load_cases() -> Result<(PathBuf, CasesFile), Failed> {
    let dir = fixtures_dir()?;
    let text = std::fs::read_to_string(dir.join("cases.json"))
        .map_err(|err| Failed::from(format!("harness error: cannot read cases.json: {err}")))?;
    let parsed: CasesFile = serde_json::from_str(&text)
        .map_err(|err| Failed::from(format!("harness error: cannot parse cases.json: {err}")))?;
    if parsed.schema_version != 1 {
        return Err(Failed::from(format!(
            "harness error: cases.json is schemaVersion {}, this adapter implements 1",
            parsed.schema_version
        )));
    }
    Ok((dir, parsed))
}

/// The decoded logical bytes of a registered fixture, checked against the
/// digest the registry records for them.
///
/// `contentSha256` is not documentation: a fixture that is regenerated,
/// re-encoded or quietly edited changes the bytes every port verifies, and
/// the pinned expectations would then describe something no other port ever
/// saw. Checking it here is what makes that guarantee load-bearing. The
/// digest is over the LOGICAL bytes — post-codec, the same bytes handed to
/// the library.
fn fixture_bytes(
    dir: &Path,
    fixtures: &BTreeMap<String, Fixture>,
    id: &str,
) -> Result<Vec<u8>, Failed> {
    let entry = fixtures.get(id).ok_or_else(|| {
        Failed::from(format!(
            "harness error: cases.json registers no fixture \"{id}\""
        ))
    })?;
    let raw = std::fs::read(dir.join(&entry.path)).map_err(|err| {
        Failed::from(format!(
            "harness error: cannot read fixture \"{id}\" ({}): {err}",
            entry.path
        ))
    })?;
    let bytes = match entry.codec.as_str() {
        "raw" => raw,
        "base64" => {
            let text = String::from_utf8_lossy(&raw);
            let stripped: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            apple_purchase_receipt_verifier::base64::decode_lenient(&stripped)
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
            "fixture \"{id}\" ({}, codec {}) has drifted: cases.json records contentSha256 {}, \
             the decoded bytes hash to {actual}",
            entry.path, entry.codec, entry.content_sha256
        )));
    }
    Ok(bytes)
}

fn check_whole_registry(dir: &Path, fixtures: &BTreeMap<String, Fixture>) -> Result<(), Failed> {
    if fixtures.is_empty() {
        return Err(Failed::from(
            "harness error: cases.json registers no fixtures",
        ));
    }
    for id in fixtures.keys() {
        fixture_bytes(dir, fixtures, id)?;
    }
    Ok(())
}

// --- config → API -------------------------------------------------------

fn trust_anchors(
    dir: &Path,
    fixtures: &BTreeMap<String, Fixture>,
    spec: &TrustedRoots,
) -> Result<Vec<TrustAnchor>, Failed> {
    match spec.source.as_str() {
        "builtin" => match spec.name.as_deref() {
            Some("apple-jws-roots") => Ok(apple_jws_roots().to_vec()),
            Some("apple-receipt-roots") => Ok(apple_receipt_roots().to_vec()),
            other => Err(Failed::from(format!(
                "harness error: unknown builtin root set {other:?}"
            ))),
        },
        "fixtures" => {
            let ids = spec.fixtures.as_deref().ok_or_else(|| {
                Failed::from("harness error: trustedRoots.source=fixtures with no fixtures")
            })?;
            let mut anchors = Vec::with_capacity(ids.len());
            for id in ids {
                let der = fixture_bytes(dir, fixtures, id)?;
                anchors.push(TrustAnchor::from_der(&der).map_err(|err| {
                    Failed::from(format!(
                        "harness error: fixture \"{id}\" is not an anchor: {err}"
                    ))
                })?);
            }
            Ok(anchors)
        }
        other => Err(Failed::from(format!(
            "harness error: unknown trustedRoots source \"{other}\""
        ))),
    }
}

/// `verifyRaw` enforces no claim, so its cases may omit `bundleId` and
/// `acceptedEnvironments` — but the builder still demands both. These
/// placeholders match nothing any fixture carries, so a claim check that
/// leaked into `verify_raw` shows up as a failure rather than as a pass.
/// An empty string, a wildcard, or "all four environments" would turn that
/// leak into a silent pass.
const UNMATCHABLE_BUNDLE_ID: &str = "conformance.unset.bundle.id";
const UNMATCHABLE_ENVIRONMENTS: [Environment; 1] = [Environment::LocalTesting];

fn environments(names: &[String]) -> Result<Vec<Environment>, Failed> {
    names
        .iter()
        .map(|name| {
            Environment::from_str(name).map_err(|err| Failed::from(format!("harness error: {err}")))
        })
        .collect()
}

fn jws_verifier(
    dir: &Path,
    fixtures: &BTreeMap<String, Fixture>,
    config: &Config,
    clock: Option<FixedClock>,
) -> Result<JwsVerifier, Failed> {
    let mut builder = JwsVerifier::builder()
        .trusted_roots(trust_anchors(dir, fixtures, &config.trusted_roots)?)
        .bundle_id(
            config
                .bundle_id
                .clone()
                .unwrap_or_else(|| UNMATCHABLE_BUNDLE_ID.to_owned()),
        );
    builder = match &config.accepted_environments {
        Some(names) => builder.accepted_environments(environments(names)?),
        None => builder.accepted_environments(UNMATCHABLE_ENVIRONMENTS),
    };
    if let Some(app_apple_id) = config.app_apple_id {
        builder = builder.app_apple_id(app_apple_id);
    }
    // The unit conversion happens here and nowhere else in the port.
    if let Some(seconds) = config.max_signed_age_seconds {
        builder = builder.max_signed_age(Duration::from_secs(seconds));
    }
    if let Some(clock) = clock {
        builder = builder.clock(Arc::new(clock));
    }
    builder
        .build()
        .map_err(|err| Failed::from(format!("harness error: cannot build JwsVerifier: {err}")))
}

fn case_clock(case: &Case) -> Result<Option<FixedClock>, Failed> {
    let Some(spec) = &case.clock else {
        return Ok(None);
    };
    let millis = datetime::parse_rfc3339(&spec.now).ok_or_else(|| {
        Failed::from(format!("harness error: unparseable clock \"{}\"", spec.now))
    })?;
    Ok(Some(FixedClock::from_unix_millis(millis)))
}

fn require_no_clock(clock: Option<FixedClock>, operation: &str) -> Result<(), Failed> {
    if clock.is_some() {
        return Err(Failed::from(format!(
            "harness error: {operation} has no clock seam, but the case pins one"
        )));
    }
    Ok(())
}

// --- result normalisation ------------------------------------------------

fn hex_value(bytes: &[u8]) -> Value {
    Value::from(hex::encode(bytes))
}

fn put_bytes(target: &mut Map<String, Value>, key: &str, bytes: Option<&[u8]>) {
    let value = bytes.map_or(Value::Null, hex_value);
    target.insert(key.to_owned(), value.clone());
    target.insert(format!("{key}Hex"), value);
}

fn put_date(target: &mut Map<String, Value>, key: &str, at: Option<std::time::SystemTime>) {
    let value = at.map_or(Value::Null, |at| Value::from(datetime::to_rfc3339_utc(at)));
    target.insert(key.to_owned(), value);
}

fn put_int(target: &mut Map<String, Value>, key: &str, value: Option<i64>) {
    target.insert(key.to_owned(), value.map_or(Value::Null, Value::from));
}

fn put_string(target: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    target.insert(key.to_owned(), value.map_or(Value::Null, Value::from));
}

fn unknown_attributes(map: &BTreeMap<u32, Vec<Vec<u8>>>) -> Value {
    let mut out = Map::new();
    for (attribute_type, values) in map {
        out.insert(
            attribute_type.to_string(),
            Value::Array(values.iter().map(|v| hex_value(v)).collect()),
        );
    }
    Value::Object(out)
}

fn in_app_json(purchase: &InAppPurchase) -> Value {
    let mut out = Map::new();
    out.insert(
        "unknownAttributes".to_owned(),
        unknown_attributes(&purchase.unknown_attributes),
    );
    put_int(&mut out, "quantity", purchase.quantity);
    put_string(&mut out, "productId", purchase.product_id.as_deref());
    put_string(
        &mut out,
        "transactionId",
        purchase.transaction_id.as_deref(),
    );
    put_string(
        &mut out,
        "originalTransactionId",
        purchase.original_transaction_id.as_deref(),
    );
    put_date(&mut out, "purchaseDate", purchase.purchase_date);
    put_date(
        &mut out,
        "originalPurchaseDate",
        purchase.original_purchase_date,
    );
    put_date(&mut out, "expiresDate", purchase.expires_date);
    put_date(&mut out, "cancellationDate", purchase.cancellation_date);
    put_int(
        &mut out,
        "webOrderLineItemId",
        purchase.web_order_line_item_id,
    );
    put_int(
        &mut out,
        "isInIntroOfferPeriod",
        purchase.is_in_intro_offer_period,
    );
    Value::Object(out)
}

/// The language-neutral view of an [`AppReceipt`]: dates as ISO-8601 UTC,
/// byte fields as lowercase hex mirrored under `<name>Hex`, maps as objects
/// keyed by the stringified attribute type.
fn app_receipt_json(receipt: &AppReceipt) -> Value {
    let mut out = Map::new();
    out.insert(
        "unknownAttributes".to_owned(),
        unknown_attributes(&receipt.unknown_attributes),
    );
    put_string(&mut out, "receiptType", receipt.receipt_type.as_deref());
    put_string(&mut out, "bundleId", receipt.bundle_id.as_deref());
    put_bytes(
        &mut out,
        "bundleIdBytes",
        receipt.bundle_id_bytes.as_deref(),
    );
    put_string(&mut out, "appVersion", receipt.app_version.as_deref());
    put_bytes(&mut out, "opaqueValue", receipt.opaque_value.as_deref());
    put_bytes(&mut out, "sha1Hash", receipt.sha1_hash.as_deref());
    put_date(&mut out, "creationDate", receipt.creation_date);
    put_date(
        &mut out,
        "originalPurchaseDate",
        receipt.original_purchase_date,
    );
    put_string(
        &mut out,
        "originalAppVersion",
        receipt.original_app_version.as_deref(),
    );
    put_date(&mut out, "expirationDate", receipt.expiration_date);
    out.insert(
        "inAppPurchases".to_owned(),
        Value::Array(receipt.in_app_purchases.iter().map(in_app_json).collect()),
    );
    Value::Object(out)
}

// --- field paths --------------------------------------------------------

#[derive(Debug)]
enum Step {
    Name(String),
    Bracket(String),
}

/// A path step is either a name (`bundleId`, `length`) or a bracket
/// (`[9999]`, `[0]`, `[productId=com.example.app.vip]`). Bracket contents
/// hold dots, so a plain `split('.')` is wrong.
fn path_steps(path: &str) -> Result<Vec<Step>, Failed> {
    let mut steps = Vec::new();
    let mut current = String::new();
    let mut chars = path.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '.' => {
                if !current.is_empty() {
                    steps.push(Step::Name(std::mem::take(&mut current)));
                }
            }
            '[' => {
                if !current.is_empty() {
                    steps.push(Step::Name(std::mem::take(&mut current)));
                }
                let mut inner = String::new();
                let mut closed = false;
                for c in chars.by_ref() {
                    if c == ']' {
                        closed = true;
                        break;
                    }
                    inner.push(c);
                }
                if !closed || inner.is_empty() {
                    return Err(Failed::from(format!(
                        "harness error: unparseable field path \"{path}\""
                    )));
                }
                steps.push(Step::Bracket(inner));
            }
            ']' => {
                return Err(Failed::from(format!(
                    "harness error: unparseable field path \"{path}\""
                )))
            }
            other => current.push(other),
        }
    }
    if !current.is_empty() {
        steps.push(Step::Name(current));
    }
    if steps.is_empty() {
        return Err(Failed::from(format!(
            "harness error: unparseable field path \"{path}\""
        )));
    }
    Ok(steps)
}

/// Resolves one language-neutral field path against a normalised result.
///
/// Returns an owned value because `x.length` has no counterpart inside the
/// tree to borrow.
fn resolve_path(root: &Value, path: &str) -> Result<Option<Value>, Failed> {
    let mut current = root.clone();
    for step in path_steps(path)? {
        if current.is_null() {
            return Ok(None);
        }
        match step {
            Step::Name(name) => {
                if name == "length" {
                    if let Value::Array(items) = &current {
                        return Ok(Some(Value::from(items.len())));
                    }
                }
                match current.get(&name) {
                    Some(next) => current = next.clone(),
                    None => return Ok(None),
                }
            }
            Step::Bracket(inner) => match inner.split_once('=') {
                Some((key, wanted)) if !key.is_empty() => {
                    let Value::Array(items) = &current else {
                        return Err(Failed::from(format!(
                            "{path}: [{inner}] does not select from a list"
                        )));
                    };
                    let matches: Vec<&Value> = items
                        .iter()
                        .filter(|item| item.get(key).and_then(Value::as_str) == Some(wanted))
                        .collect();
                    match matches.as_slice() {
                        [only] => {
                            let only = (*only).clone();
                            current = only;
                        }
                        other => {
                            return Err(Failed::from(format!(
                                "{path}: [{inner}] must select exactly one element, selected {}",
                                other.len()
                            )))
                        }
                    }
                }
                _ => {
                    let next = match &current {
                        Value::Array(items) => inner
                            .parse::<usize>()
                            .ok()
                            .and_then(|index| items.get(index))
                            .cloned(),
                        other => other.get(&inner).cloned(),
                    };
                    match next {
                        Some(next) => current = next,
                        None => return Ok(None),
                    }
                }
            },
        }
    }
    Ok(Some(current))
}

// --- one case ------------------------------------------------------------

fn run_case(dir: PathBuf, fixtures: BTreeMap<String, Fixture>, case: Case) -> Result<(), Failed> {
    let input = fixture_bytes(&dir, &fixtures, &case.input.fixture)?;
    let clock = case_clock(&case)?;
    let outcome: Result<Value, VerificationError> = match case.operation.as_str() {
        "verifyTransaction" => {
            let verifier = jws_verifier(&dir, &fixtures, &case.config, clock)?;
            let jws = String::from_utf8_lossy(&input).into_owned();
            verifier
                .verify_transaction(&jws)
                .map(|p| Value::Object(p.claims))
        }
        "verifyAppTransaction" => {
            let verifier = jws_verifier(&dir, &fixtures, &case.config, clock)?;
            let jws = String::from_utf8_lossy(&input).into_owned();
            verifier
                .verify_app_transaction(&jws)
                .map(|p| Value::Object(p.claims))
        }
        "verifyRaw" => {
            let verifier = jws_verifier(&dir, &fixtures, &case.config, clock)?;
            let jws = String::from_utf8_lossy(&input).into_owned();
            verifier.verify_raw(&jws).map(Value::Object)
        }
        "verifyReceipt" => {
            require_no_clock(clock, "verifyReceipt")?;
            let bundle_id = case.config.bundle_id.clone().ok_or_else(|| {
                Failed::from("harness error: verifyReceipt case without a bundleId")
            })?;
            let verifier = ReceiptVerifier::builder()
                .trusted_roots(trust_anchors(&dir, &fixtures, &case.config.trusted_roots)?)
                .bundle_id(bundle_id)
                .build()
                .map_err(|err| {
                    Failed::from(format!(
                        "harness error: cannot build ReceiptVerifier: {err}"
                    ))
                })?;
            let result = match &case.config.device_guid_hex {
                Some(guid_hex) => {
                    let guid = hex::decode(guid_hex).map_err(|err| {
                        Failed::from(format!("harness error: deviceGuidHex is not hex: {err}"))
                    })?;
                    verifier.verify_with_device_guid(&input, &guid)
                }
                None => verifier.verify(&input),
            };
            result.map(|receipt| app_receipt_json(&receipt))
        }
        "verifyReceiptEndpoint" => {
            let name = case.config.environment.as_deref().ok_or_else(|| {
                Failed::from("harness error: verifyReceiptEndpoint case without an environment")
            })?;
            let environment = Environment::from_str(name)
                .map_err(|err| Failed::from(format!("harness error: {err}")))?;
            let mut builder = VerifyReceiptEndpoint::builder()
                .trusted_roots(trust_anchors(&dir, &fixtures, &case.config.trusted_roots)?)
                .environment(environment);
            if let Some(clock) = clock {
                builder = builder.clock(Arc::new(clock));
            }
            let endpoint = builder.build().map_err(|err| {
                Failed::from(format!(
                    "harness error: cannot build VerifyReceiptEndpoint: {err}"
                ))
            })?;
            let base64_input = apple_purchase_receipt_verifier::base64::encode(&input);
            let response = endpoint.verify_receipt(&VerifyReceiptRequest::new(base64_input));
            if !matches!(
                response.status,
                status::OK
                    | status::MALFORMED
                    | status::NOT_AUTHENTICATED
                    | status::SANDBOX_RECEIPT_ON_PRODUCTION
                    | status::PRODUCTION_RECEIPT_ON_SANDBOX
                    | status::INTERNAL
            ) {
                return Err(Failed::from(format!(
                    "harness error: endpoint answered status {}, which is outside the documented set",
                    response.status
                )));
            }
            Ok(response.to_json_value())
        }
        other => {
            return Err(Failed::from(format!(
                "harness error: no adapter for operation \"{other}\""
            )))
        }
    };

    match outcome {
        Err(error) => {
            if case.expected.status != "error" {
                return Err(Failed::from(format!(
                    "expected success but the call failed with {}",
                    error.reason()
                )));
            }
            let expected_text = case.expected.reason.as_deref().ok_or_else(|| {
                Failed::from("harness error: an error case with no expected reason")
            })?;
            // Only a VerificationError carries a canonical Reason — which
            // the type system enforces here, since that is the only error
            // type a verification entry point can return. An unknown token
            // in the file is a harness failure, never a near-miss match.
            let expected = Reason::from_str(expected_text)
                .map_err(|err| Failed::from(format!("harness error: {err}")))?;
            if error.reason() != expected {
                return Err(Failed::from(format!(
                    "reason: expected {expected}, got {}",
                    error.reason()
                )));
            }
            Ok(())
        }
        Ok(actual) => {
            if case.expected.status != "ok" {
                return Err(Failed::from(format!(
                    "expected {} but the call returned a value",
                    case.expected.reason.as_deref().unwrap_or("an error")
                )));
            }
            let fields =
                case.expected.fields.as_ref().ok_or_else(|| {
                    Failed::from("harness error: an ok case with no expected fields")
                })?;
            for (path, expected) in fields {
                let resolved = resolve_path(&actual, path)?;
                match expected {
                    // null means "absent or unset".
                    Value::Null => {
                        if !matches!(resolved, None | Some(Value::Null)) {
                            return Err(Failed::from(format!(
                                "{path}: expected absent, got {}",
                                resolved.map_or_else(|| "nothing".to_owned(), |v| v.to_string())
                            )));
                        }
                    }
                    _ => {
                        let Some(value) = resolved else {
                            return Err(Failed::from(format!(
                                "{path}: expected {expected}, got nothing"
                            )));
                        };
                        if &value != expected {
                            return Err(Failed::from(format!(
                                "{path}: expected {expected}, got {value}"
                            )));
                        }
                    }
                }
            }
            Ok(())
        }
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

    // Read before any case runs: a fixture no case happens to reference
    // would otherwise drift unnoticed, and the registry is the thing being
    // guarded.
    {
        let dir = dir.clone();
        let fixtures = file.fixtures.clone();
        trials.push(Trial::test(
            "cases.json every registered fixture matches its contentSha256",
            move || check_whole_registry(&dir, &fixtures),
        ));
    }

    let mut represented: Vec<String> = Vec::new();
    for case in &file.cases {
        represented.push(case.id.clone());
        let dir = dir.clone();
        let fixtures = file.fixtures.clone();
        let case = case.clone();
        let name = format!("cases.json {}", case.id);
        trials.push(Trial::test(name, move || run_case(dir, fixtures, case)));
    }

    // Coverage self-check: every case in the file became a trial, asserted
    // against the parsed length rather than a literal, so a silently dropped
    // operation cannot hide.
    {
        let represented = represented.clone();
        trials.push(Trial::test("cases.json every case ran", move || {
            let (_, fresh) = load_cases()?;
            let expected: Vec<String> = fresh.cases.iter().map(|c| c.id.clone()).collect();
            if expected.len() != represented.len() {
                return Err(Failed::from(format!(
                    "cases.json holds {} cases but the adapter generated {}",
                    expected.len(),
                    represented.len()
                )));
            }
            for id in &expected {
                if !represented.contains(id) {
                    return Err(Failed::from(format!("case \"{id}\" was never run")));
                }
            }
            Ok(())
        }));
    }

    libtest_mimic::run(&arguments, trials).exit_code()
}
