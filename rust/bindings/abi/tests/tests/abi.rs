//! The ABI tests of the canonical-ABI final round (ARCHITECTURE.md §9, "The
//! canonical ABI holds"), on the built aprv.wasm, through a hand-rolled host
//! and through Wasmtime's component runtime. Each rule is one test that runs
//! on both hosts where both can express it.

use aprv_abi_tests::{
    artifacts, is_trap, ComponentGuest, CoreGuest, Guest, Randomness, HOST, IFACE,
};
use serde_json::Value;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULTS: &[u8] = br#"{"roots":[]}"#;

fn fixture(relative: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../fixtures")
        .join(relative);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The genuine sandbox G5 receipt, as the `receipt-data` a client sends.
fn g5() -> Vec<u8> {
    let text = String::from_utf8(fixture("public-receipts/receipt-sandbox-g5.b64")).unwrap();
    text.split_whitespace().collect::<String>().into_bytes()
}

fn transaction() -> Vec<u8> {
    String::from_utf8(fixture("generated/transaction.jws"))
        .unwrap()
        .trim()
        .as_bytes()
        .to_vec()
}

fn jws_config() -> Vec<u8> {
    let root = fixture("generated/jws-root.der");
    format!("{{\"roots\":[\"{}\"]}}", standard_base64(&root)).into_bytes()
}

fn standard_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            out.push(if i <= chunk.len() {
                char::from(ALPHABET[((n >> shift) & 0x3f) as usize])
            } else {
                '='
            });
        }
    }
    out
}

fn now() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("not JSON ({e}): {text}"))
}

fn endpoint_body() -> Vec<u8> {
    format!(
        "{{\"receipt-data\":\"{}\"}}",
        String::from_utf8(g5()).unwrap()
    )
    .into_bytes()
}

type Make = fn(Randomness) -> Box<dyn Guest>;

fn hosts() -> [(&'static str, Make); 2] {
    [
        ("hand-rolled", |r| Box::new(CoreGuest::new(r).unwrap())),
        ("component", |r| Box::new(ComponentGuest::new(r).unwrap())),
    ]
}

/// A guest after `init` with `config`, which must answer `{"ok":true}`.
fn ready(make: Make, config: &[u8]) -> Box<dyn Guest> {
    let mut guest = make(Randomness::default());
    assert_eq!(guest.init(config).unwrap(), r#"{"ok":true}"#);
    guest
}

fn verifies(guest: &mut dyn Guest) -> bool {
    let answer = guest.verify_receipt(now(), &g5()).unwrap();
    json(&answer)["verified"] == true
}

#[test]
fn the_module_imports_random_get_and_exports_the_interface_only() {
    let module = &artifacts().module;
    let imports: Vec<(String, String)> = module
        .imports()
        .map(|i| (i.module().to_owned(), i.name().to_owned()))
        .collect();
    assert_eq!(imports, [(HOST.to_owned(), "random-get".to_owned())]);
    let mut exports: Vec<String> = module.exports().map(|e| e.name().to_owned()).collect();
    exports.sort();
    exports.retain(|e| !e.starts_with("cabi_realloc_wit_bindgen_"));
    let mut expected: Vec<String> = [
        "init",
        "verify-receipt",
        "verify-signed-data",
        "verify-receipt-endpoint",
    ]
    .iter()
    .flat_map(|op| [format!("{IFACE}#{op}"), format!("cabi_post_{IFACE}#{op}")])
    .chain(["cabi_realloc", "memory", "_initialize"].map(String::from))
    .collect();
    expected.sort();
    assert_eq!(exports, expected);

    let component = artifacts().component.component_type();
    let engine = &artifacts().engine;
    let imports: Vec<&str> = component.imports(engine).map(|(name, _)| name).collect();
    let exports: Vec<&str> = component.exports(engine).map(|(name, _)| name).collect();
    assert_eq!(imports, [HOST]);
    assert_eq!(exports, [IFACE]);
}

#[test]
fn no_start_function_is_needed_and_the_calls_answer_the_wire() {
    // Neither host calls _initialize: each export runs the constructors on
    // its first call.
    for (host, make) in hosts() {
        let mut guest = ready(make, DEFAULTS);
        let receipt = json(&guest.verify_receipt(now(), &g5()).unwrap());
        assert_eq!(receipt["verified"], true, "{host}");
        assert_eq!(
            receipt["payload"]["receipt_type"], "ProductionSandbox",
            "{host}"
        );
        assert_eq!(receipt.as_object().unwrap().len(), 2, "{host}");

        let sandbox = json(
            &guest
                .verify_receipt_endpoint(1, now(), &endpoint_body())
                .unwrap(),
        );
        assert_eq!(sandbox["status"], 0, "{host}");
        let production = guest
            .verify_receipt_endpoint(0, now(), &endpoint_body())
            .unwrap();
        assert_eq!(production, r#"{"status":21007}"#, "{host}");

        let mut guest = ready(make, &jws_config());
        let jws = json(&guest.verify_signed_data(now(), &transaction()).unwrap());
        assert_eq!(jws["verified"], true, "{host}");
        let payload = json(jws["payload"].as_str().expect("the payload is a string"));
        assert_eq!(payload["bundleId"], "com.example.app", "{host}");
    }
}

#[test]
fn an_environment_other_than_0_or_1_traps() {
    for (host, make) in hosts() {
        for env in [2, 255, u32::MAX] {
            let mut guest = ready(make, DEFAULTS);
            let result = guest.verify_receipt_endpoint(env, now(), &endpoint_body());
            assert!(is_trap(&result), "{host} env {env}: {result:?}");
        }
    }
}

#[test]
fn a_verify_before_init_traps() {
    for (host, make) in hosts() {
        let mut guest = make(Randomness::default());
        assert!(is_trap(&guest.verify_receipt(now(), &g5())), "{host}");
        let mut guest = make(Randomness::default());
        assert!(
            is_trap(&guest.verify_signed_data(now(), &transaction())),
            "{host}"
        );
        let mut guest = make(Randomness::default());
        assert!(
            is_trap(&guest.verify_receipt_endpoint(1, now(), &endpoint_body())),
            "{host}"
        );
    }
}

#[test]
fn a_second_init_after_a_successful_one_traps() {
    for (host, make) in hosts() {
        let mut guest = ready(make, DEFAULTS);
        assert!(is_trap(&guest.init(DEFAULTS)), "{host}");
        let mut guest = ready(make, &jws_config());
        assert!(is_trap(&guest.init(b"{\"roots\":[\"AQID\"]}")), "{host}");
    }
}

#[test]
fn a_refused_configuration_is_a_value_and_init_may_be_retried() {
    for (host, make) in hosts() {
        let mut guest = make(Randomness::default());
        for refused in [
            &br#"{"roots":["bm90IGEgY2VydGlmaWNhdGU="]}"#[..],
            b"{not json",
            br#"{"root":[]}"#,
            b"\xff",
            br#"{"roots":["AQ"]}"#,
        ] {
            let answer = json(&guest.init(refused).unwrap());
            assert_eq!(answer["ok"], false, "{host}");
            assert!(answer["message"].is_string(), "{host}");
            assert_eq!(answer.as_object().unwrap().len(), 2, "{host}");
        }
        assert_eq!(guest.init(b"").unwrap(), r#"{"ok":true}"#, "{host}");
        assert!(verifies(guest.as_mut()), "{host}");
    }
}

#[test]
fn a_random_get_answer_of_the_wrong_length_traps() {
    for (host, make) in hosts() {
        // One short, one long, none at all, and far too many.
        for trim in [1, -1, i64::MAX, -4096] {
            let mut guest = make(Randomness { trim });
            assert_eq!(guest.init(&jws_config()).unwrap(), r#"{"ok":true}"#);
            let result = guest.verify_signed_data(now(), &transaction());
            assert!(is_trap(&result), "{host} trim {trim}: {result:?}");
        }
    }
    // And it is called at all: an ES256 verification asks for randomness.
    let mut guest = CoreGuest::new(Randomness::default()).unwrap();
    guest.init(&jws_config()).unwrap();
    guest.verify_signed_data(now(), &transaction()).unwrap();
    assert!(guest.store.data().random_calls > 0);
}

#[test]
fn a_trap_in_one_instance_leaves_another_verifying() {
    for (host, make) in hosts() {
        let mut trapped = ready(make, DEFAULTS);
        let mut other = ready(make, DEFAULTS);
        assert!(verifies(other.as_mut()), "{host}");
        assert!(is_trap(&trapped.verify_receipt_endpoint(
            2,
            now(),
            &endpoint_body()
        )));
        assert!(
            verifies(other.as_mut()) && verifies(other.as_mut()),
            "{host}"
        );
    }
    // A component runtime refuses a trapped instance; a hand-rolled host has
    // to discard it itself (ARCHITECTURE.md §4).
    let mut trapped = ComponentGuest::new(Randomness::default()).unwrap();
    trapped.init(DEFAULTS).unwrap();
    assert!(trapped
        .verify_receipt_endpoint(2, now(), &endpoint_body())
        .is_err());
    let again = trapped.verify_receipt(now(), &g5());
    assert!(again.is_err() && !is_trap(&again), "{again:?}");
}

#[test]
fn two_thousand_calls_leave_linear_memory_the_same_size() {
    let mut guest = CoreGuest::new(Randomness::default()).unwrap();
    guest.init(DEFAULTS).unwrap();
    for _ in 0..200 {
        assert!(verifies(&mut guest));
    }
    let before = guest.memory_size();
    for _ in 0..2000 {
        assert!(verifies(&mut guest));
    }
    assert_eq!(guest.memory_size(), before);
}

#[test]
fn input_that_is_not_utf8_is_a_value() {
    for (host, make) in hosts() {
        let mut guest = ready(make, DEFAULTS);
        let jws = json(
            &guest
                .verify_signed_data(now(), b"eyJ\xff.eyJ9.c2ln")
                .unwrap(),
        );
        assert_eq!(jws["verified"], false, "{host}");
        assert_eq!(jws["reason"], "MALFORMED", "{host}");
        let receipt = json(&guest.verify_receipt(now(), b"MIIT\xfe\xff==").unwrap());
        assert_eq!(receipt["reason"], "MALFORMED", "{host}");
        assert_eq!(receipt["message"], "receipt is not valid base64", "{host}");
        let body = guest
            .verify_receipt_endpoint(1, now(), b"{\"receipt-data\":\"\xff\"}")
            .unwrap();
        assert_eq!(body, r#"{"status":21002}"#, "{host}");
    }
}

#[test]
fn a_clock_beyond_i64_is_an_internal_error() {
    for (host, make) in hosts() {
        let mut guest = ready(make, DEFAULTS);
        for now_ms in [1_u64 << 63, u64::MAX] {
            let answer = json(&guest.verify_receipt(now_ms, &g5()).unwrap());
            assert_eq!(answer["reason"], "INTERNAL_ERROR", "{host}");
            let answer = json(&guest.verify_signed_data(now_ms, &transaction()).unwrap());
            assert_eq!(answer["reason"], "INTERNAL_ERROR", "{host}");
            let body = guest
                .verify_receipt_endpoint(1, now_ms, &endpoint_body())
                .unwrap();
            assert_eq!(body, r#"{"status":21009}"#, "{host}");
        }
        assert!(verifies(guest.as_mut()), "{host}");
    }
}

/// `_initialize` need not be called; calling it first is harmless, a
/// second time traps (crt1-reactor's guard), and after an export has run
/// it only registers the constructors' one atexit handler again: the
/// instance goes on verifying (README.md; review round 2, F8).
#[test]
fn initialize_is_optional_once_and_harmless_after_an_export() {
    let mut first = CoreGuest::new(Randomness::default()).unwrap();
    first.call_initialize().unwrap();
    assert_eq!(first.init(DEFAULTS).unwrap(), r#"{"ok":true}"#);
    assert!(verifies(&mut first));
    let mut twice = CoreGuest::new(Randomness::default()).unwrap();
    twice.call_initialize().unwrap();
    let again = twice.call_initialize();
    assert!(is_trap(&again), "{again:?}");
    let mut after = CoreGuest::new(Randomness::default()).unwrap();
    assert_eq!(after.init(DEFAULTS).unwrap(), r#"{"ok":true}"#);
    assert!(verifies(&mut after));
    after.call_initialize().unwrap();
    assert!(verifies(&mut after));
}

/// Every cap is decided on the input's length before a byte of it is read,
/// so a host that lowers at most 3,145,729 bytes (the largest cap plus one)
/// gets the answer a longer input would get, TOO_LARGE or 21002, and the
/// instance grows by no more than that copy (review round 2, F2).
#[test]
fn a_host_that_lowers_the_largest_cap_plus_one_gets_too_large() {
    const LARGEST_CAP_PLUS_ONE: usize = 3_145_729;
    let over = vec![b'A'; LARGEST_CAP_PLUS_ONE];
    for (host, make) in hosts() {
        let mut guest = ready(make, DEFAULTS);
        let receipt = json(&guest.verify_receipt(now(), &over).unwrap());
        assert_eq!(receipt["reason"], "TOO_LARGE", "{host}");
        let jws = json(&guest.verify_signed_data(now(), &over).unwrap());
        assert_eq!(jws["reason"], "TOO_LARGE", "{host}");
        let body = guest.verify_receipt_endpoint(1, now(), &over).unwrap();
        assert_eq!(body, r#"{"status":21002}"#, "{host}");
        assert!(verifies(guest.as_mut()), "{host}");
    }
    let mut guest = CoreGuest::new(Randomness::default()).unwrap();
    guest.init(DEFAULTS).unwrap();
    assert!(verifies(&mut guest));
    let before = guest.memory_size();
    for _ in 0..3 {
        guest.verify_receipt(now(), &over).unwrap();
        guest.verify_signed_data(now(), &over).unwrap();
    }
    let grown = guest.memory_size() - before;
    assert!(
        grown <= LARGEST_CAP_PLUS_ONE + (1 << 20),
        "memory grew by {grown} bytes for inputs of {LARGEST_CAP_PLUS_ONE}"
    );
}
