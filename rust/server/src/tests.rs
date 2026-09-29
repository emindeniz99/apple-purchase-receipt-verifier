//! In-process tests of the HTTP layer, the limits and the lifecycles
//! (`cargo test --features compile`). They compile components at start, so
//! they need the full build:
//!
//! - the real component, from `APRV_TEST_COMPONENT` (a component `.wasm`;
//!   the stand-in until lane A's module lands, then the release's);
//! - hostile components written below in the component text format: one
//!   that loops forever, one that grows its memory by 1 GiB, one that
//!   returns a string that is not UTF-8, one that asks for 1 GiB of random
//!   bytes. Each must end in a 500 problem while the server keeps answering.

use crate::http::{self, App, ROUTES};
use crate::roots::{Roots, DEFAULT_ROOT_SHA256};
use crate::runtime::{Load, Op, Runtime, Verifier};
use crate::MAX_BODY;
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use std::sync::{Arc, OnceLock};
use tower::ServiceExt;

fn repo(path: &str) -> String {
    format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"))
}

fn component_path() -> String {
    std::env::var("APRV_TEST_COMPONENT").unwrap_or_else(|_| {
        panic!("set APRV_TEST_COMPONENT to the aprv.wasm component (.wasm) these tests run")
    })
}

/// The real component, compiled once for every test that uses it.
fn real() -> Arc<Verifier> {
    static V: OnceLock<Arc<Verifier>> = OnceLock::new();
    V.get_or_init(|| {
        let rt = Runtime::new(Load::File(&component_path()), 10_000).expect("load the component");
        Arc::new(Verifier::new(rt, Roots::Defaults.config_json(), false).expect("init"))
    })
    .clone()
}

fn app(verifier: Arc<Verifier>, token: Option<&str>) -> axum::Router {
    let info = serde_json::json!({
        "component_sha256": verifier.runtime.source.component_sha256,
        "roots": Roots::Defaults.info(),
    });
    http::router(Arc::new(App {
        verifier,
        permits: tokio::sync::Semaphore::new(2),
        token: token.map(|t| t.as_bytes().to_vec()),
        info,
    }))
}

fn g5() -> Vec<u8> {
    let text =
        std::fs::read_to_string(repo("fixtures/public-receipts/receipt-sandbox-g5.b64")).unwrap();
    text.split_whitespace().collect::<String>().into_bytes()
}

async fn send(
    router: &axum::Router,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> (StatusCode, String, Vec<u8>) {
    let mut req = Request::builder().method(method).uri(path);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let res = router
        .clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let ct = res
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let body = to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, ct, body)
}

fn problem(ct: &str, body: &[u8]) -> Value {
    assert_eq!(ct, "application/problem+json");
    let v: Value = serde_json::from_slice(body).unwrap();
    for k in ["type", "title", "status", "detail", "code"] {
        assert!(v.get(k).is_some(), "problem without {k}: {v}");
    }
    v
}

// ------------------------------------------------------------ the real component

#[tokio::test]
async fn a_verification_result_is_200_with_the_module_json_byte_for_byte() {
    let v = real();
    let r = app(v.clone(), None);
    let (s, ct, body) = send(
        &r,
        "POST",
        "/v1/receipt/verify",
        &[("x-aprv-now-ms", "1700000000000")],
        g5(),
    )
    .await;
    assert_eq!((s, ct.as_str()), (StatusCode::OK, "application/json"));
    let direct = v
        .invoke(
            Op::VerifyReceipt {
                now_ms: 1_700_000_000_000,
            },
            &g5(),
        )
        .unwrap();
    assert_eq!(
        body,
        direct.as_bytes(),
        "the server must not touch the module's JSON"
    );
    assert!(direct.contains(r#""verified":true"#), "{direct}");
    // Not verified is still a result: 200.
    let (s, _, body) = send(
        &r,
        "POST",
        "/v1/signed-data/verify",
        &[],
        b"not.a.jws".to_vec(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(String::from_utf8(body)
        .unwrap()
        .contains(r#""verified":false"#));
    // The endpoint answers Apple's format on both routes.
    let req = [br#"{"receipt-data":""#.as_slice(), &g5(), br#""}"#].concat();
    for (path, env) in [
        ("/v1/verify-receipt/sandbox", 1),
        ("/v1/verify-receipt/production", 0),
    ] {
        let (s, _, body) = send(
            &r,
            "POST",
            path,
            &[("x-aprv-now-ms", "1700000000000")],
            req.clone(),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let direct = v
            .invoke(
                Op::Endpoint {
                    env,
                    now_ms: 1_700_000_000_000,
                },
                &req,
            )
            .unwrap();
        assert_eq!(String::from_utf8(body).unwrap(), direct);
    }
}

#[tokio::test]
async fn the_body_cap_is_413_before_the_module_sees_it() {
    let r = app(real(), None);
    let (s, ct, body) = send(
        &r,
        "POST",
        "/v1/receipt/verify",
        &[],
        vec![b'A'; MAX_BODY + 1],
    )
    .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(problem(&ct, &body)["code"], "PAYLOAD_TOO_LARGE");
    // Far over the cap (past what the server drains) is 413 as well.
    let big = vec![b'A'; http::MAX_DRAIN + 1];
    let (s, ct, body) = send(&r, "POST", "/v1/verify-receipt/sandbox", &[], big).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(problem(&ct, &body)["code"], "PAYLOAD_TOO_LARGE");
    // Exactly at the cap the module answers (a result, not a 413).
    let (s, _, _) = send(&r, "POST", "/v1/receipt/verify", &[], vec![b'A'; MAX_BODY]).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn the_token_guards_every_v1_route_and_nothing_else() {
    let r = app(real(), Some("0123456789abcdef0123456789abcdef"));
    for (method, path) in ROUTES.iter().filter(|(_, p)| p.starts_with("/v1/")) {
        let m = method.to_uppercase();
        let (s, ct, body) = send(&r, &m, path, &[], g5()).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(problem(&ct, &body)["code"], "UNAUTHORIZED");
        let (s, _, _) = send(
            &r,
            &m,
            path,
            &[("x-aprv-token", "0123456789abcdef0123456789abcdeX")],
            g5(),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}: a wrong token");
        let (s, _, _) = send(
            &r,
            &m,
            path,
            &[("x-aprv-token", "0123456789abcdef0123456789abcdef")],
            g5(),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{path}: the right token");
    }
    for path in ["/healthz", "/readyz", "/openapi.json"] {
        assert_eq!(
            send(&r, "GET", path, &[], vec![]).await.0,
            StatusCode::OK,
            "{path}"
        );
    }
}

#[tokio::test]
async fn a_bad_clock_header_404_and_405_are_problems() {
    let r = app(real(), None);
    for bad in ["", "-1", "1.5", "18446744073709551616", "0x10", " 1"] {
        let (s, ct, body) = send(
            &r,
            "POST",
            "/v1/receipt/verify",
            &[("x-aprv-now-ms", bad)],
            g5(),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad:?}");
        assert_eq!(problem(&ct, &body)["code"], "BAD_REQUEST");
    }
    let (s, _, _) = send(
        &r,
        "POST",
        "/v1/receipt/verify",
        &[("x-aprv-now-ms", "18446744073709551615")],
        g5(),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "u64::MAX is a clock");
    let (s, ct, body) = send(&r, "GET", "/v1/nothing", &[], vec![]).await;
    assert_eq!(
        (s, problem(&ct, &body)["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("NOT_FOUND"))
    );
    let (s, ct, body) = send(&r, "GET", "/v1/receipt/verify", &[], vec![]).await;
    assert_eq!(
        (s, problem(&ct, &body)["code"].as_str()),
        (StatusCode::METHOD_NOT_ALLOWED, Some("METHOD_NOT_ALLOWED"))
    );
}

#[tokio::test]
async fn info_serves_the_component_hash_and_root_fingerprints() {
    let v = real();
    let r = app(v.clone(), None);
    let (s, _, body) = send(&r, "GET", "/v1/info", &[], vec![]).await;
    assert_eq!(s, StatusCode::OK);
    let info: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        info["component_sha256"],
        v.runtime.source.component_sha256.as_str()
    );
    assert_eq!(
        info["roots"]["sha256"],
        serde_json::json!(DEFAULT_ROOT_SHA256)
    );
}

#[tokio::test]
async fn the_openapi_document_lists_exactly_the_routes_the_server_answers() {
    let r = app(real(), None);
    let (s, _, body) = send(&r, "GET", "/openapi.json", &[], vec![]).await;
    assert_eq!(s, StatusCode::OK);
    let doc: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["openapi"], "3.1.0");
    let mut documented: Vec<(String, String)> = doc["paths"]
        .as_object()
        .unwrap()
        .iter()
        .flat_map(|(p, ops)| {
            ops.as_object()
                .unwrap()
                .keys()
                .map(move |m| (m.clone(), p.clone()))
        })
        .collect();
    documented.sort();
    let mut routes: Vec<(String, String)> = ROUTES
        .iter()
        .map(|(m, p)| (m.to_string(), p.to_string()))
        .collect();
    routes.sort();
    assert_eq!(documented, routes);
    for (m, p) in ROUTES {
        let (s, _, _) = send(&r, &m.to_uppercase(), p, &[], g5()).await;
        assert_eq!(s, StatusCode::OK, "{m} {p} is documented but not answered");
    }
    // Nothing references a file the served document does not carry.
    assert!(!String::from_utf8(body).unwrap().contains("../bindings/"));
}

/// Until lane A2 writes rust/bindings/wire/schema/, the served document
/// carries placeholders for the two result schemas. Run with --ignored
/// once they exist; CI runs it (CI-NOTES.md).
#[tokio::test]
#[ignore = "needs rust/bindings/wire/schema/ (lane A2)"]
async fn the_wire_schemas_are_bundled() {
    assert!(!http::OPENAPI_JSON.contains("not present when this binary was built"));
}

#[test]
fn a_refused_root_stops_the_server_at_start() {
    let rt = Runtime::new(Load::File(&component_path()), 10_000).unwrap();
    let e = Verifier::new(
        rt,
        Roots::Configured(vec![vec![1, 2, 3]]).config_json(),
        false,
    )
    .err()
    .unwrap();
    assert!(
        e.contains("refused the roots configuration") && e.contains(r#""ok":false"#),
        "{e}"
    );
}

#[test]
fn a_store_holds_exactly_one_component_instance() {
    let rt = Runtime::new(Load::File(&component_path()), 10_000).unwrap();
    // One instance per store works (and init, and a call) ...
    let mut i = rt.ready_instance(b"{}").unwrap().unwrap();
    assert!(i
        .call(Op::VerifyReceipt { now_ms: 0 }, &g5())
        .unwrap()
        .contains(r#""verified":true"#));
    // ... and the store limit refuses a second one.
    let e = i.instantiate_again(&rt).unwrap_err();
    assert!(format!("{e:#}").contains("instance"), "{e:#}");
}

#[test]
fn a_trapped_pool_instance_is_discarded_and_the_next_call_gets_a_fresh_one() {
    let rt = Runtime::new(Load::File(&component_path()), 10_000).unwrap();
    let v = Verifier::new(rt, b"{}".to_vec(), true).unwrap();
    let req = [br#"{"receipt-data":""#.as_slice(), &g5(), br#""}"#].concat();
    // env 2 is not a value a route produces; the guest traps on it.
    let e = v
        .invoke(Op::Endpoint { env: 2, now_ms: 0 }, &req)
        .unwrap_err();
    assert!(matches!(e, crate::runtime::InvokeError::Trap(_)), "{e:?}");
    assert!(v
        .invoke(Op::VerifyReceipt { now_ms: 0 }, &g5())
        .unwrap()
        .contains(r#""verified":true"#));
}

// ------------------------------------------------------------ hostile components

/// A component with aprv.wasm's interface whose operations misbehave:
/// init answers {"ok":true}; verify-receipt loops forever; verify-signed-data
/// grows memory by 16,384 pages (1 GiB); verify-receipt-endpoint returns
/// bytes that are not UTF-8 as its string; and with env 1 asks the host
/// for 1 GiB of random bytes first.
const HOSTILE: &str = r#"
(component
  (import "aprv:verifier/host@1.0.0" (instance $host
    (export "random-get" (func (param "len" u32) (result (list u8))))))
  (core module $libc
    (memory (export "memory") 1)
    (global $bump (mut i32) (i32.const 4096))
    (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
      (local $p i32)
      (local.set $p (global.get $bump))
      (global.set $bump (i32.and (i32.add (i32.add (global.get $bump) (local.get 3)) (i32.const 7)) (i32.const -8)))
      (local.get $p)))
  (core instance $libc (instantiate $libc))
  (alias core export $libc "memory" (core memory $mem))
  (alias core export $libc "cabi_realloc" (core func $realloc))
  (alias export $host "random-get" (func $random-get))
  (core func $random-get-lowered (canon lower (func $random-get) (memory $mem) (realloc $realloc)))
  (core module $m
    (import "libc" "memory" (memory 1))
    (import "host" "random-get" (func $random (param i32 i32)))
    (data (i32.const 16) "{\22ok\22:true}")
    (data (i32.const 64) "\ff\fe")
    (func $ret (param $p i32) (param $l i32) (result i32)
      (i32.store (i32.const 0) (local.get $p))
      (i32.store (i32.const 4) (local.get $l))
      (i32.const 0))
    (func (export "init") (param i32 i32) (result i32)
      (call $ret (i32.const 16) (i32.const 11)))
    (func (export "verify-receipt") (param i64 i32 i32) (result i32)
      (loop $l (br $l))
      (unreachable))
    (func (export "verify-signed-data") (param i64 i32 i32) (result i32)
      (drop (memory.grow (i32.const 16384)))
      (call $ret (i32.const 16) (i32.const 11)))
    (func (export "verify-receipt-endpoint") (param i32 i64 i32 i32) (result i32)
      (if (i32.eq (local.get 0) (i32.const 1))
        (then (call $random (i32.const 0x40000000) (i32.const 8))))
      (call $ret (i32.const 64) (i32.const 2))))
  (core instance $i (instantiate $m
    (with "libc" (instance $libc))
    (with "host" (instance (export "random-get" (func $random-get-lowered))))))
  (func $init (param "config-json" (list u8)) (result string)
    (canon lift (core func $i "init") (memory $mem) (realloc $realloc)))
  (func $verify-receipt (param "now-ms" u64) (param "receipt-base64" (list u8)) (result string)
    (canon lift (core func $i "verify-receipt") (memory $mem) (realloc $realloc)))
  (func $verify-signed-data (param "now-ms" u64) (param "jws" (list u8)) (result string)
    (canon lift (core func $i "verify-signed-data") (memory $mem) (realloc $realloc)))
  (func $verify-receipt-endpoint (param "env" u32) (param "now-ms" u64) (param "request-json" (list u8)) (result string)
    (canon lift (core func $i "verify-receipt-endpoint") (memory $mem) (realloc $realloc)))
  (instance $verify
    (export "init" (func $init))
    (export "verify-receipt" (func $verify-receipt))
    (export "verify-signed-data" (func $verify-signed-data))
    (export "verify-receipt-endpoint" (func $verify-receipt-endpoint)))
  (export "aprv:verifier/verify@1.0.0" (instance $verify)))
"#;

fn hostile(pool: bool, time_limit_ms: u64) -> Arc<Verifier> {
    let wasm = wat::parse_str(HOSTILE).expect("the hostile component parses");
    let path = std::env::temp_dir().join(format!("aprv-hostile-{}.wasm", std::process::id()));
    std::fs::write(&path, wasm).unwrap();
    let rt = Runtime::new(Load::File(path.to_str().unwrap()), time_limit_ms)
        .expect("the hostile component loads");
    Arc::new(Verifier::new(rt, b"{}".to_vec(), pool).expect("its init says ok"))
}

async fn hostile_round(r: &axum::Router) {
    let t = std::time::Instant::now();
    let (s, ct, body) = send(r, "POST", "/v1/receipt/verify", &[], b"x".to_vec()).await;
    let p = problem(&ct, &body);
    assert_eq!(
        (s, p["code"].as_str()),
        (StatusCode::INTERNAL_SERVER_ERROR, Some("WASM_TRAP")),
        "{p}"
    );
    assert!(
        p["detail"]
            .as_str()
            .unwrap()
            .contains("time limit of 300 ms"),
        "{p}"
    );
    assert!(
        t.elapsed() < std::time::Duration::from_secs(5),
        "the loop ran {:?}",
        t.elapsed()
    );

    let (s, ct, body) = send(r, "POST", "/v1/signed-data/verify", &[], b"x".to_vec()).await;
    let p = problem(&ct, &body);
    assert_eq!(
        (s, p["code"].as_str()),
        (StatusCode::INTERNAL_SERVER_ERROR, Some("WASM_TRAP")),
        "{p}"
    );

    let (s, ct, body) = send(
        r,
        "POST",
        "/v1/verify-receipt/production",
        &[],
        b"x".to_vec(),
    )
    .await;
    let p = problem(&ct, &body);
    assert_eq!(
        (s, p["code"].as_str()),
        (StatusCode::INTERNAL_SERVER_ERROR, Some("ABI_ERROR")),
        "{p}"
    );

    let (s, ct, body) = send(r, "POST", "/v1/verify-receipt/sandbox", &[], b"x".to_vec()).await;
    let p = problem(&ct, &body);
    assert_eq!(
        (s, p["code"].as_str()),
        (StatusCode::INTERNAL_SERVER_ERROR, Some("WASM_TRAP")),
        "{p}"
    );
    assert!(p["detail"].as_str().unwrap().contains("random-get"), "{p}");

    // The server is still there.
    assert_eq!(
        send(r, "GET", "/healthz", &[], vec![]).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_hostile_component_ends_in_500s_and_the_server_survives_fresh() {
    let r = app(hostile(false, 300), None);
    hostile_round(&r).await;
    hostile_round(&r).await;
}

#[tokio::test]
async fn a_hostile_component_ends_in_500s_and_the_server_survives_pool() {
    let r = app(hostile(true, 300), None);
    hostile_round(&r).await;
    hostile_round(&r).await;
}

#[test]
fn a_1_gib_grow_is_refused_by_the_store_limit() {
    let v = hostile(false, 300);
    let e = v
        .invoke(Op::VerifySignedData { now_ms: 0 }, b"")
        .unwrap_err();
    let msg = e.to_string();
    assert!(matches!(e, crate::runtime::InvokeError::Trap(_)), "{msg}");
    assert!(msg.contains("grow") || msg.contains("memory"), "{msg}");
}

/// A precompiled file records the settings of the engine that wrote it.
/// One written with other settings (here: no epoch interruption) is
/// refused by Wasmtime, and the error names the setting.
#[test]
fn a_file_precompiled_with_other_settings_is_refused() {
    let wasm = wat::parse_str(HOSTILE).unwrap();
    let mut other = wasmtime::Config::new();
    other.epoch_interruption(false);
    let code = wasmtime::Engine::new(&other)
        .unwrap()
        .precompile_component(&wasm)
        .unwrap();
    let engine = wasmtime::Engine::new(&crate::runtime::config()).unwrap();
    // SAFETY: bytes this test just produced with Wasmtime's own precompile.
    let e = unsafe { wasmtime::component::Component::deserialize(&engine, &code) }
        .err()
        .unwrap();
    assert!(format!("{e:#}").contains("epoch"), "{e:#}");
}
