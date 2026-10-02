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

/// The real component, compiled once for every test that uses it, in the
/// default (pool) lifecycle.
fn real() -> Arc<Verifier> {
    static V: OnceLock<Arc<Verifier>> = OnceLock::new();
    V.get_or_init(|| {
        let rt = Runtime::new(Load::File(&component_path()), 10_000).expect("load the component");
        Arc::new(Verifier::new(rt, Roots::Defaults.config_json(), true).expect("init"))
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

/// The module's answer to `input` as every Wasm host feeds it: cut to
/// MAX_BODY + 1 bytes.
fn module_answer(v: &Verifier, op: Op, input: &[u8]) -> String {
    v.invoke(op, &input[..input.len().min(MAX_BODY + 1)])
        .unwrap()
}

const NOW: u64 = 1_700_000_000_000;

/// Each route with the size fixtures it takes (fixtures/limits, at and over
/// the caps) and bodies far over MAX_BODY and past MAX_DRAIN.
fn size_inputs() -> Vec<(&'static str, Op, String, Vec<u8>)> {
    let receipt = Op::VerifyReceipt { now_ms: NOW };
    let jws = Op::VerifySignedData { now_ms: NOW };
    let production = Op::Endpoint {
        env: 0,
        now_ms: NOW,
    };
    let sandbox = Op::Endpoint {
        env: 1,
        now_ms: NOW,
    };
    let routes = [
        (
            "/v1/receipt/verify",
            receipt,
            &[
                "receipt-b64-at-cap.txt",
                "receipt-b64-over-cap.txt",
                "receipt-der-over-cap.der",
            ][..],
        ),
        (
            "/v1/signed-data/verify",
            jws,
            &["jws-at-cap.jws", "jws-over-cap.jws"][..],
        ),
        (
            "/v1/verify-receipt/production",
            production,
            &[
                "body-ascii-at-cap.json",
                "body-ascii-over-cap.json",
                "body-2byte-at-cap.json",
                "body-2byte-over-cap.json",
            ][..],
        ),
        (
            "/v1/verify-receipt/sandbox",
            sandbox,
            &["body-ascii-at-cap.json", "body-ascii-over-cap.json"][..],
        ),
    ];
    let mut out = Vec::new();
    for (path, op, files) in routes {
        for f in files {
            let bytes = std::fs::read(repo(&format!("fixtures/limits/{f}"))).unwrap();
            out.push((path, op, f.to_string(), bytes));
        }
        out.push((path, op, "2 x MAX_BODY".into(), vec![b'A'; 2 * MAX_BODY]));
        out.push((
            path,
            op,
            "MAX_DRAIN + 1".into(),
            vec![b'A'; http::MAX_DRAIN + 1],
        ));
    }
    out
}

/// Over the cap the server answers 413 with the module's own JSON for the
/// first MAX_BODY + 1 bytes, byte for byte; at or under it, 200.
#[tokio::test]
async fn a_body_over_the_cap_is_413_with_the_module_answer_byte_for_byte() {
    let v = real();
    let r = app(v.clone(), None);
    let mut over = 0;
    for (path, op, name, body) in size_inputs() {
        let want = module_answer(&v, op, &body);
        let len = body.len();
        let (s, ct, got) = send(
            &r,
            "POST",
            path,
            &[("x-aprv-now-ms", "1700000000000")],
            body,
        )
        .await;
        let status = if len > MAX_BODY {
            over += 1;
            assert!(
                want.contains(r#""reason":"TOO_LARGE""#) || want == r#"{"status":21002}"#,
                "{path} {name}: the module did not refuse it for its size: {want}"
            );
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::OK
        };
        assert_eq!(
            (s, ct.as_str()),
            (status, "application/json"),
            "{path} {name}"
        );
        assert_eq!(String::from_utf8(got).unwrap(), want, "{path} {name}");
    }
    assert_eq!(over, 13, "the over-cap inputs");
}

/// The CLI feeds the module the same bytes and prints its answer, exiting
/// 3 over the cap.
#[test]
fn the_cli_prints_the_module_answer_and_exits_3_over_the_cap() {
    let v = real();
    for (path, op, name, body) in size_inputs() {
        let (input, over) = crate::read_input(&body[..]).unwrap();
        let mut out = Vec::new();
        let code = crate::answer(&v.runtime, b"{}", op, &input, over, &mut out);
        let want = if body.len() > MAX_BODY { 3 } else { 0 };
        assert_eq!(code, want, "{path} {name}");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            module_answer(&v, op, &body),
            "{path} {name}"
        );
    }
}

/// One HTTP/1.1 response read off a socket: the status line, the headers
/// (names lowercased) and the body, by its Content-Length.
fn read_response(s: &mut impl std::io::BufRead) -> (String, Vec<(String, String)>, Vec<u8>) {
    let mut status = String::new();
    s.read_line(&mut status).unwrap();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        s.read_line(&mut line).unwrap();
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (k, v) = line.split_once(':').unwrap();
        headers.push((k.to_ascii_lowercase(), v.trim().to_owned()));
    }
    let len: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .map(|(_, v)| v.parse().unwrap())
        .unwrap();
    let mut body = vec![0; len];
    s.read_exact(&mut body).unwrap();
    (status.trim_end().to_owned(), headers, body)
}

/// Over a real connection: a body between the cap and MAX_DRAIN is drained,
/// answered 413 and the connection kept; a body announced past MAX_DRAIN is
/// read only to MAX_BODY + 1 bytes, answered 413 and the connection closed.
#[tokio::test(flavor = "multi_thread")]
async fn over_a_connection_the_drain_keeps_it_and_past_the_drain_it_closes() {
    use std::io::{BufReader, Read, Write};
    let v = real();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let r = app(v.clone(), None);
    tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
    let want = module_answer(
        &v,
        Op::Endpoint {
            env: 1,
            now_ms: NOW,
        },
        &vec![b'A'; MAX_BODY + 1],
    );
    assert_eq!(want, r#"{"status":21002}"#);
    tokio::task::spawn_blocking(move || {
        let head = |len: usize| {
            format!(
                "POST /v1/verify-receipt/sandbox HTTP/1.1\r\nHost: aprv\r\nX-Aprv-Now-Ms: {NOW}\r\nContent-Length: {len}\r\n\r\n"
            )
        };
        // Twice the cap, sent whole: drained, answered, the connection kept.
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(60))).unwrap();
        s.write_all(head(2 * MAX_BODY).as_bytes()).unwrap();
        s.write_all(&vec![b'A'; 2 * MAX_BODY]).unwrap();
        let mut rd = BufReader::new(s.try_clone().unwrap());
        let (status, headers, body) = read_response(&mut rd);
        assert!(status.starts_with("HTTP/1.1 413"), "{status}");
        assert!(headers.contains(&("content-type".into(), "application/json".into())));
        assert!(!headers.iter().any(|(k, _)| k == "connection"), "{headers:?}");
        assert_eq!(String::from_utf8(body).unwrap(), want);
        s.write_all(b"GET /healthz HTTP/1.1\r\nHost: aprv\r\n\r\n").unwrap();
        let (status, _, body) = read_response(&mut rd);
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        assert_eq!(body, b"ok");

        // Announced past MAX_DRAIN, MAX_BODY + 1 bytes sent: answered, closed.
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(60))).unwrap();
        s.write_all(head(http::MAX_DRAIN + 1).as_bytes()).unwrap();
        s.write_all(&vec![b'A'; MAX_BODY + 1]).unwrap();
        let mut rd = BufReader::new(s);
        let (status, headers, body) = read_response(&mut rd);
        assert!(status.starts_with("HTTP/1.1 413"), "{status}");
        assert!(headers.contains(&("connection".into(), "close".into())), "{headers:?}");
        assert_eq!(String::from_utf8(body).unwrap(), want);
        let mut rest = Vec::new();
        assert_eq!(rd.read_to_end(&mut rest).unwrap(), 0, "the server closed the connection");
    })
    .await
    .unwrap();
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

/// The served document carries the wire schemas of rust/bindings/wire/schema/,
/// not the placeholders a build without them would leave.
#[tokio::test]
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

/// A truncated `.cer` passes the roots file reader (its first byte is
/// 0x30, so it is taken as DER, unparsed) and the module's `init` refuses
/// it: the CLI exits 2, and `serve` stops at start as for any refused root.
#[test]
fn a_truncated_der_root_file_is_refused_by_init() {
    let der = std::fs::read(repo("certs/AppleRootCA-G3.cer")).unwrap();
    let roots = Roots::from_files(&[("cut.cer", &der[..der.len() / 2])]).unwrap();
    let v = real();
    let refused = v
        .runtime
        .ready_instance(&roots.config_json())
        .unwrap()
        .err()
        .expect("init refuses a truncated certificate");
    assert!(refused.contains(r#""ok":false"#), "{refused}");
    let mut out = Vec::new();
    let op = Op::VerifyReceipt { now_ms: NOW };
    assert_eq!(
        crate::answer(&v.runtime, &roots.config_json(), op, b"", false, &mut out),
        2
    );
    assert!(out.is_empty());
    // The whole file is a root the module takes.
    let whole = Roots::from_files(&[("AppleRootCA-G3.cer", &der)]).unwrap();
    assert!(v
        .runtime
        .ready_instance(&whole.config_json())
        .unwrap()
        .is_ok());
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
const HOSTILE: &str = include_str!("../tests/hostile.wat");

fn hostile(pool: bool, time_limit_ms: u64) -> Arc<Verifier> {
    // One file per call: the tests run in parallel, and a shared name let
    // one test read the file while another was rewriting it (seen on
    // Windows as an empty file, "not a .wasm component").
    static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let wasm = wat::parse_str(HOSTILE).expect("the hostile component parses");
    let path = std::env::temp_dir().join(format!("aprv-hostile-{}-{n}.wasm", std::process::id()));
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
