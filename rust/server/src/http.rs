//! `aprv serve`: the HTTP routes over one `Verifier` (ARCHITECTURE.md §7.7).
//!
//! A route picks the operation and passes the request body through
//! unchanged. A verification result, verified or not, is HTTP 200 with the
//! module's JSON byte for byte; a body of the `max_input_bytes` the
//! module's `init` answer states, or longer, is cut to that length, and
//! the module's answer to that (its own size refusal) is HTTP 413 with the
//! same JSON. Everything else is an RFC 9457 problem
//! (`application/problem+json`) with a `code` member.

use crate::runtime::{Environment, InvokeError, Op, Verifier};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// The problem types, documented in README.md ("Problems").
const PROBLEM_BASE: &str =
    "https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/rust/server/README.md#";

pub const NOW_HEADER: &str = "x-aprv-now-ms";
pub const TOKEN_HEADER: &str = "x-aprv-token";

/// The served OpenAPI document (openapi.yaml as JSON, wire schemas bundled).
pub const OPENAPI_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/openapi.json"));

/// Every route this server answers, as the OpenAPI document must list them
/// (a test holds the router, this list and openapi.yaml together).
#[cfg_attr(not(all(test, feature = "compile")), allow(dead_code))]
pub const ROUTES: &[(&str, &str)] = &[
    ("post", "/v1/receipt/verify"),
    ("post", "/v1/signed-data/verify"),
    ("post", "/v1/verify-receipt/production"),
    ("post", "/v1/verify-receipt/sandbox"),
    ("get", "/v1/info"),
    ("get", "/healthz"),
    ("get", "/readyz"),
    ("get", "/openapi.json"),
];

pub struct App {
    pub verifier: Arc<Verifier>,
    /// One permit per worker. A call holds its permit until the guest call
    /// ends, not until the request's future does: a client that disconnects
    /// drops the future while `spawn_blocking` keeps running.
    pub permits: Arc<tokio::sync::Semaphore>,
    /// One permit per request body that is being received or is waiting
    /// for a worker. A request takes one before it reads its body and
    /// gives it back once a worker takes the call, so at most this many
    /// bodies, each cut to `max_input_bytes`, are held in memory ahead of
    /// the workers however many requests arrive.
    pub uploads: Arc<tokio::sync::Semaphore>,
    /// How long a body may take to arrive once admitted: a client that
    /// stalls partway gets 408 and its connection closed, and gives its
    /// upload permit back.
    pub body_timeout: std::time::Duration,
    pub token: Option<Vec<u8>>,
    pub info: Value,
}

pub fn problem(status: StatusCode, code: &str, title: &str, detail: &str) -> Response {
    let body = json!({
        "type": format!("{PROBLEM_BASE}{}", code.to_ascii_lowercase().replace('_', "-")),
        "title": title,
        "status": status.as_u16(),
        "detail": detail,
        "code": code,
    });
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        )],
        body.to_string(),
    )
        .into_response()
}

pub fn router(app: Arc<App>) -> Router {
    let v1 = Router::new()
        .route("/v1/receipt/verify", post(verify_receipt))
        .route("/v1/signed-data/verify", post(verify_signed_data))
        .route("/v1/verify-receipt/production", post(endpoint_production))
        .route("/v1/verify-receipt/sandbox", post(endpoint_sandbox))
        .route("/v1/info", get(info))
        .route_layer(middleware::from_fn_with_state(app.clone(), require_token));
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ready" }))
        .route("/openapi.json", get(openapi))
        .merge(v1)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(app)
}

async fn not_found() -> Response {
    problem(
        StatusCode::NOT_FOUND,
        "NOT_FOUND",
        "Not Found",
        "no such route; GET /openapi.json lists them",
    )
}

async fn method_not_allowed() -> Response {
    problem(
        StatusCode::METHOD_NOT_ALLOWED,
        "METHOD_NOT_ALLOWED",
        "Method Not Allowed",
        "this route does not take that method; GET /openapi.json lists the routes",
    )
}

async fn openapi() -> Response {
    ([(header::CONTENT_TYPE, "application/json")], OPENAPI_JSON).into_response()
}

async fn info(State(app): State<Arc<App>>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        app.info.to_string(),
    )
        .into_response()
}

/// With a token configured, every `/v1/` route needs `X-Aprv-Token`.
async fn require_token(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    if let Some(want) = &app.token {
        let got = headers
            .get(TOKEN_HEADER)
            .map(|v| v.as_bytes())
            .unwrap_or(b"");
        // Compared as SHA-256 digests, in constant time: `ct_eq` on the
        // tokens themselves returns at once on a length mismatch, which
        // would let timing tell the token's length. Digests are always 32
        // bytes, so every presented token costs the same comparison.
        let (got, want) = (Sha256::digest(got), Sha256::digest(want));
        if !bool::from(got.as_slice().ct_eq(want.as_slice())) {
            return problem(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Unauthorized",
                "missing or wrong X-Aprv-Token",
            );
        }
    }
    next.run(req).await
}

/// `X-Aprv-Now-Ms` (0 to `i64::MAX` in decimal: WIT `now-ms` is an `s64`
/// since ABI 0.2.0, and a clock before 1970 is the caller's to refuse) or
/// the server's clock.
fn now_ms(headers: &HeaderMap) -> Result<i64, Box<Response>> {
    let Some(v) = headers.get(NOW_HEADER) else {
        return Ok(crate::clock_ms());
    };
    let s = v.to_str().unwrap_or("");
    let ok = !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit());
    match s.parse::<i64>() {
        Ok(n) if ok => Ok(n),
        _ => Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Bad Request",
            "X-Aprv-Now-Ms must be an integer from 0 to 9223372036854775807 in decimal (milliseconds since the Unix epoch)",
        ))),
    }
}

async fn verify_receipt(s: State<Arc<App>>, h: HeaderMap, b: Body) -> Response {
    run(s, &h, b, |now_ms| Op::VerifyReceipt { now_ms }).await
}
async fn verify_signed_data(s: State<Arc<App>>, h: HeaderMap, b: Body) -> Response {
    run(s, &h, b, |now_ms| Op::VerifySignedData { now_ms }).await
}
async fn endpoint_production(s: State<Arc<App>>, h: HeaderMap, b: Body) -> Response {
    run(s, &h, b, |now_ms| Op::Endpoint {
        env: Environment::Production,
        now_ms,
    })
    .await
}
async fn endpoint_sandbox(s: State<Arc<App>>, h: HeaderMap, b: Body) -> Response {
    run(s, &h, b, |now_ms| Op::Endpoint {
        env: Environment::Sandbox,
        now_ms,
    })
    .await
}

/// Past the cap the server keeps reading, and discards, up to this many
/// bytes before it answers 413: a client that is still sending when the
/// answer comes would otherwise see its connection reset instead of the
/// answer (measured: Python's http.client got EPIPE on corpus rows over the
/// cap). A body announced larger than this is read only as far as the
/// module needs, answered, and the connection closed; one that turns out
/// larger while it streams is answered and closed the same way.
pub const MAX_DRAIN: usize = 16 << 20;

/// `aprv serve`'s body deadline ([`App::body_timeout`]): 30 s lets the
/// 3 MiB cap through at about 100 KB/s.
pub const BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Request bodies admitted per worker ([`App::uploads`]).
pub const UPLOADS_PER_WORKER: usize = 4;

/// `aprv serve`'s request-head deadline ([`Limits::header_timeout`]),
/// hyper's own default: a head is a few hundred bytes, so 30 s is generous
/// for any client, and a keep-alive client that idles longer reconnects.
pub const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `aprv serve`'s connection cap ([`Limits::max_connections`]): far more
/// than the workers can use at once, and half the 1,024-descriptor soft
/// limit many systems start a process with.
pub const MAX_CONNECTIONS: usize = 512;

/// The bounds [`serve`] puts on connections, before any request is read.
#[derive(Clone, Copy)]
pub struct Limits {
    /// How long a connection may take to send a complete request head,
    /// counted from accept and again from the end of each response, so it
    /// is also the keep-alive idle timeout. The connection is closed
    /// without an answer when it passes.
    pub header_timeout: std::time::Duration,
    /// Connections open at once. At the cap the server stops accepting;
    /// further connections wait in the listen backlog until one closes.
    pub max_connections: usize,
}

/// Serves `router` over HTTP/1.1 on `listener` within `limits` until
/// `shutdown` completes. Then it stops accepting, closes idle connections,
/// and returns once the requests in flight are answered.
///
/// `axum::serve` sets no timer on hyper's connection builder, which turns
/// hyper's request-head deadline off, and it accepts without bound: a peer
/// that opens connections and sends nothing could hold every descriptor
/// before the token check ran. This loop is `axum::serve` with those two
/// bounds added.
pub async fn serve(
    listener: tokio::net::TcpListener,
    router: Router,
    limits: Limits,
    shutdown: impl std::future::Future<Output = ()>,
) {
    use hyper_util::rt::{TokioIo, TokioTimer};
    use hyper_util::server::graceful::GracefulShutdown;
    use hyper_util::service::TowerToHyperService;

    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_timeout);
    let open = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let permit = tokio::select! {
            p = open.clone().acquire_owned() => p.expect("the semaphore is never closed"),
            () = &mut shutdown => break,
        };
        let stream = tokio::select! {
            r = listener.accept() => match r {
                Ok((stream, _)) => stream,
                Err(e) => {
                    accept_failed(e).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let conn = builder.serve_connection(
            TokioIo::new(stream),
            TowerToHyperService::new(router.clone()),
        );
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            // A failed connection (a reset, a passed deadline) has nobody
            // to tell; it ends, and so does its place.
            let _ = conn.await;
            drop(permit);
        });
    }
    drop(listener);
    graceful.shutdown().await;
}

/// As `axum::serve` handles an accept error: a connection that failed
/// before it was accepted is skipped; anything else (out of descriptors)
/// is reported and retried after a second.
async fn accept_failed(e: std::io::Error) {
    use std::io::ErrorKind::{ConnectionAborted, ConnectionRefused, ConnectionReset};
    if matches!(
        e.kind(),
        ConnectionAborted | ConnectionRefused | ConnectionReset
    ) {
        return;
    }
    eprintln!("aprv: accept: {e}");
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
}

/// A request body as the module gets it: at most the `max_input_bytes` its
/// `init` answer states, so an input over the cap still reaches the module
/// over its cap and the module answers it (TOO_LARGE, 21002 at the
/// endpoint), as every Wasm host cuts an input to the length `init` states
/// (DECISIONS.md R42).
struct Capped {
    bytes: Vec<u8>,
    /// The body was `max_input_bytes` or longer, over the module's cap:
    /// the answer is 413.
    over: bool,
    /// Part of the body was left unread: the connection is closed.
    close: bool,
}

/// Reads the request body, keeping at most `keep` bytes (the module's
/// `max_input_bytes`); `Err` is the problem to send.
async fn read_capped(
    headers: &HeaderMap,
    body: Body,
    keep: usize,
) -> Result<Capped, Box<Response>> {
    let announced = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    // Announced past the drain limit: read what the module needs and stop.
    let announced_big = announced.is_some_and(|n| n > MAX_DRAIN as u64);
    let mut body = body;
    let mut buf = Vec::with_capacity(announced.map_or(0, |n| n.min(keep as u64) as usize));
    let mut total = 0usize;
    let mut close = false;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| {
            Box::new(problem(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Bad Request",
                &format!("reading the body: {e}"),
            ))
        })?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        total = total.saturating_add(data.len());
        let room = keep - buf.len();
        buf.extend_from_slice(&data[..data.len().min(room)]);
        if (announced_big && total >= keep) || total > MAX_DRAIN {
            close = true;
            break;
        }
    }
    Ok(Capped {
        over: total >= keep,
        bytes: buf,
        close,
    })
}

async fn run(
    State(app): State<Arc<App>>,
    headers: &HeaderMap,
    body: Body,
    op: impl FnOnce(i64) -> Op,
) -> Response {
    // The clock header is checked first, so a bad one costs no body read.
    let op = match now_ms(headers) {
        Ok(n) => op(n),
        Err(p) => return *p,
    };
    let shutting_down = || {
        problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Internal Server Error",
            "shutting down",
        )
    };
    // The body is admitted before it is read, and the admission is held
    // until a worker takes the call.
    let Ok(upload) = app.uploads.clone().acquire_owned().await else {
        return shutting_down();
    };
    let read = read_capped(headers, body, app.verifier.max_input_bytes());
    let body = match tokio::time::timeout(app.body_timeout, read).await {
        Ok(Ok(b)) => b,
        Ok(Err(p)) => return *p,
        Err(_) => {
            let mut response = problem(
                StatusCode::REQUEST_TIMEOUT,
                "REQUEST_TIMEOUT",
                "Request Timeout",
                &format!(
                    "the body did not arrive within {} ms",
                    app.body_timeout.as_millis()
                ),
            );
            response
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("close"));
            return response;
        }
    };
    let Ok(permit) = app.permits.clone().acquire_owned().await else {
        return shutting_down();
    };
    drop(upload);
    let a = app.clone();
    let input = body.bytes;
    let res = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        a.verifier.invoke(op, &input)
    })
    .await;
    let internal = |d: &str| {
        problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Internal Server Error",
            d,
        )
    };
    let mut response = match res {
        // A body over the cap is still the module's answer, byte for byte;
        // only the status says the cap was passed.
        Ok(Ok(json)) => (
            if body.over {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::OK
            },
            [(header::CONTENT_TYPE, "application/json")],
            json,
        )
            .into_response(),
        Ok(Err(InvokeError::Trap(m))) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "WASM_TRAP",
            "Wasm Trap",
            first_line(&m),
        ),
        Ok(Err(InvokeError::Abi(m))) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ABI_ERROR",
            "ABI Error",
            first_line(&m),
        ),
        Ok(Err(InvokeError::Internal(m))) => internal(first_line(&m)),
        Err(e) => internal(&format!("the worker was lost: {e}")),
    };
    if body.close {
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or("")
}

/// The connection bounds of [`serve`], over real sockets. They need no
/// component, so they run in every build.
#[cfg(test)]
mod serve_tests {
    use super::{serve, Limits};
    use axum::routing::get;
    use std::io::{ErrorKind, Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::time::{Duration, Instant};

    const HEALTHZ: &[u8] = b"GET /healthz HTTP/1.1\r\nHost: aprv\r\n\r\n";

    /// A server of one route, `/healthz`, within `limits`; dropping the
    /// sender shuts it down, and the handle ends when `serve` returns.
    async fn start(
        limits: Limits,
    ) -> (
        SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = axum::Router::new().route("/healthz", get(|| async { "ok" }));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve(listener, router, limits, async move {
            let _ = stopped.await;
        }));
        (addr, stop, server)
    }

    fn connect(addr: SocketAddr) -> TcpStream {
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s
    }

    /// Reads until the server closes the connection; what it sent first.
    fn until_closed(s: &mut TcpStream) -> Vec<u8> {
        let mut got = Vec::new();
        match s.read_to_end(&mut got) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
            Err(e) => panic!("the server did not close the connection: {e}"),
        }
        got
    }

    /// Reads one `/healthz` answer off `s`, leaving it open: the status line.
    fn read_ok(s: &mut TcpStream) -> String {
        let mut got = Vec::new();
        let mut buf = [0u8; 512];
        while !got.ends_with(b"\r\n\r\nok") {
            let n = s.read(&mut buf).unwrap();
            assert!(n > 0, "closed before the answer: {got:?}");
            got.extend_from_slice(&buf[..n]);
        }
        let text = String::from_utf8(got).unwrap();
        text.lines().next().unwrap().to_owned()
    }

    fn healthz(s: &mut TcpStream) -> String {
        s.write_all(HEALTHZ).unwrap();
        read_ok(s)
    }

    /// A peer that sends part of a head and stalls is cut off at the
    /// deadline, unanswered, and its place goes to the next connection:
    /// with a cap of one, a stalled head would otherwise lock every client
    /// out for good.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_partial_request_head_is_dropped_after_the_header_timeout() {
        let limits = Limits {
            header_timeout: Duration::from_millis(300),
            max_connections: 1,
        };
        let (addr, _stop, _server) = start(limits).await;
        tokio::task::spawn_blocking(move || {
            let start = Instant::now();
            let mut stalled = connect(addr);
            stalled
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: a")
                .unwrap();
            assert_eq!(
                until_closed(&mut stalled),
                b"",
                "a passed head deadline gets no answer"
            );
            let held = start.elapsed();
            assert!(held >= Duration::from_millis(250), "closed after {held:?}");
            assert!(held < Duration::from_secs(5), "closed after {held:?}");
            let mut next = connect(addr);
            assert_eq!(healthz(&mut next), "HTTP/1.1 200 OK");
        })
        .await
        .unwrap();
    }

    /// The same deadline runs between requests: a keep-alive connection
    /// that sends nothing after its answer is closed once it passes.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_idle_keep_alive_connection_is_closed_after_the_header_timeout() {
        let limits = Limits {
            header_timeout: Duration::from_millis(300),
            max_connections: 4,
        };
        let (addr, _stop, _server) = start(limits).await;
        tokio::task::spawn_blocking(move || {
            let mut s = connect(addr);
            assert_eq!(healthz(&mut s), "HTTP/1.1 200 OK");
            assert_eq!(healthz(&mut s), "HTTP/1.1 200 OK", "kept alive");
            let idle = Instant::now();
            assert_eq!(until_closed(&mut s), b"");
            let held = idle.elapsed();
            assert!(held >= Duration::from_millis(250), "closed after {held:?}");
            assert!(held < Duration::from_secs(5), "closed after {held:?}");
        })
        .await
        .unwrap();
    }

    /// At the cap the server accepts no more: a further connection gets
    /// no answer while the others stay open, and is served as soon as one
    /// of them closes.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_connection_cap_holds_until_a_connection_closes() {
        let limits = Limits {
            header_timeout: Duration::from_secs(30),
            max_connections: 2,
        };
        let (addr, _stop, _server) = start(limits).await;
        tokio::task::spawn_blocking(move || {
            let mut first = connect(addr);
            let mut second = connect(addr);
            assert_eq!(healthz(&mut first), "HTTP/1.1 200 OK");
            assert_eq!(healthz(&mut second), "HTTP/1.1 200 OK");
            // The kernel completes the handshake from the listen backlog;
            // the server has not accepted it, so nothing answers.
            let mut third = connect(addr);
            third.write_all(HEALTHZ).unwrap();
            third
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let e = third
                .read(&mut [0u8; 64])
                .expect_err("answered over the cap");
            assert!(
                matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
                "{e}"
            );
            drop(first);
            third
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            assert_eq!(read_ok(&mut third), "HTTP/1.1 200 OK");
            assert_eq!(healthz(&mut second), "HTTP/1.1 200 OK");
        })
        .await
        .unwrap();
    }

    /// Shutdown stops accepting and closes an idle keep-alive connection at
    /// once rather than waiting out its deadline, then `serve` returns.
    #[tokio::test(flavor = "multi_thread")]
    async fn shutdown_closes_idle_connections_and_returns() {
        let limits = Limits {
            header_timeout: Duration::from_secs(30),
            max_connections: 4,
        };
        let (addr, stop, server) = start(limits).await;
        let mut s = tokio::task::spawn_blocking(move || {
            let mut s = connect(addr);
            assert_eq!(healthz(&mut s), "HTTP/1.1 200 OK");
            s
        })
        .await
        .unwrap();
        drop(stop);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("serve returned within 5 s")
            .unwrap();
        let rest = tokio::task::spawn_blocking(move || until_closed(&mut s))
            .await
            .unwrap();
        assert_eq!(rest, b"");
    }
}
