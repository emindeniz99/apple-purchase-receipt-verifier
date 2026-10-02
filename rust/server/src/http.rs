//! `aprv serve`: the HTTP routes over one `Verifier` (ARCHITECTURE.md §7.7).
//!
//! A route picks the operation and passes the request body through
//! unchanged. A verification result, verified or not, is HTTP 200 with the
//! module's JSON byte for byte; a body over MAX_BODY is cut to MAX_BODY + 1
//! bytes, and the module's answer to that (its own size refusal) is HTTP
//! 413 with the same JSON. Everything else is an RFC 9457 problem
//! (`application/problem+json`) with a `code` member.

use crate::runtime::{InvokeError, Op, Verifier};
use crate::MAX_BODY;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub permits: tokio::sync::Semaphore,
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
        // Constant time over the expected token's length.
        let mut diff = (got.len() != want.len()) as u8;
        for (i, w) in want.iter().enumerate() {
            diff |= w ^ got.get(i).copied().unwrap_or(0);
        }
        if diff != 0 {
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

/// `X-Aprv-Now-Ms` (a u64 in decimal) or the server's clock.
fn now_ms(headers: &HeaderMap) -> Result<u64, Box<Response>> {
    let Some(v) = headers.get(NOW_HEADER) else {
        return Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0));
    };
    let s = v.to_str().unwrap_or("");
    let ok = !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit());
    match s.parse::<u64>() {
        Ok(n) if ok => Ok(n),
        _ => Err(Box::new(problem(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Bad Request",
            "X-Aprv-Now-Ms must be an unsigned 64-bit integer in decimal (milliseconds since the Unix epoch)",
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
    run(s, &h, b, |now_ms| Op::Endpoint { env: 0, now_ms }).await
}
async fn endpoint_sandbox(s: State<Arc<App>>, h: HeaderMap, b: Body) -> Response {
    run(s, &h, b, |now_ms| Op::Endpoint { env: 1, now_ms }).await
}

/// Past the cap the server keeps reading, and discards, up to this many
/// bytes before it answers 413: a client that is still sending when the
/// answer comes would otherwise see its connection reset instead of the
/// answer (measured: Python's http.client got EPIPE on corpus rows over the
/// cap). A body announced larger than this is read only as far as the
/// module needs, answered, and the connection closed; one that turns out
/// larger while it streams is answered and closed the same way.
pub const MAX_DRAIN: usize = 16 << 20;

/// A request body as the module gets it: at most MAX_BODY + 1 bytes, so an
/// input over the cap still reaches the module over its cap and the module
/// answers it (TOO_LARGE, 21002 at the endpoint), as every Wasm host cuts
/// an input to the same length (Go's `maxInput`, Swift's `maxInputBytes`).
struct Capped {
    bytes: Vec<u8>,
    /// The body was larger than MAX_BODY: the answer is 413.
    over: bool,
    /// Part of the body was left unread: the connection is closed.
    close: bool,
}

/// Reads the request body; `Err` is the problem to send.
async fn read_capped(headers: &HeaderMap, body: Body) -> Result<Capped, Box<Response>> {
    const KEEP: usize = MAX_BODY + 1;
    let announced = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    // Announced past the drain limit: read what the module needs and stop.
    let announced_big = announced.is_some_and(|n| n > MAX_DRAIN as u64);
    let mut body = body;
    let mut buf = Vec::with_capacity(announced.map_or(0, |n| n.min(KEEP as u64) as usize));
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
        let room = KEEP - buf.len();
        buf.extend_from_slice(&data[..data.len().min(room)]);
        if (announced_big && total >= KEEP) || total > MAX_DRAIN {
            close = true;
            break;
        }
    }
    Ok(Capped {
        over: total > MAX_BODY,
        bytes: buf,
        close,
    })
}

async fn run(
    State(app): State<Arc<App>>,
    headers: &HeaderMap,
    body: Body,
    op: impl FnOnce(u64) -> Op,
) -> Response {
    // The clock header is checked first, so a bad one costs no body read.
    let op = match now_ms(headers) {
        Ok(n) => op(n),
        Err(p) => return *p,
    };
    let body = match read_capped(headers, body).await {
        Ok(b) => b,
        Err(p) => return *p,
    };
    let Ok(permit) = app.permits.acquire().await else {
        return problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Internal Server Error",
            "shutting down",
        );
    };
    let a = app.clone();
    let input = body.bytes;
    let res = tokio::task::spawn_blocking(move || a.verifier.invoke(op, &input)).await;
    drop(permit);
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
