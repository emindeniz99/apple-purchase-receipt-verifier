//! The HTTP adapter (feature "server"). Spike only (2026-09-26).
//! Routes select the ABI operation; the body goes to the module unchanged.

use crate::abi::{self, InvokeError, Verifier, MAX_BODY};
use crate::{die, load_runtime, usage};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;


struct App {
    verifier: Verifier,
    permits: tokio::sync::Semaphore,
    token: Option<Vec<u8>>,
    ready: AtomicBool,
}

struct ServeOpts {
    listen: String,
    managed: bool,
    lifecycle: String,
    workers: usize,
}

fn parse_serve(args: &[String]) -> Result<ServeOpts, String> {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let mut o = ServeOpts {
        listen: std::env::var("APRV_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".into()),
        managed: false,
        lifecycle: std::env::var("APRV_LIFECYCLE").unwrap_or_else(|_| "fresh".into()),
        workers: std::env::var("APRV_WORKERS").ok().and_then(|v| v.parse().ok()).unwrap_or(cores),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--listen" => o.listen = it.next().ok_or("--listen needs ADDR")?.clone(),
            "--managed" => o.managed = true,
            "--lifecycle" => o.lifecycle = it.next().ok_or("--lifecycle needs a value")?.clone(),
            "--workers" => o.workers = it.next().and_then(|v| v.parse().ok()).ok_or("--workers needs N")?,
            _ => return Err(format!("unknown option {a}")),
        }
    }
    if o.managed {
        // Managed mode (the Java 8 child): loopback, OS-chosen port, always.
        o.listen = "127.0.0.1:0".into();
    }
    Ok(o)
}

pub fn serve(args: &[String]) -> i32 {
    let o = match parse_serve(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("aprv: {e}");
            return usage();
        }
    };
    let t0 = Instant::now();
    // Managed mode: the parent writes a random token as the first stdin line,
    // then keeps stdin open. EOF on stdin means the parent is gone: exit.
    let token = if o.managed {
        let mut line = Vec::new();
        let mut stdin = std::io::stdin().lock();
        let mut b = [0u8; 1];
        while stdin.read(&mut b).map(|n| n == 1).unwrap_or(false) && b[0] != b'\n' && line.len() < 256 {
            line.push(b[0]);
        }
        if line.len() < 32 {
            return die("managed mode needs a token of at least 32 bytes as the first stdin line");
        }
        drop(stdin);
        std::thread::spawn(|| {
            let mut buf = [0u8; 64];
            let mut stdin = std::io::stdin().lock();
            while matches!(stdin.read(&mut buf), Ok(n) if n > 0) {}
            std::process::exit(0);
        });
        Some(line)
    } else {
        std::env::var("APRV_TOKEN").ok().filter(|t| !t.is_empty()).map(String::into_bytes)
    };
    let (pool, pooling) = match o.lifecycle.as_str() {
        "pool" => (true, false),
        "fresh" => (false, false),
        "fresh-pooling" => (false, true),
        other => return die(format!("unknown lifecycle {other}")),
    };
    let (runtime, source, load_ms) = match load_runtime(pooling) {
        Ok(r) => r,
        Err(e) => return die(format!("{e:#}")),
    };
    let t1 = Instant::now();
    let verifier = match Verifier::new(runtime, pool, o.workers) {
        Ok(v) => v,
        Err(e) => return die(format!("{e:#}")),
    };
    let warm_ms = t1.elapsed().as_secs_f64() * 1e3;
    let app = Arc::new(App {
        verifier,
        permits: tokio::sync::Semaphore::new(o.workers),
        token,
        ready: AtomicBool::new(false),
    });
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");
    rt.block_on(async move {
        let listener = match tokio::net::TcpListener::bind(&o.listen).await {
            Ok(l) => l,
            Err(e) => return die(format!("bind {}: {e}", o.listen)),
        };
        let addr = listener.local_addr().expect("local_addr");
        app.ready.store(true, Ordering::SeqCst);
        eprintln!(
            "aprv: listening on {addr}; lifecycle {} x{}; {source}; load {load_ms:.1} ms, instances {warm_ms:.1} ms, to ready {:.1} ms",
            o.lifecycle,
            o.workers,
            t0.elapsed().as_secs_f64() * 1e3
        );
        // One line on stdout, flushed: the managed parent reads the port here.
        println!("APRV_LISTEN={addr}");
        let _ = std::io::stdout().flush();
        let router = routes(app.clone());
        if let Err(e) = axum::serve(listener, router).with_graceful_shutdown(sigterm()).await {
            return die(e);
        }
        0
    })
}

fn routes(app: Arc<App>) -> Router {
    let r = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .route("/v1/receipt/verify", post(|s: State<Arc<App>>, b: Bytes| run(s, abi::OP_VERIFY_RECEIPT, b)))
        .route("/v1/signed-data/verify", post(|s: State<Arc<App>>, b: Bytes| run(s, abi::OP_VERIFY_SIGNED_DATA, b)))
        .route("/v1/verify-receipt/production", post(|s: State<Arc<App>>, b: Bytes| run(s, abi::OP_ENDPOINT_PRODUCTION, b)))
        .route("/v1/verify-receipt/sandbox", post(|s: State<Arc<App>>, b: Bytes| run(s, abi::OP_ENDPOINT_SANDBOX, b)));
    // Spike only: the corpus's test variants (op + 256: test trust anchors and
    // a pinned clock, parsed by the guest), so the whole corpus can run here.
    #[cfg(feature = "spike")]
    let r = r.route(
        "/spike/call/{op}",
        post(|s: State<Arc<App>>, axum::extract::Path(op): axum::extract::Path<i32>, b: Bytes| async move {
            if !(257..=260).contains(&op) {
                return (StatusCode::NOT_FOUND, "spike route takes ops 257..260 only").into_response();
            }
            run(s, op, b).await
        })
        .layer(DefaultBodyLimit::max(MAX_BODY + (1 << 20))),
    );
    // Spike only, never in a default build: a deliberate process crash.
    #[cfg(feature = "crash")]
    let r = r.route("/spike/crash", post(crash));
    r.layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(app.clone(), require_token))
        .with_state(app)
}

#[cfg(feature = "crash")]
async fn crash() -> &'static str {
    std::process::abort()
}

async fn readyz(State(app): State<Arc<App>>) -> Response {
    if app.ready.load(Ordering::SeqCst) {
        "ready".into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "starting").into_response()
    }
}

/// With a token configured, every route needs `X-Aprv-Token: <token>`.
async fn require_token(State(app): State<Arc<App>>, headers: HeaderMap, req: Request, next: Next) -> Response {
    if let Some(want) = &app.token {
        let got = headers.get("x-aprv-token").map(|v| v.as_bytes()).unwrap_or(b"");
        // Constant time over the expected length.
        let mut diff = (got.len() != want.len()) as u8;
        for (i, w) in want.iter().enumerate() {
            diff |= w ^ got.get(i).copied().unwrap_or(0);
        }
        if diff != 0 {
            return (StatusCode::UNAUTHORIZED, "missing or wrong X-Aprv-Token").into_response();
        }
    }
    next.run(req).await
}

fn error_json(status: StatusCode, kind: &str, message: &str) -> Response {
    let escaped: String = message
        .chars()
        .flat_map(|c| match c {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect(),
            c if (c as u32) < 0x20 => format!("\\u{:04x}", c as u32).chars().collect(),
            c => vec![c],
        })
        .collect();
    (status, [(header::CONTENT_TYPE, "application/json")], format!("{{\"error\":\"{kind}\",\"message\":\"{escaped}\"}}")).into_response()
}

/// A verification result (verified or not) is 200 with the module's JSON,
/// untouched. A trap, an ABI error or a lost worker is 5xx.
async fn run(State(app): State<Arc<App>>, op: i32, body: Bytes) -> Response {
    let Ok(permit) = app.permits.acquire().await else {
        return error_json(StatusCode::SERVICE_UNAVAILABLE, "SHUTTING_DOWN", "no workers");
    };
    let a = app.clone();
    let res = tokio::task::spawn_blocking(move || a.verifier.invoke(op, &body)).await;
    drop(permit);
    match res {
        Ok(Ok(json)) => (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], json).into_response(),
        Ok(Err(InvokeError::Trap(m))) => error_json(StatusCode::INTERNAL_SERVER_ERROR, "WASM_TRAP", &m),
        Ok(Err(InvokeError::Abi(m))) => error_json(StatusCode::INTERNAL_SERVER_ERROR, "ABI_ERROR", &m),
        Err(e) => error_json(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", &e.to_string()),
    }
}

async fn sigterm() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
