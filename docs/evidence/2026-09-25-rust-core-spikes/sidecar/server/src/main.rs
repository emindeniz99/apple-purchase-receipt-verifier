//! aprv-sidecar: a local HTTP server speaking Apple's exact verifyReceipt
//! JSON contract, backed by the `apple-purchase-receipt-verifier` Rust core.
//!
//! Research spike. Not product code.

use aprv::{apple_receipt_roots, Environment, VerifyReceiptEndpoint, MAX_REQUEST_BYTES};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use std::io::Write as _;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// Small margin over the core's own MAX_REQUEST_BYTES check, so a body
/// slightly over the limit reaches the core (which answers 21002/200) rather
/// than being rejected by axum's own body-limit layer with a bare HTTP 413.
const BODY_LIMIT_MARGIN: usize = 4096;

#[tokio::main]
async fn main() {
    let environment = resolve_environment();

    let endpoint = VerifyReceiptEndpoint::builder()
        .environment(environment)
        .trusted_roots(apple_receipt_roots().to_vec())
        .build()
        .expect("valid endpoint config (roots + Production/Sandbox environment)");
    let endpoint = Arc::new(endpoint);

    let app = Router::new()
        .route("/verifyReceipt", post(verify_receipt))
        .route("/health", get(health))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES + BODY_LIMIT_MARGIN))
        .with_state(endpoint);

    let addr: SocketAddr = "127.0.0.1:0".parse().expect("valid loopback addr");
    let listener = TcpListener::bind(addr).await.expect("bind 127.0.0.1:0");
    let port = listener.local_addr().expect("local_addr").port();

    // Exactly one line, then flush: stdout is block-buffered when piped to
    // the parent (ProcessBuilder), so println! alone is not enough.
    println!("APRV_SIDECAR_PORT={port}");
    std::io::stdout().flush().expect("flush stdout");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

/// Environment from the first CLI argument, falling back to the
/// `APRV_ENVIRONMENT` env var. Must be "Production" or "Sandbox"
/// (case-sensitive, Apple's own spelling; `Environment::from_str` accepts
/// exactly that).
fn resolve_environment() -> Environment {
    let raw = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("APRV_ENVIRONMENT").ok())
        .unwrap_or_else(|| {
            eprintln!("usage: aprv-sidecar <Production|Sandbox>  (or APRV_ENVIRONMENT env var)");
            std::process::exit(2);
        });
    match Environment::from_str(&raw) {
        Ok(env @ (Environment::Production | Environment::Sandbox)) => env,
        _ => {
            eprintln!("invalid environment {raw:?}: must be Production or Sandbox");
            std::process::exit(2);
        }
    }
}

async fn health() -> &'static str {
    "ok"
}

async fn verify_receipt(
    State(endpoint): State<Arc<VerifyReceiptEndpoint>>,
    body: Bytes,
) -> impl IntoResponse {
    // The core takes &str (it works on already-decoded JSON text); a body
    // that isn't valid UTF-8 isn't valid JSON either, so a lossy decode is
    // safe here — it can only turn an already-malformed body into a
    // differently-malformed one, and the core's own JSON parse rejects both
    // the same way (status 21002).
    let text = String::from_utf8_lossy(&body).into_owned();

    // CPU-bound verification (RSA/EC signature checks, ASN.1 walk) must not
    // block the async runtime's worker threads.
    let json = match tokio::task::spawn_blocking(move || endpoint.verify_receipt_json(&text))
        .await
    {
        Ok(json) => json,
        // The core catches its own panics (Reason::InternalError, 21009);
        // this only fires if the blocking task itself was cancelled/aborted,
        // which does not happen in this server's lifecycle.
        Err(_) => r#"{"status":21009}"#.to_owned(),
    };

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
}

/// Resolves when SIGTERM arrives, or when stdin reaches EOF (the parent JVM
/// process died and closed the pipe) — whichever comes first.
async fn shutdown_signal() {
    let sigterm = async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term =
                signal(SignalKind::terminate()).expect("install SIGTERM handler");
            term.recv().await;
        }
        #[cfg(not(unix))]
        std::future::pending::<()>().await;
    };

    let stdin_eof = async {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 64];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) => break,  // EOF: parent closed the pipe.
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    };

    tokio::select! {
        () = sigterm => {}
        () = stdin_eof => {}
    }
}
