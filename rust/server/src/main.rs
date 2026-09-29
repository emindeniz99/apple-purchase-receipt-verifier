//! `aprv`: runs the released aprv.wasm component through Wasmtime, as an
//! HTTP server (`aprv serve`, standalone or as a managed child) or as a
//! one-shot CLI. It holds no verification logic: no base64 rule, CMS, JWS,
//! certificate or trust decision. See README.md for the wire contract.

mod http;
mod manifest;
mod roots;
mod runtime;
#[cfg(all(test, feature = "compile"))]
mod tests;

use roots::Roots;
use runtime::{Load, Op, Runtime, Verifier};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Instant;

/// The request body cap: Apple's verifyReceipt answers 3,145,728 bytes and
/// refuses one more (fixtures/cases.json, "Resource bounds"). The HTTP
/// server answers a larger body 413 and the CLI exits 3, before the module
/// sees a byte.
pub const MAX_BODY: usize = 3_145_728;

const USAGE: &str = "\
usage:
  aprv serve [--listen ADDR] [--managed] [--roots FILE] [--token-file FILE]
             [--lifecycle fresh|pool] [--workers N] [--time-limit-ms N]
  aprv verify-receipt [--now-ms N] [--roots FILE] [--time-limit-ms N]         stdin -> stdout
  aprv verify-signed-data [--now-ms N] [--roots FILE] [--time-limit-ms N]     stdin -> stdout
  aprv verify-receipt-endpoint <production|sandbox> [--now-ms N] [--roots FILE] [--time-limit-ms N]
  aprv info
  aprv precompile COMPONENT.wasm --target TRIPLE -o OUT.ccwasm                (full build only)
Every command but precompile also takes --component FILE.wasm (full build only).
Environment: APRV_LISTEN (serve's address; default 127.0.0.1:8080), APRV_TOKEN (serve's token).
CLI exit codes: 0 a result, 2 usage or configuration, 3 input over 3145728 bytes, 70 trap, ABI or load failure.";

/// CLI exit codes.
const EXIT_OK: i32 = 0;
const EXIT_USAGE: i32 = 2;
const EXIT_TOO_LARGE: i32 = 3;
const EXIT_SOFTWARE: i32 = 70;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("serve") => serve(&args[1..]),
        Some("verify-receipt") => one_shot(Command::Receipt, &args[1..]),
        Some("verify-signed-data") => one_shot(Command::SignedData, &args[1..]),
        Some("verify-receipt-endpoint") => match args.get(1).map(String::as_str) {
            Some("production") => one_shot(Command::Endpoint(0), &args[2..]),
            Some("sandbox") => one_shot(Command::Endpoint(1), &args[2..]),
            _ => usage("verify-receipt-endpoint needs production or sandbox"),
        },
        Some("info") => info(&args[1..]),
        Some("precompile") => precompile(&args[1..]),
        Some("help" | "--help" | "-h") => {
            println!("{USAGE}");
            EXIT_OK
        }
        _ => usage("no command"),
    };
    std::process::exit(code);
}

fn usage(msg: &str) -> i32 {
    eprintln!("aprv: {msg}\n{USAGE}");
    EXIT_USAGE
}

fn die(msg: impl std::fmt::Display) -> i32 {
    eprintln!("aprv: {msg}");
    EXIT_SOFTWARE
}

/// Options shared by every command.
#[derive(Default)]
struct Opts {
    listen: Option<String>,
    managed: bool,
    roots: Option<String>,
    token_file: Option<String>,
    pool: bool,
    workers: Option<usize>,
    time_limit_ms: Option<u64>,
    now_ms: Option<u64>,
    component: Option<String>,
}

fn parse(args: &[String], allowed: &[&str]) -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if !allowed.contains(&a.as_str()) {
            return Err(format!("unknown option {a}"));
        }
        let mut val = || it.next().cloned().ok_or(format!("{a} needs a value"));
        match a.as_str() {
            "--listen" => o.listen = Some(val()?),
            "--managed" => o.managed = true,
            "--roots" => o.roots = Some(val()?),
            "--token-file" => o.token_file = Some(val()?),
            "--component" => o.component = Some(val()?),
            "--lifecycle" => {
                o.pool = match val()?.as_str() {
                    "fresh" => false,
                    "pool" => true,
                    other => return Err(format!("--lifecycle takes fresh or pool, not {other}")),
                }
            }
            "--workers" => {
                o.workers = Some(
                    val()?
                        .parse()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or("--workers needs a positive integer")?,
                )
            }
            "--time-limit-ms" => {
                o.time_limit_ms = Some(
                    val()?
                        .parse()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or("--time-limit-ms needs a positive integer")?,
                )
            }
            "--now-ms" => {
                o.now_ms = Some(
                    val()?
                        .parse()
                        .map_err(|_| "--now-ms needs an unsigned 64-bit integer")?,
                )
            }
            _ => unreachable!("every allowed option is matched"),
        }
    }
    Ok(o)
}

fn load(o: &Opts) -> Result<Runtime, String> {
    let l = match &o.component {
        Some(p) => Load::File(p),
        None => Load::Embedded,
    };
    Runtime::new(l, o.time_limit_ms.unwrap_or(runtime::DEFAULT_TIME_LIMIT_MS))
}

fn roots_from(o: &Opts) -> Result<Roots, String> {
    match &o.roots {
        None => Ok(Roots::Defaults),
        Some(p) => {
            let text = std::fs::read_to_string(p).map_err(|e| format!("--roots {p}: {e}"))?;
            Roots::from_file_text(&text).map_err(|e| format!("--roots {p}: {e}"))
        }
    }
}

// ------------------------------------------------------------ one-shot CLI

#[derive(Clone, Copy)]
enum Command {
    Receipt,
    SignedData,
    Endpoint(u32),
}

/// Reads stdin (at most MAX_BODY bytes), runs one operation in one fresh
/// instance and writes the module's JSON to stdout, byte for byte.
fn one_shot(cmd: Command, args: &[String]) -> i32 {
    let o = match parse(
        args,
        &["--now-ms", "--roots", "--time-limit-ms", "--component"],
    ) {
        Ok(o) => o,
        Err(e) => return usage(&e),
    };
    let roots = match roots_from(&o) {
        Ok(r) => r,
        Err(e) => return usage(&e),
    };
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin()
        .lock()
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut input)
    {
        return die(format!("reading stdin: {e}"));
    }
    if input.len() > MAX_BODY {
        eprintln!("aprv: input larger than {MAX_BODY} bytes");
        return EXIT_TOO_LARGE;
    }
    let runtime = match load(&o) {
        Ok(r) => r,
        Err(e) => return die(e),
    };
    // cli-fast-exit: the process ends right after the answer, so the runtime
    // is never dropped. Dropping it deregisters the compiled code's unwind
    // information one entry at a time, which costs about 55 ms under the
    // LLVM libunwind a static musl binary links; the kernel frees it all at
    // exit anyway (docs/evidence/2026-09-27-static-musl-server.md §3).
    let runtime = std::mem::ManuallyDrop::new(runtime);
    let now_ms = o.now_ms.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    });
    let op = match cmd {
        Command::Receipt => Op::VerifyReceipt { now_ms },
        Command::SignedData => Op::VerifySignedData { now_ms },
        Command::Endpoint(env) => Op::Endpoint { env, now_ms },
    };
    let mut instance = match runtime.ready_instance(&roots.config_json()) {
        Ok(Ok(i)) => i,
        Ok(Err(answer)) => {
            eprintln!("aprv: the component refused the roots configuration: {answer}");
            return EXIT_USAGE;
        }
        Err(e) => return die(e),
    };
    let out = match instance.call(op, &input) {
        Ok(out) => out,
        Err(e) => return die(e),
    };
    std::mem::forget(instance);
    let mut stdout = std::io::stdout().lock();
    if stdout
        .write_all(out.as_bytes())
        .and_then(|_| stdout.flush())
        .is_err()
    {
        return die("writing stdout");
    }
    EXIT_OK
}

// ------------------------------------------------------------ info, precompile

fn build_info(runtime: &Runtime) -> serde_json::Value {
    serde_json::json!({
        "abi": "aprv:verifier@1.0.0",
        "component_sha256": runtime.source.component_sha256,
        "component_source": runtime.source.description,
        "wasmtime": runtime::WASMTIME_VERSION,
        "engine_features": runtime::engine_features(),
        "wasm_features": runtime::wasm_features(&runtime::config()),
        "epoch_interruption": true,
        "limits": {
            "max_body_bytes": MAX_BODY,
            "max_guest_memory_bytes": runtime::MAX_GUEST_MEMORY,
            "max_core_instances_per_store": runtime::MAX_CORE_INSTANCES,
        },
        "arch": std::env::consts::ARCH,
        "os": std::env::consts::OS,
    })
}

fn info(args: &[String]) -> i32 {
    let o = match parse(args, &["--component"]) {
        Ok(o) => o,
        Err(e) => return usage(&e),
    };
    let t = Instant::now();
    match load(&o) {
        Ok(runtime) => {
            // As the CLI: exit without the runtime's slow teardown.
            let runtime = std::mem::ManuallyDrop::new(runtime);
            let mut v = build_info(&runtime);
            v["load_ms"] = serde_json::json!((t.elapsed().as_secs_f64() * 1e4).round() / 10.0);
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
            EXIT_OK
        }
        Err(e) => {
            println!(
                "{}",
                serde_json::json!({
                    "wasmtime": runtime::WASMTIME_VERSION,
                    "engine_features": runtime::engine_features(),
                    "wasm_features": runtime::wasm_features(&runtime::config()),
                    "error": e,
                })
            );
            EXIT_SOFTWARE
        }
    }
}

#[cfg(feature = "compile")]
fn precompile(args: &[String]) -> i32 {
    let (mut component, mut target, mut out) = (None, None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--target" => target = it.next(),
            "-o" => out = it.next(),
            s if !s.starts_with('-') && component.is_none() => component = Some(a),
            _ => return usage(&format!("unknown precompile argument {a}")),
        }
    }
    let (Some(c), Some(t), Some(o)) = (component, target, out) else {
        return usage("precompile needs COMPONENT.wasm, --target TRIPLE and -o OUT.ccwasm");
    };
    match runtime::precompile(c, t, o) {
        Ok(msg) => {
            println!("{msg}");
            EXIT_OK
        }
        Err(e) => die(e),
    }
}

#[cfg(not(feature = "compile"))]
fn precompile(_: &[String]) -> i32 {
    die("precompile needs the full build (feature `compile`)")
}

// ------------------------------------------------------------ serve

fn serve(args: &[String]) -> i32 {
    let o = match parse(
        args,
        &[
            "--listen",
            "--managed",
            "--roots",
            "--token-file",
            "--lifecycle",
            "--workers",
            "--time-limit-ms",
            "--component",
        ],
    ) {
        Ok(o) => o,
        Err(e) => return usage(&e),
    };
    let t0 = Instant::now();
    let (listen, token, roots) = if o.managed {
        if o.roots.is_some() || o.token_file.is_some() || o.listen.is_some() {
            return usage("--managed reads its token and roots from stdin and binds 127.0.0.1:0");
        }
        match managed_handshake() {
            Ok((token, roots)) => ("127.0.0.1:0".to_owned(), Some(token), roots),
            Err(e) => {
                eprintln!("aprv: managed mode: {e}");
                return EXIT_USAGE;
            }
        }
    } else {
        let listen = o
            .listen
            .clone()
            .or_else(|| std::env::var("APRV_LISTEN").ok().filter(|s| !s.is_empty()))
            .unwrap_or_else(|| "127.0.0.1:8080".into());
        let token = match &o.token_file {
            Some(p) => match std::fs::read(p) {
                Ok(t) => Some(t.trim_ascii().to_vec()).filter(|t| !t.is_empty()),
                Err(e) => return usage(&format!("--token-file {p}: {e}")),
            },
            None => std::env::var("APRV_TOKEN")
                .ok()
                .filter(|t| !t.is_empty())
                .map(String::into_bytes),
        };
        let roots = match roots_from(&o) {
            Ok(r) => r,
            Err(e) => return usage(&e),
        };
        (listen, token, roots)
    };
    let runtime = match load(&o) {
        Ok(r) => r,
        Err(e) => return die(e),
    };
    let load_ms = t0.elapsed().as_secs_f64() * 1e3;
    let mut info = build_info(&runtime);
    let verifier = match Verifier::new(runtime, roots.config_json(), o.pool) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("aprv: {e}");
            return EXIT_USAGE;
        }
    };
    let workers = o.workers.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });
    info["roots"] = roots.info();
    info["lifecycle"] = verifier.lifecycle_name().into();
    info["workers"] = workers.into();
    info["time_limit_ms"] = o
        .time_limit_ms
        .unwrap_or(runtime::DEFAULT_TIME_LIMIT_MS)
        .into();
    info["token_required"] = token.is_some().into();
    let lifecycle = verifier.lifecycle_name();
    let app = Arc::new(http::App {
        verifier: Arc::new(verifier),
        permits: tokio::sync::Semaphore::new(workers),
        token,
        info,
    });
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return die(format!("tokio runtime: {e}")),
    };
    rt.block_on(async move {
        let listener = match tokio::net::TcpListener::bind(&listen).await {
            Ok(l) => l,
            Err(e) => return die(format!("bind {listen}: {e}")),
        };
        let addr = match listener.local_addr() {
            Ok(a) => a,
            Err(e) => return die(format!("local address: {e}")),
        };
        eprintln!(
            "aprv: listening on {addr}; lifecycle {lifecycle}, {workers} workers; load {load_ms:.1} ms, ready {:.1} ms",
            t0.elapsed().as_secs_f64() * 1e3
        );
        // One line on stdout, flushed: a managed parent reads the port here.
        println!("APRV_LISTEN={addr}");
        let _ = std::io::stdout().flush();
        if let Err(e) = axum::serve(listener, http::router(app)).with_graceful_shutdown(shutdown()).await {
            return die(e);
        }
        EXIT_OK
    })
}

/// Managed mode (the child of a Java 8 or PHP parent): the first stdin line
/// is the token (at least 32 bytes; the parent sends 256 random bits), the
/// second the roots as `init` takes them (`{}` for the built-in Apple
/// roots). stdin then stays open; EOF means the parent is gone, and the
/// server exits.
fn managed_handshake() -> Result<(Vec<u8>, Roots), String> {
    let mut stdin = std::io::stdin().lock();
    let token = read_line(&mut stdin, 1024)?;
    if token.len() < 32 {
        return Err("the first stdin line must be a token of at least 32 bytes".into());
    }
    let roots_line = read_line(&mut stdin, 1 << 20)?;
    let roots_text = String::from_utf8(roots_line).map_err(|_| "the roots line is not UTF-8")?;
    let roots = Roots::from_config_json(&roots_text)?;
    drop(stdin);
    std::thread::Builder::new()
        .name("aprv-stdin".into())
        .spawn(|| {
            let mut buf = [0u8; 256];
            let mut stdin = std::io::stdin().lock();
            while matches!(stdin.read(&mut buf), Ok(n) if n > 0) {}
            std::process::exit(EXIT_OK);
        })
        .map_err(|e| format!("stdin watcher: {e}"))?;
    Ok((token, roots))
}

/// One line without its `\n` (and a `\r` before it), at most `max` bytes.
fn read_line(r: &mut impl Read, max: usize) -> Result<Vec<u8>, String> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match r.read(&mut b) {
            Ok(0) => return Err("stdin closed during the handshake".into()),
            Ok(_) if b[0] == b'\n' => break,
            Ok(_) if line.len() >= max => {
                return Err(format!("a handshake line is longer than {max} bytes"))
            }
            Ok(_) => line.push(b[0]),
            Err(e) => return Err(format!("reading stdin: {e}")),
        }
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(line)
}

async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) {
            (Ok(mut term), Ok(mut int)) => {
                tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
            }
            _ => std::future::pending::<()>().await,
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
