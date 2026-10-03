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

use clap::{Args, Parser, Subcommand, ValueEnum};
use roots::Roots;
use runtime::{Instance, Load, Op, Runtime, Verifier};
use std::io::{BufRead, Read, Write};
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::time::Instant;

/// After `--help`: what clap's generated text does not say. The input
/// length is the module's own: its `init` answer states `max_input_bytes`
/// (one over its largest cap; `aprv info` shows it), a longer body or stdin
/// reaches the module cut to that length, and the module answers its own
/// size refusal for it (DECISIONS.md R42). The HTTP server sends that
/// answer with status 413 and the CLI prints it and exits 3.
const AFTER_HELP: &str = "\
Every command but precompile takes --component FILE.wasm in the full build.
Environment: APRV_LISTEN (serve's address; default 127.0.0.1:8080), APRV_TOKEN (serve's token).
CLI exit codes: 0 a result, 2 usage or configuration, 3 input over the module's size cap (the module's answer is on stdout), 70 trap, ABI or load failure.";

/// CLI exit codes.
const EXIT_OK: i32 = 0;
const EXIT_USAGE: i32 = 2;
const EXIT_TOO_LARGE: i32 = 3;
const EXIT_SOFTWARE: i32 = 70;

/// Runs aprv.wasm, the receipt and App Store JWS verifier, through Wasmtime.
#[derive(Parser)]
#[command(name = "aprv", after_help = AFTER_HELP, args_override_self = true)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the HTTP routes (README.md, "The wire contract")
    Serve(ServeArgs),
    /// stdin: a receipt's receipt-data string; stdout: the module's answer
    VerifyReceipt(OneShotArgs),
    /// stdin: a compact JWS; stdout: the module's answer
    VerifySignedData(OneShotArgs),
    /// stdin: a verifyReceipt request body; stdout: Apple's response
    VerifyReceiptEndpoint {
        #[arg(value_enum)]
        environment: Environment,
        #[command(flatten)]
        args: OneShotArgs,
    },
    /// The component's SHA-256, the Wasmtime version and features, the limits
    Info(ComponentArg),
    /// Precompile a component for TARGET's baseline ISA (full build only)
    Precompile {
        #[arg(value_name = "COMPONENT.wasm")]
        component: String,
        #[arg(long, value_name = "TRIPLE")]
        target: String,
        #[arg(short = 'o', value_name = "OUT.ccwasm")]
        out: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Environment {
    Production,
    Sandbox,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
enum Lifecycle {
    /// Keep instances, one request at a time each (DECISIONS.md R23)
    Pool,
    /// A new store, instance and init per request
    Fresh,
}

#[derive(Args)]
struct ComponentArg {
    /// Compile this component at start instead of the embedded one (full build only)
    #[arg(long, value_name = "FILE.wasm")]
    component: Option<String>,
}

#[derive(Args)]
struct OneShotArgs {
    /// The verification clock, ms since the Unix epoch [default: the system clock]
    #[arg(long, value_name = "N")]
    now_ms: Option<u64>,
    /// A trusted root file, repeatable: a DER certificate (an Apple .cer), or base64 lines and PEM
    /// blocks (README.md, "Flags and environment") [default: the module's Apple roots]
    #[arg(long, value_name = "FILE")]
    roots: Vec<String>,
    /// The guest time limit per call [default: 10000]
    #[arg(long, value_name = "N")]
    time_limit_ms: Option<NonZeroU64>,
    #[command(flatten)]
    component: ComponentArg,
}

#[derive(Args)]
struct ServeArgs {
    /// The bind address; overrides APRV_LISTEN [default: 127.0.0.1:8080]
    #[arg(long, value_name = "ADDR")]
    listen: Option<String>,
    /// The child of a parent process: token and roots on stdin, 127.0.0.1:0
    #[arg(long, conflicts_with_all = ["listen", "roots", "token_file"])]
    managed: bool,
    /// A trusted root file, repeatable: a DER certificate (an Apple .cer), or base64 lines and PEM
    /// blocks (README.md, "Flags and environment") [default: the module's Apple roots]
    #[arg(long, value_name = "FILE")]
    roots: Vec<String>,
    /// The token /v1/ routes require; overrides APRV_TOKEN
    #[arg(long, value_name = "FILE")]
    token_file: Option<String>,
    /// How instances serve requests
    #[arg(long, value_enum, default_value_t = Lifecycle::Pool)]
    lifecycle: Lifecycle,
    /// Concurrent verifications [default: the CPU count]
    #[arg(long, value_name = "N")]
    workers: Option<NonZeroUsize>,
    /// The guest time limit per call [default: 10000]
    #[arg(long, value_name = "N")]
    time_limit_ms: Option<NonZeroU64>,
    #[command(flatten)]
    component: ComponentArg,
}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // --help prints to stdout and is not an error.
            let _ = e.print();
            std::process::exit(if e.use_stderr() { EXIT_USAGE } else { EXIT_OK });
        }
    };
    let code = match cli.command {
        Cmd::Serve(a) => serve(a),
        Cmd::VerifyReceipt(a) => one_shot(Command::Receipt, a),
        Cmd::VerifySignedData(a) => one_shot(Command::SignedData, a),
        Cmd::VerifyReceiptEndpoint { environment, args } => one_shot(
            Command::Endpoint(match environment {
                Environment::Production => 0,
                Environment::Sandbox => 1,
            }),
            args,
        ),
        Cmd::Info(a) => info(a),
        Cmd::Precompile {
            component,
            target,
            out,
        } => precompile(&component, &target, &out),
    };
    std::process::exit(code);
}

fn usage(msg: &str) -> i32 {
    eprintln!("aprv: {msg}");
    EXIT_USAGE
}

/// The system clock in milliseconds since the Unix epoch (0 before it):
/// the call's clock when the caller gives none.
fn clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn die(msg: impl std::fmt::Display) -> i32 {
    eprintln!("aprv: {msg}");
    EXIT_SOFTWARE
}

fn load(component: &ComponentArg, time_limit_ms: Option<NonZeroU64>) -> Result<Runtime, String> {
    let l = match &component.component {
        Some(p) => Load::File(p),
        None => Load::Embedded,
    };
    Runtime::new(
        l,
        time_limit_ms.map_or(runtime::DEFAULT_TIME_LIMIT_MS, NonZeroU64::get),
    )
}

/// The `--roots` files, in order; none means the module's Apple roots.
fn roots_from(paths: &[String]) -> Result<Roots, String> {
    let files = paths
        .iter()
        .map(|p| {
            std::fs::read(p)
                .map(|b| (p.as_str(), b))
                .map_err(|e| format!("--roots {p}: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let files: Vec<(&str, &[u8])> = files.iter().map(|(p, b)| (*p, b.as_slice())).collect();
    Roots::from_files(&files)
}

// ------------------------------------------------------------ one-shot CLI

#[derive(Clone, Copy)]
enum Command {
    Receipt,
    SignedData,
    Endpoint(u32),
}

/// Runs one operation in one fresh instance on stdin and writes the
/// module's JSON to stdout, byte for byte. Stdin is read only after `init`,
/// to the `max_input_bytes` its answer states: a longer input is cut to
/// that length, as the server cuts a body, so the module answers its own
/// size refusal; that answer is printed like any other and the exit status
/// is 3.
fn one_shot(cmd: Command, o: OneShotArgs) -> i32 {
    let roots = match roots_from(&o.roots) {
        Ok(r) => r,
        Err(e) => return usage(&e),
    };
    let runtime = match load(&o.component, o.time_limit_ms) {
        Ok(r) => r,
        Err(e) => return die(e),
    };
    // cli-fast-exit: the process ends right after the answer, so the runtime
    // is never dropped. Dropping it deregisters the compiled code's unwind
    // information one entry at a time, which costs about 55 ms under the
    // LLVM libunwind a static musl binary links; the kernel frees it all at
    // exit anyway (docs/evidence/2026-09-27-static-musl-server.md §3).
    let runtime = std::mem::ManuallyDrop::new(runtime);
    let (instance, max_input) = match ready(&runtime, &roots.config_json()) {
        Ok(ready) => ready,
        Err(code) => return code,
    };
    let (input, over) = match read_input(std::io::stdin().lock(), max_input) {
        Ok(read) => read,
        Err(e) => return die(format!("reading stdin: {e}")),
    };
    let now_ms = o.now_ms.unwrap_or_else(clock_ms);
    let op = match cmd {
        Command::Receipt => Op::VerifyReceipt { now_ms },
        Command::SignedData => Op::VerifySignedData { now_ms },
        Command::Endpoint(env) => Op::Endpoint { env, now_ms },
    };
    answer(
        instance,
        op,
        &input,
        over.then_some(max_input),
        &mut std::io::stdout().lock(),
    )
}

/// A fresh instance after `init`, and the `max_input_bytes` its answer
/// states; otherwise the exit status, with the reason on stderr: 2 for
/// roots `init` refused, 70 for a failure.
fn ready(runtime: &Runtime, config_json: &[u8]) -> Result<(Instance, usize), i32> {
    match runtime.ready_instance(config_json) {
        Ok(Ok(ready)) => Ok(ready),
        Ok(Err(answer)) => {
            eprintln!("aprv: the component refused the roots configuration: {answer}");
            Err(EXIT_USAGE)
        }
        Err(e) => Err(die(e)),
    }
}

/// The module's input: at most `max_input` bytes of `r` (the length the
/// module's `init` answer states), and whether it is over the module's cap,
/// which an input of that length or more is.
fn read_input(r: impl Read, max_input: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut input = Vec::new();
    r.take(max_input as u64).read_to_end(&mut input)?;
    let over = input.len() >= max_input;
    Ok((input, over))
}

/// Runs `op` on `input` in `instance`, a fresh one after `init`, writes the
/// module's answer to `out` and returns the exit status: 0, or 3 for an
/// input over the cap (`over` holds the length it was cut to).
fn answer(
    mut instance: Instance,
    op: Op,
    input: &[u8],
    over: Option<usize>,
    out: &mut impl Write,
) -> i32 {
    let json = match instance.call(op, input) {
        Ok(json) => json,
        Err(e) => return die(e),
    };
    std::mem::forget(instance);
    if out
        .write_all(json.as_bytes())
        .and_then(|_| out.flush())
        .is_err()
    {
        return die("writing stdout");
    }
    if let Some(max_input) = over {
        eprintln!(
            "aprv: input over the module's size cap; the module answered its first {max_input} bytes"
        );
        return EXIT_TOO_LARGE;
    }
    EXIT_OK
}

// ------------------------------------------------------------ info, precompile

/// What `aprv info` and `GET /v1/info` state. `max_input_bytes` is the
/// length the module's `init` answer stated.
fn build_info(runtime: &Runtime, max_input_bytes: usize) -> serde_json::Value {
    serde_json::json!({
        "abi": "aprv:verifier@0.1.0",
        "component_sha256": runtime.source.component_sha256,
        "component_source": runtime.source.description,
        "wasmtime": runtime::WASMTIME_VERSION,
        "engine_features": runtime::engine_features(),
        "wasm_features": runtime::wasm_features(&runtime::config()),
        "epoch_interruption": true,
        "limits": {
            "max_input_bytes": max_input_bytes,
            "max_guest_memory_bytes": runtime::MAX_GUEST_MEMORY,
            "max_core_instances_per_store": runtime::MAX_CORE_INSTANCES,
        },
        "arch": std::env::consts::ARCH,
        "os": std::env::consts::OS,
    })
}

fn info(component: ComponentArg) -> i32 {
    let t = Instant::now();
    // The input length is the module's: one instance with the built-in
    // roots says it.
    let ready = load(&component, None).and_then(|runtime| {
        let runtime = std::mem::ManuallyDrop::new(runtime);
        match runtime.ready_instance(&Roots::Defaults.config_json()) {
            Ok(Ok((instance, max))) => {
                std::mem::forget(instance);
                Ok((runtime, max))
            }
            Ok(Err(answer)) => Err(format!(
                "the component refused its built-in roots: {answer}"
            )),
            Err(e) => Err(format!("the component failed its init: {e}")),
        }
    });
    match ready {
        Ok((runtime, max_input_bytes)) => {
            // As the CLI: exit without the runtime's slow teardown.
            let mut v = build_info(&runtime, max_input_bytes);
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
fn precompile(component: &str, target: &str, out: &str) -> i32 {
    match runtime::precompile(component, target, out) {
        Ok(msg) => {
            println!("{msg}");
            EXIT_OK
        }
        Err(e) => die(e),
    }
}

#[cfg(not(feature = "compile"))]
fn precompile(_: &str, _: &str, _: &str) -> i32 {
    die("precompile needs the full build (feature `compile`)")
}

// ------------------------------------------------------------ serve

fn serve(o: ServeArgs) -> i32 {
    let t0 = Instant::now();
    let (listen, token, roots) = if o.managed {
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
        let roots = match roots_from(&o.roots) {
            Ok(r) => r,
            Err(e) => return usage(&e),
        };
        (listen, token, roots)
    };
    let runtime = match load(&o.component, o.time_limit_ms) {
        Ok(r) => r,
        Err(e) => return die(e),
    };
    let load_ms = t0.elapsed().as_secs_f64() * 1e3;
    let verifier = match Verifier::new(runtime, roots.config_json(), o.lifecycle == Lifecycle::Pool)
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("aprv: {e}");
            return EXIT_USAGE;
        }
    };
    let mut info = build_info(&verifier.runtime, verifier.max_input_bytes());
    let workers = o.workers.map_or_else(
        || {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        },
        NonZeroUsize::get,
    );
    info["roots"] = roots.info();
    info["lifecycle"] = verifier.lifecycle_name().into();
    info["workers"] = workers.into();
    info["time_limit_ms"] = o
        .time_limit_ms
        .map_or(runtime::DEFAULT_TIME_LIMIT_MS, NonZeroU64::get)
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
/// stdin's own buffer is read, so what follows the line stays for the
/// watcher thread.
fn read_line(r: &mut impl BufRead, max: usize) -> Result<Vec<u8>, String> {
    let mut line = Vec::new();
    r.take(max as u64 + 1)
        .read_until(b'\n', &mut line)
        .map_err(|e| format!("reading stdin: {e}"))?;
    if line.last() == Some(&b'\n') {
        line.pop();
    } else if line.len() > max {
        return Err(format!("a handshake line is longer than {max} bytes"));
    } else {
        return Err("stdin closed during the handshake".into());
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

#[cfg(test)]
mod cli_tests {
    use super::{Cli, Cmd, Lifecycle, EXIT_USAGE};
    use clap::{CommandFactory, Parser};

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("aprv").chain(args.iter().copied()))
    }

    /// The handshake lines: CRLF or LF, at most `max` bytes before the `\n`
    /// (a `\r` counts), what follows left unread; a longer line or EOF
    /// before the newline is refused.
    #[test]
    fn read_line_takes_one_line_of_at_most_max_bytes() {
        use super::read_line;
        let mut r = &b"abc\r\nde\nrest"[..];
        assert_eq!(read_line(&mut r, 4).unwrap(), b"abc");
        assert_eq!(read_line(&mut r, 4).unwrap(), b"de");
        assert_eq!(r, b"rest", "nothing past the line is consumed");
        assert_eq!(read_line(&mut &b"\n"[..], 3).unwrap(), b"");
        assert_eq!(
            read_line(&mut &b"abc\r\n"[..], 3).unwrap_err(),
            "a handshake line is longer than 3 bytes"
        );
        assert_eq!(read_line(&mut &b"abc\n"[..], 3).unwrap(), b"abc");
        assert_eq!(
            read_line(&mut &b"abcd\n"[..], 3).unwrap_err(),
            "a handshake line is longer than 3 bytes"
        );
        assert_eq!(
            read_line(&mut &b"abc"[..], 3).unwrap_err(),
            "stdin closed during the handshake"
        );
        assert_eq!(
            read_line(&mut &b""[..], 3).unwrap_err(),
            "stdin closed during the handshake"
        );
    }

    #[test]
    fn the_command_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn serve_defaults_to_the_pool_and_fresh_stays_selectable() {
        let lifecycle = |a: &[&str]| match parse(a).unwrap().command {
            Cmd::Serve(s) => s.lifecycle,
            _ => unreachable!(),
        };
        assert_eq!(
            lifecycle(&["serve"]),
            Lifecycle::Pool,
            "the default lifecycle is pool"
        );
        assert_eq!(
            lifecycle(&["serve", "--lifecycle", "pool"]),
            Lifecycle::Pool
        );
        assert_eq!(
            lifecycle(&["serve", "--lifecycle", "fresh"]),
            Lifecycle::Fresh
        );
        assert!(parse(&["serve", "--lifecycle", "other"]).is_err());
    }

    /// Every command and flag the hand-written parser took is taken where it
    /// was; a bad value, a flag on the wrong command, or `--managed` with a
    /// flag it replaces is a usage error, exit 2, as before.
    #[test]
    fn the_commands_and_flags_of_the_hand_written_parser() {
        for ok in [
            &[
                "serve",
                "--listen",
                "127.0.0.1:0",
                "--roots",
                "r",
                "--token-file",
                "t",
                "--lifecycle",
                "fresh",
                "--workers",
                "2",
                "--time-limit-ms",
                "5",
                "--component",
                "c.wasm",
            ][..],
            &[
                "serve",
                "--managed",
                "--workers",
                "1",
                "--lifecycle",
                "pool",
            ],
            &[
                "verify-receipt",
                "--now-ms",
                "18446744073709551615",
                "--roots",
                "r",
                "--time-limit-ms",
                "1",
                "--component",
                "c.wasm",
            ],
            &["verify-signed-data", "--now-ms", "0"],
            &["verify-receipt-endpoint", "production", "--now-ms", "1"],
            &["verify-receipt-endpoint", "sandbox"],
            &["info", "--component", "c.wasm"],
            &["info"],
            &[
                "precompile",
                "c.wasm",
                "--target",
                "x86_64-unknown-linux-musl",
                "-o",
                "out.ccwasm",
            ],
            // A repeated flag: the last one wins, as before.
            &["serve", "--workers", "1", "--workers", "2"],
        ] {
            assert!(parse(ok).is_ok(), "{ok:?}: {:?}", parse(ok).err());
        }
        for bad in [
            &[][..],
            &["nothing"],
            &["serve", "--managed", "--roots", "r"],
            &["serve", "--managed", "--listen", "127.0.0.1:1"],
            &["serve", "--managed", "--token-file", "t"],
            &["serve", "--workers", "0"],
            &["serve", "--time-limit-ms", "0"],
            &["serve", "--now-ms", "1"],
            &["verify-receipt", "--now-ms", "-1"],
            &["verify-receipt", "--now-ms", "18446744073709551616"],
            &["verify-receipt", "--listen", "127.0.0.1:1"],
            &["verify-receipt", "--roots"],
            &["verify-receipt-endpoint"],
            &["verify-receipt-endpoint", "staging"],
            &["info", "--roots", "r"],
            &["precompile", "c.wasm"],
        ] {
            let e = parse(bad).err().unwrap_or_else(|| panic!("{bad:?} parsed"));
            assert!(e.use_stderr(), "{bad:?}");
            assert_eq!(e.exit_code(), EXIT_USAGE, "{bad:?}");
        }
        // Help goes to stdout and is not an error.
        for help in [&["--help"][..], &["-h"], &["help"], &["serve", "--help"]] {
            let e = parse(help).err().unwrap();
            assert!(!e.use_stderr(), "{help:?}");
            assert_eq!(e.exit_code(), 0, "{help:?}");
        }
        let workers = match parse(&["serve", "--workers", "1", "--workers", "2"])
            .unwrap()
            .command
        {
            Cmd::Serve(s) => s.workers.map(|n| n.get()),
            _ => unreachable!(),
        };
        assert_eq!(workers, Some(2));
        // --roots is the one flag that adds up, in order.
        let roots = match parse(&["verify-receipt", "--roots", "a.cer", "--roots", "b.pem"])
            .unwrap()
            .command
        {
            Cmd::VerifyReceipt(a) => a.roots,
            _ => unreachable!(),
        };
        assert_eq!(roots, ["a.cer", "b.pem"]);
    }
}
