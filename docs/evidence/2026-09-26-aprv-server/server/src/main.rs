//! aprv: an HTTP-to-Wasm-ABI adapter hosting aprv.wasm through Wasmtime,
//! plus a one-shot CLI mode. Research spike (2026-09-26), not product code.
//!
//!   aprv serve [--listen ADDR] [--managed] [--lifecycle pool|fresh|fresh-pooling] [--workers N]
//!   aprv verify-receipt | verify-signed-data | verify-receipt-endpoint <production|sandbox>
//!   aprv precompile OUT.cwasm        (builds with the compiler only)
//!   aprv info
//!
//! Routes select the ABI operation and pass the body through unchanged.

mod abi;
#[cfg(feature = "server")]
mod server;

#[cfg(feature = "spike")]
use abi::Verifier;
use abi::MAX_BODY;
use std::io::{Read, Write};
#[cfg(feature = "spike")]
use std::sync::Arc;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        #[cfg(feature = "server")]
        Some("serve") => server::serve(&args[1..]),
        Some("verify-receipt") => one_shot(abi::OP_VERIFY_RECEIPT),
        Some("verify-signed-data") => one_shot(abi::OP_VERIFY_SIGNED_DATA),
        Some("verify-receipt-endpoint") => match args.get(1).map(String::as_str) {
            Some("production") => one_shot(abi::OP_ENDPOINT_PRODUCTION),
            Some("sandbox") => one_shot(abi::OP_ENDPOINT_SANDBOX),
            _ => usage(),
        },
        #[cfg(all(feature = "compile", feature = "embed"))]
        Some("precompile") => precompile(args.get(1)),
        Some("info") => info(),
        #[cfg(feature = "spike")]
        Some("bench") => bench(&args[1..]),
        _ => usage(),
    };
    std::process::exit(code);
}

pub(crate) fn usage() -> i32 {
    eprintln!("usage: aprv serve [--listen ADDR] [--managed] [--lifecycle pool|fresh] [--workers N]\n       aprv verify-receipt | verify-signed-data | verify-receipt-endpoint <production|sandbox>  (stdin -> stdout)\n       aprv precompile OUT.cwasm | aprv info");
    2
}

pub(crate) fn die(msg: impl std::fmt::Display) -> i32 {
    eprintln!("aprv: {msg}");
    70
}

pub(crate) fn load_runtime(pooling: bool) -> wasmtime::Result<(abi::Runtime, String, f64)> {
    let t = Instant::now();
    let engine = abi::engine(pooling)?;
    let loaded = abi::load(&engine)?;
    let runtime = abi::Runtime::new(engine, &loaded.module)?;
    Ok((runtime, loaded.source, t.elapsed().as_secs_f64() * 1e3))
}

// ---------------------------------------------------------------- one-shot CLI

/// Reads stdin (at most MAX_BODY bytes), runs one operation in one fresh
/// instance, writes the module's JSON to stdout. Exit 0 for any verification
/// result (verified or not), 3 for input too large, 70 for a trap, an ABI
/// error or a load failure.
fn one_shot(op: i32) -> i32 {
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().lock().take(MAX_BODY as u64 + 1).read_to_end(&mut input) {
        return die(format!("reading stdin: {e}"));
    }
    if input.len() > MAX_BODY {
        eprintln!("aprv: input larger than {MAX_BODY} bytes");
        return 3;
    }
    let (runtime, _, _) = match load_runtime(false) {
        Ok(r) => r,
        Err(e) => return die(format!("{e:#}")),
    };
    let out = match runtime.instantiate().and_then(|mut w| w.invoke(op, &input)) {
        Ok(out) => out,
        Err(e) => return die(e),
    };
    let mut stdout = std::io::stdout().lock();
    if stdout.write_all(&out).and_then(|_| stdout.flush()).is_err() {
        return 74;
    }
    0
}

#[cfg(all(feature = "compile", feature = "embed"))]
fn precompile(out: Option<&String>) -> i32 {
    let Some(out) = out else { return usage() };
    let engine = match abi::engine(false) {
        Ok(e) => e,
        Err(e) => return die(format!("{e:#}")),
    };
    let wasm = abi::embedded_wasm();
    if abi::sha256_hex(wasm) != abi::WASM_SHA256 {
        return die("embedded module is not the pinned canonical module");
    }
    match engine.precompile_module(wasm) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(out, &bytes) {
                return die(e);
            }
            println!("wrote {out}: {} bytes, sha256 {}", bytes.len(), abi::sha256_hex(&bytes));
            0
        }
        Err(e) => die(format!("{e:#}")),
    }
}

fn info() -> i32 {
    println!("compiler (cranelift): {}", cfg!(feature = "compile"));
    println!("embedded module: {}", cfg!(feature = "embed"));
    println!("pinned cwasm sha256: {}", option_env!("APRV_CWASM_SHA256").unwrap_or("-"));
    println!("canonical wasm sha256: {}", abi::WASM_SHA256);
    println!("arch: {} os: {}", std::env::consts::ARCH, std::env::consts::OS);
    println!("guest memory cap: {} bytes", abi::MAX_GUEST_MEMORY);
    match abi::config(false) {
        Ok(c) => println!("config: {c:?}"),
        Err(e) => println!("config: {e:#}"),
    }
    match load_runtime(false) {
        Ok((_, source, ms)) => println!("module: {source} ({ms:.1} ms)"),
        Err(e) => println!("module: load failed: {e:#}"),
    }
    0
}

// ----------------------------------------------------------- spike: bench

/// In-process timing of the lifecycle models without HTTP:
///   aprv bench <op> <input-file> <lifecycle pool|fresh|fresh-pooling> <threads> <calls-per-thread>
#[cfg(feature = "spike")]
fn bench(args: &[String]) -> i32 {
    if args.len() != 5 {
        return usage();
    }
    let op: i32 = args[0].parse().unwrap_or(0);
    let input = std::fs::read(&args[1]).expect("input file");
    let (pool, pooling) = match args[2].as_str() {
        "pool" => (true, false),
        "fresh" => (false, false),
        "fresh-pooling" => (false, true),
        _ => return usage(),
    };
    let threads: usize = args[3].parse().unwrap_or(1);
    let n: usize = args[4].parse().unwrap_or(100);
    let (runtime, source, load_ms) = load_runtime(pooling).expect("load");
    let v = Arc::new(Verifier::new(runtime, pool, threads).expect("verifier"));
    let check = |out: &[u8]| {
        let s = std::str::from_utf8(out).unwrap_or("");
        assert!(s.contains("\"verified\":true") || s.contains("\"status\":0"), "not verified: {}", &s[..s.len().min(200)]);
    };
    for _ in 0..(n / 5).max(5) {
        check(&v.invoke(op, &input).expect("warm"));
    }
    let t = Instant::now();
    let hs: Vec<_> = (0..threads)
        .map(|_| {
            let (v, input) = (v.clone(), input.clone());
            std::thread::spawn(move || {
                let mut lat = Vec::with_capacity(n);
                for _ in 0..n {
                    let t = Instant::now();
                    check(&v.invoke(op, &input).expect("invoke"));
                    lat.push(t.elapsed().as_secs_f64() * 1e6);
                }
                lat
            })
        })
        .collect();
    let mut lat: Vec<f64> = hs.into_iter().flat_map(|h| h.join().unwrap()).collect();
    let secs = t.elapsed().as_secs_f64();
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |p: f64| lat[((lat.len() as f64 * p) as usize).min(lat.len() - 1)];
    println!(
        "{{\"op\":{op},\"lifecycle\":\"{}\",\"threads\":{threads},\"calls\":{},\"per_s\":{:.1},\"p50_us\":{:.0},\"p99_us\":{:.0},\"load_ms\":{load_ms:.1},\"source\":\"{source}\"}}",
        args[2],
        lat.len(),
        lat.len() as f64 / secs,
        pct(0.5),
        pct(0.99)
    );
    0
}
