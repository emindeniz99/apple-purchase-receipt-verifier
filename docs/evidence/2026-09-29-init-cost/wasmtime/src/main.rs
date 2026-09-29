//! Evidence only (2026-09-29). What `init` costs against one call, on
//! Wasmtime 49 (the ABI tests' two hosts: the core module called by hand,
//! and the component through Wasmtime's component runtime, the way
//! aprv-server binds it).
//!
//!   APRV_WASM=... APRV_COMPONENT=... init-cost-wasmtime <fixtures-dir> [runs] [calls]
//!
//! For each host and each input (the sandbox G5 receipt under Apple's
//! roots, the generated transaction JWS under its fixture root), `runs`
//! runs (default 7) of `calls` iterations (default 20) each, after one
//! warm-up run; every iteration times, in microseconds:
//!   - fresh: instantiate, `init`, one verify call, as a new instance per
//!     request does;
//!   - pool: one verify call on an instance that has had `init`.
//! One JSON line per host, input and run with each phase's mean; run.sh
//! takes the median of the runs.

use aprv_abi_tests::{artifacts, ComponentGuest, CoreGuest, Guest, Randomness};
use std::time::Instant;

const NOW_MS: u64 = 1_790_640_000_000; // 2026-09-29T00:00:00Z

fn b64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            out.push(if i <= chunk.len() { char::from(A[((n >> shift) & 0x3f) as usize]) } else { '=' });
        }
    }
    out
}

struct Input {
    name: &'static str,
    config: Vec<u8>,
    jws: bool,
    bytes: Vec<u8>,
}

fn call(g: &mut dyn Guest, input: &Input) -> String {
    let out = if input.jws {
        g.verify_signed_data(NOW_MS, &input.bytes)
    } else {
        g.verify_receipt(NOW_MS, &input.bytes)
    }
    .expect("no trap");
    assert!(out.starts_with(r#"{"verified":true"#), "{}: {out}", input.name);
    out
}

fn new_guest(host: &str) -> Box<dyn Guest> {
    match host {
        "core" => Box::new(CoreGuest::new(Randomness::default()).expect("instantiate")),
        _ => Box::new(ComponentGuest::new(Randomness::default()).expect("instantiate")),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let fixtures = std::path::PathBuf::from(args.get(1).expect("usage: init-cost-wasmtime <fixtures-dir> [runs] [calls]"));
    let runs: usize = args.get(2).map_or(7, |s| s.parse().expect("runs"));
    let calls: usize = args.get(3).map_or(20, |s| s.parse().expect("calls"));
    let read = |p: &str| std::fs::read(fixtures.join(p)).unwrap_or_else(|e| panic!("{p}: {e}"));
    let g5: String = String::from_utf8(read("public-receipts/receipt-sandbox-g5.b64"))
        .unwrap()
        .split_whitespace()
        .collect();
    let inputs = [
        Input { name: "g5", config: br#"{"roots":[]}"#.to_vec(), jws: false, bytes: g5.into_bytes() },
        Input {
            name: "jws",
            config: format!(r#"{{"roots":["{}"]}}"#, b64(&read("generated/jws-root.der"))).into_bytes(),
            jws: true,
            bytes: String::from_utf8(read("generated/transaction.jws")).unwrap().trim().as_bytes().to_vec(),
        },
    ];
    let t = Instant::now();
    artifacts();
    eprintln!("compile (module and component): {} ms", t.elapsed().as_millis());
    for host in ["core", "component"] {
        for input in &inputs {
            let mut pooled = new_guest(host);
            assert_eq!(pooled.init(&input.config).expect("init"), r#"{"ok":true}"#);
            for run in 0..=runs {
                let (mut inst, mut init, mut first, mut pool) = (0f64, 0f64, 0f64, 0f64);
                for _ in 0..calls {
                    let a = Instant::now();
                    let mut g = new_guest(host);
                    let b = Instant::now();
                    assert_eq!(g.init(&input.config).expect("init"), r#"{"ok":true}"#);
                    let c = Instant::now();
                    call(g.as_mut(), input);
                    let d = Instant::now();
                    call(pooled.as_mut(), input);
                    let e = Instant::now();
                    inst += (b - a).as_secs_f64();
                    init += (c - b).as_secs_f64();
                    first += (d - c).as_secs_f64();
                    pool += (e - d).as_secs_f64();
                }
                if run == 0 {
                    continue; // warm-up
                }
                let us = |s: f64| s * 1e6 / calls as f64;
                println!(
                    "{{\"host\":\"wasmtime-{host}\",\"input\":\"{}\",\"run\":{run},\"calls\":{calls},\"instantiate_us\":{:.1},\"init_us\":{:.1},\"fresh_call_us\":{:.1},\"pool_call_us\":{:.1}}}",
                    input.name,
                    us(inst),
                    us(init),
                    us(first),
                    us(pool)
                );
            }
        }
    }
}
