//! Spike only (2026-09-29, round 13). The canonical-ABI component on Rust
//! Wasmtime 49 with `wasmtime::component::bindgen!` (typed, generated
//! bindings), and the ABI v1 core module the way aprv-server hosts it
//! today, for comparison. See Cargo.toml for the three builds.
//!
//!   aprv-wt calls   PATH CALLS.jsonl     PATH: component .wasm (compile) or precompiled .ccwasm; rows on stdout
//!   aprv-wt tests   PATH CASES.jsonl     the checks reachable through typed bindings
//!   aprv-wt precompile COMPONENT.wasm V1.wasm OUTDIR    (compile) -> aprv-cabi.ccwasm, aprv-abi1.cwasm, aprv-abi1.no-cm.cwasm
//!   aprv-wt startup cabi|v1 PATH|- CASES.jsonl          one start-up to the first g5 ("-": the embedded file)
//!   aprv-wt info                                        the build's features
#[cfg(feature = "component")]
use std::io::{BufRead, Write};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use wasmtime::{Config, Engine, Result};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// The one Config every build uses (as aprv-server), so that files
/// precompiled by the full build load in the runtime-only builds.
fn engine() -> Result<Engine> {
    Engine::new(&Config::new())
}

#[cfg(feature = "component")]
mod cabi {
    use super::*;
    use wasmtime::component::{Component, HasSelf, Linker};
    use wasmtime::Store;

    // --- component host (hand-written) begin ---
    wasmtime::component::bindgen!({ path: "wit", world: "aprv" });

    pub struct Host;
    impl aprv::verifier::host::Host for Host {
        fn random_get(&mut self, len: u32) -> Vec<u8> {
            let mut b = vec![0u8; len as usize - crate::test_trim()]; // test hook
            getrandom::fill(&mut b).expect("getrandom");
            b
        }
    }

    pub fn linker(engine: &Engine) -> Result<Linker<Host>> {
        let mut l = Linker::new(engine);
        Aprv::add_to_linker::<Host, HasSelf<Host>>(&mut l, |h| h)?;
        Ok(l)
    }

    pub struct Guest {
        pub store: Store<Host>,
        pub aprv: Aprv,
    }

    impl Guest {
        pub fn new(pre: &AprvPre<Host>) -> Result<Guest> {
            let mut store = Store::new(pre.engine(), Host);
            let aprv = pre.instantiate(&mut store)?;
            Ok(Guest { store, aprv })
        }
    }
    // --- component host (hand-written) end ---

    impl Guest {
        pub fn init(&mut self, config: &[u8]) -> Result<String> {
            self.aprv.aprv_verifier_verify().call_init(&mut self.store, config)
        }
        pub fn verify_receipt(&mut self, now: u64, b: &[u8]) -> Result<String> {
            self.aprv.aprv_verifier_verify().call_verify_receipt(&mut self.store, now, b)
        }
        pub fn verify_signed_data(&mut self, now: u64, b: &[u8]) -> Result<String> {
            self.aprv.aprv_verifier_verify().call_verify_signed_data(&mut self.store, now, b)
        }
        pub fn endpoint(&mut self, env: u32, now: u64, b: &[u8]) -> Result<String> {
            self.aprv.aprv_verifier_verify().call_verify_receipt_endpoint(&mut self.store, env, now, b)
        }
    }

    /// A component from a .wasm (needs the compiler) or a precompiled file.
    pub fn load(engine: &Engine, path: &str) -> Result<Component> {
        if path == "-" {
            #[cfg(feature = "embed")]
            // SAFETY: bytes this spike's own full build produced with `precompile`, embedded at build time.
            return unsafe { Component::deserialize(engine, include_bytes!(env!("APRV_CCWASM"))) };
            #[cfg(not(feature = "embed"))]
            wasmtime::bail!("this build embeds no component");
        }
        let bytes = std::fs::read(path)?;
        if bytes.starts_with(b"\0asm") {
            #[cfg(feature = "compile")]
            return Component::new(engine, &bytes);
            #[cfg(not(feature = "compile"))]
            wasmtime::bail!("this build has no compiler: it loads only a precompiled component");
        }
        // SAFETY: a file this spike's own full build wrote with `precompile` (spike only; aprv-server pins a hash).
        unsafe { Component::deserialize(engine, &bytes) }
    }

    pub fn pre(engine: &Engine, path: &str) -> Result<AprvPre<Host>> {
        let component = load(engine, path)?;
        AprvPre::new(linker(engine)?.instantiate_pre(&component)?)
    }
}

#[cfg(feature = "component")]
thread_local!(static TRIM: std::cell::Cell<usize> = const { std::cell::Cell::new(0) });
#[cfg(feature = "component")]
fn test_trim() -> usize {
    TRIM.with(|t| t.get())
}

/// ABI v1's core module, the way aprv-server hosts it (lifecycle as its abi.rs).
mod v1 {
    use super::*;
    use wasmtime::{Instance, Linker, Module, Store};

    pub fn load(engine: &Engine, path: &str) -> Result<Module> {
        if path == "-" {
            #[cfg(feature = "embed")]
            // SAFETY: as aprv-server: bytes embedded at build time.
            return unsafe { Module::deserialize(engine, include_bytes!(env!("APRV_CWASM"))) };
            #[cfg(not(feature = "embed"))]
            wasmtime::bail!("this build embeds no module");
        }
        let bytes = std::fs::read(path)?;
        if bytes.starts_with(b"\0asm") {
            #[cfg(feature = "compile")]
            return Module::new(engine, &bytes);
            #[cfg(not(feature = "compile"))]
            wasmtime::bail!("this build has no compiler: it loads only a precompiled module");
        }
        // SAFETY: a file this spike's own full build wrote with `precompile`.
        unsafe { Module::deserialize(engine, &bytes) }
    }

    pub fn instance(engine: &Engine, module: &Module) -> Result<(Store<()>, Instance)> {
        let mut linker = Linker::new(engine);
        linker.func_wrap("aprv", "clock_now_ms", || now_ms() as f64)?;
        linker.func_wrap("aprv", "random_get", |mut c: wasmtime::Caller<'_, ()>, p: u32, n: u32| -> i32 {
            let mem = c.get_export("memory").and_then(|e| e.into_memory()).unwrap();
            let buf = &mut mem.data_mut(&mut c)[p as usize..(p + n) as usize];
            getrandom::fill(buf).map(|_| 0).unwrap_or(1)
        })?;
        let mut store = Store::new(engine, ());
        let inst = linker.instantiate(&mut store, module)?;
        inst.get_typed_func::<(), ()>(&mut store, "_initialize")?.call(&mut store, ())?;
        Ok((store, inst))
    }

    pub fn call(store: &mut Store<()>, inst: &Instance, op: u32, input: &[u8]) -> Result<String> {
        let f1 = |s: &mut Store<()>, n: &str| inst.get_typed_func::<u32, u32>(&mut *s, n);
        let mem = inst.get_memory(&mut *store, "memory").unwrap();
        let p = f1(store, "aprv_alloc")?.call(&mut *store, input.len() as u32)?;
        mem.write(&mut *store, p as usize, input)?;
        let h = inst.get_typed_func::<(u32, u32, u32, u32), u32>(&mut *store, "aprv_call")?.call(&mut *store, (1, op, p, input.len() as u32))?;
        let rp = f1(store, "aprv_result_ptr")?.call(&mut *store, h)?;
        let rn = f1(store, "aprv_result_len")?.call(&mut *store, h)?;
        let out = mem.data(&*store)[rp as usize..(rp + rn) as usize].to_vec();
        inst.get_typed_func::<u32, ()>(&mut *store, "aprv_result_free")?.call(&mut *store, h)?;
        inst.get_typed_func::<(u32, u32), ()>(&mut *store, "aprv_dealloc")?.call(&mut *store, (p, input.len() as u32))?;
        Ok(String::from_utf8(out)?)
    }
}

fn b64(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).expect("base64")
}

fn row(path: &str, id: &str) -> serde_json::Value {
    let text = std::fs::read_to_string(path).unwrap();
    let line = text.lines().find(|l| l.contains(&format!("\"{id}\""))).unwrap();
    serde_json::from_str(line).unwrap()
}

#[cfg(feature = "component")]
fn calls(path: &str, calls: &str) -> Result<()> {
    use std::collections::HashMap;
    let engine = engine()?;
    let pre = cabi::pre(&engine, path)?;
    let mut inst: HashMap<String, cabi::Guest> = HashMap::new();
    let (mut rows, mut traps) = (0, 0);
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for line in std::io::BufReader::new(std::fs::File::open(calls)?).lines() {
        let r: serde_json::Value = serde_json::from_str(&line?)?;
        rows += 1;
        let id = &r["id"];
        if let Some(m) = r.get("map") {
            writeln!(out, "{}", serde_json::json!({"id": id, "map": m}))?;
            continue;
        }
        let config = r["config"].as_str().unwrap().to_string();
        let mut answer = None;
        if !inst.contains_key(&config) {
            let mut g = cabi::Guest::new(&pre)?;
            let ok = g.init(config.as_bytes())?;
            if ok == r#"{"ok":true}"# {
                inst.insert(config.clone(), g);
            } else {
                answer = Some(ok); // init refused the config: that is the row's answer
            }
        }
        let o = match answer {
            Some(a) => serde_json::json!({"id": id, "out": a}),
            None => {
                let g = inst.get_mut(&config).unwrap();
                let now = r["now"].as_i64().map(|n| n as u64).unwrap_or_else(now_ms);
                let input = b64(r["b64"].as_str().unwrap());
                let res = match r["fn"].as_str().unwrap() {
                    "verify-receipt" => g.verify_receipt(now, &input),
                    "verify-signed-data" => g.verify_signed_data(now, &input),
                    _ => g.endpoint(r["env"].as_u64().unwrap() as u32, now, &input),
                };
                match res {
                    Ok(s) => serde_json::json!({"id": id, "out": s}),
                    Err(e) => {
                        traps += 1;
                        inst.remove(&config); // a trap discards the instance
                        serde_json::json!({"id": id, "trap": e.to_string()})
                    }
                }
            }
        };
        writeln!(out, "{o}")?;
    }
    eprintln!("{}", serde_json::json!({"host": "wasmtime 49.0.1 (component, bindgen!)", "rows": rows, "traps": traps}));
    Ok(())
}

#[cfg(feature = "component")]
fn tests(path: &str, cases: &str) -> Result<i32> {
    let engine = engine()?;
    let pre = cabi::pre(&engine, path)?;
    let g5 = b64(row(cases, "receipt/verify-genuine-sandbox-g5-against-apple-roots")["b64"].as_str().unwrap());
    let jr = row(cases, "transaction/verify-shared-sandbox");
    let (jws, jcfg) = (b64(jr["b64"].as_str().unwrap()), jr["config"].as_str().unwrap().as_bytes().to_vec());
    let req = [br#"{"receipt-data":""#.as_slice(), &g5, br#""}"#].concat();
    let mut failed = 0;
    let mut check = |name: &str, ok: bool, detail: String| {
        failed += !ok as i32;
        println!("{} {name}: {}", if ok { "PASS" } else { "FAIL" }, detail.chars().take(160).collect::<String>());
    };
    let show = |r: Result<String>| match r {
        Ok(s) => s,
        Err(e) => format!("TRAP {}", e.to_string().lines().next().unwrap_or("")),
    };
    let fresh = |c: &[u8]| -> cabi::Guest {
        let mut g = cabi::Guest::new(&pre).unwrap();
        assert_eq!(g.init(c).unwrap(), r#"{"ok":true}"#);
        g
    };
    let mut g = cabi::Guest::new(&pre)?;
    let s = show(g.verify_receipt(now_ms(), &g5));
    check("verify before init traps", s.starts_with("TRAP"), s);
    let s = show(g.verify_receipt(now_ms(), &g5));
    check("  ... and the trapped instance refuses further calls", s.starts_with("TRAP"), s);
    let mut g = fresh(b"");
    let s = show(g.verify_receipt(now_ms(), &g5));
    check("verify-receipt(genuine g5) verifies", s.contains(r#""verified":true"#), s);
    let s = show(g.init(b""));
    check("a second init traps", s.starts_with("TRAP"), s);
    let mut g = cabi::Guest::new(&pre)?;
    let s = show(g.init(b"{not json"));
    let s2 = show(g.init(b""));
    check("a config that is not JSON is {\"ok\":false}, and init can be retried", s.contains(r#""ok":false"#) && s2 == r#"{"ok":true}"#, s);
    let mut gj = fresh(&jcfg);
    let s = show(gj.verify_signed_data(now_ms(), &jws));
    check("verify-signed-data(shared-sandbox JWS, its test roots) verifies", s.contains(r#""verified":true"#), s);
    let mut g = fresh(b"");
    let s = show(g.endpoint(1, now_ms(), &req));
    check("verify-receipt-endpoint(env 1 = sandbox, g5) answers status 0", s.contains(r#""status":0"#), s.chars().rev().take(30).collect::<String>().chars().rev().collect());
    let s = show(g.verify_signed_data(now_ms(), b"ey\xff\xfe.x"));
    check("a JWS that is not UTF-8 reaches the guest and is a value (ABI v1's answer)", s.contains("jws is not valid UTF-8"), s);
    for env in [2u32, 255, u32::MAX] {
        let mut g = fresh(b"");
        let s = show(g.endpoint(env, now_ms(), &req));
        let after = show(g.verify_receipt(now_ms(), &g5));
        check(&format!("endpoint with env {env} traps"), s.starts_with("TRAP"), format!("{s}; instance afterwards: {}", after.chars().take(60).collect::<String>()));
    }
    TRIM.with(|t| t.set(1));
    let mut gr = fresh(&jcfg);
    let s = show(gr.verify_signed_data(now_ms(), &jws));
    TRIM.with(|t| t.set(0));
    check("random-get answering the wrong length traps", s.starts_with("TRAP"), s);
    let (mut a, mut b) = (fresh(b""), fresh(b""));
    let _ = a.endpoint(2, now_ms(), &req);
    let s = show(b.verify_receipt(now_ms(), &g5));
    check("isolation: a trap (env 2) in one instance leaves another verifying", s.contains(r#""verified":true"#), String::new());
    println!("NOT REACHABLE with typed bindings: a wrong argument type or count (compile error), pointers and lengths, post-return (the runtime runs it)");
    println!("summary: {failed} failed");
    Ok(failed)
}

#[cfg(feature = "compile")]
fn precompile(component: &str, v1: &str, outdir: &str) -> Result<()> {
    // A precompiled file records the engine's wasm features, and a runtime
    // refuses a file whose features differ from its own. With the
    // component-model feature compiled in, Config::new() turns the
    // component_model wasm feature on, so the ABI v1 module is written twice:
    // for runtimes with component-model, and (as aprv-server's `precompile`
    // does today) for runtimes without it.
    let engine = engine()?;
    let mut no_cm = Config::new();
    no_cm.wasm_component_model(false);
    let engine_no_cm = Engine::new(&no_cm)?;
    for (src, out, e, is_component) in [
        (component, "aprv-cabi.ccwasm", &engine, true),
        (v1, "aprv-abi1.cwasm", &engine, false),
        (v1, "aprv-abi1.no-cm.cwasm", &engine_no_cm, false),
    ] {
        let bytes = std::fs::read(src)?;
        let t = Instant::now();
        let c = if is_component { e.precompile_component(&bytes)? } else { e.precompile_module(&bytes)? };
        std::fs::write(format!("{outdir}/{out}"), &c)?;
        println!("{out}: {} bytes from {} bytes of wasm, precompiled in {:.0} ms", c.len(), bytes.len(), t.elapsed().as_secs_f64() * 1000.0);
    }
    Ok(())
}

fn startup(which: &str, path: &str, cases: &str) -> Result<()> {
    let t0 = Instant::now();
    let g5 = b64(row(cases, "receipt/verify-genuine-sandbox-g5-against-apple-roots")["b64"].as_str().unwrap());
    let t1 = Instant::now();
    let engine = engine()?;
    let (first, second, t2, t3, t4, t5);
    if which == "v1" {
        let module = v1::load(&engine, path)?;
        t2 = Instant::now();
        let (mut store, inst) = v1::instance(&engine, &module)?;
        t3 = Instant::now();
        first = v1::call(&mut store, &inst, 1, &g5)?;
        t4 = Instant::now();
        second = v1::call(&mut store, &inst, 1, &g5)?;
    } else {
        #[cfg(feature = "component")]
        {
            let pre = cabi::pre(&engine, path)?;
            t2 = Instant::now();
            let mut g = cabi::Guest::new(&pre)?;
            g.init(b"")?;
            t3 = Instant::now();
            first = g.verify_receipt(now_ms(), &g5)?;
            t4 = Instant::now();
            second = g.verify_receipt(now_ms(), &g5)?;
        }
        #[cfg(not(feature = "component"))]
        wasmtime::bail!("this build has no component-model");
    }
    t5 = Instant::now();
    assert!(first.contains(r#""verified":true"#) && second.contains(r#""verified":true"#), "{first}");
    let ms = |a: Instant, b: Instant| (b - a).as_secs_f64() * 1000.0;
    println!(
        "{}",
        serde_json::json!({"module": if which == "v1" { "ABI v1 core .cwasm" } else { "canonical-ABI component .ccwasm" },
            "engine_and_load_ms": (ms(t1, t2) * 100.0).round() / 100.0, "instantiate_and_init_ms": (ms(t2, t3) * 100.0).round() / 100.0,
            "first_g5_ms": (ms(t3, t4) * 100.0).round() / 100.0, "second_g5_ms": (ms(t4, t5) * 100.0).round() / 100.0,
            "in_process_to_first_result_ms": (ms(t0, t4) - ms(t0, t1)).round()})
    );
    Ok(())
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let arg = |i: usize| a.get(i).map(String::as_str).unwrap_or("");
    match arg(1) {
        #[cfg(feature = "component")]
        "calls" => calls(arg(2), arg(3))?,
        #[cfg(feature = "component")]
        "tests" => std::process::exit(tests(arg(2), arg(3))?),
        #[cfg(feature = "compile")]
        "precompile" => precompile(arg(2), arg(3), arg(4))?,
        "startup" => startup(arg(2), arg(3), arg(4))?,
        "info" => println!(
            "features: compile={} component={} embed={}",
            cfg!(feature = "compile"),
            cfg!(feature = "component"),
            cfg!(feature = "embed")
        ),
        _ => {
            eprintln!("usage: aprv-wt calls|tests PATH FILE.jsonl | precompile COMPONENT V1 OUTDIR | startup cabi|v1 PATH|- CASES | info");
            std::process::exit(2);
        }
    }
    Ok(())
}
