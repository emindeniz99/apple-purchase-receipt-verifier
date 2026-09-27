//! Spike only (2026-09-27, round 9): a native host for aprv.wasm (ABI v1)
//! over one engine per build: Wasmi 1.1.0 (`v1`), Wasmi 2.0.0 (`v2-*`) or
//! Wasmtime 49.0.1 (`wt`). The same binary interface as ../wamr-host/host.c:
//!
//!   aprv-rt-host serve MODULE --mode M          line protocol on stdin/stdout (py/driver.py)
//!   aprv-rt-host first MODULE G5 --mode M       one cold process to its first verified g5 (JSON)
//!   aprv-rt-host bench MODULE G5 JWS --mode M   warm-up curve and steady state (JSON lines)
//!
//! --mode: Wasmi eager | lazy-translation | lazy (Config::compilation_mode);
//!         Wasmtime cranelift | winch | pulley.
//!
//! The host provides exactly the module's two imports, aprv.clock_now_ms and
//! aprv.random_get, and runs the ABI v1 call lifecycle: aprv_alloc, copy in,
//! aprv_call, aprv_result_ptr/len, copy out, aprv_result_free, aprv_dealloc.
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(feature = "v1")]
use wasmi_v1 as w;
#[cfg(feature = "v2")]
use wasmi_v2 as w;
#[cfg(feature = "wt")]
use wasmtime as w;

#[cfg(not(any(feature = "v1", feature = "v2", feature = "wt")))]
compile_error!("pick one engine feature: v1, v2-*, or wt");

#[cfg(feature = "wt")]
type WErr = wasmtime::Error;
#[cfg(not(feature = "wt"))]
type WErr = w::Error;

static CLOCK_CALLS: AtomicU64 = AtomicU64::new(0);
static RANDOM_CALLS: AtomicU64 = AtomicU64::new(0);

fn engine_label() -> &'static str {
    #[cfg(feature = "v1")]
    return "wasmi 1.1.0";
    #[cfg(feature = "v2")]
    return if cfg!(feature = "v2-auto") {
        "wasmi 2.0.0 v2-auto"
    } else if cfg!(feature = "v2-tail-indirect") {
        "wasmi 2.0.0 v2-tail-indirect"
    } else if cfg!(feature = "v2-tail") {
        "wasmi 2.0.0 v2-tail"
    } else if cfg!(feature = "v2-loop-indirect") {
        "wasmi 2.0.0 v2-loop-indirect"
    } else if cfg!(feature = "v2-loop") {
        "wasmi 2.0.0 v2-loop"
    } else if cfg!(feature = "v2-unstable") {
        "wasmi 2.0.0 v2-unstable"
    } else {
        "wasmi 2.0.0"
    };
    #[cfg(feature = "wt")]
    return "wasmtime 49.0.1";
}

fn err_msg(msg: &str) -> WErr {
    #[cfg(feature = "wt")]
    return wasmtime::Error::msg(msg.to_string());
    #[cfg(not(feature = "wt"))]
    return w::Error::new(msg.to_string());
}

fn describe(e: &WErr) -> String {
    #[cfg(feature = "wt")]
    {
        let code = e.downcast_ref::<wasmtime::Trap>().map(|t| format!(" (trap {t:?})")).unwrap_or_default();
        format!("{e}{code}")
    }
    #[cfg(not(feature = "wt"))]
    {
        let code = e.as_trap_code().map(|t| format!(" (trap {t:?})")).unwrap_or_default();
        format!("{e}{code}")
    }
}

fn config(mode: &str) -> Result<w::Config, String> {
    #[allow(unused_mut)]
    let mut c = w::Config::default();
    #[cfg(not(feature = "wt"))]
    {
        let m = match mode {
            "eager" => w::CompilationMode::Eager,
            "lazy-translation" => w::CompilationMode::LazyTranslation,
            "lazy" => w::CompilationMode::Lazy,
            _ => return Err(format!("unknown Wasmi mode {mode}")),
        };
        c.compilation_mode(m);
    }
    #[cfg(feature = "wt")]
    match mode {
        "cranelift" => {
            c.strategy(wasmtime::Strategy::Cranelift);
        }
        "winch" => {
            c.strategy(wasmtime::Strategy::Winch);
        }
        "pulley" => {
            c.target("pulley64").map_err(|e| e.to_string())?;
        }
        _ => return Err(format!("unknown Wasmtime mode {mode}")),
    }
    Ok(c)
}

struct Runtime {
    engine: w::Engine,
    module: w::Module,
    linker: w::Linker<()>,
}

fn clock_now_ms() -> f64 {
    CLOCK_CALLS.fetch_add(1, Relaxed);
    let ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    ms as f64
}

fn random_get(mut caller: w::Caller<'_, ()>, ptr: i32, len: i32) -> Result<i32, WErr> {
    RANDOM_CALLS.fetch_add(1, Relaxed);
    let mem = match caller.get_export("memory") {
        Some(w::Extern::Memory(m)) => m,
        _ => return Err(err_msg("aprv.random_get: no memory export")),
    };
    let size = mem.data_size(&caller) as i64;
    if ptr < 0 || len < 0 || ptr as i64 + len as i64 > size {
        return Err(err_msg("aprv.random_get out of bounds"));
    }
    if len > 0 {
        let data = mem.data_mut(&mut caller);
        getrandom::fill(&mut data[ptr as usize..ptr as usize + len as usize]).map_err(|_| err_msg("getrandom failed"))?;
    }
    Ok(0)
}

impl Runtime {
    fn engine(mode: &str) -> Result<w::Engine, String> {
        let c = config(mode)?;
        #[cfg(feature = "wt")]
        return w::Engine::new(&c).map_err(|e| e.to_string());
        #[cfg(not(feature = "wt"))]
        return Ok(w::Engine::new(&c));
    }

    fn load(engine: w::Engine, wasm: &[u8]) -> Result<Runtime, String> {
        let module = w::Module::new(&engine, wasm).map_err(|e| describe(&e))?;
        for imp in module.imports() {
            if !(imp.module() == "aprv" && (imp.name() == "clock_now_ms" || imp.name() == "random_get")) {
                return Err(format!("unexpected import {}.{}", imp.module(), imp.name()));
            }
        }
        let mut linker = w::Linker::<()>::new(&engine);
        linker.func_wrap("aprv", "clock_now_ms", clock_now_ms).map_err(|e| e.to_string())?;
        linker.func_wrap("aprv", "random_get", random_get).map_err(|e| e.to_string())?;
        Ok(Runtime { engine, module, linker })
    }
}

struct Inst {
    store: w::Store<()>,
    instance: w::Instance,
    memory: w::Memory,
    alloc: w::TypedFunc<i32, i32>,
    dealloc: w::TypedFunc<(i32, i32), ()>,
    call: w::TypedFunc<(i32, i32, i32, i32), i32>,
    rptr: w::TypedFunc<i32, i32>,
    rlen: w::TypedFunc<i32, i32>,
    rfree: w::TypedFunc<i32, ()>,
}

enum Fail {
    Trap(String),
    Error(String),
}

impl Inst {
    fn new(rt: &Runtime) -> Result<Inst, String> {
        let mut store = w::Store::new(&rt.engine, ());
        #[cfg(feature = "wt")]
        let instance = rt.linker.instantiate(&mut store, &rt.module).map_err(|e| describe(&e))?;
        #[cfg(not(feature = "wt"))]
        let instance = rt.linker.instantiate_and_start(&mut store, &rt.module).map_err(|e| describe(&e))?;
        let memory = instance.get_memory(&mut store, "memory").ok_or("no memory export")?;
        macro_rules! f {
            ($name:expr) => {
                instance.get_typed_func(&mut store, $name).map_err(|e| format!("{}: {}", $name, e))?
            };
        }
        let init: w::TypedFunc<(), ()> = f!("_initialize");
        let version: w::TypedFunc<(), i32> = f!("aprv_abi_version");
        let inst = Inst {
            alloc: f!("aprv_alloc"),
            dealloc: f!("aprv_dealloc"),
            call: f!("aprv_call"),
            rptr: f!("aprv_result_ptr"),
            rlen: f!("aprv_result_len"),
            rfree: f!("aprv_result_free"),
            memory,
            instance,
            store,
        };
        let mut inst = inst;
        init.call(&mut inst.store, ()).map_err(|e| describe(&e))?;
        let v = version.call(&mut inst.store, ()).map_err(|e| describe(&e))?;
        if v != 1 {
            return Err(format!("APRV Wasm ABI mismatch: module={v}, caller=1"));
        }
        Ok(inst)
    }

    fn mem_len(&self) -> usize {
        self.memory.data_size(&self.store)
    }

    /// The full ABI v1 call lifecycle; the result is a host-owned copy.
    fn invoke(&mut self, abi: i32, op: i32, data: &[u8]) -> Result<Vec<u8>, Fail> {
        let t = |e: WErr| Fail::Trap(describe(&e));
        let n = data.len() as i32;
        let p = self.alloc.call(&mut self.store, n).map_err(t)?;
        if p == 0 {
            return Err(Fail::Error(format!("aprv_alloc({n}) failed")));
        }
        if n > 0 {
            self.memory.write(&mut self.store, p as u32 as usize, data).map_err(|e| Fail::Trap(e.to_string()))?;
        }
        let h = self.call.call(&mut self.store, (abi, op, p, n)).map_err(t)?;
        let rp = self.rptr.call(&mut self.store, h).map_err(t)? as u32 as usize;
        let rn = self.rlen.call(&mut self.store, h).map_err(t)? as u32 as usize;
        if rp + rn > self.mem_len() {
            return Err(Fail::Trap("result out of bounds".into()));
        }
        let out = self.memory.data(&self.store)[rp..rp + rn].to_vec();
        self.rfree.call(&mut self.store, h).map_err(t)?;
        self.dealloc.call(&mut self.store, (p, n)).map_err(t)?;
        Ok(out)
    }

    /// Calls any export with i32 arguments (the ABI tests' raw calls).
    fn raw(&mut self, name: &str, args: &[i32]) -> Result<Vec<i32>, Fail> {
        let f = self.instance.get_func(&mut self.store, name).ok_or_else(|| Fail::Error(format!("no export {name}")))?;
        let nres = f.ty(&self.store).results().len();
        let params: Vec<w::Val> = args.iter().map(|a| w::Val::I32(*a)).collect();
        let mut results = vec![w::Val::I32(0); nres];
        f.call(&mut self.store, &params, &mut results).map_err(|e| Fail::Trap(describe(&e)))?;
        Ok(results.iter().map(|v| match v {
            w::Val::I32(x) => *x,
            _ => 0,
        }).collect())
    }
}

fn ms(t: Instant) -> f64 {
    (t.elapsed().as_secs_f64() * 1e6).round() / 1e3
}

fn proc_status(key: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with(key)).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()))
        .unwrap_or(0)
}

/// CLOCK_MONOTONIC in ns: the parent (py/startup.py) reads the same clock
/// before it spawns this process, so the difference is spawn-to-first-result.
fn mono_ns() -> i64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as i64 * 1_000_000_000 + ts.tv_nsec as i64
}

fn verified(out: &[u8]) -> bool {
    out.windows(15).any(|w| w == b"\"verified\":true")
}

fn arg_mode(args: &[String]) -> String {
    args.iter().position(|a| a == "--mode").and_then(|i| args.get(i + 1)).cloned().unwrap_or_default()
}

fn die(msg: String) -> ! {
    eprintln!("aprv-rt-host: {msg}");
    std::process::exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = arg_mode(&args);
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let t0 = Instant::now();
    let engine = Runtime::engine(&mode).unwrap_or_else(|e| die(e));
    let init_ms = ms(t0);
    let t1 = Instant::now();
    let wasm = std::fs::read(&args[2]).unwrap_or_else(|e| die(format!("{}: {e}", args[2])));
    let rt = Runtime::load(engine, &wasm).unwrap_or_else(|e| die(e));
    let load_ms = ms(t1);
    match cmd {
        "serve" => serve(&rt),
        "first" => {
            let g5 = std::fs::read(&args[3]).unwrap_or_else(|e| die(e.to_string()));
            let t2 = Instant::now();
            let mut i = Inst::new(&rt).unwrap_or_else(|e| die(e));
            let instantiate_ms = ms(t2);
            let t3 = Instant::now();
            let out = i.invoke(1, 1, &g5).unwrap_or_else(|_| die("first call failed".into()));
            let first_call_ms = ms(t3);
            let first_ns = mono_ns();
            let t4 = Instant::now();
            let out2 = i.invoke(1, 1, &g5).unwrap_or_else(|_| die("second call failed".into()));
            let second_call_ms = ms(t4);
            println!(
                "{{\"engine\":\"{}\",\"mode\":\"{mode}\",\"init_ms\":{init_ms},\"load_ms\":{load_ms},\"instantiate_ms\":{instantiate_ms},\"first_call_ms\":{first_call_ms},\"second_call_ms\":{second_call_ms},\"verified\":{},\"first_result_mono_ns\":{first_ns},\"rss_kb\":{},\"hwm_kb\":{}}}",
                engine_label(),
                verified(&out) && verified(&out2),
                proc_status("VmRSS:"),
                proc_status("VmHWM:")
            );
            std::process::exit(0);
        }
        "bench" => {
            let g5 = std::fs::read(&args[3]).unwrap_or_else(|e| die(e.to_string()));
            let jws = std::fs::read(&args[4]).unwrap_or_else(|e| die(e.to_string()));
            let t2 = Instant::now();
            let mut i = Inst::new(&rt).unwrap_or_else(|e| die(e));
            let instantiate_ms = ms(t2);
            println!(
                "{{\"phase\":\"setup\",\"engine\":\"{}\",\"mode\":\"{mode}\",\"init_ms\":{init_ms},\"load_ms\":{load_ms},\"instantiate_ms\":{instantiate_ms},\"rss_kb\":{}}}",
                engine_label(),
                proc_status("VmRSS:")
            );
            for (name, op, input) in [("g5", 1, &g5), ("jws", 258, &jws)] {
                bench_op(&mut i, name, op, input);
            }
            println!("{{\"phase\":\"end\",\"rss_kb\":{},\"hwm_kb\":{}}}", proc_status("VmRSS:"), proc_status("VmHWM:"));
        }
        _ => die("usage: aprv-rt-host serve|first|bench MODULE [G5 [JWS]] --mode M".into()),
    }
}

/// Calls #1..#100 timed one by one, then a steady-state loop of at least
/// 20 calls and 2 seconds.
fn bench_op(i: &mut Inst, name: &str, op: i32, input: &[u8]) {
    let mut marks = Vec::new();
    let mut bad = 0;
    for n in 1..=100 {
        let t = Instant::now();
        let out = i.invoke(1, op, input).unwrap_or_else(|_| die(format!("{name} call {n} failed")));
        let us = t.elapsed().as_micros();
        if !verified(&out) {
            bad += 1;
        }
        if [1, 2, 5, 10, 100].contains(&n) {
            marks.push(format!("\"{n}\":{us}"));
        }
    }
    let t = Instant::now();
    let mut calls = 0u64;
    while calls < 20 || t.elapsed().as_secs_f64() < 2.0 {
        let out = i.invoke(1, op, input).unwrap_or_else(|_| die(format!("{name} steady call failed")));
        if !verified(&out) {
            bad += 1;
        }
        calls += 1;
    }
    let secs = t.elapsed().as_secs_f64();
    println!(
        "{{\"op\":\"{name}\",\"calls_us\":{{{}}},\"steady_calls\":{calls},\"steady_s\":{:.3},\"per_s\":{:.1},\"mean_us\":{:.0},\"not_verified\":{bad}}}",
        marks.join(","),
        secs,
        calls as f64 / secs,
        secs * 1e6 / calls as f64
    );
}

// ---- the line protocol (py/driver.py) ----

fn read_exact<const N: usize>(r: &mut impl Read) -> Option<[u8; N]> {
    let mut b = [0u8; N];
    r.read_exact(&mut b).ok().map(|_| b)
}

fn read_u32(r: &mut impl Read) -> Option<u32> {
    read_exact::<4>(r).map(u32::from_le_bytes)
}

fn reply(out: &mut impl Write, status: u8, payload: &[u8]) {
    out.write_all(&[status]).unwrap();
    out.write_all(&(payload.len() as u32).to_le_bytes()).unwrap();
    out.write_all(payload).unwrap();
    out.flush().unwrap();
}

fn serve(rt: &Runtime) {
    let stdin = std::io::stdin();
    let mut r = std::io::BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut o = std::io::BufWriter::new(stdout.lock());
    let mut insts: std::collections::HashMap<u32, Inst> = Default::default();
    let mut next = 1u32;
    while let Some([cmd]) = read_exact::<1>(&mut r) {
        match cmd {
            b'n' => match Inst::new(rt) {
                Ok(i) => {
                    insts.insert(next, i);
                    reply(&mut o, 0, &next.to_le_bytes());
                    next += 1;
                }
                Err(e) => reply(&mut o, 2, e.as_bytes()),
            },
            b'd' => {
                let id = read_u32(&mut r).unwrap();
                insts.remove(&id);
                reply(&mut o, 0, b"");
            }
            b'r' => {
                let id = read_u32(&mut r).unwrap();
                let [nl] = read_exact::<1>(&mut r).unwrap();
                let mut name = vec![0u8; nl as usize];
                r.read_exact(&mut name).unwrap();
                let [na] = read_exact::<1>(&mut r).unwrap();
                let a: Vec<i32> = (0..na).map(|_| read_u32(&mut r).unwrap() as i32).collect();
                let i = insts.get_mut(&id).unwrap();
                match i.raw(std::str::from_utf8(&name).unwrap(), &a) {
                    Ok(v) => {
                        let mut p = vec![v.len() as u8];
                        v.iter().for_each(|x| p.extend_from_slice(&x.to_le_bytes()));
                        reply(&mut o, 0, &p)
                    }
                    Err(Fail::Trap(m)) => reply(&mut o, 1, m.as_bytes()),
                    Err(Fail::Error(m)) => reply(&mut o, 2, m.as_bytes()),
                }
            }
            b'i' => {
                let id = read_u32(&mut r).unwrap();
                let abi = read_u32(&mut r).unwrap() as i32;
                let op = read_u32(&mut r).unwrap() as i32;
                let n = read_u32(&mut r).unwrap() as usize;
                let mut data = vec![0u8; n];
                r.read_exact(&mut data).unwrap();
                let i = insts.get_mut(&id).unwrap();
                match i.invoke(abi, op, &data) {
                    Ok(v) => reply(&mut o, 0, &v),
                    Err(Fail::Trap(m)) => reply(&mut o, 1, m.as_bytes()),
                    Err(Fail::Error(m)) => reply(&mut o, 2, m.as_bytes()),
                }
            }
            b'm' => {
                let id = read_u32(&mut r).unwrap();
                reply(&mut o, 0, &(insts[&id].mem_len() as u32).to_le_bytes());
            }
            b'c' => {
                let mut p = CLOCK_CALLS.load(Relaxed).to_le_bytes().to_vec();
                p.extend_from_slice(&RANDOM_CALLS.load(Relaxed).to_le_bytes());
                reply(&mut o, 0, &p);
            }
            b'e' => reply(&mut o, 0, format!("{} {}", engine_label(), arg_mode(&std::env::args().collect::<Vec<_>>())).as_bytes()),
            b'q' => break,
            _ => {
                reply(&mut o, 2, b"unknown command");
                break;
            }
        }
    }
}
