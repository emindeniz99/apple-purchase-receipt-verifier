//! The Wasm ABI v1 bridge: engine, module loading, and the one internal
//! `invoke(operation, bytes) -> bytes`. Spike only (2026-09-26).
//!
//! Nothing here reads the input or the output: no base64, CMS, JWS,
//! certificate or policy code. The bytes go in, the module's JSON comes out.
#![cfg_attr(not(any(feature = "server", feature = "spike")), allow(dead_code))]

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use wasmtime::{
    bail, ensure, Caller, Config, Engine, InstancePre, Linker, Memory, Module, Result, Store,
    StoreLimits, StoreLimitsBuilder, TypedFunc,
};

/// Linear memory one instance may grow to. The module's own input caps (3 MiB)
/// keep real use far below this; a runaway guest traps instead of eating RAM.
pub const MAX_GUEST_MEMORY: usize = 256 << 20;

pub const ABI_VERSION: i32 = 1;
/// Apple's verifyReceipt body limit (fixtures/cases.json, "Resource bounds"):
/// 3,145,728 bytes is answered, one byte more is HTTP 413.
pub const MAX_BODY: usize = 3_145_728;
/// SHA-256 of the canonical module this spike hosts ($SCRATCH/abi/READY).
pub const WASM_SHA256: &str = "b14e14b2c3b8a38953c6ac03d941e42647321fdb86cfb0e3629c006687b636b3";

pub const OP_VERIFY_RECEIPT: i32 = 1;
pub const OP_VERIFY_SIGNED_DATA: i32 = 2;
pub const OP_ENDPOINT_PRODUCTION: i32 = 3;
pub const OP_ENDPOINT_SANDBOX: i32 = 4;

#[cfg(all(feature = "embed", feature = "compile"))]
static EMBEDDED: &[u8] = include_bytes!(env!("APRV_WASM"));
#[cfg(all(feature = "embed", not(feature = "compile")))]
static EMBEDDED: &[u8] = include_bytes!(env!("APRV_CWASM"));

/// The one Config every build uses, so that a module precompiled by the
/// full build deserializes in the runtime-only build (Wasmtime refuses a
/// module compiled under different settings).
pub fn engine(pooling: bool) -> Result<Engine> {
    Engine::new(&config(pooling)?)
}

pub fn config(pooling: bool) -> Result<Config> {
    let mut config = Config::new();
    // Spike only: APRV_TARGET=pulley64 selects Wasmtime's Pulley interpreter
    // (the backend Wasmtime uses where Cranelift has no native backend), both
    // to precompile and to load, so its speed can be measured on this host.
    if let Ok(t) = std::env::var("APRV_TARGET") {
        config.target(&t)?;
    }
    if pooling {
        #[cfg(feature = "pooling")]
        {
            let mut p = wasmtime::PoolingAllocationConfig::default();
            p.total_memories(64).total_tables(64).total_core_instances(64);
            config.allocation_strategy(wasmtime::InstanceAllocationStrategy::Pooling(p));
        }
        #[cfg(not(feature = "pooling"))]
        bail!("this build has no pooling allocator");
    }
    Ok(config)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Where the module came from, for logs and `aprv info`.
pub struct Loaded {
    pub module: Module,
    pub source: String,
}

/// Loads the module. Precompiled code is native code: it is deserialized only
/// when it is embedded in this binary at build time, or when a side file's
/// SHA-256 equals the hash pinned into this binary at build time
/// (APRV_CWASM_SHA256). Anything else is refused before Wasmtime sees it.
pub fn load(engine: &Engine) -> Result<Loaded> {
    if let Some(path) = std::env::var_os("APRV_MODULE_FILE") {
        let bytes = std::fs::read(&path)?;
        let got = sha256_hex(&bytes);
        if bytes.starts_with(b"\0asm") {
            #[cfg(feature = "compile")]
            {
                ensure!(got == WASM_SHA256, "module file sha256 {got} is not the pinned {WASM_SHA256}");
                return Ok(Loaded { module: Module::new(engine, &bytes)?, source: format!("file .wasm, compiled at start, sha256 {got}") });
            }
            #[cfg(not(feature = "compile"))]
            bail!("this build has no compiler: it loads only a precompiled module");
        }
        let Some(pin) = option_env!("APRV_CWASM_SHA256") else {
            bail!("no precompiled module hash was pinned into this build; refusing to load native code from a file");
        };
        ensure!(got == pin, "precompiled module sha256 {got} is not the pinned {pin}; refusing to load it");
        // SAFETY: the bytes are exactly the file our own build produced
        // (checked against the hash pinned at build time just above).
        let module = unsafe { Module::deserialize(engine, &bytes)? };
        return Ok(Loaded { module, source: format!("file .cwasm, deserialized, sha256 {got}") });
    }
    #[cfg(all(feature = "embed", feature = "compile"))]
    return Ok(Loaded { module: Module::new(engine, EMBEDDED)?, source: "embedded .wasm, compiled at start".into() });
    #[cfg(all(feature = "embed", not(feature = "compile")))]
    {
        // SAFETY: bytes our own build produced with `aprv precompile` and
        // embedded with include_bytes!; they are part of this signed binary.
        let module = unsafe { Module::deserialize(engine, EMBEDDED)? };
        return Ok(Loaded { module, source: "embedded .cwasm, deserialized".into() });
    }
    #[allow(unreachable_code)]
    {
        bail!("no module: this build embeds none; set APRV_MODULE_FILE")
    }
}

#[cfg(all(feature = "embed", feature = "compile"))]
pub fn embedded_wasm() -> &'static [u8] {
    EMBEDDED
}

/// A failure that is not a verification result.
#[derive(Debug)]
pub enum InvokeError {
    /// The module broke the ABI contract (bad pointer or length, version).
    Abi(String),
    /// A Wasm trap. The instance is discarded.
    Trap(String),
}

impl std::fmt::Display for InvokeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvokeError::Abi(m) => write!(f, "ABI error: {m}"),
            InvokeError::Trap(m) => write!(f, "Wasm trap: {m}"),
        }
    }
}

fn trap(e: wasmtime::Error) -> InvokeError {
    InvokeError::Trap(format!("{e:#}"))
}

/// A compiled module with its two host imports linked.
pub struct Runtime {
    engine: Engine,
    pre: InstancePre<StoreLimits>,
}

impl Runtime {
    pub fn new(engine: Engine, module: &Module) -> Result<Self> {
        for imp in module.imports() {
            ensure!(
                imp.module() == "aprv" && matches!(imp.name(), "clock_now_ms" | "random_get"),
                "unexpected import {}.{}",
                imp.module(),
                imp.name()
            );
        }
        let mut linker: Linker<StoreLimits> = Linker::new(&engine);
        // Wall clock, milliseconds since the Unix epoch (as JS Date.now()).
        linker.func_wrap("aprv", "clock_now_ms", || -> f64 {
            match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(d) => d.as_millis() as f64,
                Err(_) => -1.0, // before 1970: the guest fails closed
            }
        })?;
        // OS CSPRNG into guest memory; an out-of-bounds range traps.
        linker.func_wrap("aprv", "random_get", |mut caller: Caller<'_, StoreLimits>, ptr: i32, len: i32| -> Result<i32> {
            let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory()) else {
                bail!("aprv.random_get: no memory export");
            };
            let data = mem.data_mut(&mut caller);
            let (p, l) = (ptr as u32 as usize, len as u32 as usize);
            let Some(end) = p.checked_add(l).filter(|e| *e <= data.len()) else {
                bail!("aprv.random_get out of bounds");
            };
            Ok(match getrandom::fill(&mut data[p..end]) {
                Ok(()) => 0,
                Err(_) => 1, // non-zero: the guest fails closed
            })
        })?;
        let pre = linker.instantiate_pre(module)?;
        Ok(Runtime { engine, pre })
    }

    /// A fresh Store + Instance, initialised and version-checked.
    pub fn instantiate(&self) -> Result<Worker, InvokeError> {
        let limits = StoreLimitsBuilder::new().memory_size(MAX_GUEST_MEMORY).instances(1).trap_on_grow_failure(true).build();
        let mut store = Store::new(&self.engine, limits);
        store.limiter(|l| l);
        let inst = self.pre.instantiate(&mut store).map_err(trap)?;
        let f = |e: wasmtime::Error| InvokeError::Abi(format!("{e:#}"));
        let init: TypedFunc<(), ()> = inst.get_typed_func(&mut store, "_initialize").map_err(f)?;
        let version: TypedFunc<(), i32> = inst.get_typed_func(&mut store, "aprv_abi_version").map_err(f)?;
        let memory = inst.get_memory(&mut store, "memory").ok_or_else(|| InvokeError::Abi("no memory export".into()))?;
        init.call(&mut store, ()).map_err(trap)?;
        let v = version.call(&mut store, ()).map_err(trap)?;
        if v != ABI_VERSION {
            return Err(InvokeError::Abi(format!("APRV Wasm ABI mismatch: module={v}, caller={ABI_VERSION}")));
        }
        Ok(Worker {
            memory,
            call: inst.get_typed_func(&mut store, "aprv_call").map_err(f)?,
            alloc: inst.get_typed_func(&mut store, "aprv_alloc").map_err(f)?,
            dealloc: inst.get_typed_func(&mut store, "aprv_dealloc").map_err(f)?,
            rptr: inst.get_typed_func(&mut store, "aprv_result_ptr").map_err(f)?,
            rlen: inst.get_typed_func(&mut store, "aprv_result_len").map_err(f)?,
            rfree: inst.get_typed_func(&mut store, "aprv_result_free").map_err(f)?,
            store,
        })
    }
}

/// One Store/Instance pair. Never shared between threads at the same time.
pub struct Worker {
    store: Store<StoreLimits>,
    memory: Memory,
    call: TypedFunc<(i32, i32, i32, i32), i32>,
    alloc: TypedFunc<i32, i32>,
    dealloc: TypedFunc<(i32, i32), ()>,
    rptr: TypedFunc<i32, i32>,
    rlen: TypedFunc<i32, i32>,
    rfree: TypedFunc<i32, ()>,
}

impl Worker {
    /// alloc -> copy input -> aprv_call -> bounds-check -> COPY result out ->
    /// aprv_result_free -> dealloc input. No guest pointer leaves this call.
    /// Any error means the caller must drop this Worker.
    pub fn invoke(&mut self, op: i32, input: &[u8]) -> Result<Vec<u8>, InvokeError> {
        let len = i32::try_from(input.len()).map_err(|_| InvokeError::Abi("input too long for the ABI".into()))?;
        let ptr = self.alloc.call(&mut self.store, len).map_err(trap)?;
        if ptr == 0 {
            return Err(InvokeError::Abi(format!("aprv_alloc({len}) failed")));
        }
        let p = ptr as u32 as usize;
        let mem = self.memory.data_mut(&mut self.store);
        let Some(end) = p.checked_add(input.len()).filter(|e| *e <= mem.len()) else {
            return Err(InvokeError::Abi("aprv_alloc returned an out-of-bounds range".into()));
        };
        mem[p..end].copy_from_slice(input);
        let h = self.call.call(&mut self.store, (ABI_VERSION, op, ptr, len)).map_err(trap)?;
        let rp = self.rptr.call(&mut self.store, h).map_err(trap)? as u32 as usize;
        let rl = self.rlen.call(&mut self.store, h).map_err(trap)? as u32 as usize;
        let data = self.memory.data(&self.store);
        let Some(rend) = rp.checked_add(rl).filter(|e| *e <= data.len()) else {
            return Err(InvokeError::Abi("result out of bounds".into()));
        };
        let out = data[rp..rend].to_vec();
        self.rfree.call(&mut self.store, h).map_err(trap)?;
        self.dealloc.call(&mut self.store, (ptr, len)).map_err(trap)?;
        Ok(out)
    }
}

/// The two lifecycle models the brief asks to compare.
pub enum Lifecycle {
    /// A: a pool of Store/Instance pairs, one request at a time each; a
    /// trap (or any invoke error) destroys the pair instead of returning it.
    Pool(Mutex<Vec<Worker>>),
    /// B: a fresh Store + Instance per request from one compiled Module.
    Fresh,
}

pub struct Verifier {
    pub runtime: Runtime,
    pub lifecycle: Lifecycle,
}

impl Verifier {
    pub fn new(runtime: Runtime, pool: bool, prewarm: usize) -> Result<Self> {
        let lifecycle = if pool {
            let mut v = Vec::with_capacity(prewarm);
            for _ in 0..prewarm {
                v.push(runtime.instantiate().map_err(|e| wasmtime::format_err!("{e}"))?);
            }
            Lifecycle::Pool(Mutex::new(v))
        } else {
            // One instantiation up front proves the module links and reports
            // ABI version 1 before the server says it is ready.
            runtime.instantiate().map_err(|e| wasmtime::format_err!("{e}"))?;
            Lifecycle::Fresh
        };
        Ok(Verifier { runtime, lifecycle })
    }

    /// The server's single internal entry point.
    pub fn invoke(&self, op: i32, input: &[u8]) -> Result<Vec<u8>, InvokeError> {
        match &self.lifecycle {
            Lifecycle::Fresh => self.runtime.instantiate()?.invoke(op, input),
            Lifecycle::Pool(pool) => {
                let taken = pool.lock().unwrap_or_else(|p| p.into_inner()).pop();
                let mut w = match taken {
                    Some(w) => w,
                    None => self.runtime.instantiate()?,
                };
                let out = w.invoke(op, input)?; // on error `w` is dropped here
                pool.lock().unwrap_or_else(|p| p.into_inner()).push(w);
                Ok(out)
            }
        }
    }
}
