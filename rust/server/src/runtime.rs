//! The Wasmtime side: the engine, loading the component, the generated
//! bindings, per-store limits, the guest time limit and the two instance
//! lifecycles.
//!
//! Nothing here reads a receipt, a JWS or a request body: the bytes go to
//! the component unchanged and its JSON comes back unchanged.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Config, Engine, Precompiled, Store, StoreLimits, StoreLimitsBuilder, Trap};

include!(concat!(env!("OUT_DIR"), "/build_info.rs"));

wasmtime::component::bindgen!({
    path: "wit",
    world: "aprv",
    imports: { default: trappable },
});

/// The precompiled component embedded at build time (`APRV_CCWASM`).
pub struct Embedded {
    pub bytes: &'static [u8],
    pub ccwasm_sha256: &'static str,
    pub component_sha256: &'static str,
    pub target: &'static str,
    pub wasm_features: &'static [&'static str],
}

/// Linear memory one store may hold. Over the whole corpus the module peaked
/// at about 23 MiB; a runaway guest traps instead of taking the host's RAM.
pub const MAX_GUEST_MEMORY: usize = 256 << 20;
/// Core module instances one store may create. One component instance of
/// aprv.wasm needs three (wit-component's shim, the module, the fixup), so
/// this admits exactly one component instance per store.
pub const MAX_CORE_INSTANCES: usize = 3;
/// The largest `random-get` a guest may ask for. OpenSSL asks for tens of
/// bytes; a larger request traps instead of making the host allocate it.
pub const MAX_RANDOM_GET: u32 = 1 << 16;
/// The epoch ticker's period: the guest time limit's granularity.
pub const EPOCH_TICK: Duration = Duration::from_millis(10);
/// The default guest time limit per call (`--time-limit-ms`).
pub const DEFAULT_TIME_LIMIT_MS: u64 = 10_000;

/// The one engine configuration every build uses, the precompile step
/// included: a precompiled file records the settings of the engine that
/// wrote it, and Wasmtime refuses to load it under other settings.
pub fn config() -> Config {
    let mut c = Config::new();
    // The guest time limit: compiled code checks the epoch, so this setting
    // is part of what a precompiled file records.
    c.epoch_interruption(true);
    c
}

/// The Wasm features a configuration enables, sorted (from its `Debug`
/// rendering, which lists every flag).
pub fn wasm_features(c: &Config) -> Vec<String> {
    let dbg = format!("{c:?}");
    let mut v: Vec<String> = dbg
        .split([',', '{'])
        .filter_map(|f| {
            f.trim()
                .strip_prefix("wasm_")?
                .strip_suffix(": true")
                .map(str::to_owned)
        })
        .collect();
    v.sort();
    v
}

/// Cargo features of Wasmtime compiled into this binary.
pub fn engine_features() -> &'static str {
    if cfg!(feature = "compile") {
        "runtime, std, component-model, cranelift"
    } else {
        "runtime, std, component-model"
    }
}

/// The host side of the one import: OS randomness, exactly `len` bytes.
pub struct HostState {
    limits: StoreLimits,
}

impl aprv::verifier::host::Host for HostState {
    fn random_get(&mut self, len: u32) -> wasmtime::Result<Vec<u8>> {
        if len > MAX_RANDOM_GET {
            wasmtime::bail!("random-get asked for {len} bytes, more than {MAX_RANDOM_GET}");
        }
        let mut b = vec![0u8; len as usize];
        getrandom::fill(&mut b).map_err(|e| wasmtime::format_err!("random-get: {e}"))?;
        Ok(b)
    }
}

/// Where the component came from, for `info`, logs and `GET /v1/info`.
#[derive(Clone, Debug)]
pub struct Source {
    pub component_sha256: String,
    pub description: String,
}

/// The engine, the component linked against the host, and the limits.
pub struct Runtime {
    engine: Engine,
    pre: AprvPre<HostState>,
    pub source: Source,
    time_limit_ticks: u64,
    ticker_stop: Arc<AtomicBool>,
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.ticker_stop.store(true, Ordering::Relaxed);
    }
}

/// How a component is chosen at start.
pub enum Load<'a> {
    /// The `.ccwasm` embedded at build time.
    Embedded,
    /// A component `.wasm`, compiled at start (a `compile` build only).
    File(&'a str),
}

impl Runtime {
    pub fn new(load: Load<'_>, time_limit_ms: u64) -> Result<Runtime, String> {
        let engine = Engine::new(&config()).map_err(|e| format!("engine: {e:#}"))?;
        let (component, source) = match load {
            Load::Embedded => load_embedded(&engine)?,
            Load::File(path) => load_file(&engine, path)?,
        };
        let mut linker = Linker::new(&engine);
        Aprv::add_to_linker::<HostState, HasSelf<HostState>>(&mut linker, |h| h)
            .map_err(|e| format!("linker: {e:#}"))?;
        let pre = linker
            .instantiate_pre(&component)
            .and_then(AprvPre::new)
            .map_err(|e| {
                format!(
                    "the component does not match the aprv:verifier@1.0.0 interface this server \
                     binds (wit/aprv.wit): {e:#}"
                )
            })?;
        let ticks = time_limit_ms.div_ceil(EPOCH_TICK.as_millis() as u64).max(1);
        let ticker_stop = Arc::new(AtomicBool::new(false));
        {
            let (engine, stop) = (engine.clone(), ticker_stop.clone());
            std::thread::Builder::new()
                .name("aprv-epoch".into())
                .spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        std::thread::sleep(EPOCH_TICK);
                        engine.increment_epoch();
                    }
                })
                .map_err(|e| format!("epoch ticker: {e}"))?;
        }
        Ok(Runtime {
            engine,
            pre,
            source,
            time_limit_ticks: ticks,
            ticker_stop,
        })
    }

    /// A fresh store and component instance, not yet initialised.
    pub fn instantiate(&self) -> Result<Instance, InvokeError> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(MAX_GUEST_MEMORY)
            .instances(MAX_CORE_INSTANCES)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(&self.engine, HostState { limits });
        store.limiter(|h| &mut h.limits);
        store.epoch_deadline_trap();
        store.set_epoch_deadline(self.time_limit_ticks);
        // A trap while instantiating is a trap; any other failure here (a
        // store limit, say) is the host's, not the component's.
        let bindings = self.pre.instantiate(&mut store).map_err(|e| {
            match classify(e, self.time_limit_ticks) {
                InvokeError::Abi(m) => {
                    InvokeError::Internal(format!("instantiating the component: {m}"))
                }
                other => other,
            }
        })?;
        Ok(Instance {
            store,
            bindings,
            ticks: self.time_limit_ticks,
        })
    }

    /// A fresh instance with `init` done. `Ok(Err(message))` is `init`'s
    /// `{"ok":false,...}` answer: the configuration was refused.
    pub fn ready_instance(
        &self,
        config_json: &[u8],
    ) -> Result<Result<Instance, String>, InvokeError> {
        let mut i = self.instantiate()?;
        let answer = i.call(Op::Init, config_json)?;
        if answer == r#"{"ok":true}"# {
            Ok(Ok(i))
        } else {
            Ok(Err(answer))
        }
    }
}

fn load_embedded(engine: &Engine) -> Result<(Component, Source), String> {
    let Some(e) = EMBEDDED else {
        return Err(if cfg!(feature = "compile") {
            "this build embeds no component (build with APRV_CCWASM set), so pass --component FILE.wasm".into()
        } else {
            "this build embeds no component: build it with APRV_CCWASM naming a file `aprv precompile` wrote".into()
        });
    };
    // The bytes are not hashed again here: build.rs checked them against
    // their manifest before embedding them, and hashing 9.5 MB at every
    // start cost about 50 ms without SHA extensions, a third of a CLI call.
    if Engine::detect_precompiled(e.bytes) != Some(Precompiled::Component) {
        return Err("the embedded file is not a precompiled Wasmtime component".into());
    }
    let ours = wasm_features(&config());
    if e.wasm_features != ours.as_slice() {
        return Err(format!(
            "the embedded component was precompiled with Wasm features {:?}, but this engine has {:?}: \
             run `aprv precompile` from a build with this binary's Wasmtime features",
            e.wasm_features, ours
        ));
    }
    // SAFETY: `deserialize` runs the bytes as native code without validating
    // them. These bytes are part of this binary: build.rs embedded them only
    // after checking that they hash to what the manifest `aprv precompile`
    // wrote records, and they are a precompiled component (checked above).
    let component = unsafe { Component::deserialize(engine, e.bytes) }.map_err(|err| {
        format!(
            "the embedded precompiled component does not load in this engine (it must be precompiled \
             by a build with the same Wasmtime version, features and settings): {err:#}"
        )
    })?;
    Ok((
        component,
        Source {
            component_sha256: e.component_sha256.into(),
            description: format!(
                "embedded .ccwasm for {}, sha256 {}",
                e.target, e.ccwasm_sha256
            ),
        },
    ))
}

#[cfg(feature = "compile")]
fn load_file(engine: &Engine, path: &str) -> Result<(Component, Source), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    if !bytes.starts_with(b"\0asm") {
        return Err(format!(
            "{path}: not a .wasm component; precompiled files are only ever embedded"
        ));
    }
    let component = Component::new(engine, &bytes).map_err(|e| format!("{path}: {e:#}"))?;
    let sha = crate::manifest::sha256_hex(&bytes);
    Ok((
        component,
        Source {
            description: format!("file {path}, compiled at start"),
            component_sha256: sha,
        },
    ))
}

#[cfg(not(feature = "compile"))]
fn load_file(_: &Engine, _: &str) -> Result<(Component, Source), String> {
    Err(
        "--component needs the full build (feature `compile`); this runtime-only build \
         runs only its embedded precompiled component"
            .into(),
    )
}

/// `aprv precompile`: compile a component for an explicit target (its ISA
/// baseline, no host CPU features) with this build's engine settings, and
/// write the `.ccwasm` and its manifest.
#[cfg(feature = "compile")]
pub fn precompile(component: &str, target: &str, out: &str) -> Result<String, String> {
    use crate::manifest::{sha256_hex, Manifest};
    let bytes = std::fs::read(component).map_err(|e| format!("{component}: {e}"))?;
    if !bytes.starts_with(b"\0asm") {
        return Err(format!("{component}: not a .wasm"));
    }
    let mut c = config();
    c.target(target)
        .map_err(|e| format!("--target {target}: {e:#}"))?;
    let features = wasm_features(&c);
    let engine = Engine::new(&c).map_err(|e| format!("engine for {target}: {e:#}"))?;
    let code = engine
        .precompile_component(&bytes)
        .map_err(|e| format!("{component}: {e:#}"))?;
    std::fs::write(out, &code).map_err(|e| format!("{out}: {e}"))?;
    let m = Manifest {
        component_sha256: sha256_hex(&bytes),
        ccwasm_sha256: sha256_hex(&code),
        target: target.into(),
        wasmtime: WASMTIME_VERSION.into(),
        wasm_features: features,
    };
    let mpath = format!("{out}.json");
    std::fs::write(&mpath, m.to_json()).map_err(|e| format!("{mpath}: {e}"))?;
    Ok(format!(
        "wrote {out}: {} bytes, sha256 {}, for {target}, from component sha256 {}; manifest {mpath}",
        code.len(),
        m.ccwasm_sha256,
        m.component_sha256
    ))
}

/// One of the four WIT operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Init,
    VerifyReceipt {
        now_ms: u64,
    },
    VerifySignedData {
        now_ms: u64,
    },
    /// `env`: 0 production, 1 sandbox (the only two values a route or
    /// command can produce).
    Endpoint {
        env: u32,
        now_ms: u64,
    },
}

/// A failure that is not a verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvokeError {
    /// A Wasm trap, the guest time limit or a refused memory grow included.
    /// The instance is discarded.
    Trap(String),
    /// The component broke the interface (a result that does not lift, a
    /// refused `init` of a configuration accepted at start). Discarded.
    Abi(String),
    /// Anything else: an instance that could not be created.
    Internal(String),
}

impl std::fmt::Display for InvokeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvokeError::Trap(m) => write!(f, "Wasm trap: {m}"),
            InvokeError::Abi(m) => write!(f, "ABI error: {m}"),
            InvokeError::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

/// Sorts an error from a call. Anything raised while guest code ran (a trap,
/// a refused memory grow, a failing `random-get`) carries a Wasm backtrace
/// and is a trap; an error without one came from the interface (a result
/// that does not lift, an instance the runtime refuses to enter).
fn classify(e: wasmtime::Error, ticks: u64) -> InvokeError {
    let root = e.root_cause().to_string();
    match e.downcast_ref::<Trap>() {
        Some(Trap::Interrupt) => InvokeError::Trap(format!(
            "the guest exceeded its time limit of {} ms",
            ticks * EPOCH_TICK.as_millis() as u64
        )),
        Some(_) => InvokeError::Trap(root),
        None if e.is::<wasmtime::WasmBacktrace>() => InvokeError::Trap(root),
        None => InvokeError::Abi(root),
    }
}

/// One store and one component instance. Never used by two calls at once.
pub struct Instance {
    store: Store<HostState>,
    bindings: Aprv,
    ticks: u64,
}

impl Instance {
    /// Runs one operation. On any error the caller must drop this instance.
    pub fn call(&mut self, op: Op, input: &[u8]) -> Result<String, InvokeError> {
        self.store.set_epoch_deadline(self.ticks);
        let v = self.bindings.aprv_verifier_verify();
        let s = &mut self.store;
        let r = match op {
            Op::Init => v.call_init(s, input),
            Op::VerifyReceipt { now_ms } => v.call_verify_receipt(s, now_ms, input),
            Op::VerifySignedData { now_ms } => v.call_verify_signed_data(s, now_ms, input),
            Op::Endpoint { env, now_ms } => v.call_verify_receipt_endpoint(s, env, now_ms, input),
        };
        r.map_err(|e| classify(e, self.ticks))
    }
}

#[cfg(all(test, feature = "compile"))]
impl Instance {
    /// A second component instance in this instance's store: the store
    /// limit must refuse it.
    pub fn instantiate_again(&mut self, rt: &Runtime) -> wasmtime::Result<()> {
        rt.pre.instantiate(&mut self.store).map(|_| ())
    }
}

/// The instance lifecycle (ARCHITECTURE.md §5).
pub enum Lifecycle {
    /// A fresh store, instance and `init` per call (the default).
    Fresh,
    /// Instances kept between calls, one call at a time each; an instance
    /// that trapped or broke the interface is dropped, never returned.
    Pool(Mutex<Vec<Instance>>),
}

/// The runtime, the roots configuration every instance gets, and the
/// lifecycle: the one entry point the HTTP routes and the CLI call.
pub struct Verifier {
    pub runtime: Runtime,
    config_json: Vec<u8>,
    lifecycle: Lifecycle,
}

impl Verifier {
    /// Checks the configuration once with a real instance, so a refused
    /// root stops the server at start instead of failing every request.
    pub fn new(runtime: Runtime, config_json: Vec<u8>, pool: bool) -> Result<Verifier, String> {
        let first = match runtime.ready_instance(&config_json) {
            Ok(Ok(i)) => i,
            Ok(Err(answer)) => {
                return Err(format!(
                    "the component refused the roots configuration: {answer}"
                ))
            }
            Err(e) => return Err(format!("the component failed its first init: {e}")),
        };
        let lifecycle = if pool {
            Lifecycle::Pool(Mutex::new(vec![first]))
        } else {
            Lifecycle::Fresh
        };
        Ok(Verifier {
            runtime,
            config_json,
            lifecycle,
        })
    }

    fn fresh(&self) -> Result<Instance, InvokeError> {
        match self.runtime.ready_instance(&self.config_json)? {
            Ok(i) => Ok(i),
            Err(answer) => Err(InvokeError::Abi(format!(
                "init refused the configuration accepted at start: {answer}"
            ))),
        }
    }

    pub fn invoke(&self, op: Op, input: &[u8]) -> Result<String, InvokeError> {
        match &self.lifecycle {
            Lifecycle::Fresh => self.fresh()?.call(op, input),
            Lifecycle::Pool(pool) => {
                let taken = pool.lock().unwrap_or_else(|p| p.into_inner()).pop();
                let mut i = match taken {
                    Some(i) => i,
                    None => self.fresh()?,
                };
                let out = i.call(op, input)?; // on error `i` is dropped here
                pool.lock().unwrap_or_else(|p| p.into_inner()).push(i);
                Ok(out)
            }
        }
    }

    pub fn lifecycle_name(&self) -> &'static str {
        match self.lifecycle {
            Lifecycle::Fresh => "fresh",
            Lifecycle::Pool(_) => "pool",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The server binds the WIT of the ABI crate, byte for byte. Until lane
    /// A lands rust/bindings/abi/wit/aprv.wit, the server's copy is the text
    /// of docs/rust-core/ARCHITECTURE.md §4. CI runs it with --ignored.
    #[test]
    #[ignore = "needs rust/bindings/abi/wit/aprv.wit (lane A)"]
    fn the_wit_is_the_abi_crates() {
        let dir = env!("CARGO_MANIFEST_DIR");
        let ours = std::fs::read(format!("{dir}/wit/aprv.wit")).unwrap();
        let abi = std::fs::read(format!("{dir}/../bindings/abi/wit/aprv.wit")).unwrap();
        assert!(
            ours == abi,
            "rust/server/wit/aprv.wit differs from rust/bindings/abi/wit/aprv.wit"
        );
    }

    #[test]
    fn the_engine_records_component_model_and_epochs() {
        let f = wasm_features(&config());
        assert!(f.iter().any(|x| x == "component_model"), "{f:?}");
        assert!(format!("{:?}", config()).contains("epoch_interruption: true"));
    }
}
