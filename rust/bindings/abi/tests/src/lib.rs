//! Two Wasmtime hosts for aprv.wasm, for the ABI tests in `tests/abi.rs`:
//!
//! - [`CoreGuest`]: the core module called by hand over the canonical ABI,
//!   the way Endive, wazero, WasmKit, wasmtime-py, the gem and .NET call it
//!   (ARCHITECTURE.md §4, "Lifecycle of one hand-rolled call");
//! - [`ComponentGuest`]: the component through Wasmtime's component
//!   runtime, the way aprv-server and jco bind it, with no ABI code.
//!
//! Both supply `random-get` from the operating system's generator, and
//! both can be told to answer it with the wrong length. Neither calls
//! `_initialize`: the module must not need it.

use std::sync::OnceLock;
use wasmtime::component::{Component, HasSelf};
use wasmtime::{Caller, Config, Engine, Instance, Linker, Memory, Module, Result, Store, Trap};

/// The interface's export names carry the ABI version.
pub const IFACE: &str = "aprv:verifier/verify@1.0.0";
/// The module's one import.
pub const HOST: &str = "aprv:verifier/host@1.0.0";

fn path_of(var: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| {
        panic!(
            "{var} is not set: build the module with rust/bindings/abi/build.sh <out> and set \
             APRV_WASM=<out>/aprv.wasm APRV_COMPONENT=<out>/aprv.component.wasm"
        )
    })
}

/// One engine, the module and the component, compiled once per process.
pub struct Artifacts {
    pub engine: Engine,
    pub module: Module,
    pub component: Component,
}

pub fn artifacts() -> &'static Artifacts {
    static ARTIFACTS: OnceLock<Artifacts> = OnceLock::new();
    ARTIFACTS.get_or_init(|| {
        let engine = Engine::new(&Config::new()).expect("engine");
        let module = Module::from_file(&engine, path_of("APRV_WASM")).expect("APRV_WASM compiles");
        let component = Component::from_file(&engine, path_of("APRV_COMPONENT"))
            .expect("APRV_COMPONENT compiles");
        Artifacts {
            engine,
            module,
            component,
        }
    })
}

/// How `random-get` answers: `trim` bytes fewer than asked (negative: more).
#[derive(Clone, Copy, Default)]
pub struct Randomness {
    pub trim: i64,
}

impl Randomness {
    fn bytes(&self, len: u32) -> Vec<u8> {
        let n = usize::try_from((i64::from(len) - self.trim).max(0)).expect("fits");
        let mut bytes = vec![0; n];
        getrandom::fill(&mut bytes).expect("the operating system's generator");
        bytes
    }
}

/// True when `result` failed with a guest trap (`unreachable`, as the
/// module's every deliberate trap is).
pub fn is_trap<T>(result: &Result<T>) -> bool {
    matches!(result, Err(error) if error.downcast_ref::<Trap>() == Some(&Trap::UnreachableCodeReached))
}

/// The calls both hosts offer, in WIT terms.
pub trait Guest {
    fn init(&mut self, config: &[u8]) -> Result<String>;
    fn verify_receipt(&mut self, now_ms: u64, receipt: &[u8]) -> Result<String>;
    fn verify_signed_data(&mut self, now_ms: u64, jws: &[u8]) -> Result<String>;
    fn verify_receipt_endpoint(&mut self, env: u32, now_ms: u64, body: &[u8]) -> Result<String>;
}

// ------------------------------------------------------------ hand-rolled

pub struct CoreState {
    randomness: Randomness,
    pub random_calls: u32,
}

/// The core module, called by hand.
pub struct CoreGuest {
    pub store: Store<CoreState>,
    instance: Instance,
    memory: Memory,
}

impl CoreGuest {
    pub fn new(randomness: Randomness) -> Result<CoreGuest> {
        let artifacts = artifacts();
        let mut linker = Linker::new(&artifacts.engine);
        // random-get: func(len: u32) -> list<u8>, lowered as (len, retptr);
        // the list lives in guest memory from the guest's cabi_realloc.
        linker.func_wrap(
            HOST,
            "random-get",
            |mut caller: Caller<'_, CoreState>, len: i32, retptr: i32| -> Result<()> {
                caller.data_mut().random_calls += 1;
                let bytes = caller.data().randomness.bytes(len.cast_unsigned());
                let realloc = caller
                    .get_export("cabi_realloc")
                    .and_then(|e| e.into_func())
                    .expect("cabi_realloc")
                    .typed::<(i32, i32, i32, i32), i32>(&caller)?;
                let n = i32::try_from(bytes.len())?;
                let ptr = realloc.call(&mut caller, (0, 0, 1, n))?;
                let memory = caller
                    .get_export("memory")
                    .and_then(|e| e.into_memory())
                    .expect("memory");
                memory.write(&mut caller, usize::try_from(ptr.cast_unsigned())?, &bytes)?;
                let area = usize::try_from(retptr.cast_unsigned())?;
                memory.write(&mut caller, area, &ptr.to_le_bytes())?;
                memory.write(&mut caller, area + 4, &n.to_le_bytes())?;
                Ok(())
            },
        )?;
        let mut store = Store::new(
            &artifacts.engine,
            CoreState {
                randomness,
                random_calls: 0,
            },
        );
        let instance = linker.instantiate(&mut store, &artifacts.module)?;
        let memory = instance.get_memory(&mut store, "memory").expect("memory");
        Ok(CoreGuest {
            store,
            instance,
            memory,
        })
    }

    /// The linear memory's size in bytes.
    pub fn memory_size(&self) -> usize {
        self.memory.data_size(&self.store)
    }

    /// Calls the reactor's `_initialize` export, which a host need not call.
    pub fn call_initialize(&mut self) -> Result<()> {
        self.instance
            .get_typed_func::<(), ()>(&mut self.store, "_initialize")?
            .call(&mut self.store, ())
    }

    /// `cabi_realloc(0, 0, 1, len)`, then the bytes copied in; the guest
    /// owns the buffer from here.
    fn lower(&mut self, bytes: &[u8]) -> Result<(i32, i32)> {
        let realloc = self
            .instance
            .get_typed_func::<(i32, i32, i32, i32), i32>(&mut self.store, "cabi_realloc")?;
        let len = i32::try_from(bytes.len())?;
        let ptr = realloc.call(&mut self.store, (0, 0, 1, len))?;
        self.memory.write(
            &mut self.store,
            usize::try_from(ptr.cast_unsigned())?,
            bytes,
        )?;
        Ok((ptr, len))
    }

    /// Reads the result string at the return area, bounds-checked, then
    /// calls the export's post-return function.
    fn lift(&mut self, export: &str, retptr: i32) -> Result<String> {
        let size = self.memory.data_size(&self.store);
        let area = usize::try_from(retptr.cast_unsigned())?;
        wasmtime::ensure!(area + 8 <= size, "return area {area} is out of range");
        let mut word = [0u8; 8];
        self.memory.read(&self.store, area, &mut word)?;
        let ptr = usize::try_from(u32::from_le_bytes(word[..4].try_into()?))?;
        let len = usize::try_from(u32::from_le_bytes(word[4..].try_into()?))?;
        wasmtime::ensure!(ptr + len <= size, "result ({ptr}, {len}) is out of range");
        let mut out = vec![0; len];
        self.memory.read(&self.store, ptr, &mut out)?;
        let post = self
            .instance
            .get_typed_func::<i32, ()>(&mut self.store, &format!("cabi_post_{IFACE}#{export}"))?;
        post.call(&mut self.store, retptr)?;
        Ok(String::from_utf8(out)?)
    }

    fn verify(&mut self, export: &str, now_ms: u64, input: &[u8]) -> Result<String> {
        let (ptr, len) = self.lower(input)?;
        let f = self.instance.get_typed_func::<(i64, i32, i32), i32>(
            &mut self.store,
            &format!("{IFACE}#{export}"),
        )?;
        let retptr = f.call(&mut self.store, (now_ms.cast_signed(), ptr, len))?;
        self.lift(export, retptr)
    }
}

impl Guest for CoreGuest {
    fn init(&mut self, config: &[u8]) -> Result<String> {
        let (ptr, len) = self.lower(config)?;
        let f = self
            .instance
            .get_typed_func::<(i32, i32), i32>(&mut self.store, &format!("{IFACE}#init"))?;
        let retptr = f.call(&mut self.store, (ptr, len))?;
        self.lift("init", retptr)
    }

    fn verify_receipt(&mut self, now_ms: u64, receipt: &[u8]) -> Result<String> {
        self.verify("verify-receipt", now_ms, receipt)
    }

    fn verify_signed_data(&mut self, now_ms: u64, jws: &[u8]) -> Result<String> {
        self.verify("verify-signed-data", now_ms, jws)
    }

    fn verify_receipt_endpoint(&mut self, env: u32, now_ms: u64, body: &[u8]) -> Result<String> {
        let (ptr, len) = self.lower(body)?;
        let export = "verify-receipt-endpoint";
        let f = self.instance.get_typed_func::<(i32, i64, i32, i32), i32>(
            &mut self.store,
            &format!("{IFACE}#{export}"),
        )?;
        let retptr = f.call(
            &mut self.store,
            (env.cast_signed(), now_ms.cast_signed(), ptr, len),
        )?;
        self.lift(export, retptr)
    }
}

// -------------------------------------------------------------- component

mod bindings {
    wasmtime::component::bindgen!({ path: "../wit", world: "aprv" });
}

pub struct ComponentState {
    randomness: Randomness,
}

impl bindings::aprv::verifier::host::Host for ComponentState {
    fn random_get(&mut self, len: u32) -> Vec<u8> {
        self.randomness.bytes(len)
    }
}

/// The component, through Wasmtime's component runtime.
pub struct ComponentGuest {
    store: Store<ComponentState>,
    aprv: bindings::Aprv,
}

impl ComponentGuest {
    pub fn new(randomness: Randomness) -> Result<ComponentGuest> {
        let artifacts = artifacts();
        let mut linker = wasmtime::component::Linker::new(&artifacts.engine);
        bindings::Aprv::add_to_linker::<ComponentState, HasSelf<ComponentState>>(
            &mut linker,
            |s| s,
        )?;
        let mut store = Store::new(&artifacts.engine, ComponentState { randomness });
        let aprv = bindings::Aprv::instantiate(&mut store, &artifacts.component, &linker)?;
        Ok(ComponentGuest { store, aprv })
    }
}

impl Guest for ComponentGuest {
    fn init(&mut self, config: &[u8]) -> Result<String> {
        self.aprv
            .aprv_verifier_verify()
            .call_init(&mut self.store, config)
    }

    fn verify_receipt(&mut self, now_ms: u64, receipt: &[u8]) -> Result<String> {
        self.aprv
            .aprv_verifier_verify()
            .call_verify_receipt(&mut self.store, now_ms, receipt)
    }

    fn verify_signed_data(&mut self, now_ms: u64, jws: &[u8]) -> Result<String> {
        self.aprv
            .aprv_verifier_verify()
            .call_verify_signed_data(&mut self.store, now_ms, jws)
    }

    fn verify_receipt_endpoint(&mut self, env: u32, now_ms: u64, body: &[u8]) -> Result<String> {
        self.aprv
            .aprv_verifier_verify()
            .call_verify_receipt_endpoint(&mut self.store, env, now_ms, body)
    }
}
