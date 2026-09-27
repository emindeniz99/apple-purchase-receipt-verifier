//! Spike only (2026-09-27, round 11): the APRV-specific C ABI around Wasmi
//! 2.0.0's safe Rust API. It exposes exactly what py/aprv_wasmi_rs needs and
//! nothing general-purpose. The host imports (aprv.clock_now_ms,
//! aprv.random_get) live here in Rust, so Python never runs inside a Wasm
//! call. Every entry point catches panics; `unsafe` is confined to reading
//! and writing the caller's pointers.
//!
//! Status codes: 0 ok, 1 trap (the instance must be discarded), 2 error.
use std::ffi::{c_char, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{SystemTime, UNIX_EPOCH};
use wasmi::{CompilationMode, Config, Engine, Error, Extern, Instance, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder, Val};

static CLOCK_CALLS: AtomicU64 = AtomicU64::new(0);
static RANDOM_CALLS: AtomicU64 = AtomicU64::new(0);

pub struct Runtime {
    engine: Engine,
    module: Module,
    linker: Linker<StoreLimits>,
    fuel: u64,                // per-call budget; 0 = fuel metering off
    max_memory: usize,        // bytes; 0 = no cap beyond the module's own
}

pub struct Inst {
    store: Store<StoreLimits>,
    instance: Instance,
    memory: Memory,
    fuel_used: u64,
}

fn msg(out: *mut c_char, cap: usize, text: &str) {
    if out.is_null() || cap == 0 {
        return;
    }
    let n = text.len().min(cap - 1);
    // SAFETY: the caller passes a writable buffer of `cap` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(text.as_ptr(), out as *mut u8, n);
        *out.add(n) = 0;
    }
}

fn guard<R>(err: *mut c_char, cap: usize, fallback: R, f: impl FnOnce() -> R) -> R {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| {
        msg(err, cap, "panic inside aprv_wasmi");
        fallback
    })
}

fn random_get(mut caller: wasmi::Caller<'_, StoreLimits>, ptr: i32, len: i32) -> Result<i32, Error> {
    RANDOM_CALLS.fetch_add(1, Relaxed);
    let Some(Extern::Memory(mem)) = caller.get_export("memory") else { return Err(Error::new("no memory")) };
    let data = mem.data_mut(&mut caller);
    let (p, n) = (ptr as u32 as usize, len as u32 as usize);
    if ptr < 0 || len < 0 || p.checked_add(n).is_none_or(|end| end > data.len()) {
        return Err(Error::new("aprv.random_get out of bounds"));
    }
    getrandom::fill(&mut data[p..p + n]).map_err(|_| Error::new("getrandom failed"))?;
    Ok(0)
}

/// mode: 0 eager, 1 lazy-translation, 2 lazy. fuel: per-call budget, 0 = off.
/// max_memory: linear-memory cap in bytes, 0 = none.
#[no_mangle]
pub extern "C" fn aprv_rt_new(wasm: *const u8, len: usize, mode: u32, fuel: u64, max_memory: usize, err: *mut c_char, cap: usize) -> *mut Runtime {
    guard(err, cap, std::ptr::null_mut(), || {
        // SAFETY: the caller passes `len` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(wasm, len) };
        let mut config = Config::default();
        config.compilation_mode(match mode {
            0 => CompilationMode::Eager,
            2 => CompilationMode::Lazy,
            _ => CompilationMode::LazyTranslation,
        });
        config.consume_fuel(fuel > 0);
        let engine = Engine::new(&config);
        let module = match Module::new(&engine, bytes) {
            Ok(m) => m,
            Err(e) => {
                msg(err, cap, &format!("module rejected: {e}"));
                return std::ptr::null_mut();
            }
        };
        let mut linker = Linker::<StoreLimits>::new(&engine);
        let ok = linker
            .func_wrap("aprv", "clock_now_ms", || {
                CLOCK_CALLS.fetch_add(1, Relaxed);
                SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as f64).unwrap_or(0.0)
            })
            .and_then(|l| l.func_wrap("aprv", "random_get", random_get))
            .is_ok();
        if !ok {
            msg(err, cap, "linker");
            return std::ptr::null_mut();
        }
        Box::into_raw(Box::new(Runtime { engine, module, linker, fuel, max_memory }))
    })
}

#[no_mangle]
pub extern "C" fn aprv_rt_free(rt: *mut Runtime) {
    if !rt.is_null() {
        // SAFETY: `rt` came from aprv_rt_new and is freed once, after its instances.
        drop(unsafe { Box::from_raw(rt) });
    }
}

fn set_fuel(inst: &mut Inst, fuel: u64) -> Result<(), Error> {
    if fuel > 0 {
        inst.store.set_fuel(fuel)?;
    }
    Ok(())
}

/// Runs an export with i32 arguments under the per-call fuel budget.
fn call(inst: &mut Inst, fuel: u64, name: &str, args: &[i32]) -> Result<Option<i32>, (i32, String)> {
    let f = inst.instance.get_func(&inst.store, name).ok_or((2, format!("no export {name}")))?;
    let params: Vec<Val> = args.iter().map(|a| Val::I32(*a)).collect();
    let mut results = vec![Val::I32(0); f.ty(&inst.store).results().len()];
    set_fuel(inst, fuel).map_err(|e| (2, e.to_string()))?;
    let r = f.call(&mut inst.store, &params, &mut results);
    if fuel > 0 {
        inst.fuel_used = fuel - inst.store.get_fuel().unwrap_or(0);
    }
    r.map_err(|e| (1, e.to_string()))?;
    Ok(results.first().and_then(Val::i32))
}

#[no_mangle]
pub extern "C" fn aprv_inst_new(rt: *const Runtime, err: *mut c_char, cap: usize) -> *mut Inst {
    guard(err, cap, std::ptr::null_mut(), || {
        // SAFETY: `rt` is a live pointer from aprv_rt_new.
        let rt = unsafe { &*rt };
        let mut limits = StoreLimitsBuilder::new().instances(1).memories(1).tables(1);
        if rt.max_memory > 0 {
            limits = limits.memory_size(rt.max_memory);
        }
        let mut store = Store::new(&rt.engine, limits.build());
        store.limiter(|l| l);
        if rt.fuel > 0 && store.set_fuel(rt.fuel).is_err() {
            return std::ptr::null_mut();
        }
        let made = rt.linker.instantiate_and_start(&mut store, &rt.module).map_err(|e| e.to_string()).and_then(|instance| {
            let memory = instance.get_memory(&store, "memory").ok_or("no memory export".to_string())?;
            Ok(Inst { store, instance, memory, fuel_used: 0 })
        });
        let mut inst = match made {
            Ok(i) => i,
            Err(e) => {
                msg(err, cap, &e);
                return std::ptr::null_mut();
            }
        };
        let init = call(&mut inst, rt.fuel, "_initialize", &[]).and_then(|_| call(&mut inst, rt.fuel, "aprv_abi_version", &[]));
        match init {
            Ok(Some(1)) => Box::into_raw(Box::new(inst)),
            Ok(v) => {
                msg(err, cap, &format!("APRV Wasm ABI mismatch: module={v:?}, caller=1"));
                std::ptr::null_mut()
            }
            Err((_, e)) => {
                msg(err, cap, &e);
                std::ptr::null_mut()
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn aprv_inst_free(inst: *mut Inst) {
    if !inst.is_null() {
        // SAFETY: `inst` came from aprv_inst_new and is freed once.
        drop(unsafe { Box::from_raw(inst) });
    }
}

/// The ABI v1 call lifecycle. On success *out/*out_len hold a copy the
/// caller frees with aprv_buf_free.
#[no_mangle]
pub extern "C" fn aprv_inst_invoke(
    rt: *const Runtime, inst: *mut Inst, abi: i32, op: i32, input: *const u8, len: usize,
    out: *mut *mut u8, out_len: *mut usize, err: *mut c_char, cap: usize,
) -> i32 {
    guard(err, cap, 3, || {
        // SAFETY: live pointers from this library; `input` holds `len` bytes; out pointers are writable.
        let (rt, inst, data) = unsafe { (&*rt, &mut *inst, std::slice::from_raw_parts(input, len)) };
        let mut run = || -> Result<Vec<u8>, (i32, String)> {
            let n = i32::try_from(data.len()).map_err(|_| (2, "input too large".to_string()))?;
            let p = call(inst, rt.fuel, "aprv_alloc", &[n])?.unwrap_or(0);
            if p == 0 {
                return Err((2, format!("aprv_alloc({n}) failed")));
            }
            inst.memory.write(&mut inst.store, p as u32 as usize, data).map_err(|e| (1, e.to_string()))?;
            let h = call(inst, rt.fuel, "aprv_call", &[abi, op, p, n])?.unwrap_or(0);
            let used = inst.fuel_used;
            let rp = call(inst, rt.fuel, "aprv_result_ptr", &[h])?.unwrap_or(0) as u32 as usize;
            let rn = call(inst, rt.fuel, "aprv_result_len", &[h])?.unwrap_or(0) as u32 as usize;
            let mut buf = vec![0u8; rn];
            inst.memory.read(&inst.store, rp, &mut buf).map_err(|_| (1, "result out of bounds".to_string()))?;
            call(inst, rt.fuel, "aprv_result_free", &[h])?;
            call(inst, rt.fuel, "aprv_dealloc", &[p, n])?;
            inst.fuel_used = used;
            Ok(buf)
        };
        match run() {
            Ok(buf) => {
                let b = buf.into_boxed_slice();
                // SAFETY: out pointers are writable; ownership moves to the caller.
                unsafe {
                    *out_len = b.len();
                    *out = Box::into_raw(b) as *mut u8;
                }
                0
            }
            Err((code, e)) => {
                msg(err, cap, &e);
                code
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn aprv_buf_free(buf: *mut u8, len: usize) {
    if !buf.is_null() {
        // SAFETY: (buf, len) came from aprv_inst_invoke and is freed once.
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(buf, len)) });
    }
}

/// Raw export call with i32 arguments (the ABI tests). *nres is 0 or 1.
#[no_mangle]
pub extern "C" fn aprv_inst_raw(
    rt: *const Runtime, inst: *mut Inst, name: *const c_char, args: *const i32, nargs: usize,
    result: *mut i32, nres: *mut u32, err: *mut c_char, cap: usize,
) -> i32 {
    guard(err, cap, 3, || {
        // SAFETY: live pointers; `name` is NUL-terminated; `args` holds `nargs` values; outputs writable.
        let (rt, inst, name, args) = unsafe { (&*rt, &mut *inst, CStr::from_ptr(name), std::slice::from_raw_parts(args, nargs)) };
        match call(inst, rt.fuel, &name.to_string_lossy(), args) {
            Ok(v) => {
                // SAFETY: as above.
                unsafe {
                    *nres = v.is_some() as u32;
                    *result = v.unwrap_or(0);
                }
                0
            }
            Err((code, e)) => {
                msg(err, cap, &e);
                code
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn aprv_inst_memory_size(inst: *const Inst) -> usize {
    // SAFETY: live pointer from aprv_inst_new.
    let inst = unsafe { &*inst };
    inst.memory.data_size(&inst.store)
}

/// Fuel the last aprv_call (or raw call) consumed; 0 when metering is off.
#[no_mangle]
pub extern "C" fn aprv_inst_fuel_used(inst: *const Inst) -> u64 {
    // SAFETY: live pointer from aprv_inst_new.
    unsafe { (*inst).fuel_used }
}

#[no_mangle]
pub extern "C" fn aprv_import_counts(clock: *mut u64, random: *mut u64) {
    // SAFETY: both pointers are writable.
    unsafe {
        *clock = CLOCK_CALLS.load(Relaxed);
        *random = RANDOM_CALLS.load(Relaxed);
    }
}
