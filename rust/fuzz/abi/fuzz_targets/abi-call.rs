#![no_main]

//! aprv.wasm through its exports on Wasmtime, called by hand over the
//! canonical ABI as the Endive, wazero, WasmKit, wasmtime-py, gem and .NET
//! hosts call it. The input picks the export, `env` and `now-ms`, and the
//! rest is the `list<u8>`: as it is, or (one bit of the first byte) as the
//! base64 a client sends, bare for `verify-receipt` and wrapped as
//! `{"receipt-data": ...}` for the endpoint, so mutations reach the
//! envelope. Invariants beyond "the host does not crash":
//!
//! - `init` with Apple's roots answers `{"ok":true,"max_input_bytes":...}`;
//! - a verify call with `env` 0 or 1 never traps, and answers UTF-8 JSON of
//!   its shape (`{"verified":...` or, at the endpoint, `{"status":...`);
//! - `env` above 1 always traps, and the next call on a fresh instance
//!   verifies again (a trapped instance is discarded, as every host does).
//!
//! Coverage comes from the host side only: the guest runs as Cranelift's
//! code, which libFuzzer does not instrument. The OpenSSL-instrumented
//! targets beside it cover the core natively; this one covers the boundary.
//!
//!   APRV_WASM=<out>/aprv.wasm cargo +nightly fuzz run --fuzz-dir rust/fuzz/abi abi-call

use base64::Engine as _;
use libfuzzer_sys::fuzz_target;
use std::sync::{Mutex, OnceLock};
use wasmtime::{Caller, Config, Engine, Instance, Linker, Memory, Module, Store, Trap, TypedFunc};

const IFACE: &str = "aprv:verifier/verify@0.1.0";

struct Compiled {
    engine: Engine,
    module: Module,
}

fn compiled() -> &'static Compiled {
    static COMPILED: OnceLock<Compiled> = OnceLock::new();
    COMPILED.get_or_init(|| {
        let path = std::env::var("APRV_WASM")
            .expect("APRV_WASM is not set: build the module with rust/bindings/abi/build.sh <out>");
        let engine = Engine::new(&Config::new()).expect("engine");
        let module = Module::from_file(&engine, path).expect("APRV_WASM compiles");
        Compiled { engine, module }
    })
}

struct Guest {
    store: Store<()>,
    instance: Instance,
    memory: Memory,
    realloc: TypedFunc<(i32, i32, i32, i32), i32>,
}

impl Guest {
    fn new() -> Guest {
        let c = compiled();
        let mut linker = Linker::new(&c.engine);
        linker
            .func_wrap(
                "aprv:verifier/host@0.1.0",
                "random-get",
                |mut caller: Caller<'_, ()>, len: i32, retptr: i32| -> wasmtime::Result<()> {
                    // Deterministic bytes: the fuzzer must replay an input.
                    let n = usize::try_from(len.cast_unsigned())?;
                    let bytes: Vec<u8> = (0..n)
                        .map(|i| (i as u8).wrapping_mul(151).wrapping_add(7))
                        .collect();
                    let realloc = caller
                        .get_export("cabi_realloc")
                        .and_then(|e| e.into_func())
                        .expect("cabi_realloc")
                        .typed::<(i32, i32, i32, i32), i32>(&caller)?;
                    let ptr = realloc.call(&mut caller, (0, 0, 1, len))?;
                    let memory = caller
                        .get_export("memory")
                        .and_then(|e| e.into_memory())
                        .expect("memory");
                    memory.write(&mut caller, usize::try_from(ptr.cast_unsigned())?, &bytes)?;
                    let area = usize::try_from(retptr.cast_unsigned())?;
                    memory.write(&mut caller, area, &ptr.to_le_bytes())?;
                    memory.write(&mut caller, area + 4, &len.to_le_bytes())?;
                    Ok(())
                },
            )
            .expect("random-get");
        let mut store = Store::new(&c.engine, ());
        let instance = linker
            .instantiate(&mut store, &c.module)
            .expect("instantiate");
        let memory = instance.get_memory(&mut store, "memory").expect("memory");
        let realloc = instance
            .get_typed_func::<(i32, i32, i32, i32), i32>(&mut store, "cabi_realloc")
            .expect("cabi_realloc");
        let mut guest = Guest {
            store,
            instance,
            memory,
            realloc,
        };
        let answer = guest
            .call_init(br#"{"roots":[]}"#)
            .expect("init does not trap");
        assert!(
            answer.starts_with(r#"{"ok":true,"max_input_bytes":"#),
            "init with Apple's roots: {answer}"
        );
        guest
    }

    fn lower(&mut self, bytes: &[u8]) -> wasmtime::Result<(i32, i32)> {
        let len = i32::try_from(bytes.len())?;
        let ptr = self.realloc.call(&mut self.store, (0, 0, 1, len))?;
        self.memory.write(
            &mut self.store,
            usize::try_from(ptr.cast_unsigned())?,
            bytes,
        )?;
        Ok((ptr, len))
    }

    fn lift(&mut self, export: &str, retptr: i32) -> wasmtime::Result<String> {
        let size = self.memory.data_size(&self.store);
        let area = usize::try_from(retptr.cast_unsigned())?;
        assert!(area + 8 <= size, "the return area is inside memory");
        let mut word = [0u8; 8];
        self.memory.read(&self.store, area, &mut word)?;
        let ptr = usize::try_from(u32::from_le_bytes(word[..4].try_into()?))?;
        let len = usize::try_from(u32::from_le_bytes(word[4..].try_into()?))?;
        assert!(ptr + len <= size, "the result is inside memory");
        let mut out = vec![0; len];
        self.memory.read(&self.store, ptr, &mut out)?;
        let post = self
            .instance
            .get_typed_func::<i32, ()>(&mut self.store, &format!("cabi_post_{IFACE}#{export}"))?;
        post.call(&mut self.store, retptr)?;
        Ok(String::from_utf8(out).expect("every answer is UTF-8"))
    }

    fn call_init(&mut self, config: &[u8]) -> wasmtime::Result<String> {
        let (ptr, len) = self.lower(config)?;
        let f = self
            .instance
            .get_typed_func::<(i32, i32), i32>(&mut self.store, &format!("{IFACE}#init"))?;
        let retptr = f.call(&mut self.store, (ptr, len))?;
        self.lift("init", retptr)
    }

    fn call(&mut self, op: u8, env: u32, now_ms: u64, input: &[u8]) -> wasmtime::Result<String> {
        let (ptr, len) = self.lower(input)?;
        let now = now_ms.cast_signed();
        let (export, retptr) = match op {
            0 => {
                let f = self.instance.get_typed_func::<(i64, i32, i32), i32>(
                    &mut self.store,
                    &format!("{IFACE}#verify-receipt"),
                )?;
                ("verify-receipt", f.call(&mut self.store, (now, ptr, len))?)
            }
            1 => {
                let f = self.instance.get_typed_func::<(i64, i32, i32), i32>(
                    &mut self.store,
                    &format!("{IFACE}#verify-signed-data"),
                )?;
                (
                    "verify-signed-data",
                    f.call(&mut self.store, (now, ptr, len))?,
                )
            }
            _ => {
                let f = self.instance.get_typed_func::<(i32, i64, i32, i32), i32>(
                    &mut self.store,
                    &format!("{IFACE}#verify-receipt-endpoint"),
                )?;
                (
                    "verify-receipt-endpoint",
                    f.call(&mut self.store, (env.cast_signed(), now, ptr, len))?,
                )
            }
        };
        self.lift(export, retptr)
    }
}

/// One pooled instance, `init`ed once, as a pooled host keeps it; replaced
/// after a trap.
fn guest() -> &'static Mutex<Option<Guest>> {
    static GUEST: OnceLock<Mutex<Option<Guest>>> = OnceLock::new();
    GUEST.get_or_init(|| Mutex::new(None))
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 13 {
        return;
    }
    let op = data[0] % 3;
    // Mostly the two environments, sometimes any u32.
    let raw_env = u32::from_le_bytes(data[1..5].try_into().unwrap());
    let env = if data[0] & 0x80 == 0 {
        raw_env & 1
    } else {
        raw_env
    };
    let now_ms = u64::from_le_bytes(data[5..13].try_into().unwrap());
    let wrapped;
    let input = if data[0] & 0x40 != 0 && op != 1 {
        let text = base64::engine::general_purpose::STANDARD.encode(&data[13..]);
        wrapped = if op == 0 {
            text.into_bytes()
        } else {
            format!("{{\"receipt-data\":\"{text}\"}}").into_bytes()
        };
        &wrapped[..]
    } else {
        &data[13..]
    };

    let mut slot = guest()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let g = slot.get_or_insert_with(Guest::new);
    match g.call(op, env, now_ms, input) {
        Ok(answer) => {
            assert!(
                op != 2 || env <= 1,
                "env {env} answered instead of trapping: {answer}"
            );
            let shape = if op == 2 {
                "{\"status\":"
            } else {
                "{\"verified\":"
            };
            assert!(answer.starts_with(shape), "answer {answer:.200}");
        }
        Err(error) => {
            let trap = error.downcast_ref::<Trap>().copied();
            assert!(
                op == 2 && env > 1 && trap == Some(Trap::UnreachableCodeReached),
                "a trap for op {op}, env {env}, now-ms {now_ms}, {} input bytes: {error:?}",
                input.len()
            );
            *slot = None;
            // A fresh instance verifies after the trap.
            let mut fresh = Guest::new();
            let answer = fresh
                .call(1, 0, 0, b"not.a.jws")
                .expect("a fresh instance answers");
            assert!(answer.starts_with("{\"verified\":false"), "{answer}");
            *slot = Some(fresh);
        }
    }
});
