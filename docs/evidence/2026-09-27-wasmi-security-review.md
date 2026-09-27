# Wasmi 2.0.0 as the sandbox around OpenSSL-in-Wasm: security desk review

Date: 2026-09-27. Scripts and raw inventories are in
`2026-09-27-wasmi-security-review/`; its `README.md` lists every file and
how to reproduce them.

## What this feeds

The plan may run `aprv.wasm` (Rust + OpenSSL 4, wasm32-wasip1) inside Wasmi
2.0.0 as the Python runtime, reached over a thin ctypes/cffi binding —
either over Wasmi's official C API (`wasmi_c_api_impl`) or over a narrow
APRV-specific Rust cdylib. Wasmi would be the isolation boundary around
OpenSSL-in-Wasm, so its own memory safety is what matters. This is a desk
review: it reads the exact 2.0.0 sources and the primary security
documents, and runs a few small checks. It does not build the bindings or
run benchmarks (round 11 does that) and it changes no production path.

Labels: **VERIFIED** (read in 2.0.0 crate source or a primary doc),
**TESTED** (ran here), **DOCUMENTED** (upstream states it; not
independently checked), **UNVERIFIED** (could not confirm).

## Findings first

1. **Wasmi 2.0.0 is written in `safe`-looking Rust but is not
   `unsafe`-free: its execution core carries 220 class-A `unsafe` sites
   whose soundness rests on the translator/validator, not the type system
   (VERIFIED).** "Written in Rust" is not "no unsafe" here. The whole
   register-machine executor threads raw pointers (`Ip`, `Sp`, `Inst`,
   `Mem0Ptr`) through its hot path and reconstructs slices and references
   from them without bounds checks, on the invariant that Wasm validation
   plus correct translation already proved the access in range. This is a
   deliberate, documented design and it is exactly the code the 2024
   Runtime Verification audit called out as new and risky — but that audit
   covered v0.36, three minor generations before the executor this note
   reviews (finding 6).

2. **Linear-memory bounds checks are explicit software checks, not
   virtual-memory guard pages (VERIFIED).** Every `T.load`/`T.store`
   computes an effective address with a checked add and a `slice::get`
   range check before touching bytes (`wasmi_core/src/memory/access.rs`);
   the backing store is a plain heap `Vec<u8>` (`ByteBuffer`), not an
   `mmap`ed reservation with a guard region. There is no signal handler and
   no reliance on the host MMU. That is the right property for this
   embedding: it means a bad guest access traps deterministically on every
   platform instead of depending on OS-level guard pages, and it needs no
   `SIGSEGV` handler competing with CPython's. (Cost: a branch per access;
   round 9 already measured Wasmi's throughput.)

3. **One further memory-safety issue was found during this review and
   reported privately to the Wasmi maintainer on 2026-09-27, as Wasmi's
   `SECURITY.md` asks. Its details are withheld here until upstream
   publishes a fix.** It is not reachable by `aprv.wasm`: the module has
   exactly two function imports and one defined memory
   (`results/aprv-module-surface.txt`), and the APRV facade only ever
   instantiates that pinned module. The embedding requirements in the
   Verdict are the local mitigation.

4. **The C API adds a second `unsafe` boundary and ships a large surface of
   functions that abort the process, but our facade can avoid essentially
   all of it (VERIFIED).** `wasmi_c_api_impl` 2.0.0 exports **303** C
   functions (`results/capi-functions.tsv`); **76** are `unimplemented!`
   (every call aborts) and **16** more can panic on some inputs. None of
   the 76 unimplemented ones is on the path an APRV facade needs
   (engine/config/store, module new+validate, memory `Func::new` host
   callbacks, instance new, exports, memory data/size, func call, fuel).
   The panics that *are* on that path are input-guarded and avoidable:
   `wasm_memory_size`/`wasm_table_size` panic only above `u32::MAX`
   pages/elements (never for a 27-page module), the `wasm_*_vec_copy`
   family panics only on a corrupted vector the facade never constructs,
   and `wasm_functype_new` panics on a null element the facade never
   passes. Crucially, a panic here **aborts, it does not corrupt**: the
   crate's MSRV is 1.86, so a panic reaching an `extern "C"` frame aborts
   the process (no unwinding across FFI, no UB), and `wasm_func_call`
   additionally wraps the guest call in `catch_unwind` and converts a panic
   to a trap (VERIFIED, `func.rs`).

5. **A narrow APRV-specific Rust cdylib is the safer and simpler binding —
   clear verdict (VERIFIED reasoning).** See the dedicated section below.
   In short: the generic C API forces Python to own raw `wasm_*_vec_t`
   pointers, `wasm_ref_t`/`Box` ownership transfers, and the manual
   free-function discipline of ~40 `unsafe extern` entry points, and it
   gives no C setter for the isolation-relevant knobs (compilation mode has
   one; fuel has one; stack height, memory-page limits and the proposal
   switches do not). A ~100–200-line cdylib that calls the safe Wasmi Rust API inside
   and exposes ~10 C functions (pointer+len in/out, one opaque handle)
   shrinks the Python-visible `unsafe` surface to that handle plus two byte
   buffers, and lets the boundary be configured in Rust where every knob
   exists.

6. **Wasmi is independently audited twice, but neither audit covers the
   2.0.0 executor this review is about (VERIFIED, `results/audits.txt`).**
   SRLabs audited **v0.31.0** for Parity (Dec 2023): differential fuzzing
   vs Wasmtime, no issues. Runtime Verification audited **v0.36.0**
   (commit `02621ad7`) for the Stellar Development Foundation (delivered
   Nov 2024, 8 weeks): 4 code findings (one High: unbounded `count` into
   `<*mut T>::offset`/`add`, acknowledged-not-fixed), 8 fuzzing findings
   (three High, all fixed), and a per-site review of the then-112 `unsafe`
   uses. **Everything from v0.37 through v2.0.0 — the register-IR rewrite
   (#1655), the lock-free append-only `CodeMap`, the new `InstanceEntity`
   cache, the tail-call dispatch, lazy translation — is unaudited.** 2.0.0's `unsafe` count is roughly
   3× the audited v0.36 (finding 7).

7. **RustSec/GHSA status: no advisory against any wasmi-family crate at the
   versions we would ship; the only advisories are historical and the one
   transitive dependency with open advisories is `spin` (VERIFIED,
   `results/advisories.txt`).** Two Wasmi advisories exist, both fixed
   before 2.0.0: GHSA-75jp-vq8x-h4cq / CVE-2024-28123 (OOB write, host→Wasm
   call >128 params, fixed 0.31.1) and GHSA-g4v2-cjqp-rfmq / CVE-2025-66627
   (**critical use-after-free in linear memory**, "attacker-controlled
   memory reads … memory corruption may allow arbitrary writes", affected
   0.41.0–1.0.0, fixed in the 1.0.1 / 0.51.3 / 0.47.1 / 0.41.2 line). The
   CVE-2025-66627 fix commit `0e6f0d2` is a use-after-free in
   `ByteBuffer::grow` (a `Vec::from_raw_parts` whose `Vec` then dropped and
   freed the buffer) — the very `ByteBuffer` that 2.0.0 still uses, now with
   the `ManuallyDrop` fix carried in (VERIFIED, buffer.rs lines 191–203).
   That a critical UAF lived in this exact code for four minor versions and
   was found by external review (R. T. Morris), plus the privately reported
   issue in finding 3, is the strongest reason to treat 2.0.0's post-
   0.36 memory code as "capable and improving, but young."

## Execution core: unsafe inventory and classification

Method: a lexer-light scan (`scripts/unsafe_inventory.py`) counts every
`unsafe` keyword outside comments/strings, tagged by kind (block / fn /
impl / attr) and scope (src / test / build), cross-checked against
`grep -c '\bunsafe\b'`. `scripts/classify.py` then applies hand-written
risk classes to the core-crate `src` rows, first-match-wins, each rule
written after reading the site. Raw lists:
`results/unsafe-raw.tsv`, `results/unsafe-classified.tsv`,
`results/unsafe-summary.txt`.

**Counts by crate (`src` scope; the whole resolved graph was scanned)**
(VERIFIED):

| crate | src `unsafe` sites | note |
|---|---:|---|
| `wasmi` 2.0.0 | 289 (212 block, 59 fn, 18 impl) | the executor, code map, instance, store |
| `wasmi_c_api_impl` 2.0.0 | 266 (152 attr, 75 block, 37 fn, 2 impl) | reviewed separately below |
| `wasmi_collections` 2.0.0 | 23 | stable arenas (pointer-stable storage) |
| `wasmi_core` 2.0.0 | 7 | linear-memory `ByteBuffer`, SIMD transmutes |
| `wasmi_ir` 2.0.0 | 3 | opcode transmute, array decode |
| `wasmparser` 0.228.0 | 1 | one `KebabStr` transmute in validation |
| `wasmi_c_api_macros` 2.0.0 | 9 | all `unsafe(no_mangle)` attrs (generated exports) |

The 152 `wasmi_c_api_impl` "attr" sites are the edition-2024
`#[cfg_attr(..., unsafe(no_mangle))]` spelling of an exported C symbol, not
unsafe operations; they are counted so the raw total matches `grep`, and
excluded from the risk classes. Do **not** read the 266 C-API sites or the
23-per-file `wasmi_collections` test blocks as equivalent to executor
sites — that is why the classifier separates scope and kind.

**Core `src` sites by risk class** (VERIFIED, `results/unsafe-summary.txt`;
covers `wasmi`, `wasmi_core`, `wasmi_ir`, `wasmi_collections`, the one
`wasmparser` site — 323 sites):

| class | sites | what it is |
|---|---:|---|
| **A — can affect guest/host isolation directly** | **220** | see the A sub-classes |
| A-inst | 94 | instance-entity cache: `ThinPtr<InstanceEntity>`, raw `NonNull` to table/global/func/mem/segment entities, `AnyHandle` kind casts (`transmute`) |
| A-ip | 74 | instruction stream + dispatch: unchecked `Ip::decode`/`add`/`offset`, branch-table offset arithmetic, handler-pointer `transmute`, `FuncEntryPtr` baked into bytecode, `HANDLERS.get_unchecked` |
| A-stack | 20 | value stack: `Sp`/slot pointer arithmetic, `Vec::set_len` on cells, host-call in/out `from_raw_parts` |
| A-mem | 18 | linear memory: `ByteBuffer` slice/`Vec` reconstruction, the `(memory 0)` cache extract + `mem0_bytes` `from_raw_parts_mut` |
| A-assume | 14 | `unreachable_unchecked!` in the executor: UB in release **only if** a translator/executor invariant is false |
| **B — lifetime / provenance / aliasing / concurrency** | 62 | append-only lock-free `CodeMap` state machine (42), pointer-stable arenas (14), `Store<T>`↔`PrunedStore` `transmute` (2), misc |
| **C — `unsafe impl Send`/`Sync`** | 28 | 14 types; each carries a written safety argument |
| **D — benign / unreachable for APRV** | 13 | `str::from_utf8_unchecked` on data it wrote, SIMD/opcode same-size transmutes, `Module::new_unchecked` (the validation-bypass API — APRV always validates) |

### Class A: the invariant each relies on, and where it is established

- **A-mem (linear memory).** `wasmi_core::memory::access::{load,store}` do a
  checked `effective_address` (checked add, `usize::try_from`) then
  `slice::get(addr..).get(..N)` — a **software bounds check on every
  access**, established at the access site, not by a guard page (finding 2,
  VERIFIED). `ByteBuffer::data/data_mut` build a `&mut [u8]` from
  `(ptr, len)` that are consistent by construction (`Vec`- or
  `&'static mut [u8]`-backed). The executor's fast path skips the
  per-access entity fetch by caching `(memory 0)`'s `(ptr,len)` in `Args`
  and reconstructing the slice with `state::mem0_bytes` (`from_raw_parts_mut`).
- **A-ip (instruction stream / dispatch).** `Ip::decode`/`skip`/`add`/
  `offset` are `unsafe fn` that read and advance a `*const u8` into the
  engine's immutable, append-only bytecode with **no bounds check**; the
  invariant ("Ip points at a valid encoding and the buffer outlives use")
  is established by the translator emitting well-formed bytecode into a
  `CodeMap` that is never freed while the engine lives, and by every
  handler decoding exactly what it emitted. The default (x86-64) dispatch
  `transmute`s a decoded `usize` into a handler `fn` pointer
  (`decode_handler`); the indirect variants index `HANDLERS` with
  `get_unchecked` on the invariant that `OpCode` is a contiguous `0..LEN_OPS`
  (`wasmi_ir::opcode::OpCode::new` is the checked constructor). If bytecode
  or an opcode were ever malformed, these are UB in release — so their
  soundness is entirely the translator's correctness, which is what the
  fuzzing (finding 8) and the RV audit stressed on an older executor.
- **A-stack (value stack).** `Sp` is a `*mut Cell`; `get`/`set`/`offset`
  do pointer arithmetic into the stack cells, and `ValueStack::set_len`
  grows the `Vec<Cell>` without initializing (sound because `Cell` has no
  invalid bit pattern, per the in-source safety comment). Bounds come from
  the translator computing each frame's slot count and `grow_if_needed`
  checking `max_height` before use.
- **A-inst (instance cache).** `Inst` is a `ThinPtr<InstanceEntity>` held
  in a register; entity lookups (`get_memory`, `get_table`, …) return raw
  `NonNull` on the invariant that the instance is boxed, never moved, and
  outlives the execution (documented at `state.rs:207` and `cache.rs`).
  `AnyHandle` casts are `transmute`s guarded by a debug-only kind assert.
- **A-assume (`unreachable_unchecked!`).** 14 executor sites lower to
  `core::hint::unreachable_unchecked()` in release and to a real
  `unreachable!` panic **whenever `debug_assertions` OR the `extra-checks`
  crate feature is on** (VERIFIED, `engine/utils.rs`). This is the single
  most useful embedding lever: building the APRV cdylib with `extra-checks`
  turns every one of these, plus the executor's other elided checks, into a
  panic (documented ~20% slowdown) instead of UB. See requirements.

Classes B/C/D are not on the per-instruction isolation path. The 28 C-class
`unsafe impl Send/Sync` each carry a written argument; the pointer-stable
arenas and the lock-free `CodeMap` (B) are where the lazy-compilation state
machine lives (`AtomicU8` state + `UnsafeCell` payload, CAS on
UNCOMPILED→COMPILING) — correct-looking, and the natural place for a future
concurrency bug, but APRV calls from one thread per instance.

## Linear-memory bounds checking: software, not guard pages (VERIFIED)

Stated in finding 2 and detailed under A-mem. Confirmed by reading
`wasmi_core/src/memory/{access.rs,buffer.rs}`: checked address + `slice::get`
range check per access; `Vec<u8>` backing; no `mmap`, `mprotect`, signal
handler or `catch_unwind`-around-SIGSEGV anywhere in `wasmi`/`wasmi_core`
(grepped). This is the property that makes Wasmi safe to embed inside
CPython without fighting the interpreter over the segfault handler, and it
makes out-of-bounds guest accesses deterministic traps on every target.

## C API review (VERIFIED)

Full function table with panic flags: `results/capi-functions.tsv`
(`scripts/capi_surface.py`). Headline numbers: **303** exported functions,
**76** `unimplemented!` (always abort), **16** conditional panics, **~44**
declared `unsafe extern` (raw-pointer contracts the caller must uphold).

**Functions an APRV facade needs, and their rules** (VERIFIED):

| need | C function(s) | pointer / ownership rule | misuse | panics? |
|---|---|---|---|---|
| engine/config | `wasm_engine_new`, `wasm_config_new`, `wasmi_config_compilation_mode_set`, `wasmi_config_consume_fuel_set` | config consumed by engine_new | — | no |
| store | `wasm_store_new` / `wasmi_store_new`, `wasmi_store_context`, `wasmi_context_set_fuel` | `Box`; context borrows store | use-after-free if store freed first | no |
| module | `wasm_module_new`, `wasm_module_validate` | reads a `wasm_byte_vec_t` | returns NULL on invalid | no |
| imports | `wasm_functype_new`, `wasm_func_new_with_env` | `Box` transfer; env `*mut c_void` + finalizer | — | `wasm_functype_new` panics on a null elem the facade never passes |
| instance | `wasm_instance_new`, `wasm_instance_exports` | imports vec by `*const`; trap out-param | wrong import order/arity → trap, not UB | no |
| memory | `wasm_memory_data`, `wasm_memory_data_size` | raw `*mut u8` into live store memory | dangling if read after store mutation/free | data/size: no; `wasm_memory_size` (pages) aborts >u32::MAX |
| call | `wasm_func_call` | params/results `wasm_val_vec_t` | guest trap or panic → returns a trap (catch_unwind) | contained |
| free | `wasm_*_delete` | `Box` drop | double free if called twice | no |

**Unsupported / always-abort functions (the 76), grouped** (VERIFIED): the
whole `wasm_ref_*` reference-type family (`wasm_ref_as_*`, ~30), every
type's `*_same` / `*_get_host_info` variants generated by `declare_ref!`,
all of `wasm_frame_*` (backtrace frames), `wasm_trap_origin`/`_trace`,
`wasm_foreign_new`, and `wasm_module_serialize`/`_deserialize`. Full list
in `results/capi-functions.tsv` (`panics=unimplemented`). **None is on the
APRV path**, and a facade that never calls them never hits them.

**Panics do not unwind across FFI (VERIFIED).** MSRV 1.86 ⇒ a panic that
reaches an `extern "C"` frame aborts (defined behavior since Rust 1.81), so
every `unimplemented!`/`panic!` above is a clean process abort, not UB.
`wasm_func_call` further wraps the guest in `catch_unwind` (std) and turns
a panic into a trap. The known C-API crash on record (issue #1921,
"C-API debug build segfault", closed via #1950) was an alignment issue in
the *debug* dispatch build and is not a release-build memory-safety hole
(DOCUMENTED).

### Verdict: narrow Rust cdylib over the generic C API

**Use a narrow APRV-specific Rust cdylib, not the generic C API.** Reasons,
in order of weight:

1. **Smaller Python-visible `unsafe` surface.** The generic C API makes
   Python own ~44 `unsafe extern` entry points, the `wasm_val_vec_t` /
   `wasm_byte_vec_t` / `wasm_ref_t` `Box`-ownership and free discipline, and
   303 symbols of which 76 abort. A cdylib exposing ~10 functions
   (`aprv_new/free`, `aprv_call(ptr,len)->(ptr,len)`, `aprv_result_free`,
   the two host imports wired in Rust) reduces the ctypes contract to one
   opaque handle plus pointer+len byte buffers — the same tiny ABI the
   plan already defines for the guest.
2. **The isolation knobs live in Rust, not in C.** The C API has setters
   for compilation mode and fuel, but **none** for stack height
   (`Config::set_max_stack_height`/`set_max_recursion_depth`), memory-page
   limits (`StoreLimitsBuilder::memory_size` + `Store::limiter`), or
   switching off Wasm proposals the module does not use (the
   `Config::wasm_*` switches). A cdylib sets all of them at construction; over the C API
   they are simply unreachable.
3. **`unsafe` surface of the cdylib itself is minimal and auditable:** the
   FFI boundary (pointer+len in, pointer+len out, one `Box`-as-handle) is
   the only `unsafe` you write; everything inside is the safe Wasmi Rust
   API (`Engine`, `Config`, `Store`, `Linker`, `Memory`, `Func::wrap`,
   `TypedFunc::call`). Wasmi's own `wasm_func_call` shows the one pattern to
   copy: `catch_unwind` around the call so a Wasmi panic becomes an error
   code, never an unwind into CPython.
4. **Simpler, not just safer:** ~100–200 lines vs. binding, ordering and
   freeing the generic C vector/ref types from Python.

The only thing the generic C API buys is not writing Rust; given this
project already compiles Rust for the guest, that is not a saving. Do not
productize either here — this is the recommendation, not an implementation.

## Audit and security history (VERIFIED unless marked)

**Independent audits** (`results/audits.txt`, both PDFs shipped in the tag;
sha256 recorded in `results/crates.txt`):

- **SRLabs for Parity Technologies, v0.31.0, "v1.3 – Dec 20, 2023."**
  Manual review + two new **differential fuzzing harnesses vs Wasmtime**
  (one for execution correctness, one for gas/fuel). "No issues were
  uncovered during this dedicated audit workstream for the Wasmi Rust
  implementation." Recommended continuous fuzzing.
- **Runtime Verification Inc. for the Stellar Development Foundation,
  v0.36.0 (`02621ad7`), delivered Nov 27 2024, 8 weeks.** Focus: the
  executor + translator, and "many instances of `unsafe` code in the
  upgraded executor crate" — a per-site review of the **112** `unsafe`
  uses then in scope. Findings: C1 (Low, fixed), C2 RegisterAlloc bounds
  (Low, not addressed), C3 fuel truncation (Low, not addressed), **C4
  (High)** unbounded `count` into `<*mut/*const T>::offset/add` can
  overflow `isize` on small-word targets (acknowledged, deferred to
  `extra-checks`), plus 8 fuzzing findings F1–F8 (F1 High `realloc()`
  abort / heap OOB write, F5/F6 High output mismatches vs Wasmtime — all
  "Addressed by client"). "All crashes and output differences have been
  fixed."

**Architectural change since the last audited release, and what is
unaudited** (VERIFIED from CHANGELOG + source): everything after v0.36 is
unaudited, and it is a lot — the complete new IR + accumulator-register
executor (#1655, #1827, #1855), fixed 64-bit cells (#1755), tail-call
`auto-dispatch` (#1968), the lock-free append-only `CodeMap` (#1898,
#1893), the new `InstanceEntity` layout + cache (#1940, #1996, #1997),
lazy translation, stable input-bytecode fuel (#2013), and the `validate`/
`memory64`/`debug` feature splits. The 220 class-A `unsafe` sites all live in this unaudited code. 2.0.0 is
also brand-new: crates.io shows `2.0.0` published **2026-09-01**, a final
release after `2.0.0-beta.0..10`, not yanked (VERIFIED).

**Advisories** (`results/advisories.txt`; OSV = GitHub Advisory DB +
RustSec, queried 2026-09-27; RustSec DB clone `e211151`; Wasmi's GHSA page
read by hand):

- wasmi-family crates (`wasmi`, `wasmi_core`, `wasmi_ir`,
  `wasmi_collections`, `wasmi_c_api_impl`, `wasmi_c_api_macros`): **no
  advisory affects 2.0.0.** The two historical Wasmi advisories both
  predate it: CVE-2024-28123 (OOB write >128 host→Wasm params, ≤0.31.0) and
  **CVE-2025-66627** (critical linear-memory use-after-free, 0.41.0–1.0.0,
  fixed 1.0.1/0.51.3/0.47.1/0.41.2; the `ByteBuffer::grow` fix `0e6f0d2` is
  carried into 2.0.0).
- transitive: `wasmparser` 0.228.0, `libm` 0.2.16, `bitflags` 2.13.2 —
  none. **`spin` 0.9.9** — RUSTSEC-2019-0013 (RwLock, fixed ≥0.5.2, not
  applicable), RUSTSEC-2023-0031 (`Once::try_call_once` unsound, fixed
  **0.9.8**; 0.9.9 ≥ 0.9.8, so **not affected**), RUSTSEC-2019-0031
  (`spin` "no longer actively maintained" — informational). Wasmi uses
  `spin::Mutex` only for the `CodeMap` alloc lock. No action needed, but
  the unmaintained note is a supply-chain watch item.

**Fuzzing** (`results/upstream-testing.txt`, VERIFIED from the tag):
in-repo `cargo-fuzz` targets `translate`, `execute`, `differential`;
differential oracles for **Wasmtime and Wasmi v1** (`crates/fuzz/src/oracle/`),
with `wasm-smith`-generated modules across all three compilation modes
(Lazy/LazyTranslation/Eager chosen per input). **Enrolled in OSS-Fuzz**
(`google/oss-fuzz/projects/wasmi`, ASan + libFuzzer, builds all three
targets `--all-features`). CI also runs each target 180 s per push and runs
**Miri** over the workspace lib/doc tests and a nightly cron Miri pass over
the whole Wasm spec suite (`miri.yml`). Reciprocally, **Wasmtime's** own
fuzzing has a `diff_wasmi` oracle, though its tree currently pins wasmi
**1.0.8** (DOCUMENTED), so Wasmtime-side differential coverage of 2.0.0 is
not yet in effect. One gap worth naming: the `execute`/`differential`
harnesses instantiate with an **empty `Linker`**, so a generated module
that imports anything (including two memories) fails to instantiate and is
skipped — i.e. the finding-3 shape is outside what the in-repo fuzzers
currently exercise (VERIFIED).

**Spec-test coverage** (VERIFIED): `crates/wast/tests/mod.rs` drives the
official `WebAssembly/testsuite` submodule (pin `d76759e`) — 357 test
files, run in `buffered` and `fueled` modes, plus dedicated
`multi_memory`, `memory64`, `custom_page_sizes` and `missing_features`
modules; proposals enabled include multi-memory (48 entries), memory64
(25), tail-call, extended-const, custom-page-sizes, relaxed-simd,
wide-arithmetic and SIMD (65). Only one test is `#[ignore]`d (a slow
"torture" stack loop, run in a separate CI step). The README claims 100%
spec-suite compliance (DOCUMENTED). Note the spec harness runs in
`CompilationMode::Eager` (VERIFIED); the plan's `LazyTranslation` default
is the fuzzers' concern, not the spec suite's.

**Differential testing:** present and active (Wasmtime + wasmi-v1 oracles,
above) — the strongest single signal for a young executor, and the same
technique both audits leaned on.

## Verdict

**Wasmi 2.0.0 is a sound choice as the sandbox boundary for this specific
use, with conditions.** Its isolation model is the right shape for embedding
in CPython: explicit software bounds checks on every linear-memory access
(no guard pages, no signal handler), deterministic traps, a tiny RSS, and a
clean panic=abort story across the FFI. Its memory safety rests on a large
body of `unsafe` (220 class-A executor sites) whose correctness is the
translator's, and that body is **new and unaudited** — the two independent
audits stop at v0.36, three generations back, and a critical linear-memory
use-after-free (CVE-2025-66627) lived in the still-current `ByteBuffer` as
recently as the 1.0 line. During this review one further issue was found
and reported privately upstream (finding 3); it is not reachable by
`aprv.wasm`, but it is a reminder that the
post-0.36 executor has un-audited corners. Net: acceptable **because** the
threat model is a single trusted module (`aprv.wasm`) that APRV builds
itself, run one-thread-per-instance, not arbitrary attacker modules — and
**only if** the embedding pins the module, keeps validation on, and applies
the limits below. It is mature and active (2.0.0 is 2026-09-01; upstream
fuzzes, runs Miri nightly and is in OSS-Fuzz), which meets the dependency-
quality bar; the caveat is the audit coverage, not the maintenance.

**Binding: build a narrow APRV-specific Rust cdylib over the safe Wasmi
Rust API — do not expose the generic Wasm C API to Python.** It shrinks the
Python `unsafe` surface to one handle plus two byte buffers, keeps the
isolation knobs reachable (they are not, over the C API), avoids the 76
process-aborting C entry points entirely, and is smaller.

**Concrete embedding requirements that follow from this review:**

1. **`panic = "abort"` in the cdylib's release profile**, and wrap every
   guest call in `catch_unwind` (as Wasmi's own `wasm_func_call` does) so a
   Wasmi panic becomes an APRV error code, never an unwind into CPython.
2. **Fuel on** (`Config::consume_fuel(true)` + `Store::set_fuel`) with a
   per-call budget; it is the only bound on a runaway/adversarial guest and
   it is stable in 2.0.0.
3. **Set explicit limits** at construction (only reachable from Rust):
   `Config::set_max_stack_height` / `set_max_recursion_depth` (defaults are
   1,000 frames / 1,000,000 cells — cap them to what `aprv.wasm` needs),
   and `StoreLimitsBuilder::memory_size(...)` + `Store::limiter(...)` to cap
   linear-memory pages.
4. **Disable Wasm features `aprv.wasm` does not use**, every
   `Config::wasm_*` proposal switch off the module's surface; keep `Config::validate` on
   (never `Module::new_unchecked`).
5. **Consider building the cdylib with the `extra-checks` crate feature**
   (~20% slower, DOCUMENTED) at least for a hardened build: it turns the 14
   A-assume `unreachable_unchecked!` sites and the executor's other elided
   checks from release-mode UB into panics-then-aborts. Round 11 can
   measure whether the cost is acceptable given the owner's usable band.
6. **Pin the exact versions and verify hashes** (`results/crates.txt`):
   `wasmi`/`wasmi_core`/`wasmi_ir`/`wasmi_collections`/`wasmi_c_api_impl`
   all `2.0.0`, `wasmparser 0.228.0`, `spin 0.9.9` (≥0.9.8, clears
   RUSTSEC-2023-0031). Add `cargo-audit`/`cargo-deny` to CI so a future
   advisory against this graph (spin is unmaintained) is caught.
7. **One thread per `Store`/instance** — APRV already does this; it keeps
   the class-B/C concurrency `unsafe` (lock-free `CodeMap`, `Send/Sync`
   impls) off the hot path.
8. **Finding 3 was reported privately upstream on 2026-09-27.** Re-check
   for a fixed release before shipping, and add its details to this note
   once upstream has published them.
