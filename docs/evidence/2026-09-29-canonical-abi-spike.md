# The canonical ABI as aprv.wasm's export ABI

Date: 2026-09-29. Code, scripts and raw results are in
`2026-09-29-canonical-abi-spike/`. Its `README.md` has the file table and
the commands to reproduce.

**Question.** Can `aprv.wasm` expose its four operations through the
canonical ABI (the Component Model's rulebook) on the same `wasm32-wasip1`
core module, such that:

- hosts without component support call the core exports by hand in a few
  lines;
- hosts with component support get generated bindings;
- the crypto does not change;
- all 6,179 rows stay byte-identical;
- size and start-up cost nothing measurable against the ABI v1 module
  (`b14e14b2…36b3`)?

The owner's choice of export ABI depends on the answer. This is a spike, time-boxed to about half a
day. Nothing under `rust/` or any other production path changed.

Labels: TESTED (ran here), EXPECTED (inferred, not run).

## Verdict: PASS WITH CAVEATS

| Criterion | Result |
|---|---|
| Hand-rolled hosts, few lines | **Yes (TESTED).** The string call is 19 lines in Go (wazero) and 12 in Java (Endive). With the `random-get` import the whole marked region is 38 and 35 lines |
| Generated bindings | **jco: yes. wasmtime-py: no generator (TESTED).** jco 1.35.0 transpiles the component with no adapter, and the Node host is 9 lines. wasmtime-py 49.0.0 has no `bindgen` any more. Its last release that has one (38.0.0) panics on this component. wasmtime-py's run-time-typed `wasmtime.component` API works instead, with no generated code, in 15 lines |
| Crypto unchanged | **Yes (TESTED).** The same core tree. A rebuild of ABI v1 from it is byte-identical to b14e14b2, and 5,933 of 6,179 rows are byte-identical |
| 6,179 rows byte-identical | **No, as written: 246 rows differ. All 246 come from the interface itself (TESTED).** 0 rows are unexplained. All five host runs agree with each other on all 6,179 rows |
| No measurable size or start-up cost | **Small but measurable (TESTED).** Stripped size is +0.47% (+12.6 KB) as generated, +0.90% checked. On wazero, runtime plus compile is +2 to 4%. First call and throughput are within noise |

The caveats that matter for the decision, in order:

1. **The generated release-mode lifts trust the caller.** In release,
   wit-bindgen 0.62.0 lifts strings with `from_utf8_unchecked` and the enum
   with `transmute`. It checks both only under `debug_assertions`. A
   hand-rolled host that passes a bad enum or non-UTF-8 bytes therefore
   gets undefined behaviour, not a trap. Turning `debug-assertions` on for
   the guest crate alone makes all of these trap, for +0.43% size. Use the
   checked build if this route is chosen.
2. **Heap misuse is not caught.** In either variant, a foreign argument
   pointer (the guest frees it) and a second post-return on the same result
   return normally, with the allocator silently corrupted. ABI v1's handle table
   trapped on a double free and on an invalid or stale handle. Component
   runtimes cannot make these mistakes. Hand-rolled hosts can.
3. **The return area is one static 8-byte slot.** A second call before the
   first result is read overwrites the first result's (ptr, len). This is
   harmless for one call at a time per instance, which is the model anyway.
4. **Two extra exports.** `aprv_clock_now_ms` and `aprv_random_get` leak
   out as exports. They are the Rust definitions of the two C symbols that
   `wasi-none.c` calls, and a `#[no_mangle]` item in a Rust cdylib is
   exported even when it is not `pub`. This is cosmetic. It could be fixed
   in the C file or with a post-link strip; not done here.
5. **Tool quirks.**
   - jco's glue reads the unversioned import key (`aprv:verifier/host`),
     while its own `.d.ts` declares `aprv:verifier/host@1.0.0`. Passing
     only the declared key throws.
   - wasmtime-py accepts negative and over-range u64s, which ctypes wraps.
   - wasmtime-py poisons the instance ("cannot enter component instance")
     after the host passes an invalid enum name.

## The module

Build: wit-bindgen 0.62.0 (Rust guest, `generate!`), rustc 1.98.1,
wasi-sdk 34.0, ABI v1's exact RUSTFLAGS and Route C `wasi-none.c` object,
then `wasm-tools component new` with **no adapter**
(`results/build.txt`). The module has no WASI imports left to adapt.

Core module interface (`results/build.txt`):

```text
import  "aprv:verifier/host@1.0.0" "random-get"                     (len i32, retptr i32) -> ()
export  "aprv:verifier/verify@1.0.0#init"                            (ptr i32, len i32) -> retptr i32
export  "aprv:verifier/verify@1.0.0#verify-receipt"                  (now i64, ptr, len) -> retptr
export  "aprv:verifier/verify@1.0.0#verify-signed-data"              (now i64, ptr, len) -> retptr
export  "aprv:verifier/verify@1.0.0#verify-receipt-endpoint"         (env i32, now i64, ptr, len) -> retptr
export  "cabi_post_aprv:verifier/verify@1.0.0#<each of the four>"   (retptr) -> ()
export  "cabi_realloc" (old, old_size, align, new_size) -> ptr      (+ cabi_realloc_wit_bindgen_0_62_0)
export  memory, _initialize, aprv_clock_now_ms, aprv_random_get      (the last two: caveat 4)
```

- **Return area:** one static slot holding `[ptr u32 LE, len u32 LE]` of a
  UTF-8 string. It is the same address on every call (1,723,816 as
  generated, 1,729,192 checked; `results/tests-wazero.txt`).
- **Ownership:** argument buffers must come from `cabi_realloc(0, 0, 1, n)`,
  and the guest frees them. The post-return function frees the result. All
  four post-return exports alias one function.
- **Start-up:** each export runs `__wasm_call_ctors` on its first call, so
  hosts need not call `_initialize`. The component does not call it.
- **Imports:** only `random-get`, kept as a WIT import (the brief's
  preferred form) rather than the core `aprv.random_get`. The
  `aprv.clock_now_ms` import is gone: `now-ms` is an argument, and the
  guest defines the C clock symbol to return it. In the JWS test,
  `random-get` ran once (`results/tests-wazero.txt`).
- **Semantics as specified (TESTED on wazero, jco, wasmtime-py):**
  - a verify before `init` traps, and so does a second `init`;
  - a config that is not JSON, or a root that is not base64 or not a
    certificate, answers `{"ok":false,"message"}`, and `init` can be
    retried;
  - verification failures are values;
  - `now-ms` is the chain instant when the input carries no date, and
    `request_date` at the endpoint.

Sizes (`results/sizes.txt`; stripped = `wasm-tools strip --all`):

| Module | Bytes | Stripped | gzip -9 of stripped | Stripped vs ABI v1 |
|---|---|---|---|---|
| ABI v1 (b14e14b2) | 2,952,613 | 2,700,240 | 898,495 | 0 |
| canonical ABI, as generated (56edb9ee…) | 2,966,618 | 2,712,814 | 904,984 | +12,574 (+0.47%) |
| canonical ABI, checked (dc4771a1…) | 2,980,266 | 2,724,537 | 908,243 | +24,297 (+0.90%) |
| component, as generated (16c4796f…) | 2,969,167 | 2,714,549 | 905,990 | +14,309 (+0.53%) |
| component, checked (cda89d47…) | 2,982,815 | 2,726,272 | 909,011 | +26,032 (+0.96%) |

- As generated, the growth is +10.1 KB of code and +2.1 KB of data. The
  checked variant adds +16.4 KB of code and +7.5 KB of data (the
  assertion paths and messages).
- The component wrapper adds 2,549 bytes, and its type section is 467
  bytes.
- jco's output is the 2,979,769-byte core module plus two small shim
  modules (186 and 181 bytes) and `aprv.js`: 130,734 bytes, or 63,523
  with `--minify` (`results/jco-transpile.txt`).

## Corpus parity (`results/corpus-*.txt`, `results/classify.txt`)

`py/calls_cabi.py` maps each ABI v1 call onto the new interface:

- an ABI v1 test envelope's anchors become the `init` config;
- its pinned clock becomes `now-ms`;
- the wall clock is used otherwise.

Each host ran all 6,179 rows. Each result was compared byte for byte with
ABI v1's Node rows, with `request_date*` masked where the clock is the wall
clock.

| Category | Rows | Why |
|---|---|---|
| identical | 5,933 | |
| not-a-string (verify-signed-data) | 243 | ABI v1's input was not UTF-8, so a WIT `string` cannot carry it. The row passes U+FFFD-replaced text. ABI v1 answered `jws is not valid UTF-8`. Now 241 rows keep the reason `INVALID_JWS_FORMAT` with a different message, and 2 rows answer `INVALID_CERTIFICATE`. The other 61 lossy rows (20 receipt, 41 endpoint) are identical |
| clock-moves-chain | 2 | `endpoint/injected-clock-cannot-{authenticate-an-expired,expire-a-valid}-chain`. ABI v1 (core 0.6) used a pinned clock only for `request_date`. `now-ms` is also the chain instant (the 0.7 rule), so both verdicts flip exactly as 0.7 specifies |
| init-refusal | 1 | `hostile/ctor/root-not-a-cert`. ABI v1 said `INVALID_TEST_ENVELOPE` per call. `init` now answers `{"ok":false,"message":"roots[0]: trust anchor is not a certificate"}` |
| DIFFERENT | **0** | |

- The distribution is the same on wazero (checked and as generated),
  Endive, jco and wasmtime-py, per corpus as well as in total.
- Row by row against wazero, every other host is identical on 6,179 of
  6,179 rows. There were 0 traps on any host.
- Wall time for all five corpora: wazero 23 s, Endive 55 s, jco 14 s,
  wasmtime-py 17 s.

## Hand-written host code (`results/count.txt`)

These are non-blank, non-comment lines between each host's
`(hand-written) begin/end` markers.

| Host | Whole region | The string call alone | What the region holds |
|---|---|---|---|
| wazero (Go), by hand | 38 | 19 (`Guest.Call`, with error returns) | Guest type, `random-get` import, `Call` |
| Endive (Java), by hand | 35 | 12 (`call`) | fields, `random-get` import, 5 lines of instance builder, `call` |
| jco (Node), generated | 9 | 0 (`verify.verifyReceipt(nowMs, text)`) | glue import, core-module loader, `random-get` |
| wasmtime-py, run-time typed | 15 | 2 | instantiate, export lookup, call, `random-get` |

A hand-rolled string call is always the same six steps:

1. `cabi_realloc(0, 0, 1, n)`;
2. write the argument;
3. call with (scalars…, ptr, len);
4. read (ptr, len) at the returned address;
5. copy the result out;
6. call `cabi_post_…`.

The `random-get` import is the reverse: `cabi_realloc` in the guest, fill
the buffer, write (ptr, len) at `retptr`.

## Misuse and isolation

**Hand-rolled, on wazero (`results/tests-wazero.txt`, 27 and 26 checks:
follow-ups run only after a misuse that did not trap).** Both variants
pass:

- trap on verify-before-init and on a second init;
- `ok:false` on a bad config, then a successful retry;
- the three operations on real inputs;
- an argument range past the end of memory, or overflowing u32, traps (OOB);
- 300 calls without post-return leak (1,769,472 → 2,752,512 bytes). With
  post-return, 2,000 calls do not grow memory;
- a wrong-length `random-get` answer traps;
- a trap in one instance leaves another untouched.

Where the two variants differ:

| Misuse | As generated | Checked |
|---|---|---|
| enum value 2, 255, 0xFFFFFFFF | returns a value, core error (value 2 decoded as a third case: UB) | trap |
| string argument not UTF-8 | returns a value (the body re-checks UTF-8) | trap |
| post-return with a never-returned pointer (0) | no trap | trap |
| argument pointer not from `cabi_realloc` | no trap, and the guest frees it | no trap, and the guest frees it |
| post-return twice on one result | no trap (double free) | no trap (double free) |

**Component hosts.** The runtime removes the whole table above. A caller
cannot write a pointer, a length or a post-return:

- **jco** (`results/tests-jco.txt`):
  - an unknown enum case throws a `TypeError` at the binding;
  - traps surface as `RuntimeError`;
  - a lone surrogate is encoded as U+FFFD, and the endpoint answers
    `{"status":21002}`;
  - a `Number` or a negative `BigInt` is accepted for the u64.
- **wasmtime-py** (`results/tests-wasmtime-py.txt`):
  - traps surface as `WasmtimeError`, and the trapped instance refuses
    further calls;
  - an unknown enum name is refused, but it also poisons that instance;
  - a lone surrogate fails in Python's encoder before the call;
  - -1 and 2^64 pass as u64 (ctypes wraps them);
  - 2,000 calls under a 4 MiB memory limit with no post-return in host
    code succeed. Wasmtime runs post-return itself since
    bytecodealliance/wasmtime#12498 (merged 2026-02-03), which made
    `post_return` a deprecated no-op.

## Timing (`results/bench-wazero.txt`)

wazero 1.12.0, `taskset -c 0`, medians of 7 start-ups. Rates are
single-thread calls per second.

| Pair | Runtime + compile | First g5 | Steady g5/s | Steady JWS/s |
|---|---|---|---|---|
| ABI v1 / checked | 1,257.6 / 1,310.8 ms (+4.2%) | 10.86 / 12.13 ms | 221.4 / 248.5 | 73.9 / 72.9 |
| ABI v1 / as generated | 1,263.4 / 1,291.0 ms (+2.2%) | 12.32 / 9.96 ms | 229.2 / 239.5 | 78.8 / 81.9 |

- Compile time grows about as much as the code does.
- First-call and steady numbers swing both ways between runs of the same
  module, so they are noise.
- jco, for scale: 375 to 424 ms from importing the glue to the first
  result, with a 36 to 39 ms first call.
- wasmtime-py (Cranelift): Engine plus component compile takes 1.19 to
  1.35 s.
- Neither of those two was compared against ABI v1.

## Blockers and where they belong

| Issue | Belongs to |
|---|---|
| Unchecked lifts in release (caveat 1) | wit-bindgen (by design; `debug_assertions` is the switch) |
| No trap on foreign pointer or double post-return (caveat 2) | canonical ABI design: it trusts the lowering side; wit-bindgen adds no guard |
| Extra exports (caveat 4) | our code (the `#[no_mangle]` definitions) |
| `wasmtime.bindgen` gone | wasmtime-py: removed by bytecodealliance/wasmtime-py#310 (merged 2025-11-05). 38.0.0 (2025-10-20) is the last release that ships it, 39.0.0 (2025-11-20) the first without |
| 38.0.0's bindgen panics on this component | wasmtime-py (retired tool): `rust/src/bindgen.rs:1226`, `self.gen.exports.get_mut(ns).unwrap()`. Not investigated further (`results/bindgen-wasmtime-py.txt`) |
| Import-key mismatch in the glue | jco 1.35.0 |
| u64 range not checked | jco (BigInt) and wasmtime-py (ctypes) bindings |
| Instance poisoned after a bad enum name | Wasmtime (host-side lowering errors count as traps) |
| The 246 differing rows | the interface as specified (the `string` type, the `now-ms` rule, `init`), not a tool |

wasm-tools had no blockers: `component new` needed no adapter.

## Versions (`results/versions.txt`)

- Build: rustc 1.98.1; wit-bindgen 0.62.0 (crate and CLI); wasm-tools 1.259.0; wasi-sdk 34.0 (clang 23.1.0).
- Go host: wazero 1.12.0, built with go1.25.0 (fetched by GOTOOLCHAIN from go.mod; the installed go is 1.24.7).
- Java host: Endive 1.1.0 on OpenJDK 21.0.10.
- Node host: Node 22.22.2 with jco 1.35.0.
- Python host: wasmtime-py 49.0.0 on Python 3.11.15.
- Machine: x86_64.

## Not tested

- WasmKit (Swift), and every other hand-rolled host besides Go and Java.
- The misuse table on Endive. Endive ran the corpus only; the ABI is the
  same bytes as on wazero.
- Endive and jco start-up against ABI v1. Start-up was compared on wazero
  only.
- Rust Wasmtime with `bindgen!`, Deno, Bun, browsers.
- aarch64 and big-endian hosts.
- Concurrency: one instance runs one call at a time, as in ABI v1.
- A 0.7 core. This spike used ABI v1's 0.6 tree to keep the crypto fixed.
  The 0.7 API would change the guest glue, not the ABI (EXPECTED).
- Why 38.0.0's bindgen panics, beyond the source line.
- A fix for the extra exports.

## Limits

- The numbers come from one x86_64 machine on 2026-09-29, with the tool
  versions above.
- The size and start-up deltas describe this module. A different core
  changes the absolute sizes but not the glue's roughly 10 to 25 KB
  (EXPECTED).
- "Byte-identical" is measured against ABI v1's Node rows, and ABI v1 is
  core 0.6. The two clock rows would match a 0.7 reference (EXPECTED from
  the 0.7 rule, not run).
