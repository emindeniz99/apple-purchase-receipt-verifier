# The canonical ABI, final check before the plan

Date: 2026-09-29. Code, scripts and raw results are in
`2026-09-29-canonical-abi-final/`. Its `README.md` has the file table and
the commands to reproduce. This round follows round 12
(`2026-09-29-canonical-abi-spike.md`, commit 10fc088), which is unchanged.

**Question.** With the owner's changes to round 12's interface, does
`aprv.wasm`'s canonical-ABI export give the expected answers on every
host? The changes:

1. The four inputs become `list<u8>`; outputs stay `string`.
2. `env` becomes a `u32`, and the guest traps on anything but 0 or 1.
3. The two internal exports stay.
4. jco gets only its documented unversioned import key.

The expected answers: exactly 6,176 of 6,179 rows byte-identical to the
ABI v1 reference, plus the 3 intended differences. The hosts:

- hand-rolled: Endive, wazero, WasmKit;
- typed: jco on Node, Deno and Bun, wasmtime-py, and Rust Wasmtime 49 with `bindgen!`.

The Rust host also answers the question that decides aprv-server's shape:
can a runtime-only Wasmtime (no Cranelift) load a precompiled component
the way aprv-server loads its core-module `.cwasm` today?

Labels: TESTED (ran here), EXPECTED (inferred, not run).

## Verdict: PASS

- **Parity: as expected on all eight host runs (TESTED).** Every run
  gives 6,176 identical rows, 2 `clock-moves-chain` rows and 1
  `init-refusal` row. The hosts are wazero, Endive, WasmKit, jco on Node,
  Deno and Bun, wasmtime-py and Rust Wasmtime.
  - Round 12's 243 not-a-string rows are now identical, because the
    guest answers `jws is not valid UTF-8` as ABI v1 did.
  - Row by row, every host matches wazero on 6,179 of 6,179 rows, with
    0 traps (`results/classify.txt`).
- **Misuse tests: all expected traps happen (TESTED).**
  - On wazero, Endive, WasmKit and Rust Wasmtime, each of these traps:
    env 2, env 255, env 2^32-1, verify before init, a second init, and
    a wrong-length `random-get`.
  - A trap in one instance leaves a second instance verifying.
  - A foreign pointer or a double post-return does not trap, as round 12
    expected; details below.
- **aprv-server can host the component (TESTED).** Wasmtime 49.0.1 with
  `runtime` + `std` + `component-model` and no `cranelift` does these
  steps:
  - it deserializes an embedded precompiled component (`.ccwasm`,
    through `include_bytes!`);
  - it instantiates it through the `bindgen!` bindings;
  - it verifies g5.

  In-process time to the first result is 14 ms, the same as today's
  core-module `.cwasm` in aprv-server B's feature set. The cost is a
  30% larger engine: +328,528 bytes, or +143,633 gzipped. One condition
  applies: the engine that precompiles and the engine that loads must
  agree on wasm features (finding 1).
- **Sizes and start-up: small (TESTED).**
  - Module: stripped core +0.47% against ABI v1.
  - wazero start-up: first result +3.2%, with throughput equal.
  - Endive, WasmKit and Bun: within noise.
  - jco on Node and Deno: +8% for loading the glue, compiling and the
    first call, which is 8 to 11 ms.

## Findings to carry into the plan

1. **A precompiled file is tied to the wasm features of the engine that
   wrote it (TESTED, `results/wasmtime-rs-features.txt`).**
   - With the `component-model` cargo feature compiled in,
     `Config::new()` turns the `component_model` wasm feature on.
   - A core `.cwasm` written by such an engine is refused by aprv-server
     B's runtime (no component-model): `Module was compiled with support
     for WebAssembly feature component_model but it is not enabled for
     the host`.
   - The reverse direction works: a runtime with component-model loads a
     `.cwasm` written without it.
   - So whichever artifact aprv-server ships, its `precompile` step must
     run with the same Wasmtime features as the runtime that loads it.
   - The runtime refuses a mismatch at load time, before anything runs;
     it is not a silent failure.
2. **`env: u32` gives up the binding-level check that round 12's enum
   had (TESTED, `results/tests-jco.txt`,
   `results/tests-wasmtime-py.txt`).**
   - jco applies JavaScript's ToUint32 without a range check:
     - `2**32 + 1` → 1 (sandbox);
     - `1.5` → 1;
     - a string such as `"sandbox"` → 0, which is **production** and
       answers `{"status":21007}`.
   - wasmtime-py writes the int into a ctypes field unchecked: `-1`
     becomes 2^32-1 and traps in the guest; `2**32 + 1` becomes 1.
   - Only values that land outside {0, 1} reach the guest's trap.
     Round 12's enum threw a `TypeError` at the binding for any unknown
     name.
   - The same wrapping applies to `now-ms` (u64) in both bindings.
   - jco also accepts a JS string where the WIT says `list<u8>` and
     silently passes wrong bytes; the g5 text answers
     `INVALID_RECEIPT_FORMAT`.
   - wasmtime-py rejects a `str` there with a `TypeError`.
   - Rust's generated bindings are checked at compile time.
3. **wasmtime-py lowers `list<u8>` one element at a time in Python
   (TESTED, `results/wasmtime-py-bytes.txt`).**
   - It costs about 1.1 µs per input byte: 1.1 ms per KB, 107 ms per
     100 KB.
   - The corpus took 226 s on wasmtime-py, against 17 s with round 12's
     string inputs.
   - The cause is `ListType.convert_to_c` in wasmtime-py 49.0.0. The
     guest and Wasmtime are not involved.
   - A Python package built on this API needs an upstream fast path for
     bytes, or a native binding.
4. **Only component runtimes stop using an instance after it traps
   (TESTED).**
   - jco, wasmtime-py and Rust Wasmtime refuse further calls ("cannot
     enter component instance").
   - wazero, Endive and WasmKit let the trapped instance keep answering.
     A hand-rolled host must discard it itself, as every runner here
     does.
5. **Heap misuse is still silent on hand-rolled hosts (TESTED,
   `results/tests-{wazero,endive,wasmkit}.txt`).** The results are the
   same on all three:
   - A double post-return on one result does not trap. The instance
     keeps verifying afterwards, but its allocator has freed the block
     twice.
   - A post-return on a foreign heap block traps out of bounds, because
     that block's bytes were read as a (ptr, len).
   - A foreign block whose first 8 bytes happen to form an in-range
     (ptr, len) would free an arbitrary block (EXPECTED, not run).
   - Component runtimes cannot make either mistake.
6. **Deno needs `--allow-env=JCO_DEBUG` (TESTED).**
   - jco 1.35.0's glue reads `process.env.JCO_DEBUG` on every call.
     Under `deno run --allow-read` alone, every call throws
     `NotCapable`.
   - With the grant, Deno matches Node row for row.
   - Bun needed nothing. It words traps and BigInt errors differently
     (JavaScriptCore messages), and its first call is slower (152 ms,
     against 69 ms on Node).
   - Module loading (dynamic `import()` of the glue, which itself imports
     nothing), `BigInt` for u64 and `TextDecoder` behave the same on all
     three: the rows are identical.
7. **The two internal exports**, `aprv_clock_now_ms` and
   `aprv_random_get`, are the Rust definitions of the symbols
   `wasi-none.c` calls. A Rust cdylib exports every `#[no_mangle]` item.
   They are not part of the interface, and no host calls them.
8. **jco's typings name the import key with the version**
   (`'aprv:verifier/host@1.0.0'` in `aprv.d.ts`), while the glue reads the
   documented unversioned key. The runner passes only the unversioned
   key, as jco's documentation says. This is an inconsistency in the
   typings only.

## The module (`results/build.txt`, `results/sizes.txt`)

The build: wit-bindgen 0.62.0, rustc 1.98.1, wasi-sdk 34.0, ABI v1's
RUSTFLAGS and `wasi-none.c`, then `wasm-tools component new` with no
adapter. `wire_view.rs` is identical to ABI v1's.

```text
init:                    (ptr, len) -> retptr
verify-receipt:          (now i64, ptr, len) -> retptr
verify-signed-data:      (now i64, ptr, len) -> retptr
verify-receipt-endpoint: (env i32, now i64, ptr, len) -> retptr
cabi_post_<each>, cabi_realloc, memory, _initialize; internal: aprv_clock_now_ms, aprv_random_get
import "aprv:verifier/host@1.0.0" "random-get" (len, retptr)
```

| Module | Bytes | Stripped | gzip -9 of stripped | Stripped vs ABI v1 |
|---|---|---|---|---|
| ABI v1 (b14e14b2) | 2,952,613 | 2,700,240 | 898,495 | 0 |
| core (da786ac8…) | 2,967,116 | 2,713,063 | 905,373 | +12,823 (+0.47%) |
| component (d507c2b2…) | 2,969,558 | 2,714,655 | 906,024 | +14,415 (+0.53%) |

The core module's code section is +10,354 bytes and its data section
+2,064 bytes against ABI v1.

## Parity (`results/corpus-*.txt`, `results/classify.txt`)

| Host | identical | clock-moves-chain | init-refusal | other | Corpus wall |
|---|---|---|---|---|---|
| wazero 1.12.0 (Go), by hand | 6,176 | 2 | 1 | 0 | 23 s |
| Endive 1.1.0 (Java), by hand | 6,176 | 2 | 1 | 0 | 54 s |
| WasmKit 0.4.0 (Swift), by hand | 6,176 | 2 | 1 | 0 | 101 s |
| jco 1.35.0 on Node 22.22.2 | 6,176 | 2 | 1 | 0 | 14 s |
| jco 1.35.0 on Deno 2.9.7 | 6,176 | 2 | 1 | 0 | 13 s |
| jco 1.35.0 on Bun 1.3.11 | 6,176 | 2 | 1 | 0 | 27 s |
| wasmtime-py 49.0.0 | 6,176 | 2 | 1 | 0 | 226 s (finding 3) |
| Rust Wasmtime 49.0.1, `bindgen!` | 6,176 | 2 | 1 | 0 | 30 s |

- `clock-moves-chain` covers the two
  `endpoint/injected-clock-cannot-…-chain` rows. Their verdicts flip
  under the 0.7 now-ms rule.
- `init-refusal` is `hostile/ctor/root-not-a-cert`: `init` answers
  `{"ok":false,…}` where ABI v1 said `INVALID_TEST_ENVELOPE`.
- Both are as in round 12.
- The corpus wall column includes each runner's own JSON and base64
  work.

## Host code (`results/count.txt`)

These are non-blank, non-comment lines between each host's
`(hand-written) begin/end` markers.

| Host | Marked region | Lowering helper + call | Generated code |
|---|---|---|---|
| wazero (Go) | 85 | 66 | none |
| Endive (Java) | 57 (5 are the instance builder) | 35 | none |
| WasmKit (Swift) | 79 (bounds-checked read/write: WasmKit aborts the process on an out-of-range access) | 37 | none |
| jco | 8 | 0 | `aprv.js`, 3,800 lines, 132,241 bytes |
| wasmtime-py | 15 | 2 | none (typed at run time) |
| Rust Wasmtime, `bindgen!` | 24 | 0 | 255 non-blank non-comment lines (377 in all, 14,808 bytes) |

- Each hand-rolled helper holds a four-entry signature table: `w` for
  u32, `d` for u64, `b` for `list<u8>`.
- A wrong Go/Java/Swift type or a wrong argument count raises a host
  error before any call. This is TESTED on all three hand-rolled hosts,
  for u32 where the WIT says u64, u64 where it says u32, a number where
  it says bytes, and a missing argument.
- The Go count is the largest because of Go's `if err != nil` blocks.

## Misuse and isolation (`results/tests-*.txt`)

| Case | wazero | Endive | WasmKit | jco | wasmtime-py | Rust Wasmtime |
|---|---|---|---|---|---|---|
| env 2, 255, 2^32-1 | trap | trap | trap | trap (2; -1 wraps to 2^32-1) | trap (2; -1 wraps) | trap |
| verify before init, second init | trap | trap | trap | trap | trap | trap |
| input not UTF-8 | value | value | value | value | value | value |
| wrong host type | host error | host error | host error | coerced (finding 2) | `TypeError` for str; ints wrap | compile error |
| double post-return | no trap | no trap | no trap | n/a (runtime) | n/a | n/a |
| post-return on a foreign block | OOB trap | OOB trap | OOB trap | n/a | n/a | n/a |
| trapped instance called again | answers | answers | answers | refused | refused | refused |
| trap isolation (second instance) | ok | ok | ok | ok | ok | ok |
| `random-get` wrong length | trap | trap | trap | not run | trap | trap |

On wazero, 2,000 calls with post-return leave linear memory the same
size. On wasmtime-py, 2,000 calls under a 4 MiB limit run with no
post-return in host code.

## aprv-server: the runtime-only component path (`results/wasmtime-rs-*.txt`, `results/startup-wasmtime-rs.txt`)

The binaries are Wasmtime 49.0.1, release, LTO, stripped. Each loads the
same `Config::new()`.

| Binary | Wasmtime features | Bytes | gzip -9 |
|---|---|---|---|
| full: runs `.wasm`, precompiles | runtime, std, cranelift, component-model | 11,818,344 | 4,182,732 |
| runtime, core only, nothing embedded | runtime, std (aprv-server B) | 1,080,536 | 501,666 |
| runtime + component-model, nothing embedded | runtime, std, component-model | 1,409,064 | 645,299 |
| runtime, core only, `.cwasm` embedded | runtime, std | 9,530,392 | 3,241,921 |

| Precompiled file | Bytes | gzip -9 | Precompile |
|---|---|---|---|
| component `aprv-cabi.ccwasm` (f7cc4478…) | 8,483,936 | 2,754,364 | 3.8 s |
| ABI v1 core `.cwasm`, component_model off (6990958d…) | 8,449,864 | 2,738,879 | 3.8 s |
| ABI v1 core `.cwasm`, component_model on (09e684a1…) | 8,449,864 | 2,738,872 | 3.9 s |

- **The `.ccwasm` is +34,072 bytes (+0.40%)** against the core
  `.cwasm`.
- A binary embedding only the component would be about 1,409,064 +
  8,483,936 bytes, or 9.89 MB. That figure is EXPECTED from the sum and
  was not built. The binary built here embeds both files for the
  comparison: 18,343,240 bytes.
- The no-component-model `.cwasm` has the same size as aprv-server's
  recorded artifact but a different hash (`31ca2603…` there). This was
  not investigated. The file records the engine that wrote it.

Start-up used seven fresh processes per case, `taskset -c 0`, with the
precompiled files embedded (medians, `results/startup-summary.txt`):

| Case | Engine + load | Instantiate + init | First g5 | In-process to first result |
|---|---|---|---|---|
| ABI v1 `.cwasm`, runtime without component-model (today) | 8.16 ms | 0.52 ms | 4.87 ms | 14 ms |
| ABI v1 `.cwasm`, runtime with component-model | 8.70 ms | 0.53 ms | 5.04 ms | 14 ms |
| component `.ccwasm`, runtime with component-model, `bindgen!` | 8.84 ms | 0.49 ms | 4.65 ms | 14 ms |

- Process wall time is 73 ms in every case. Most of it is the harness
  reading the 52 MB cases file, which all three cases share.
- The runtime-only component build refuses a `.wasm` ("this build has no
  compiler").

## Start-up on every host against ABI v1 (`results/bench-wazero.txt`, `results/startup-summary.txt`)

These are medians of 7 on `taskset -c 0`. The Endive, WasmKit and jco
runs use one fresh process per run.

| Host | Measure | ABI v1 | canonical ABI | Delta |
|---|---|---|---|---|
| wazero | runtime + compile + instantiate + first g5 | 1,239.1 ms | 1,279.3 ms | +3.2% |
| wazero | steady g5 / JWS per s | 235.1 / 75.8 | 238.5 / 77.0 | noise |
| Endive (JVM) | instantiate + first g5 | 1,846.9 ms | 1,805.9 ms | -2.2% (noise) |
| Endive (JVM) | JVM uptime at first result | 2,709 ms | 2,776 ms | +2.5% (noise) |
| WasmKit | parse + instantiate + first g5 | 150.8 ms | 143.6 ms | -4.8% (noise) |
| jco / Node | load glue + compile + instantiate + first g5 | 97.4 ms | 105.1 ms | +7.9% |
| jco / Deno | same | 128.6 ms | 139.2 ms | +8.2% |
| jco / Bun | same | 261.3 ms | 254.4 ms | -2.6% (noise) |
| Rust Wasmtime | in-process to first result (precompiled) | 14 ms | 14 ms | 0 |

- On jco, ABI v1 runs through its own 74-line `abi.mjs`, and the
  canonical ABI through jco's 132 KB glue. The +8 to 11 ms on Node and
  Deno is the glue.
- The whole-process numbers carry the harness's file reading. On
  WasmKit, Swift string handling of the 52 MB cases file takes about
  2.6 s before the clock starts.

## Versions (`results/versions.txt`)

- Build: rustc 1.98.1; wit-bindgen 0.62.0; wasm-tools 1.259.0; wasi-sdk 34.0.
- wazero 1.12.0, built with go1.25.0.
- Endive 1.1.0 on OpenJDK 21.0.10.
- WasmKit 0.4.0 with Swift 6.3.3.
- jco 1.35.0 on Node 22.22.2, Deno 2.9.7 and Bun 1.3.11.
- wasmtime-py 49.0.0 on Python 3.11.15.
- Rust Wasmtime 49.0.1 (`wasmtime-internal-component-macro` 49.0.1) with getrandom 0.3.4.
- Machine: x86_64.

## Not tested

- WasmKit's opt-in `ComponentModel` package trait (present in 0.4.0).
- `random-get` with a wrong length on jco.
- A foreign pointer to post-return that reads as an in-range (ptr, len)
  (finding 5, EXPECTED).
- aprv-server itself rebuilt on the component. The Rust host here uses
  aprv-server's Wasmtime version, `Config` and embedding method, but not
  its HTTP layer, pooling or limits.
- The `pulley64` target for the component. Without Cranelift: EXPECTED
  to follow the same feature rule as finding 1.
- aarch64, macOS, Windows.
- Concurrency: one call per instance at a time.
- A 0.7 core.
- Why the `.cwasm` hash differs from aprv-server's.

## Limits

- The numbers come from one x86_64 machine on 2026-09-29, with the tool
  versions above.
- Parity is measured against ABI v1's Node rows (core 0.6). The two
  clock rows follow the 0.7 rule by design.
- To make room, disk use followed `results/disk.txt`: two
  earlier-round scratch directories (a .NET build output, and a
  reinstallable npm `node_modules`) were deleted before this round.
