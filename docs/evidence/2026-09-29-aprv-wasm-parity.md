# aprv.wasm on the OpenSSL core: the contract, the ABI tests and parity (2026-09-29)

**Question.** Does the first real `aprv.wasm` (MIGRATION.md step 1.4:
`aprv-abi` over `aprv-surface` and `aprv-wire`, on the OpenSSL core) keep
the canonical-ABI contract, pass the 311 shared cases and the ABI tests,
answer every corpus row exactly as the native code it is compiled from,
and differ from the ABI v1 reference rows only where 0.7 meant to? And
can the one import be WASI 0.2's `get-random-bytes` instead of our own
(DECISIONS.md R34)? This feeds gate G1 and the host lanes, which re-run
against this module instead of the round-13 stand-in.

**Versions.** rustc 1.98.1; wasi-sdk 34.0; OpenSSL 4.0.2 for
wasm32-wasip1 from `tools/wasm-toolchain.sh` (rust-core, ba56248);
wasm-tools 1.259.0; wit-bindgen 0.62.0; Node 22.22.2; Wasmtime 49.0.1;
Ajv 8.20.0 (the 2020 draft, strict mode); jsonschema 0.58.2. Linux x86_64.

**Method.** `rust/bindings/abi/build.sh` builds the module and the
component (`results/build.txt`). Four hosts run it:

- `tools/wasm-trap-host.mjs` (lane D, on rust-core): Node's WebAssembly,
  the core exports called by hand, every import but `random-get` a
  throwing function; `cases`, `abi-tests` and `calls` modes;
- the same host with its `_initialize` call removed;
- `rust/bindings/abi/tests`: Wasmtime 49.0.1, the core module by hand and
  the component through `bindgen!`, neither calling `_initialize`;
- `2026-09-29-aprv-wasm-parity/runner/`: the module's native twin, the same
  four bodies over `aprv-surface` and `aprv-wire` compiled for x86_64.

The corpora are the substrate bake-off's five (1,179 rows plus 5,000
mutants), as round 13's call files (`py/calls_bytes.py` of the
canonical-ABI final round), with every unpinned clock pinned to
2026-09-29T00:00:00Z so the module and its twin judge dateless inputs at
the same instant.

## Results

**The contract** (`results/build.txt`, `results/check-wasm.txt`). The
module is 3,005,922 bytes, SHA-256
`4cbe2b02056afc41c352fbbacdf6b3804f6f081beaaa8e8ff104340e9ed8826e`
(2,746,570 with every custom section stripped, 913,814 of that gzipped);
the component is 3,008,364 bytes,
`8f758c0b032f5d288b214250437f5085e79344211055b729d155fea0a4460dd5`,
2,442 bytes more, as in round 13. It imports exactly
`aprv:verifier/host@1.0.0` `random-get` and exports exactly the four
`@1.0.0` operations, their `cabi_post_` functions, `cabi_realloc` with
wit-bindgen's `cabi_realloc_wit_bindgen_0_62_0` alias, `memory` and
`_initialize`. The stand-in's two internal exports (`aprv_clock_now_ms`,
`aprv_random_get`, round 13's finding 7) are gone: the Rust side hands the
link-time C file its clock and randomness through two C setters, so no
Rust symbol is exported. lane D's `tools/check-wasm.sh` passes all five
checks. The interface read back from the component equals the committed
WIT; wit-bindgen 0.62.0 embeds no doc comments, so the comparison covers
names and types.

**Reproducible** (`results/reproduce.txt`). A second build from a fresh
clone in another directory, with another target directory, gave the same
two hashes. Its first attempt found that the vendored openssl-sys's
`build/` directory had never been committed (the root `.gitignore` ignores
`build/`), so no fresh clone could build the workspace; fixed on the
branch.

**The 311 cases** (`results/cases-trap-host.txt`,
`results/no-initialize.txt`): 311 passed, 0 failed, 0 traps, 0 other
imports called, through the host that traps on any unexpected import and
with every WASI function but `random_get` and `clock_time_get` trapping
inside the module. The same with `_initialize` never called. The
stand-in fails 184 of them under the same host
(`results/standin-case-differences.txt`, by id: 91 `receipt/`, 28
`signed-data/`, 22 `base64/`, 22 `receipt-base64/`, 16 `transaction/`, 2
`endpoint/`, 2 `raw/`, 1 `app-transaction/`); those are the 0.6-versus-0.7
rows the host lanes' runs move on.

**The ABI tests** (`results/abi-tests-node.txt`,
`results/abi-tests-wasmtime.txt`): all pass on the Node hand-rolled host
(18 checks) and on both Wasmtime hosts (11 tests): `env` 2, 255 and
2^32-1 trap; a verify before `init` and a second `init` trap; a refused
configuration is a value and `init` retries; a `random-get` answer one
byte short or long traps (one `random-get` call per ES256 JWS); a trap in
one instance leaves another verifying, and Wasmtime's component runtime
refuses the trapped instance; 2,000 calls leave linear memory at
2,097,152 bytes; non-UTF-8 input is a value; a `now-ms` above `i64::MAX`
is `INTERNAL_ERROR` (21009 at the endpoint).

**The corpora** (`results/parity.txt`):

| Corpus | Rows | Module = native twin | Traps | Module = OpenSSL core's 0.7 API rows | Text API could not take the row | Verdict differs from ABI v1 Node, old core agrees |
|---|---:|---:|---:|---:|---:|---:|
| cases | 153 | 153 | 0 | 153 | 0 | 31 |
| hostile | 811 | 811 | 0 | 704 | 88 non-UTF-8, 19 lossy endpoint bodies | 9 |
| algorithms | 22 | 22 | 0 | 22 | 0 | 16 |
| substrate | 193 | 193 | 0 | 193 | 0 | 65 |
| fuzz | 5,000 | 5,000 | 0 | 4,825 | 175 non-UTF-8 | 28 |
| **all** | **6,179** | **6,179** | **0** | **5,897** | **282** | **149** |

- The module answers every row byte for byte as its native twin, and as
  the OpenSSL core's 0.7 public API wherever that API could take the row
  (`docs/evidence/2026-09-29-openssl-core-parity`'s rows).
- 263 rows are not UTF-8 (20 receipts, 243 JWS): the text API refused to
  take them (`NOT_UTF8`); through the bytes API they are values, all
  `MALFORMED`, none a trap. 19 endpoint bodies are not UTF-8: that
  runner read them lossily and answered all 19 with status 0; the bytes API
  answers 21002 (JSON text is UTF-8), which is what the ABI v1 Node rows
  answered.
- Against the ABI v1 Node rows, 149 rows differ on the verdict, every one
  a row where the pre-migration 0.7 core gives the module's verdict too:
  the 0.7 contract changes A1 listed (the intermediate marker OID, the
  endpoint's 21003, caller policy leaving the core, the P-521 and
  canonical-name chains). The bytes API removes the 282 rows A1 had to
  count as "the text API cannot take it" and 19 of its 21 "ref 21002,
  0.7 status 0" endpoint rows. No difference is new to the module.
  Round 13's three intended differences (two `injected-clock` endpoint
  rows under the per-call `now-ms`, one `init` refusal of a root that is
  not a certificate) are inside these counts: the pinned-clock rows agree
  with the 0.7 core, and the refused root is refused on both sides.
- Every answer validates against `rust/bindings/wire/schema/` under Ajv
  2020 strict: 3,922 `verify-receipt`, 2,085 `verify-signed-data` and 1
  `init` answer from the corpora; 318, 274 and 53 (and 53 configurations)
  from the cases (`results/cases-schemas.txt`). The wire crate's own test
  validates the same shapes with the jsonschema crate.

**`wasi:random` instead of `host.random-get`**
(`results/wasi-random.txt`, `wasi-random/`). The same module with WASI
0.2.6's `get-random-bytes: func(len: u64) -> list<u8>` as its import:

| | `host.random-get` | `wasi:random` |
|---|---:|---:|
| module | 3,005,922 B | 3,005,965 B (+43) |
| component | 3,008,364 B | 3,008,419 B (+55) |
| imports | 1 | 1 |
| corpus rows identical to the other | | 6,179 of 6,179 |
| corpus time, Node trap host | 10.69 s | 10.36 s |

It costs nothing measurable. **It is not adopted**: R34's condition is that
nothing else changes, and three things would. The interface every host
lane, lane B's server (its WIT is compared byte for byte) and lane D's
`check-wasm.sh` already bind changes. The import's name carries the WASI
patch version (`wasi:random/random@0.2.6`), which every hand-rolled host
would have to match exactly. And the benefit, a WASI host supplying the
function with no code of ours, reaches none of our hosts: aprv-server
links Wasmtime runtime-only, without wasmtime-wasi, and jco's WASI glue was
rejected (DECISIONS.md, rejected table). The switch stays mechanical if
that changes: the WIT, one line of the guest, `generate_all`, and each
host's import name.

**Panics and the start function** (`results/build.txt`). The module is
built with `panic = "abort"` (the `wasm` profile), and the four bodies'
traps go straight to `unreachable`. std's panic handler is still linked,
26 functions, because code in std and the dependencies that can panic
(bounds and `RefCell` checks) is reachable; removing it needs a nightly
`-Z build-std` with `panic_immediate_abort`. Every such path ends in a
trap: the hook's write to stderr is `fd_write`, which traps in
`wasi-none.c`, and the abort is `unreachable`. The module has one
constructor, and every export runs it on its first call, so hosts need
not call `_initialize`; calling it first is harmless, calling it twice
traps.

## Where this stops holding

- One machine (Linux x86_64), Node 22 and Wasmtime 49.0.1. Endive,
  wazero, WasmKit, jco, wasmtime-py, the gem and .NET run this module in
  their own lanes.
- The corpora are the spike's; CI's reference rows are the 311 cases.
- Timings are single runs on a shared 4-CPU machine; only "equal within
  noise" is claimed for them.
- The native twin shares every line of the module's code below the
  boundary, so their agreement proves the Wasm build changes nothing; it
  is not a second implementation. The OpenSSL core rows and the ABI v1
  Node rows are the independent comparisons.
