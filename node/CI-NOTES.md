# CI notes for the npm package over aprv.wasm

For the integrator. This lane does not edit `.github/`; these are the
changes `node/` now needs there and in the root documents.

## What the build needs

- `npm ci --ignore-scripts` still works: jco 1.35.0 and its dependencies
  need no install script (checked from a clean copy of `node/`).
- `npm run build` (and `npm test`, `npm pack`, `npm publish` through
  `prepack`) now runs `jco transpile` before `tsc`. It reads the component
  from `node/wasm/aprv.component.wasm`, which is gitignored and never
  committed (owner rule on large files). Every job that builds `node/`
  must first provide the rust-wasm job's `aprv.component.wasm`: set
  `APRV_COMPONENT` to its path (used as given), or copy it into place and
  update `node/wasm/aprv.component.wasm.sha256`, which the build checks the
  in-place copy against (it pins the G1b component of lane/core
  c4410c7 today). A missing
  file fails the build with a message saying so. The build prints the
  file's SHA-256 and writes it to `dist/generated/component.sha256`.
- `src/generated/` is build output and is gitignored.

## Jobs to change in `ci.yml`

| Job | Change |
|---|---|
| `node` (Node 20, 22, 24, 26) | Unchanged command (`npm ci --ignore-scripts && npm test`). Needs the component provided first (above). With the G1b component (lane/core c4410c7): 730 of 730 tests, the 338 cases passing on both entry points |
| `node-runtimes` | Matrix becomes `node, bun, deno, workerd, edge`, and each leg runs `npm ci --ignore-scripts && npm run build && npm run runtime:${{ matrix.runtime }}`. The three `workerd-*` legs collapse to one: the package needs no compatibility flag, so the floor date and `nodejs_compat_v2` legs no longer test anything of ours |
| `node-runtimes-web` | Delete: the `/web` entry point runs the same module as `.`, and every runtime leg above smokes both entry points. The `test:runtimes:web` script is gone |
| `node-runtimes-fastly` | Delete (R5): Fastly Compute runs no WebAssembly. The `test:runtimes:fastly` script and the `@fastly/js-compute` dev dependency are gone |
| `node-fuzz` | Delete: `node/fuzz/` fuzzed the JavaScript DER, CMS and JWS readers, which are gone. The core's own fuzz jobs cover the parser now. Also drop the `/node/fuzz` entry in `.github/dependabot.yml` and `node/fuzz/**` in `.github/codeql/codeql-config.yml` |
| `node-roots-generated` | Keep until Phase 7, as the lane brief says. `src/roots-data.ts` is excluded from the TypeScript build and no longer ships |
| `node-lint` | Unchanged. Its "link bench/bench.mjs" step still works: the bench no longer imports `decodeReceiptBase64` |
| new `node-browsers` | `npm ci --ignore-scripts && npm i --no-save playwright@1.56.1 && npx playwright install --with-deps chromium firefox webkit && npm run build && npm run runtime:browser -- chromium firefox webkit`. Only Chromium ran in the lane's container (`/opt/pw-browsers` has no Firefox or WebKit); Firefox and WebKit are untested |

`benchmark.yml`'s Node job is unchanged in shape; its output loses the
`decodeBase64` rows, since the package has no public decoder.

`release.yml`: `publish-npm` must build from the release's component, so
`npm run build` and `npm publish` both need `APRV_COMPONENT` set to the
component the release built (`aprv.component.wasm`), after checking its
SHA-256 against the release's. The `smoke-npm` job's tarball check can add
`dist/generated/aprv.core.wasm`, `dist/generated/aprv.js` and the nine
files under `licenses/` to the paths it requires.

## The copy of the module jco extracts

`jco transpile` writes the component's core module out as
`dist/generated/aprv.core.wasm`, and that file is not byte-identical to the
standalone core module: for the G1 module it is 3,005,461 bytes against
`aprv.wasm`'s 3,005,922 (for the round-13 stand-in, 2,966,655 against
2,967,116). `wasm-tools component new` rewrites the module's custom
sections when it wraps it: deleting only the `component-type` section
from the standalone module gives 2,966,609 bytes, still a different file.
The `wasm-copies` check therefore
needs to compare the npm package's copy against the core module embedded in
the release's component (or check `dist/generated/component.sha256` against
the component's published hash), not against `aprv.wasm` itself.

## Rows for the root documents

- `SUPPORT-MATRIX.md`, Node table, line 50: drop `node-runtimes-fastly` and
  `node-fuzz` from the Node 22 row, and name the new runtime legs
  (node, bun, deno, workerd, edge) plus `node-browsers`.
- `README.md` and `SUPPORT-MATRIX.md`: remove Fastly Compute and Akamai
  EdgeWorkers wherever they appear as supported JavaScript runtimes.
- `BENCHMARKS.md`: the Node column's `decodeBase64` row has no successor.
  The memory and timing results below are the G1 module's, on a shared
  and heavily loaded machine; rerun them on a quiet one for the table.
- The CHANGELOG entry comes from the lane's `feat(node)!:` commit and its
  `BREAKING CHANGE:` footer.

## Module drops: one command

`node scripts/g1.mjs DROP_DIR` builds from `DROP_DIR/aprv.component.wasm`
and runs, in order: the node:test suite, the runtime smoke on Node and
workerd, `scripts/corpus.mjs` (the five corpora's pinned call files through
the package's host layer, compared byte for byte with
`DROP_DIR/rows/module-<corpus>.jsonl`), `bench/bench.mjs`,
`bench/startup.mjs`, `bench/memory.mjs` and `bench/memory-workerd.mjs`. It
stops at the first failure. A CI job for the corpus parity can run
`node scripts/corpus.mjs CALLS_DIR ROWS_DIR` alone after `npm run build`.

G1b (lane/core c4410c7, component sha256 `11798a29…`), 2026-09-29, Node
22.22.2, the same counts as G1 (05b4ad9) had against its own rows:

| Corpus | Rows | Identical to the module's reference rows | Traps |
|---|---:|---:|---:|
| algorithms | 22 | 22 | 0 |
| cases | 153 | 153 | 0 |
| fuzz | 5,000 | 5,000 | 0 |
| hostile | 811 | 811 | 0 |
| substrate | 193 | 193 | 0 |

## Timing

Two runs of `node bench/bench.mjs` (median µs per call) and
`node bench/startup.mjs` (median of 7 fresh processes, ms), Node 22.22.2,
2026-09-29, on the shared 4-vCPU container with a load average of 17 to 22
from other work. Treat them as upper bounds; round 13 measured 1,343 µs per
g5 receipt through ABI v1 on a quiet run of the same container type.

| Call | Run 1 | Run 2 |
|---|---:|---:|
| `verifyReceipt`, g5 | 4,985 | 4,831 |
| `verifyReceiptEndpoint`, g5 | 5,035 | 3,856 |
| tampered signature, g5 | 3,334 | 3,971 |
| `verifyReceipt`, 187-purchase legacy | 31,480 | 31,091 |
| `verifyReceiptEndpoint`, legacy | 38,781 | 22,847 |
| tampered signature, legacy | 7,219 | 6,022 |

| Start-up step | Run 1 | Run 2 |
|---|---:|---:|
| `import` of the package | 29.9 | 43.3 |
| first `createVerifier` (compile, instantiate, `init`) | 153.3 | 134.5 |
| second `createVerifier` (instantiate, `init`) | 51.9 | 34.0 |
| first `verifyReceipt`, g5 | 62.2 | 48.4 |
| second `verifyReceipt`, g5 | 27.6 | 30.8 |

G1b, one run under a load average of 21 to 30: `verifyReceipt` g5
8,013 µs, endpoint g5 7,064 µs, tampered g5 6,767 µs, legacy 58,135 /
46,844 / 10,415 µs; start-up medians 52.4 ms import, 250.2 ms first
`createVerifier`, 59.7 ms second, 66.7 ms and 48.7 ms for the first two
g5 calls. These track the machine's load, not the module: the G1 and G1b
figures are both upper bounds.

The facade adds nothing measurable over calling jco's bindings directly (a
g5 `verifyReceipt` at 9.9 to 12.3 ms through the facade against 11.7 to
12.3 ms raw, in the same loaded process).

## Memory (MIGRATION 4.3)

`node bench/memory.mjs` and `node bench/memory-workerd.mjs` (workerd
1.20260903.1, peak RSS of the whole `workerd test` process), G1b module:

| Runtime | Receipt | Call | Peak RSS |
|---|---|---|---|
| Node 22.22.2 | tiny (156 B of base64) | `verifyReceipt` / endpoint | 98 / 99 MiB |
| Node 22.22.2 | flat-max (3,145,704 B) | `verifyReceipt` / endpoint | 113 / 120 MiB |
| workerd | tiny | `verifyReceipt` / endpoint | 69 / 69 MiB |
| workerd | flat-max | `verifyReceipt` / endpoint | 98 / 104 MiB |

The review-fixed core refuses the flat-max receipt (`MALFORMED`, "signer
certificate not embedded") before it reads the payload: 84 ms through the
facade on the loaded machine, with linear memory growing from 2 MiB to
16.1 MiB. G1 read the whole payload first (about 0.8 s, 73.9 MiB of linear
memory, 176 MiB on Node and 161 MiB in workerd). Linear memory never
shrinks, so an instance keeps what it grew to. workerd run locally does
not enforce the 128 MB isolate limit, so a production Worker is not
measured, but the whole workerd process now peaks at 104 MiB, runtime
included (104 MiB is 109 MB), so the isolate itself stayed under 128 MB
here; how production counts it is not measured.

## Bun's WASI `random_get` bug (MIGRATION 4.5)

`docs/evidence/2026-09-26-security-substrate-bakeoff/wasm/bun-random-get.mjs`
rechecked on 2026-09-29:

| Bun | Result |
|---|---|
| 1.3.11 | still wrong: returns 16 instead of 0 and writes bytes across the whole 64 KiB memory (nonzero range 0 to 65535) |
| 1.3.14 | still wrong, same output |
| 1.4.0 | fixed: returns 0 and writes only [1000, 1016) |
| 1.4.2 (latest) | fixed, same output |

Fixed in Bun 1.4.0, so there is nothing left to report upstream. It never
affected this package, which does not use `node:wasi`: `aprv.wasm` imports
only `random-get`, answered from `crypto.getRandomValues`. The package's
runtime smoke passes on Bun 1.3.11 and 1.4.2.
