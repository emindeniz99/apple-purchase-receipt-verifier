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
  in-place copy against (it pins the round-13 stand-in today). A missing
  file fails the build with a message saying so. The build prints the
  file's SHA-256 and writes it to `dist/generated/component.sha256`.
- `src/generated/` is build output and is gitignored.

## Jobs to change in `ci.yml`

| Job | Change |
|---|---|
| `node` (Node 20, 22, 24, 26) | Unchanged command (`npm ci --ignore-scripts && npm test`). Needs the component provided first (above). With the round-13 stand-in, 221 of the 311 cases fail on each entry point (list in the lane hand-back); with the core's component it must be 311/311 on both entry points |
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
standalone core module: for the stand-in it is 2,966,655 bytes against
2,967,116. `wasm-tools component new` rewrites the module's custom
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
  The workerd memory result (below) belongs in the benchmarks once it is
  rerun with the release module.
- The CHANGELOG entry comes from the lane's `feat(node)!:` commit and its
  `BREAKING CHANGE:` footer.

## Memory (MIGRATION 4.3), with the stand-in module

`node bench/memory.mjs`, and the same receipt in workerd 1.20260903.1
(scratch config, peak RSS of the whole `workerd test` process):

| Runtime | Receipt | Call | Peak RSS |
|---|---|---|---|
| Node 22.22.2 | tiny (156 B of base64) | `verifyReceipt` / endpoint | 96 / 96 MiB |
| Node 22.22.2 | flat-max (3,145,704 B) | `verifyReceipt` / endpoint | 151 / 158 MiB |
| workerd | tiny | `verifyReceipt` / endpoint | 69 / 69 MiB |
| workerd | flat-max | `verifyReceipt` / endpoint | 134 / 137 MiB |

The module's linear memory grew from 2 MiB to 53.2 MiB on the flat-max
receipt and does not shrink afterwards. workerd run locally does not
enforce the 128 MB isolate limit, so whether a production Worker admits
this receipt is not measured; the numbers above are the whole process,
workerd's own runtime included.

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
