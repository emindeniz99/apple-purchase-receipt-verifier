# OpenSSL 4.0.2 with the CMS API, on every route

Date: 2026-09-26. Code, scripts and raw results:
`2026-09-26-openssl-cms-everywhere/`. Its `README.md` has the file table
and the commands.

This round continues three notes from the same day, whose code it reuses
unchanged:

- `2026-09-26-security-substrate-bakeoff.md`: the adapter, the policy, the
  corpora and the Java oracle.
- `2026-09-26-wasm-architecture-bakeoff.md`: the wasm routes, runners and
  npm facades.
- `2026-09-26-substrate-followup.md`: the CMS adapter (`adapter-cms`) and
  the fuzz setup.

Labels: TESTED (ran here), DOCUMENTED (read in a source, manifest or
specification), EXPECTED (inferred, not run), UNKNOWN. Nothing in `rust/`,
`docs/rust-core/` or any other production path changed. `DECISIONS.md` is
untouched. No system package was installed or upgraded in this round.

## The question

The owner leans towards OpenSSL 4.x stable with the CMS API. Before R21 is
written, this round checks that choice on every route:

1. Can a normal cargo build get OpenSSL 4.0.2 without a hand-built tree?
2. Does the CMS path, with the `asn1.rs` prescan as the guard, give exactly
   the native answers on every route and every host? And do its npm
   tarballs pass the smoke matrix?
3. Why can openssl-sys not target `wasm32-unknown-unknown`? Is Route C the
   working substitute?
4. Does a coverage-guided fuzz campaign on the CMS path find anything?
5. What exactly are the 18 rows where the CMS path still differs from Java?

All builds use rustc 1.98.1, installed under `$SCRATCH`. The one exception
is fuzzing, which needs nightly for `-Zsanitizer` and the sancov passes. The
only OpenSSL is 4.0.2.

## Results, one line per task

| Task | Result | Label | Source |
|---|---|---|---|
| 1. Vendored OpenSSL 4.0.2 | Works. A copy of openssl-sys 0.9.117 with ONE manifest line changed (`openssl-src` `"300.2.0"` → `"400.0.1"`), wired in with `[patch.crates-io]`: no code change, OpenSSL 4.0.2 built inside `cargo build`, 1,179 of 1,179 rows identical to the `OPENSSL_DIR` build. The only blocker is openssl-sys's published requirement | TESTED | `results/vendored.txt`, `results/parity.txt` |
| 2. CMS path on every route | 33 runs of 1,179 rows, all identical to native CMS. Route C: 9 hosts. WASIp1: 9 hosts. Emscripten: 7 hosts. Component: 8 hosts (Wasmtime native, and jco on 7 hosts). Every run has the native Java tallies (1,030 Java-equal of 1,048) | TESTED | `results/matrix.txt`, `results/java-tallies.txt` |
| 2. npm tarballs | `aprv-spike-core-openssl-cms` (Route C) and `aprv-spike-wasip1-openssl-cms`: 16 of 16 smoke runs pass. The hosts are Node, Bun, Deno, the three browsers, the Lambda-like run and `wrangler dev --local` | TESTED | `results/npm-smoke.jsonl` |
| 3. `wasm32-unknown-unknown` | openssl-sys 0.9.117 does not compile: 20 × E0432, because `libc` 0.2.189 exports no `size_t`, `time_t` or `FILE` for that target. Route C is the working substitute: it imports only `aprv.clock_now_ms` and `aprv.random_get`, and ran on all 9 hosts | TESTED | `results/unknown-unknown.txt`, `results/imports.txt` |
| 4. Fuzzing the CMS path | 2 × 45 min, ASan and libFuzzer, OpenSSL instrumented, seeded with the previous campaign's corpus. Result: 9.33 million executions and no finding (no crash, leak, timeout or OOM), so there is nothing to minimize | TESTED | `results/fuzz-campaign.txt` |
| 5. The 18 non-Java rows | None is a forgery or an acceptance of anything unsigned. 1 is an acceptance Java refuses, of a signature the key holder really made over non-DER bytes. The other 17 reject either way, or concern the JSON layer. Three small read-only checks would align 11 of them, with 0 new rejections on 5,740 modelled rows. The other 7 should stay as they are | TESTED (model) and DOCUMENTED (specs) | `results/prescan-model.txt`, section 5 |

## 1. Vendored build (TESTED)

- **What exists.** `openssl-src` 400.0.1+4.0.2 (crates.io, 2026-08-25)
  builds OpenSSL 4.0.2 inside a build script.
- **The blocker.** openssl-sys 0.9.117, still the newest, declares
  `[build-dependencies.openssl-src] version = "300.2.0"`, which means
  `^300.2.0`. So its `vendored` feature can only reach OpenSSL 3.x.
- **The change.** `scripts/vendored.sh` copies openssl-sys 0.9.117 and
  changes exactly that line to `"400.0.1"`. The `legacy` feature and
  `optional` are unchanged. The copy is wired in with `[patch.crates-io]`.
  No source file changes: `build/find_vendored.rs` uses
  `openssl_src::Build::{new, openssl_dir, build}` and
  `Artifacts::{lib_dir, include_dir}`, which 400.0.1 keeps.
- **The build.** The build script reported "Configuring OpenSSL version
  4.0.2", `cargo:version_number=40000020` and `cargo:vendored=1`. The CMS
  C ABI built with the adapter's `vendored` feature, with no `OPENSSL_DIR`
  anywhere.
- **Parity:** 1,179 of 1,179 rows identical to the `OPENSSL_DIR` build, and
  the same Java tallies.
- **Differences to know before relying on it:**
  - openssl-src passes `--openssldir=/usr/local/ssl` unless
    `OPENSSL_CONFIG_DIR` is set, and does not pass `no-autoload-config`.
    The adapter's `OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG)` still
    keeps any config file unread; the substrate bake-off TESTED that for
    the openssl-src 3.6 build. A production build should still set
    `OPENSSL_CONFIG_DIR` to a path that does not exist.
  - Its default Configure line also drops some ciphers (`no-camellia`,
    `no-idea`, `no-seed`, `no-md2`, `no-rc5`). The `.so` is 6,336,528 B
    against 8,619,992 B, and no corpus row needs those ciphers.
  - openssl-src's target table maps `wasm32-wasi` but not `wasm32-wasip1`
    (DOCUMENTED, `src/lib.rs`). So the wasm routes keep the `OPENSSL_DIR`
    builds of `$SCRATCH/inst-wasm` and `inst-em`.

So `OPENSSL_DIR` remains the route for wasm. For native builds, the whole
blocker is one requirement in a published manifest.

## 2. The CMS path on every route (TESTED)

### What was built

Every artifact uses the same core copy and the same pieces:

- the substrate policy;
- the follow-up's `adapter-cms` (`CMS_SignerInfo_verify` and
  `CMS_SignerInfo_verify_content`);
- the substrate bake-off's `asn1.rs` prescan;
- the wasm bake-off's clock seam, shim, guest, `wasi-none.c` and link
  fixes.

All of it is built by `scripts/build.sh` with rustc 1.98.1 over OpenSSL
4.0.2.

| Artifact | Route | Size raw / strip+gzip | Imports (TESTED, `results/imports.txt`) |
|---|---|---|---|
| native `.so` (`OPENSSL_DIR`) | C ABI | 8,619,992 / 2,789,725 | libc |
| native `.so` (vendored) | C ABI | 6,336,528 / 1,966,051 | libc |
| `cms-c.wasm` | C: freestanding | 3,000,116 / 986,315 | `aprv.clock_now_ms`, `aprv.random_get`, nothing else |
| `cms-w1.wasm` | A: `wasm32-wasip1` | 3,006,245 / 987,914 | 17 `wasi_snapshot_preview1` functions (environ ×2, clock_time_get, 12 fd/path functions, proc_exit, random_get). Only `random_get` (once) and `clock_time_get` are ever called |
| `cms-em` `aprv-em.wasm` | B: Emscripten | 2,191,960 / 893,385 | 22 JS functions from the glue. Called: environ ×2 (libc init), `random_get` once, clock, heap growth |
| `cms-em` glue | B | node+web 13,882 B, web-only 12,857 B | the two `.wasm` files are byte-identical |
| `cms-comp.component.wasm` | D: component | 3,038,350 / 996,970 | `wasi:io/error`, `wasi:io/streams`, `wasi:cli/stderr`, `wasi:clocks/monotonic-clock`, `wasi:clocks/wall-clock`, `wasi:random/random` (all @0.2.12), and `aprv:verifier/types` |
| jco output | D | `aprv.js` 236,337 B (37,008 gzip), 4 core modules | the same, through the 41-line `wasi-p2-min.mjs` |

- **Cost of the CMS path.** It adds 1 to 2 % to each module against the
  PKCS7 path: `ossl-c` was 2,933,868 B and `cms-c` is 3,000,116 B.
- **Wasm features.** Core modules and the component need only wasm2/lime1.
  Emscripten adds legacy exceptions (`results/imports.txt`).
- **Glue.** No glue contains `process.env`, SOCKFS, MEMFS or WebSocket
  code.

### Matrix

Each cell is rows identical to native CMS, out of 1,179.

| Artifact | Node | Bun | Deno | Chromium 141 | Firefox 156 | WebKitGTK 2.52.6 | workerd | wazero | Wasmtime |
|---|---|---|---|---|---|---|---|---|---|
| Route C `cms-c` | 1,179 | 1,179 | 1,179 | 1,179 | 1,179 | 1,179 | 1,179 | 1,179 | 1,179 |
| WASIp1 `cms-w1` (minimal host, no `node:wasi`) | 1,179 | 1,179 | 1,179 | 1,179 | 1,179 | 1,179 | 1,179 | 1,179 | 1,179 |
| Emscripten `cms-em` | 1,179 | 1,179 | 1,179 | 1,179 | 1,179 | 1,179 | 1,179 (web glue) | n/a | n/a |
| Component `cms-comp` | 1,179 (jco) | 1,179 (jco) | 1,179 (jco) | 1,179 (jco) | 1,179 (jco) | 1,179 (jco) | 1,179 (jco) | n/a (no Component Model) | 1,179 (native Component Model) |

Source: `results/matrix.txt` and `results/parity.txt`. Also compared:

- The native CMS build under rustc 1.98.1 against the follow-up's (rustc
  1.94.1): 1,179 of 1,179 identical.
- The vendored build: 1,179 of 1,179.

That is 35 comparisons, all identical row by row.

**Java.** Every run has the same three-way tallies as native CMS
(`results/java-tallies.txt`), 35 of 35:

| Corpus | Tally (agree, cand=java, cand=rust, cand-own, abi) |
|---|---|
| cases | 153 0 0 0 0 |
| substrate | 169 21 2 1 0 |
| hostile | 655 10 12 3 131 |
| algorithms | 8 14 0 0 0 |

That is 1,030 Java-equal rows of the 1,048 the C ABI can express.

### npm tarballs

`scripts/npm.sh` builds two packages. They share the wasm bake-off's
`abi.js`, `node.js`, `browser.js`, `workerd.js` and `index.d.ts`, and all
are `"private": true`:

| Package | Tarball | Note |
|---|---|---|
| `aprv-spike-core-openssl-cms` | 1,001,740 B, 9 files | `cms-c.wasm` and the Route C `instantiate.js`. It refuses any import other than the two `aprv` functions |
| `aprv-spike-wasip1-openssl-cms` | 1,004,352 B, 9 files | `cms-w1.wasm` and `npm/wasip1/instantiate.js`: a fixed WASI answer set (clock, `crypto.getRandomValues`, empty arguments and environment, no preopens, discarding stdout/stderr). Every other WASI call traps |

Installed from the tarballs, both passed on every host, 16 of 16 runs
(`results/npm-smoke.jsonl`):

- Node, Bun and Deno;
- Chromium, Firefox and WebKitGTK, loading straight from `node_modules`;
- the Lambda-like run under `node --permission`: 200 repeated and 64
  concurrent invocations with 0 mismatches, with file writes, reads
  outside the package, and `child_process` denied;
- `wrangler dev --local`.

## 3. `wasm32-unknown-unknown` (TESTED)

- **The attempt.** The CMS shim was built for `wasm32-unknown-unknown`
  with rustc 1.98.1 (`scripts/unknown.sh`).
- **The C side is not the problem.** openssl-sys's build script found
  OpenSSL 4.0.2's headers through `OPENSSL_DIR` and compiled its probe with
  wasi-sdk's clang.
- **The failure is in Rust, before any C links.** `openssl-sys` 0.9.117
  itself fails with 20 × E0432:
  - `unresolved import libc::size_t` (18);
  - `libc::time_t` (1);
  - `libc::FILE` (1).
  They are in `src/evp.rs:2`, `src/sha.rs:2` and 18 `src/handwritten/*.rs`
  modules (every location is in `results/unknown-unknown.txt`).
- **The cause.** `libc` 0.2.189 chooses its platform module by `cfg`
  (`src/lib.rs`: windows, fuchsia, …, `unix` at line 250, `wasi` at line
  290, …). The final `else` is "non-supported targets: empty", and
  `wasm32-unknown-unknown` (`target_os = "unknown"`, no `target_env`)
  lands there. So the C type aliases openssl-sys declares its bindings
  with do not exist.
- **What it would take.** No build flag or C toolchain choice can change
  that. It would need a `libc` that defines C types for a target that has
  no C library, or an openssl-sys that does not use `libc`.
- **The substitute.** Route C compiles the same crates for
  `wasm32-wasip1`, where `libc` has its `wasi` module, and links wasi-sdk's
  wasi-libc. `c/wasi-none.c` then defines every WASI function wasi-libc
  would import, inside the module. The final `cms-c.wasm` imports exactly
  `aprv.clock_now_ms` and `aprv.random_get`: no WASI, no other host
  function. That is the same host contract a `wasm32-unknown-unknown`
  module with a clock and a CSPRNG import would have.
- **Result:** it ran 1,179 of 1,179 on all 9 hosts above.

Imports of each final module: see the table in section 2 and
`results/imports.txt`.

## 4. Fuzzing the CMS path (TESTED)

The fuzz targets are the repository's own, `rust/fuzz` `verify-receipt`
and `verify-transaction`, left unchanged. They ran over the CMS build
(`substrate-cms` and `substrate-prescan`) and were linked against OpenSSL
4.0.2 (no-asm), built with clang 18 AddressSanitizer and libFuzzer
coverage, so OpenSSL's own code is instrumented as well.

The two campaigns ran in parallel for 2,700 s each, from 12:08:58Z to
12:53:59Z. The seeds were the follow-up campaign's corpus plus its seed set,
and were only read:

| Target | Seeds |
|---|---|
| receipt | 1,594 + 3,834 files |
| transaction | 2,371 + 2,061 files |

The limits were `-timeout=10 -rss_limit_mb=2048 -max_len=65536`, with
`detect_leaks=1`.

| Target | Executions | exec/s | Coverage start → end | New units | Peak RSS | Findings |
|---|---|---|---|---|---|---|
| `verify-receipt` | 4,931,206 | 1,825 | 7,048 → 7,236 (ft 21,896) | 1,273 | 609 MB | 0 |
| `verify-transaction` | 4,403,659 | 1,630 | 8,077 → 8,174 (ft 22,373) | 2,345 | 555 MB | 0 |

Neither campaign found anything:

- no ASan report, leak, timeout or OOM;
- both artifact directories are empty;
- the slowest unit took under 1 s.

So there is no reproducer to minimize. The coverage gain over the seeded
start is small, which is expected: the seeds are an already-converged corpus
for the same targets on the PKCS7 path. What this campaign adds is the code
that differs, namely the CMS calls in `cms_path.rs` and OpenSSL's
`crypto/cms` behind them.

One exception to the round's rule of "rustc 1.98.1 for everything": the fuzz
binaries use nightly 1.100.0 (2026-09-25), because cargo-fuzz passes
`-Zsanitizer=address`, which stable rustc refuses.

Limits:

- 45 minutes per target is a smoke-level campaign, not an exhaustive one;
- the targets cover the verifier API only, not the C ABI or the wasm hosts;
- only the native x86_64 build was fuzzed.

The source is `results/fuzz-campaign.txt`.

## 5. The 18 rows where OpenSSL CMS still differs from Java

The 18 rows are the CMS + prescan build's non-Java rows. They are the same
in every artifact above, and `$FUP/results/tri-ossl402cmspre-*.txt` lists
them.

**Codes:**

| Code | Meaning |
|---|---|
| 0 | valid |
| 1 | invalid JWS format |
| 2 | invalid certificate |
| 4 | invalid chain |
| 5 | invalid signature |
| 9 | invalid receipt format |
| 21002 | endpoint "malformed data" |

**Could Apple produce it?** Every row is a mutation or a synthetic test
input, built from test keys or by mutating a fixture. The column answers
whether a genuine Apple receipt or JWS could ever have that shape. The
genuine receipts in `fixtures/` were checked here (TESTED, the parser in
`py/prescan_model.py`):
- the sandbox g5 receipt;
- the legacy receipt;
- the three Xcode receipts (BER, indefinite length).

None of them carries signedAttrs or `crls`, and all of their time fields
are valid.

**Could a prescan fix it?** The prescan column refers to the three checks
modelled in `py/prescan_model.py`. Each only reads bytes and none is a CMS
implementation:

| Check | Placement | What it enforces | Answer when it fails |
|---|---|---|---|
| T | runs first | the syntax of every UTCTime and GeneralizedTime in the tree | 9 |
| A | at the signature step | signedAttrs elements are in DER SET OF order | 5 |
| U | runs first, for JWS | the protected header is valid UTF-8 | 1 |

| # | Row | Kind | Java | OpenSSL | Which follows the spec | Apple could produce it? | Small prescan? |
|---|---|---|---|---|---|---|---|
| 1 | `substrate/cms/attributes-unsorted-signed-as-sent` | receipt, generated | 5 | **0** | **Java.** RFC 5652 §5.3: "SignedAttributes MUST be DER encoded"; X.690 §11.6: SET OF elements in ascending order; RFC 5652 §5.4: the signature covers the DER encoding. The input is not DER, so the signature does not match it | No: Apple receipts carry no signedAttrs at all | **Yes**, check A → 5 |
| 2 | `substrate/cms/attributes-unsorted-signed-sorted` | receipt, generated | 0 | 5 | Both defensible. The input breaks §5.3 (not DER), so rejecting it is conservative. Java re-encodes to DER as §5.4 describes, and accepts | No | No: matching Java needs re-sorting (rewriting) the input. Keep the rejection |
| 3 | `substrate/cms/crls-garbage` | receipt, generated | 0 | 9 | **OpenSSL.** RFC 5652 §5.1 and §10.2.1: `crls` is `RevocationInfoChoices`; garbage there is malformed ASN.1. Java skips the field | No: Apple receipts carry no `crls` | No: matching Java needs dropping the field. Keep |
| 4 | `hostile/endpoint/trailing-garbage` | endpoint JSON body, `…}xyz` | 0 | 21002 | **OpenSSL build** (its Rust JSON layer). RFC 8259 §2: JSON-text = ws value ws, so trailing bytes are not JSON. Java's reader stops after the first value | Not Apple-issued: the body comes from the caller. Apple's verifyReceipt request is a JSON object | Not an OpenSSL question: the same Rust code runs in the pure-Rust core. Keep |
| 5 | `hostile/endpoint/m3-184626924` | endpoint JSON body, `…}2` | 0 | 21002 | same as row 4 | same | same |
| 6-9 | `hostile/jws/m0-534728031`, `m0-672945841`, `m0-718123265`, `m1-160010987` | JWS; the protected header decodes to invalid UTF-8 (bytes 0xB2, 0xD9, 0xE6, 0xC6 inside the `x5c` string) | 1 | 2 | **Java.** RFC 7515 §5.2 step 3: the decoded header MUST be UTF-8 of a valid JSON object; RFC 8259 §8.1. The Rust front end (shared with the pure-Rust core) reaches `x5c` decoding first | No: Apple's headers are ASCII JSON | **Yes**, check U → 1 (in the shared Rust JWS front end) |
| 10-15 | `hostile/receipt-der/g5-m0-701123523`, `g5-m1-236749769`, `g5-m1-324520034`, `g5-m1-853597831`, `gen-m1-933684943`, `gen-m1-280546414` | receipt; a certificate time holds a non-digit byte (0x11, 0xE0, 0xA6, '#', 0x9D; a 't' in place of 'Z'), plus other flips | 9 | 4 | **Java** on the reason. X.680 and RFC 5280 §4.1.2.5.1/§4.1.2.5.2 require digits in fixed positions, and BC refuses at decode. OpenSSL decodes lazily and fails the chain first. Both reject | No: Apple's times are valid (checked above) | **Yes**, check T → 9 |
| 16 | `hostile/receipt-der/gen-m1-619385370` | receipt; the ContentInfo `contentType` OID is changed | 4 | 9 | **OpenSSL.** RFC 5652 §3 and §5.1: SignedData is identified by id-signedData. BC does not check the OID and fails later at the chain | No | No: matching Java means ignoring the OID. Keep |
| 17 | `hostile/receipt-der/g5-m1-127707244` | receipt; an issuer or subject UTF8String holds 0xA5 (invalid UTF-8), plus other flips | 4 | 9 | **OpenSSL.** RFC 5280 §4.1.2.4 (DirectoryString) and RFC 3629: invalid UTF-8 is malformed. OpenSSL refuses at decode; BC decodes lazily and fails the chain | No | No: the only way to match is to parse less strictly. Keep |
| 18 | `hostile/receipt-der/g5-m1-233102848` | receipt; an extension's `extnValue` tag is SEQUENCE instead of OCTET STRING, plus payload flips | 2 | 9 | **OpenSSL** on structure: RFC 5280 §4.1 `extnValue OCTET STRING`. Java reports the certificate (2), a more specific reason. Both reject | No | Only by parsing certificates in Rust, which is the X.509 code this move is meant to drop. Keep |

**Model result** (`results/prescan-model.txt`, a Python model of the three
checks, not a Rust build):

- **Scope:** all receipt and JWS rows of the four corpora and the 5,000
  mutants, 5,740 rows.
- **Java-equal rows** rise from 5,557 to 5,612.
- **New rejections of rows that Java and the build both accept: 0.** No
  genuine receipt is affected.
- **Rows aligned, of the 18:** 11 (rows 1, 6-9 and 10-15). On the 5,000
  mutants, 44 more rows align.
- **Placement matters.** Check A must sit at the signature step, not at
  parse. Placed at parse, it changed 9 mutants that Java already rejects
  for another reason.
- **Check A must not require definite lengths.** Java and OpenSSL both
  accept `substrate/cms/attributes-indefinite-length`.

The remaining 7 rows (2, 3, 4, 5, 16, 17 and 18) are ones where OpenSSL is
stricter or the difference is in the shared JSON layer. Making them match
Java would mean parsing less strictly or rewriting input, and this note
advises against it.

**Row 1 in detail** (the one acceptance Java refuses):

- **What is accepted.** A SignerInfo whose signedAttrs SET OF is sent in
  non-DER order, where the signer computed the signature over exactly those
  non-DER bytes. The attributes include the correct `messageDigest` of the
  content, the chain goes to a pinned root, and the signature is by that
  chain's leaf key.
- **What OpenSSL does.** It verifies over the attributes as received.
  `CMS_Attributes_Verify` is declared as `SEQUENCE_OF` with the SET tag
  (`crypto/cms/cms_asn1.c:403`), so re-encoding keeps the received order
  and only normalises lengths (DOCUMENTED).
- **What Java/BC does.** It re-encodes the attributes as a DER SET, which
  sorts them, and verifies over that. The signer signed the unsorted form,
  so the signature fails, and Java answers 5.
- **Is it a forgery?** No. Producing such a receipt needs the signer's
  private key. Nobody can create it from a genuine receipt: reordering a
  genuine receipt's attributes changes the bytes OpenSSL verifies, and
  OpenSSL then rejects it (row 2).
- **Is it malleability?** Row 2 is the mirror case. Java accepts a
  reordered, non-DER re-encoding of a genuinely signed SignerInfo, so there
  can be two byte encodings of one signed receipt. OpenSSL accepts only the
  bytes that were signed. Neither lets anyone change signed content.
- **Which side the spec takes.** The input breaks RFC 5652 §5.3 (signed
  attributes MUST be DER), and §5.4 defines the signature over the DER
  encoding. Java's rejection therefore follows the spec, and OpenSSL's
  acceptance follows the signer's actual bytes.
- **Relevance to Apple.** Apple's receipts carry no signedAttrs, so for
  genuine input the question never arises. Check A (a byte-order comparison
  of the SET elements, ~15 lines over the existing `asn1.rs` reader) would
  make the OpenSSL build answer 5 like Java.

## 6. Where these results stop holding

- **Platform:** Linux x86_64, headless browsers and Xvfb. There is no
  Safari, no real Lambda and no deployed Worker.
- **Parity scope:** "identical" means identical on the 1,179 corpus rows
  (and the 5,000 mutants where stated).
- **The vendored build** was tested natively only. For the wasm routes,
  openssl-src 400.0.1 has no `wasm32-wasip1` mapping.
- **Section 5's alignment counts are a model.** The three checks are
  written in Python, not in `substrate.rs`. A Rust implementation would
  need the same corpus run to confirm them.
- **Fuzzing** is 2 × 45 minutes on one core each, with OpenSSL's C
  instrumented (no-asm). It found nothing, which does not prove there is
  nothing to find.
- **Data:** every corpus and seed is from `fixtures/` or generated from test
  keys. No production receipt was used.
