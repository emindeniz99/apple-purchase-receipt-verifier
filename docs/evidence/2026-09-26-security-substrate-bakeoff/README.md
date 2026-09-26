# Security substrate bake-off (2026-09-26)

Sources for `../2026-09-26-security-substrate-bakeoff.md`. The question: can
the Rust core keep its policy while OpenSSL, LibreSSL or AWS-LC, through one
rust-openssl adapter, replace the core's own ASN.1, CMS, X.509, path and
crypto code? Nothing here changes production code. The core is copied to
`$SCRATCH`, patched there and built there.

Placeholders: `$REPO` is the repository root, `$SCRATCH` a scratch directory
outside it, `$SPIKE` this folder, `$CORPORA` a folder of request corpora
(`$SCRATCH/corpora` in the runs recorded here).

## Files

| File | Question it answered |
|---|---|
| `security-openssl/` | The adapter: the only crate with `unsafe`. One source for OpenSSL, LibreSSL and AWS-LC, picked by cargo features (`vendored`, `aws-lc`) and `OPENSSL_DIR`. Features `a1` (verify through `PKCS7_verify`) and `negative-control` (load the default config and trust paths, to prove the isolation check can see them). |
| `security-openssl/build.rs` | Emits `aprv_openssl`, `aprv_libressl` or `aprv_awslc` from openssl-sys's metadata, so library differences are one `cfg` each. |
| `core-patch/substrate.rs` | The policy over the adapter: Java's order of checks and reason codes, no `unsafe`. Replaces the calls into `asn1`/`cms`/`x509`/`chain`/`crypto` for receipts and JWS. |
| `core-patch/core.patch` | Adds the optional dependency, the `substrate*` features and the two dispatch points to a scratch copy of `rust/`. `@SPIKE@` is replaced with this folder by `build-variant.sh`. |
| `scripts/build-libs.sh` | Downloads (pinned URL and sha256) and builds static OpenSSL 4.0.2 and LibreSSL 4.3.2 for Linux x86_64. |
| `scripts/build-variant.sh` | Builds the unchanged `rust/ffi` C ABI over the patched core for one variant. |
| `scripts/all-variants.sh` | Every native variant, one build at a time, then every corpus. |
| `scripts/run-corpora.sh` | One variant through every corpus via the previous spike's `run_rust.py`; writes `results/tri-<variant>-<corpus>.txt`. |
| `py/gen_corpus.py` | The `substrate` corpus (193 requests): time, CMS shapes, path rules, floods, parser stress. |
| `py/tri.py` | Three-way differential: Java oracle, current Rust, candidate. Classes `agree`, `cand=java`, `cand=rust`, `cand-own`, `abi`. |
| `py/where.py` | Which structure a hostile mutation landed in (used to classify `cand-own` rows). |
| `scripts/isolation.sh`, `py/gen_isolation.py`, `c/run1.c` | Trust-store isolation: the chain's real root planted in `SSL_CERT_FILE`, `SSL_CERT_DIR`, a hostile `OPENSSL_CONF`; strace for files and sockets. `run1.c` is also the target for memcheck. |
| `scripts/sizes.sh` | Raw, stripped and gzip size, `NEEDED` libraries and exported symbols of each `.so`. |
| `scripts/bench.sh` | Latency and throughput at 1, 4 and 16 threads, with the Native Image spike's `c/harness.c`. |
| `scripts/loc.sh`, `py/loc.py` | Line, `unsafe` and `cfg` counts. |
| `py/memcheck.py` | Runs corpus rows one per process through `run1` under valgrind memcheck (or a sanitizer build). |
| `py/mutate.py` | A seeded mutation corpus of receipt and JWS rows, for the brief fuzz. |
| `scripts/build-wasm-libs.sh` | Fetches wasi-sdk 34 (pinned sha256) and builds OpenSSL 4.0.2 (works) and LibreSSL 4.3.2 (fails, recorded) for `wasm32-wasip1`. |
| `scripts/build-wasm.sh` | Builds `wasm/shim` for `wasm32-wasip1` or `wasm32-unknown-unknown` over the patched core. Carries the two link fixes the C substrates need on WASI. |
| `wasm/shim/` | A cdylib that links the unchanged `rust/ffi` C ABI and adds `aprv_alloc`/`aprv_dealloc`, so a wasm host can pass bytes in. |
| `wasm/run.mjs` | Runs a corpus through a wasm module under Node (`node:wasi`), Bun or Deno. Same row format as `run_rust.py`. |
| `wasm/wazero/` | The same runner in Go on wazero 1.12.0 (pure Go, no cgo). |
| `py/same.py` | Row-by-row: does a wasm run give the verdict of the native run of the same variant? |
| `scripts/run-wasm-corpora.sh`, `scripts/bench-wasm.sh` | Every corpus through one module under Node and wazero; single-thread wasm latency. |
| `results/` | Raw outputs. `tri-*.txt` (differentials), `isolation*.txt`, `sizes.txt`, `bench.jsonl`, `loc.txt`, `memcheck.txt`, `fuzz.txt`, `wasm-*.txt/jsonl`. |

## Variants

| Name | Substrate | Features | Library source |
|---|---|---|---|
| `rust` | current pure-Rust core | none | this repository |
| `ossl402` | OpenSSL 4.0.2, static | `substrate` | `build-libs.sh openssl` |
| `ossl402pre` | same, with the Rust BER prescan first | `substrate,substrate-prescan` | same |
| `ossl402a1` | same, signature through `PKCS7_verify` | `substrate,substrate-a1` | same |
| `libressl432`, `libressl432a1` | LibreSSL 4.3.2, static | as above | `build-libs.sh libressl` |
| `awslc`, `awslca1` | AWS-LC 1.73.0 in aws-lc-sys 0.41.0 | `substrate-aws-lc` (+`substrate-a1`) | crates.io |
| `ossl36v` | OpenSSL 3.6.3 in openssl-src 300.6.1 | `substrate-vendored` | crates.io |
| `ossl402neg` | `ossl402` with `negative-control` | isolation check only | same |

## Reproduce

Linux x86_64, 4 vCPUs, rustc 1.94.1, clang 18, cmake, ninja, perl, Python 3
with `cryptography` (a venv), JDK 25, strace, valgrind, Node 22, Go 1.25
(through `GOTOOLCHAIN`), Bun 1.3.11, Deno 2.9.7. The Java oracle is the
previous spike's `OracleCli` (`2026-09-25-java-native-image-spike`, its
`build.sh` writes the class path to `$SCRATCH/build/cp.txt`).

```sh
export REPO=... SCRATCH=... CORPORA=$SCRATCH/corpora SPIKE=$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff
PREV=$REPO/docs/evidence/2026-09-25-java-native-image-spike
JAVA="java -cp $(cat $SCRATCH/build/cp.txt) aprvj.OracleCli"

# 1. Corpora and the Java oracle (keys in substrate.jsonl are fresh per run,
#    so the oracle must run on the same file)
python3 $PREV/py/requests_gen.py $REPO/fixtures cases   > $CORPORA/cases.jsonl
python3 $PREV/py/requests_gen.py $REPO/fixtures hostile > $CORPORA/hostile.jsonl
#    algorithms.jsonl: $PREV README step 2 (AlgorithmCorpus.java)
python3 $SPIKE/py/gen_corpus.py $REPO/fixtures > $CORPORA/substrate.jsonl
for c in cases hostile algorithms substrate; do $JAVA $CORPORA/$c.jsonl > $CORPORA/jvm25-$c.jsonl; done

# 2. Native libraries, then every native variant and its differential
$SPIKE/scripts/build-libs.sh openssl
$SPIKE/scripts/build-libs.sh libressl
$SPIKE/scripts/all-variants.sh            # writes results/tri-*.txt

# 3. Isolation, sizes, performance, line counts
$SPIKE/scripts/isolation.sh rust ossl402 libressl432 awslc ossl36v > $SPIKE/results/isolation.txt
OPENSSL_DIR=$SCRATCH/inst/openssl-4.0.2 OPENSSL_STATIC=1 \
  $SPIKE/scripts/build-variant.sh ossl402neg substrate,substrate-negative-control
$SPIKE/scripts/isolation.sh ossl402neg > $SPIKE/results/isolation-negative-control.txt
$SPIKE/scripts/sizes.sh rust ossl402 ossl402pre ossl402a1 libressl432 awslc ossl36v > $SPIKE/results/sizes.txt
$SPIKE/scripts/bench.sh rust ossl402 libressl432 awslc ossl36v > $SPIKE/results/bench.jsonl
$SPIKE/scripts/loc.sh

# 4. Memory checks and the brief fuzz (run1 per variant as in isolation.sh)
python3 $SPIKE/py/memcheck.py $SCRATCH/mc/run1-ossl402 $REPO $SCRATCH/mc/w-ossl402 \
  $CORPORA/cases.jsonl $CORPORA/algorithms.jsonl $CORPORA/substrate.jsonl $CORPORA/hostile.jsonl:4
cat $CORPORA/cases.jsonl $CORPORA/substrate.jsonl > $SCRATCH/seedpool.jsonl
python3 $SPIKE/py/mutate.py $SCRATCH/seedpool.jsonl 5000 20260926 > $CORPORA/fuzz.jsonl
$JAVA $CORPORA/fuzz.jsonl > $CORPORA/jvm25-fuzz.jsonl
$SPIKE/scripts/run-corpora.sh rust fuzz; $SPIKE/scripts/run-corpora.sh ossl402 fuzz   # etc.

# 5. Wasm
$SPIKE/scripts/build-wasm-libs.sh wasi-sdk
$SPIKE/scripts/build-wasm-libs.sh openssl
$SPIKE/scripts/build-wasm-libs.sh libressl        # fails: see the note, section 7
WS=$SCRATCH/wasi-sdk-34.0-x86_64-linux; export WASI_SDK=$WS
T="--target=wasm32-wasip1 --sysroot=$WS/share/wasi-sysroot"
$SPIKE/scripts/build-wasm.sh rust wasm32-wasip1 ""
$SPIKE/scripts/build-wasm.sh rust-uu wasm32-unknown-unknown ""
CC_wasm32_wasip1=$WS/bin/clang CFLAGS_wasm32_wasip1="$T" AR_wasm32_wasip1=$WS/bin/llvm-ar \
  OPENSSL_DIR=$SCRATCH/inst-wasm/openssl-4.0.2 OPENSSL_STATIC=1 \
  $SPIKE/scripts/build-wasm.sh ossl402-w wasm32-wasip1 substrate
F="$T -DOPENSSL_NO_SOCK -DOPENSSL_NO_TTY"
CC_wasm32_wasip1=$WS/bin/clang CXX_wasm32_wasip1=$WS/bin/clang++ AR_wasm32_wasip1=$WS/bin/llvm-ar \
  CFLAGS_wasm32_wasip1="$F" CXXFLAGS_wasm32_wasip1="$F -D__wasilibc___struct_iovec_h -D__DEFINED_struct_iovec" \
  BINDGEN_EXTRA_CLANG_ARGS_wasm32_wasip1="$F" CMAKE_TOOLCHAIN_FILE_wasm32_wasip1=$WS/share/cmake/wasi-sdk-p1.cmake \
  $SPIKE/scripts/build-wasm.sh awslc-w wasm32-wasip1 substrate-aws-lc
go build -C $SPIKE/wasm/wazero -o $SCRATCH/wazero-run .
for m in rust:rust ossl402-w:ossl402 awslc-w:awslc; do
  $SPIKE/scripts/run-wasm-corpora.sh ${m%%:*}-wasip1 \
    $SCRATCH/target-wasm-${m%%:*}/wasm32-wasip1/release/aprv_wasm_shim.wasm ${m#*:}
done
#    Bun: bun wasm/run.mjs ... (APRV_FIX_RANDOM_GET=1 for OpenSSL); Deno: deno run --allow-read --allow-env wasm/run.mjs ...
$SPIKE/scripts/bench-wasm.sh ossl402-w-wasm32-wasip1 <module> 1000
```

Pinned downloads (all checked by sha256 in the scripts): OpenSSL 4.0.2
`736b4675…543a8`, LibreSSL 4.3.2 `edf01aee…0847b5` (signed SHA256 file),
wasi-sdk 34.0 `b761e3a0…984b2c4` (no published checksum; first-use hash).
Crates come from crates.io at the versions in `security-openssl/Cargo.toml`
and the ffi crate's `Cargo.lock`.

No binaries, archives, toolchains or library sources are kept here; sizes
and hashes of the built artifacts are in `results/sizes.txt` and
`results/wasm-sizes.txt`.
