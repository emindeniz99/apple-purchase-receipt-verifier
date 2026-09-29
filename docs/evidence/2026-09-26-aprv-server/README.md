# aprv-server spike (2026-09-26)

Sources for `../2026-09-26-aprv-server.md`: an HTTP-to-Wasm-ABI adapter that
hosts the canonical `aprv-abi1.wasm` through the `wasmtime` crate, its
one-shot CLI mode, a Java 8 client that runs it as a supervised child, a PHP
client, and a Dockerfile. Nothing here touches production code; CI builds
none of it.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the wasm bake-off's scratch directory; the canonical module is `$SCRATCH/abi/art/aprv-abi1.wasm`, the ABI round's calls and Node rows are `$SCRATCH/abi/calls` and `$SCRATCH/abi/run` (read-only here); this round writes under `$SCRATCH/server` |
| `$JDK8` | a Temurin 8 JDK home |

## Files

| File | Question it answered |
|---|---|
| `server/Cargo.toml`, `Cargo.lock` | The binary `aprv` and its features: `compile` (Cranelift, variant A), `embed`, `server`, and the spike-only `spike`, `crash`, `pooling`, `pulley`. Variant B is `--no-default-features --features server,embed`: Wasmtime with `runtime` and `std` only |
| `server/src/abi.rs` | The ABI v1 bridge: one `Config`, module loading (embedded, or a side file whose SHA-256 must equal the hash pinned at build time), the two host imports (system clock, OS CSPRNG), the one `invoke(op, bytes) -> bytes`, and the two lifecycles (`pool`, `fresh`) |
| `server/src/server.rs` | The HTTP routes, the token check, managed mode (loopback, port 0, token on stdin, exit on stdin EOF), status mapping |
| `server/src/main.rs` | The one-shot CLI (`verify-receipt`, `verify-signed-data`, `verify-receipt-endpoint <env>`), `precompile`, `info`, and the spike-only in-process `bench` |
| `loadtest/` | `aprv-load`: keep-alive HTTP client (one write per request, `TCP_NODELAY`), latency percentiles, and requests per server CPU-second from `/proc/<pid>/stat` |
| `py/corpus_http.py` | Runs every ABI v1 call of the five corpora through the server and compares each answer with the Node row of the same module |
| `py/startup.py` | Start-up, first verification and resident memory of one server binary |
| `py/cli_bench.py` | Process-per-call latency and throughput of the CLI |
| `java/AprvClient.java` | The Java 8 client: resolution order URL, executable, download; supervisor; download with pinned SHA-256, file lock and owner-only cache |
| `java/Tests.java` | The Java 8 checks and the round-trip benchmark |
| `php/Aprv.php`, `php/run.php` | The PHP façade with the CLI and HTTP transports, and its checks |
| `docker/Dockerfile` | Multi-stage image of variant B, non-root, loopback by default |
| `scripts/env.sh`, `scripts/lib.sh` | Shared settings; start and stop a server in the background |
| `scripts/build.sh` | Builds every variant into `$SCRATCH/server/bin` and precompiles the module |
| `scripts/bench-http.sh` | Lifecycle `pool` against `fresh` over HTTP, 1/2/4 clients |
| `scripts/bench-inprocess.sh` | The same lifecycles in-process (no HTTP), plus fresh instances from the pooling allocator |
| `scripts/corpus.sh` | The corpus through the server, both lifecycles |
| `scripts/measure.sh` | `sizes`, `server` (variant A against B), `cli`, `baseline` (explicit-target precompile) |
| `scripts/java.sh`, `scripts/php.sh`, `scripts/docker.sh` | The Java 8, PHP and Docker runs |
| `scripts/ppc64le.sh` | Pulley: on x86_64, and variant B cross-built for ppc64le under qemu-user |
| `results/*.txt` | The outputs the note cites: `sizes`, `server-a-vs-b`, `bench-http`, `bench-inprocess`, `corpus-http`, `cli`, `java8`, `php`, `pulley`, `baseline-target`, `docker`, `info`, `versions` |

## Reproduce

```sh
export REPO=... SCRATCH=... JDK8=...
EV=$REPO/docs/evidence/2026-09-26-aprv-server
sh $EV/scripts/build.sh                       # about 7 minutes, 1.1 GB of target dir
. $EV/scripts/env.sh                          # for $SV below
sh $EV/scripts/measure.sh sizes    > $EV/results/sizes.txt
sh $EV/scripts/bench-http.sh $SV/bin/aprv-spike > $EV/results/bench-http.txt
sh $EV/scripts/bench-inprocess.sh > $EV/results/bench-inprocess.txt
sh $EV/scripts/corpus.sh $SV/bin/aprv-spike     > $EV/results/corpus-http.txt
sh $EV/scripts/measure.sh server   > $EV/results/server-a-vs-b.txt
sh $EV/scripts/measure.sh cli      > $EV/results/cli.txt
sh $EV/scripts/measure.sh baseline > $EV/results/baseline-target.txt
sh $EV/scripts/java.sh             > $EV/results/java8.txt 2>&1
sh $EV/scripts/php.sh              > $EV/results/php.txt
sh $EV/scripts/docker.sh           > $EV/results/docker.txt
sh $EV/scripts/ppc64le.sh          > $EV/results/pulley.txt   # needs the rust-std target, the cross gcc and qemu-user
```

`build.sh` uses rustc 1.98.1 (`$SCRATCH/rustup`) with its own
`CARGO_HOME` and `CARGO_TARGET_DIR` under `$SCRATCH/server`. The embedded
module comes from `APRV_WASM` / `APRV_CWASM` at build time; the pinned
hash of a side-file module from `APRV_CWASM_SHA256`.

At run time: `APRV_LISTEN` (default `127.0.0.1:8080`), `APRV_LIFECYCLE`
(`fresh` default, or `pool`), `APRV_WORKERS` (default: the CPU count),
`APRV_TOKEN` (optional for a standalone server), `APRV_MODULE_FILE` (a side
file). `APRV_TARGET` (spike only) selects a Wasmtime target such as
`pulley64` or `x86_64-unknown-linux-gnu` for `precompile`.
