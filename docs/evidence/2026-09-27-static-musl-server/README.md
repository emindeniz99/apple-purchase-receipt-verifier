# Static musl aprv-server (2026-09-27, round 10)

Sources for `../2026-09-27-static-musl-server.md`. The round builds the
2026-09-26 aprv-server spike's variant B as fully static musl binaries for
x86_64 and aarch64. Variant B is Wasmtime 49.0.1 runtime-only, with the
canonical module precompiled to a Cranelift `.cwasm` for the target's
baseline ISA and embedded in the binary. The round then:

- proves the binaries are static, and that they run on this glibc host, in
  an empty chroot and in an Alpine minirootfs;
- compares them with the glibc build, with musl's malloc and with mimalloc;
- runs the corpus through the musl server;
- runs an aarch64 correctness smoke under QEMU.

The server crate is not copied. `server.patch` applies to
`../2026-09-26-aprv-server/server`. It adds three spike-only features:
`mimalloc`, `alloc-count` and `cli-fast-exit`. It also adds two entries
to `Cargo.lock` (mimalloc 0.1.52, libmimalloc-sys 0.1.49) and changes no
other dependency.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the wasm bake-off's scratch directory. This round writes under `$SCRATCH/r10`. It reads the module, the calls files and the Node rows from `$SCRATCH/abi`, the Rust toolchain from `$SCRATCH/rustup`, and the zig venv (PyPI `ziglang` + `cargo-zigbuild`) from `$SCRATCH/r11/venv-zig` |
| `$CORPORA` | the substrate bake-off's request corpora (used by `qemu.sh` via round 9's driver) |

## Files

| File | What it is for |
|---|---|
| `server.patch` | Against the aprv-server spike's crate. `mimalloc` makes mimalloc the Rust global allocator. `alloc-count` counts Rust heap allocations and `aprv bench` prints them per call. `cli-fast-exit` means the one-shot CLI does not drop the Wasmtime runtime before exiting. It adds the two `Cargo.lock` entries |
| `scripts/env.sh` | Shared settings. It generates the four request bodies from the ABI v1 calls file; they are byte-identical to the aprv-server spike's |
| `scripts/build.sh` | 1. Builds `aprv-full` with `wasmtime/all-arch` and precompiles one `.cwasm` per triple. 2. Builds every row: `gnu`, `musl`, `musl-mimalloc` for x86_64 with `cargo build`, and `a64-musl` and `a64-musl-mimalloc` with `cargo zigbuild`. It builds the feature sets `min` (what ships) and `spike`, plus `gnu-count` and the `*-fastexit` rows (`ONLY="..."` builds a subset). 3. Builds `aprv-load`. 4. Builds round 9's Rust host with Wasmtime (feature `wt`) for aarch64 musl. It prints sizes, `file` and `readelf` facts, and the compilers recorded in `.comment` |
| `scripts/linkargs.sh` | The exact musl link lines from rustc's `--print link-args`, summarised: linker driver, crt objects, which `libc.a` |
| `scripts/smoke.sh` | `host`, `chroot` (the binary alone in an empty directory) or `qemu`: the CLI's four commands and the server's six routes |
| `scripts/measure.sh` | `static`, `startup`, `bench`, `http`, `rss`, `alloc`, `corpus` (see its header) |
| `scripts/alpine.sh` | The official Alpine minirootfs, sha256-checked. The static server runs in it. Round 11's musl cdylib runs on Alpine's own python3 |
| `scripts/qemu.sh` | aarch64 under qemu-user, correctness only: smoke, the corpus over HTTP, and the 37 ABI tests on round 9's host |
| `scripts/versions.sh` | Machine, tools, crates, the module, and the three `.cwasm` hashes and FDE counts |
| `py/cli_first.py` | CLI start-up: time to the complete verdict on stdout and to process exit, peak RSS and minor faults, from wait4 |
| `py/summarize.py` | The note's tables, from `results/` |
| `results/build.txt`, `results/build-fastexit.txt`, `results/linkargs.txt` | Builds, sizes, link facts |
| `results/static.txt`, `results/smoke.txt`, `results/alpine.txt` | Static-ness; host and empty-chroot smoke; Alpine |
| `results/startup.txt`, `results/bench.txt`, `results/http.txt`, `results/rss.txt` | Timings, 3 to 5 interleaved rounds each |
| `results/alloc.txt` | Rust allocations per call; syscalls per call |
| `results/corpus.txt`, `results/qemu.txt` | Parity (x86_64 musl), aarch64 smoke |
| `results/summary.txt`, `results/versions.txt`, `results/disk.txt` | Tables, versions, disk |

## Reproduce

```sh
export REPO=... SCRATCH=... CORPORA=... PYTHONDONTWRITEBYTECODE=1
F=$REPO/docs/evidence/2026-09-27-static-musl-server
# once: rustup target add --toolchain 1.98.1 x86_64-unknown-linux-musl aarch64-unknown-linux-musl
#       python3 -m venv $SCRATCH/r11/venv-zig && $SCRATCH/r11/venv-zig/bin/pip install ziglang cargo-zigbuild
#       apt: musl-tools (musl-gcc, for mimalloc's C on x86_64 musl), qemu-user, valgrind, strace
sh $F/scripts/build.sh > $F/results/build.txt            # about 15 minutes, up to 1.9 GB of target dir
ONLY="gnu-fastexit-min musl-fastexit-min musl-mimalloc-fastexit-min" sh $F/scripts/build.sh > $F/results/build-fastexit.txt
sh $F/scripts/linkargs.sh > $F/results/linkargs.txt
sh $F/scripts/measure.sh static > $F/results/static.txt
for b in musl-spike musl-mimalloc-spike gnu-spike; do sh $F/scripts/smoke.sh host $SCRATCH/r10/bin/$b; done   > $F/results/smoke.txt
for b in musl-spike musl-mimalloc-spike gnu-spike; do sh $F/scripts/smoke.sh chroot $SCRATCH/r10/bin/$b; done >> $F/results/smoke.txt
for m in startup bench http rss alloc corpus; do sh $F/scripts/measure.sh $m > $F/results/$m.txt; done   # idle machine
sh $F/scripts/alpine.sh > $F/results/alpine.txt
sh $F/scripts/qemu.sh > $F/results/qemu.txt
sh $F/scripts/versions.sh > $F/results/versions.txt
python3 $F/py/summarize.py $F/results > $F/results/summary.txt
```

`smoke.sh chroot` and `alpine.sh` need root, for `chroot`.
