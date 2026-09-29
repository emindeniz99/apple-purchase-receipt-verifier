# Static musl aprv-server: x86_64 and aarch64, musl malloc against mimalloc

Date: 2026-09-27 (round 10). Code, scripts and raw results are in
`2026-09-27-static-musl-server/`. Its `README.md` has the file table and
the commands to reproduce.

**Question.** Can aprv-server ship as one fully static musl binary per
architecture, and what does that cost against the glibc build? The server
shape is the one `2026-09-26-aprv-server.md` settled on: Wasmtime 49.0.1
runtime-only, with the canonical module precompiled to a Cranelift `.cwasm`
and embedded. This round measures size, start-up, throughput, RSS and
parity, with musl's own malloc and with mimalloc. It feeds the release
shape of the server binaries.

Labels: TESTED (ran here), DOCUMENTED (read in a primary source), EXPECTED
(inferred, not run). Nothing under `python/`, `rust/`, `docs/rust-core` or
any other production path changed. The server crate is the 2026-09-26
spike's, unchanged except for `server.patch`, which adds three spike-only
features (`mimalloc`, `alloc-count`, `cli-fast-exit`).

**Environment** (`results/versions.txt`):

- Ubuntu 24.04 x86-64, 4 vCPUs (Intel Xeon 2.80 GHz, the CPU of rounds 9
  and 11), 16 GB RAM.
- Rust 1.98.1 with the rust-std targets `x86_64-unknown-linux-musl` and
  `aarch64-unknown-linux-musl`; zig 0.16.0 and cargo-zigbuild 0.23.4 from
  PyPI (the aarch64 builds only); host gcc 13.3; musl-tools 1.2.4 (the
  `musl-gcc` wrapper that builds mimalloc's C on x86_64).
- Crates: wasmtime 49.0.1 (`runtime`, `std`), axum 0.8.9, tokio 1.53.1,
  mimalloc 0.1.52 / libmimalloc-sys 0.1.49 (mimalloc 3.3.2, its default).
- Module `aprv-abi1.wasm` sha256 `b14e14b2…87b636b3`, precompiled per triple
  with an explicit target, so the baseline ISA with no host CPU features
  (`results/build.txt`).

## Answer

- **Both static binaries build and run (TESTED).**
  - x86_64 is a `static-pie`; aarch64 is `-static` non-PIE.
  - Neither has an INTERP header or a NEEDED entry.
  - The x86_64 musl binaries serve every CLI command and HTTP route from
    an empty directory that holds only the binary, and from an official
    Alpine 3.24.2 minirootfs.
  - The glibc build fails in that empty directory with ENOENT (no loader).
- **Size:** +1.3% stripped against glibc (10.46 MB against 10.32 MB), +2.1%
  gzipped (3.66 MB against 3.58 MB). aarch64 is 10.15 MB, gzip 3.39 MB.
- **Throughput:** musl is 6 to 8% below glibc per server CPU-second,
  receipt and JWS alike. Callgrind counts the same instructions for both,
  so that gap is not extra work, and the round-to-round ranges overlap.
- **RSS:** musl uses 1.5 to 2 MiB less.
- **Parity:** the corpus through the musl server matches the glibc server
  row for row.
- **One real problem, with a one-line fix.** A static musl CLI takes
  70 ms from spawn to exit against glibc's 15 ms. The verdict is already on
  stdout at 14.5 ms (1 CPU). The other 55 ms is teardown: Wasmtime
  deregisters the module's unwind info one FDE at a time, and LLVM
  libunwind makes that quadratic in the FDE count (section 3). Not
  dropping the runtime in the one-shot path (`cli-fast-exit`) brings the
  musl CLI to 15 to 18 ms to exit. Server mode is unaffected: it pays the
  cost once, at shutdown.
- **mimalloc: no.** It gains no throughput. It costs 11 MiB more peak RSS
  in the CLI and 17 MiB more in the server. It makes the server's first
  verification 18 ms instead of 6 ms, and adds C code built by a second
  compiler. Wasmtime does not allocate heavily on the hot path (section 4),
  so there is nothing for a faster allocator to win.

**Recommendation from the evidence:** ship static musl with musl's own
malloc for both architectures, and exit the one-shot CLI without dropping
the Wasmtime runtime. aarch64 is correct under emulation. Its speed is
unmeasured, as in round 11.

## 1. Toolchain, linker, libc (TESTED, `results/build.txt`, `results/linkargs.txt`)

| Row | Build | Linker driver | libc linked | `file` |
|---|---|---|---|---|
| gnu | `cargo build --target x86_64-unknown-linux-gnu` | host `cc`, rust-lld (`.comment`: LLD 22.1.8) | glibc 2.39, dynamic | PIE, interpreter `/lib64/ld-linux-x86-64.so.2`, NEEDED libgcc_s, libm, libc |
| musl, musl-mimalloc | `cargo build --target x86_64-unknown-linux-musl` | host `cc` (gcc 13.3, GNU ld) | rustc's self-contained musl: `rcrt1.o`, `crti.o`, `crtbeginS.o`, `crtendS.o`, `crtn.o`, `-lc` from the rustlib `self-contained` directory, `-static-pie` | static-pie linked |
| a64-musl, a64-musl-mimalloc | `cargo zigbuild --target aarch64-unknown-linux-musl` | zig cc (`.comment`: LLD 21.1.0, clang 21.1.0) | the same rustc self-contained musl (`crt1.o`…, `-lc`), `-static -no-pie` | statically linked |

- **Which musl.** rustc's self-contained `libc.a` defines `statx`, so it is
  musl 1.2.5 or later. The `.comment` "GCC: (GNU) 9.4.0" in every musl
  binary, aarch64 included, comes from those prebuilt objects. The zig
  path therefore also links rustc's musl rather than zig's own (TESTED from
  the link line). zig contributes the linker, and clang 21 objects of its
  own (which ones was not checked).
- **mimalloc's C.** On x86_64 musl, cc-rs 1.5.1 picks `musl-gcc`: it looks
  for `x86_64-linux-musl-gcc`, then `musl-gcc` (DOCUMENTED in its source).
  Those are musl 1.2.4 headers against a 1.2.5 `libc.a`, which is fine for
  musl's stable ABI (EXPECTED). On aarch64, zig's clang compiles it.
- **The precompiled modules.**
  - The `.cwasm` for `x86_64-unknown-linux-gnu` and for
    `x86_64-unknown-linux-musl` are the same size (8,458,112 bytes) and
    differ in 978 bytes. That is target metadata, since the code is the
    same ISA; whether one loads in the other was not tested. Each row
    embeds its own.
  - Precompiling for aarch64 from an x86_64 host needs the compiler build
    with `wasmtime/all-arch`. Without it `precompile` fails with "Support
    for this target is disabled".

**Sizes** (features `server,embed`, what ships; stripped with llvm-strip;
`results/summary.txt`):

| Binary | Raw | Stripped | gzip -9 | xz -9 |
|---|---:|---:|---:|---:|
| glibc x86_64 | 10,801,512 | 10,322,744 | 3,580,885 | 2,726,496 |
| musl x86_64 | 10,957,424 | 10,457,856 (+1.3%) | 3,656,734 (+2.1%) | 2,789,028 |
| musl + mimalloc x86_64 | 11,134,640 | 10,615,552 (+2.8%) | 3,714,472 (+3.7%) | 2,837,972 |
| musl aarch64 | 10,150,928 | 10,150,752 | 3,390,574 | 2,430,620 |
| musl + mimalloc aarch64 | 10,282,616 | 10,282,440 | 3,442,814 | 2,472,988 |

The embedded `.cwasm` is about 8.4 MB of each, and 2.7 MB of each gzip
(round 8). The aarch64 builds come out of zig's linker already stripped.

## 2. Where it runs (TESTED, `results/static.txt`, `results/smoke.txt`, `results/alpine.txt`)

- **`ldd`:** "statically linked" (x86_64) or "not a dynamic executable"
  (aarch64). **`readelf`:** INTERP 0 and NEEDED 0 for every musl binary.
- **This glibc host:**
  - CLI: `info`, `verify-receipt` (verified), `verify-signed-data` (the
    public route's answer, `INVALID_CHAIN` against Apple's roots) and
    `verify-receipt-endpoint sandbox` (status 0).
  - Server: `/healthz` 200, `/readyz` 200, and the receipt, public-JWS,
    test-anchor-JWS (`/spike/call/258`, verified) and sandbox-endpoint
    routes, all 200 with the expected bodies.
- **An empty chroot.** The directory held exactly one file, the binary:
  no libc, no loader, no `/proc`, `/dev` or `/etc`.
  - Both x86_64 musl rows passed the same checks there as on the host
    (`info`, the three CLI commands, server start, the six routes), with
    curl reaching the chrooted server over loopback.
  - The glibc binary in the same place fails every command with
    `No such file or directory`: its interpreter is missing.
- **Alpine minirootfs 3.24.2 x86_64.** Fetched from
  `dl-cdn.alpinelinux.org`, with its sha256 checked against that release's
  `latest-releases.yaml`: `c5ca053c…90388677`. The static server passed the
  CLI receipt check and five HTTP routes inside it.

## 3. Start-up, and the teardown that musl makes quadratic

**CLI start-up** (`py/cli_first.py`, `results/startup.txt`). One process
per verification, fed the g5 receipt on stdin. "First result" is the
moment the complete verdict has arrived on stdout; "exit" is the moment
the process has exited, which is what a caller waiting for the exit status
sees. Each cell is the median of three interleaved rounds, each the median
of 7 cold runs (range of the round medians).

| Row | First result, 4 CPUs | Exit, 4 CPUs | First result, `taskset -c 0` | Exit, `taskset -c 0` | Peak RSS |
|---|---:|---:|---:|---:|---:|
| glibc | 13.5 ms (13.1–13.5) | 14.5 ms | 15.0 ms (14.0–16.1) | 15.8 ms | 21.3 MiB |
| musl | 13.2 ms (13.0–13.2) | **70.1 ms** | 14.5 ms (14.3–14.8) | **70.8 ms** | 19.8 MiB |
| musl + mimalloc | 15.9 ms | **114.2 ms** | 15.5 ms | **100.0 ms** | 31.4 MiB |
| glibc, fast exit | 15.6 ms | 16.3 ms | 14.9 ms | 15.5 ms | 21.2 MiB |
| **musl, fast exit** | 14.4 ms | **15.2 ms** | 17.5 ms | **18.1 ms** | 19.8 MiB |
| musl + mimalloc, fast exit | 15.7 ms | 16.6 ms | 15.0 ms | 15.7 ms | 31.4 MiB |

**Server start-up** (the spike's `startup.py`, 7 runs, `results/rss.txt`):

| Row | Start to listening | First verification | Warm | RSS idle / peak |
|---|---:|---:|---:|---:|
| glibc | 11.4 ms | 7.4 ms | 4.95 ms | 20.9 / 21.9 MiB |
| musl | 10.0 ms | 6.1 ms | 5.19 ms | 19.0 / 19.9 MiB |
| musl + mimalloc | 12.7 ms | 17.9 ms | 5.68 ms | 30.5 / 37.3 MiB |

**Why the musl CLI exits 55 ms late.**

1. **Where it happens (TESTED).** `strace -r` shows a 53 ms stretch of
   pure userspace work *after* the verdict is written and the input file
   is closed, just before the runtime's memory is unmapped.
2. **What it is (TESTED).** Callgrind over one musl CLI run puts 94.4% of
   all instructions (687 M of 728 M) in `__deregister_frame` →
   `libunwind::DwarfFDECache::removeAllIn`. The glibc run executes 40 M
   instructions in total.
3. **Why musl only (DOCUMENTED, Wasmtime 49.0.1
   `src/runtime/vm/sys/unix/unwind.rs`).** Wasmtime detects LLVM libunwind
   (the unwinder a static musl Rust binary links) through
   `__unw_add_dynamic_fde`. With libunwind it registers every FDE of the
   module separately, and deregisters them one by one when the module
   drops. With libgcc (glibc) it registers the whole `.eh_frame` in one
   call.
4. **Why it is quadratic.** libunwind's `removeAllIn` scans its whole FDE
   cache on every call. This module has 13,093 FDEs (`readelf` over the
   `.cwasm`, `results/versions.txt`), so teardown is quadratic in the
   number of compiled functions. Wasmtime's own comment reverses the order
   to keep libgcc's linked list linear, which does not help libunwind.
5. **mimalloc makes it longer still,** by a further 30 to 45 ms at exit.
   Callgrind counts the same instructions, and the delay also disappears
   with fast exit. Its cause was not investigated further.

**The fix, measured.** `cli-fast-exit` wraps the loaded runtime in
`ManuallyDrop` in the one-shot path, so the process exits without
deregistering and the kernel reclaims everything. The musl CLI then exits
at 15.2 ms (4 CPUs) and 18.1 ms (1 CPU), level with glibc. The change is
two lines in `one_shot` (`server.patch`).

**Who else pays it (EXPECTED, not run):**

- **macOS.** Wasmtime treats it as always-libunwind, so a macOS CLI build
  should show the same exit delay.
- **Long-running servers** pay it once, at shutdown: about 55 ms for this
  module.

This is a performance issue, not a security one, and a candidate for an
upstream Wasmtime report: deregistering in bulk, or skipping it at process
exit.

## 4. Throughput and the allocator (TESTED)

**In-process, no HTTP** (`aprv bench` on CPU 0, one thread, 5 interleaved
rounds, calls/s median (min–max), `results/bench.txt`):

| Op, lifecycle | glibc | musl | musl + mimalloc |
|---|---:|---:|---:|
| receipt, fresh instance per call | 246.2 (222.0–261.5) | 230.4 (212.0–239.6), −6.4% | 231.7 (213.5–233.5), −5.9% |
| receipt, pooled instance | 588.5 (511.1–607.6) | 553.9 (537.2–577.4), −5.9% | 551.3 (462.3–574.8), −6.3% |
| JWS, fresh | 107.2 (101.9–110.5) | 96.8 (92.7–100.5), −9.7% | 101.6 (89.4–103.6), −5.2% |
| JWS, pooled | 150.8 (137.6–161.2) | 146.2 (137.9–149.5), −3.1% | 138.7 (120.8–142.7), −8.0% |

**Over HTTP.** The server ran on CPU 0 (1 worker, fresh lifecycle, the
spike's default) and aprv-load on CPUs 1–3 with one keep-alive connection,
for 8 s, 3 interleaved rounds. The table gives requests per server
CPU-second (`results/http.txt`):

| Op | glibc | musl | musl + mimalloc |
|---|---:|---:|---:|
| receipt | 232.0 (230.1–252.6) | 218.6 (211.7–223.8), −5.8% | 217.6 (213.2–220.7), −6.2% |
| JWS | 103.7 (101.9–108.2) | 95.9 (90.6–100.0), −7.5% | 96.4 (95.7–101.4), −7.0% |
| p50 latency, receipt / JWS | 4.11 / 9.25 ms | 4.47 / 9.90 ms | 4.39 / 9.95 ms |
| server peak RSS | 22.2 MiB | 20.2 MiB | 37.5 MiB |

Every row stays about 10 times above the 10 JWS/s-per-core floor.

**Does Wasmtime allocate heavily on the hot path? No** (`results/alloc.txt`):

- **Rust heap allocations**, from a counting global allocator on the glibc
  row:
  - 21 allocations and about 190 KB per call with a fresh instance per
    call;
  - 1 allocation and 0.8 to 2.2 KB per call with a pooled instance.
- **Guest linear memory is Wasmtime's own `mmap`, not malloc.**
- **Syscalls per call, fresh lifecycle.** glibc makes 11.2: 7.2
  `mprotect`, 2.4 `mmap`, 1.2 `munmap`, 0.4 `brk`. musl makes 16.6: the
  same `mprotect`s, plus 5.3 `mmap` and 4.1 `munmap`, because musl's
  mallocng returns those ~190 KB blocks to the kernel. mimalloc brings the
  count back to 10.8 and wins nothing.
- **Pooled lifecycle:** no syscalls per call on any row, and musl is still
  ~6% behind.

**The musl gap is not extra instructions (TESTED).** Callgrind of 50
pooled receipt calls gives:

- glibc: 1,071 M instructions.
- musl: 1,075 M instructions outside the teardown of section 3.
- The guest's own compiled code has identical counts on both.
- The libc work the guest triggers is 0.3% of the total: `memory.fill`
  and `memory.copy` become libc `memset`/`memmove`, glibc's AVX2 variants
  against musl's generic ones.

So the 6% is not in code either side runs more of. The ranges overlap,
and this spike does not attribute it further.

## 5. Parity (TESTED, `results/corpus.txt`)

All 6,179 rows went over HTTP through `musl-spike` and
`musl-mimalloc-spike` (fresh lifecycle, 4 workers), using the spike's
`corpus_http.py`:

- **6,153 byte-identical to Node** (384 on the public routes and 5,769 on
  the spike route for the test variants);
- **25 answered HTTP 413,** the server's 3 MiB request-body cap, where
  Node answered a refusal;
- **1 row not expressible in ABI v1.**

That is exactly the breakdown of the glibc server on 2026-09-26
(`2026-09-26-aprv-server/results/corpus-http.txt`), corpus by corpus.

## 6. aarch64 under QEMU: correctness smoke only (TESTED, `results/qemu.txt`)

`qemu-aarch64` 8.2.2, user mode. **None of these timings are ARM64
performance.**

- **The static aarch64 server** (embedded aarch64 baseline `.cwasm`):
  - all four CLI commands and all six HTTP routes answered as on x86_64;
  - the 6,179-row corpus over HTTP gave the same breakdown as section 5
    (161 s, emulated).
- **The 37 ABI tests.** aprv-server exposes no raw exports, so these ran
  on round 9's Rust host built with Wasmtime 49.0.1 (feature `wt`) as a
  static aarch64 musl binary. It compiled the module with Cranelift's
  aarch64 backend at start, and round 9's driver ran it. Result: **37/37
  ABI tests and 2/2 isolation checks.**

## 7. Round 11's open item: the musl Wasmi cdylib on a musl Python (TESTED, `results/alpine.txt`)

Round 11 built its Wasmi cdylib for `x86_64-unknown-linux-musl`
(`-crt-static` off, `NEEDED libc.so`) but could not load it anywhere.

- Rebuilt the same way (`cargo zigbuild`) and loaded by round 11's ctypes
  facade on the Alpine rootfs's own `python3` (Python 3.14.7, installed
  with `apk` through this machine's proxy), it **verified g5** with fuel
  5e9 and the 64 MiB cap. That took 71 ms from load to verdict.
- **Two ways to get this wrong, both hit here:**
  - The same `-crt-static` build linked by the host `cc` instead of zig
    silently links glibc (NEEDED `libc.so.6`) while claiming the musl
    target.
  - Alpine's OpenSSL reads `/etc/ssl/cert.pem`, not only
    `ca-certificates.crt`.

## Where these results stop holding

- **CPU and targets.** One x86-64 CPU model. aarch64 speed is unmeasured,
  and its correctness is under emulation only.
- **Versions and module.** Wasmtime 49.0.1 exactly, with Rust 1.98.1's
  bundled musl and this module. The teardown cost scales with the square
  of the FDE count, so it moves with the module's function count.
- **Noise.** Throughput differences under about 5 to 10% are within the
  round-to-round ranges above.
- **Allocator.** mimalloc was tested at its crate defaults (v3, no
  `secure`, no `local_dynamic_tls`).

## Disk and processes (`results/disk.txt`)

- **Free disk:** 5.8 GB at the start, 3.5 GB at the lowest point (during
  the builds, before the x86_64 target directory was deleted mid-run),
  5.5 GB at the end.
- **Kept in scratch:** the built binaries and the three `.cwasm` files,
  about 380 MB. Removed: the target directories, the Alpine rootfs, and
  the callgrind and strace outputs.
- **Processes:** no background process is left.
