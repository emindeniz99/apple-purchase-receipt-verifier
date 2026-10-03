# aprv-server

`aprv` is one Rust binary that runs the released `aprv.wasm` component
through Wasmtime. It is an HTTP server (`aprv serve`), the managed child
the Java 8 `-wasm` engine and PHP start (`aprv serve --managed`), and a
one-shot CLI (`aprv verify-receipt` and friends).

It adds no verification logic. It has no base64 rule, no CMS, JWS or
certificate code and no trust decision: a route or a command picks one of
the component's four operations (`aprv:verifier/verify@0.1.0`,
[`wit/aprv.wit`](wit/aprv.wit)) and passes the bytes through. The server
therefore cannot disagree with the other packages about a verdict. The
design is in `docs/rust-core/ARCHITECTURE.md` §7.7 and
`docs/rust-core/THREAT-MODEL.md` §5 and §6.

## Modes

| Command | What it does |
|---|---|
| `aprv serve` | HTTP on `127.0.0.1:8080`, or on `APRV_LISTEN` / `--listen` |
| `aprv serve --managed` | The child of a Java 8 or PHP parent; see [Managed mode](#managed-mode) |
| `aprv verify-receipt` | stdin: the receipt's `receipt-data` string (base64 of the DER) |
| `aprv verify-signed-data` | stdin: a compact JWS |
| `aprv verify-receipt-endpoint production\|sandbox` | stdin: a verifyReceipt request body; stdout: Apple's response |
| `aprv info` | JSON: the component's SHA-256, the Wasmtime version and features, the limits (`max_input_bytes` from one `init` with the built-in roots) |
| `aprv precompile C.wasm --target T -o F.ccwasm` | The full build only; see [The precompile rule](#the-precompile-rule) |

### Flags and environment

| Flag | Commands | Meaning |
|---|---|---|
| `--roots FILE` | serve, CLI | A file of trusted roots; repeat the flag for several files, whose roots add up in order. A file whose first byte is 0x30 (an ASN.1 SEQUENCE, the rule the core uses) is one DER certificate, such as Apple's `.cer` files, passed to `init` as it is. Any other file is text: one base64 root per line (DER, or PEM bytes, which the module reads as is), or PEM `CERTIFICATE` blocks, which the `pem` crate unwraps to DER so `/v1/info` reports DER fingerprints; `#` comments and blank lines are skipped. An empty file is refused. Without the flag, the three Apple roots built into the module |
| `--now-ms N` | CLI | The verification clock, ms since the Unix epoch (u64). Default: the system clock |
| `--listen ADDR` | serve | The bind address; overrides `APRV_LISTEN`. Default `127.0.0.1:8080` |
| `--token-file FILE` | serve | The token `/v1/` routes require (trimmed). Overrides `APRV_TOKEN` |
| `--lifecycle pool\|fresh` | serve | `pool` (default): instances are kept, one request at a time each, at most one per worker, and one that trapped or broke the interface is destroyed, never reused. `fresh`: a new store, instance and `init` per request. The default follows DECISIONS.md R23: `init` costs 2.3 to 3.7 ms and a fresh instance 1.45 to 4 times a pooled call (`docs/evidence/2026-09-29-init-cost.md`) |
| `--workers N` | serve | Concurrent verifications. Default: the CPU count |
| `--time-limit-ms N` | serve, CLI | The guest time limit per call. Default 10,000 |
| `--component FILE.wasm` | all | The full build only: compile this component at start instead of the embedded one (development and tests) |

`aprv --help` and `aprv <command> --help` print the same, generated from
the parser (`clap`); a bad flag or value exits 2.

| Variable | Meaning |
|---|---|
| `APRV_LISTEN` | `serve`'s bind address. `--managed` ignores it |
| `APRV_TOKEN` | `serve`'s token, when `--token-file` is not given |
| `APRV_CCWASM` | Build time only: the `.ccwasm` the runtime-only build embeds |

These belong to the server binary. The language packages define no
environment variables of their own.

### CLI exit codes

| Code | Meaning |
|---|---|
| 0 | A result: the module's JSON is on stdout, verified or not |
| 2 | Usage or configuration: a bad flag, an unreadable `--roots` file, roots `init` refused |
| 3 | stdin is over the module's size cap: `max_input_bytes` long or longer, the length the module's `init` answer states (3,145,729, one over its 3,145,728-byte cap; `aprv info` shows it). The module got that many bytes and its answer, its own size refusal, is on stdout as for 0 |
| 70 | A trap, an ABI fault or a load failure; the message is on stderr |

The CLI never drops the Wasmtime runtime before it exits
(`cli-fast-exit`): under the LLVM libunwind a static musl binary links,
deregistering the compiled code's unwind information cost 55 ms per
process (`docs/evidence/2026-09-27-static-musl-server.md` §3).

## The wire contract

| Route | Body | Operation |
|---|---|---|
| `POST /v1/receipt/verify` | the `receipt-data` string | `verify-receipt(now-ms, body)` |
| `POST /v1/signed-data/verify` | the compact JWS | `verify-signed-data(now-ms, body)` |
| `POST /v1/verify-receipt/production` | a verifyReceipt request | `verify-receipt-endpoint(0, now-ms, body)` |
| `POST /v1/verify-receipt/sandbox` | a verifyReceipt request | `verify-receipt-endpoint(1, now-ms, body)` |
| `GET /v1/info` | | the component's SHA-256, the roots' SHA-256 fingerprints, the engine and limits |
| `GET /healthz`, `GET /readyz` | | `ok`, `ready` (the server listens only after its first `init` succeeded) |
| `GET /openapi.json` | | [`openapi.yaml`](openapi.yaml) as JSON, the wire schemas bundled |

- **A verification result is HTTP 200** with the module's JSON, byte for
  byte, verified or not: `{"verified":true,"payload":...,"environment":...}`,
  `{"verified":false,"reason":"...","message":"..."}`, or Apple's
  endpoint response. The bodies are described by
  `rust/bindings/wire/schema/verify-receipt-result.schema.json` and
  `verify-signed-data-result.schema.json`, which the OpenAPI document
  references.
- **A body over the module's cap is HTTP 413 with the module's answer.**
  The module's `init` answer states `max_input_bytes`, one over its
  largest cap (3,145,729 today), and `GET /v1/info` reports it under
  `limits`. The server hands the module at most that many bytes of a body,
  as every Wasm host cuts an input, so a body of that length or longer
  still reaches the module over its cap and the module answers its own
  size refusal: `TOO_LARGE`, or `{"status":21002}` at the endpoint. That
  JSON is the 413's body, byte for byte, with the 200's schema; a client
  reads it as it reads a 200. The cap, the length and the refusal's
  wording live in the module alone (DECISIONS.md R42).
- **`X-Aprv-Now-Ms`** (u64, decimal) is the call's clock: the
  certificate-validity instant when the input states no usable date, and
  `request_date` at the endpoint. Without it, the server's clock.
- **`X-Aprv-Token`**: with a token configured, every `/v1/` route needs it
  (compared in constant time). `/healthz`, `/readyz` and `/openapi.json`
  do not.
- **Roots** are fixed at start (`--roots`, or the managed handshake). Every
  instance gets them through `init`. `GET /v1/info` serves each root's
  SHA-256 (of the DER) and the component's SHA-256, so a client can refuse
  a server that runs something else.

### Problems

Everything that is not a verification result (a 200, or the 413 above)
is an RFC 9457 problem,
`application/problem+json`, with `type` (a link to the heading below),
`title`, `status`, `detail` and `code`.

#### bad-request
400 `BAD_REQUEST`: `X-Aprv-Now-Ms` is not a u64 in decimal, or the body
could not be read.

#### unauthorized
401 `UNAUTHORIZED`: a token is configured and `X-Aprv-Token` is missing
or wrong.

#### not-found
404 `NOT_FOUND`: no such route.

#### method-not-allowed
405 `METHOD_NOT_ALLOWED`: the route exists for another method.

#### wasm-trap
500 `WASM_TRAP`: the component trapped, the guest time limit and the
memory limit included. The instance is discarded.

#### abi-error
500 `ABI_ERROR`: the component broke the interface (a result that is not
UTF-8, an `init` that refused the roots it accepted at start). The
instance is discarded.

#### internal-error
500 `INTERNAL_ERROR`: the server could not run the call (an instance
could not be created, a worker was lost).

A client maps both 500 codes and a failed connection to `INTERNAL_ERROR`
(21009 at the endpoint), keeping the category in the cause
(ARCHITECTURE.md §4, "Six outcomes").

## Managed mode

`aprv serve --managed` is how a parent process owns a server:

1. The parent starts `aprv serve --managed` with pipes on stdin and stdout.
2. It writes the token as the first stdin line: at least 32 bytes; send
   256 random bits (64 hex digits). Never in argv (world-readable in
   `/proc`) or the environment.
3. It writes the roots as the second line, in `init`'s own shape
   (`rust/bindings/wire/schema/init-config.schema.json`):
   `{"roots":["<base64>", ...]}`, each root DER or PEM bytes, or `{}`
   for the Apple roots. An
   empty list is refused.
4. The child binds `127.0.0.1:0` whatever `APRV_LISTEN` says and prints
   one line, `APRV_LISTEN=127.0.0.1:<port>`, on stdout.
5. The parent sends every `/v1/` request with `X-Aprv-Token`.
6. The parent keeps stdin open. EOF on stdin, which also happens when the
   parent dies (even by `kill -9`), makes the child exit 0.

A bad handshake exits 2 with a message on stderr and prints no address.
`scripts/managed-smoke.py` drives a session and checks each step.

## Limits

| Limit | Value |
|---|---|
| Request body, CLI stdin | The module's: its largest cap is 3,145,728 bytes, Apple's own verifyReceipt limit, and its `init` answer states `max_input_bytes`, one more. A larger input reaches the module cut to `max_input_bytes`; its answer is a 413 or exit 3. Past the cap the server reads and discards up to 16 MiB before answering, so a client still sending gets the answer rather than a reset, and keeps its connection. A body announced larger (`Content-Length`) is read to `max_input_bytes`, answered, and the connection closed; so is one that streams past 16 MiB. A component whose `init` states a `max_input_bytes` over 16 MiB breaks the interface: the server reads no body further than that, so it refuses the component at start (exit 70) rather than answer a prefix as the whole input |
| Linear memory per store | 256 MiB (`StoreLimits`, `trap_on_grow_failure`); a larger grow traps |
| Instances per store | one component instance (3 core instances: wit-component's shim, the module, the fixup) |
| Guest time per call | 10 s by default (`--time-limit-ms`), by epoch interruption with a 10 ms tick |
| `random-get` | at most 65,536 bytes per call; OpenSSL asks for tens |
| Concurrent verifications | a semaphore of `--workers`, default the CPU count |

A trapped instance is discarded in both lifecycles. In the default pool
an instance that answered normally serves later requests, so its guest
memory outlives the call; `--lifecycle fresh` gives every request a new
instance, so nothing of one input's guest state reaches the next.

## The precompile rule

The shipped binary is Wasmtime **runtime-only** (no Cranelift): it starts
in milliseconds and cannot compile. It runs one precompiled component,
embedded at build time:

1. The full build (`--features compile`) runs
   `aprv precompile aprv.component.wasm --target <triple> -o aprv.ccwasm`.
   An explicit target means the ISA baseline, with no host CPU features. It
   writes `aprv.ccwasm.json` beside it: the component's and the file's
   SHA-256, the target, the Wasmtime version and the Wasm features.
2. The runtime-only build embeds the file named by `APRV_CCWASM`. Its
   `build.rs` refuses a plain `.wasm`, a file that no longer hashes to its
   manifest, and a file precompiled for another target or Wasmtime version.
3. At start the binary checks that the embedded bytes are a precompiled
   component, compares the Wasm features the manifest recorded with its
   own, and deserializes. Wasmtime refuses a file written under other
   engine settings; the error says so. The bytes are not hashed again at
   start: build.rs checked them, and hashing 9.5 MB cost about 50 ms per
   start on a CPU without SHA extensions.

Both builds use one engine configuration (`runtime::config()`: Wasmtime's
defaults plus epoch interruption), because a precompiled file records the
settings of the engine that wrote it. `aprv info` prints the component's
SHA-256, the Wasmtime version, its features and the Wasm features.

`scripts/build-static.sh COMPONENT.wasm [TARGET]` runs both stages. For
`x86_64-unknown-linux-musl` (the default) the result is a static-pie with
musl's own malloc, no INTERP and no NEEDED, which the script checks with
`readelf`. For `aarch64-unknown-linux-musl` it needs a cross linker; see
the script's header (not tested in this repository's container).

## Docker

[`Dockerfile`](Dockerfile) builds from the repository root with the
component as a named context and its SHA-256 as a build argument: the
builder stage checks the hash and runs `build-static.sh`; the final image
is `gcr.io/distroless/static-debian13:nonroot`, both bases pinned by
digest, running as uid 65532 with `org.opencontainers.image.*` labels.
Inside the container the server listens on `127.0.0.1:8080`, so a published
port reaches nothing until `APRV_LISTEN=0.0.0.0:8080` is set; set a token
too. `scripts/docker-smoke.sh IMAGE` checks all of this.

## Measured

The sizes are of the build on the G1d component (the 0.7 core after
review round 3, component SHA-256 `ccccbfb5…`), `x86_64-unknown-linux-musl`.
The start-up and per-call times were measured on a shared 4-CPU machine
with `scripts/startup.py` (medians of 7 runs and of 200 calls): the first
five rows on the G1c component (`84fe428c…`) at a load average of 1 to 3,
the last on G1d at a load average of 11 to 15. G1d changed six failure
messages and no code path the timings exercise.

| What | Value |
|---|---|
| Shipped binary (runtime-only, static, stripped) | 11,547,568 B; 4,068,062 B gzip -9 |
| Embedded `.ccwasm` | 9,205,832 B |
| Full (Cranelift) glibc build | 12,485,792 B; 4,478,520 B gzip -9 |
| Load: engine and embedded component (`aprv info`) | 10 to 20 ms |
| `aprv serve` to its address line; to the first g5 result | 16.4 ms; 24.7 ms |
| One-shot CLI process, g5 receipt; JWS | 19.5 ms; 26.9 ms |
| HTTP keep-alive, fresh lifecycle, per call: g5; JWS | 6.2 ms; 14.0 ms |
| HTTP keep-alive per call, pool (the default) vs fresh, G1d: g5; JWS | pool 3.4 ms, 12.9 ms; fresh 8.2 ms, 18.3 ms |

## Tests and checks

| What | How |
|---|---|
| Unit and in-process tests | `APRV_TEST_COMPONENT=<component .wasm> cargo test --features compile` (the real component over the router; hostile components: an infinite loop, a 1 GiB grow, a non-UTF-8 result, a 1 GiB `random-get`). Two tests tie the server to `rust/bindings/`: its WIT equals `rust/bindings/abi/wit/aprv.wit`, and `/openapi.json` bundles the wire schemas |
| Every case of `fixtures/cases.json` | `scripts/cases.py --aprv <binary>`, over HTTP and the CLI |
| The corpus | `scripts/corpus.py --aprv <binary> --calls ... --node ... --mode http\|cli` |
| Limits in a real process | `scripts/hostile-smoke.sh <full build>` (the hostile component of `tests/hostile.wat`) |
| Managed mode | `scripts/managed-smoke.py --aprv <binary>` |
| Start-up and per-call cost, for the record | `scripts/startup.py --aprv <binary>` |
| All of the above against one component | `scripts/check-component.sh` (APRV_COMPONENT, OUT; see its header) |
| OpenAPI | `npx @stoplight/spectral-cli lint --fail-severity=hint openapi.yaml` (ruleset `.spectral.yaml`); Schemathesis against a running server |
| Image | `scripts/docker-smoke.sh IMAGE` |

`CI-NOTES.md` lists the jobs.
