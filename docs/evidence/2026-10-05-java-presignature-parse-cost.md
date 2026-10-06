# Java: the cost of the receipt parse before the signature

Date: 2026-10-05. Measures what a receipt at the input cap costs the Java
implementation before any signer is trusted, for owner decision Q55 (Java
has no node budget before the signature) and the residual-risk sentence
in THREAT-MODEL.md §3.7. One section also measures an attempt to parse
the payload once (Q55 a), commit `4254101`, which was reverted in
`28c31de`. Sources and commands:
[`2026-10-05-java-presignature-parse-cost/`](2026-10-05-java-presignature-parse-cost/).

## Question

The Rust core walks the envelope and the payload under a budget of
100,000 values before it decodes anything. Java has no such budget:
BouncyCastle parses the whole CMS envelope, and
`ReceiptDecoder.readCreationDate` decodes the whole top-level attribute
SET to find the creation date, both before any signer is matched. How
much heap and time does a receipt at the 3,145,728-character cap cost
there, and what does the core answer for the same inputs?

## Setup

Every result file was produced on 2026-10-06 by the committed scripts,
on one set of inputs. A first run on 2026-10-05 gave the same heap and
allocation figures; it is not kept, because its probe wrote a fixed
creation date, which a test chain issued a day later no longer covers.

- OpenJDK 21.0.10 (Ubuntu build), 4 vCPU, 16 GB RAM, one thread. G1
  unless stated; the bisection was repeated with `-XX:+UseSerialGC`.
- bcprov, bcutil and bcpkix 1.86, jackson-core 2.22.3.
- The library at `main` `3a31f14`, which parses the payload twice: once
  before the signature for the date, again after it. For the single-parse
  section, `ReceiptCore` and `ReceiptDecoder` from commit `4254101`.

Inputs, written by `PresignatureCost make` (sizes from
`results/make.txt`), all signed by one `TestPki` leaf and dated at the
moment `make` ran, inside the chain's validity:

| Input | DER bytes | Base64 chars | What it carries |
|---|---|---|---|
| `baseline` | 3,123 | 4,164 | a genuine-shaped `TestPki.receiptPayload` with one in-app purchase |
| `tiny-attributes` | 2,359,255 | 3,145,676 | the same payload SET with 195,562 attributes appended, each SEQUENCE { INTEGER type (3 bytes, distinct), INTEGER 1, OCTET STRING of 0 bytes }, 12 bytes; payload 2,347,140 bytes |
| `unsigned-attribute` | 2,359,253 | 3,145,672 | the baseline receipt with one unsigned attribute on its SignerInfo whose value SET holds 1,178,054 empty SEQUENCEs |

Each input runs under the `TestPki` root, where it verifies, and under
Apple's roots, where it ends at `UNTRUSTED_CHAIN` after only the work
before trust. Anyone can produce the second: a self-signed key is enough.
The unsigned attribute sits outside the signature, so anyone can also
append it to a genuine receipt, which then still verifies.

## Results

Per call over 20 warm calls (after 30 warm-up calls), three JVM runs;
smallest `-Xmx` at which one call in a fresh JVM completes, bisected to
1 MiB three times. From `results/two-parses-3a31f14-g1.txt` and
`results/two-parses-3a31f14-serial.txt`, the code on `main`.

| Input | Roots | Verdict | ms per call | MiB allocated per call | Smallest `-Xmx`, MiB |
|---|---|---|---|---|---|
| `baseline` | TestPki | verifies | 12.3, 8.9, 11.5 | 0.3 | 13 |
| `baseline` | Apple | `UNTRUSTED_CHAIN` | 1.6, 1.3, 2.3 | 0.1 | 13 (Serial: 11) |
| `tiny-attributes` | TestPki | verifies | 482, 392, 395 | 294.4 | 79 |
| `tiny-attributes` | Apple | `UNTRUSTED_CHAIN` | 222, 177, 190 | 144.2 | 79 |
| `unsigned-attribute` | TestPki | verifies | 198, 196, 201 | 73.0 | 27 |
| `unsigned-attribute` | Apple | `UNTRUSTED_CHAIN` | 187, 185, 189 | 72.8 | 27 |

Every bisection gave the same figure three times, and Serial GC the same
as G1 except the one baseline row marked. The heap a verified
`tiny-attributes` result keeps after GC is 26.5 to 26.6 MiB: its 195,562
unknown attributes, returned to the caller. The other results keep under
1 MiB.

Against a genuine receipt's 13 MiB, the `tiny-attributes` receipt needs
66 MiB more heap at its peak: 22 times its 3.0 MiB of base64, 29 times
its 2.25 MiB of DER. That peak is reached before trust, since the
`UNTRUSTED_CHAIN` run needs the same 79 MiB. The 144 MiB it allocates
before trust is 48 times the input. The `unsigned-attribute` receipt
needs 14 MiB more, about 5 times its input. Every call averaged under
0.5 s.

### Parsing once (Q55 a): tried and reverted

Commit `4254101` kept the attributes read before the signature and
decoded them after it, instead of reading the SET a second time. It was
reverted in `28c31de`: keeping a failed early read until after the
signature, so that its verdict and cause stay as before, cost 27 net
lines in `java/src/main`, and the change moves neither the peak heap nor
the cost before trust. Its figures below stay valid as evidence for that
commit. The same `run.sh`, from `results/two-parses-3a31f14-g1.txt` and
`results/single-parse-4254101-g1.txt`:

| Input | Roots | ms per call, `3a31f14` | ms per call, `4254101` | MiB allocated, `3a31f14` | MiB allocated, `4254101` |
|---|---|---|---|---|---|
| `tiny-attributes` | TestPki | 482, 392, 395 | 271, 233, 237 | 294.4 | 168.2 |
| `tiny-attributes` | Apple | 222, 177, 190 | 168, 171, 164 | 144.2 | 144.2 |
| `unsigned-attribute` | TestPki | 198, 196, 201 | 196, 184, 194 | 73.0 | 73.0 |

Dropping the second parse cuts the allocation of a verified cap-sized
receipt of tiny attributes from 294 to 168 MiB and its time from 392 to
482 ms to 233 to 271 ms. It does not move the peak (79 MiB on both, G1
and Serial, `results/single-parse-4254101-serial.txt`), because the
second parse on `3a31f14` runs after the first one's tree is garbage.
The work before trust is unchanged: the same decode, kept. Timings of a
few milliseconds vary from run to run (the verified baseline took 8.9 to
12.3 ms on `3a31f14` and 5.5 to 13.9 ms on `4254101`); the allocation
figures are the steady ones.

### Against the core

`core.sh` ran the same three files through the `aprv.wasm` committed
under `go/internal/wasm/` at `3a31f14`, on the Go package's wazero host
(`results/core.txt`). Only verdicts and process times were recorded,
not the module's memory:

| Input | TestPki root | Apple's roots |
|---|---|---|
| `baseline` | ok | `UNTRUSTED_CHAIN` |
| `tiny-attributes` | `UNREADABLE_PAYLOAD` | `UNTRUSTED_CHAIN` |
| `unsigned-attribute` | `MALFORMED` | `MALFORMED` |

Each corediff process took 1.4 to 1.9 s, most of it compiling the
module, so those times are not a per-call cost.

The verdicts follow from the code and from DECISIONS.md R20 ("More than
100,000 values in the envelope, or in one attribute SET"). Both Java
inputs carry a SignerInfo that names an embedded certificate, so the
core does read the payload before the signature, unlike the signerless
receipt its own hostile figures were measured on: `read_creation_date`
walks the top-level SET under `MAX_ASN1_NODES` (100,000 values), and
the 195,562 attributes, about 780,000 values, exhaust it. The date
falls back to the clock, the chain and the signature pass under the
TestPki root, and the full parse after the signature hits the same
budget: `UNREADABLE_PAYLOAD`, where Java verifies. The unsigned
attribute's 1,178,054 values exceed the envelope budget, so the core
refuses it as `MALFORMED` before anything is decoded, where Java parses
it and verifies.

The core's measured figures are for other shapes and are not this
note's: a signerless receipt of 3 MiB of tiny attributes, which never
reads the payload, grew linear memory from 1.9 to 16.1 MiB in 16.5 to
26.1 ms, and 1.17 million empty SEQUENCEs in an unsigned attribute were
refused as `MALFORMED` in 10.2 ms and 14.5 MB, both through `aprv.wasm`
in V8 (docs/rust-core/THREAT-MODEL.md §5,
[`2026-09-29-core-review-fixes.md`](2026-09-29-core-review-fixes.md)).
The second is close to the shape of `unsigned-attribute`; no core memory
figure exists for `tiny-attributes` signed under a named certificate.

## Verdict

The owner's Q55 question of 2026-10-05 set the bar for "a real
amplification problem" at more than 20 times the input or more than
2 s. The `tiny-attributes` shape crosses the first: 22 times the base64
in peak heap, all of it spent before trust. The time is far below the
second. No code was added for it; the options went to the owner. Only
the input cap bounds the cost, and java/README.md tells hosts to cap
body size and concurrency and to size the heap against the latter.

## Where this stops holding

- One machine, one JDK, one thread. Time scales with the machine;
  allocation and the bisected heap are the steady figures.
- The smallest `-Xmx` includes the JVM's own floor (13 MiB here) and the
  caller's copy of the base64 string, so the growth over the baseline, not
  the absolute figure, is what an input costs. It is a fresh JVM's first
  call, with the interpreter's allocation pattern.
- bcprov 1.86. A BouncyCastle that builds its tree differently changes
  every figure.
- The core's verdicts are those of the `aprv.wasm` committed under
  `go/internal/wasm/` at `3a31f14`, which can lag `rust/src` between
  releases.
- Two shapes. A shape that makes BouncyCastle hold more per byte than an
  attribute of 12 bytes or an empty SEQUENCE of 2 was not searched for.
